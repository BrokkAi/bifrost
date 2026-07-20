mod common;

use brokk_bifrost::Language;
use common::InlineTestProject;
use common::usage_graph::{assert_every_edge_endpoint_is_a_node, has_edge, usage_graph_at};
use serde_json::Value;
use std::path::PathBuf;

fn usage_graph() -> Value {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("usage-graph-scala");
    usage_graph_at(root, "{}")
}

#[test]
fn scala_inverted_explicit_package_singleton_collision_fails_closed() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "collision/Api.scala",
            "package collision\nobject Api { class ActorContext }\n",
        )
        .file(
            "collision/Api/Types.scala",
            "package collision.Api\nclass ActorContext\n",
        )
        .file(
            "app/Use.scala",
            r#"package app
import collision.{Api => mixed}
object Use {
  def context: mixed.ActorContext = null
}
"#,
        )
        .build();
    let value = usage_graph_at(project.root(), "{}");
    for target in ["collision.Api$.ActorContext", "collision.Api.ActorContext"] {
        assert!(
            !has_edge(&value, "app.Use$.context", target),
            "same-tier package/singleton import leaked to {target}: {}",
            value["edges"]
        );
    }
}

#[test]
fn scala_inverted_local_inference_keeps_field_identity_and_value_type_distinct() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "model/Runtime.scala",
            r#"package model
class EntityRef { def ask(): String = "ok" }
class ClusterSharding { def entityRefFor(): EntityRef = new EntityRef }
object ClusterSharding { def apply(system: String): ClusterSharding = new ClusterSharding }
class Graph { def buildTargets(): Int = 1 }
object Graph { def apply(nodes: Set[Int])(edge: (Int, Int) => Boolean): Graph = new Graph }
object Factories {
  def make(): Graph = new Graph
  def make(value: Int): EntityRef = new EntityRef
  def ambiguous(value: Int): EntityRef = new EntityRef
  def ambiguous(value: String): Graph = new Graph
}
"#,
        )
        .file(
            "app/WeatherRoutes.scala",
            r#"package app
import model.*
class WeatherRoutes(system: String) {
  private var sharding = ClusterSharding(system)
  def route(): String = {
    val ref = sharding.entityRefFor()
    ref.ask()
  }
  def reset(): EntityRef = {
    sharding = ClusterSharding(system)
    sharding.entityRefFor()
  }
}
"#,
        )
        .file(
            "app/LayerMacros.scala",
            r#"package app
import model.Graph
object LayerMacros {
  def build(nodes: List[Int]): Int = {
    val graph = Graph(nodes.toSet)(_ < _)
    graph.buildTargets()
  }
}
"#,
        )
        .file(
            "app/ImportedFactories.scala",
            r#"package app
import model.Factories.{ambiguous, make}
import model.Graph
object ImportedFactories {
  def positive(): Int = {
    val graph = make()
    graph.buildTargets()
  }
  def negative(): Int = {
    val uncertain = ambiguous(1)
    uncertain.buildTargets()
  }
}
"#,
        )
        .build();

    let value = usage_graph_at(project.root(), "{}");
    for (caller, callee) in [
        (
            "app.WeatherRoutes.route",
            "model.ClusterSharding.entityRefFor",
        ),
        ("app.WeatherRoutes.route", "model.EntityRef.ask"),
        (
            "app.WeatherRoutes.reset",
            "model.ClusterSharding.entityRefFor",
        ),
        ("app.LayerMacros$.build", "model.Graph.buildTargets"),
        (
            "app.ImportedFactories$.positive",
            "model.Graph.buildTargets",
        ),
    ] {
        assert!(
            has_edge(&value, caller, callee),
            "missing local-inference edge {caller} -> {callee}: {}",
            value["edges"]
        );
    }
    assert!(
        !has_edge(
            &value,
            "app.ImportedFactories$.negative",
            "model.Graph.buildTargets"
        ),
        "same-shape imported overload returns must fail closed: {}",
        value["edges"]
    );
}

#[test]
fn scala_inverted_graph_resolves_exact_lexical_type_namespace_before_lower_tiers() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "lexical/Main.scala",
            r#"package lexical
class Collision { class Member }
object StableCollision { class Member }
trait Contract { type Result = String; class Inherited }
class Direct extends Contract {
  def beforeAlias(value: Result): Result = value
  type Result = Int
  def beforeClass(value: Factory): Factory = value
  class Factory
}
class InheritedUse extends Contract {
  val Result = "term"
  def alias(value: Result): Result = value
  def nested(value: Inherited): Inherited = value
}
class Covariant[+Collision, +StableCollision] {
  def blocked(value: Collision): Collision = value
  def qualifiedBlocked: Any = new StableCollision.Member
}
class LocalBarrier {
  def use: Unit = {
    type Collision = String
    type StableCollision = String
    val blocked: Collision = "ok"
    val qualifiedBlocked = new StableCollision.Member
  }
}
class QualifiedControl {
  def value: Any = new StableCollision.Member
}
trait DiamondRoot { class Diamond }
trait DiamondLeft extends DiamondRoot
trait DiamondRight extends DiamondRoot
class DiamondUse extends DiamondLeft with DiamondRight {
  def value(input: Diamond): Diamond = input
}
trait Left { class Conflict }
trait Right { class Conflict }
class AmbiguousUse extends Left with Right {
  def value(input: Conflict): Conflict = input
}
"#,
        )
        .file(
            "jvm/replica/Base.scala",
            "package replica\ntrait Base { class Exact }\nclass Local extends Base { def value(input: Exact): Exact = input }\n",
        )
        .file(
            "js/replica/Base.scala",
            "package replica\ntrait Base { class Exact }\n",
        )
        .file(
            "fallback/replica/Exact.scala",
            "package replica\nclass Exact\n",
        )
        .file(
            "external/replica/Use.scala",
            r#"package replica
class External extends Base { def value(input: Exact): Exact = input }
class QualifiedExternal extends replica.Base { def value(input: Exact): Exact = input }
"#,
        )
        .build();
    let value = usage_graph_at(project.root(), "{}");

    for (caller, callee) in [
        ("lexical.Direct.beforeClass", "lexical.Direct.Factory"),
        ("lexical.InheritedUse.nested", "lexical.Contract.Inherited"),
        (
            "lexical.QualifiedControl.value",
            "lexical.StableCollision$.Member",
        ),
        ("lexical.DiamondUse.value", "lexical.DiamondRoot.Diamond"),
        ("replica.Local.value", "replica.Base.Exact"),
    ] {
        assert!(
            has_edge(&value, caller, callee),
            "missing exact lexical type edge {caller} -> {callee}: {}",
            value["edges"]
        );
    }
    for (caller, callee) in [
        ("lexical.Covariant.blocked", "lexical.Collision"),
        (
            "lexical.Covariant.qualifiedBlocked",
            "lexical.StableCollision$.Member",
        ),
        ("lexical.LocalBarrier.use", "lexical.Collision"),
        (
            "lexical.LocalBarrier.use",
            "lexical.StableCollision$.Member",
        ),
        ("lexical.AmbiguousUse.value", "lexical.Left.Conflict"),
        ("lexical.AmbiguousUse.value", "lexical.Right.Conflict"),
        ("replica.External.value", "replica.Exact"),
        ("replica.QualifiedExternal.value", "replica.Exact"),
    ] {
        assert!(
            !has_edge(&value, caller, callee),
            "ambiguous or shadowed lexical type leaked {caller} -> {callee}: {}",
            value["edges"]
        );
    }
}

#[test]
fn scala_inverted_graph_filters_callable_roles_before_shape() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/Roles.scala",
            r#"package app
trait Context
trait Contains { infix def contains(value: Int): Boolean = true }
class Roleful(value: Int) extends Contains {
  def this() = this(0)
  def this(text: String, flag: Boolean) = this(text.length)
}
object Roleful { def apply(using Context): Roleful = new Roleful(0) }
object Use {
  given Context = new Context {}
  def primary = new Roleful(1)
  def secondaryZero = new Roleful()
  def secondaryTwo = new Roleful("two", true)
  def wrongNew = new Roleful("wrong", false, 3)
  def companion = Roleful()
  def primaryFallback = Roleful(2)
  def secondaryMustNotBeBare = Roleful("two", true)
  def inheritedInfix(value: Roleful) = value contains 1
}
"#,
        )
        .file(
            "jvm/Same.scala",
            r#"package duplicate
class Same(value: Int)
object Same {
  def apply(value: Int): Same = new Same(value)
  def unapply(value: Any): Option[Int] = None
}
"#,
        )
        .file(
            "js/Same.scala",
            r#"package duplicate
class Same(value: Int)
object Same {
  def apply(value: Int): Same = new Same(value)
  def unapply(value: Any): Option[Int] = None
}
"#,
        )
        .file(
            "external/Ambiguous.scala",
            r#"package external
object Ambiguous {
  def value = new duplicate.Same(1)
  def bare = duplicate.Same(1)
  def pattern(value: Any): Int = value match {
    case duplicate.Same(found) => found
    case _ => 0
  }
}
"#,
        )
        .build();
    let value = usage_graph_at(project.root(), "{}");
    for caller in [
        "app.Use$.primary",
        "app.Use$.secondaryZero",
        "app.Use$.secondaryTwo",
        "app.Use$.primaryFallback",
    ] {
        assert!(
            has_edge(&value, caller, "app.Roleful.Roleful"),
            "missing construction edge for {caller}: {}",
            value["edges"]
        );
    }
    for caller in ["app.Use$.wrongNew", "app.Use$.secondaryMustNotBeBare"] {
        assert!(
            !has_edge(&value, caller, "app.Roleful.Roleful"),
            "role-incompatible constructor leaked for {caller}: {}",
            value["edges"]
        );
    }
    assert!(
        has_edge(&value, "app.Use$.companion", "app.Roleful$.apply"),
        "companion apply was not selected: {}",
        value["edges"]
    );
    assert!(
        !has_edge(&value, "app.Use$.companion", "app.Roleful.Roleful"),
        "secondary constructor participated in ordinary companion lookup: {}",
        value["edges"]
    );
    assert!(
        has_edge(&value, "app.Use$.inheritedInfix", "app.Contains.contains"),
        "inherited ordinary infix call was lost: {}",
        value["edges"]
    );
    assert!(
        !has_edge(&value, "external.Ambiguous$.value", "duplicate.Same.Same"),
        "same-role/same-shape external physical owners must remain ambiguous: {}",
        value["edges"]
    );
    for (caller, higher_tier) in [
        ("external.Ambiguous$.bare", "duplicate.Same$.apply"),
        ("external.Ambiguous$.pattern", "duplicate.Same$.unapply"),
    ] {
        assert!(
            !has_edge(&value, caller, higher_tier)
                && !has_edge(&value, caller, "duplicate.Same.Same"),
            "an ambiguous ordinary callable tier must not fall through to the primary constructor: {}",
            value["edges"]
        );
    }
}

#[test]
fn scala_inverted_overrides_inherit_defaults_only_from_exact_callable_families() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "defaults/Overrides.scala",
            r#"package defaults
trait DirectBase {
  def direct(incomplete: Boolean, completion: Boolean = false): Int = 0
}
class Direct extends DirectBase {
  override def direct(incomplete: Boolean, completion: Boolean): Int = 1
  def one: Int = direct(true)
  def two: Int = direct(true, false)
}
trait Root {
  def transitive(incomplete: Boolean, completion: Boolean = false): Int = 0
}
trait Mid extends Root {
  override def transitive(incomplete: Boolean, completion: Boolean): Int = 1
}
class Leaf extends Mid {
  override def transitive(incomplete: Boolean, completion: Boolean): Int = 2
  def one: Int = transitive(true)
}
trait DifferentTypesBase {
  def different(value: String, fallback: String = "fallback"): Int = 0
}
class DifferentTypes extends DifferentTypesBase {
  def different(value: Int, fallback: Int): Int = 1
  def one: Int = different(1)
}
trait DifferentListsBase {
  def differentLists(value: Boolean)(fallback: Boolean = false): Int = 0
}
class DifferentLists extends DifferentListsBase {
  def differentLists(value: Boolean, fallback: Boolean): Int = 1
  def one: Int = differentLists(true)
}
trait UnresolvedBase {
  def unresolved(value: Missing, fallback: Missing = null): Int = 0
}
class Unresolved extends UnresolvedBase {
  override def unresolved(value: Missing, fallback: Missing): Int = 1
  def one: Int = unresolved(null)
}
trait CompetingLeft {
  def competing(first: Boolean = false, second: Boolean): Int = 0
}
trait CompetingRight {
  def competing(first: Boolean, second: Boolean = false): Int = 0
}
class Competing extends CompetingLeft with CompetingRight {
  override def competing(first: Boolean, second: Boolean): Int = 1
  def none: Int = competing()
}
"#,
        )
        .file("shadow/Boolean.scala", "package shadow\nclass Boolean\n")
        .file(
            "defaults/Shadowed.scala",
            r#"package defaults
trait BuiltinBase {
  def shadowed(value: scala.Boolean, fallback: scala.Boolean = false): Int = 0
}
class Shadowed extends BuiltinBase {
  def shadowed(value: shadow.Boolean, fallback: shadow.Boolean): Int = 1
  def one: Int = shadowed(new shadow.Boolean)
}
"#,
        )
        .file(
            "jvm/physical/Base.scala",
            "package physical\ntrait Base { def ambiguous(value: Boolean, fallback: Boolean = false): Int = 0 }\n",
        )
        .file(
            "js/physical/Base.scala",
            "package physical\ntrait Base { def ambiguous(value: Boolean, fallback: Boolean = false): Int = 0 }\n",
        )
        .file(
            "physical/Use.scala",
            r#"package physical
class Use extends Base {
  override def ambiguous(value: Boolean, fallback: Boolean): Int = 1
  def one: Int = ambiguous(true)
}
"#,
        )
        .build();
    let value = usage_graph_at(project.root(), "{}");

    for (caller, concrete, ancestor) in [
        (
            "defaults.Direct.one",
            "defaults.Direct.direct",
            "defaults.DirectBase.direct",
        ),
        (
            "defaults.Direct.two",
            "defaults.Direct.direct",
            "defaults.DirectBase.direct",
        ),
        (
            "defaults.Leaf.one",
            "defaults.Leaf.transitive",
            "defaults.Root.transitive",
        ),
    ] {
        assert!(
            has_edge(&value, caller, concrete),
            "inherited default did not retain concrete override {caller} -> {concrete}: {}",
            value["edges"]
        );
        assert!(
            !has_edge(&value, caller, ancestor),
            "inherited default substituted ancestor target {caller} -> {ancestor}: {}",
            value["edges"]
        );
    }
    assert!(
        !has_edge(&value, "defaults.Leaf.one", "defaults.Mid.transitive"),
        "transitive inherited default substituted the intermediate override: {}",
        value["edges"]
    );

    for (caller, concrete) in [
        (
            "defaults.DifferentTypes.one",
            "defaults.DifferentTypes.different",
        ),
        (
            "defaults.DifferentLists.one",
            "defaults.DifferentLists.differentLists",
        ),
        ("defaults.Unresolved.one", "defaults.Unresolved.unresolved"),
        ("defaults.Shadowed.one", "defaults.Shadowed.shadowed"),
        ("physical.Use.one", "physical.Use.ambiguous"),
        ("defaults.Competing.none", "defaults.Competing.competing"),
    ] {
        assert!(
            !has_edge(&value, caller, concrete),
            "unproven override family inherited a default {caller} -> {concrete}: {}",
            value["edges"]
        );
    }
}

#[test]
fn scala_inverted_typed_receivers_keep_exact_physical_owner_identity() {
    let replica = |platform: &str, argument_type: &str, argument: &str| {
        format!(
            r#"package replica
object RedBlackTree {{
  final class Tree {{
    def blackWithLeft(value: {argument_type}): Tree = this
  }}
  def {platform}Balance(tree: Tree): Tree = tree.blackWithLeft({argument})
}}
"#
        )
    };
    let project = InlineTestProject::with_language(Language::Scala)
        .file("jvm/replica/RedBlackTree.scala", replica("jvm", "Int", "1"))
        .file(
            "js/replica/RedBlackTree.scala",
            replica("js", "String", "\"left\""),
        )
        .file(
            "native/replica/RedBlackTree.scala",
            replica("native", "Boolean", "true"),
        )
        .file(
            "consumer/Ambiguous.scala",
            r#"package consumer
import replica.RedBlackTree.Tree
object Ambiguous {
  def balance(tree: Tree): Tree = tree.blackWithLeft(1)
}
"#,
        )
        .build();
    let value = usage_graph_at(project.root(), "{}");
    let callee = "replica.RedBlackTree$.Tree.blackWithLeft";
    for caller in [
        "replica.RedBlackTree$.jvmBalance",
        "replica.RedBlackTree$.jsBalance",
        "replica.RedBlackTree$.nativeBalance",
    ] {
        assert!(
            has_edge(&value, caller, callee),
            "exact physical receiver did not select its member for {caller}: {}",
            value["edges"]
        );
    }
    assert!(
        !has_edge(&value, "consumer.Ambiguous$.balance", callee),
        "an imported logical receiver with three physical declarations selected a replica: {}",
        value["edges"]
    );
}

#[test]
fn scala_inverted_typed_pattern_binders_activate_for_guard_and_body_only() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "model/Root.scala",
            r#"package model
object Root { final class Nested(val id: Int) }
final class Shadow
object Other { val flag: Any = new Object }
"#,
        )
        .file(
            "app/Use.scala",
            r#"package app
import model.{Root => owner}
import model.Other.flag

object Use {
  def qualified(input: Any): Any = input match {
    case value: owner.Nested => value
  }

  def sameRootName(input: Any): Any = input match {
    case owner: owner.Nested if owner != null => owner
  }

  def bodyBinding(input: Any): Any = input match {
    case flag: owner.Nested if flag != null => flag
  }

  def priorShadow(input: Any): Any = {
    val owner = new model.Shadow
    input match { case value: owner.Nested => value }
  }
}
"#,
        )
        .build();
    let value = usage_graph_at(project.root(), "{}");

    for caller in [
        "app.Use$.qualified",
        "app.Use$.sameRootName",
        "app.Use$.bodyBinding",
    ] {
        assert!(
            has_edge(&value, caller, "model.Root$.Nested"),
            "typed pattern did not resolve for {caller}: {}",
            value["edges"]
        );
    }
    assert!(
        !has_edge(&value, "app.Use$.priorShadow", "model.Root$.Nested"),
        "a real prior local root must block the imported stable path: {}",
        value["edges"]
    );
    assert!(
        !has_edge(&value, "app.Use$.bodyBinding", "model.Other$.flag"),
        "the pattern binder must shadow the imported field in guard and body: {}",
        value["edges"]
    );
}

#[test]
fn scala_inverted_records_owned_class_hierarchy_parameterless_and_self_type_edges() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/Members.scala",
            r#"package app

trait DeepReady { def ready: Boolean = false }
class Base extends DeepReady {
  def ready: Boolean = true
  def run(value: Int): Int = value
  def execute(value: Int): Int = value
  def fresh(): Base = new Base
}
class Mid extends Base
class Child extends Mid {
  def bare: Boolean = ready
  def applied: Int = run(1)
}
class Use {
  def qualified(base: Base): Boolean = base.ready
}
class FactoryScope {
  def makeBase(): Base = new Base
  class Nested {
    def local: Boolean = {
      val base = makeBase()
      base.ready
    }
  }
}
class LocalObjectScope {
  def build: Boolean = {
    object Logic extends Base {
      def local: Boolean = ready
      def viaFactory: Boolean = {
        val base = fresh()
        base.ready
      }
    }
    Logic.local
  }
}
class LocalValDeclarationBlock {
  def build: Boolean = {
    abstract class Logic extends Base {
      val ready: Boolean
      def local: Boolean = ready
    }
    true
  }
}
class LocalVarDeclarationBlock {
  def build: Boolean = {
    abstract class Logic extends Base {
      var ready: Boolean
      def local: Boolean = ready
    }
    true
  }
}
class NestedFactory {
  final class Product() {
    def available: Boolean = true
  }
  def use: Boolean = {
    val product = Product()
    product.available
  }
}

class Mailbox { def systemQueueGet: Int = 1 }
trait Queue { self: Mailbox =>
  def drain: Int = systemQueueGet
}

class Shadow extends Base {
  val ready: Boolean = false
  def read: Boolean = ready
}
class ObjectBlock extends Base {
  object ready
  def read: Any = ready
}
class AliasDoesNotBlock extends Base {
  type ready = Int
  def read: Boolean = ready
}
trait TraitReady {
  def ready: Boolean = false
  def execute(value: Int): Int = value + 1
}
class Ambiguous extends Base with TraitReady {
  def read: Boolean = ready
  def applied: Int = execute(1)
  def qualified(value: Ambiguous): Int = value.execute(2)
  def infix(value: Ambiguous): Int = value execute 3
}
trait LeftExecute { def deep(value: Int): Int = value }
trait RightRoot extends LeftExecute { override def deep(value: Int): Int = value + 1 }
trait RightLeaf extends RightRoot
class DeepMixin extends LeftExecute with RightLeaf {
  def applied: Int = deep(1)
  def qualified(value: DeepMixin): Int = value.deep(2)
  def infix(value: DeepMixin): Int = value deep 3
}
trait SharedRoot { def shared(value: Int): Int = value }
trait SharedLeft extends SharedRoot { override def shared(value: Int): Int = value + 1 }
trait SharedRight extends SharedRoot
class SharedMixin extends SharedLeft with SharedRight {
  def applied: Int = shared(1)
  def qualified(value: SharedMixin): Int = value.shared(2)
  def infix(value: SharedMixin): Int = value shared 3
}
trait AbstractReady { def ready: Boolean }
class AbstractContract extends Base with AbstractReady {
  def read: Boolean = ready
}

class OuterBase { def token: Int = 1 }
class SelfBase { def token: Int = 2 }
trait Outer extends OuterBase { self: SelfBase =>
  class Inner { def read: Int = token }
}

trait SelfNoMember
class OuterCarrier extends Base {
  trait SelfScope { self: SelfNoMember =>
    class Inner { def read: Boolean = ready }
  }
}
"#,
        )
        .build();
    let value = usage_graph_at(project.root(), "{}");

    for (caller, callee) in [
        ("app.Child.bare", "app.Base.ready"),
        ("app.Child.applied", "app.Base.run"),
        ("app.Use.qualified", "app.Base.ready"),
        ("app.FactoryScope.Nested.local", "app.Base.ready"),
        ("app.LocalObjectScope.build", "app.Base.ready"),
        ("app.AbstractContract.read", "app.Base.ready"),
        ("app.AliasDoesNotBlock.read", "app.Base.ready"),
        ("app.OuterCarrier.SelfScope.Inner.read", "app.Base.ready"),
        (
            "app.NestedFactory.use",
            "app.NestedFactory.Product.available",
        ),
        ("app.Queue.drain", "app.Mailbox.systemQueueGet"),
        ("app.Outer.Inner.read", "app.OuterBase.token"),
    ] {
        assert!(
            has_edge(&value, caller, callee),
            "missing owned-class edge {caller} -> {callee}: {}",
            value["edges"]
        );
    }
    for caller in [
        "app.Shadow.read",
        "app.ObjectBlock.read",
        "app.Ambiguous.read",
        "app.Ambiguous.applied",
        "app.Ambiguous.qualified",
        "app.Ambiguous.infix",
        "app.LocalValDeclarationBlock.build",
        "app.LocalVarDeclarationBlock.build",
    ] {
        assert!(
            !has_edge(
                &value,
                caller,
                if caller.starts_with("app.Ambiguous.") {
                    "app.Base.execute"
                } else {
                    "app.Base.ready"
                }
            ),
            "field/trait ambiguity leaked {caller} -> Base.ready: {}",
            value["edges"]
        );
    }
    for caller in [
        "app.DeepMixin.applied",
        "app.DeepMixin.qualified",
        "app.DeepMixin.infix",
    ] {
        assert!(
            has_edge(&value, caller, "app.RightRoot.deep"),
            "right parent chain did not win {caller}: {}",
            value["edges"]
        );
        assert!(
            !has_edge(&value, caller, "app.LeftExecute.deep"),
            "nearer left parent leaked into {caller}: {}",
            value["edges"]
        );
    }
    for caller in [
        "app.SharedMixin.applied",
        "app.SharedMixin.qualified",
        "app.SharedMixin.infix",
    ] {
        assert!(
            has_edge(&value, caller, "app.SharedLeft.shared"),
            "duplicate-eliding linearization did not reach left override for {caller}: {}",
            value["edges"]
        );
        assert!(
            !has_edge(&value, caller, "app.SharedRoot.shared"),
            "shared ancestor outranked left override for {caller}: {}",
            value["edges"]
        );
    }
    for caller in [
        "app.Ambiguous.applied",
        "app.Ambiguous.qualified",
        "app.Ambiguous.infix",
    ] {
        assert!(
            has_edge(&value, caller, "app.TraitReady.execute"),
            "concrete rightmost trait did not win {caller}: {}",
            value["edges"]
        );
    }
    assert!(
        !has_edge(&value, "app.Outer.Inner.read", "app.SelfBase.token"),
        "outer self type outranked its lexical owner hierarchy: {}",
        value["edges"]
    );
}

#[test]
fn scala_wildcard_package_and_package_object_keep_unique_stable_objects_visible() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "model/package.scala",
            "package object model { def packageMember: Int = 1 }\n",
        )
        .file(
            "model/BrowserEval.scala",
            "package model\nobject BrowserEval { def clickAtActionable: Int = 1 }\n",
        )
        .file(
            "app/Use.scala",
            r#"package app
import model.*
object Use { def click: Int = BrowserEval.clickAtActionable }
"#,
        )
        .build();
    let value = usage_graph_at(project.root(), "{}");
    assert!(
        has_edge(
            &value,
            "app.Use$.click",
            "model.BrowserEval$.clickAtActionable"
        ),
        "package/package-object wildcard hid unique stable object: {}",
        value["edges"]
    );
}

#[test]
fn resolves_instance_object_and_unqualified_calls() {
    let value = usage_graph();

    // `s.run()` where `val s = new Service()` — local type resolves the receiver.
    assert!(
        has_edge(
            &value,
            "example.Consumer.viaInstance",
            "example.Service.run"
        ),
        "expected viaInstance -> Service.run: {}",
        value["edges"]
    );
    // `svc.run()` where `svc: Service` — typed parameter resolves the receiver.
    assert!(
        has_edge(&value, "example.Consumer.viaParam", "example.Service.run"),
        "expected viaParam -> Service.run: {}",
        value["edges"]
    );
    // `Helpers.help()` — object method call. The object node keeps its `$`
    // suffix, so the edge target is `example.Helpers$.help`.
    assert!(
        has_edge(
            &value,
            "example.Consumer.viaObject",
            "example.Helpers$.help"
        ),
        "expected viaObject -> Helpers$.help: {}",
        value["edges"]
    );
    // Unqualified `local()` attributes to the enclosing class.
    assert!(
        has_edge(
            &value,
            "example.Consumer.callsLocal",
            "example.Consumer.local"
        ),
        "expected callsLocal -> Consumer.local: {}",
        value["edges"]
    );
}

#[test]
fn scala_inverted_resolves_unqualified_calls_through_lexical_owner_tiers() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/Owners.scala",
            r#"package app

object Outer {
  def catalog(value: Int): Int = value

  class Inner {
    def use: Int = catalog(1)
  }

  class Nearer {
    def catalog(value: Int): Int = value + 1
    def use: Int = catalog(2)
  }
}

object Unrelated {
  def catalog(value: Int): Int = value + 2
  def use: Int = catalog(3)
}
"#,
        )
        .build();
    let value = usage_graph_at(project.root(), "{}");

    assert!(
        has_edge(&value, "app.Outer$.Inner.use", "app.Outer$.catalog"),
        "nested lexical call must resolve to the outer owner: {}",
        value["edges"]
    );
    assert!(
        !has_edge(&value, "app.Outer$.Nearer.use", "app.Outer$.catalog")
            && !has_edge(&value, "app.Unrelated$.use", "app.Outer$.catalog"),
        "nearer or unrelated owners must not leak to the outer callable: {}",
        value["edges"]
    );
}

#[test]
fn scala_inverted_fresh_instance_receivers_require_a_valid_constructor() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/Fresh.scala",
            r#"package app

class Worker(seed: Int) {
  def run(): Int = seed
}

object Use {
  def good: Int = new Worker(1).run()
  def wrongConstructor: Int = new Worker().run()
}
"#,
        )
        .build();
    let value = usage_graph_at(project.root(), "{}");

    assert!(
        has_edge(&value, "app.Use$.good", "app.Worker.run"),
        "valid fresh instance must type its member receiver: {}",
        value["edges"]
    );
    assert!(
        !has_edge(&value, "app.Use$.wrongConstructor", "app.Worker.run"),
        "wrong constructor shape must not type the receiver: {}",
        value["edges"]
    );
}

#[test]
fn type_references_edge_to_the_type_node() {
    let value = usage_graph();

    // `new Service()` (and the `Service` return type) edges to the type node.
    assert!(
        has_edge(&value, "example.Consumer.makeService", "example.Service"),
        "expected makeService -> Service: {}",
        value["edges"]
    );
    assert!(
        has_edge(&value, "example.Consumer.viaInstance", "example.Service"),
        "expected viaInstance -> Service (new Service()): {}",
        value["edges"]
    );
}

#[test]
fn scala_inverted_resolves_lexical_singletons_and_separates_type_term_namespaces() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "model/Outer.scala",
            r#"package model
object Outer {
  object Token
  class UseRef
  object internal { object PathToken }
  object Factory { def apply(value: Int): UseRef = new UseRef }
  object Pattern { def unapply(value: Any): Option[Int] = None }
  def singleton: Any = Token
  def stablePath(value: Any): Int = value match {
    case internal.PathToken => 1
    case _ => 0
  }
  def made = Factory(1)
  def extracted(value: Any): Int = value match {
    case Pattern(number) => number
    case _ => 0
  }
  def shadowedSingleton(Token: Any): Any = Token
  def typedWithTerm(UseRef: Int, tree: Any): Any = tree match {
    case value: UseRef => value
    case _ => tree
  }
}
object Other {
  object Token
  class UseRef
  def singleton: Any = Token
  def typed(tree: Any): Any = tree match {
    case value: UseRef => value
    case _ => tree
  }
}
"#,
        )
        .file(
            "duplicate/First.scala",
            r#"package duplicate
object Outer {
  object Token
  def singleton: Any = Token
}
class PackageType
object PackageToken
"#,
        )
        .file(
            "duplicate/Second.scala",
            r#"package duplicate
object Outer {
  object Token
  def singleton: Any = Token
}
class PackageType
object PackageToken
"#,
        )
        .file(
            "consumer/Ambiguous.scala",
            r#"package consumer
object Ambiguous {
  def typed: duplicate.PackageType = null
  def token(value: Any): Int = value match {
    case duplicate.PackageToken => 1
    case _ => 0
  }
}
"#,
        )
        .build();

    let value = usage_graph_at(project.root(), "{}");
    assert!(
        has_edge(&value, "model.Outer$.singleton", "model.Outer$.Token$"),
        "{}",
        value["edges"]
    );
    assert!(
        has_edge(&value, "model.Outer$.typedWithTerm", "model.Outer$.UseRef"),
        "{}",
        value["edges"]
    );
    for (caller, callee) in [
        (
            "model.Outer$.stablePath",
            "model.Outer$.internal$.PathToken$",
        ),
        ("model.Outer$.made", "model.Outer$.Factory$.apply"),
        ("model.Outer$.extracted", "model.Outer$.Pattern$.unapply"),
    ] {
        assert!(
            has_edge(&value, caller, callee),
            "missing {caller} -> {callee}: {}",
            value["edges"]
        );
    }
    assert!(
        has_edge(
            &value,
            "duplicate.Outer$.singleton",
            "duplicate.Outer$.Token$"
        ),
        "each duplicate physical owner should resolve its own nested singleton before logical graph identities collapse: {}",
        value["edges"]
    );
    for (caller, callee) in [
        ("model.Outer$.shadowedSingleton", "model.Outer$.Token$"),
        ("model.Other$.singleton", "model.Outer$.Token$"),
        ("model.Other$.typed", "model.Outer$.UseRef"),
        ("consumer.Ambiguous$.typed", "duplicate.PackageType"),
        ("consumer.Ambiguous$.token", "duplicate.PackageToken$"),
    ] {
        assert!(
            !has_edge(&value, caller, callee),
            "unexpected {caller} -> {callee}: {}",
            value["edges"]
        );
    }
}

#[test]
fn receiver_typing_is_type_based_not_name_based() {
    let value = usage_graph();

    // `other.run()` where `other: Consumer` resolves to `Consumer.run`, which is
    // not a node — so it must NOT edge to `Service.run` despite the member name.
    assert!(
        !has_edge(
            &value,
            "example.Consumer.wrongReceiver",
            "example.Service.run"
        ),
        "wrongReceiver must not edge to Service.run: {}",
        value["edges"]
    );
}

#[test]
fn self_recursion_produces_no_edge_and_unused_has_no_incoming() {
    let value = usage_graph();

    // A method calling itself is not an edge.
    assert!(
        !has_edge(
            &value,
            "example.Consumer.recurse",
            "example.Consumer.recurse"
        ),
        "self-recursion must not be an edge: {}",
        value["edges"]
    );
    assert!(
        !value["edges"]
            .as_array()
            .expect("edges array")
            .iter()
            .any(|edge| edge["from"] == edge["to"]),
        "no self references may appear as edges: {}",
        value["edges"]
    );
    // `Service.unused` is never called.
    assert!(
        !value["edges"]
            .as_array()
            .expect("edges array")
            .iter()
            .any(|edge| edge["to"].as_str() == Some("example.Service.unused")),
        "unused method must have no incoming edges: {}",
        value["edges"]
    );
}

#[test]
fn every_edge_endpoint_is_a_node() {
    assert_every_edge_endpoint_is_a_node(&usage_graph());
}

#[test]
fn scala3_indented_this_and_block_scoping() {
    let value = usage_graph();

    // `this.help()` (Scala's `this` is a plain identifier) attributes to the
    // enclosing class.
    assert!(
        has_edge(
            &value,
            "example.Indented.callsThis",
            "example.Indented.help"
        ),
        "expected callsThis -> Indented.help: {}",
        value["edges"]
    );
    // A `val svc` shadow inside a Scala 3 `indented_block` branch must not leak
    // into the method scope, so the trailing `svc.run()` still resolves to the
    // Service-typed parameter.
    assert!(
        has_edge(
            &value,
            "example.Indented.shadowInBranch",
            "example.Service.run"
        ),
        "indented-block shadow must not leak to the method scope: {}",
        value["edges"]
    );
}

#[test]
fn path_filter_only_emits_matching_scala_callers() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "example/Helpers.scala",
            r#"package example

object Helpers {
  def help(): Int = 1
}
"#,
        )
        .file(
            "example/Kept.scala",
            r#"package example

class Kept {
  def call(): Int = Helpers.help()
}
"#,
        )
        .file(
            "example/Ignored.scala",
            r#"package example

class Ignored {
  def call(): Int = Helpers.help()
}
"#,
        )
        .build();

    let value = usage_graph_at(project.root(), r#"{"paths":["example/Kept.scala"]}"#);
    assert!(
        has_edge(&value, "example.Kept.call", "example.Helpers$.help"),
        "kept Scala caller should still resolve object callee nodes: {}",
        value["edges"]
    );
    assert!(
        !has_edge(&value, "example.Ignored.call", "example.Helpers$.help"),
        "path-filtered usage_graph must not emit edges from ignored callers: {}",
        value["edges"]
    );
}

#[test]
fn path_filter_resolves_imported_extension_methods() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/Syntax.scala",
            r#"package app

object Syntax:
  extension (value: String)
    def slug(): String = value.toLowerCase
"#,
        )
        .file(
            "app/Kept.scala",
            r#"package app

object Kept:
  import Syntax.*
  def call(): String = "Hello World".slug()
"#,
        )
        .file(
            "app/Ignored.scala",
            r#"package app

object Ignored:
  import Syntax.*
  def call(): String = "Goodbye".slug()
"#,
        )
        .build();

    let value = usage_graph_at(project.root(), r#"{"paths":["app/Kept.scala"]}"#);
    assert!(
        has_edge(&value, "app.Kept$.call", "app.Syntax$.slug"),
        "path-filtered Scala graph should resolve extension methods imported by scanned files: {}",
        value["edges"]
    );
    assert!(
        !has_edge(&value, "app.Ignored$.call", "app.Syntax$.slug"),
        "path-filtered Scala graph must not emit extension edges from ignored callers: {}",
        value["edges"]
    );
}

#[test]
fn usage_graph_resolves_structured_scala_field_chains() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "model/Fields.scala",
            r#"package model
class Leaf(val token: Int) { def read(): Int = token }
class Middle(val leaf: Leaf)
class Base(val inherited: Middle)
class Child extends Base(new Middle(new Leaf(1))) {
  def inheritedBare: Int = inherited.leaf.token
  def inheritedShadow(inherited: other.Middle): Int = inherited.leaf.token
}
object Stable { val middle: Middle = new Middle(new Leaf(2)) }
object Owners { final class State(val leaf: Leaf) }
"#,
        )
        .file(
            "other/Fields.scala",
            "package other\nclass Leaf(val token: Int)\nclass Middle(val leaf: Leaf)\n",
        )
        .file(
            "dup/First.scala",
            "package dup\nclass Owner(val value: Int)\n",
        )
        .file(
            "dup/Second.scala",
            "package dup\nclass Owner(val value: Int)\n",
        )
        .file(
            "app/Use.scala",
            r#"package app
import model.{Child, Middle, Owners, Stable}
object Use {
  def typed(middle: Middle): Int = middle.leaf.read()
  def inherited(child: Child): Int = child.inherited.leaf.read()
  def stable: Int = Stable.middle.leaf.read()
  def nested: Int = { val state = new Owners.State(new model.Leaf(1)); state.leaf.read() }
  def localShadow(middle: other.Middle): Int = middle.leaf.read()
  def ambiguous(owner: dup.Owner): Int = owner.value
}
"#,
        )
        .build();

    let value = usage_graph_at(project.root(), "{}");
    for caller in [
        "app.Use$.typed",
        "app.Use$.inherited",
        "app.Use$.stable",
        "app.Use$.nested",
    ] {
        assert!(has_edge(&value, caller, "model.Leaf.read"), "{value}");
    }
    assert!(!has_edge(
        &value,
        "model.Child.inheritedShadow",
        "model.Leaf.read"
    ));
    assert!(!has_edge(&value, "app.Use$.localShadow", "model.Leaf.read"));
    assert!(!has_edge(&value, "app.Use$.ambiguous", "dup.Owner.value"));
}

#[test]
fn scala_inverted_resolves_local_stable_paths_and_reassigned_owner_fields() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/Consumer.scala",
            r#"package app

class Quotes { def render(): Int = 1 }
class Repr(val qctx: Quotes)
class OtherQuotes { def render(): Int = 2 }
class OtherRepr(val qctx: OtherQuotes)
class Widget { def run(): Unit = () }
class OtherWidget { def run(): Unit = () }

class Consumer {
  private var checkbox: Widget = _

  def stablePath(): Any = {
    val repr = new Repr(new Quotes)
    val singleton: repr.qctx.type = repr.qctx
    repr.qctx.render()
  }

  def reassignedOwnerField(): Unit = {
    checkbox = new Widget // previous expression ends with var
    checkbox.run()
  }

  def parameterShadowsField(checkbox: OtherWidget): Unit = checkbox.run()

  def localShadowsField(): Unit = {
    val checkbox = new OtherWidget
    checkbox.run()
  }

  def unrelatedStablePath(repr: OtherRepr): Int = {
    val singleton: repr.qctx.type = repr.qctx
    repr.qctx.render()
  }
}
"#,
        )
        .file(
            "duplicate/First.scala",
            "package duplicate\nclass Quotes\nclass Repr(val qctx: Quotes)\n",
        )
        .file(
            "duplicate/Second.scala",
            "package duplicate\nclass Quotes\nclass Repr(val qctx: Quotes)\n",
        )
        .file(
            "duplicate/Use.scala",
            "package duplicate\nobject Use {\n  val repr = new Repr(new Quotes)\n  val singleton: repr.qctx.type = repr.qctx\n}\n",
        )
        .build();

    let value = usage_graph_at(project.root(), "{}");
    for (caller, callee) in [
        ("app.Consumer.stablePath", "app.Quotes.render"),
        ("app.Consumer.reassignedOwnerField", "app.Widget.run"),
    ] {
        assert!(
            has_edge(&value, caller, callee),
            "missing structured field edge {caller} -> {callee}: {}",
            value["edges"]
        );
    }
    for caller in [
        "app.Consumer.parameterShadowsField",
        "app.Consumer.localShadowsField",
    ] {
        assert!(
            !has_edge(&value, caller, "app.Widget.run"),
            "shadowed binding leaked to the enclosing field's value type from {caller}: {}",
            value["edges"]
        );
    }
    assert!(
        !has_edge(
            &value,
            "app.Consumer.unrelatedStablePath",
            "app.Quotes.render"
        ),
        "unrelated stable root leaked to app.Quotes.render: {}",
        value["edges"]
    );
    assert!(
        !has_edge(&value, "duplicate.Use$", "duplicate.Repr.qctx"),
        "a physically ambiguous stable field path selected an arbitrary replica: {}",
        value["edges"]
    );
}

#[test]
fn scoped_usage_graph_skips_unrelated_invalid_scala_callers() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "example/Helpers.scala",
            r#"package example

object Helpers {
  def help(): Int = 1
}
"#,
        )
        .file(
            "example/Kept.scala",
            r#"package example

class Kept {
  def call(): Int = Helpers.help()
}
"#,
        )
        .file(
            "broken/Broken.scala",
            r#"package broken

class Broken {
  def nope(
"#,
        )
        .build();

    let value = usage_graph_at(project.root(), r#"{"paths":["example/Kept.scala"]}"#);
    assert!(
        has_edge(&value, "example.Kept.call", "example.Helpers$.help"),
        "filtered Scala edge graph should not require parsing unrelated callers: {}",
        value["edges"]
    );
}

#[test]
fn ordered_parameter_lists_gate_scala_inverted_callable_edges() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "example/Calls.scala",
            r#"package example

class Api {
  def curried(value: Int)(label: String = "default"): Int = value
  def gathered(prefix: Int = 0)(values: String*): Int = prefix
}

class Consumer(api: Api) {
  def validCurried(): Int = api.curried(1)()
  def invalidFirstList(): Int = api.curried()("missing")
  def invalidSecondList(): Int = api.curried(1)("too", "many")
  def partialUnique(): String => Int = api.curried(1)
  def validDefaultsAndRepeated(): Int = api.gathered()("one", "two")
  def invalidDefaultedList(): Int = api.gathered(1, 2)("one")
}
"#,
        )
        .build();

    let value = usage_graph_at(project.root(), "{}");
    assert!(
        has_edge(
            &value,
            "example.Consumer.validCurried",
            "example.Api.curried"
        ),
        "valid ordered call lists should resolve: {}",
        value["edges"]
    );
    assert!(
        has_edge(
            &value,
            "example.Consumer.partialUnique",
            "example.Api.curried"
        ),
        "a unique callable may be structurally unapplied after a valid prefix: {}",
        value["edges"]
    );
    assert!(
        !has_edge(
            &value,
            "example.Consumer.invalidFirstList",
            "example.Api.curried"
        ),
        "invalid first list must not resolve: {}",
        value["edges"]
    );
    assert!(
        !has_edge(
            &value,
            "example.Consumer.invalidSecondList",
            "example.Api.curried"
        ),
        "invalid second list must not resolve: {}",
        value["edges"]
    );
    assert!(
        has_edge(
            &value,
            "example.Consumer.validDefaultsAndRepeated",
            "example.Api.gathered"
        ),
        "defaults and repeated parameters must apply independently per list: {}",
        value["edges"]
    );
    assert!(
        !has_edge(
            &value,
            "example.Consumer.invalidDefaultedList",
            "example.Api.gathered"
        ),
        "an invalid defaulted list must fail closed before the repeated list: {}",
        value["edges"]
    );
}

#[test]
fn scala_inverted_type_edges_preserve_class_and_object_identity_roles() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "example/Token.scala",
            r#"package example

class Token
object Token {
  class Nested
  def unapply(value: (String, String)): Option[(String, String)] = Some(value)
}

class Consumer {
  def classOnly(value: Token): Token = new Token
  def objectBare(): Token.type = Token
  def nestedOwner(): Token.Nested = new Token.Nested
  def extractor(value: String): String = value match {
    case Token(found) => found
    case _ => value
  }
  def infixExtractor(value: (String, String)): String = value match {
    case left Token right => left + right
    case _ => ""
  }
}
"#,
        )
        .build();

    let value = usage_graph_at(project.root(), "{}");
    assert!(
        has_edge(&value, "example.Consumer.classOnly", "example.Token"),
        "class type/construction roles should edge to the class: {}",
        value["edges"]
    );
    assert!(
        !has_edge(&value, "example.Consumer.classOnly", "example.Token$"),
        "class-only roles must not edge to the companion object: {}",
        value["edges"]
    );
    for caller in [
        "example.Consumer.objectBare",
        "example.Consumer.nestedOwner",
    ] {
        assert!(
            has_edge(&value, caller, "example.Token$"),
            "object role in {caller} should edge to the companion object: {}",
            value["edges"]
        );
        assert!(
            !has_edge(&value, caller, "example.Token"),
            "object role in {caller} must not edge to the class: {}",
            value["edges"]
        );
    }
    for caller in [
        "example.Consumer.extractor",
        "example.Consumer.infixExtractor",
    ] {
        assert!(
            has_edge(&value, caller, "example.Token$"),
            "object role in {caller} should edge to the companion object: {}",
            value["edges"]
        );
        assert!(
            has_edge(&value, caller, "example.Token"),
            "exact companion extractor in {caller} should project to the class: {}",
            value["edges"]
        );
    }
}

#[test]
fn scala_inverted_type_edges_include_mixin_and_infix_type_roles_only() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "model/Roles.scala",
            r#"package model

class Base
class CurriedBase(first: Int)(second: Int)
trait First
trait InHandler
trait OutHandler
object InHandler

infix abstract class CanEqual[A, B]
object CanEqual
"#,
        )
        .file(
            "app/Use.scala",
            r#"package app

import model.{Base, CurriedBase, First, InHandler, OutHandler, CanEqual}

object Use {
  def mixinRole(): Base =
    new Base with First with InHandler with OutHandler {}

  def curriedMixinRole(): CurriedBase =
    new CurriedBase(1)(2) with OutHandler

  def curriedFactory(): CurriedBase = new CurriedBase(1)(2)
  def ordinaryWith: Any = curriedFactory() with OutHandler

  def infixTypeRole[A, B](evidence: A CanEqual B): Unit = ()

  def termObjectRole: Any = InHandler
  def ordinaryInfix(left: String, right: String): String = left CanEqual right
}
"#,
        )
        .build();

    let value = usage_graph_at(project.root(), "{}");
    assert!(
        has_edge(&value, "app.Use$.mixinRole", "model.InHandler"),
        "anonymous mixin RHS should edge to the exact trait: {}",
        value["edges"]
    );
    assert!(
        has_edge(&value, "app.Use$.curriedMixinRole", "model.OutHandler"),
        "curried anonymous mixin RHS should edge to the exact trait: {}",
        value["edges"]
    );
    assert!(
        has_edge(&value, "app.Use$.infixTypeRole", "model.CanEqual"),
        "infix_type operator should edge to the exact type constructor: {}",
        value["edges"]
    );
    assert!(
        !has_edge(&value, "app.Use$.termObjectRole", "model.InHandler"),
        "term object role must not edge to its companion trait: {}",
        value["edges"]
    );
    assert!(
        !has_edge(&value, "app.Use$.ordinaryInfix", "model.CanEqual"),
        "ordinary term infix operator must not become a type role: {}",
        value["edges"]
    );
    assert!(
        !has_edge(&value, "app.Use$.ordinaryWith", "model.OutHandler"),
        "ordinary call infix expression must not become an anonymous mixin type role: {}",
        value["edges"]
    );
}

#[test]
fn scala_inverted_companion_nested_and_wildcard_object_roles_are_exact() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/Owners.scala",
            r#"package app
class Token { def make(): Token = this }
object Token { def make(): Token = new Token }
object Outer {
  def make(): Int = 1
  object Inner { def make(): Int = 2 }
}
object Shared
class Holder { val Shared: Int = 1 }
object Use {
  def companion(): Token = Token.make()
  def nested(): Outer.Inner.type = Outer.Inner
  def nestedCall(): Int = Outer.Inner.make()
  def unqualifiedNested = Inner
  def instanceField(holder: Holder): Int = holder.Shared
}
"#,
        )
        .file("left/Shared.scala", "package left\nobject Shared { def make(): Int = 1 }\n")
        .file("right/Shared.scala", "package right\nobject Shared { def make(): Int = 2 }\n")
        .file(
            "app/Ambiguous.scala",
            "package app\nimport left._\nimport right._\nobject Ambiguous {\n  def bare(): Shared.type = Shared\n  def call(): Int = Shared.make()\n}\n",
        )
        .file(
            "app/Explicit.scala",
            "package app\nimport left.Shared\nimport right._\nobject Explicit { def call(): Int = Shared.make() }\n",
        )
        .build();
    let value = usage_graph_at(project.root(), "{}");
    assert!(
        has_edge(&value, "app.Use$.companion", "app.Token$.make"),
        "{}",
        value["edges"]
    );
    assert!(
        !has_edge(&value, "app.Use$.companion", "app.Token.make"),
        "{}",
        value["edges"]
    );
    assert!(
        has_edge(&value, "app.Use$.nested", "app.Outer$.Inner$"),
        "{}",
        value["edges"]
    );
    assert!(
        has_edge(&value, "app.Use$.nestedCall", "app.Outer$.Inner$.make"),
        "{}",
        value["edges"]
    );
    assert!(
        !has_edge(&value, "app.Use$.nestedCall", "app.Outer$.make"),
        "{}",
        value["edges"]
    );
    assert!(
        !has_edge(&value, "app.Use$.unqualifiedNested", "app.Outer$.Inner$"),
        "{}",
        value["edges"]
    );
    assert!(
        !has_edge(&value, "app.Use$.instanceField", "app.Shared$"),
        "{}",
        value["edges"]
    );
    for callee in ["left.Shared$", "right.Shared$"] {
        assert!(
            !has_edge(&value, "app.Ambiguous$.bare", callee),
            "{callee}: {}",
            value["edges"]
        );
    }
    for callee in ["left.Shared$.make", "right.Shared$.make"] {
        assert!(
            !has_edge(&value, "app.Ambiguous$.call", callee),
            "{callee}: {}",
            value["edges"]
        );
    }
    assert!(
        has_edge(&value, "app.Explicit$.call", "left.Shared$.make"),
        "{}",
        value["edges"]
    );
}

#[test]
fn scala_inverted_graph_honors_method_and_anonymous_local_import_contexts() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/Owner.scala",
            r#"package app
object Owner {
  private class RetryTick
  private object RetryTick
}
"#,
        )
        .file("other/RetryTick.scala", "package other\nobject RetryTick\n")
        .file(
            "app/Consumer.scala",
            r#"package app
class Consumer {
  def methodLocal: Any = {
    import Owner._
    accept(RetryTick)
  }
  def anonymousLocal: Any = new Runnable {
    import Owner._
    def run(): Unit = accept(RetryTick)
  }
  def aliasLocal: Any = {
    import Owner.{RetryTick => AliasTick}
    accept(AliasTick)
  }
  def beforeImport: Any = {
    accept(RetryTick)
    import Owner._
  }
  def siblingScope: Any = {
    { import Owner._; accept(RetryTick) }
    accept(RetryTick)
  }
  def shadowed: Any = {
    import Owner._
    val RetryTick = other.RetryTick
    accept(RetryTick)
  }
  def ambiguous: Any = {
    import Owner._
    import other._
    accept(RetryTick)
  }
  def absent: Any = accept(RetryTick)
  private def accept(value: Any): Any = value
}
"#,
        )
        .build();
    let value = usage_graph_at(project.root(), "{}");

    for caller in [
        "app.Consumer.methodLocal",
        "app.Consumer.anonymousLocal",
        "app.Consumer.aliasLocal",
        "app.Consumer.siblingScope",
    ] {
        assert!(
            has_edge(&value, caller, "app.Owner$.RetryTick$"),
            "{caller} should edge to the exact imported object: {}",
            value["edges"]
        );
        assert!(
            !has_edge(&value, caller, "app.Owner$.RetryTick"),
            "{caller} must not edge to the same-name class: {}",
            value["edges"]
        );
    }
    for caller in [
        "app.Consumer.beforeImport",
        "app.Consumer.shadowed",
        "app.Consumer.ambiguous",
        "app.Consumer.absent",
    ] {
        assert!(
            !has_edge(&value, caller, "app.Owner$.RetryTick$"),
            "{caller} must not see the target object: {}",
            value["edges"]
        );
    }
}

#[test]
fn scala_inverted_uses_parser_active_enclosing_package_for_constructors() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "scala/collection/ArrayOps.scala",
            "package scala.collection\nclass ArrayOps(value: Int)\n",
        )
        .file(
            "scala/collection/immutable/ArraySeq.scala",
            r#"package scala.collection
package immutable
object ArraySeq { def make = new ArrayOps(1) }
"#,
        )
        .build();
    let value = usage_graph_at(project.root(), "{}");
    assert!(
        has_edge(
            &value,
            "scala.collection.immutable.ArraySeq$.make",
            "scala.collection.ArrayOps"
        ),
        "{}",
        value["edges"]
    );
}

#[test]
fn scala_inverted_resolves_unique_unapplied_companion_apply_values() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "model/Token.scala",
            "package model\ncase class Token(value: Int)\n",
        )
        .file(
            "app/Use.scala",
            r#"package app
import model.Token
object Use {
  def accept(value: Int, function: Int => Token): Token = function(value)
  def keep(value: Any): Any = value
  def contextual = accept(1, Token)
  def inferred = Option(1).map(Token)
  def rejected = keep(Token)
}
"#,
        )
        .build();
    let value = usage_graph_at(project.root(), "{}");
    for caller in ["app.Use$.contextual", "app.Use$.inferred"] {
        assert!(
            has_edge(&value, caller, "model.Token"),
            "{caller}: {}",
            value["edges"]
        );
    }
    // The graph schema projects an exact companion-object type dependency
    // onto the class-shaped type node; direct UsageFinder/MCP assertions above
    // retain the exact `Token$` versus `Token` identity proof.
    assert!(
        has_edge(&value, "app.Use$.rejected", "model.Token"),
        "{}",
        value["edges"]
    );
}

#[test]
fn scala_inverted_lowers_unqualified_type_roles_with_exact_precedence() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "model/Model.scala",
            r#"package model
class Extracted(val value: Int)
object Extracted { def unapply(value: Any): Option[Int] = None }
class Built(val value: Int)
abstract class Zero
final class Projected private (val value: Int)
object Projected { def apply(value: Int): Projected = new Projected(value) }
class Other
class Plain(val value: Int)
object Plain { def apply(value: Int): Other = new Other }
object LexicalCollision { def apply(value: Int): Other = new Other }
object NestedFactory {
  final class Settings private (val value: Int)
  object Settings { def apply(value: Int): Settings = new Settings(value) }
  def nested = Settings(8)
}
trait Growable { def +=(value: Int): Unit }
"#,
        )
        .file(
            "app/Use.scala",
            r#"package app
import model.*
object Use {
  def extract(value: Any): Int = value match { case Extracted(found) => found; case _ => 0 }
  def built = Built(1)
  def projected = Projected(2)
  def plain = Plain(3)
  def explicitlyPlain = new Plain(4)
  def zero = new Zero:
    override def toString = "zero"
  def grow(target: Growable): Unit = target += 1
}
class LocalWins {
  def Projected(value: Int): Int = value
  def value = Projected(9)
}
class NestedWins {
  class LexicalCollision(val value: Int)
  def value = LexicalCollision(7)
}
"#,
        )
        .build();

    let value = usage_graph_at(project.root(), "{}");
    for (caller, callee) in [
        ("app.Use$.extract", "model.Extracted"),
        ("app.Use$.built", "model.Built"),
        ("app.Use$.projected", "model.Projected"),
        ("app.Use$.projected", "model.Projected$.apply"),
        ("app.Use$.plain", "model.Plain$.apply"),
        ("app.Use$.explicitlyPlain", "model.Plain"),
        ("app.Use$.zero", "model.Zero"),
        ("app.Use$.grow", "model.Growable.+="),
        ("app.LocalWins.value", "app.LocalWins.Projected"),
        ("app.NestedWins.value", "app.NestedWins.LexicalCollision"),
        (
            "model.NestedFactory$.nested",
            "model.NestedFactory$.Settings",
        ),
        (
            "model.NestedFactory$.nested",
            "model.NestedFactory$.Settings$.apply",
        ),
    ] {
        assert!(
            has_edge(&value, caller, callee),
            "expected {caller} -> {callee}: {}",
            value["edges"]
        );
    }
    for (caller, callee) in [
        ("app.Use$.plain", "model.Plain"),
        ("app.LocalWins.value", "model.Projected"),
        ("app.LocalWins.value", "model.Projected$.apply"),
        ("app.NestedWins.value", "model.LexicalCollision$.apply"),
    ] {
        assert!(
            !has_edge(&value, caller, callee),
            "unexpected {caller} -> {callee}: {}",
            value["edges"]
        );
    }
}

#[test]
fn scala_inverted_resolves_same_file_companion_wildcard_nested_type() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file("kyo/Chunk.scala", "package kyo\nclass Chunk[+A]\n")
        .file(
            "kyo/Batch.scala",
            r#"package kyo
object Batch:
    import internal.*
    def run[A, S](v: A): A =
        type Item = A | Int
        def expand(items: List[Item]) =
            Kyo.foreach(items) {
                case ToExpand[A @unchecked, S @unchecked](seq: Seq[Any], cont) =>
                    Kyo.foreach(seq)(v => v)
                case item => item
            }
        expand(Nil)
    end run
    object internal:
        case class Call[A](v: A)
    end internal
end Batch
"#,
        )
        .file(
            "kyo/ai/Context.scala",
            r#"package kyo.ai
import Context.*
import kyo.*
case class Context(calls: Chunk[Call]):
    def assistantMessage(calls: Chunk[Call]): Context = this
end Context
object Context:
    case class Call(id: String)
end Context
"#,
        )
        .build();
    let value = usage_graph_at(project.root(), "{}");
    assert!(
        has_edge(
            &value,
            "kyo.ai.Context.assistantMessage",
            "kyo.ai.Context$.Call"
        ),
        "{}",
        value["edges"]
    );
    assert!(
        !has_edge(
            &value,
            "kyo.ai.Context.assistantMessage",
            "kyo.Batch$.internal$.Call"
        ),
        "{}",
        value["edges"]
    );
}

#[test]
fn scala_inverted_applies_compilation_unit_import_precedence() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/Shared.scala",
            "package app\nobject Shared { def make(): Int = 0 }\n",
        )
        .file(
            "left/Shared.scala",
            "package left\nobject Shared { def make(): Int = 1 }\n",
        )
        .file(
            "app/WildcardWins.scala",
            "package app\nimport left._\nobject WildcardWins { def call(): Int = Shared.make() }\n",
        )
        .build();
    let value = usage_graph_at(project.root(), "{}");
    assert!(
        has_edge(&value, "app.WildcardWins$.call", "left.Shared$.make"),
        "{}",
        value["edges"]
    );
    assert!(
        !has_edge(&value, "app.WildcardWins$.call", "app.Shared$.make"),
        "{}",
        value["edges"]
    );

    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "left/Shared.scala",
            "package left\nobject Shared { def make(): Int = 1 }\n",
        )
        .file(
            "app/LocalWins.scala",
            "package app\nimport left.Shared\nobject Shared { def make(): Int = 2 }\nobject LocalWins { def call(): Int = Shared.make() }\n",
        )
        .build();
    let value = usage_graph_at(project.root(), "{}");
    assert!(
        has_edge(&value, "app.LocalWins$.call", "app.Shared$.make"),
        "{}",
        value["edges"]
    );
    assert!(
        !has_edge(&value, "app.LocalWins$.call", "left.Shared$.make"),
        "{}",
        value["edges"]
    );
}

#[test]
fn scala_inverted_resolves_generic_lexical_constructors_and_stable_paths() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "model/Flags.scala",
            r#"package model
object Flags {
  val Enabled: Int = 1
  case object Nested
}
"#,
        )
        .file(
            "app/Use.scala",
            r#"package app

import model.Flags

object Use {
  class Generic[A](value: A)

  def validGeneric = new Generic[Int](1)
  def wrongGenericArity = new Generic[Int]()
  def localConstructorRoot(Generic: LocalFactory) = new Generic[Int](1)
  def directField: Int = Flags.Enabled
  def stableField(value: Any): Int = value match {
    case Flags.Enabled => 1
    case model.Flags.Enabled => 2
    case _ => 0
  }
  def stableObject(value: Any): Int = value match {
    case Flags.Nested => 1
    case model.Flags.Nested => 2
    case _ => 0
  }
  def localRootIsNotImported(Flags: LocalFlags): Int = Flags.Enabled
  def decoyObject(value: Any): Int = value match {
    case decoy.Flags.Nested => 1
    case _ => 0
  }
}

class LocalFlags { val Enabled: Int = 2 }
class LocalFactory
"#,
        )
        .file(
            "decoy/Flags.scala",
            r#"package decoy
object Flags {
  val Enabled: Int = 2
  case object Nested
}
"#,
        )
        .build();

    let value = usage_graph_at(project.root(), "{}");
    assert!(
        has_edge(&value, "app.Use$.validGeneric", "app.Use$.Generic"),
        "{}",
        value["edges"]
    );
    assert!(
        !has_edge(&value, "app.Use$.wrongGenericArity", "app.Use$.Generic"),
        "{}",
        value["edges"]
    );
    assert!(
        has_edge(&value, "app.Use$.localConstructorRoot", "app.Use$.Generic"),
        "{}",
        value["edges"]
    );
    assert!(
        has_edge(&value, "app.Use$.stableObject", "model.Flags$.Nested$"),
        "{}",
        value["edges"]
    );
    assert!(
        !has_edge(&value, "app.Use$.decoyObject", "model.Flags$.Nested$"),
        "{}",
        value["edges"]
    );
}

#[test]
fn scala_inverted_matches_all_same_file_overloads_and_curried_constructor_lists() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/Calls.scala",
            r#"package app
class Api {
  def route(value: Int, label: String): Int = value
  def route(value: Int): Int = value
  def flip(value: Int): Int = value
  def flip(value: Int, label: String): Int = value
}
class Curried(value: Int)(label: String = "default")
class Use(api: Api) {
  def routeOne(): Int = api.route(1)
  def routeTwo(): Int = api.route(1, "two")
  def routeNone(): Int = api.route()
  def routeThree(): Int = api.route(1, "two", "three")
  def routePartial(): Int => Int = api.route
  def flipOne(): Int = api.flip(1)
  def flipTwo(): Int = api.flip(1, "two")
  def flipNone(): Int = api.flip()
  def flipThree(): Int = api.flip(1, "two", "three")
  def flipPartial(): Int => Int = api.flip
  def validConstructor(): Any = new Curried(1)()
  def invalidFirstConstructor(): Any = new Curried()("missing")
  def invalidLaterConstructor(): Any = new Curried(1)("too", "many")
}
"#,
        )
        .build();
    let value = usage_graph_at(project.root(), "{}");
    for (method, valid, invalid) in [
        (
            "route",
            ["app.Use.routeOne", "app.Use.routeTwo"],
            [
                "app.Use.routeNone",
                "app.Use.routeThree",
                "app.Use.routePartial",
            ],
        ),
        (
            "flip",
            ["app.Use.flipOne", "app.Use.flipTwo"],
            [
                "app.Use.flipNone",
                "app.Use.flipThree",
                "app.Use.flipPartial",
            ],
        ),
    ] {
        for caller in valid {
            assert!(
                has_edge(&value, caller, &format!("app.Api.{method}")),
                "{}",
                value["edges"]
            );
        }
        for caller in invalid {
            assert!(
                !has_edge(&value, caller, &format!("app.Api.{method}")),
                "{}",
                value["edges"]
            );
        }
    }
    assert!(
        has_edge(&value, "app.Use.validConstructor", "app.Curried"),
        "{}",
        value["edges"]
    );
    for caller in [
        "app.Use.invalidFirstConstructor",
        "app.Use.invalidLaterConstructor",
    ] {
        assert!(
            !has_edge(&value, caller, "app.Curried"),
            "{}",
            value["edges"]
        );
    }
}

#[test]
fn scala_inverted_graph_shares_structured_call_list_semantics() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/Calls.scala",
            r#"package app
trait Context
object Api {
  def block(value: => Int)(using Context): Int = value
  def aligned(using Context)(value: Int)(using Context): Int = value
  def contextualOnly(using Context): Int = 1
  def partial(prefix: String)(line: String): String = prefix + line
  def select(prefix: String)(line: String): String = prefix + line
  def select(left: String, right: String)(line: String): String = left + right + line
  def ambiguous(prefix: String)(line: String): String = prefix + line
  def ambiguous(prefix: Int)(line: String): String = prefix.toString + line
}
object Use {
  import Api.*
  given Context = new Context {}
  def consume(run: String => String): String = run("line")
  def consumeTwo(run: (String, String) => String): String = run("left", "right")
  def blockResult: Int = Api.block {
    val first = 1
    val second = 2
    first + second
  }
  def alignedResult: Int = Api.aligned(1)
  def contextualResult: Int = Api.contextualOnly()
  def partialResult: String = consume(Api.partial("prefix"))
  def selectedPartial: String = consume(Api.select("prefix"))
  def wrongExpected: String = consumeTwo(Api.partial("prefix"))
  // Both overloads have the same call-list shape. Argument types are not
  // shape evidence, so the partial application must remain ambiguous.
  def ambiguousPartial: String = consume(Api.ambiguous("prefix"))
}
"#,
        )
        .build();
    let value = usage_graph_at(project.root(), "{}");

    for (caller, callee) in [
        ("app.Use$.blockResult", "app.Api$.block"),
        ("app.Use$.alignedResult", "app.Api$.aligned"),
        ("app.Use$.contextualResult", "app.Api$.contextualOnly"),
        ("app.Use$.partialResult", "app.Api$.partial"),
        ("app.Use$.selectedPartial", "app.Api$.select"),
    ] {
        assert!(has_edge(&value, caller, callee), "{}", value["edges"]);
    }
    assert!(
        !has_edge(&value, "app.Use$.wrongExpected", "app.Api$.partial"),
        "{}",
        value["edges"]
    );
    assert!(
        !has_edge(&value, "app.Use$.ambiguousPartial", "app.Api$.ambiguous"),
        "{}",
        value["edges"]
    );
}

#[test]
fn scala_inverted_handles_generic_only_calls_and_semantic_argument_arity() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/Calls.scala",
            r#"package app
trait Context
class Transform(value: String)
object Transform {
  def apply(value: String): Transform = new Transform(value)
  def apply(left: String, right: String): Transform = new Transform(left + right)
}
object Api {
  def plain[A]: Int = 1
  def contextual[A](using Context): Int = 2
  def explicitZero[A](): Int = 3
  def explicitOne[A](value: Int): Int = value
  def five(a: Int, b: Int, c: Int, d: Int, e: Int): Int = a + b + c + d + e
  def consume(marker: Int, run: String => Transform): Transform = run(marker.toString)
}
object Use {
  import Api.*
  given Context = new Context {}
  def plainResult: Int = plain[Int]
  def contextualResult: Int = contextual[Int]
  def missingParens: Int = explicitZero[Int]
  def missingValue: Int = explicitOne[Int]
  def exact: Int = five(1, 2, 3, 4, 5 /* unused */)
  def extra: Int = five(1, 2, 3, 4, 5, 6 /* unused */)
  def methodValue: Transform = consume(1, /* ignored */ Transform)
}
"#,
        )
        .build();
    let value = usage_graph_at(project.root(), "{}");

    for (caller, callee) in [
        ("app.Use$.plainResult", "app.Api$.plain"),
        ("app.Use$.contextualResult", "app.Api$.contextual"),
        ("app.Use$.exact", "app.Api$.five"),
        ("app.Use$.methodValue", "app.Transform"),
    ] {
        assert!(has_edge(&value, caller, callee), "{}", value["edges"]);
    }
    for (caller, callee) in [
        ("app.Use$.missingParens", "app.Api$.explicitZero"),
        ("app.Use$.missingValue", "app.Api$.explicitOne"),
        ("app.Use$.extra", "app.Api$.five"),
    ] {
        assert!(!has_edge(&value, caller, callee), "{}", value["edges"]);
    }
}

#[test]
fn scala_inverted_method_values_use_expected_parameter_type_before_uniqueness() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file("model/TokenOne.scala", "package model\nclass Token\n")
        .file("model/TokenTwo.scala", "package model\nclass Token\n")
        .file(
            "app/LocalTokenDuplicate.scala",
            "package app\nclass LocalToken\n",
        )
        .file("shadow/String.scala", "package shadow\nclass String\n")
        .file(
            "app/Candidates.scala",
            "package app\nobject Candidates { def builtin(value: String): Unit = () }\n",
        )
        .file(
            "app/ShadowUse.scala",
            r#"package app
import shadow.String
import Candidates.builtin

object ShadowUse {
  private def consume(value: String)(f: String => Unit): Unit = f(value)
  def rejected: Unit = consume(null)(builtin)
}
"#,
        )
        .file(
            "app/Yaml.scala",
            r#"package app
import model.Token

class LocalToken

object Yaml {
  object Cst { class Document }

  def parse(input: String): String = input
  def parse(document: Cst.Document): String = "document"
  def parse(input: String, index: Int): String = input + index
  def wrong(value: Int): String = value.toString
  def binary(value: String, index: Int): String = value + index
  def unknown(value: Missing): String = "unknown"
  def ambiguous(value: Token): String = "ambiguous"
  def exact(value: LocalToken): String = "exact"

  private def consumeString(value: String)(f: String => String): String = f(value)
  private def consumeDocument(value: Cst.Document)(f: Cst.Document => String): String = f(value)
  private def consumeMissing(value: Missing)(f: Missing => String): String = f(value)
  private def consumeToken(value: Token)(f: Token => String): String = f(value)
  private def consumeLocal(value: LocalToken)(f: LocalToken => String): String = f(value)

  def fromString: String = consumeString("yaml")(parse)
  def fromDocument: String = consumeDocument(new Cst.Document)(parse)
  def wrongSameArity: String = consumeString("yaml")(wrong)
  def wrongBinary: String = consumeString("yaml")(binary)
  def unresolved: String = consumeMissing(null)(unknown)
  def physicallyAmbiguous: String = consumeToken(null)(ambiguous)
  def sourceExact: String = consumeLocal(new LocalToken)(exact)
}
"#,
        )
        .build();
    let value = usage_graph_at(project.root(), "{}");

    assert!(
        has_edge(&value, "app.Yaml$.fromString", "app.Yaml$.parse"),
        "String method value did not select parse: {}",
        value["edges"]
    );
    assert!(
        has_edge(&value, "app.Yaml$.fromDocument", "app.Yaml$.parse"),
        "Document method value did not select parse: {}",
        value["edges"]
    );
    assert!(
        has_edge(&value, "app.Yaml$.sourceExact", "app.Yaml$.exact"),
        "source-exact duplicate type did not select exact: {}",
        value["edges"]
    );
    for (caller, callee) in [
        ("app.Yaml$.wrongSameArity", "app.Yaml$.wrong"),
        ("app.Yaml$.wrongBinary", "app.Yaml$.binary"),
        ("app.Yaml$.unresolved", "app.Yaml$.unknown"),
        ("app.Yaml$.physicallyAmbiguous", "app.Yaml$.ambiguous"),
        ("app.ShadowUse$.rejected", "app.Candidates$.builtin"),
    ] {
        assert!(
            !has_edge(&value, caller, callee),
            "incompatible method value leaked {caller} -> {callee}: {}",
            value["edges"]
        );
    }
}

#[test]
fn scala_inverted_keeps_overload_shape_receiver_and_return_facts_aligned() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/Aligned.scala",
            r#"package app
class A { def run(): Int = 1 }
class B { def run(): Int = 2 }
object Factory {
  def make(value: Int): A = new A
  def make(value: Int, label: String): B = new B
}
object Extensions {
  extension (value: A) def tag(number: Int): Int = number
  extension (value: B) def tag(number: Int, label: String): Int = number
}
object Use {
  import Extensions._
  def returnA(): Int = Factory.make(1).run()
  def returnB(): Int = Factory.make(1, "b").run()
  def extensionA(value: A): Int = value.tag(1)
  def extensionB(value: B): Int = value.tag(1, "b")
  def wrongShapeA(value: A): Int = value.tag(1, "bad")
  def wrongShapeB(value: B): Int = value.tag(1)
  def unappliedA(value: A) = value.tag
}
"#,
        )
        .build();
    let value = usage_graph_at(project.root(), "{}");
    assert!(
        has_edge(&value, "app.Use$.returnA", "app.A.run"),
        "{}",
        value["edges"]
    );
    assert!(
        !has_edge(&value, "app.Use$.returnA", "app.B.run"),
        "{}",
        value["edges"]
    );
    assert!(
        has_edge(&value, "app.Use$.returnB", "app.B.run"),
        "{}",
        value["edges"]
    );
    assert!(
        !has_edge(&value, "app.Use$.returnB", "app.A.run"),
        "{}",
        value["edges"]
    );
    for caller in ["app.Use$.extensionA", "app.Use$.extensionB"] {
        assert!(
            has_edge(&value, caller, "app.Extensions$.tag"),
            "{caller}: {}",
            value["edges"]
        );
    }
    for caller in [
        "app.Use$.wrongShapeA",
        "app.Use$.wrongShapeB",
        "app.Use$.unappliedA",
    ] {
        assert!(
            !has_edge(&value, caller, "app.Extensions$.tag"),
            "{caller}: {}",
            value["edges"]
        );
    }
}

#[test]
fn object_sensitive_factory_receiver_resolves_only_constructed_type() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "example/App.scala",
            r#"package example

class Service {
  def run(): Int = 1
}

class Other {
  def run(): Int = 2
}

object Factory {
  def make(): Service = new Service()
}

class Consumer {
  def viaFactory(): Int = {
    val service = Factory.make()
    service.run()
  }
}
"#,
        )
        .build();

    let value = usage_graph_at(project.root(), "{}");
    assert!(
        has_edge(&value, "example.Consumer.viaFactory", "example.Service.run"),
        "factory receiver should edge only to Service.run: {}",
        value["edges"]
    );
    assert!(
        !has_edge(&value, "example.Consumer.viaFactory", "example.Other.run"),
        "factory receiver must not fall back to same-name Other.run: {}",
        value["edges"]
    );
}

#[test]
fn trait_method_receivers_and_overrides_emit_structured_edges() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "example/App.scala",
            r#"package example

trait Renderer {
  def render(value: String): String
}

class ConsoleRenderer extends Renderer {
  override def render(value: String): String = value.trim
  def render(): String = "empty"
}

class OtherRenderer {
  def render(value: String): String = value
}

class Consumer {
  def viaTrait(renderer: Renderer, value: String): String = renderer.render(value)
  def viaConcrete(console: ConsoleRenderer, value: String): String = console.render(value)
  def overload(console: ConsoleRenderer): String = console.render()
  def unrelated(other: OtherRenderer, value: String): String = other.render(value)
}

object ConsoleRenderer {
  def default: ConsoleRenderer = new ConsoleRenderer()
}

object App {
  import ConsoleRenderer.{default => renderer}

  def direct(): String = renderer.render("  ok ")
}
"#,
        )
        .build();

    let value = usage_graph_at(project.root(), "{}");
    assert!(
        has_edge(
            &value,
            "example.ConsoleRenderer.render",
            "example.Renderer.render"
        ),
        "override declaration should edge to the trait method: {}",
        value["edges"]
    );
    assert!(
        has_edge(
            &value,
            "example.Consumer.viaTrait",
            "example.Renderer.render"
        ),
        "trait-typed receiver should edge to Renderer.render: {}",
        value["edges"]
    );
    assert!(
        has_edge(
            &value,
            "example.Consumer.viaConcrete",
            "example.ConsoleRenderer.render"
        ),
        "concrete receiver should edge to ConsoleRenderer.render: {}",
        value["edges"]
    );
    assert!(
        has_edge(
            &value,
            "example.App$.direct",
            "example.ConsoleRenderer.render"
        ),
        "imported factory alias receiver should edge to ConsoleRenderer.render: {}",
        value["edges"]
    );
    assert!(
        !has_edge(
            &value,
            "example.Consumer.overload",
            "example.Renderer.render"
        ) && !has_edge(
            &value,
            "example.Consumer.unrelated",
            "example.Renderer.render"
        ),
        "overloads and unrelated same-name methods must not edge to the trait method: {}",
        value["edges"]
    );
}

#[test]
fn scala_inverted_fails_closed_for_ambiguous_declaration_type_paths() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "A.scala",
            "class A { def run(): Int = 0; class Nested { def run(): Int = 0 } }\n",
        )
        .file(
            "left/A.scala",
            "package left\nclass A { def run(): Int = 1; class Nested { def run(): Int = 1 } }\n",
        )
        .file(
            "right/A.scala",
            "package right\nclass A { def run(): Int = 2; class Nested { def run(): Int = 2 } }\n",
        )
        .file(
            "proven/Service.scala",
            "package proven\nclass Service { def run(): Int = 3 }\n",
        )
        .file(
            "app/AmbiguousReturn.scala",
            r#"package app
import left._
import right._

object Factory {
  def make(): A = ???
  def makeNested(): A.Nested = ???
  def makeProven(): proven.Service = ???
}

object Use {
  def call(): Int = Factory.make().run()
  def nestedCall(): Int = Factory.makeNested().run()
  def provenCall(): Int = Factory.makeProven().run()
}
"#,
        )
        .build();
    let value = usage_graph_at(project.root(), "{}");

    for run_fqn in ["A.run", "left.A.run", "right.A.run"] {
        assert!(
            !has_edge(&value, "app.Use$.call", run_fqn),
            "ambiguous declaration return type must not resolve to {run_fqn}: {}",
            value["edges"]
        );
    }
    for run_fqn in ["A.Nested.run", "left.A.Nested.run", "right.A.Nested.run"] {
        assert!(
            !has_edge(&value, "app.Use$.nestedCall", run_fqn),
            "ambiguous qualified declaration return type must not resolve to {run_fqn}: {}",
            value["edges"]
        );
    }
    assert!(
        has_edge(&value, "app.Use$.provenCall", "proven.Service.run"),
        "a structurally proven package prefix should resolve: {}",
        value["edges"]
    );
}

#[test]
fn class_method_overrides_do_not_emit_family_edges() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "exact/App.scala",
            r#"package exact

class Base {
  def run(value: String): String = value
}

class Child extends Base {
  override def run(value: String): String = value.trim
}

class Consumer {
  def viaBase(base: Base, value: String): String = base.run(value)
  def viaChild(child: Child, value: String): String = child.run(value)
}
"#,
        )
        .build();

    let value = usage_graph_at(project.root(), "{}");
    assert!(
        has_edge(&value, "exact.Consumer.viaBase", "exact.Base.run"),
        "base-typed receiver should edge to Base.run: {}",
        value["edges"]
    );
    assert!(
        has_edge(&value, "exact.Consumer.viaChild", "exact.Child.run"),
        "child-typed receiver should edge to Child.run: {}",
        value["edges"]
    );
    assert!(
        !has_edge(&value, "exact.Child.run", "exact.Base.run"),
        "ordinary class override should not edge to base method: {}",
        value["edges"]
    );
}

#[test]
fn overloaded_factory_receiver_emits_no_partial_edge() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "example/App.scala",
            r#"package example

class Service {
  def run(): Int = 1
}

class Other {
  def run(): Int = 2
}

object Factory {
  def make(value: Int): Service = new Service()
  def make(value: String): Other = new Other()
}

class Consumer {
  def caller(): Int = {
    val service = Factory.make(1)
    service.run()
  }
}
"#,
        )
        .build();

    let value = usage_graph_at(project.root(), "{}");
    assert!(
        !has_edge(&value, "example.Consumer.caller", "example.Service.run")
            && !has_edge(&value, "example.Consumer.caller", "example.Other.run"),
        "overloaded factory receiver must not choose a same-arity return type by traversal order: {}",
        value["edges"]
    );
}

#[test]
fn factory_return_types_resolve_through_shared_type_index() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "example/App.scala",
            r#"package example

class Service {
  def run(): Int = 1
}

class Noise00
class Noise01
class Noise02
class Noise03
class Noise04
class Noise05
class Noise06
class Noise07
class Noise08
class Noise09
class Noise10
class Noise11
class Noise12
class Noise13
class Noise14
class Noise15

object Factory {
  def makeQualified(): example.Service = new Service()
  def makeLocal(): Service = new Service()
}

class Consumer {
  def viaQualified(): Int = {
    val service = Factory.makeQualified()
    service.run()
  }

  def viaLocal(): Int = {
    val service = Factory.makeLocal()
    service.run()
  }
}
"#,
        )
        .build();

    let value = usage_graph_at(project.root(), "{}");
    assert!(
        has_edge(
            &value,
            "example.Consumer.viaQualified",
            "example.Service.run"
        ),
        "fully-qualified factory return type should edge to Service.run: {}",
        value["edges"]
    );
    assert!(
        has_edge(&value, "example.Consumer.viaLocal", "example.Service.run"),
        "same-package factory return type should edge to Service.run: {}",
        value["edges"]
    );
}

#[test]
fn qualified_stable_type_paths_emit_exact_inverse_edges() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "model/Structure.scala",
            r#"package model

object Structure {
  case class Value(value: Int)
  object Deep { class Leaf }
}
"#,
        )
        .file(
            "decoy/Structure.scala",
            r#"package decoy

object Structure {
  case class Value(value: Int)
  object Deep { class Leaf }
}
"#,
        )
        .file(
            "app/Use.scala",
            r#"package app

import model.Structure

object Use {
  def typed: Option[Structure.Value] = None
  def created = new Structure.Value(1)
  def wrongConstructor = new Structure.Value(1, 2)
  def applied = Structure.Value(2)
  def wrongApply = Structure.Value(2, 3)
  def extracted(value: Structure.Value): Int = value match {
    case Structure.Value(number) => number
  }
  def deep: Option[Structure.Deep.Leaf] = None
}
"#,
        )
        .file(
            "app/Alias.scala",
            r#"package app

import model.{Structure as Schema}

object Alias {
  def typed: Option[Schema.Value] = None
  def deep: Option[Schema.Deep.Leaf] = None
}
"#,
        )
        .file(
            "app/PackageRoot.scala",
            r#"package app

object PackageRoot {
  def typed: Option[model.Structure.Value] = None
  def deep: Option[model.Structure.Deep.Leaf] = None
}
"#,
        )
        .file(
            "decoy/Use.scala",
            r#"package decoy

object Use {
  def typed: Option[Structure.Value] = None
  def applied = Structure.Value(3)
}
"#,
        )
        .build();

    let value = usage_graph_at(project.root(), "{}");
    let target = "model.Structure$.Value";
    for caller in [
        "app.Use$.typed",
        "app.Use$.created",
        "app.Use$.applied",
        "app.Use$.extracted",
        "app.Alias$.typed",
        "app.PackageRoot$.typed",
    ] {
        assert!(
            has_edge(&value, caller, target),
            "expected {caller} -> {target}: {}",
            value["edges"]
        );
    }
    for caller in ["app.Use$.wrongConstructor", "app.Use$.wrongApply"] {
        assert!(
            !has_edge(&value, caller, target),
            "wrong-arity {caller} must not edge to {target}: {}",
            value["edges"]
        );
    }
    assert!(
        !has_edge(&value, "decoy.Use$.typed", target)
            && !has_edge(&value, "decoy.Use$.applied", target),
        "same-name decoy must not edge to {target}: {}",
        value["edges"]
    );

    let leaf = "model.Structure$.Deep$.Leaf";
    for caller in ["app.Use$.deep", "app.Alias$.deep", "app.PackageRoot$.deep"] {
        assert!(
            has_edge(&value, caller, leaf),
            "expected {caller} -> {leaf}: {}",
            value["edges"]
        );
    }
}

#[test]
fn scala_inverted_type_namespace_uses_exact_companion_roots() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "model/Types.scala",
            r#"package model

type Maybe[A] = Option[A]
infix type <[A, B] = Either[A, B]

object Tasty {
  sealed trait Symbol
  object Symbol {
    sealed trait ClassLike
    final class Class extends ClassLike
    final class Field
  }

  def classLike: Maybe[Symbol.ClassLike] = None
  def concrete: Maybe[Symbol.Class] = None
  def field: Maybe[Symbol.Field] = None
}
"#,
        )
        .file(
            "model/SamePackage.scala",
            r#"package model

object SamePackage {
  def maybe: Maybe[Int] = None
  def effect: Int < String = Left(1)
  val Maybe = 1
  def term: Int = Maybe
}
"#,
        )
        .file(
            "app/Imported.scala",
            r#"package app

import model.*
import model.{Maybe as Optional}

object Imported {
  def maybe: Optional[Int] = None
  def effect: Int < String = Left(1)
  def qualified: model.Maybe[Int] = None
}
"#,
        )
        .build();

    let value = usage_graph_at(project.root(), "{}");
    for (caller, target) in [
        ("model.Tasty$.classLike", "model.Tasty$.Symbol$.ClassLike"),
        ("model.Tasty$.concrete", "model.Tasty$.Symbol$.Class"),
        ("model.Tasty$.field", "model.Tasty$.Symbol$.Field"),
    ] {
        assert!(
            has_edge(&value, caller, target),
            "expected exact companion-root edge {caller} -> {target}: {}",
            value["edges"]
        );
    }
}

#[test]
fn qualified_type_roots_preserve_package_and_renamed_object_precedence() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "akka/stream/javadsl/Flow.scala",
            "package akka.stream.javadsl\nclass Flow[In, Out, Mat]\n",
        )
        .file(
            "akka/stream/javadsl/Compound.scala",
            r#"package akka.stream.javadsl
object Compound {
  def flow: javadsl.Flow[Int, String, Unit] = null
}
"#,
        )
        .file(
            "akka/stream/javadsl/Sequential.scala",
            r#"package akka.stream
package javadsl
object Sequential {
  def flow: javadsl.Flow[Int, String, Unit] = null
}
"#,
        )
        .file(
            "akka/stream/javadsl/Visibility.scala",
            r#"package akka.stream.javadsl
object Visibility {
  def before: javadsl.Flow[Int, String, Unit] = null
  import decoy.javadsl
  def after: javadsl.Flow[Int, String, Unit] = null
}
"#,
        )
        .file(
            "scala/collection/immutable/RedBlackTree.scala",
            "package scala.collection.immutable\nobject RedBlackTree { trait SetHelper[A] }\n",
        )
        .file(
            "tests/init/crash/rbtree.scala",
            "package scala.collection.immutable\nobject RedBlackTree { class Tree[A] }\n",
        )
        .file(
            "scala/collection/immutable/TreeSet.scala",
            r#"package scala.collection.immutable
import scala.collection.immutable.{RedBlackTree => RB}
class TreeSet[A] extends RB.SetHelper[A]
"#,
        )
        .file(
            "decoy/Roots.scala",
            "package decoy\nobject javadsl { class Flow[In, Out, Mat] }\nobject RedBlackTree { trait SetHelper[A] }\n",
        )
        .file(
            "akka/stream/javadsl/Collision.scala",
            r#"package akka.stream.javadsl
import decoy.*
object Collision {
  def flow: javadsl.Flow[Int, String, Unit] = null
}
"#,
        )
        .file(
            "scala/collection/immutable/Ambiguous.scala",
            r#"package scala.collection.immutable
import scala.collection.immutable.{RedBlackTree => RB}
import decoy.{RedBlackTree => RB}
class Ambiguous[A] extends RB.SetHelper[A]
"#,
        )
        .file(
            "replica/RootOne.scala",
            "package replica\nobject Root { trait Tail }\n",
        )
        .file(
            "replica/RootTwo.scala",
            "package replica\nobject Root { trait Tail }\n",
        )
        .file(
            "replica/Use.scala",
            "package replica\nimport replica.{Root => Alias}\nclass Use extends Alias.Tail\n",
        )
        .build();

    let value = usage_graph_at(project.root(), "{}");
    for caller in [
        "akka.stream.javadsl.Compound$.flow",
        "akka.stream.javadsl.Sequential$.flow",
        "akka.stream.javadsl.Visibility$.before",
    ] {
        assert!(
            has_edge(&value, caller, "akka.stream.javadsl.Flow"),
            "enclosing package root was not retained for {caller}: {}",
            value["edges"]
        );
    }
    assert!(
        !has_edge(
            &value,
            "akka.stream.javadsl.Visibility$.after",
            "akka.stream.javadsl.Flow",
        ),
        "a later explicit import was visible before its declaration: {}",
        value["edges"]
    );
    assert!(
        has_edge(
            &value,
            "scala.collection.immutable.TreeSet",
            "scala.collection.immutable.RedBlackTree$.SetHelper",
        ),
        "renamed stable object root did not resolve in extends role: {}",
        value["edges"]
    );
    assert!(
        !has_edge(
            &value,
            "akka.stream.javadsl.Collision$.flow",
            "akka.stream.javadsl.Flow",
        ),
        "package root leaked through a higher-precedence wildcard: {}",
        value["edges"]
    );
    assert!(
        !has_edge(
            &value,
            "scala.collection.immutable.Ambiguous",
            "scala.collection.immutable.RedBlackTree$.SetHelper",
        ),
        "ambiguous renamed root selected an arbitrary target: {}",
        value["edges"]
    );
    assert!(
        !has_edge(&value, "replica.Use", "replica.Root$.Tail"),
        "two physical roots completing the same tail selected an arbitrary target: {}",
        value["edges"]
    );
}

#[test]
fn scala_inverted_graph_handles_generic_companion_enum_roots_and_convergent_diamonds() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "app/Model.scala",
            r#"package app

object Chart {
  final case class Encoding[A, B](left: A, right: B)
  def generic = Encoding[Int, String](1, "one")
}

enum Extent {
  case Continuous(min: Double, max: Double)
  case Categories(keys: List[String])
}
object Extent {
  def categories(keys: List[String]): Extent = Extent.Categories(keys)
}
object Scale {
  def keys(extent: Extent): List[String] = extent match {
    case Extent.Categories(values) => values
    case _ => Nil
  }
}

trait SharedOps { infix def contains(value: Int): Boolean = true }
trait Intermediate extends SharedOps
class Convergent extends Intermediate with SharedOps
object EnumerationLike {
  def selected(ids: Convergent): Boolean = ids contains 1
}

trait LeftOps { infix def contains(value: Int): Boolean = true }
trait RightOps { infix def contains(value: Int): Boolean = true }
object AmbiguousLike {
  def selected(ids: LeftOps | RightOps): Boolean = ids contains 1
}
"#,
        )
        .file(
            "jvm/replica/Extent.scala",
            "package replica\nenum Extent { case Categories(keys: List[String]) }\nobject Extent\n",
        )
        .file(
            "js/replica/Extent.scala",
            "package replica\nenum Extent { case Categories(keys: List[String]) }\nobject Extent\n",
        )
        .file(
            "external/Use.scala",
            r#"package external
object Use {
  def keys(extent: replica.Extent): List[String] = extent match {
    case replica.Extent.Categories(values) => values
    case _ => Nil
  }
}
"#,
        )
        .build();
    let value = usage_graph_at(project.root(), "{}");

    for (caller, callee) in [
        ("app.Chart$.generic", "app.Chart$.Encoding"),
        ("app.Scale$.keys", "app.Extent.Categories"),
        ("app.EnumerationLike$.selected", "app.SharedOps.contains"),
    ] {
        assert!(
            has_edge(&value, caller, callee),
            "missing #662 structured edge {caller} -> {callee}: {}",
            value["edges"]
        );
    }
    for callee in ["app.LeftOps.contains", "app.RightOps.contains"] {
        assert!(
            !has_edge(&value, "app.AmbiguousLike$.selected", callee),
            "distinct diamond selected {callee}: {}",
            value["edges"]
        );
    }
    assert!(
        !has_edge(&value, "external.Use$.keys", "replica.Extent.Categories"),
        "physically ambiguous enum root selected a case: {}",
        value["edges"]
    );
}

#[test]
fn scala_inverted_resolves_package_lexical_field_and_application_projections() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "root/api/Types.scala",
            "package root.api\nclass ActorContext\n",
        )
        .file(
            "root/consumer/sibling/Local.scala",
            "package root.consumer.sibling\nclass Local\n",
        )
        .file(
            "root/model/Model.scala",
            r#"package root.model

object Result {
  opaque type Success[A] = A
  object Success
}
class Context { val system: Int = 1 }
trait Actor { val context: Context = new Context }
trait Generator[A]
trait GeneratorMarker[A]
object Generator {
  def anonymous[A] = new Generator[List[A]] with GeneratorMarker[List[A]] {}
}
case class Good[A](value: A)
object Good { class GoodType[A] }

object Outer {
  object internal { class BranchData }
  class Holder { def branch: internal.BranchData = null }
}

object Constructors {
  object ByteString1 {
    def apply(value: Int): ByteString1 = new ByteString1(value)
  }
  final class ByteString1 private (val value: Int)
  trait Generator[A]
  trait Marker[A]
  abstract class FlowVisitorCollect[A](empty: A, combine: (A, A) => A)
  class Inside { def bytes = ByteString1(1) }
}

object Qualified {
  final class Applied(val value: Int)
  object Applied { def apply(value: Int): Applied = new Applied(value) }
  final class Extracted(val value: Int)
  object Extracted { def unapply(value: Any): Option[Int] = None }
  object Factory { def apply(value: Int): Int = value }
  object Pattern { def unapply(value: Any): Option[Int] = None }
}
"#,
        )
        .file(
            "root/model/PatternUse.scala",
            r#"package root.model
object PatternUse {
  val constructed = Good(1)
  def extract(value: Any): Any = value match {
    case (Good(found), Good(_)) => found
    case _ => value
  }
}
"#,
        )
        .file(
            "root/consumer/Use.scala",
            r#"package root.consumer

import root.{api => classic}
import root.api
import root.model.*
import root.model.Constructors.*

class Child extends Actor { def inherited = context }

object Use {
  def aliased: classic.ActorContext = null
  def directlyImported: api.ActorContext = null
  def relative: sibling.Local = null
  def stable: Result.Success[Int] = 1
  def term = Result.Success
  def explicit = new Constructors.FlowVisitorCollect[Int](0, _ + _) {}
  def anonymous = new Constructors.Generator[Int] with Constructors.Marker[Int] {}
  def qualifiedApply = Qualified.Applied(2)
  def qualifiedExtract(value: Any): Int = value match {
    case Qualified.Extracted(found) => found
    case _ => 0
  }
  def objectApply = Qualified.Factory(3)
  def objectExtract(value: Any): Int = value match {
    case Qualified.Pattern(found) => found
    case _ => 0
  }
}
"#,
        )
        .file(
            "decoy/api/Types.scala",
            "package decoy.api\nclass ActorContext\n",
        )
        .file(
            "root/consumer/Ambiguous.scala",
            r#"package root.consumer
import root.{api => clash}
import decoy.{api => clash}
object Ambiguous {
  def wrong: clash.ActorContext = null
}
"#,
        )
        .build();

    let value = usage_graph_at(project.root(), "{}");
    for (caller, callee) in [
        ("root.consumer.Use$.aliased", "root.api.ActorContext"),
        (
            "root.consumer.Use$.directlyImported",
            "root.api.ActorContext",
        ),
        ("root.consumer.Use$.relative", "root.consumer.sibling.Local"),
        (
            "root.model.Outer$.Holder.branch",
            "root.model.Outer$.internal$.BranchData",
        ),
        (
            "root.model.Constructors$.Inside.bytes",
            "root.model.Constructors$.ByteString1",
        ),
        (
            "root.consumer.Use$.explicit",
            "root.model.Constructors$.FlowVisitorCollect",
        ),
        (
            "root.consumer.Use$.anonymous",
            "root.model.Constructors$.Generator",
        ),
        ("root.model.Generator$.anonymous", "root.model.Generator"),
        (
            "root.consumer.Use$.qualifiedApply",
            "root.model.Qualified$.Applied$.apply",
        ),
        (
            "root.consumer.Use$.qualifiedExtract",
            "root.model.Qualified$.Extracted$.unapply",
        ),
        (
            "root.consumer.Use$.objectApply",
            "root.model.Qualified$.Factory$.apply",
        ),
        (
            "root.consumer.Use$.objectExtract",
            "root.model.Qualified$.Pattern$.unapply",
        ),
    ] {
        assert!(
            has_edge(&value, caller, callee),
            "missing shared Scala resolution edge {caller} -> {callee}: {}",
            value["edges"]
        );
    }
    assert!(
        !has_edge(
            &value,
            "root.consumer.Ambiguous$.wrong",
            "root.api.ActorContext"
        ),
        "ambiguous package alias leaked to root.api.ActorContext: {}",
        value["edges"]
    );
}
