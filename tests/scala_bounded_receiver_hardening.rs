mod common;

use brokk_bifrost::analyzer::structural::{CodeQuery, execute_workspace};
use brokk_bifrost::{AnalyzerConfig, IAnalyzer, Language, ScalaAnalyzer, WorkspaceAnalyzer};
use common::InlineTestProject;
use serde_json::{Value, json};

fn metadata(analyzer: &ScalaAnalyzer, fqn: &str) -> brokk_bifrost::analyzer::SignatureMetadata {
    let definitions = analyzer.get_definitions(fqn);
    assert_eq!(definitions.len(), 1, "expected one definition for {fqn}");
    let metadata = analyzer.signature_metadata(&definitions[0]);
    assert_eq!(metadata.len(), 1, "expected one signature for {fqn}");
    metadata.into_iter().next().expect("one signature")
}

#[test]
fn scala_extension_metadata_preserves_parser_derived_receiver_identity() {
    const SOURCE: &str = r#"
package syntax

import domain.Service

object Ops {
  extension (service: Service)
    def enhance(level: Int = 0): Unit = ()
}
"#;

    let project = InlineTestProject::with_language(Language::Scala)
        .file("syntax/Ops.scala", SOURCE)
        .build();
    let analyzer = ScalaAnalyzer::from_project(project.project().clone());
    let extension = metadata(&analyzer, "syntax.Ops$.enhance");
    let receiver = extension
        .extension_receiver_type_identity()
        .and_then(|identity| identity.nominal_name())
        .expect("structured extension receiver");

    assert_eq!(extension.extension_receiver_type(), Some("Service"));
    assert_eq!(receiver.path(), ["Service"]);
    assert_eq!(receiver.lexical_scope(), ["Ops$"]);
    assert!(!receiver.is_absolute());
    assert!(
        extension
            .callable_arity()
            .expect("extension callable arity")
            .accepts(0)
    );
}

#[test]
fn scala_return_metadata_preserves_parser_identity_and_uncertainty() {
    const SOURCE: &str = r#"
package app

class Box[T]
class Holder { class Nested }

object Factory {
  import external.Result

  class Nested

  def imported(): Result = ???
  def qualified(): external.Result = ???
  def absolute(): _root_.external.Result = ???
  def generic(): Box[String] = ???
  def nested(): Nested = ???
  def typeParameter[T](): T = ???
  def projected(): Holder#Nested = ???
  def wildcard(): Box[_] = ???
}
"#;

    let project = InlineTestProject::with_language(Language::Scala)
        .file("app/Factory.scala", SOURCE)
        .build();
    let analyzer = ScalaAnalyzer::from_project(project.project().clone());

    let imported = metadata(&analyzer, "app.Factory$.imported");
    let imported_name = imported
        .return_type_identity()
        .and_then(|identity| identity.nominal_name())
        .expect("imported nominal identity");
    assert_eq!(imported_name.path(), ["Result"]);
    assert_eq!(imported_name.lexical_scope(), ["Factory$"]);
    assert!(!imported_name.is_absolute());

    let qualified = metadata(&analyzer, "app.Factory$.qualified");
    let qualified_name = qualified
        .return_type_identity()
        .and_then(|identity| identity.nominal_name())
        .expect("qualified nominal identity");
    assert_eq!(qualified_name.path(), ["external", "Result"]);
    assert_eq!(qualified_name.lexical_scope(), ["Factory$"]);
    assert!(!qualified_name.is_absolute());

    let absolute = metadata(&analyzer, "app.Factory$.absolute");
    let absolute_name = absolute
        .return_type_identity()
        .and_then(|identity| identity.nominal_name())
        .expect("absolute nominal identity");
    assert_eq!(absolute_name.path(), ["external", "Result"]);
    assert!(absolute_name.is_absolute());

    let generic = metadata(&analyzer, "app.Factory$.generic");
    let generic_identity = generic
        .return_type_identity()
        .expect("generic structured identity");
    assert_eq!(generic_identity.generic_argument_count(), Some(1));
    assert_eq!(
        generic_identity
            .nominal_name()
            .expect("generic nominal base")
            .path(),
        ["Box"]
    );

    let nested = metadata(&analyzer, "app.Factory$.nested");
    assert_eq!(
        nested
            .return_type_identity()
            .and_then(|identity| identity.nominal_name())
            .expect("nested nominal identity")
            .lexical_scope(),
        ["Factory$"]
    );

    let type_parameter = metadata(&analyzer, "app.Factory$.typeParameter");
    assert_eq!(type_parameter.type_parameters(), ["T"]);
    assert_eq!(type_parameter.bare_return_type_parameter(), Some("T"));

    assert!(
        metadata(&analyzer, "app.Factory$.projected")
            .return_type_identity()
            .is_none(),
        "path-dependent projected types must remain uncertain"
    );
    assert!(
        metadata(&analyzer, "app.Factory$.wildcard")
            .return_type_identity()
            .is_none(),
        "wildcard generic arguments must invalidate the complete identity"
    );
}

fn member_analysis_named(files: &[(&str, &str)], caller: &str, callee: &str) -> Value {
    let mut project = InlineTestProject::with_language(Language::Scala);
    for (path, source) in files {
        project = project.file(*path, *source);
    }
    let project = project.build();
    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "match": { "kind": "call", "callee": { "name": callee } },
        "inside": { "kind": "method", "name": caller },
        "steps": [{ "op": "member_targets" }]
    }))
    .expect("Scala receiver query");
    serde_json::to_value(execute_workspace(&workspace, &query)).expect("serialized result")
}

fn member_analysis(files: &[(&str, &str)], caller: &str) -> Value {
    member_analysis_named(files, caller, "run")
}

fn only_target_fqn(result: &Value) -> &str {
    let rows = result["results"]
        .as_array()
        .expect("receiver-analysis rows");
    assert_eq!(rows.len(), 1, "{result}");
    let targets = rows[0]["member_targets"]
        .as_array()
        .unwrap_or_else(|| panic!("member targets: {result}"));
    assert_eq!(targets.len(), 1, "{result}");
    targets[0]["fq_name"].as_str().expect("target fq name")
}

#[test]
fn scala_factory_returns_use_declaration_scope_without_same_file_guessing() {
    const EXTERNAL: &str = r#"
package external
class Result { def run(): Unit = () }
"#;
    const OTHER: &str = r#"
package other
class Result { def run(): Unit = () }
"#;
    const IMPORTED: &str = r#"
package app

object Hidden {
  class Result { def run(): Unit = () }
}

object ImportedFactory {
  import external.Result
  def makeImported(): Result = new Result()
}
"#;
    const ALIASED: &str = r#"
package app

object AliasedFactory {
  import external.Result as ImportedResult
  def makeAliased(): ImportedResult = new ImportedResult()
}
"#;
    const NESTED: &str = r#"
package app

object NestedFactory {
  class Result { def run(): Unit = () }
  def makeNested(): Result = new Result()
}
"#;
    const QUALIFIED: &str = r#"
package app

object QualifiedFactory {
  def makeQualified(): external.Result = new external.Result()
}
"#;
    const ABSOLUTE: &str = r#"
package app

object AbsoluteFactory {
  def makeAbsolute(): _root_.external.Result = new external.Result()
}
"#;
    const GENERIC: &str = r#"
package app

class Box[T] { def run(): Unit = () }

object GenericFactory {
  def makeGeneric(): Box[String] = new Box[String]()
}
"#;
    const AMBIGUOUS: &str = r#"
package app

object AmbiguousFactory {
  import external.Result
  import other.Result
  def makeAmbiguous(): Result = ???
}
"#;
    const CALLER: &str = r#"
package app

object Caller {
  def importedCall(): Unit = ImportedFactory.makeImported().run()
  def aliasedCall(): Unit = AliasedFactory.makeAliased().run()
  def nestedCall(): Unit = NestedFactory.makeNested().run()
  def qualifiedCall(): Unit = QualifiedFactory.makeQualified().run()
  def absoluteCall(): Unit = AbsoluteFactory.makeAbsolute().run()
  def genericCall(): Unit = GenericFactory.makeGeneric().run()
  def ambiguousCall(): Unit = AmbiguousFactory.makeAmbiguous().run()
}
"#;
    let files = [
        ("external/Result.scala", EXTERNAL),
        ("other/Result.scala", OTHER),
        ("app/Imported.scala", IMPORTED),
        ("app/Aliased.scala", ALIASED),
        ("app/Nested.scala", NESTED),
        ("app/Qualified.scala", QUALIFIED),
        ("app/Absolute.scala", ABSOLUTE),
        ("app/Generic.scala", GENERIC),
        ("app/Ambiguous.scala", AMBIGUOUS),
        ("app/Caller.scala", CALLER),
    ];

    let imported = member_analysis(&files, "importedCall");
    assert_eq!(
        only_target_fqn(&imported),
        "external.Result.run",
        "{imported}"
    );
    assert!(
        !imported.to_string().contains("Hidden$.Result.run"),
        "{imported}"
    );

    let aliased = member_analysis(&files, "aliasedCall");
    assert_eq!(
        only_target_fqn(&aliased),
        "external.Result.run",
        "{aliased}"
    );

    let nested = member_analysis(&files, "nestedCall");
    assert_eq!(
        only_target_fqn(&nested),
        "app.NestedFactory$.Result.run",
        "{nested}"
    );

    let qualified = member_analysis(&files, "qualifiedCall");
    assert_eq!(
        only_target_fqn(&qualified),
        "external.Result.run",
        "{qualified}"
    );

    let absolute = member_analysis(&files, "absoluteCall");
    assert_eq!(
        only_target_fqn(&absolute),
        "external.Result.run",
        "{absolute}"
    );

    let generic = member_analysis(&files, "genericCall");
    assert_eq!(only_target_fqn(&generic), "app.Box.run", "{generic}");

    let ambiguous = member_analysis(&files, "ambiguousCall");
    let rows = ambiguous["results"]
        .as_array()
        .expect("ambiguous receiver-analysis rows");
    assert_eq!(rows.len(), 1, "{ambiguous}");
    assert!(
        matches!(
            rows[0]["outcome"].as_str(),
            Some("ambiguous" | "unknown" | "unsupported")
        ),
        "uncertain duplicate imports must remain an explicit uncertainty outcome: {ambiguous}"
    );
    assert!(
        rows[0]["member_targets"]
            .as_array()
            .is_none_or(Vec::is_empty),
        "two visible imported identities must not select either declaration: {ambiguous}"
    );
}

#[test]
fn scala_exact_extension_resolution_uses_receiver_identity_and_import_visibility() {
    const SERVICE: &str = r#"
package domain

class Service
class OtherService
"#;
    const EXTENSIONS: &str = r#"
package syntax

import domain.Service
import domain.OtherService

object Ops {
  extension (service: Service)
    def enhance(): Unit = ()
}

object UnrelatedOps {
  extension (service: OtherService)
    def enhance(): Unit = ()
}
"#;
    const CALLER: &str = r#"
package app

import domain.Service
import syntax.Ops.*
import syntax.Ops.enhance as boosted
import syntax.UnrelatedOps.*

object Caller {
  def exactExtension(): Unit = {
    val service: Service = new Service()
    service.enhance()
  }

  def aliasedExtension(): Unit = {
    val service: Service = new Service()
    service.boosted()
  }
}
"#;
    let files = [
        ("domain/Service.scala", SERVICE),
        ("syntax/Ops.scala", EXTENSIONS),
        ("app/Caller.scala", CALLER),
    ];

    let result = member_analysis_named(&files, "exactExtension", "enhance");
    assert_eq!(only_target_fqn(&result), "syntax.Ops$.enhance", "{result}");
    assert!(
        !result.to_string().contains("syntax.UnrelatedOps$.enhance"),
        "same-named extension for an unrelated receiver must be excluded: {result}"
    );

    let aliased = member_analysis_named(&files, "aliasedExtension", "boosted");
    assert_eq!(
        only_target_fqn(&aliased),
        "syntax.Ops$.enhance",
        "explicit aliases must retain the parser-derived target identity: {aliased}"
    );
}

#[test]
fn scala_direct_member_precedes_same_named_extension() {
    const SERVICE: &str = r#"
package domain

class Service {
  def enhance(): Unit = ()
}
"#;
    const EXTENSION: &str = r#"
package syntax

import domain.Service

object Ops {
  extension (service: Service)
    def enhance(): Unit = ()
}
"#;
    const CALLER: &str = r#"
package app

import domain.Service
import syntax.Ops.*

object Caller {
  def directCollision(): Unit = {
    val service: Service = new Service()
    service.enhance()
  }
}
"#;
    let files = [
        ("domain/Service.scala", SERVICE),
        ("syntax/Ops.scala", EXTENSION),
        ("app/Caller.scala", CALLER),
    ];

    let result = member_analysis_named(&files, "directCollision", "enhance");
    assert_eq!(
        only_target_fqn(&result),
        "domain.Service.enhance",
        "{result}"
    );
    assert!(
        !result.to_string().contains("syntax.Ops$.enhance"),
        "an applicable direct member must win before extension lookup: {result}"
    );
}

#[test]
fn scala_extension_is_considered_after_direct_overloads_are_inapplicable() {
    const SERVICE: &str = r#"
package domain

class Service {
  def enhance(level: Int): Unit = ()
}
"#;
    const EXTENSION: &str = r#"
package syntax

import domain.Service

object Ops {
  extension (service: Service)
    def enhance(): Unit = ()
}
"#;
    const CALLER: &str = r#"
package app

import domain.Service
import syntax.Ops.*

object Caller {
  def extensionFallback(): Unit = {
    val service: Service = new Service()
    service.enhance()
  }
}
"#;
    let files = [
        ("domain/Service.scala", SERVICE),
        ("syntax/Ops.scala", EXTENSION),
        ("app/Caller.scala", CALLER),
    ];

    let result = member_analysis_named(&files, "extensionFallback", "enhance");
    assert_eq!(only_target_fqn(&result), "syntax.Ops$.enhance", "{result}");
}

#[test]
fn scala_applicable_extension_overloads_remain_explicitly_ambiguous() {
    const SERVICE: &str = r#"
package domain
class Service
"#;
    const EXTENSION: &str = r#"
package syntax

import domain.Service

object Ops {
  extension (service: Service)
    def enhance(): Unit = ()

  extension (service: Service)
    def enhance(level: Int = 0): Unit = ()
}
"#;
    const CALLER: &str = r#"
package app

import domain.Service
import syntax.Ops.*

object Caller {
  def ambiguousExtension(): Unit = {
    val service: Service = new Service()
    service.enhance()
  }
}
"#;
    let files = [
        ("domain/Service.scala", SERVICE),
        ("syntax/Ops.scala", EXTENSION),
        ("app/Caller.scala", CALLER),
    ];

    let result = member_analysis_named(&files, "ambiguousExtension", "enhance");
    let rows = result["results"].as_array().expect("receiver rows");
    assert_eq!(rows.len(), 1, "{result}");
    assert_eq!(
        rows[0]["outcome"].as_str(),
        Some("ambiguous"),
        "applicable extension overloads must not collapse to one target: {result}"
    );
    let targets = rows[0]["member_targets"]
        .as_array()
        .expect("ambiguous extension candidate evidence");
    assert_eq!(
        targets.len(),
        1,
        "same-symbol overload ambiguity may retain its declaration candidate: {result}"
    );
    assert_eq!(
        targets[0]["fq_name"].as_str(),
        Some("syntax.Ops$.enhance"),
        "{result}"
    );
}

#[test]
fn scala_unresolved_generic_extension_receiver_remains_unknown() {
    const SERVICE: &str = r#"
package domain
class Service
"#;
    const EXTENSION: &str = r#"
package syntax

object GenericOps {
  extension [T] (value: T)
    def enhance(): Unit = ()
}
"#;
    const CALLER: &str = r#"
package app

import domain.Service
import syntax.GenericOps.*

object Caller {
  def unresolvedGenericExtension(): Unit = {
    val service: Service = new Service()
    service.enhance()
  }
}
"#;
    let files = [
        ("domain/Service.scala", SERVICE),
        ("syntax/GenericOps.scala", EXTENSION),
        ("app/Caller.scala", CALLER),
    ];

    let result = member_analysis_named(&files, "unresolvedGenericExtension", "enhance");
    let rows = result["results"].as_array().expect("receiver rows");
    assert_eq!(rows.len(), 1, "{result}");
    assert_eq!(
        rows[0]["outcome"].as_str(),
        Some("unknown"),
        "unresolved type-parameter applicability must remain open: {result}"
    );
    assert!(
        rows[0]["member_targets"]
            .as_array()
            .is_none_or(Vec::is_empty),
        "{result}"
    );
}

#[test]
fn scala_infix_and_postfix_sites_use_parser_shaped_receivers() {
    const SOURCE: &str = r#"
package app

class Service {
  def combine(other: Service): Service = this
  def +:(other: Other): Service = this
  def finish(): Unit = ()
}

class Other {
  def +:(service: Service): Other = this
}

object Caller {
  def leftInfix(): Unit = {
    val service: Service = new Service()
    val other: Service = new Service()
    service combine other
  }

  def rightInfix(): Unit = {
    val service: Service = new Service()
    val other: Other = new Other()
    other +: service
  }

  def postfixCall(): Unit = {
    val service: Service = new Service()
    service finish
  }
}
"#;
    let files = [("app/ReceiverSites.scala", SOURCE)];

    let left = member_analysis_named(&files, "leftInfix", "combine");
    assert_eq!(only_target_fqn(&left), "app.Service.combine", "{left}");

    let right = member_analysis_named(&files, "rightInfix", "+:");
    assert_eq!(
        only_target_fqn(&right),
        "app.Service.+:",
        "colon-suffixed infix operators dispatch on the parser-shaped right receiver: {right}"
    );
    assert!(
        !right.to_string().contains("app.Other.+:"),
        "the syntactic left operand must not capture a right-associative operator: {right}"
    );

    let postfix = member_analysis_named(&files, "postfixCall", "finish");
    assert_eq!(only_target_fqn(&postfix), "app.Service.finish", "{postfix}");
}

#[test]
fn scala_inherited_members_use_nearest_breadth_first_depth() {
    const SOURCE: &str = r#"
package app

trait Root {
  def run(): Unit = ()
}

trait Mid extends Root {
  override def run(): Unit = ()
}

class Child extends Mid

object Caller {
  def inheritedCall(): Unit = {
    val child: Child = new Child()
    child.run()
  }
}
"#;
    let files = [("app/Hierarchy.scala", SOURCE)];
    let result = member_analysis(&files, "inheritedCall");
    assert_eq!(
        only_target_fqn(&result),
        "app.Mid.run",
        "the nearest inherited override must stop deeper traversal: {result}"
    );
    assert!(
        !result.to_string().contains("app.Root.run"),
        "a shadowed deeper declaration must not leak into the target set: {result}"
    );
}

#[test]
fn scala_inherited_members_resolve_parser_derived_import_paths() {
    const BASE: &str = r#"
package lib

trait Base {
  def run(): Unit = ()
}
"#;
    const CHILDREN: &str = r#"
package app

import lib.Base as ImportedBase

class AliasedChild extends ImportedBase

object WildcardScope {
  import lib.*
  class WildcardChild extends Base
}
"#;
    const CALLER: &str = r#"
package app

object Caller {
  def aliasedInherited(): Unit = {
    val child: AliasedChild = new AliasedChild()
    child.run()
  }

  def wildcardInherited(): Unit = {
    val child: WildcardScope.WildcardChild = new WildcardScope.WildcardChild()
    child.run()
  }
}
"#;
    let files = [
        ("lib/Base.scala", BASE),
        ("app/Children.scala", CHILDREN),
        ("app/Caller.scala", CALLER),
    ];

    let aliased = member_analysis(&files, "aliasedInherited");
    assert_eq!(only_target_fqn(&aliased), "lib.Base.run", "{aliased}");

    let wildcard = member_analysis(&files, "wildcardInherited");
    assert_eq!(only_target_fqn(&wildcard), "lib.Base.run", "{wildcard}");
}

#[test]
fn scala_direct_override_precedes_inherited_members() {
    const SOURCE: &str = r#"
package app

trait Base {
  def run(): Unit = ()
}

class Child extends Base {
  override def run(): Unit = ()
}

object Caller {
  def directOverride(): Unit = {
    val child: Child = new Child()
    child.run()
  }
}
"#;
    let files = [("app/DirectOverride.scala", SOURCE)];
    let result = member_analysis(&files, "directOverride");
    assert_eq!(only_target_fqn(&result), "app.Child.run", "{result}");
    assert!(
        !result.to_string().contains("app.Base.run"),
        "direct declaration precedence must remain ahead of hierarchy lookup: {result}"
    );
}

#[test]
fn scala_same_depth_inherited_members_remain_ambiguous() {
    const SOURCE: &str = r#"
package app

trait Left {
  def run(): Unit = ()
}

trait Right {
  def run(): Unit = ()
}

class Child extends Left with Right

object Caller {
  def ambiguousInherited(): Unit = {
    val child: Child = new Child()
    child.run()
  }
}
"#;
    let files = [("app/AmbiguousHierarchy.scala", SOURCE)];
    let result = member_analysis(&files, "ambiguousInherited");
    let rows = result["results"].as_array().expect("receiver rows");
    assert_eq!(rows.len(), 1, "{result}");
    assert_eq!(rows[0]["outcome"].as_str(), Some("ambiguous"), "{result}");
    let targets = rows[0]["member_targets"]
        .as_array()
        .expect("same-depth inherited candidate evidence");
    let mut fqns = targets
        .iter()
        .filter_map(|target| target["fq_name"].as_str())
        .collect::<Vec<_>>();
    fqns.sort_unstable();
    assert_eq!(fqns, ["app.Left.run", "app.Right.run"], "{result}");
}

#[test]
fn scala_super_member_uses_explicit_ancestor_scope() {
    const SOURCE: &str = r#"
package app

class Base {
  def run(): Unit = ()
}

class Child extends Base {
  override def run(): Unit = ()

  def callSuper(): Unit = super.run()
}
"#;
    let files = [("app/SuperScope.scala", SOURCE)];
    let result = member_analysis(&files, "callSuper");
    assert_eq!(only_target_fqn(&result), "app.Base.run", "{result}");
    assert!(
        !result.to_string().contains("app.Child.run"),
        "explicit super scope must bypass the current owner's direct tier: {result}"
    );
}

#[test]
fn scala_inherited_factory_return_type_drives_member_chain() {
    const SOURCE: &str = r#"
package app

class Result {
  def run(): Unit = ()
}

trait Factory {
  def make(): Result = new Result()
}

class ChildFactory extends Factory

object Caller {
  def inheritedFactoryChain(): Unit = {
    val factory: ChildFactory = new ChildFactory()
    factory.make().run()
  }
}
"#;
    let files = [("app/InheritedFactory.scala", SOURCE)];
    let result = member_analysis(&files, "inheritedFactoryChain");
    assert_eq!(only_target_fqn(&result), "app.Result.run", "{result}");
}

#[test]
fn scala_base_targeted_extension_accepts_derived_receiver() {
    const SOURCE: &str = r#"
package app

trait Base
class Child extends Base

object Ops {
  extension (base: Base)
    def enhance(): Unit = ()
}

object Caller {
  import Ops.*

  def derivedExtension(): Unit = {
    val child: Child = new Child()
    child.enhance()
  }
}
"#;
    let files = [("app/DerivedExtension.scala", SOURCE)];
    let result = member_analysis_named(&files, "derivedExtension", "enhance");
    assert_eq!(only_target_fqn(&result), "app.Ops$.enhance", "{result}");
}

#[test]
fn scala_incomplete_hierarchy_blocks_extension_fallback() {
    const SOURCE: &str = r#"
package app

class Child extends MissingBase

object Ops {
  extension (child: Child)
    def run(): Unit = ()
}

object Caller {
  import Ops.*

  def incompleteHierarchy(): Unit = {
    val child: Child = new Child()
    child.run()
  }
}
"#;
    let files = [("app/IncompleteHierarchy.scala", SOURCE)];
    let result = member_analysis(&files, "incompleteHierarchy");
    let rows = result["results"].as_array().expect("receiver rows");
    assert_eq!(rows.len(), 1, "{result}");
    assert_eq!(
        rows[0]["outcome"].as_str(),
        Some("unknown"),
        "an unresolved parser-derived parent must not fall through to an extension: {result}"
    );
    assert!(
        rows[0]["member_targets"]
            .as_array()
            .is_none_or(Vec::is_empty),
        "{result}"
    );
}
