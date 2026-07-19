mod extractor;
mod hits;
mod inverted;
mod resolver;
mod shared;
pub(super) mod syntax;

use crate::analyzer::usages::common::language_for_target;
use crate::analyzer::usages::inverted_edges::{UsageEdgeWeights, UsageEdges};
use crate::analyzer::usages::model::FuzzyResult;
use crate::analyzer::usages::outcome::{GraphFailureReason, GraphUsageOutcome};
use crate::analyzer::usages::scala_graph::resolver::{TargetKind, TargetSpec};
use crate::analyzer::usages::scala_graph::shared::{ScalaEdgeResolver, ScalaQueryResolver};
use crate::analyzer::usages::traits::{
    UsageAnalyzer, UsageEdgeResolver, UsageQueryResolver, UsageScanScope,
};
use crate::analyzer::{
    CodeUnit, IAnalyzer, Language, ProjectFile, ScalaAnalyzer, resolve_analyzer,
};
use crate::hash::HashSet;

pub(crate) use inverted::{NameResolver as ScalaNameResolver, ProjectTypes as ScalaProjectTypes};
pub(in crate::analyzer::usages) use resolver::{
    import_candidate_fq_names, import_candidate_owner_fq_names, method_call_arity_applies,
    method_signature_arity, package_name_of, resolved_extension_receiver_type,
    scala_builtin_type_name, scala_extension_receiver_matches_resolved, scala_literal_type_name,
    scala_normalized_fq_name,
};
pub(in crate::analyzer::usages) use syntax::{node_text as scala_node_text, scala_import_path};

pub(crate) fn build_scala_usage_edges<F>(
    analyzer: &dyn IAnalyzer,
    nodes: &HashSet<String>,
    keep_file: F,
) -> Option<UsageEdges>
where
    F: Fn(&ProjectFile) -> bool + Sync,
{
    let resolver = ScalaEdgeResolver::try_new(analyzer)?;
    Some(resolver.build_edges(analyzer, nodes, keep_file))
}

pub(crate) fn build_scala_usage_edge_weights<F>(
    analyzer: &dyn IAnalyzer,
    nodes: &HashSet<String>,
    keep_file: F,
) -> Option<UsageEdgeWeights>
where
    F: Fn(&ProjectFile) -> bool + Sync,
{
    let resolver = ScalaEdgeResolver::try_new(analyzer)?;
    Some(resolver.build_edge_weights(analyzer, nodes, keep_file))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ScalaDeadCodeBulkEligibility {
    BulkSafe,
    NeedsPrecise,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct ScalaDeadCodeBulkContext {
    wildcard_owner_imports: HashSet<String>,
    direct_member_imports: HashSet<String>,
}

impl ScalaDeadCodeBulkContext {
    pub(crate) fn from_analyzer(analyzer: &dyn IAnalyzer) -> Option<Self> {
        let scala = resolve_analyzer::<ScalaAnalyzer>(analyzer)?;
        let mut context = Self::default();
        let files: Vec<_> = scala.get_analyzed_files().into_iter().collect();
        let imports_by_file = scala.bulk_import_infos(files.clone());
        for file in files {
            for import in imports_by_file.get(&file).into_iter().flatten() {
                let Some(path) = scala_import_path(import) else {
                    continue;
                };
                let normalized_path = scala_normalized_fq_name(&path);
                if import.is_wildcard {
                    context.wildcard_owner_imports.insert(normalized_path);
                } else {
                    context.direct_member_imports.insert(normalized_path);
                }
            }
        }
        Some(context)
    }

    fn imports_can_expose_member(&self, spec: &TargetSpec) -> bool {
        let Some(owner_fq_name) = spec.owner_fq_name.as_deref() else {
            return false;
        };
        let normalized_owner = scala_normalized_fq_name(owner_fq_name);
        normalized_import_paths_contain(&self.wildcard_owner_imports, &normalized_owner)
            || normalized_import_paths_contain(&self.direct_member_imports, &spec.target_fq_name)
    }
}

fn normalized_import_paths_contain(paths: &HashSet<String>, target_fq_name: &str) -> bool {
    paths.contains(target_fq_name)
        || target_fq_name
            .match_indices('.')
            .any(|(separator, _)| paths.contains(&target_fq_name[separator + 1..]))
}

pub(crate) fn dead_code_bulk_eligibility(
    analyzer: &dyn IAnalyzer,
    target: &CodeUnit,
    overloaded_fqns: &HashSet<String>,
    context: &ScalaDeadCodeBulkContext,
) -> ScalaDeadCodeBulkEligibility {
    let Some(scala) = resolve_analyzer::<ScalaAnalyzer>(analyzer) else {
        return ScalaDeadCodeBulkEligibility::NeedsPrecise;
    };
    let Some(spec) = TargetSpec::from_target(scala, target) else {
        return ScalaDeadCodeBulkEligibility::NeedsPrecise;
    };

    match spec.kind {
        TargetKind::Type => ScalaDeadCodeBulkEligibility::BulkSafe,
        TargetKind::Method if spec.owner.is_none() => ScalaDeadCodeBulkEligibility::NeedsPrecise,
        TargetKind::Method if scala.signatures(target).len() > 1 => {
            ScalaDeadCodeBulkEligibility::NeedsPrecise
        }
        TargetKind::Method if overloaded_fqns.contains(target.fq_name().as_str()) => {
            ScalaDeadCodeBulkEligibility::NeedsPrecise
        }
        TargetKind::Method if context.imports_can_expose_member(&spec) => {
            ScalaDeadCodeBulkEligibility::NeedsPrecise
        }
        TargetKind::Method => ScalaDeadCodeBulkEligibility::BulkSafe,
        TargetKind::Constructor | TargetKind::Field => ScalaDeadCodeBulkEligibility::NeedsPrecise,
    }
}

#[derive(Default)]
pub struct ScalaUsageGraphStrategy {
    _private: (),
}

impl ScalaUsageGraphStrategy {
    pub fn new() -> Self {
        Self { _private: () }
    }

    pub fn can_handle(target: &CodeUnit) -> bool {
        language_for_target(target) == Language::Scala
    }

    pub(crate) fn find_graph_usages(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        scan_scope: &UsageScanScope<'_>,
        max_usages: usize,
    ) -> GraphUsageOutcome {
        if overloads.is_empty() {
            return GraphUsageOutcome::Resolved(FuzzyResult::empty_success());
        }

        let target = &overloads[0];
        if language_for_target(target) != Language::Scala {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::UnsupportedTargetLanguage("target is not Scala"),
                "ScalaUsageGraphStrategy",
            );
        }

        let Some(resolver) = ScalaQueryResolver::try_new(analyzer) else {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::MissingAnalyzerCapability(
                    "analyzer does not expose ScalaAnalyzer",
                ),
                "ScalaUsageGraphStrategy",
            );
        };

        resolver.find_usages(analyzer, overloads, scan_scope, max_usages)
    }
}

impl UsageAnalyzer for ScalaUsageGraphStrategy {
    fn find_usages(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        candidate_files: &HashSet<ProjectFile>,
        max_usages: usize,
    ) -> FuzzyResult {
        let scan_scope = UsageScanScope::new(candidate_files, false);
        self.find_graph_usages(analyzer, overloads, &scan_scope, max_usages)
            .into_fuzzy_result()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::{Project, TestProject};
    use std::sync::Arc;

    #[test]
    fn scala_inverted_keeps_companion_bare_field_owners_exact() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let file = ProjectFile::new(root.clone(), "app/CompanionFields.scala");
        file.write(
            r#"package app
import svc.Service

class Obj {
  def classRead: Int = field
  def classShadow: Int = { val field: Int = 4; field }
  val field: Int = 1
}
object Obj {
  def objectRead: Int = field
  def objectShadow: Int = { val field: Int = 5; field }
  val field: Int = 2
}
object Sibling {
  val field: Int = 3
  def siblingRead: Int = field
}
class Params(val first: Int, var second: Int) {
  def read: Int = first + second
  def shadow(first: Int): Int = first
}
class ScopeLeak {
  { val Service: Int = 0 }
  def call: Int = Service.run()
}
object Stable {
  val Enabled: Int = 1
}
object Decoy {
  val Enabled: Int = 2
}
class StableHolder {
  val Enabled: Int = 3
}
object StableUse {
  def direct: Int = Stable.Enabled
  def stable(value: Any): Int = value match {
    case Stable.Enabled => 1
    case _ => 0
  }
  def packageStable(value: Any): Int = value match {
    case app.Stable.Enabled => 1
    case _ => 0
  }
  def localRoot(Stable: StableHolder): Int = Stable.Enabled
  def decoy: Int = Decoy.Enabled
}
"#,
        )
        .unwrap();
        let service_file = ProjectFile::new(root.clone(), "svc/Service.scala");
        service_file
            .write("package svc\nobject Service { def run(): Int = 1 }\n")
            .unwrap();
        let project = TestProject::new(root, Language::Scala);
        let analyzer = ScalaAnalyzer::new(Arc::new(project));
        let nodes: HashSet<String> = analyzer
            .all_declarations()
            .map(|unit| unit.fq_name())
            .collect();
        let edges = build_scala_usage_edges(&analyzer, &nodes, |_| true)
            .expect("Scala inverted edge build should succeed");

        let has_edge = |caller: &str, callee: &str| {
            edges
                .edges
                .contains_key(&(caller.to_string(), callee.to_string()))
        };
        assert!(has_edge("app.Obj$.objectRead", "app.Obj$.field"));
        assert!(!has_edge("app.Obj.classRead", "app.Obj$.field"));
        assert!(!has_edge("app.Sibling$.siblingRead", "app.Obj$.field"));
        assert!(has_edge("app.Obj.classRead", "app.Obj.field"));
        assert!(!has_edge("app.Obj$.objectRead", "app.Obj.field"));
        assert!(!has_edge("app.Obj.classShadow", "app.Obj.field"));
        assert!(!has_edge("app.Obj$.objectShadow", "app.Obj$.field"));
        assert!(has_edge("app.Params.read", "app.Params.first"));
        assert!(has_edge("app.Params.read", "app.Params.second"));
        assert!(!has_edge("app.Params.shadow", "app.Params.first"));
        assert!(has_edge("app.ScopeLeak.call", "svc.Service$.run"));
        assert!(has_edge("app.StableUse$.direct", "app.Stable$.Enabled"));
        assert!(has_edge("app.StableUse$.stable", "app.Stable$.Enabled"));
        assert!(has_edge(
            "app.StableUse$.packageStable",
            "app.Stable$.Enabled"
        ));
        assert!(!has_edge("app.StableUse$.localRoot", "app.Stable$.Enabled"));
        assert!(!has_edge("app.StableUse$.decoy", "app.Stable$.Enabled"));
    }

    #[test]
    fn scala_inverted_resolves_exact_structured_field_chains() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let write = |path: &str, source: &str| {
            ProjectFile::new(root.clone(), path).write(source).unwrap();
        };
        write(
            "model/Fields.scala",
            r#"package model
class Leaf(val token: Int)
class Middle(val leaf: Leaf)
class Base(val inherited: Middle)
class Child extends Base(new Middle(new Leaf(1))) {
  def inheritedBare: Int = inherited.leaf.token
  def inheritedShadow(inherited: other.Middle): Int = inherited.leaf.token
}
object Stable { val middle: Middle = new Middle(new Leaf(2)) }
object Owners { final class State(var maximumHeapSize: Int) }
object AliasOnly { type Value = Int }
object Result {
  opaque type Success[A] = A
  object Success
}
"#,
        );
        write(
            "other/Fields.scala",
            "package other\nclass Leaf(val token: Int)\nclass Middle(val leaf: Leaf)\n",
        );
        write(
            "dup/First.scala",
            "package dup\nclass Owner(val value: Int)\n",
        );
        write(
            "dup/Second.scala",
            "package dup\nclass Owner(val value: Int)\n",
        );
        write(
            "root/api/Types.scala",
            "package root.api\nclass ActorContext\n",
        );
        write(
            "decoy/Objects.scala",
            "package decoy\nobject Api { class ActorContext }\n",
        );
        write(
            "collision/Api.scala",
            "package collision\nobject Api { class ActorContext }\n",
        );
        write(
            "app/collision/Api.scala",
            "package app.collision\nobject Api { class ActorContext }\n",
        );
        write(
            "app/Use.scala",
            r#"package app
import model.*
import root.{api => mixed}
import decoy.{Api => mixed}
import collision.{Api => overlap}

class ImportedChild extends Child {
  def inheritedBare: Middle = inherited
}

object Use {
  def typed(middle: Middle): Int = middle.leaf.token
  def inherited(child: Child): Int = child.inherited.leaf.token
  def stable: Int = Stable.middle.leaf.token
  def nested: Int = { val state = new Owners.State(1); state.maximumHeapSize }
  def localShadow(middle: other.Middle): Int = middle.leaf.token
  def ambiguous(owner: dup.Owner): Int = owner.value
  def aliasIsNotATerm: Any = AliasOnly.Value
  def stableTypeMember: Result.Success[Int] = 1
  def stableTermMember: Any = Result.Success
  def ambiguousPackageObject: mixed.ActorContext = null
  def relativeObjectImport: overlap.ActorContext = null
}
"#,
        );

        let project = TestProject::new(root, Language::Scala);
        let analyzer = ScalaAnalyzer::new(Arc::new(project));
        let nodes: HashSet<String> = analyzer
            .all_declarations()
            .map(|unit| unit.fq_name())
            .collect();
        let edges = build_scala_usage_edges(&analyzer, &nodes, |_| true)
            .expect("Scala inverted field-chain build should succeed");
        let has_edge = |caller: &str, callee: &str| {
            edges
                .edges
                .contains_key(&(caller.to_string(), callee.to_string()))
        };

        for caller in ["app.Use$.typed", "app.Use$.inherited", "app.Use$.stable"] {
            assert!(
                has_edge(caller, "model.Middle.leaf"),
                "missing {caller} -> leaf"
            );
            assert!(
                has_edge(caller, "model.Leaf.token"),
                "missing {caller} -> token"
            );
        }
        assert!(has_edge(
            "model.Child.inheritedBare",
            "model.Base.inherited"
        ));
        assert!(has_edge("model.Child.inheritedBare", "model.Middle.leaf"));
        assert!(has_edge("model.Child.inheritedBare", "model.Leaf.token"));
        assert!(has_edge("app.Use$.inherited", "model.Base.inherited"));
        assert!(has_edge("app.Use$.stable", "model.Stable$.middle"));
        assert!(has_edge(
            "app.ImportedChild.inheritedBare",
            "model.Base.inherited"
        ));
        assert!(has_edge(
            "app.Use$.stableTypeMember",
            "model.Result$.Success"
        ));
        assert!(has_edge(
            "app.Use$.nested",
            "model.Owners$.State.maximumHeapSize"
        ));

        for caller in ["app.Use$.localShadow", "model.Child.inheritedShadow"] {
            assert!(!has_edge(caller, "model.Middle.leaf"));
            assert!(!has_edge(caller, "model.Leaf.token"));
        }
        assert!(!has_edge("app.Use$.ambiguous", "dup.Owner.value"));
        assert!(!has_edge(
            "app.Use$.aliasIsNotATerm",
            "model.AliasOnly$.Value"
        ));
        assert!(!has_edge(
            "app.Use$.stableTermMember",
            "model.Result$.Success"
        ));
        for callee in ["root.api.ActorContext", "decoy.Api$.ActorContext"] {
            assert!(!has_edge("app.Use$.ambiguousPackageObject", callee));
        }
        assert!(has_edge(
            "app.Use$.relativeObjectImport",
            "app.collision.Api$.ActorContext"
        ));
        assert!(!has_edge(
            "app.Use$.relativeObjectImport",
            "collision.Api$.ActorContext"
        ));
    }

    #[test]
    fn scala_usage_graph_bulk_fetch_bypasses_lru_and_preserves_point_entry() {
        const FILE_COUNT: usize = 132;
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        for index in 0..FILE_COUNT {
            let file = ProjectFile::new(root.clone(), format!("C{index}.scala"));
            let source = if index == 0 {
                "package bulk\n\ntrait Base\n\nobject Extensions {\n  extension (value: String) def run(): Unit = ()\n}\n\nclass C0 extends Base\n".to_string()
            } else {
                format!(
                    "package bulk\n\nimport bulk.Extensions.run\n\nclass C{index} extends Base\n"
                )
            };
            file.write(source).unwrap();
        }

        let project = TestProject::new(root, Language::Scala);
        let analyzer = ScalaAnalyzer::new(Arc::new(project.clone()));
        let warm_file = ProjectFile::new(project.root().to_path_buf(), "C0.scala");

        analyzer.reset_full_hydration_count_for_test();
        assert!(!analyzer.declarations(&warm_file).is_empty());
        let lru_after_warm = analyzer.full_hydration_count_for_test();
        assert_eq!(lru_after_warm, 1);

        let nodes: HashSet<String> = analyzer
            .all_declarations()
            .map(|unit| unit.fq_name())
            .collect();
        let _edges = build_scala_usage_edges(&analyzer, &nodes, |_| true)
            .expect("scala usage graph should build");
        assert_eq!(
            analyzer.full_hydration_count_for_test(),
            lru_after_warm,
            "whole-workspace graph build must not hydrate through the LRU path"
        );
        assert_eq!(
            analyzer.bulk_hydration_count_for_test(),
            FILE_COUNT,
            "bulk hydrations should be exactly one per file"
        );

        assert!(!analyzer.declarations(&warm_file).is_empty());
        assert_eq!(
            analyzer.full_hydration_count_for_test(),
            lru_after_warm,
            "point query warmed before graph build should still hit the LRU"
        );
    }
}
