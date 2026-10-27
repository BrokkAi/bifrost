pub(crate) mod shared;

use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;

use brokk_bifrost_analysis::analyzer::usages::traits::GraphUsageAnalyzer;
use brokk_bifrost_core::analyzer::query_token::QueryToken;

use brokk_bifrost_analysis::analyzer::usages::common::language_for_target;

use brokk_bifrost_analysis::analyzer::usages::inverted_edges::UsageEdgeBuildResult;

use brokk_bifrost_core::analyzer::usages::inverted_edges::UsageEdgeWeights;

use brokk_bifrost_core::analyzer::usages::inverted_edges::UsageEdges;
#[cfg(test)]
use brokk_bifrost_core::analyzer::usages::model::FuzzyResult;

use brokk_bifrost_core::analyzer::usages::outcome::GraphUsageOutcome;

use crate::analyzer::usages::scala_graph::shared::ScalaEdgeResolver;

use crate::analyzer::usages::scala_graph::shared::ScalaQueryResolver;

use brokk_bifrost_analysis::analyzer::usages::traits::GraphUsageDispatchSpec;

use brokk_bifrost_core::analyzer::usages::scan_scope::UsageScanScope;

use brokk_bifrost_core::analyzer::model::CodeUnit;

use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

use brokk_bifrost_core::analyzer::model::Language;

use brokk_bifrost_core::analyzer::model::ProjectFile;

use crate::analyzer::ScalaAnalyzer;

use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;

use brokk_bifrost_core::hash::HashSet;

use brokk_bifrost_jvm::scala::graph::resolver::TargetKind;

use brokk_bifrost_jvm::scala::graph::resolver::TargetSpec;

pub(in crate::analyzer::usages) use brokk_bifrost_jvm::scala::graph::resolver::scala_normalized_fq_name;

pub(in crate::analyzer::usages) use brokk_bifrost_jvm::scala::graph::syntax::scala_import_path;

#[cfg(test)]
pub(crate) fn build_scala_usage_edges<F>(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    nodes: &HashSet<String>,
    keep_file: F,
) -> Option<UsageEdges>
where
    F: Fn(&ProjectFile) -> bool + Sync,
{
    let resolver = ScalaEdgeResolver::try_new(analyzer)?;
    Some(resolver.build_edges(analyzer, token, nodes, keep_file))
}

pub(crate) fn build_rooted_scala_usage_edges<F>(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    callers: &HashSet<String>,
    keep_file: F,
) -> Option<UsageEdges>
where
    F: Fn(&ProjectFile) -> bool + Sync,
{
    let resolver = ScalaEdgeResolver::try_new(analyzer)?;
    Some(resolver.build_rooted_edges(analyzer, token, callers, keep_file))
}

pub(crate) fn build_inbound_scala_usage_edges_with_completeness(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    callees: &HashSet<String>,
) -> Option<UsageEdgeBuildResult<UsageEdges>> {
    let resolver = ScalaEdgeResolver::try_new(analyzer)?;
    Some(resolver.build_inbound_edges_with_completeness(analyzer, token, callees, |_| true))
}

pub(crate) fn build_scala_usage_edge_weights<F>(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    nodes: &HashSet<String>,
    keep_file: F,
) -> Option<UsageEdgeWeights>
where
    F: Fn(&ProjectFile) -> bool + Sync,
{
    let resolver = ScalaEdgeResolver::try_new(analyzer)?;
    Some(resolver.build_edges(analyzer, token, nodes, keep_file))
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
    token: QueryToken<'_>,
    target: &CodeUnit,
    overloaded_fqns: &HashSet<String>,
    context: &ScalaDeadCodeBulkContext,
) -> ScalaDeadCodeBulkEligibility {
    let Some(scala) = resolve_analyzer::<ScalaAnalyzer>(analyzer) else {
        return ScalaDeadCodeBulkEligibility::NeedsPrecise;
    };
    let types = scala.project_types();
    let Some(spec) = TargetSpec::from_target(scala, token, &types, target) else {
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
    pub const fn new() -> Self {
        Self { _private: () }
    }

    pub fn can_handle(target: &CodeUnit) -> bool {
        language_for_target(target) == Language::Scala
    }
}

impl GraphUsageAnalyzer for ScalaUsageGraphStrategy {
    fn find_graph_usages(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        scan_scope: &UsageScanScope<'_>,
        max_usages: usize,
    ) -> GraphUsageOutcome {
        brokk_bifrost_analysis::analyzer::usages::traits::dispatch_graph_usage_query::<
            ScalaQueryResolver<'_>,
        >(
            analyzer,
            overloads,
            scan_scope,
            max_usages,
            GraphUsageDispatchSpec {
                target_language: Language::Scala,
                unsupported_target: "target is not Scala",
                missing_analyzer: "analyzer does not expose ScalaAnalyzer",
                strategy: "ScalaUsageGraphStrategy",
            },
        )
    }
}

#[cfg(test)]
mod tests {

    use crate::analyzer::usages::scala_graph::*;

    use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;

    use brokk_bifrost_core::analyzer::query_token::QueryScope;

    use brokk_bifrost_core::analyzer::project::Project;

    use brokk_bifrost_core::analyzer::project::TestProject;
    use brokk_bifrost_test_macros::hardwon;
    use std::sync::Arc;

    #[test]
    #[hardwon("#6942: receiver_type_declaration recursion depth followed source nesting")]
    fn scala_receiver_type_declaration_deep_fields_are_stack_safe() {
        use brokk_bifrost_core::analyzer::tree_walk::node_range;
        use brokk_bifrost_core::analyzer::usages::inverted_edges::{
            ClassRangeIndex, FileDeclarations, FileEdgeScanInput,
        };
        use brokk_bifrost_core::hash::HashMap;
        use brokk_bifrost_core::text_utils::compute_line_starts;
        use brokk_bifrost_jvm::scala::graph::inverted::scan_edge_file;

        let depth = 3000;
        let source = format!(
            "package app\nclass Link {{ val next: Link = this; def end(): Int = 1; def deep(): Int = this{}.end() }}",
            ".next".repeat(depth)
        );
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&brokk_bifrost_jvm::scala::language::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(&source, None).unwrap();
        assert!(!tree.root_node().has_error());
        let mut longest = 0;
        let mut declarations = FileDeclarations {
            enclosers: Vec::new(),
            definitions: HashMap::default(),
        };
        brokk_bifrost_core::analyzer::tree_walk::walk_named_tree_preorder(
            tree.root_node(),
            true,
            |node| {
                if node.kind() == "function_definition" {
                    let name = node
                        .child_by_field_name("name")
                        .unwrap()
                        .utf8_text(source.as_bytes())
                        .unwrap();
                    let key = format!("app.Link.{name}");
                    declarations
                        .enclosers
                        .push((node.start_byte(), node.end_byte(), key.clone()));
                    declarations
                        .definitions
                        .insert(key, vec![(node.start_byte(), node.end_byte())]);
                }
                if node.kind() == "call_expression" {
                    let mut value = node.child_by_field_name("function").unwrap();
                    let mut count = 0;
                    while value.kind() == "field_expression" {
                        count += 1;
                        value = value.child_by_field_name("value").unwrap();
                    }
                    longest = longest.max(count);
                }
                brokk_bifrost_core::analyzer::tree_walk::WalkControl::Continue
            },
        );
        assert_eq!(longest, depth + 1);
        eprintln!("receiver_type_declaration: parsed {longest} field values");
        let project = crate::inline_project::InlineTestProject::with_language(Language::Scala)
            .file("Link.scala", "package app\nclass Link { val next: Link = this; def end(): Int = 1; def deep(): Int = this.end() }")
            .build();
        let analyzer = ScalaAnalyzer::new(project.project_dyn());
        // Index the declarations without sending the deep body through the unrelated
        // native fact producer. The edge scanner consumes its own parsed query tree.
        let types = analyzer.project_types();
        let file = project.file("Link.scala");
        let state = types.bulk_file_state(&file).unwrap();
        let link = analyzer
            .get_definitions("app.Link")
            .into_iter()
            .find(CodeUnit::is_class)
            .unwrap();
        let class_ranges =
            ClassRangeIndex::from_class_spans([(link, node_range(tree.root_node()))]);
        let line_starts = compute_line_starts(&source);
        let nodes = HashSet::from_iter(["app.Link.deep".to_owned(), "app.Link.end".to_owned()]);
        std::thread::scope(|scope| {
            std::thread::Builder::new()
                .stack_size(128 * 1024)
                .spawn_scoped(scope, || {
                    let query = AnalyzerQueryScope::new(&analyzer);
                    let input = FileEdgeScanInput::new(
                        &tree,
                        &source,
                        &line_starts,
                        Language::Scala,
                        &nodes,
                        &declarations,
                    );
                    let edges = scan_edge_file(
                        &analyzer,
                        query.token(),
                        &types,
                        &file,
                        &state,
                        class_ranges,
                        &input,
                    );
                    assert!(
                        edges
                            .edge_lines
                            .contains_key(&("app.Link.deep".to_owned(), "app.Link.end".to_owned())),
                        "the deep call must produce an edge: {:?}",
                        edges.edge_lines
                    );
                })
                .unwrap()
                .join()
                .unwrap();
        });
    }

    #[test]
    #[hardwon(
        "#2844: A complete real Scala inbound graph is reused by dead-code lookup without invoking the builder again"
    )]
    fn complete_inbound_graph_is_reused_by_the_dead_code_cache() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let file = ProjectFile::new(root.clone(), "Target.scala");
        file.write("package app\nclass Target\n").unwrap();
        let analyzer = ScalaAnalyzer::new(Arc::new(TestProject::new(root, Language::Scala)));
        let callees = HashSet::from_iter(["app.Target".to_string()]);

        let first =
            brokk_bifrost_analysis::analyzer::usages::inverted_edges::cached_dead_code_usage_edges(
                &analyzer,
                &analyzer.dead_code_usage_edges,
                &callees,
                |token| {
                    build_inbound_scala_usage_edges_with_completeness(&analyzer, token, &callees)
                },
            )
            .expect("complete Scala graph should be cached");
        let second =
            brokk_bifrost_analysis::analyzer::usages::inverted_edges::cached_dead_code_usage_edges(
                &analyzer,
                &analyzer.dead_code_usage_edges,
                &callees,
                |_| panic!("canonical target set should hit the Scala dead-code cache"),
            )
            .expect("cached Scala graph should be returned");

        assert!(Arc::ptr_eq(&first, &second));
    }

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
        let scope = AnalyzerQueryScope::new(&analyzer);
        let token = scope.token();
        let edges = build_scala_usage_edges(&analyzer, token, &nodes, |_| true)
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
type Maybe[A] = Option[A]
infix type <[A, B] = Either[A, B]
object Stable { val middle: Middle = new Middle(new Leaf(2)) }
object Owners { final class State(var maximumHeapSize: Int) }
object AliasOnly { type Value = Int }
object Result {
  opaque type Success[A] = A
  object Success
}
object SupervisorStrategy {
  type Decider = Throwable => String
  trait Strategy { def decider: Decider }
}
object ClusterShardingSettings {
  object PassivationStrategySettings { final class AdmissionSettings }
  final class Settings(
    val admission: Option[PassivationStrategySettings.AdmissionSettings]
  )
}
trait FSM {
  case class EventData(value: Int)
  val Event = EventData
}
final class Manager extends FSM {
  def receive(value: Any): Int = value match {
    case Event(number) => number
    case _ => 0
  }
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
  def packageAlias: Maybe[Int] = None
  def packageOperator: Int < String = Left(1)
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
        let scope = AnalyzerQueryScope::new(&analyzer);
        let token = scope.token();
        let edges = build_scala_usage_edges(&analyzer, token, &nodes, |_| true)
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
        assert!(has_edge("app.Use$.packageAlias", "model.Maybe"));
        assert!(has_edge("app.Use$.packageOperator", "model.<"));
        assert!(has_edge(
            "model.SupervisorStrategy$.Strategy.decider",
            "model.SupervisorStrategy$.Decider"
        ));
        assert!(has_edge(
            "model.ClusterShardingSettings$.Settings.admission",
            "model.ClusterShardingSettings$.PassivationStrategySettings$.AdmissionSettings"
        ));
        assert!(has_edge("model.Manager.receive", "model.FSM.Event"));
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

    #[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
    #[test]
    fn scala_usage_graph_bulk_fetch_bypasses_lru_and_preserves_point_entry() {
        const FILE_COUNT: usize = 132;
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        for index in 0..FILE_COUNT {
            let file = ProjectFile::new(root.clone(), format!("C{index}.scala"));
            let source = if index == 0 {
                "package bulk\n\ntrait Base\n\nobject Extensions {\n  extension (value: String) def run(): Unit = ()\n}\n\nclass C0 extends Base {\n  type Alias = String\n  class Nested\n  def alias(value: Alias): Alias = value\n  def nested(value: Nested): Nested = value\n}\n".to_string()
            } else {
                format!(
                    "package bulk\n\nimport bulk.Extensions.run\n\nclass C{index} extends Base {{\n  type Alias = String\n  class Nested\n  def alias(value: Alias): Alias = value\n  def nested(value: Nested): Nested = value\n}}\n"
                )
            };
            file.write(source).unwrap();
        }
        let project = TestProject::new(root, Language::Scala);
        let mut analyzer = ScalaAnalyzer::new(Arc::new(project.clone()));
        let warm_file = ProjectFile::new(project.root().to_path_buf(), "C0.scala");

        analyzer.clear_retained_file_states_for_test();
        analyzer.reset_full_hydration_count_for_test();
        assert!(!analyzer.declarations(&warm_file).is_empty());
        let lru_after_warm = analyzer.full_hydration_count_for_test();
        assert_eq!(lru_after_warm, 1);

        let nodes: HashSet<String> = analyzer
            .all_declarations()
            .map(|unit| unit.fq_name())
            .collect();
        assert_eq!(
            analyzer.full_hydration_count_for_test(),
            lru_after_warm,
            "declaration cataloging must not hydrate through the LRU path"
        );
        let scope = AnalyzerQueryScope::new(&analyzer);
        let token = scope.token();
        let _edges = build_scala_usage_edges(&analyzer, token, &nodes, |_| true)
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

    /// #3142: a targeted find-references query sweeps the workspace once for
    /// the seed's derived structures but materializes full per-file facts only
    /// for the files the query actually scans or resolves through. Here the
    /// workspace spreads one package per file, the scan set is one file, and
    /// the target's package closure is one more: the touched set is a
    /// handful, not the workspace.

    #[test]
    fn scala_targeted_query_materializes_facts_only_for_touched_files() {
        const FILE_COUNT: usize = 132;
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        for index in 0..FILE_COUNT {
            let file = ProjectFile::new(root.clone(), format!("C{index}.scala"));
            let source = if index == 0 {
                "package p0\n\nclass Leaf\n".to_string()
            } else if index == 5 {
                "package p5\n\nimport p0.Leaf\n\nclass UsesLeaf {\n  def make: Leaf = new Leaf\n}\n"
                    .to_string()
            } else {
                format!("package p{index}\n\nclass C{index}\n")
            };
            file.write(source).unwrap();
        }
        let project = TestProject::new(root.clone(), Language::Scala);
        let analyzer = ScalaAnalyzer::new(Arc::new(project));
        let target = analyzer
            .all_declarations()
            .find(|unit| unit.fq_name() == "p0.Leaf")
            .expect("the corpus declares p0.Leaf");
        let scanned = ProjectFile::new(root, "C5.scala");
        let candidates = HashSet::from_iter([scanned.clone()]);

        use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerTestHooks;

        use brokk_bifrost_analysis::analyzer::usages::traits::UsageAnalyzer;
        analyzer.reset_full_hydration_count_for_test();
        analyzer.reset_scala_query_file_facts_touched_for_test();
        let bulk_before = analyzer.bulk_hydration_count_for_test();

        let result = ScalaUsageGraphStrategy::new().find_usages(
            &analyzer,
            std::slice::from_ref(&target),
            &candidates,
            1000,
        );
        let FuzzyResult::Success {
            hits_by_overload, ..
        } = result
        else {
            panic!("expected a successful usage query, got {result:?}");
        };
        let hits = hits_by_overload
            .get(&target)
            .expect("the query target keys the hits");
        assert!(
            hits.iter().any(|hit| hit.file == scanned),
            "expected the C5 `new Leaf` site among {hits:?}",
        );

        // The sweep hydrates every workspace file once; the provider hydrates
        // each touched file once. Nothing hydrates twice.
        let touched = analyzer.scala_query_file_facts_touched_for_test();
        assert_eq!(
            analyzer.bulk_hydration_count_for_test() - bulk_before,
            FILE_COUNT + touched,
            "sweep hydrates each file once, provider hydrates each touched file once",
        );
        assert_eq!(
            touched, 2,
            "only the target's file and the scanned file materialize full per-file facts",
        );
    }
}
