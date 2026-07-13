mod extractor;
mod hits;
mod inverted;
mod resolver;
mod shared;
pub(super) mod syntax;

use crate::analyzer::usages::common::language_for_target;
use crate::analyzer::usages::inverted_edges::UsageEdges;
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
        self.wildcard_owner_imports.contains(owner_fq_name)
            || self.direct_member_imports.contains(&spec.target_fq_name)
    }
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
    fn scala_usage_graph_bulk_fetch_bypasses_lru_and_preserves_point_entry() {
        const FILE_COUNT: usize = 132;
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        for index in 0..FILE_COUNT {
            let file = ProjectFile::new(root.clone(), format!("C{index}.scala"));
            file.write(format!(
                "package bulk\n\nclass C{index} {{\n  def run(): Unit = ()\n}}\n"
            ))
            .unwrap();
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
        let edges = build_scala_usage_edges(&analyzer, &nodes, |_| true)
            .expect("scala usage graph should build");
        assert!(
            edges.edges.is_empty(),
            "fixture has no calls, only exercises graph file-state reads"
        );
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
