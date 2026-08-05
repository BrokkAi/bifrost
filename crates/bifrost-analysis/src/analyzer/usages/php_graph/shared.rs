use super::{PhpAnalyzerFacts, php_graph_source};
use crate::analyzer::usages::common::{analyzed_files_for_language, language_for_file};
use crate::analyzer::usages::inverted_edges::{
    UsageEdgeBuildOutput, UsageEdgeWeights, UsageEdges, build_edge_output, parse_and_collect,
};
use crate::analyzer::usages::model::{FuzzyResult, UsageHit};
use crate::analyzer::usages::outcome::{GraphFailureReason, GraphUsageOutcome};
use crate::analyzer::usages::traits::{UsageQueryResolver, UsageScanScope};
use crate::analyzer::{CodeUnit, IAnalyzer, Language, PhpAnalyzer, ProjectFile, resolve_analyzer};
use crate::hash::HashSet;
use brokk_bifrost_php::graph::extractor::scan_file;
use brokk_bifrost_php::graph::hits::push_override_declaration_hit;
use brokk_bifrost_php::graph::inverted::scan_php_file;
use brokk_bifrost_php::graph::resolver::{PhpHierarchyIndex, TargetKind, TargetSpec};
use std::collections::BTreeSet;

pub(crate) struct PhpQueryResolver<'a> {
    php: &'a PhpAnalyzer,
}

impl<'a> UsageQueryResolver<'a> for PhpQueryResolver<'a> {
    fn try_new(analyzer: &'a dyn IAnalyzer) -> Option<Self> {
        Some(Self {
            php: resolve_analyzer::<PhpAnalyzer>(analyzer)?,
        })
    }

    fn find_usages(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        scan_scope: &UsageScanScope<'_>,
        max_usages: usize,
    ) -> GraphUsageOutcome {
        let Some(target) = overloads.first() else {
            return GraphUsageOutcome::Resolved(FuzzyResult::empty_success());
        };
        let Some(spec) = TargetSpec::from_target(self.php, target) else {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::UnsupportedTargetShape("unsupported target shape"),
                "PhpUsageGraphStrategy",
            );
        };

        let candidate_files = scan_scope.candidate_files();
        let mut files: HashSet<ProjectFile> = candidate_files
            .iter()
            .filter(|file| language_for_file(file) == Language::Php)
            .cloned()
            .collect();
        if scan_scope.allows(target.source()) {
            files.insert(target.source().clone());
        }

        let facts = PhpAnalyzerFacts(analyzer);
        let source = php_graph_source(analyzer, &facts);
        let hierarchy = matches!(
            spec.kind,
            TargetKind::Constructor | TargetKind::Method | TargetKind::Field
        )
        .then(|| PhpHierarchyIndex::for_target_owner(self.php, &spec));
        let empty_hierarchy = PhpHierarchyIndex::default();
        let hierarchy = hierarchy.as_ref().unwrap_or(&empty_hierarchy);
        let mut hits: BTreeSet<UsageHit> = BTreeSet::new();
        for override_declaration in
            hierarchy.overriding_methods(self.php, &spec, &files, scan_scope.cancellation())
        {
            if scan_scope.is_cancelled() {
                break;
            }
            push_override_declaration_hit(self.php, source, &override_declaration, &mut hits);
        }
        for file in files {
            if scan_scope.is_cancelled() {
                break;
            }
            scan_file(self.php, source, &file, &spec, hierarchy, &mut hits);
            let external_callsites =
                crate::analyzer::usages::common::external_usage_hit_count(&hits);
            if external_callsites > max_usages {
                return GraphUsageOutcome::Resolved(FuzzyResult::TooManyCallsites {
                    short_name: target.short_name().to_string(),
                    total_callsites: external_callsites,
                    limit: max_usages,
                    sample_hits: hits,
                });
            }
        }

        GraphUsageOutcome::Resolved(FuzzyResult::success(target.clone(), hits))
    }
}

pub(crate) struct PhpEdgeResolver<'a> {
    php: &'a PhpAnalyzer,
    files: Vec<ProjectFile>,
}

/// The whole-workspace `caller -> callee` scan behind this language's
/// [`LanguageEdgePass`](crate::analyzer::languages::LanguageEdgePass): borrow the concrete
/// analyzer once, then walk every file once and finalize into either site-bearing edges or
/// reference-kind weights.
impl<'a> PhpEdgeResolver<'a> {
    pub(crate) fn try_new(analyzer: &'a dyn IAnalyzer) -> Option<Self> {
        let php = resolve_analyzer::<PhpAnalyzer>(analyzer)?;
        let files = analyzed_files_for_language(analyzer, Language::Php);
        Some(Self { php, files })
    }

    pub(crate) fn build_edges<F>(
        &self,
        analyzer: &dyn IAnalyzer,
        nodes: &HashSet<String>,
        keep_file: F,
    ) -> UsageEdges
    where
        F: Fn(&ProjectFile) -> bool + Sync,
    {
        self.build_php_edges(analyzer, nodes, keep_file)
    }

    pub(crate) fn build_edge_weights<F>(
        &self,
        analyzer: &dyn IAnalyzer,
        nodes: &HashSet<String>,
        keep_file: F,
    ) -> UsageEdgeWeights
    where
        F: Fn(&ProjectFile) -> bool + Sync,
    {
        self.build_php_edges(analyzer, nodes, keep_file)
    }

    /// The inverted pass's fan-out: the shared driver's parallel walk plus
    /// on-demand parsing, with [`scan_php_file`] resolving each file. Both halves
    /// of that split are deliberate -- `build_edge_output` and `parse_and_collect`
    /// are the language-agnostic driver and stay here, exactly as Python's do.
    fn build_php_edges<Output, F>(
        &self,
        analyzer: &dyn IAnalyzer,
        nodes: &HashSet<String>,
        keep_file: F,
    ) -> Output
    where
        Output: UsageEdgeBuildOutput<String>,
        F: Fn(&ProjectFile) -> bool + Sync,
    {
        let facts = PhpAnalyzerFacts(analyzer);
        let source = php_graph_source(analyzer, &facts);
        let language = tree_sitter_php::LANGUAGE_PHP.into();
        build_edge_output(&self.files, keep_file, |file| {
            parse_and_collect(analyzer, file, nodes, &language, |input| {
                scan_php_file(source, self.php, file, input)
            })
        })
    }
}
