use super::extractor::scan_file;
use super::hits::push_override_declaration_hit;
use super::inverted;
use super::resolver::{PhpHierarchyIndex, TargetKind, TargetSpec};
use crate::analyzer::usages::common::{analyzed_files_for_language, language_for_file};
use crate::analyzer::usages::inverted_edges::{UsageEdgeWeights, UsageEdges};
use crate::analyzer::usages::model::{FuzzyResult, UsageHit};
use crate::analyzer::usages::outcome::{GraphFailureReason, GraphUsageOutcome};
use crate::analyzer::usages::traits::{UsageEdgeResolver, UsageQueryResolver, UsageScanScope};
use crate::analyzer::{CodeUnit, IAnalyzer, Language, PhpAnalyzer, ProjectFile, resolve_analyzer};
use crate::hash::HashSet;
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
            push_override_declaration_hit(self.php, analyzer, &override_declaration, &mut hits);
        }
        for file in files {
            if scan_scope.is_cancelled() {
                break;
            }
            scan_file(self.php, analyzer, &file, &spec, hierarchy, &mut hits);
            if hits.len() > max_usages {
                return GraphUsageOutcome::Resolved(FuzzyResult::TooManyCallsites {
                    short_name: target.short_name().to_string(),
                    total_callsites: hits.len(),
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

impl<'a> UsageEdgeResolver<'a> for PhpEdgeResolver<'a> {
    fn try_new(analyzer: &'a dyn IAnalyzer) -> Option<Self> {
        let php = resolve_analyzer::<PhpAnalyzer>(analyzer)?;
        let files = analyzed_files_for_language(analyzer, Language::Php);
        Some(Self { php, files })
    }

    fn build_edges<F>(
        &self,
        analyzer: &dyn IAnalyzer,
        nodes: &HashSet<String>,
        keep_file: F,
    ) -> UsageEdges
    where
        F: Fn(&ProjectFile) -> bool + Sync,
    {
        inverted::build_php_edges(analyzer, self.php, &self.files, nodes, keep_file)
    }

    fn build_edge_weights<F>(
        &self,
        analyzer: &dyn IAnalyzer,
        nodes: &HashSet<String>,
        keep_file: F,
    ) -> UsageEdgeWeights
    where
        F: Fn(&ProjectFile) -> bool + Sync,
    {
        inverted::build_php_edges(analyzer, self.php, &self.files, nodes, keep_file)
    }
}
