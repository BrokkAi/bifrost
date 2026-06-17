use super::extractor::scan_file;
use super::inverted;
use super::resolver::{PhpHierarchyIndex, TargetKind, TargetSpec, resolve_php_analyzer};
use crate::analyzer::usages::common::language_for_file;
use crate::analyzer::usages::inverted_edges::UsageEdges;
use crate::analyzer::usages::model::{FuzzyResult, UsageHit};
use crate::analyzer::usages::outcome::{GraphFailureReason, GraphUsageOutcome};
use crate::analyzer::{CodeUnit, IAnalyzer, Language, PhpAnalyzer, ProjectFile};
use crate::hash::HashSet;
use std::collections::BTreeSet;

pub(crate) struct PhpQueryResolver<'a> {
    php: &'a PhpAnalyzer,
}

impl<'a> PhpQueryResolver<'a> {
    pub(crate) fn new(analyzer: &'a dyn IAnalyzer) -> Option<Self> {
        Some(Self {
            php: resolve_php_analyzer(analyzer)?,
        })
    }

    pub(crate) fn find_usages(
        &self,
        analyzer: &dyn IAnalyzer,
        target: &CodeUnit,
        candidate_files: &HashSet<ProjectFile>,
        max_usages: usize,
    ) -> GraphUsageOutcome {
        let Some(spec) = TargetSpec::from_target(self.php, target) else {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::UnsupportedTargetShape("unsupported target shape"),
                "PhpUsageGraphStrategy",
            );
        };

        let files: HashSet<ProjectFile> = candidate_files
            .iter()
            .filter(|file| language_for_file(file) == Language::Php)
            .cloned()
            .chain(std::iter::once(target.source().clone()))
            .collect();

        let hierarchy = matches!(spec.kind, TargetKind::Method | TargetKind::Field)
            .then(|| PhpHierarchyIndex::build(self.php, &files));
        let empty_hierarchy = PhpHierarchyIndex::default();
        let hierarchy = hierarchy.as_ref().unwrap_or(&empty_hierarchy);
        let mut hits: BTreeSet<UsageHit> = BTreeSet::new();
        for file in files {
            scan_file(self.php, analyzer, &file, &spec, hierarchy, &mut hits);
            if hits.len() > max_usages {
                return GraphUsageOutcome::Resolved(FuzzyResult::TooManyCallsites {
                    short_name: target.short_name().to_string(),
                    total_callsites: hits.len(),
                    limit: max_usages,
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

impl<'a> PhpEdgeResolver<'a> {
    pub(crate) fn new(analyzer: &'a dyn IAnalyzer) -> Option<Self> {
        let php = resolve_php_analyzer(analyzer)?;
        let files: Vec<ProjectFile> = analyzer
            .project()
            .analyzable_files(Language::Php)
            .ok()?
            .into_iter()
            .collect();
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
        inverted::build_php_edges(analyzer, self.php, &self.files, nodes, keep_file)
    }
}
