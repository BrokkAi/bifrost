//! Receiver-aware Ruby usage resolution.
//!
//! Ruby remains dynamic, so this strategy only emits graph hits when parser and
//! analyzer facts prove the target. Same-name calls with unknown receivers are
//! returned in the unproven usage tier so callers can treat them as
//! inconclusive evidence instead of query failure.

mod extractor;
mod hits;
mod inverted;
mod resolver;
mod shared;
mod syntax;

pub(crate) use extractor::{
    ruby_enclosing_receiver, ruby_field_reference_owner_and_scope, ruby_receiver_type,
    ruby_seed_assignment, ruby_seed_parameter_shadows, ruby_type_owner,
};
pub(crate) use resolver::{ReceiverMode, ReceiverType, RubySemanticIndex, ruby_field_target};
pub(crate) use syntax::{
    is_call_method_identifier, is_declaration_constant, is_declaration_identifier,
    is_dynamic_dispatch_method, is_plain_assignment_left_variable, method_receiver_mode, node_text,
    symbol_or_string_value,
};

use crate::analyzer::ruby::parse_ruby_tree;
use crate::analyzer::usages::common::language_for_target;
use crate::analyzer::usages::inverted_edges::UsageEdges;
use crate::analyzer::usages::model::FuzzyResult;
use crate::analyzer::usages::outcome::{GraphFailureReason, GraphUsageOutcome};
use crate::analyzer::usages::traits::{UsageAnalyzer, UsageEdgeResolver, UsageScanScope};
use crate::analyzer::{CodeUnit, IAnalyzer, Language, ProjectFile, RubyAnalyzer, resolve_analyzer};
use crate::hash::HashSet;
use crate::text_utils::compute_line_starts;
use std::collections::BTreeSet;

use self::extractor::{RubyFileScan, language_for_file};
use self::resolver::RubyTargetSpec;
use self::shared::RubyEdgeResolver;

const STRATEGY: &str = "RubyUsageGraphStrategy";

pub fn build_ruby_usage_edges(
    analyzer: &dyn IAnalyzer,
    nodes: &HashSet<String>,
    keep_file: impl Fn(&ProjectFile) -> bool + Sync,
) -> Option<UsageEdges> {
    let resolver = RubyEdgeResolver::try_new(analyzer)?;
    Some(resolver.build_edges(analyzer, nodes, keep_file))
}

#[derive(Default)]
pub struct RubyUsageGraphStrategy;

impl RubyUsageGraphStrategy {
    pub fn new() -> Self {
        Self
    }

    pub fn can_handle(target: &CodeUnit) -> bool {
        language_for_target(target) == Language::Ruby
    }

    pub(crate) fn find_graph_usages(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        scan_scope: &UsageScanScope<'_>,
        max_usages: usize,
    ) -> GraphUsageOutcome {
        let Some(target) = overloads.first() else {
            return GraphUsageOutcome::Resolved(FuzzyResult::empty_success());
        };
        if language_for_target(target) != Language::Ruby {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::UnsupportedTargetLanguage("target is not Ruby"),
                STRATEGY,
            );
        }
        let Some(ruby) = resolve_analyzer::<RubyAnalyzer>(analyzer) else {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::MissingAnalyzerCapability("Ruby analyzer is unavailable"),
                STRATEGY,
            );
        };
        let Some(spec) = RubyTargetSpec::from_target(analyzer, target) else {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::UnsupportedTargetShape("target shape is unsupported"),
                STRATEGY,
            );
        };

        let semantic = RubySemanticIndex::build(analyzer, ruby, &spec);
        let mut scan_files = scan_scope.candidate_files().clone();
        if scan_scope.allows(target.source()) {
            scan_files.insert(target.source().clone());
        }
        scan_files.extend(
            ruby.zeitwerk_reference_files_for_identifier(&spec.member_name)
                .into_iter()
                .filter(|file| scan_scope.allows(file)),
        );

        let mut hits = BTreeSet::new();
        let mut unproven_hits = BTreeSet::new();
        for file in &scan_files {
            if scan_scope.is_cancelled() {
                break;
            }
            if language_for_file(file) != Language::Ruby {
                continue;
            }
            let Ok(source) = analyzer.project().read_source(file) else {
                continue;
            };
            let Some(tree) = parse_ruby_tree(&source) else {
                continue;
            };
            let line_starts = compute_line_starts(&source);
            let visible_files = semantic.visible_files_from(file);
            let mut scan = RubyFileScan {
                analyzer,
                semantic: &semantic,
                support: analyzer.global_usage_definition_index(),
                file,
                source: &source,
                line_starts: &line_starts,
                visible_files,
                spec: &spec,
                hits: &mut hits,
                unproven_hits: &mut unproven_hits,
            };
            scan.scan(tree.root_node());
        }

        let hits: BTreeSet<_> = hits
            .into_iter()
            .filter(|hit| hit.enclosing != spec.target)
            .collect();
        let unproven_hits: BTreeSet<_> = unproven_hits
            .into_iter()
            .filter(|hit| hit.enclosing != spec.target)
            .collect();

        if hits.len() > max_usages {
            return GraphUsageOutcome::Resolved(FuzzyResult::TooManyCallsites {
                short_name: spec.target.short_name().to_string(),
                total_callsites: hits.len(),
                limit: max_usages,
                sample_hits: hits,
            });
        }

        GraphUsageOutcome::Resolved(FuzzyResult::success_with_unproven(
            spec.target.clone(),
            hits,
            unproven_hits,
        ))
    }
}

impl UsageAnalyzer for RubyUsageGraphStrategy {
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
