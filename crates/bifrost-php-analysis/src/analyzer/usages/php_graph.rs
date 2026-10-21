//! The analysis-side wrappers over [`brokk_bifrost_php::graph`].
//!
//! The scans themselves moved with the language knowledge. What stays here is
//! the downcast that produces their arguments, the `GraphUsageAnalyzer` /
//! `UsageQueryResolver` / `UsageAnalyzer` strategy shells (all analysis-owned
//! traits), the dead-code eligibility downcast, and the inverted pass's fan-out.

mod shared;

use brokk_bifrost_core::analyzer::fq_name::SegmentKind;

use brokk_bifrost_core::analyzer::fq_name::segment_interner;

use brokk_bifrost_analysis::analyzer::store::StoreError;

use brokk_bifrost_analysis::analyzer::usages::common::language_for_target;

use brokk_bifrost_core::analyzer::usages::inverted_edges::UsageEdgeWeights;

use brokk_bifrost_core::analyzer::usages::inverted_edges::UsageEdges;

use brokk_bifrost_core::analyzer::usages::outcome::GraphUsageOutcome;

use crate::analyzer::usages::php_graph::shared::PhpEdgeResolver;

use crate::analyzer::usages::php_graph::shared::PhpQueryResolver;

use brokk_bifrost_analysis::analyzer::usages::traits::GraphUsageAnalyzer;

use brokk_bifrost_analysis::analyzer::usages::traits::GraphUsageDispatchSpec;

use brokk_bifrost_core::analyzer::usages::scan_scope::UsageScanScope;

use brokk_bifrost_analysis::analyzer::analyzer_definition_lookup::AnalyzerDefinitionLookup;

use brokk_bifrost_core::analyzer::model::CodeUnit;

use brokk_bifrost_core::analyzer::definition_lookup::DefinitionLanguageScope;

use brokk_bifrost_core::analyzer::fq_name::FqName;

use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

use brokk_bifrost_core::analyzer::model::Language;

use crate::analyzer::PhpAnalyzer;

use brokk_bifrost_core::analyzer::model::ProjectFile;

use brokk_bifrost_core::analyzer::definition_lookup::RelationalBatchOutcome;

use brokk_bifrost_core::analyzer::definition_lookup::RelationalCallableFact;

use brokk_bifrost_core::analyzer::definition_lookup::RelationalDefinitionQuery;

use brokk_bifrost_core::analyzer::definition_lookup::RelationalDefinitionQuestion;

use brokk_bifrost_core::analyzer::definition_lookup::RelationalDefinitionValue;

use brokk_bifrost_core::analyzer::model::StructuredTypeName;

use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;

use brokk_bifrost_core::cancellation::CancellationToken;

use brokk_bifrost_core::hash::HashMap;

use brokk_bifrost_core::analyzer::RelationalName;
use brokk_bifrost_core::hash::HashSet;
use brokk_bifrost_php::graph::resolver::{TargetKind, TargetSpec};
use brokk_bifrost_php::graph::{PhpCallableFacts, PhpGraphSource};
use std::sync::Mutex;

/// Request-local PHP callable facts. Signature rows and return-type definition
/// candidates are fetched only for declarations the scan reaches; the bounded
/// lookup memoizes repeated names for the life of this facts source.
pub(crate) struct PhpAnalyzerFacts<'a> {
    analyzer: &'a dyn IAnalyzer,
    definitions: AnalyzerDefinitionLookup<'a>,
    declaration_returns: Mutex<HashMap<CodeUnit, Option<String>>>,
    callable_returns: Mutex<HashMap<String, Option<String>>>,
}

impl<'a> PhpAnalyzerFacts<'a> {
    pub(crate) fn new(analyzer: &'a dyn IAnalyzer) -> Self {
        Self {
            analyzer,
            definitions: AnalyzerDefinitionLookup::new(analyzer, Language::None),
            declaration_returns: Mutex::new(HashMap::default()),
            callable_returns: Mutex::new(HashMap::default()),
        }
    }

    fn callable_facts(&self, declarations: &[CodeUnit]) -> Option<Vec<RelationalCallableFact>> {
        let mut names = declarations
            .iter()
            .map(|declaration| declaration.fq().clone())
            .collect::<Vec<_>>();
        let mut seen = HashSet::default();
        names.retain(|name| seen.insert(name.clone()));
        let questions = names
            .into_iter()
            .map(|name| RelationalDefinitionQuestion {
                language_scope: DefinitionLanguageScope::Language(Language::Php),
                name: RelationalName::stable(name),
                query: RelationalDefinitionQuery::CallableFacts,
            })
            .collect::<Vec<_>>();
        let values = self.query(&questions)?;
        Some(
            values
                .into_iter()
                .flat_map(|value| match value {
                    RelationalDefinitionValue::CallableFacts(facts) => facts,
                    _ => unreachable!("PHP callable-facts query returned the wrong shape"),
                })
                .collect(),
        )
    }

    fn resolved_return_type(&self, facts: &[RelationalCallableFact]) -> Option<String> {
        let mut names = facts
            .iter()
            .map(|fact| {
                fact.metadata
                    .as_ref()?
                    .return_type_identity()?
                    .nominal_name()
                    .and_then(php_resolved_type_fq_name)
            })
            .collect::<Option<Vec<_>>>()?;
        let mut seen = HashSet::default();
        names.retain(|name| seen.insert(name.clone()));
        if names.is_empty() {
            return None;
        }
        let questions = names
            .into_iter()
            .map(|name| RelationalDefinitionQuestion {
                language_scope: DefinitionLanguageScope::Language(Language::Php),
                name: RelationalName::stable(name),
                query: RelationalDefinitionQuery::ExactName,
            })
            .collect::<Vec<_>>();
        let values = self.query(&questions)?;
        let mut resolved = Vec::new();
        for value in values {
            let RelationalDefinitionValue::Definitions(units) = value else {
                unreachable!("PHP return-type query returned the wrong shape")
            };
            if units.is_empty() {
                return None;
            }
            resolved.extend(units.into_iter().map(|unit| unit.fq_name()));
        }
        resolved.sort();
        resolved.dedup();
        (resolved.len() == 1).then(|| resolved.remove(0))
    }

    fn query(
        &self,
        questions: &[RelationalDefinitionQuestion],
    ) -> Option<Vec<RelationalDefinitionValue>> {
        if questions.is_empty() {
            return Some(Vec::new());
        }
        let requests = questions
            .iter()
            .enumerate()
            .map(|(ordinal, question)| question.request(ordinal))
            .collect::<Vec<_>>();
        match self
            .analyzer
            .relational_definition_batch(&requests, &CancellationToken::new())
        {
            RelationalBatchOutcome::Complete(results) => {
                assert_eq!(results.len(), requests.len());
                Some(results.into_iter().map(|result| result.value).collect())
            }
            RelationalBatchOutcome::Cancelled => None,
            RelationalBatchOutcome::Failed(error) => {
                self.analyzer
                    .record_query_failure(StoreError::new(error.message()));
                None
            }
        }
    }
}

impl PhpCallableFacts for PhpAnalyzerFacts<'_> {
    fn declaration_return_type_fqn(&self, unit: &CodeUnit) -> Option<String> {
        if let Some(cached) = self
            .declaration_returns
            .lock()
            .expect("PHP declaration return cache poisoned")
            .get(unit)
        {
            return cached.clone();
        }
        let facts = self
            .callable_facts(std::slice::from_ref(unit))?
            .into_iter()
            .filter(|fact| fact.declaration == *unit)
            .collect::<Vec<_>>();
        let resolved = self.resolved_return_type(&facts);
        self.declaration_returns
            .lock()
            .expect("PHP declaration return cache poisoned")
            .insert(unit.clone(), resolved.clone());
        resolved
    }

    fn callable_return_type_fqn(&self, callable_fqn: &str) -> Option<String> {
        if let Some(cached) = self
            .callable_returns
            .lock()
            .expect("PHP callable return cache poisoned")
            .get(callable_fqn)
        {
            return cached.clone();
        }
        let mut declarations = self
            .definitions
            .fqn(callable_fqn)
            .into_iter()
            .filter(CodeUnit::is_function)
            .collect::<Vec<_>>();
        declarations.sort();
        declarations.dedup();
        let facts = self.callable_facts(&declarations)?;
        let resolved = self.resolved_return_type(&facts);
        self.callable_returns
            .lock()
            .expect("PHP callable return cache poisoned")
            .insert(callable_fqn.to_string(), resolved.clone());
        resolved
    }
}

fn php_resolved_type_fq_name(name: &StructuredTypeName) -> Option<FqName> {
    if !name.is_absolute() || !name.lexical_scope().is_empty() {
        return None;
    }
    let (type_name, packages) = name.path().split_last()?;
    let interner = segment_interner();
    let mut fq = FqName::new();
    for package in packages {
        fq.push(interner.intern(package, SegmentKind::Package));
    }
    fq.push(interner.intern(type_name, SegmentKind::Type));
    Some(fq)
}

/// The [`PhpGraphSource`] built from the *dispatching* analyzer.
///
/// Deliberately not the PHP analyzer: in a mixed workspace the query is issued
/// against a `MultiAnalyzer`, whose `definitions` merges every language's shards
/// and whose enclosing-unit lookup crosses language boundaries.
pub(crate) fn php_graph_source<'a>(
    analyzer: &'a dyn IAnalyzer,
    facts: &'a dyn PhpCallableFacts,
) -> PhpGraphSource<'a> {
    PhpGraphSource {
        index: analyzer,
        facts,
    }
}

pub(crate) fn build_php_usage_edges<F>(
    analyzer: &dyn IAnalyzer,
    nodes: &HashSet<String>,
    keep_file: F,
) -> Option<UsageEdges>
where
    F: Fn(&ProjectFile) -> bool + Sync,
{
    let resolver = PhpEdgeResolver::try_new(analyzer)?;
    Some(resolver.build_edges(analyzer, nodes, keep_file))
}

pub(crate) fn build_rooted_php_usage_edges<F>(
    analyzer: &dyn IAnalyzer,
    callers: &HashSet<String>,
    keep_file: F,
) -> Option<UsageEdges>
where
    F: Fn(&ProjectFile) -> bool + Sync,
{
    let resolver = PhpEdgeResolver::try_new(analyzer)?;
    Some(resolver.build_rooted_edges(analyzer, callers, keep_file))
}

pub(crate) fn build_php_usage_edge_weights<F>(
    analyzer: &dyn IAnalyzer,
    nodes: &HashSet<String>,
    keep_file: F,
) -> Option<UsageEdgeWeights>
where
    F: Fn(&ProjectFile) -> bool + Sync,
{
    let resolver = PhpEdgeResolver::try_new(analyzer)?;
    Some(resolver.build_edges(analyzer, nodes, keep_file))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PhpDeadCodeBulkEligibility {
    BulkSafe,
    NeedsPrecise,
}

pub(crate) fn dead_code_bulk_eligibility(
    analyzer: &dyn IAnalyzer,
    target: &CodeUnit,
) -> PhpDeadCodeBulkEligibility {
    let Some(php) = resolve_analyzer::<PhpAnalyzer>(analyzer) else {
        return PhpDeadCodeBulkEligibility::NeedsPrecise;
    };
    let Some(spec) = TargetSpec::from_target(php, target) else {
        return PhpDeadCodeBulkEligibility::NeedsPrecise;
    };
    match spec.kind {
        TargetKind::Type | TargetKind::Function | TargetKind::Method => {
            PhpDeadCodeBulkEligibility::BulkSafe
        }
        TargetKind::Constructor | TargetKind::Field | TargetKind::Constant => {
            PhpDeadCodeBulkEligibility::NeedsPrecise
        }
    }
}

#[derive(Default)]
pub struct PhpUsageGraphStrategy {
    _private: (),
}

impl PhpUsageGraphStrategy {
    pub const fn new() -> Self {
        Self { _private: () }
    }

    pub fn can_handle(target: &CodeUnit) -> bool {
        language_for_target(target) == Language::Php
    }
}

impl GraphUsageAnalyzer for PhpUsageGraphStrategy {
    fn find_graph_usages(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        scan_scope: &UsageScanScope<'_>,
        max_usages: usize,
    ) -> GraphUsageOutcome {
        brokk_bifrost_analysis::analyzer::usages::traits::dispatch_graph_usage_query::<
            PhpQueryResolver<'_>,
        >(
            analyzer,
            overloads,
            scan_scope,
            max_usages,
            GraphUsageDispatchSpec {
                target_language: Language::Php,
                unsupported_target: "target is not PHP",
                missing_analyzer: "analyzer does not expose PhpAnalyzer",
                strategy: "PhpUsageGraphStrategy",
            },
        )
    }
}
