//! Analyzer-owned bounded receiver queries for structural traversal.

use crate::analyzer::common::language_for_file;
use crate::analyzer::languages::{
    BoundedReceiverQuery, LanguageSupport, ReceiverFactContext, ReceiverFileCtx, ReceiverFileFacts,
    ReceiverFileSetup, StructuralReceiverResolver, language_support,
};
use crate::analyzer::semantic::{
    AbstractObjectIdentity, CandidateCoverage, OracleLimitValues, OracleLimits, SemanticBudget,
    SemanticBudgetDimension, SemanticBudgetExceeded, SemanticCapability, SemanticOutcome,
    SemanticProviderError, SemanticRequest, SemanticWork, SourcePointsToResult,
    WorkspaceSemanticOracle,
};
use crate::analyzer::store::LimitedQueryRows;
use crate::analyzer::structural::FileFacts;
use crate::analyzer::structural::provider::StructuralSyntaxLimitedOutcome;
use crate::analyzer::tree_sitter_analyzer::{
    BoundedNamedTreeWalk, walk_named_tree_preorder_bounded,
};
use crate::analyzer::usages::get_definition::{
    BoundedResolution, DefinitionLookupOutcome, DefinitionLookupStatus,
    java::{BoundedJavaResolution, JavaResolutionSession, resolve_java_bounded},
    parse_tree_for_language, resolve_reference_site_with_line_starts,
};
use crate::analyzer::usages::get_type::{
    TypeLookupOutcome, TypeLookupStatus, TypeLookupType, java::resolve_java_type_bounded,
};
use crate::analyzer::usages::receiver_analysis::{
    ReceiverAnalysisBudget, ReceiverAnalysisOutcome, ReceiverAnalysisReport, ReceiverAnalysisWork,
    ReceiverBudgetLimit, ReceiverValue,
};
use crate::analyzer::usages::receiver_sites::{
    ReceiverSiteIndex, ReceiverSiteIndexBuild, ReceiverSiteIndexLimit, ReceiverSiteInputMode,
    ReceiverSiteKind, ReceiverSiteSelection, ReceiverSiteSelectionLimit, build_receiver_site_index,
};
use crate::analyzer::usages::reference_site::{
    ResolvedReferenceSite, SourceLocationRequest, node_range, smallest_named_node_covering,
};
use crate::analyzer::usages::target_kind::TypeLookupTargetKind;
use crate::analyzer::{
    AnalyzerDefinitionLookup, CodeUnit, DispatchExtensibility, IAnalyzer, Language, ProjectFile,
    Range, WorkspaceAnalyzer,
};
use crate::cancellation::CancellationToken;
use crate::hash::HashMap;
use crate::path_utils::rel_path_string;
use crate::text_utils::compute_line_starts;
use std::cell::RefCell;
use std::sync::Arc;
use tree_sitter::Node;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum ReceiverQueryOperation {
    ReceiverTargets,
    PointsTo,
    MemberTargets,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReceiverQueryInput {
    Expression,
    ContainingSite,
}

impl ReceiverQueryOperation {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::ReceiverTargets => "receiver_targets",
            Self::PointsTo => "points_to",
            Self::MemberTargets => "member_targets",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct ReceiverQuerySite {
    pub(crate) file: ProjectFile,
    pub(crate) language: Language,
    pub(crate) range: Range,
    pub(crate) text: String,
    pub(crate) syntax_kind: String,
    pub(crate) member_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum ReceiverQueryAnalysis {
    Values(ReceiverAnalysisOutcome<ReceiverValue>),
    MemberTargets(ReceiverAnalysisOutcome<CodeUnit>),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct ReceiverQueryReport {
    pub(crate) operation: ReceiverQueryOperation,
    pub(crate) site: ReceiverQuerySite,
    pub(crate) analysis: ReceiverQueryAnalysis,
    pub(crate) work: ReceiverAnalysisWork,
    pub(crate) candidates_truncated: bool,
    pub(crate) semantic_unsupported: Option<SemanticCapability>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ReceiverQueryError {
    Cancelled,
    SemanticProvider(SemanticProviderError),
}

pub(crate) struct ReceiverQueryService<'a> {
    analyzer: &'a dyn IAnalyzer,
    workspace: Option<&'a WorkspaceAnalyzer>,
    definitions: AnalyzerDefinitionLookup<'a>,
    prepared_files: RefCell<HashMap<ProjectFile, PreparedReceiverFile>>,
    prepared_java_files: RefCell<HashMap<ProjectFile, PreparedJavaReceiverFile>>,
    prepared_structural_files: RefCell<HashMap<ProjectFile, PreparedStructuralReceiverFile>>,
}

struct PreparedReceiverFile {
    source: String,
    tree: tree_sitter::Tree,
    facts: ReceiverFileFacts,
}

struct PreparedStructuralReceiverFile {
    facts: Arc<FileFacts>,
    sites: ReceiverSiteIndex,
    syntax: Arc<crate::analyzer::tree_sitter_analyzer::PreparedSyntaxTree>,
}

impl PreparedStructuralReceiverFile {
    fn matches(&self, facts: &Arc<FileFacts>) -> bool {
        Arc::ptr_eq(&self.facts, facts)
            && self.sites.source() == facts.source()
            && self.syntax.source() == facts.source()
    }
}

struct PreparedJavaReceiverFile {
    source: String,
    tree: tree_sitter::Tree,
    line_starts: Vec<usize>,
}

#[derive(Clone, Copy)]
struct JavaReceiverResolutionInput<'a> {
    source: &'a str,
    tree: &'a tree_sitter::Tree,
    line_starts: &'a [usize],
}

impl PreparedJavaReceiverFile {
    fn resolution_input(&self) -> JavaReceiverResolutionInput<'_> {
        JavaReceiverResolutionInput {
            source: &self.source,
            tree: &self.tree,
            line_starts: &self.line_starts,
        }
    }
}

enum SemanticReceiverGate {
    Bypassed {
        work: ReceiverAnalysisWork,
    },
    Available {
        work: ReceiverAnalysisWork,
        points_to: SourcePointsToResult,
        evidence: SemanticReceiverEvidence,
    },
    Unavailable {
        work: ReceiverAnalysisWork,
        unsupported: Option<SemanticCapability>,
    },
    Exceeded {
        work: ReceiverAnalysisWork,
        limit: ReceiverBudgetLimit,
    },
}

impl SemanticReceiverGate {
    fn work(&self) -> ReceiverAnalysisWork {
        match self {
            Self::Bypassed { work }
            | Self::Available { work, .. }
            | Self::Unavailable { work, .. }
            | Self::Exceeded { work, .. } => *work,
        }
    }

    fn exceeded_limit(&self) -> Option<ReceiverBudgetLimit> {
        match self {
            Self::Exceeded { limit, .. } => Some(*limit),
            Self::Bypassed { .. } | Self::Available { .. } | Self::Unavailable { .. } => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SemanticReceiverEvidence {
    ExhaustiveComplete,
    Incomplete {
        coverage: CandidateCoverage,
        unsupported: Option<SemanticCapability>,
        origin: SemanticReceiverIncompleteness,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SemanticReceiverIncompleteness {
    /// The retained candidates are individually proven and complete, but a
    /// globally incomplete adapter capability keeps the candidate set open.
    GlobalCapabilitiesWithProvenCandidates,
    /// Query-local uncertainty, including unproven candidates and disabled or
    /// truncated call context.
    Local,
}

impl SemanticReceiverEvidence {
    fn from_outcome<T>(outcome: &SemanticOutcome<T>, coverage: CandidateCoverage) -> Self {
        if outcome.is_complete() && coverage.is_exhaustive() {
            Self::ExhaustiveComplete
        } else {
            Self::Incomplete {
                coverage,
                unsupported: match outcome {
                    SemanticOutcome::Unsupported { capability, .. } => Some(*capability),
                    _ => None,
                },
                origin: SemanticReceiverIncompleteness::Local,
            }
        }
    }

    fn from_points_to_outcome(
        outcome: &SemanticOutcome<SourcePointsToResult>,
        points_to: &SourcePointsToResult,
    ) -> Self {
        let mut evidence = Self::from_outcome(outcome, points_to.coverage());
        if matches!(
            evidence,
            Self::Incomplete {
                coverage: CandidateCoverage::Open,
                unsupported: None,
                ..
            }
        ) && points_to.globally_incomplete_with_proven_candidates()
        {
            evidence = Self::Incomplete {
                coverage: CandidateCoverage::Open,
                unsupported: None,
                origin: SemanticReceiverIncompleteness::GlobalCapabilitiesWithProvenCandidates,
            };
        }
        evidence
    }

    const fn supports_precise(self) -> bool {
        matches!(self, Self::ExhaustiveComplete)
    }

    const fn legacy_provider_can_close(self) -> bool {
        matches!(
            self,
            Self::Incomplete {
                origin: SemanticReceiverIncompleteness::GlobalCapabilitiesWithProvenCandidates,
                ..
            }
        )
    }

    const fn is_truncated(self) -> bool {
        matches!(
            self,
            Self::Incomplete {
                coverage: CandidateCoverage::Truncated,
                ..
            }
        )
    }

    const fn unsupported_capability(self) -> Option<SemanticCapability> {
        match self {
            Self::Incomplete { unsupported, .. } => unsupported,
            Self::ExhaustiveComplete => None,
        }
    }
}

/// One receiver-query budget shared by setup, the neutral semantic gate, and
/// the compatibility provider. Setup consumes the same scope capacity as the
/// two analysis phases even though it remains separately visible in reports.
#[derive(Debug, Clone, Copy)]
struct ReceiverWorkLedger {
    budget: ReceiverAnalysisBudget,
    work: ReceiverAnalysisWork,
}

impl ReceiverWorkLedger {
    fn new(budget: ReceiverAnalysisBudget) -> Self {
        Self {
            budget,
            work: ReceiverAnalysisWork::default(),
        }
    }

    fn remaining_budget(&self) -> ReceiverAnalysisBudget {
        ReceiverAnalysisBudget {
            max_scope_nodes: self
                .budget
                .max_scope_nodes
                .saturating_sub(self.work.setup_nodes.saturating_add(self.work.scope_nodes)),
            max_summary_expansions: self
                .budget
                .max_summary_expansions
                .saturating_sub(self.work.summary_expansions),
            ..self.budget
        }
    }

    fn charge_setup(&mut self, nodes: usize) -> Result<(), ReceiverBudgetLimit> {
        let remaining = self.remaining_budget().max_scope_nodes;
        self.work.setup_nodes = self.work.setup_nodes.saturating_add(nodes.min(remaining));
        if nodes > remaining {
            Err(ReceiverBudgetLimit::ScopeNodes)
        } else {
            Ok(())
        }
    }

    fn charge_analysis(&mut self, work: ReceiverAnalysisWork) -> Result<(), ReceiverBudgetLimit> {
        debug_assert_eq!(work.setup_nodes, 0);
        let remaining = self.remaining_budget();
        let scope_exceeded = work.scope_nodes > remaining.max_scope_nodes;
        let summaries_exceeded = work.summary_expansions > remaining.max_summary_expansions;
        self.work.scope_nodes = self
            .work
            .scope_nodes
            .saturating_add(work.scope_nodes.min(remaining.max_scope_nodes));
        self.work.summary_expansions = self.work.summary_expansions.saturating_add(
            work.summary_expansions
                .min(remaining.max_summary_expansions),
        );
        if scope_exceeded {
            Err(ReceiverBudgetLimit::ScopeNodes)
        } else if summaries_exceeded {
            Err(ReceiverBudgetLimit::SummaryExpansions)
        } else {
            Ok(())
        }
    }

    fn work(&self) -> ReceiverAnalysisWork {
        self.work
    }
}

enum CompatibilityOutcome<T> {
    Complete(T),
    Exceeded(ReceiverBudgetLimit),
}

fn charge_compatibility<T>(
    ledger: &mut ReceiverWorkLedger,
    resolution: BoundedJavaResolution<T>,
) -> Result<CompatibilityOutcome<T>, ReceiverQueryError> {
    let aggregate_limit = ledger.charge_analysis(resolution.work()).err();
    match resolution {
        BoundedJavaResolution::Complete { value, .. } => Ok(match aggregate_limit {
            Some(limit) => CompatibilityOutcome::Exceeded(limit),
            None => CompatibilityOutcome::Complete(value),
        }),
        BoundedJavaResolution::Exceeded { limit, .. } => Ok(CompatibilityOutcome::Exceeded(
            aggregate_limit.unwrap_or(limit),
        )),
        BoundedJavaResolution::Cancelled { .. } => Err(ReceiverQueryError::Cancelled),
    }
}

fn charge_bounded_resolution<T>(
    ledger: &mut ReceiverWorkLedger,
    resolution: BoundedResolution<T>,
) -> Result<CompatibilityOutcome<T>, ReceiverQueryError> {
    let aggregate_limit = ledger.charge_analysis(resolution.work()).err();
    match resolution {
        BoundedResolution::Complete { value, .. } => Ok(match aggregate_limit {
            Some(limit) => CompatibilityOutcome::Exceeded(limit),
            None => CompatibilityOutcome::Complete(value),
        }),
        BoundedResolution::Exceeded { limit, .. } => Ok(CompatibilityOutcome::Exceeded(
            aggregate_limit.unwrap_or(limit),
        )),
        BoundedResolution::Cancelled { .. } => Err(ReceiverQueryError::Cancelled),
    }
}

fn charge_scope_step(ledger: &mut ReceiverWorkLedger) -> Result<(), ReceiverBudgetLimit> {
    ledger.charge_analysis(ReceiverAnalysisWork {
        scope_nodes: 1,
        ..ReceiverAnalysisWork::default()
    })
}

fn charge_summary_step(ledger: &mut ReceiverWorkLedger) -> Result<(), ReceiverBudgetLimit> {
    ledger.charge_analysis(ReceiverAnalysisWork {
        summary_expansions: 1,
        ..ReceiverAnalysisWork::default()
    })
}

fn charge_limited_projection<T>(
    batch: LimitedQueryRows<T>,
    cancellation: Option<&CancellationToken>,
    ledger: &mut ReceiverWorkLedger,
) -> Result<CompatibilityOutcome<Vec<T>>, ReceiverQueryError> {
    check_cancelled(cancellation)?;
    let charged_rows = batch.inspected.max(batch.rows.len());
    for _ in 0..charged_rows {
        check_cancelled(cancellation)?;
        if let Err(limit) = charge_scope_step(ledger) {
            return Ok(CompatibilityOutcome::Exceeded(limit));
        }
    }
    if !batch.complete {
        return Ok(CompatibilityOutcome::Exceeded(
            ReceiverBudgetLimit::ScopeNodes,
        ));
    }
    Ok(CompatibilityOutcome::Complete(batch.rows))
}

impl<'a> ReceiverQueryService<'a> {
    pub(crate) fn new(analyzer: &'a dyn IAnalyzer) -> Self {
        Self {
            analyzer,
            workspace: None,
            definitions: AnalyzerDefinitionLookup::new(analyzer, Language::None),
            prepared_files: RefCell::new(HashMap::default()),
            prepared_java_files: RefCell::new(HashMap::default()),
            prepared_structural_files: RefCell::new(HashMap::default()),
        }
    }

    pub(crate) fn from_workspace(workspace: &'a WorkspaceAnalyzer) -> Self {
        let analyzer = workspace.analyzer();
        Self {
            analyzer,
            workspace: Some(workspace),
            definitions: AnalyzerDefinitionLookup::new(analyzer, Language::None),
            prepared_files: RefCell::new(HashMap::default()),
            prepared_java_files: RefCell::new(HashMap::default()),
            prepared_structural_files: RefCell::new(HashMap::default()),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn analyze_with_structural_facts(
        &self,
        operation: ReceiverQueryOperation,
        file: &ProjectFile,
        range: Range,
        input: ReceiverQueryInput,
        facts: &Arc<FileFacts>,
        budget: ReceiverAnalysisBudget,
        cancellation: Option<&CancellationToken>,
    ) -> Result<ReceiverQueryReport, ReceiverQueryError> {
        self.analyze_with_optional_structural_facts(
            operation,
            file,
            range,
            input,
            Some(facts),
            budget,
            cancellation,
        )
    }

    pub(crate) fn analyze(
        &self,
        operation: ReceiverQueryOperation,
        file: &ProjectFile,
        range: Range,
        input: ReceiverQueryInput,
        budget: ReceiverAnalysisBudget,
        cancellation: Option<&CancellationToken>,
    ) -> Result<ReceiverQueryReport, ReceiverQueryError> {
        self.analyze_with_optional_structural_facts(
            operation,
            file,
            range,
            input,
            None,
            budget,
            cancellation,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn analyze_with_optional_structural_facts(
        &self,
        operation: ReceiverQueryOperation,
        file: &ProjectFile,
        range: Range,
        input: ReceiverQueryInput,
        structural_facts: Option<&Arc<FileFacts>>,
        budget: ReceiverAnalysisBudget,
        cancellation: Option<&CancellationToken>,
    ) -> Result<ReceiverQueryReport, ReceiverQueryError> {
        check_cancelled(cancellation)?;
        let language = language_for_file(file);
        if let Some(resolver) =
            language_support(language).and_then(LanguageSupport::structural_receiver)
        {
            return self.analyze_structural(
                operation,
                file,
                language,
                resolver,
                range,
                input,
                structural_facts,
                budget,
                cancellation,
            );
        }
        let indexed_source = self.analyzer.indexed_source(file);
        if language == Language::Java {
            return self.analyze_java(
                operation,
                file,
                range,
                input,
                budget,
                cancellation,
                indexed_source,
            );
        }
        let Some(factory) = language_support(language).and_then(LanguageSupport::receiver_facts)
        else {
            return Ok(unsupported_report(
                operation,
                file,
                language,
                range,
                "receiver_analysis_language_unsupported",
                indexed_source.as_deref(),
            ));
        };
        let Some(source) = indexed_source else {
            return Ok(unsupported_report(
                operation,
                file,
                language,
                range,
                "indexed_source_unavailable",
                None,
            ));
        };
        let mut ledger = ReceiverWorkLedger::new(budget);
        if !self.prepared_files.borrow().contains_key(file) {
            match factory.prepare_file(&ReceiverFileCtx {
                file,
                language,
                source: &source,
                max_scope_nodes: ledger.remaining_budget().max_scope_nodes,
                cancellation,
            }) {
                ReceiverFileSetup::Ready {
                    tree,
                    facts,
                    visited,
                } => {
                    ledger
                        .charge_setup(visited)
                        .expect("completed setup traversal fits its supplied receiver budget");
                    self.prepared_files.borrow_mut().insert(
                        file.clone(),
                        PreparedReceiverFile {
                            source,
                            tree,
                            facts,
                        },
                    );
                }
                ReceiverFileSetup::ParseFailed => {
                    return Ok(unsupported_report(
                        operation,
                        file,
                        language,
                        range,
                        "receiver_source_parse_failed",
                        Some(&source),
                    ));
                }
                ReceiverFileSetup::ExceededScope { visited } => {
                    let _ = ledger.charge_setup(visited);
                    return Ok(setup_budget_report(
                        operation,
                        file,
                        language,
                        range,
                        &source,
                        ledger.work(),
                    ));
                }
                ReceiverFileSetup::Cancelled => {
                    return Err(ReceiverQueryError::Cancelled);
                }
            }
        }
        let prepared_files = self.prepared_files.borrow();
        let prepared = prepared_files
            .get(file)
            .expect("receiver file was prepared above");
        let source = prepared.source.as_str();
        let tree = &prepared.tree;
        let Some(input_node) =
            smallest_named_node_covering(tree.root_node(), range.start_byte, range.end_byte)
        else {
            let mut report = unsupported_report(
                operation,
                file,
                language,
                range,
                "receiver_input_range_unavailable",
                Some(source),
            );
            report.work = ledger.work();
            return Ok(report);
        };
        let provider = factory.make_receiver_facts(ReceiverFactContext {
            analyzer: self.analyzer,
            definitions: &self.definitions,
            language,
            file,
            source,
            root: tree.root_node(),
            facts: &prepared.facts,
        });

        let report = match operation {
            ReceiverQueryOperation::PointsTo => {
                let gate = self.semantic_receiver_gate(
                    file,
                    node_range(input_node),
                    ledger.remaining_budget(),
                    cancellation,
                )?;
                if let Some(limit) = charge_semantic_gate(&mut ledger, &gate) {
                    return Ok(budget_report(
                        operation,
                        site(
                            file,
                            language,
                            node_range(input_node),
                            source,
                            input_node.kind(),
                            None,
                        ),
                        ledger.work(),
                        limit,
                    ));
                }
                let analysis = provider.resolve_receiver(input_node, ledger.remaining_budget());
                finalize_legacy_report(
                    values_report(operation, file, language, input_node, source, analysis),
                    gate,
                    &mut ledger,
                )
            }
            ReceiverQueryOperation::ReceiverTargets => {
                let receiver = match input {
                    ReceiverQueryInput::Expression => input_node,
                    ReceiverQueryInput::ContainingSite => {
                        let Some(receiver) = provider
                            .member_expression_at_site(input_node)
                            .and_then(|member| member.child_by_field_name("object"))
                        else {
                            let mut report = unsupported_report(
                                operation,
                                file,
                                language,
                                range,
                                "receiver_site_without_receiver",
                                Some(source),
                            );
                            report.work = ledger.work();
                            return Ok(report);
                        };
                        receiver
                    }
                };
                let gate = self.semantic_receiver_gate(
                    file,
                    node_range(receiver),
                    ledger.remaining_budget(),
                    cancellation,
                )?;
                if let Some(limit) = charge_semantic_gate(&mut ledger, &gate) {
                    return Ok(budget_report(
                        operation,
                        site(
                            file,
                            language,
                            node_range(receiver),
                            source,
                            receiver.kind(),
                            None,
                        ),
                        ledger.work(),
                        limit,
                    ));
                }
                let analysis = provider.resolve_receiver(receiver, ledger.remaining_budget());
                finalize_legacy_report(
                    values_report(operation, file, language, receiver, source, analysis),
                    gate,
                    &mut ledger,
                )
            }
            ReceiverQueryOperation::MemberTargets => {
                let Some(member_expression) = provider.member_expression_at_site(input_node) else {
                    let mut report = unsupported_report(
                        operation,
                        file,
                        language,
                        range,
                        "member_target_site_unsupported",
                        Some(source),
                    );
                    report.work = ledger.work();
                    return Ok(report);
                };
                let Some(property) = member_expression.child_by_field_name("property") else {
                    let mut report = unsupported_report(
                        operation,
                        file,
                        language,
                        range,
                        "member_target_site_unsupported",
                        Some(source),
                    );
                    report.work = ledger.work();
                    return Ok(report);
                };
                let Some(receiver) = member_expression.child_by_field_name("object") else {
                    let mut report = unsupported_report(
                        operation,
                        file,
                        language,
                        range,
                        "member_target_site_unsupported",
                        Some(source),
                    );
                    report.work = ledger.work();
                    return Ok(report);
                };
                let member_name = source
                    .get(property.start_byte()..property.end_byte())
                    .unwrap_or_default();
                if member_name.is_empty() {
                    let mut report = unsupported_report(
                        operation,
                        file,
                        language,
                        range,
                        "member_target_site_unsupported",
                        Some(source),
                    );
                    report.work = ledger.work();
                    return Ok(report);
                }
                let gate_site = site(
                    file,
                    language,
                    node_range(receiver),
                    source,
                    "receiver",
                    Some(member_name.to_string()),
                );
                let gate = self.semantic_receiver_gate(
                    file,
                    node_range(receiver),
                    ledger.remaining_budget(),
                    cancellation,
                )?;
                if let Some(limit) = charge_semantic_gate(&mut ledger, &gate) {
                    return Ok(budget_report(operation, gate_site, ledger.work(), limit));
                }
                let member_report = provider
                    .resolve_member_targets_at_site(
                        input_node,
                        Some(member_name),
                        input_node.start_byte(),
                        ledger.remaining_budget(),
                    )
                    .expect("validated member expression remains supported by its provider");
                let site = site(
                    file,
                    language,
                    member_report.receiver_range,
                    source,
                    "receiver",
                    Some(member_report.member_name),
                );
                finalize_legacy_report(
                    ReceiverQueryReport {
                        operation,
                        site,
                        analysis: ReceiverQueryAnalysis::MemberTargets(
                            member_report.analysis.outcome,
                        ),
                        work: member_report.analysis.work,
                        candidates_truncated: member_report.analysis.candidates_truncated,
                        semantic_unsupported: None,
                    },
                    gate,
                    &mut ledger,
                )
            }
        };
        check_cancelled(cancellation)?;
        Ok(report)
    }

    fn semantic_receiver_gate(
        &self,
        file: &ProjectFile,
        range: Range,
        budget: ReceiverAnalysisBudget,
        cancellation: Option<&CancellationToken>,
    ) -> Result<SemanticReceiverGate, ReceiverQueryError> {
        let Some(workspace) = self.workspace else {
            return Ok(SemanticReceiverGate::Bypassed {
                work: ReceiverAnalysisWork::default(),
            });
        };
        let cancellation = cancellation.cloned().unwrap_or_default();
        let mut semantic = match ReceiverSemanticBridge::new(budget) {
            Ok(semantic) => semantic,
            Err(limit) => {
                return Ok(SemanticReceiverGate::Exceeded {
                    work: ReceiverAnalysisWork::default(),
                    limit,
                });
            }
        };
        let outcome = semantic
            .oracle(workspace)
            .pointees_at_source(
                file,
                range,
                &mut SemanticRequest::new(&mut semantic.budget, &cancellation),
            )
            .map_err(ReceiverQueryError::SemanticProvider)?;
        let work = semantic.work();
        let unsupported = match &outcome {
            SemanticOutcome::Unsupported { capability, .. } => Some(*capability),
            _ => None,
        };
        let evidence = outcome.available_value().map(|points_to| {
            let evidence = SemanticReceiverEvidence::from_points_to_outcome(&outcome, points_to);
            if semantic.call_context_disabled
                && points_to.object_candidates().any(|candidate| {
                    matches!(
                        candidate.value().identity(),
                        AbstractObjectIdentity::CallResult(_)
                    )
                })
            {
                SemanticReceiverEvidence::Incomplete {
                    coverage: if points_to.coverage().is_truncated() {
                        CandidateCoverage::Truncated
                    } else {
                        CandidateCoverage::Open
                    },
                    unsupported,
                    origin: SemanticReceiverIncompleteness::Local,
                }
            } else {
                evidence
            }
        });
        match outcome {
            SemanticOutcome::Cancelled { .. } => Err(ReceiverQueryError::Cancelled),
            SemanticOutcome::ExceededBudget { exceeded, .. } => {
                Ok(SemanticReceiverGate::Exceeded {
                    work,
                    limit: ReceiverSemanticBridge::receiver_limit(exceeded),
                })
            }
            outcome => match outcome.available_value() {
                Some(points_to) if !points_to.is_empty() => Ok(SemanticReceiverGate::Available {
                    work,
                    points_to: points_to.clone(),
                    evidence: evidence.expect("available semantic value has evidence quality"),
                }),
                Some(_) | None => Ok(SemanticReceiverGate::Unavailable { work, unsupported }),
            },
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn analyze_structural(
        &self,
        operation: ReceiverQueryOperation,
        file: &ProjectFile,
        language: Language,
        resolver: &'static dyn StructuralReceiverResolver,
        range: Range,
        input: ReceiverQueryInput,
        structural_facts: Option<&Arc<FileFacts>>,
        budget: ReceiverAnalysisBudget,
        cancellation: Option<&CancellationToken>,
    ) -> Result<ReceiverQueryReport, ReceiverQueryError> {
        let Some(workspace) = self.workspace else {
            return Ok(unsupported_report(
                operation,
                file,
                language,
                range,
                "receiver_semantic_workspace_unavailable",
                None,
            ));
        };

        let mut ledger = ReceiverWorkLedger::new(budget);
        let Some(facts) = structural_facts else {
            return Ok(unsupported_report(
                operation,
                file,
                language,
                range,
                "receiver_structural_facts_unavailable",
                None,
            ));
        };
        let prepared_matches = self
            .prepared_structural_files
            .borrow()
            .get(file)
            .is_some_and(|prepared| prepared.matches(facts));
        if !prepared_matches {
            match build_receiver_site_index(
                Arc::clone(facts),
                ReceiverSiteIndexLimit {
                    max_work_items: ledger.remaining_budget().max_scope_nodes,
                },
                cancellation,
            ) {
                ReceiverSiteIndexBuild::Complete {
                    index,
                    inspected_work,
                } => {
                    ledger
                        .charge_setup(inspected_work)
                        .expect("completed site indexing fits its supplied receiver budget");
                    check_cancelled(cancellation)?;
                    let syntax_nodes = index.source().len().div_ceil(256).max(1);
                    if ledger.charge_setup(syntax_nodes).is_err() {
                        return Ok(setup_budget_report(
                            operation,
                            file,
                            language,
                            range,
                            index.source(),
                            ledger.work(),
                        ));
                    }
                    let Some(syntax) = prepared_structural_syntax_limited(
                        self.analyzer,
                        language,
                        file,
                        index.source().len(),
                        cancellation,
                    ) else {
                        let mut report = unsupported_report(
                            operation,
                            file,
                            language,
                            range,
                            "receiver_analyzer_unavailable",
                            Some(index.source()),
                        );
                        report.work = ledger.work();
                        return Ok(report);
                    };
                    let syntax = match syntax {
                        StructuralSyntaxLimitedOutcome::Available(syntax) => {
                            let syntax = syntax.into_inner();
                            if syntax.source() == index.source() {
                                syntax
                            } else {
                                let mut report = unsupported_report(
                                    operation,
                                    file,
                                    language,
                                    range,
                                    "receiver_source_snapshot_mismatch",
                                    Some(index.source()),
                                );
                                report.work = ledger.work();
                                return Ok(report);
                            }
                        }
                        StructuralSyntaxLimitedOutcome::Exceeded { .. } => {
                            let mut report = unsupported_report(
                                operation,
                                file,
                                language,
                                range,
                                "receiver_source_snapshot_mismatch",
                                Some(index.source()),
                            );
                            report.work = ledger.work();
                            return Ok(report);
                        }
                        StructuralSyntaxLimitedOutcome::Cancelled => {
                            return Err(ReceiverQueryError::Cancelled);
                        }
                        StructuralSyntaxLimitedOutcome::Unavailable => {
                            let mut report = unsupported_report(
                                operation,
                                file,
                                language,
                                range,
                                "receiver_source_parse_failed",
                                Some(index.source()),
                            );
                            report.work = ledger.work();
                            return Ok(report);
                        }
                    };
                    check_cancelled(cancellation)?;
                    self.prepared_structural_files.borrow_mut().insert(
                        file.clone(),
                        PreparedStructuralReceiverFile {
                            facts: Arc::clone(facts),
                            sites: index,
                            syntax,
                        },
                    );
                }
                ReceiverSiteIndexBuild::Exceeded { inspected_work } => {
                    let _ = ledger.charge_setup(inspected_work);
                    return Ok(setup_budget_report(
                        operation,
                        file,
                        language,
                        range,
                        facts.source(),
                        ledger.work(),
                    ));
                }
                ReceiverSiteIndexBuild::Cancelled { inspected_work } => {
                    let _ = ledger.charge_setup(inspected_work);
                    return Err(ReceiverQueryError::Cancelled);
                }
            }
        }

        let prepared_files = self.prepared_structural_files.borrow();
        let prepared = prepared_files
            .get(file)
            .expect("structural receiver sites were prepared above");
        debug_assert!(prepared.matches(facts));
        let source = prepared.sites.source();
        let selection_mode = match input {
            ReceiverQueryInput::ContainingSite => ReceiverSiteInputMode::ContainingSite,
            ReceiverQueryInput::Expression => ReceiverSiteInputMode::Expression,
        };
        let selected = match prepared.sites.select_bounded(
            range,
            selection_mode,
            ReceiverSiteSelectionLimit {
                max_inspected_sites: ledger.remaining_budget().max_scope_nodes,
            },
            cancellation,
        ) {
            ReceiverSiteSelection::Complete {
                site,
                inspected_sites,
            } => {
                ledger
                    .charge_setup(inspected_sites)
                    .expect("completed site selection fits its supplied receiver budget");
                site
            }
            ReceiverSiteSelection::Exceeded { inspected_sites } => {
                let _ = ledger.charge_setup(inspected_sites);
                return Ok(setup_budget_report(
                    operation,
                    file,
                    language,
                    range,
                    source,
                    ledger.work(),
                ));
            }
            ReceiverSiteSelection::Cancelled { inspected_sites } => {
                let _ = ledger.charge_setup(inspected_sites);
                return Err(ReceiverQueryError::Cancelled);
            }
        };
        let query_range = match (operation, input, selected) {
            (ReceiverQueryOperation::MemberTargets, _, Some(site))
            | (_, ReceiverQueryInput::ContainingSite, Some(site)) => site.receiver_range,
            (ReceiverQueryOperation::MemberTargets, _, None)
            | (_, ReceiverQueryInput::ContainingSite, None) => {
                let mut report = unsupported_report(
                    operation,
                    file,
                    language,
                    range,
                    "receiver_site_without_receiver",
                    Some(source),
                );
                report.work = ledger.work();
                return Ok(report);
            }
            (_, ReceiverQueryInput::Expression, _) => range,
        };
        let member_range = (operation == ReceiverQueryOperation::MemberTargets)
            .then(|| selected.and_then(|site| site.member_range))
            .flatten();
        if operation == ReceiverQueryOperation::MemberTargets && member_range.is_none() {
            let mut report = unsupported_report(
                operation,
                file,
                language,
                range,
                "member_target_site_unsupported",
                Some(source),
            );
            report.work = ledger.work();
            return Ok(report);
        }
        let syntax_kind = selected.map_or("expression", |site| match site.kind {
            ReceiverSiteKind::Call => "call",
            ReceiverSiteKind::FieldAccess => "field_access",
        });
        let member_name = member_range
            .and_then(|member| source.get(member.start_byte..member.end_byte))
            .filter(|member| !member.is_empty())
            .map(str::to_string);
        let report_site = site(
            file,
            language,
            query_range,
            source,
            syntax_kind,
            member_name,
        );

        let fallback_cancellation = CancellationToken::default();
        let cancellation = cancellation.unwrap_or(&fallback_cancellation);
        check_cancelled(Some(cancellation))?;
        if let Err(limit) = charge_scope_step(&mut ledger) {
            return Ok(budget_report(operation, report_site, ledger.work(), limit));
        }

        let reference_site = structural_reference_site(file, source, query_range);
        let resolution = resolver.resolve_type_bounded(BoundedReceiverQuery {
            analyzer: self.analyzer,
            file,
            source,
            tree: Some(prepared.syntax.tree()),
            site: &reference_site,
            budget: ledger.remaining_budget(),
            cancellation: Some(cancellation),
        });
        let type_outcome = match charge_bounded_resolution(&mut ledger, resolution)? {
            CompatibilityOutcome::Complete(outcome) => outcome,
            CompatibilityOutcome::Exceeded(limit) => {
                return Ok(budget_report(operation, report_site, ledger.work(), limit));
            }
        };
        if let Some(reason) = structural_receiver_unsupported_reason(language, &type_outcome) {
            let mut report = unknown_report(operation, report_site, ledger.work(), false);
            neutral_unsupported(&mut report.analysis, reason);
            return Ok(report);
        }
        let static_type_reference = type_outcome.target_kind == TypeLookupTargetKind::TypeReference;
        let static_type_resolved = type_outcome.status == TypeLookupStatus::Resolved;

        if operation != ReceiverQueryOperation::MemberTargets && static_type_reference {
            let projection = match project_static_receiver_values(
                &type_outcome,
                Some(cancellation),
                &mut ledger,
            )? {
                CompatibilityOutcome::Complete(projection) => projection,
                CompatibilityOutcome::Exceeded(limit) => {
                    return Ok(budget_report(operation, report_site, ledger.work(), limit));
                }
            };
            let mut analysis = ReceiverQueryAnalysis::Values(receiver_type_outcome(
                type_outcome.status,
                projection.values,
            ));
            if projection.truncated {
                neutral_incomplete(&mut analysis);
            }
            return Ok(ReceiverQueryReport {
                operation,
                site: report_site,
                analysis,
                work: ledger.work(),
                candidates_truncated: projection.truncated,
                semantic_unsupported: None,
            });
        }

        let semantic = (!static_type_reference)
            .then(|| {
                self.semantic_receiver_gate(
                    file,
                    query_range,
                    ledger.remaining_budget(),
                    Some(cancellation),
                )
            })
            .transpose()?;
        if let Some(semantic) = &semantic
            && let Some(limit) = charge_semantic_gate(&mut ledger, semantic)
        {
            return Ok(budget_report(operation, report_site, ledger.work(), limit));
        }
        let (points_to, evidence) = match semantic {
            None => (None, SemanticReceiverEvidence::ExhaustiveComplete),
            Some(SemanticReceiverGate::Available {
                points_to,
                evidence,
                ..
            }) => (Some(points_to), evidence),
            Some(SemanticReceiverGate::Bypassed { .. }) => {
                return Ok(unknown_report(operation, report_site, ledger.work(), false));
            }
            Some(SemanticReceiverGate::Unavailable { unsupported, .. }) => {
                let mut report = unknown_report(operation, report_site, ledger.work(), false);
                if let Some(capability) = unsupported {
                    neutral_unsupported(&mut report.analysis, capability.label());
                }
                return Ok(report);
            }
            Some(SemanticReceiverGate::Exceeded { .. }) => {
                unreachable!("semantic gate budget exits before compatibility analysis")
            }
        };

        if operation == ReceiverQueryOperation::MemberTargets {
            let member_range = member_range.expect("member target range was validated above");
            let reference_site = structural_reference_site(file, source, member_range);
            let resolution = resolver.resolve_definition_bounded(BoundedReceiverQuery {
                analyzer: self.analyzer,
                file,
                source,
                tree: Some(prepared.syntax.tree()),
                site: &reference_site,
                budget: ledger.remaining_budget(),
                cancellation: Some(cancellation),
            });
            let outcome = match charge_bounded_resolution(&mut ledger, resolution)? {
                CompatibilityOutcome::Complete(outcome) => outcome,
                CompatibilityOutcome::Exceeded(limit) => {
                    return Ok(budget_report(operation, report_site, ledger.work(), limit));
                }
            };
            let (outcome, resolution_truncated) =
                definition_outcome(outcome, ledger.remaining_budget().max_targets);
            let mut analysis = ReceiverQueryAnalysis::MemberTargets(outcome);
            let statically_bound_data_member =
                structural_member_is_statically_bound_data_member(language, &analysis);
            let evidence_supports_precision =
                evidence.supports_precise() || statically_bound_data_member;
            let mut dispatch_supports_precise = statically_bound_data_member;
            if !statically_bound_data_member
                && analysis_is_precise(&analysis)
                && evidence.supports_precise()
                && !resolution_truncated
                && (!static_type_reference || static_type_resolved)
            {
                dispatch_supports_precise = match structural_member_dispatch_supports_precise(
                    self.analyzer,
                    language,
                    &analysis,
                    Some(cancellation),
                    &mut ledger,
                )? {
                    CompatibilityOutcome::Complete(supports_precise) => supports_precise,
                    CompatibilityOutcome::Exceeded(limit) => {
                        return Ok(budget_report(operation, report_site, ledger.work(), limit));
                    }
                };
            }
            if !evidence_supports_precision
                || resolution_truncated
                || !dispatch_supports_precise
                || (static_type_reference && !static_type_resolved)
            {
                neutral_incomplete(&mut analysis);
            }
            return Ok(ReceiverQueryReport {
                operation,
                site: report_site,
                analysis,
                work: ledger.work(),
                candidates_truncated: evidence.is_truncated() || resolution_truncated,
                semantic_unsupported: evidence.unsupported_capability(),
            });
        }

        let points_to = points_to
            .expect("non-static structural receiver analysis requires neutral points-to evidence");
        let query_node = match java_smallest_named_node_covering(
            prepared.syntax.tree().root_node(),
            query_range.start_byte,
            query_range.end_byte,
            Some(cancellation),
            &mut ledger,
        )? {
            CompatibilityOutcome::Complete(node) => node,
            CompatibilityOutcome::Exceeded(limit) => {
                return Ok(budget_report(operation, report_site, ledger.work(), limit));
            }
        };
        let factories = if points_to_contains_call_result(&points_to, Some(cancellation))?
            && let Some(factory_node) =
                query_node.and_then(|node| structural_factory_name_node(language, node))
        {
            let factory_site = structural_reference_site(file, source, node_range(factory_node));
            let resolution = resolver.resolve_definition_bounded(BoundedReceiverQuery {
                analyzer: self.analyzer,
                file,
                source,
                tree: Some(prepared.syntax.tree()),
                site: &factory_site,
                budget: ledger.remaining_budget(),
                cancellation: Some(cancellation),
            });
            match charge_bounded_resolution(&mut ledger, resolution)? {
                CompatibilityOutcome::Complete(outcome)
                    if outcome.status == DefinitionLookupStatus::Resolved
                        && !outcome.definitions.is_empty()
                        && outcome.definitions.iter().all(|definition| {
                            if language == Language::Cpp {
                                definition.is_callable()
                            } else {
                                definition.is_function()
                            }
                        })
                        && (language == Language::Cpp || outcome.definitions.len() == 1) =>
                {
                    outcome.definitions
                }
                CompatibilityOutcome::Complete(_) => Vec::new(),
                CompatibilityOutcome::Exceeded(limit) => {
                    return Ok(budget_report(operation, report_site, ledger.work(), limit));
                }
            }
        } else {
            Vec::new()
        };
        let values = project_receiver_values(
            workspace,
            &points_to,
            &type_outcome,
            &factories,
            false,
            Some(cancellation),
            &mut ledger,
        )?;
        let projection = match values {
            CompatibilityOutcome::Complete(projection) => projection,
            CompatibilityOutcome::Exceeded(limit) => {
                return Ok(budget_report(operation, report_site, ledger.work(), limit));
            }
        };
        let mut analysis = ReceiverQueryAnalysis::Values(receiver_type_outcome(
            type_outcome.status,
            projection.values,
        ));
        if !evidence.supports_precise() || projection.truncated || projection.multiple_identities {
            neutral_incomplete(&mut analysis);
        }
        Ok(ReceiverQueryReport {
            operation,
            site: report_site,
            analysis,
            work: ledger.work(),
            candidates_truncated: evidence.is_truncated() || projection.truncated,
            semantic_unsupported: evidence.unsupported_capability(),
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn analyze_java(
        &self,
        operation: ReceiverQueryOperation,
        file: &ProjectFile,
        range: Range,
        input: ReceiverQueryInput,
        budget: ReceiverAnalysisBudget,
        cancellation: Option<&CancellationToken>,
        indexed_source: Option<String>,
    ) -> Result<ReceiverQueryReport, ReceiverQueryError> {
        let Some(workspace) = self.workspace else {
            return Ok(unsupported_report(
                operation,
                file,
                Language::Java,
                range,
                "receiver_semantic_workspace_unavailable",
                indexed_source.as_deref(),
            ));
        };
        let Some(source) = indexed_source else {
            return Ok(unsupported_report(
                operation,
                file,
                Language::Java,
                range,
                "indexed_source_unavailable",
                None,
            ));
        };

        let mut ledger = ReceiverWorkLedger::new(budget);
        if !self.prepared_java_files.borrow().contains_key(file) {
            let Some(tree) = parse_tree_for_language(file, Language::Java, &source) else {
                return Ok(unsupported_report(
                    operation,
                    file,
                    Language::Java,
                    range,
                    "receiver_source_parse_failed",
                    Some(&source),
                ));
            };
            check_cancelled(cancellation)?;
            let line_starts = compute_line_starts(&source);
            check_cancelled(cancellation)?;
            if ledger.charge_setup(line_starts.len()).is_err() {
                return Ok(setup_budget_report(
                    operation,
                    file,
                    Language::Java,
                    range,
                    &source,
                    ledger.work(),
                ));
            }
            let setup_nodes = match walk_named_tree_preorder_bounded(
                tree.root_node(),
                true,
                ledger.remaining_budget().max_scope_nodes,
                cancellation,
                |_| {},
            ) {
                BoundedNamedTreeWalk::Complete { visited } => visited,
                BoundedNamedTreeWalk::Exceeded { visited } => {
                    let _ = ledger.charge_setup(visited);
                    return Ok(setup_budget_report(
                        operation,
                        file,
                        Language::Java,
                        range,
                        &source,
                        ledger.work(),
                    ));
                }
                BoundedNamedTreeWalk::Cancelled => return Err(ReceiverQueryError::Cancelled),
            };
            ledger
                .charge_setup(setup_nodes)
                .expect("completed setup traversal fits its supplied receiver budget");
            self.prepared_java_files.borrow_mut().insert(
                file.clone(),
                PreparedJavaReceiverFile {
                    source,
                    tree,
                    line_starts,
                },
            );
        }

        let prepared_files = self.prepared_java_files.borrow();
        let prepared = prepared_files
            .get(file)
            .expect("Java receiver file was prepared above");
        let input_node = match java_smallest_named_node_covering(
            prepared.tree.root_node(),
            range.start_byte,
            range.end_byte,
            cancellation,
            &mut ledger,
        )? {
            CompatibilityOutcome::Complete(Some(node)) => node,
            CompatibilityOutcome::Complete(None) => {
                let mut report = unsupported_report(
                    operation,
                    file,
                    Language::Java,
                    range,
                    "receiver_input_range_unavailable",
                    Some(&prepared.source),
                );
                report.work = ledger.work();
                return Ok(report);
            }
            CompatibilityOutcome::Exceeded(limit) => {
                return Ok(budget_report(
                    operation,
                    site(file, Language::Java, range, &prepared.source, "query", None),
                    ledger.work(),
                    limit,
                ));
            }
        };
        let query_node = match operation {
            ReceiverQueryOperation::PointsTo => input_node,
            ReceiverQueryOperation::ReceiverTargets | ReceiverQueryOperation::MemberTargets
                if input == ReceiverQueryInput::ContainingSite =>
            {
                match java_receiver_at_site(input_node, cancellation, &mut ledger)? {
                    CompatibilityOutcome::Complete(Some(receiver)) => receiver,
                    CompatibilityOutcome::Complete(None) => {
                        let mut report = unsupported_report(
                            operation,
                            file,
                            Language::Java,
                            range,
                            "receiver_site_without_receiver",
                            Some(&prepared.source),
                        );
                        report.work = ledger.work();
                        return Ok(report);
                    }
                    CompatibilityOutcome::Exceeded(limit) => {
                        return Ok(budget_report(
                            operation,
                            site(
                                file,
                                Language::Java,
                                node_range(input_node),
                                &prepared.source,
                                input_node.kind(),
                                None,
                            ),
                            ledger.work(),
                            limit,
                        ));
                    }
                }
            }
            ReceiverQueryOperation::ReceiverTargets | ReceiverQueryOperation::MemberTargets => {
                input_node
            }
        };
        let query_range = node_range(query_node);
        let member_node = match java_member_node_at_site(input_node, cancellation, &mut ledger)? {
            CompatibilityOutcome::Complete(member) => member,
            CompatibilityOutcome::Exceeded(limit) => {
                return Ok(budget_report(
                    operation,
                    site(
                        file,
                        Language::Java,
                        query_range,
                        &prepared.source,
                        query_node.kind(),
                        None,
                    ),
                    ledger.work(),
                    limit,
                ));
            }
        };
        let member_name = member_node.and_then(|member| {
            prepared
                .source
                .get(member.start_byte()..member.end_byte())
                .map(str::to_string)
        });
        let semantic = self.semantic_receiver_gate(
            file,
            query_range,
            ledger.remaining_budget(),
            cancellation,
        )?;
        if let Some(limit) = charge_semantic_gate(&mut ledger, &semantic) {
            return Ok(budget_report(
                operation,
                site(
                    file,
                    Language::Java,
                    query_range,
                    &prepared.source,
                    query_node.kind(),
                    member_name,
                ),
                ledger.work(),
                limit,
            ));
        }
        let (points_to, mut candidates_truncated, supports_precise, semantic_unsupported) =
            match semantic {
                SemanticReceiverGate::Available {
                    points_to,
                    evidence,
                    ..
                } => (
                    points_to,
                    evidence.is_truncated(),
                    evidence.supports_precise(),
                    evidence.unsupported_capability(),
                ),
                SemanticReceiverGate::Bypassed { .. } => {
                    let mut report = java_unknown_report(
                        operation,
                        file,
                        query_node,
                        &prepared.source,
                        member_name,
                    );
                    report.work = ledger.work();
                    return Ok(report);
                }
                SemanticReceiverGate::Unavailable { unsupported, .. } => {
                    let mut report = java_unknown_report(
                        operation,
                        file,
                        query_node,
                        &prepared.source,
                        member_name,
                    );
                    report.work = ledger.work();
                    if let Some(capability) = unsupported {
                        neutral_unsupported(&mut report.analysis, capability.label());
                    }
                    return Ok(report);
                }
                SemanticReceiverGate::Exceeded { .. } => {
                    unreachable!("semantic gate budget exits before compatibility analysis")
                }
            };

        self.definitions.set_language(Language::Java);
        if operation == ReceiverQueryOperation::MemberTargets {
            let Some(member_node) = member_node else {
                let mut report =
                    java_unknown_report(operation, file, query_node, &prepared.source, member_name);
                report.work = ledger.work();
                return Ok(report);
            };
            let outcome = java_definition_at(
                self.analyzer,
                &self.definitions,
                file,
                prepared.resolution_input(),
                member_node,
                ledger.remaining_budget(),
                cancellation,
            );
            let outcome = match charge_compatibility(&mut ledger, outcome)? {
                CompatibilityOutcome::Complete(outcome) => outcome,
                CompatibilityOutcome::Exceeded(limit) => {
                    return Ok(budget_report(
                        operation,
                        site(
                            file,
                            Language::Java,
                            query_range,
                            &prepared.source,
                            query_node.kind(),
                            member_name,
                        ),
                        ledger.work(),
                        limit,
                    ));
                }
            };
            let (outcome, truncated) =
                definition_outcome(outcome, ledger.remaining_budget().max_targets);
            candidates_truncated |= truncated;
            let mut analysis = ReceiverQueryAnalysis::MemberTargets(outcome);
            if !supports_precise || candidates_truncated {
                neutral_incomplete(&mut analysis);
            }
            return Ok(ReceiverQueryReport {
                operation,
                site: site(
                    file,
                    Language::Java,
                    query_range,
                    &prepared.source,
                    query_node.kind(),
                    member_name,
                ),
                analysis,
                work: ledger.work(),
                candidates_truncated,
                semantic_unsupported,
            });
        }

        let type_resolution = java_type_outcome_at(
            self.analyzer,
            &self.definitions,
            file,
            prepared.resolution_input(),
            query_node,
            ledger.remaining_budget(),
            cancellation,
        );
        let mut type_outcome = match charge_compatibility(&mut ledger, type_resolution)? {
            CompatibilityOutcome::Complete(outcome) => outcome,
            CompatibilityOutcome::Exceeded(limit) => {
                return Ok(budget_report(
                    operation,
                    site(
                        file,
                        Language::Java,
                        query_range,
                        &prepared.source,
                        query_node.kind(),
                        member_name,
                    ),
                    ledger.work(),
                    limit,
                ));
            }
        };
        if type_outcome.types.is_empty() {
            let receiver_owners =
                current_receiver_owners(workspace, &points_to, cancellation, &mut ledger)?;
            let receiver_owners = match receiver_owners {
                CompatibilityOutcome::Complete(owners) => owners,
                CompatibilityOutcome::Exceeded(limit) => {
                    return Ok(budget_report(
                        operation,
                        site(
                            file,
                            Language::Java,
                            query_range,
                            &prepared.source,
                            query_node.kind(),
                            member_name,
                        ),
                        ledger.work(),
                        limit,
                    ));
                }
            };
            if !receiver_owners.is_empty() {
                let fqn = receiver_owners[0].fq_name();
                type_outcome.status = TypeLookupStatus::Resolved;
                type_outcome.types.push(TypeLookupType {
                    fqn,
                    definitions: receiver_owners,
                });
            }
        }
        if type_outcome.types.is_empty() {
            let context_node =
                match java_contextual_type_node(query_node, cancellation, &mut ledger)? {
                    CompatibilityOutcome::Complete(context_node) => context_node,
                    CompatibilityOutcome::Exceeded(limit) => {
                        return Ok(budget_report(
                            operation,
                            site(
                                file,
                                Language::Java,
                                query_range,
                                &prepared.source,
                                query_node.kind(),
                                member_name,
                            ),
                            ledger.work(),
                            limit,
                        ));
                    }
                };
            if let Some(context_node) = context_node {
                let contextual = java_type_outcome_at(
                    self.analyzer,
                    &self.definitions,
                    file,
                    prepared.resolution_input(),
                    context_node,
                    ledger.remaining_budget(),
                    cancellation,
                );
                type_outcome = match charge_compatibility(&mut ledger, contextual)? {
                    CompatibilityOutcome::Complete(outcome) => outcome,
                    CompatibilityOutcome::Exceeded(limit) => {
                        return Ok(budget_report(
                            operation,
                            site(
                                file,
                                Language::Java,
                                query_range,
                                &prepared.source,
                                query_node.kind(),
                                member_name,
                            ),
                            ledger.work(),
                            limit,
                        ));
                    }
                };
            }
        }
        candidates_truncated |= type_outcome
            .types
            .iter()
            .map(|ty| ty.definitions.len())
            .sum::<usize>()
            > ledger.remaining_budget().max_targets;

        let factory = if points_to_contains_call_result(&points_to, cancellation)?
            && let Some(factory_node) = java_factory_name_node(query_node)
        {
            let factory_resolution = java_definition_at(
                self.analyzer,
                &self.definitions,
                file,
                prepared.resolution_input(),
                factory_node,
                ledger.remaining_budget(),
                cancellation,
            );
            match charge_compatibility(&mut ledger, factory_resolution)? {
                CompatibilityOutcome::Complete(outcome) => (outcome.definitions.len() == 1)
                    .then(|| outcome.definitions.into_iter().next())
                    .flatten(),
                CompatibilityOutcome::Exceeded(limit) => {
                    return Ok(budget_report(
                        operation,
                        site(
                            file,
                            Language::Java,
                            query_range,
                            &prepared.source,
                            query_node.kind(),
                            member_name,
                        ),
                        ledger.work(),
                        limit,
                    ));
                }
            }
        } else {
            None
        };

        let type_resolution = java_definition_at(
            self.analyzer,
            &self.definitions,
            file,
            prepared.resolution_input(),
            query_node,
            ledger.remaining_budget(),
            cancellation,
        );
        let type_reference = match charge_compatibility(&mut ledger, type_resolution)? {
            CompatibilityOutcome::Complete(outcome) => {
                !outcome.definitions.is_empty()
                    && outcome.definitions.iter().all(CodeUnit::is_class)
            }
            CompatibilityOutcome::Exceeded(limit) => {
                return Ok(budget_report(
                    operation,
                    site(
                        file,
                        Language::Java,
                        query_range,
                        &prepared.source,
                        query_node.kind(),
                        member_name,
                    ),
                    ledger.work(),
                    limit,
                ));
            }
        };
        check_cancelled(cancellation)?;

        let mut analysis = match operation {
            ReceiverQueryOperation::ReceiverTargets | ReceiverQueryOperation::PointsTo => {
                let values = project_receiver_values(
                    workspace,
                    &points_to,
                    &type_outcome,
                    factory.as_slice(),
                    type_reference,
                    cancellation,
                    &mut ledger,
                )?;
                let projection = match values {
                    CompatibilityOutcome::Complete(projection) => projection,
                    CompatibilityOutcome::Exceeded(limit) => {
                        return Ok(budget_report(
                            operation,
                            site(
                                file,
                                Language::Java,
                                query_range,
                                &prepared.source,
                                query_node.kind(),
                                member_name,
                            ),
                            ledger.work(),
                            limit,
                        ));
                    }
                };
                candidates_truncated |= projection.truncated;
                let mut outcome = receiver_type_outcome(type_outcome.status, projection.values);
                if projection.multiple_identities {
                    downgrade_precise(&mut outcome);
                }
                ReceiverQueryAnalysis::Values(outcome)
            }
            ReceiverQueryOperation::MemberTargets => {
                unreachable!("member targets return through the exact Java resolver above")
            }
        };
        if !supports_precise || candidates_truncated {
            neutral_incomplete(&mut analysis);
        }

        check_cancelled(cancellation)?;

        Ok(ReceiverQueryReport {
            operation,
            site: site(
                file,
                Language::Java,
                query_range,
                &prepared.source,
                query_node.kind(),
                member_name,
            ),
            analysis,
            work: ledger.work(),
            candidates_truncated,
            semantic_unsupported,
        })
    }

    #[cfg(test)]
    fn prepared_file_count(&self) -> usize {
        self.prepared_files.borrow().len()
            + self.prepared_java_files.borrow().len()
            + self.prepared_structural_files.borrow().len()
    }
}

fn charge_semantic_gate(
    ledger: &mut ReceiverWorkLedger,
    gate: &SemanticReceiverGate,
) -> Option<ReceiverBudgetLimit> {
    ledger
        .charge_analysis(gate.work())
        .err()
        .or_else(|| gate.exceeded_limit())
}

fn analysis_is_precise(analysis: &ReceiverQueryAnalysis) -> bool {
    match analysis {
        ReceiverQueryAnalysis::Values(outcome) => outcome.is_precise(),
        ReceiverQueryAnalysis::MemberTargets(outcome) => outcome.is_precise(),
    }
}

fn prepared_structural_syntax_limited(
    analyzer: &dyn IAnalyzer,
    language: Language,
    file: &ProjectFile,
    max_source_bytes: usize,
    cancellation: Option<&CancellationToken>,
) -> Option<StructuralSyntaxLimitedOutcome> {
    analyzer
        .structural_search_providers()
        .into_iter()
        .find(|provider| provider.structural_language() == language)
        .map(|provider| provider.structural_syntax_limited(file, max_source_bytes, cancellation))
}

fn structural_receiver_unsupported_reason(
    language: Language,
    outcome: &TypeLookupOutcome,
) -> Option<&'static str> {
    match language {
        Language::Cpp
            if outcome
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.kind == "cpp_c_receiver_unsupported") =>
        {
            Some("cpp_c_receiver_unsupported")
        }
        Language::CSharp
            if outcome
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.kind == "csharp_dynamic_receiver_unsupported") =>
        {
            Some("csharp_dynamic_receiver_unsupported")
        }
        _ => None,
    }
}

fn structural_member_dispatch_supports_precise(
    analyzer: &dyn IAnalyzer,
    language: Language,
    analysis: &ReceiverQueryAnalysis,
    cancellation: Option<&CancellationToken>,
    ledger: &mut ReceiverWorkLedger,
) -> Result<CompatibilityOutcome<bool>, ReceiverQueryError> {
    let ReceiverQueryAnalysis::MemberTargets(ReceiverAnalysisOutcome::Precise(targets)) = analysis
    else {
        return Ok(CompatibilityOutcome::Complete(false));
    };
    let [target] = targets.as_slice() else {
        return Ok(CompatibilityOutcome::Complete(false));
    };
    check_cancelled(cancellation)?;
    if structural_member_is_statically_bound_data_member(language, analysis) {
        return Ok(CompatibilityOutcome::Complete(true));
    }
    if let Err(limit) = charge_summary_step(ledger) {
        return Ok(CompatibilityOutcome::Exceeded(limit));
    }
    if let Err(limit) = charge_scope_step(ledger) {
        return Ok(CompatibilityOutcome::Exceeded(limit));
    }
    let provider_limit = ledger.remaining_budget().max_scope_nodes.saturating_add(1);
    let metadata = language_support(language)
        .and_then(|support| support.signature_metadata_limited(analyzer, target, provider_limit));
    let Some(metadata) = metadata else {
        return Ok(CompatibilityOutcome::Exceeded(
            ReceiverBudgetLimit::ScopeNodes,
        ));
    };
    let metadata = match charge_limited_projection(metadata, cancellation, ledger)? {
        CompatibilityOutcome::Complete(metadata) => metadata,
        CompatibilityOutcome::Exceeded(limit) => {
            return Ok(CompatibilityOutcome::Exceeded(limit));
        }
    };
    if metadata.is_empty() {
        return Ok(CompatibilityOutcome::Complete(false));
    }
    Ok(CompatibilityOutcome::Complete(metadata.iter().all(
        |metadata| metadata.dispatch_extensibility() == Some(DispatchExtensibility::Closed),
    )))
}

fn structural_member_is_statically_bound_data_member(
    language: Language,
    analysis: &ReceiverQueryAnalysis,
) -> bool {
    let ReceiverQueryAnalysis::MemberTargets(ReceiverAnalysisOutcome::Precise(targets)) = analysis
    else {
        return false;
    };
    matches!(targets.as_slice(), [target] if target.is_field())
        && matches!(language, Language::Cpp | Language::Go)
}

fn finalize_legacy_report(
    report: ReceiverQueryReport,
    gate: SemanticReceiverGate,
    ledger: &mut ReceiverWorkLedger,
) -> ReceiverQueryReport {
    let compatibility_limit = ledger.charge_analysis(report.work).err();
    let mut report = apply_semantic_gate(report, gate);
    if let Some(limit) = compatibility_limit {
        neutral_exceeded(&mut report.analysis, limit);
    }
    report.work = ledger.work();
    report
}

fn apply_semantic_gate(
    mut report: ReceiverQueryReport,
    gate: SemanticReceiverGate,
) -> ReceiverQueryReport {
    match gate {
        SemanticReceiverGate::Bypassed { .. } => {}
        SemanticReceiverGate::Available {
            points_to,
            evidence,
            ..
        } => {
            let removed = retain_neutral_backed_values(&mut report.analysis, &points_to);
            report.candidates_truncated |= removed;
            report.candidates_truncated |= evidence.is_truncated();
            report.semantic_unsupported = evidence.unsupported_capability();
            // The legacy JS/TS provider independently proves closure for its
            // supported lexical forms. Preserve that proof only when neutral
            // candidates are themselves proven/complete and openness comes
            // from the adapter's global capability surface. Query-local
            // uncertainty (including disabled call context) remains
            // non-precise.
            if !evidence.supports_precise() && !evidence.legacy_provider_can_close() {
                neutral_incomplete(&mut report.analysis);
            }
        }
        SemanticReceiverGate::Unavailable { unsupported, .. } => {
            if let Some(capability) = unsupported {
                neutral_unsupported(&mut report.analysis, capability.label());
            } else {
                neutral_unknown(&mut report.analysis);
            }
        }
        SemanticReceiverGate::Exceeded { limit, .. } => {
            neutral_exceeded(&mut report.analysis, limit);
        }
    }
    report
}

fn retain_neutral_backed_values(
    analysis: &mut ReceiverQueryAnalysis,
    points_to: &SourcePointsToResult,
) -> bool {
    let ReceiverQueryAnalysis::Values(outcome) = analysis else {
        return false;
    };
    let previous = std::mem::replace(outcome, ReceiverAnalysisOutcome::Unknown);
    let (mut values, was_precise) = match previous {
        ReceiverAnalysisOutcome::Precise(values) => (values, true),
        ReceiverAnalysisOutcome::Ambiguous(values) => (values, false),
        terminal => {
            *outcome = terminal;
            return false;
        }
    };
    let original_len = values.len();
    values.retain(|value| {
        points_to
            .object_candidates()
            .any(|candidate| neutral_object_supports_receiver(candidate.value().identity(), value))
    });
    let removed = values.len() != original_len;
    *outcome = if values.is_empty() {
        ReceiverAnalysisOutcome::Unknown
    } else if was_precise && !removed {
        ReceiverAnalysisOutcome::Precise(values)
    } else {
        ReceiverAnalysisOutcome::Ambiguous(values)
    };
    removed
}

fn neutral_object_supports_receiver(
    identity: &AbstractObjectIdentity,
    value: &ReceiverValue,
) -> bool {
    if let ReceiverValue::FactoryReturn { value, .. } = value {
        return neutral_object_supports_receiver(identity, value);
    }
    match (identity, value) {
        (
            AbstractObjectIdentity::Allocation(allocation),
            ReceiverValue::AllocationSite { file, range, .. },
        ) => {
            let Some(row) = allocation
                .procedure()
                .semantics()
                .allocation(allocation.id())
            else {
                return false;
            };
            let Some(mapping) = allocation
                .procedure()
                .semantics()
                .source_mapping(row.source)
            else {
                return false;
            };
            let span = mapping.locator.anchor().span();
            allocation.procedure().artifact().key().path().as_path() == file.rel_path()
                && span.start_byte() as usize == range.start_byte
                && span.end_byte() as usize == range.end_byte
        }
        (AbstractObjectIdentity::ProcedurePort(port), ReceiverValue::CurrentReceiver(_)) => {
            port.kind() == crate::analyzer::semantic::ProcedurePortKind::Receiver
        }
        (AbstractObjectIdentity::ProcedurePort(port), ReceiverValue::InstanceType(_)) => matches!(
            port.kind(),
            crate::analyzer::semantic::ProcedurePortKind::Parameter { .. }
        ),
        (AbstractObjectIdentity::Static(_), ReceiverValue::ClassOrStaticObject(_))
        | (AbstractObjectIdentity::ModuleObject(_), ReceiverValue::ModuleOrExportObject(_)) => true,
        // Symbolic roots deliberately carry no nominal compatibility label.
        // The structured projector decorates that same neutral root as an
        // instance, allocation, static object, or module for the stable DTO.
        (
            AbstractObjectIdentity::Value(_)
            | AbstractObjectIdentity::CallResult(_)
            | AbstractObjectIdentity::LexicalCell(_)
            | AbstractObjectIdentity::CaptureSlot(_)
            | AbstractObjectIdentity::TypeSummary(_)
            | AbstractObjectIdentity::External(_),
            _,
        ) => true,
        _ => false,
    }
}

fn neutral_unknown(analysis: &mut ReceiverQueryAnalysis) {
    match analysis {
        ReceiverQueryAnalysis::Values(outcome) => replace_with_neutral_unknown(outcome),
        ReceiverQueryAnalysis::MemberTargets(outcome) => replace_with_neutral_unknown(outcome),
    }
}

fn neutral_incomplete(analysis: &mut ReceiverQueryAnalysis) {
    match analysis {
        ReceiverQueryAnalysis::Values(outcome) => downgrade_precise(outcome),
        ReceiverQueryAnalysis::MemberTargets(outcome) => downgrade_precise(outcome),
    }
}

fn neutral_unsupported(analysis: &mut ReceiverQueryAnalysis, reason: &'static str) {
    match analysis {
        ReceiverQueryAnalysis::Values(outcome) => {
            *outcome = ReceiverAnalysisOutcome::Unsupported { reason };
        }
        ReceiverQueryAnalysis::MemberTargets(outcome) => {
            *outcome = ReceiverAnalysisOutcome::Unsupported { reason };
        }
    }
}

fn downgrade_precise<T>(outcome: &mut ReceiverAnalysisOutcome<T>) {
    let ReceiverAnalysisOutcome::Precise(_) = outcome else {
        return;
    };
    let previous = std::mem::replace(outcome, ReceiverAnalysisOutcome::Unknown);
    if let ReceiverAnalysisOutcome::Precise(values) = previous
        && !values.is_empty()
    {
        *outcome = ReceiverAnalysisOutcome::Ambiguous(values);
    }
}

fn replace_with_neutral_unknown<T>(outcome: &mut ReceiverAnalysisOutcome<T>) {
    if !matches!(
        outcome,
        ReceiverAnalysisOutcome::Unsupported { .. }
            | ReceiverAnalysisOutcome::ExceededBudget { .. }
    ) {
        *outcome = ReceiverAnalysisOutcome::Unknown;
    }
}

fn neutral_exceeded(analysis: &mut ReceiverQueryAnalysis, limit: ReceiverBudgetLimit) {
    match analysis {
        ReceiverQueryAnalysis::Values(outcome) => replace_with_neutral_exceeded(outcome, limit),
        ReceiverQueryAnalysis::MemberTargets(outcome) => {
            replace_with_neutral_exceeded(outcome, limit)
        }
    }
}

fn replace_with_neutral_exceeded<T>(
    outcome: &mut ReceiverAnalysisOutcome<T>,
    limit: ReceiverBudgetLimit,
) {
    if !matches!(outcome, ReceiverAnalysisOutcome::Unsupported { .. }) {
        *outcome = ReceiverAnalysisOutcome::ExceededBudget {
            limit: limit.as_str(),
        };
    }
}

#[derive(Debug)]
struct ReceiverSemanticBridge {
    budget: SemanticBudget,
    oracle_limits: OracleLimits,
    call_context_disabled: bool,
}

impl ReceiverSemanticBridge {
    const SCOPE_DIMENSIONS: usize = 11;
    const SUMMARY_DIMENSIONS: usize = 3;

    fn new(receiver: ReceiverAnalysisBudget) -> Result<Self, ReceiverBudgetLimit> {
        if receiver.max_scope_nodes < Self::SCOPE_DIMENSIONS {
            return Err(ReceiverBudgetLimit::ScopeNodes);
        }
        if receiver.max_summary_expansions < Self::SUMMARY_DIMENSIONS {
            return Err(ReceiverBudgetLimit::SummaryExpansions);
        }

        let scope = receiver.max_scope_nodes;
        let summaries = receiver.max_summary_expansions;
        let targets = receiver.max_targets.max(1);
        // Oracle limits are positive by contract. Preserve the caller's zero
        // context request separately so any retained call-result candidate is
        // downgraded even though the representational minimum is one frame.
        let context = receiver.context_depth.max(1);
        let text = scope.saturating_mul(1_024).max(1);
        // Publishing each retained points-to candidate consumes one nested
        // entry after graph traversal succeeds. Reserve that bounded tail so
        // an otherwise complete receiver query cannot fail while serializing
        // its final candidate set.
        let publication_reserve = targets.min(scope - Self::SCOPE_DIMENSIONS);
        let [
            procedures,
            blocks,
            program_points,
            values,
            allocations,
            source_mappings,
            evidence,
            gaps,
            events,
            control_edges,
            mut nested_entries,
        ] = partition_receiver_scope_limit(scope - publication_reserve);
        nested_entries += publication_reserve;
        let [call_sites, memory_locations, captures] = partition_receiver_summary_limit(summaries);
        let budget = SemanticBudget::new(SemanticWork {
            source_bytes: text,
            procedures,
            blocks,
            program_points,
            values,
            allocations,
            call_sites,
            memory_locations,
            captures,
            source_mappings,
            evidence,
            gaps,
            events,
            control_edges,
            nested_entries,
            owned_text_bytes: text,
        })
        .expect("receiver semantic budget is positive");

        let defaults = OracleLimits::default().values();
        let oracle_limits = OracleLimits::new(OracleLimitValues {
            dispatch_targets: targets,
            objects_per_value: targets,
            alias_breadth: targets,
            source_observations: targets,
            call_context_depth: context,
            summary_depth: summaries,
            call_binding_entries: summaries,
            ..defaults
        })
        .expect("receiver oracle limits are positive");
        Ok(Self {
            budget,
            oracle_limits,
            call_context_disabled: receiver.context_depth == 0,
        })
    }

    fn oracle<'workspace>(
        &self,
        workspace: &'workspace WorkspaceAnalyzer,
    ) -> WorkspaceSemanticOracle<'workspace> {
        WorkspaceSemanticOracle::with_limits(workspace, self.oracle_limits)
    }

    fn work(&self) -> ReceiverAnalysisWork {
        Self::receiver_work(self.budget.used())
    }

    fn receiver_work(work: SemanticWork) -> ReceiverAnalysisWork {
        ReceiverAnalysisWork {
            setup_nodes: 0,
            summary_expansions: work
                .call_sites
                .saturating_add(work.memory_locations)
                .saturating_add(work.captures),
            scope_nodes: work
                .procedures
                .saturating_add(work.blocks)
                .saturating_add(work.program_points)
                .saturating_add(work.values)
                .saturating_add(work.allocations)
                .saturating_add(work.source_mappings)
                .saturating_add(work.evidence)
                .saturating_add(work.gaps)
                .saturating_add(work.events)
                .saturating_add(work.control_edges)
                .saturating_add(work.nested_entries),
        }
    }

    fn receiver_limit(exceeded: SemanticBudgetExceeded) -> ReceiverBudgetLimit {
        match exceeded.dimension() {
            SemanticBudgetDimension::CallSites
            | SemanticBudgetDimension::MemoryLocations
            | SemanticBudgetDimension::Captures => ReceiverBudgetLimit::SummaryExpansions,
            SemanticBudgetDimension::SourceBytes
            | SemanticBudgetDimension::Procedures
            | SemanticBudgetDimension::Blocks
            | SemanticBudgetDimension::ProgramPoints
            | SemanticBudgetDimension::Values
            | SemanticBudgetDimension::Allocations
            | SemanticBudgetDimension::SourceMappings
            | SemanticBudgetDimension::Evidence
            | SemanticBudgetDimension::Gaps
            | SemanticBudgetDimension::Events
            | SemanticBudgetDimension::ControlEdges
            | SemanticBudgetDimension::NestedEntries
            | SemanticBudgetDimension::OwnedTextBytes => ReceiverBudgetLimit::ScopeNodes,
        }
    }
}

fn partition_receiver_scope_limit(total: usize) -> [usize; 11] {
    const DIMENSIONS: usize = ReceiverSemanticBridge::SCOPE_DIMENSIONS;
    const NESTED_ENTRIES_INDEX: usize = DIMENSIONS - 1;
    debug_assert!(total >= DIMENSIONS);

    // Semantic materialization charges syntax traversal and nested collection
    // publication to `nested_entries`, while the other dimensions mostly
    // represent emitted rows. Give traversal one quarter of the aggregate
    // scope budget and distribute the rest evenly across the ten row
    // dimensions. Every dimension remains positive and the limits still sum
    // exactly to the receiver's aggregate scope cap.
    let mut limits = [1; DIMENSIONS];
    let remaining = total - DIMENSIONS;
    let nested_extra = remaining.div_ceil(4);
    let row_capacity = remaining - nested_extra;
    let row_dimensions = DIMENSIONS - 1;
    let quotient = row_capacity / row_dimensions;
    let remainder = row_capacity % row_dimensions;
    for (index, limit) in limits[..row_dimensions].iter_mut().enumerate() {
        *limit += quotient + usize::from(index < remainder);
    }
    limits[NESTED_ENTRIES_INDEX] += nested_extra;
    limits
}

fn partition_receiver_summary_limit(total: usize) -> [usize; 3] {
    debug_assert!(total >= 3);
    // Receiver queries are call-heavy: factory provenance and bounded
    // interprocedural flow revisit call sites while memory/capture rows remain
    // secondary. Keep every dimension positive, reserve half of the remaining
    // aggregate capacity for calls, then split the rest across memory and
    // captures. The three limits still sum exactly to the caller's aggregate
    // summary budget.
    let remaining = total - 3;
    let call_extra = remaining.div_ceil(2);
    let secondary = remaining - call_extra;
    let memory_extra = secondary.div_ceil(2);
    let capture_extra = secondary - memory_extra;
    [1 + call_extra, 1 + memory_extra, 1 + capture_extra]
}

struct ReceiverValueProjection {
    values: Vec<ReceiverValue>,
    truncated: bool,
    multiple_identities: bool,
}

fn projected_type_definitions(type_outcome: &TypeLookupOutcome) -> impl Iterator<Item = &CodeUnit> {
    let definitions_per_type = if type_outcome.status == TypeLookupStatus::Resolved {
        1
    } else {
        usize::MAX
    };
    type_outcome
        .types
        .iter()
        .flat_map(move |ty| ty.definitions.iter().take(definitions_per_type))
}

fn project_static_receiver_values(
    type_outcome: &TypeLookupOutcome,
    cancellation: Option<&CancellationToken>,
    ledger: &mut ReceiverWorkLedger,
) -> Result<CompatibilityOutcome<ReceiverValueProjection>, ReceiverQueryError> {
    let limit = ledger.remaining_budget().max_targets;
    let projected_count = projected_type_definitions(type_outcome).count();
    let mut values = Vec::with_capacity(projected_count.min(limit));
    for definition in projected_type_definitions(type_outcome) {
        if values.len() >= limit {
            break;
        }
        check_cancelled(cancellation)?;
        if let Err(limit) = charge_scope_step(ledger) {
            return Ok(CompatibilityOutcome::Exceeded(limit));
        }
        values.push(ReceiverValue::ClassOrStaticObject(definition.clone()));
    }
    Ok(CompatibilityOutcome::Complete(ReceiverValueProjection {
        values,
        truncated: projected_count > limit,
        multiple_identities: false,
    }))
}

fn project_receiver_values(
    workspace: &WorkspaceAnalyzer,
    points_to: &SourcePointsToResult,
    type_outcome: &crate::analyzer::usages::get_type::TypeLookupOutcome,
    factories: &[CodeUnit],
    type_reference: bool,
    cancellation: Option<&CancellationToken>,
    ledger: &mut ReceiverWorkLedger,
) -> Result<CompatibilityOutcome<ReceiverValueProjection>, ReceiverQueryError> {
    let limit = ledger.remaining_budget().max_targets;
    let mut allocations = Vec::new();
    let mut allocations_truncated = false;
    let mut current_receiver = false;
    let mut nominal_instance = false;
    let mut source_value_identity = false;
    let mut call_results = Vec::new();
    let mut identities = Vec::new();
    for candidate in points_to.object_candidates() {
        check_cancelled(cancellation)?;
        if let Err(limit) = charge_scope_step(ledger) {
            return Ok(CompatibilityOutcome::Exceeded(limit));
        }
        let identity = candidate.value().identity();
        if !identities.contains(&identity) {
            identities.push(identity);
        }
        match identity {
            AbstractObjectIdentity::Allocation(allocation) => {
                if !allocations.contains(allocation) {
                    if allocations.len() >= limit {
                        allocations_truncated = true;
                        break;
                    }
                    allocations.push(allocation.clone());
                }
            }
            AbstractObjectIdentity::ProcedurePort(port)
                if port.kind() == crate::analyzer::semantic::ProcedurePortKind::Receiver =>
            {
                current_receiver = true;
            }
            AbstractObjectIdentity::CallResult(result) => {
                if !call_results.contains(result) {
                    call_results.push(result.clone());
                }
            }
            AbstractObjectIdentity::Value(_) => source_value_identity = true,
            AbstractObjectIdentity::ProcedurePort(_)
            | AbstractObjectIdentity::Static(_)
            | AbstractObjectIdentity::LexicalCell(_)
            | AbstractObjectIdentity::CaptureSlot(_)
            | AbstractObjectIdentity::TypeSummary(_)
            | AbstractObjectIdentity::ModuleObject(_)
            | AbstractObjectIdentity::External(_) => nominal_instance = true,
        }
    }
    let static_reference = matches!(
        type_outcome.target_kind,
        crate::analyzer::usages::target_kind::TypeLookupTargetKind::TypeReference
    ) || type_reference;
    let mut factory_ranges = Vec::new();
    if !call_results.is_empty() {
        for factory in factories {
            let ranges = match code_unit_ranges_bounded(
                workspace.analyzer(),
                factory,
                cancellation,
                ledger,
            )? {
                CompatibilityOutcome::Complete(ranges) => ranges,
                CompatibilityOutcome::Exceeded(limit) => {
                    return Ok(CompatibilityOutcome::Exceeded(limit));
                }
            };
            factory_ranges.push((factory, ranges));
        }
    }
    let mut matching_factories = Vec::new();
    let mut unmatched_call_result = factories.is_empty() && !call_results.is_empty();
    for result in &call_results {
        let mut matched = None;
        for (factory, ranges) in &factory_ranges {
            check_cancelled(cancellation)?;
            if let Err(limit) = charge_scope_step(ledger) {
                return Ok(CompatibilityOutcome::Exceeded(limit));
            }
            if call_result_matches_factory(result, factory, ranges) {
                matched = Some((*factory).clone());
                break;
            }
        }
        if let Some(factory) = matched {
            if !matching_factories.contains(&factory) {
                matching_factories.push(factory);
            }
        } else {
            unmatched_call_result = true;
        }
    }
    // A fully matched call result is the specific public identity for the
    // exact factory expression. Some lowerers also retain generic source-value
    // scaffolding at that span; publishing it as a second nominal instance
    // duplicates the same expression and falsely turns one factory result into
    // an ambiguous answer. Other symbolic roots and unmatched calls remain
    // independent candidates.
    let factory_covers_source_value =
        !matching_factories.is_empty() && !unmatched_call_result && !call_results.is_empty();
    let include_nominal_instance =
        nominal_instance || (source_value_identity && !factory_covers_source_value);
    let projection_kinds = if static_reference {
        1
    } else {
        allocations
            .len()
            .saturating_add(usize::from(current_receiver))
            .saturating_add(usize::from(
                include_nominal_instance || unmatched_call_result,
            ))
            .saturating_add(matching_factories.len())
    };
    let projected_count = projected_type_definitions(type_outcome)
        .count()
        .saturating_mul(projection_kinds);
    let mut values = Vec::new();
    for definition in projected_type_definitions(type_outcome) {
        if values.len() >= limit {
            break;
        }
        check_cancelled(cancellation)?;
        if let Err(limit) = charge_scope_step(ledger) {
            return Ok(CompatibilityOutcome::Exceeded(limit));
        }
        if static_reference {
            values.push(ReceiverValue::ClassOrStaticObject(definition.clone()));
            continue;
        }
        if current_receiver {
            values.push(ReceiverValue::CurrentReceiver(definition.clone()));
        }
        for allocation in &allocations {
            if values.len() >= limit {
                break;
            }
            check_cancelled(cancellation)?;
            if let Err(limit) = charge_scope_step(ledger) {
                return Ok(CompatibilityOutcome::Exceeded(limit));
            }
            let row = allocation
                .procedure()
                .semantics()
                .allocation(allocation.id())
                .expect("allocation handles are validated");
            let span = allocation
                .procedure()
                .semantics()
                .source_mapping(row.source)
                .expect("allocation source is validated")
                .locator
                .anchor()
                .span();
            let key = allocation.procedure().artifact().key();
            let file = ProjectFile::new(
                workspace.analyzer().project().root().to_path_buf(),
                key.path().as_path(),
            );
            values.push(ReceiverValue::AllocationSite {
                ty: definition.clone(),
                file,
                range: Range {
                    start_byte: span.start_byte() as usize,
                    end_byte: span.end_byte() as usize,
                    start_line: span.start().line() as usize,
                    end_line: span.end().line() as usize,
                },
            });
        }
        if (include_nominal_instance || unmatched_call_result) && values.len() < limit {
            let value = ReceiverValue::InstanceType(definition.clone());
            values.push(value);
        }
        for factory in &matching_factories {
            if values.len() >= limit {
                break;
            }
            values.push(ReceiverValue::FactoryReturn {
                factory: factory.clone(),
                value: Box::new(ReceiverValue::InstanceType(definition.clone())),
            });
        }
        if values.len() >= limit {
            break;
        }
    }
    values.truncate(limit);
    Ok(CompatibilityOutcome::Complete(ReceiverValueProjection {
        values,
        truncated: allocations_truncated || projected_count > limit,
        multiple_identities: identities
            .iter()
            .filter(|identity| {
                !factory_covers_source_value
                    || !matches!(identity, AbstractObjectIdentity::Value(_))
            })
            .count()
            > 1,
    }))
}

fn points_to_contains_call_result(
    points_to: &SourcePointsToResult,
    cancellation: Option<&CancellationToken>,
) -> Result<bool, ReceiverQueryError> {
    for candidate in points_to.object_candidates() {
        check_cancelled(cancellation)?;
        if matches!(
            candidate.value().identity(),
            AbstractObjectIdentity::CallResult(_)
        ) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn code_unit_ranges_bounded(
    analyzer: &dyn IAnalyzer,
    unit: &CodeUnit,
    cancellation: Option<&CancellationToken>,
    ledger: &mut ReceiverWorkLedger,
) -> Result<CompatibilityOutcome<Vec<Range>>, ReceiverQueryError> {
    check_cancelled(cancellation)?;
    if let Err(limit) = charge_summary_step(ledger) {
        return Ok(CompatibilityOutcome::Exceeded(limit));
    }
    let language = language_for_file(unit.source());
    if matches!(
        language,
        Language::Cpp
            | Language::CSharp
            | Language::Go
            | Language::Java
            | Language::JavaScript
            | Language::Kotlin
            | Language::Php
            | Language::Python
            | Language::Ruby
            | Language::Rust
            | Language::Scala
            | Language::TypeScript
    ) {
        if let Err(limit) = charge_scope_step(ledger) {
            return Ok(CompatibilityOutcome::Exceeded(limit));
        }
        let provider_limit = ledger.remaining_budget().max_scope_nodes.saturating_add(1);
        let ranges = language_support(language)
            .expect("language was checked above")
            .declaration_ranges_limited(analyzer, unit, provider_limit);
        let Some(ranges) = ranges else {
            return Ok(CompatibilityOutcome::Exceeded(
                ReceiverBudgetLimit::ScopeNodes,
            ));
        };
        return charge_limited_projection(ranges, cancellation, ledger);
    }
    Ok(CompatibilityOutcome::Exceeded(
        ReceiverBudgetLimit::ScopeNodes,
    ))
}

fn call_result_matches_factory(
    result: &crate::analyzer::semantic::CallResultHandle,
    factory: &CodeUnit,
    factory_ranges: &[Range],
) -> bool {
    let callee = result.callee();
    if callee.artifact().key().path().as_path() != factory.source().rel_path() {
        return false;
    }
    let Some(declaration) = callee.semantics().locator().declaration().segments().last() else {
        return false;
    };
    if declaration.name() != Some(factory.identifier()) {
        return false;
    }
    let span = callee.semantics().locator().anchor().span();
    let start = span.start_byte() as usize;
    let end = span.end_byte() as usize;
    factory_ranges
        .iter()
        .any(|range| range.start_byte <= start && end <= range.end_byte)
}

fn java_factory_name_node(node: Node<'_>) -> Option<Node<'_>> {
    if node.kind() != "method_invocation" {
        return None;
    }
    node.child_by_field_name("name")
}

fn structural_factory_name_node(language: Language, node: Node<'_>) -> Option<Node<'_>> {
    if let Some(name) =
        language_support(language).and_then(|support| support.factory_name_node(node))
    {
        return Some(name);
    }
    match language {
        Language::Cpp => {
            if node.kind() != "call_expression" {
                return None;
            }
            let function = node.child_by_field_name("function")?;
            match function.kind() {
                "field_expression" => function.child_by_field_name("field"),
                "qualified_identifier" => function.child_by_field_name("name"),
                "identifier" => Some(function),
                _ => None,
            }
        }
        Language::CSharp => {
            if node.kind() != "invocation_expression" {
                return None;
            }
            let function = node.child_by_field_name("function")?;
            match function.kind() {
                "member_access_expression" => function.child_by_field_name("name"),
                "identifier" | "generic_name" => Some(function),
                _ => None,
            }
        }
        Language::Go => {
            if node.kind() != "call_expression" {
                return None;
            }
            let function = node.child_by_field_name("function")?;
            match function.kind() {
                "selector_expression" => function.child_by_field_name("field"),
                "identifier" => Some(function),
                _ => None,
            }
        }
        Language::Php => match node.kind() {
            "function_call_expression" => node.child_by_field_name("function"),
            "member_call_expression"
            | "nullsafe_member_call_expression"
            | "scoped_call_expression" => node.child_by_field_name("name"),
            _ => None,
        },
        Language::Python => {
            if node.kind() != "call" {
                return None;
            }
            let function = node.child_by_field_name("function")?;
            match function.kind() {
                "attribute" => function.child_by_field_name("attribute"),
                "identifier" => Some(function),
                _ => None,
            }
        }
        Language::Ruby => {
            if node.kind() != "call" {
                return None;
            }
            node.child_by_field_name("method")
        }
        Language::Rust => {
            if node.kind() != "call_expression" {
                return None;
            }
            let mut function = node.child_by_field_name("function")?;
            while function.kind() == "generic_function" {
                function = function.child_by_field_name("function")?;
            }
            match function.kind() {
                "field_expression" => function.child_by_field_name("field"),
                "scoped_identifier" | "scoped_type_identifier" => {
                    function.child_by_field_name("name")
                }
                "identifier" => Some(function),
                _ => None,
            }
        }
        Language::Scala => {
            if node.kind() != "call_expression" {
                return None;
            }
            let mut function = node.child_by_field_name("function")?;
            while function.kind() == "call_expression" {
                function = function.child_by_field_name("function")?;
            }
            if function.kind() == "generic_function" {
                function = function.child_by_field_name("function")?;
            }
            match function.kind() {
                "field_expression" => function.child_by_field_name("field"),
                "identifier" | "operator_identifier" => Some(function),
                _ => None,
            }
        }
        _ => None,
    }
}

fn java_definition_at(
    analyzer: &dyn IAnalyzer,
    definitions: &AnalyzerDefinitionLookup<'_>,
    file: &ProjectFile,
    input: JavaReceiverResolutionInput<'_>,
    node: Node<'_>,
    budget: ReceiverAnalysisBudget,
    cancellation: Option<&CancellationToken>,
) -> BoundedJavaResolution<DefinitionLookupOutcome> {
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        return BoundedJavaResolution::Cancelled {
            work: ReceiverAnalysisWork::default(),
        };
    }
    if budget.max_scope_nodes == 0 {
        return BoundedJavaResolution::Exceeded {
            work: ReceiverAnalysisWork::default(),
            limit: ReceiverBudgetLimit::ScopeNodes,
        };
    }
    let preprocessing_work = ReceiverAnalysisWork {
        scope_nodes: 1,
        ..ReceiverAnalysisWork::default()
    };
    let Some(site) = java_reference_site(file, input.source, input.line_starts, node) else {
        return BoundedJavaResolution::Complete {
            value: DefinitionLookupOutcome {
                status: DefinitionLookupStatus::InvalidLocation,
                reference: None,
                definitions: Vec::new(),
                lexical_definition: None,
                diagnostics: Vec::new(),
            },
            work: preprocessing_work,
        };
    };
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        return BoundedJavaResolution::Cancelled {
            work: preprocessing_work,
        };
    }
    let mut compatibility_budget = budget;
    compatibility_budget.max_scope_nodes -= 1;
    let session = JavaResolutionSession::bounded(definitions, compatibility_budget, cancellation);
    prepend_java_preprocessing_work(resolve_java_bounded(
        analyzer,
        &session,
        file,
        input.source,
        Some(input.tree),
        &site,
    ))
}

fn java_type_outcome_at(
    analyzer: &dyn IAnalyzer,
    definitions: &AnalyzerDefinitionLookup<'_>,
    file: &ProjectFile,
    input: JavaReceiverResolutionInput<'_>,
    node: Node<'_>,
    budget: ReceiverAnalysisBudget,
    cancellation: Option<&CancellationToken>,
) -> BoundedJavaResolution<TypeLookupOutcome> {
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        return BoundedJavaResolution::Cancelled {
            work: ReceiverAnalysisWork::default(),
        };
    }
    if budget.max_scope_nodes == 0 {
        return BoundedJavaResolution::Exceeded {
            work: ReceiverAnalysisWork::default(),
            limit: ReceiverBudgetLimit::ScopeNodes,
        };
    }
    let preprocessing_work = ReceiverAnalysisWork {
        scope_nodes: 1,
        ..ReceiverAnalysisWork::default()
    };
    let Some(site) = java_reference_site(file, input.source, input.line_starts, node) else {
        return BoundedJavaResolution::Complete {
            value: TypeLookupOutcome {
                status: TypeLookupStatus::InvalidLocation,
                reference: None,
                types: Vec::new(),
                diagnostics: Vec::new(),
                target_kind: TypeLookupTargetKind::ValueExpression,
            },
            work: preprocessing_work,
        };
    };
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        return BoundedJavaResolution::Cancelled {
            work: preprocessing_work,
        };
    }
    let mut compatibility_budget = budget;
    compatibility_budget.max_scope_nodes -= 1;
    let session = JavaResolutionSession::bounded(definitions, compatibility_budget, cancellation);
    prepend_java_preprocessing_work(resolve_java_type_bounded(
        analyzer,
        &session,
        file,
        input.source,
        Some(input.tree),
        &site,
    ))
}

fn prepend_java_preprocessing_work<T>(
    resolution: BoundedJavaResolution<T>,
) -> BoundedJavaResolution<T> {
    let add_preprocessing = |mut work: ReceiverAnalysisWork| {
        work.scope_nodes = work.scope_nodes.saturating_add(1);
        work
    };
    match resolution {
        BoundedJavaResolution::Complete { value, work } => BoundedJavaResolution::Complete {
            value,
            work: add_preprocessing(work),
        },
        BoundedJavaResolution::Exceeded { work, limit } => BoundedJavaResolution::Exceeded {
            work: add_preprocessing(work),
            limit,
        },
        BoundedJavaResolution::Cancelled { work } => BoundedJavaResolution::Cancelled {
            work: add_preprocessing(work),
        },
    }
}

fn java_reference_site(
    file: &ProjectFile,
    source: &str,
    line_starts: &[usize],
    node: Node<'_>,
) -> Option<crate::analyzer::usages::reference_site::ResolvedReferenceSite> {
    resolve_reference_site_with_line_starts(
        &SourceLocationRequest {
            file: file.clone(),
            line: None,
            column: None,
            start_byte: Some(node.start_byte()),
            end_byte: Some(node.end_byte()),
        },
        source,
        line_starts,
    )
    .ok()
}

fn java_parent_node<'tree>(
    node: Node<'tree>,
    cancellation: Option<&CancellationToken>,
    ledger: &mut ReceiverWorkLedger,
) -> Result<CompatibilityOutcome<Option<Node<'tree>>>, ReceiverQueryError> {
    check_cancelled(cancellation)?;
    if let Err(limit) = charge_scope_step(ledger) {
        return Ok(CompatibilityOutcome::Exceeded(limit));
    }
    Ok(CompatibilityOutcome::Complete(node.parent()))
}

fn java_contextual_type_node<'tree>(
    mut node: Node<'tree>,
    cancellation: Option<&CancellationToken>,
    ledger: &mut ReceiverWorkLedger,
) -> Result<CompatibilityOutcome<Option<Node<'tree>>>, ReceiverQueryError> {
    loop {
        let parent = match java_parent_node(node, cancellation, ledger)? {
            CompatibilityOutcome::Complete(Some(parent)) => parent,
            CompatibilityOutcome::Complete(None) => {
                return Ok(CompatibilityOutcome::Complete(None));
            }
            CompatibilityOutcome::Exceeded(limit) => {
                return Ok(CompatibilityOutcome::Exceeded(limit));
            }
        };
        if parent.kind() == "variable_declarator"
            && parent.child_by_field_name("value").is_some_and(|value| {
                value.start_byte() <= node.start_byte() && value.end_byte() >= node.end_byte()
            })
        {
            return Ok(CompatibilityOutcome::Complete(
                parent.child_by_field_name("name"),
            ));
        }
        if matches!(
            parent.kind(),
            "statement" | "expression_statement" | "return_statement" | "block"
        ) {
            return Ok(CompatibilityOutcome::Complete(None));
        }
        node = parent;
    }
}

fn definition_outcome(
    outcome: DefinitionLookupOutcome,
    limit: usize,
) -> (ReceiverAnalysisOutcome<CodeUnit>, bool) {
    let mut definitions = Vec::new();
    for definition in outcome.definitions {
        if !definitions.contains(&definition) {
            definitions.push(definition);
        }
    }
    let truncated = definitions.len() > limit;
    definitions.truncate(limit);
    let outcome = if definitions.is_empty() {
        ReceiverAnalysisOutcome::Unknown
    } else {
        match outcome.status {
            DefinitionLookupStatus::Resolved => ReceiverAnalysisOutcome::Precise(definitions),
            DefinitionLookupStatus::Ambiguous => ReceiverAnalysisOutcome::Ambiguous(definitions),
            DefinitionLookupStatus::UnsupportedLanguage => ReceiverAnalysisOutcome::Unsupported {
                reason: "receiver_analysis_language_unsupported",
            },
            DefinitionLookupStatus::NoDefinition
            | DefinitionLookupStatus::UnresolvableImportBoundary
            | DefinitionLookupStatus::InvalidLocation
            | DefinitionLookupStatus::NotFound => ReceiverAnalysisOutcome::Unknown,
        }
    };
    (outcome, truncated)
}

fn current_receiver_owners(
    workspace: &WorkspaceAnalyzer,
    points_to: &SourcePointsToResult,
    cancellation: Option<&CancellationToken>,
    ledger: &mut ReceiverWorkLedger,
) -> Result<CompatibilityOutcome<Vec<CodeUnit>>, ReceiverQueryError> {
    let analyzer = workspace.analyzer();
    let mut owners = Vec::new();
    for candidate in points_to.object_candidates() {
        check_cancelled(cancellation)?;
        if let Err(limit) = charge_scope_step(ledger) {
            return Ok(CompatibilityOutcome::Exceeded(limit));
        }
        let AbstractObjectIdentity::ProcedurePort(port) = candidate.value().identity() else {
            continue;
        };
        if port.kind() != crate::analyzer::semantic::ProcedurePortKind::Receiver {
            continue;
        }
        let file = ProjectFile::new(
            analyzer.project().root().to_path_buf(),
            port.procedure().artifact().key().path().as_path(),
        );
        if let Err(limit) = charge_scope_step(ledger) {
            return Ok(CompatibilityOutcome::Exceeded(limit));
        }
        let byte = port
            .procedure()
            .semantics()
            .locator()
            .anchor()
            .span()
            .start_byte() as usize;
        let range = Range {
            start_byte: byte,
            end_byte: byte.saturating_add(1),
            start_line: 0,
            end_line: 0,
        };
        let Some(mut owner) = analyzer.enclosing_code_unit(&file, &range) else {
            continue;
        };
        if let Err(limit) = charge_scope_step(ledger) {
            return Ok(CompatibilityOutcome::Exceeded(limit));
        }
        while !owner.is_class() {
            check_cancelled(cancellation)?;
            if let Err(limit) = charge_summary_step(ledger) {
                return Ok(CompatibilityOutcome::Exceeded(limit));
            }
            let Some(parent) = analyzer.parent_of(&owner) else {
                break;
            };
            if let Err(limit) = charge_scope_step(ledger) {
                return Ok(CompatibilityOutcome::Exceeded(limit));
            }
            owner = parent;
        }
        if owner.is_class() && !owners.contains(&owner) {
            owners.push(owner);
        }
    }
    Ok(CompatibilityOutcome::Complete(owners))
}

fn receiver_type_outcome<T>(status: TypeLookupStatus, values: Vec<T>) -> ReceiverAnalysisOutcome<T>
where
    T: Eq,
{
    let mut unique = Vec::with_capacity(values.len());
    for value in values {
        if !unique.contains(&value) {
            unique.push(value);
        }
    }
    if unique.is_empty() {
        return ReceiverAnalysisOutcome::Unknown;
    }
    match status {
        TypeLookupStatus::Resolved if unique.len() == 1 => ReceiverAnalysisOutcome::Precise(unique),
        TypeLookupStatus::Resolved | TypeLookupStatus::Ambiguous => {
            ReceiverAnalysisOutcome::Ambiguous(unique)
        }
        TypeLookupStatus::NoType
        | TypeLookupStatus::InvalidLocation
        | TypeLookupStatus::NotFound => ReceiverAnalysisOutcome::Unknown,
        TypeLookupStatus::UnsupportedLanguage => ReceiverAnalysisOutcome::Unsupported {
            reason: "receiver_analysis_language_unsupported",
        },
    }
}

fn java_unknown_report(
    operation: ReceiverQueryOperation,
    file: &ProjectFile,
    node: Node<'_>,
    source: &str,
    member_name: Option<String>,
) -> ReceiverQueryReport {
    let analysis = match operation {
        ReceiverQueryOperation::MemberTargets => {
            ReceiverQueryAnalysis::MemberTargets(ReceiverAnalysisOutcome::Unknown)
        }
        ReceiverQueryOperation::ReceiverTargets | ReceiverQueryOperation::PointsTo => {
            ReceiverQueryAnalysis::Values(ReceiverAnalysisOutcome::Unknown)
        }
    };
    ReceiverQueryReport {
        operation,
        site: site(
            file,
            Language::Java,
            node_range(node),
            source,
            node.kind(),
            member_name,
        ),
        analysis,
        work: ReceiverAnalysisWork::default(),
        candidates_truncated: false,
        semantic_unsupported: None,
    }
}

fn budget_report(
    operation: ReceiverQueryOperation,
    site: ReceiverQuerySite,
    work: ReceiverAnalysisWork,
    limit: ReceiverBudgetLimit,
) -> ReceiverQueryReport {
    let analysis = match operation {
        ReceiverQueryOperation::MemberTargets => {
            ReceiverQueryAnalysis::MemberTargets(ReceiverAnalysisOutcome::ExceededBudget {
                limit: limit.as_str(),
            })
        }
        ReceiverQueryOperation::ReceiverTargets | ReceiverQueryOperation::PointsTo => {
            ReceiverQueryAnalysis::Values(ReceiverAnalysisOutcome::ExceededBudget {
                limit: limit.as_str(),
            })
        }
    };
    ReceiverQueryReport {
        operation,
        site,
        analysis,
        work,
        candidates_truncated: false,
        semantic_unsupported: None,
    }
}

fn unknown_report(
    operation: ReceiverQueryOperation,
    site: ReceiverQuerySite,
    work: ReceiverAnalysisWork,
    candidates_truncated: bool,
) -> ReceiverQueryReport {
    let analysis = match operation {
        ReceiverQueryOperation::MemberTargets => {
            ReceiverQueryAnalysis::MemberTargets(ReceiverAnalysisOutcome::Unknown)
        }
        ReceiverQueryOperation::ReceiverTargets | ReceiverQueryOperation::PointsTo => {
            ReceiverQueryAnalysis::Values(ReceiverAnalysisOutcome::Unknown)
        }
    };
    ReceiverQueryReport {
        operation,
        site,
        analysis,
        work,
        candidates_truncated,
        semantic_unsupported: None,
    }
}

fn java_receiver_at_site<'tree>(
    mut node: Node<'tree>,
    cancellation: Option<&CancellationToken>,
    ledger: &mut ReceiverWorkLedger,
) -> Result<CompatibilityOutcome<Option<Node<'tree>>>, ReceiverQueryError> {
    loop {
        match node.kind() {
            "method_invocation" => {
                return Ok(CompatibilityOutcome::Complete(
                    node.child_by_field_name("object"),
                ));
            }
            "field_access" => {
                return Ok(CompatibilityOutcome::Complete(
                    node.child_by_field_name("object"),
                ));
            }
            _ => {
                node = match java_parent_node(node, cancellation, ledger)? {
                    CompatibilityOutcome::Complete(Some(parent)) => parent,
                    CompatibilityOutcome::Complete(None) => {
                        return Ok(CompatibilityOutcome::Complete(None));
                    }
                    CompatibilityOutcome::Exceeded(limit) => {
                        return Ok(CompatibilityOutcome::Exceeded(limit));
                    }
                };
            }
        }
    }
}

fn java_smallest_named_node_covering<'tree>(
    mut node: Node<'tree>,
    start: usize,
    end: usize,
    cancellation: Option<&CancellationToken>,
    ledger: &mut ReceiverWorkLedger,
) -> Result<CompatibilityOutcome<Option<Node<'tree>>>, ReceiverQueryError> {
    check_cancelled(cancellation)?;
    if let Err(limit) = charge_scope_step(ledger) {
        return Ok(CompatibilityOutcome::Exceeded(limit));
    }
    if node.end_byte() < end || node.start_byte() > start {
        return Ok(CompatibilityOutcome::Complete(None));
    }
    loop {
        let mut cursor = node.walk();
        let mut containing_child = None;
        for child in node.named_children(&mut cursor) {
            check_cancelled(cancellation)?;
            if let Err(limit) = charge_scope_step(ledger) {
                return Ok(CompatibilityOutcome::Exceeded(limit));
            }
            if child.start_byte() <= start && child.end_byte() >= end {
                containing_child = Some(child);
                break;
            }
        }
        match containing_child {
            Some(child) => node = child,
            None => return Ok(CompatibilityOutcome::Complete(Some(node))),
        }
    }
}

fn java_member_node_at_site<'tree>(
    mut node: Node<'tree>,
    cancellation: Option<&CancellationToken>,
    ledger: &mut ReceiverWorkLedger,
) -> Result<CompatibilityOutcome<Option<Node<'tree>>>, ReceiverQueryError> {
    loop {
        let member = match node.kind() {
            "method_invocation" => node.child_by_field_name("name"),
            "field_access" => node.child_by_field_name("field"),
            _ => None,
        };
        if let Some(member) = member {
            return Ok(CompatibilityOutcome::Complete(Some(member)));
        }
        node = match java_parent_node(node, cancellation, ledger)? {
            CompatibilityOutcome::Complete(Some(parent)) => parent,
            CompatibilityOutcome::Complete(None) => {
                return Ok(CompatibilityOutcome::Complete(None));
            }
            CompatibilityOutcome::Exceeded(limit) => {
                return Ok(CompatibilityOutcome::Exceeded(limit));
            }
        };
    }
}

fn values_report(
    operation: ReceiverQueryOperation,
    file: &ProjectFile,
    language: Language,
    node: Node<'_>,
    source: &str,
    analysis: ReceiverAnalysisReport<ReceiverValue>,
) -> ReceiverQueryReport {
    ReceiverQueryReport {
        operation,
        site: site(file, language, node_range(node), source, node.kind(), None),
        analysis: ReceiverQueryAnalysis::Values(analysis.outcome),
        work: analysis.work,
        candidates_truncated: analysis.candidates_truncated,
        semantic_unsupported: None,
    }
}

fn unsupported_report(
    operation: ReceiverQueryOperation,
    file: &ProjectFile,
    language: Language,
    range: Range,
    reason: &'static str,
    source: Option<&str>,
) -> ReceiverQueryReport {
    let analysis = match operation {
        ReceiverQueryOperation::MemberTargets => {
            ReceiverQueryAnalysis::MemberTargets(ReceiverAnalysisOutcome::Unsupported { reason })
        }
        ReceiverQueryOperation::ReceiverTargets | ReceiverQueryOperation::PointsTo => {
            ReceiverQueryAnalysis::Values(ReceiverAnalysisOutcome::Unsupported { reason })
        }
    };
    ReceiverQueryReport {
        operation,
        site: ReceiverQuerySite {
            file: file.clone(),
            language,
            range,
            text: source
                .and_then(|source| source.get(range.start_byte..range.end_byte))
                .unwrap_or_default()
                .to_string(),
            syntax_kind: "unsupported".to_string(),
            member_name: None,
        },
        analysis,
        work: ReceiverAnalysisWork::default(),
        candidates_truncated: false,
        semantic_unsupported: None,
    }
}

fn setup_budget_report(
    operation: ReceiverQueryOperation,
    file: &ProjectFile,
    language: Language,
    range: Range,
    source: &str,
    work: ReceiverAnalysisWork,
) -> ReceiverQueryReport {
    budget_report(
        operation,
        site(file, language, range, source, "setup", None),
        work,
        ReceiverBudgetLimit::ScopeNodes,
    )
}

fn structural_reference_site(
    file: &ProjectFile,
    source: &str,
    range: Range,
) -> ResolvedReferenceSite {
    ResolvedReferenceSite {
        path: rel_path_string(file),
        text: source
            .get(range.start_byte..range.end_byte)
            .unwrap_or_default()
            .to_string(),
        range,
        focus_start_byte: range.start_byte,
        focus_end_byte: range.end_byte,
    }
}

fn site(
    file: &ProjectFile,
    language: Language,
    range: Range,
    source: &str,
    syntax_kind: &str,
    member_name: Option<String>,
) -> ReceiverQuerySite {
    ReceiverQuerySite {
        file: file.clone(),
        language,
        range,
        text: source
            .get(range.start_byte..range.end_byte)
            .unwrap_or_default()
            .to_string(),
        syntax_kind: syntax_kind.to_string(),
        member_name,
    }
}

fn check_cancelled(cancellation: Option<&CancellationToken>) -> Result<(), ReceiverQueryError> {
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        Err(ReceiverQueryError::Cancelled)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests;
