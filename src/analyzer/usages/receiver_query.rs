//! Analyzer-owned bounded receiver queries for structural traversal.

use crate::analyzer::common::language_for_file;
use crate::analyzer::semantic::{
    AbstractObjectIdentity, OracleLimitValues, OracleLimits, SemanticBudget,
    SemanticBudgetDimension, SemanticBudgetExceeded, SemanticOutcome, SemanticProviderError,
    SemanticRequest, SemanticWork, SourcePointsToResult, WorkspaceSemanticOracle,
};
use crate::analyzer::tree_sitter_analyzer::{
    BoundedNamedTreeWalk, walk_named_tree_preorder_bounded,
};
use crate::analyzer::usages::get_definition::{
    DefinitionLookupOutcome, DefinitionLookupStatus, java::resolve_java, js_ts::parse_js_ts_tree,
    parse_tree_for_language,
};
use crate::analyzer::usages::get_type::{
    TypeLookupOutcome, TypeLookupStatus, TypeLookupType, java::resolve_java_type,
};
use crate::analyzer::usages::inverted_edges::ClassRangeIndex;
use crate::analyzer::usages::js_ts_graph::receiver_analysis::{
    JsTsReceiverSyntaxIndex, JsTsReceiverSyntaxIndexBuild,
    build_js_ts_receiver_syntax_index_bounded, member_expression_at_site, node_range,
    smallest_named_node_covering,
};
use crate::analyzer::usages::js_ts_graph::{JsTsReceiverFactProvider, compute_jsts_import_binder};
use crate::analyzer::usages::receiver_analysis::{
    ReceiverAnalysisBudget, ReceiverAnalysisOutcome, ReceiverAnalysisReport, ReceiverAnalysisWork,
    ReceiverBudgetLimit, ReceiverValue,
};
use crate::analyzer::usages::reference_site::{SourceLocationRequest, resolve_reference_site};
use crate::analyzer::usages::target_kind::TypeLookupTargetKind;
use crate::analyzer::{
    AnalyzerDefinitionLookup, CodeUnit, IAnalyzer, Language, ProjectFile, Range, WorkspaceAnalyzer,
};
use crate::cancellation::CancellationToken;
use crate::hash::HashMap;
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
    java_class_ranges: RefCell<HashMap<ProjectFile, ClassRangeIndex>>,
}

struct PreparedReceiverFile {
    source: String,
    tree: tree_sitter::Tree,
    imports: crate::analyzer::usages::model::ImportBinder,
    syntax_index: Arc<JsTsReceiverSyntaxIndex>,
}

struct PreparedJavaReceiverFile {
    source: String,
    tree: tree_sitter::Tree,
}

enum SemanticReceiverGate {
    Available {
        work: ReceiverAnalysisWork,
        points_to: Option<SourcePointsToResult>,
        truncated: bool,
    },
    Unavailable {
        work: ReceiverAnalysisWork,
    },
    Exceeded {
        work: ReceiverAnalysisWork,
        limit: ReceiverBudgetLimit,
    },
}

impl<'a> ReceiverQueryService<'a> {
    pub(crate) fn new(analyzer: &'a dyn IAnalyzer) -> Self {
        Self {
            analyzer,
            workspace: None,
            definitions: AnalyzerDefinitionLookup::new(analyzer, Language::None),
            prepared_files: RefCell::new(HashMap::default()),
            prepared_java_files: RefCell::new(HashMap::default()),
            java_class_ranges: RefCell::new(HashMap::default()),
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
            java_class_ranges: RefCell::new(HashMap::default()),
        }
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
        check_cancelled(cancellation)?;
        let language = language_for_file(file);
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
        if !matches!(language, Language::JavaScript | Language::TypeScript) {
            return Ok(unsupported_report(
                operation,
                file,
                language,
                range,
                "receiver_analysis_language_unsupported",
                indexed_source.as_deref(),
            ));
        }
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
        let mut setup_nodes = 0;
        if !self.prepared_files.borrow().contains_key(file) {
            let Some(tree) = parse_js_ts_tree(file, &source, language) else {
                return Ok(unsupported_report(
                    operation,
                    file,
                    language,
                    range,
                    "receiver_source_parse_failed",
                    Some(&source),
                ));
            };
            check_cancelled(cancellation)?;
            let (syntax_index, visited) = match build_js_ts_receiver_syntax_index_bounded(
                tree.root_node(),
                &source,
                cancellation,
                budget.max_scope_nodes,
            ) {
                JsTsReceiverSyntaxIndexBuild::Complete { index, visited } => (index, visited),
                JsTsReceiverSyntaxIndexBuild::ExceededScope { visited } => {
                    return Ok(setup_budget_report(
                        operation, file, language, range, &source, visited,
                    ));
                }
                JsTsReceiverSyntaxIndexBuild::Cancelled => {
                    return Err(ReceiverQueryError::Cancelled);
                }
            };
            setup_nodes = visited;
            self.prepared_files.borrow_mut().insert(
                file.clone(),
                PreparedReceiverFile {
                    imports: compute_jsts_import_binder(&source, &tree),
                    source,
                    tree,
                    syntax_index,
                },
            );
        }
        let budget = ReceiverAnalysisBudget {
            max_scope_nodes: budget.max_scope_nodes.saturating_sub(setup_nodes),
            ..budget
        };
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
            report.work.setup_nodes = setup_nodes;
            return Ok(report);
        };
        self.definitions.set_language(language);
        let provider = JsTsReceiverFactProvider::new_with_syntax_index(
            self.analyzer,
            &self.definitions,
            language,
            file,
            source,
            tree.root_node(),
            prepared.imports.clone(),
            Arc::clone(&prepared.syntax_index),
        );

        let report = match operation {
            ReceiverQueryOperation::PointsTo => {
                let gate = self.semantic_receiver_gate(
                    file,
                    node_range(input_node),
                    budget,
                    cancellation,
                )?;
                let analysis = provider.resolve_receiver_node_report(input_node, budget);
                apply_semantic_gate(
                    values_report(operation, file, language, input_node, source, analysis),
                    gate,
                )
            }
            ReceiverQueryOperation::ReceiverTargets => {
                let receiver = match input {
                    ReceiverQueryInput::Expression => input_node,
                    ReceiverQueryInput::ContainingSite => {
                        let Some(receiver) = member_expression_at_site(input_node)
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
                            report.work.setup_nodes = setup_nodes;
                            return Ok(report);
                        };
                        receiver
                    }
                };
                let gate =
                    self.semantic_receiver_gate(file, node_range(receiver), budget, cancellation)?;
                let analysis = provider.resolve_receiver_node_report(receiver, budget);
                apply_semantic_gate(
                    values_report(operation, file, language, receiver, source, analysis),
                    gate,
                )
            }
            ReceiverQueryOperation::MemberTargets => {
                let Some(member_report) = provider.resolve_member_targets_at_site(
                    input_node,
                    None,
                    input_node.start_byte(),
                    budget,
                ) else {
                    let mut report = unsupported_report(
                        operation,
                        file,
                        language,
                        range,
                        "member_target_site_unsupported",
                        Some(source),
                    );
                    report.work.setup_nodes = setup_nodes;
                    return Ok(report);
                };
                let site = site(
                    file,
                    language,
                    member_report.receiver_range,
                    source,
                    "receiver",
                    Some(member_report.member_name),
                );
                let gate = self.semantic_receiver_gate(
                    file,
                    member_report.receiver_range,
                    budget,
                    cancellation,
                )?;
                apply_semantic_gate(
                    ReceiverQueryReport {
                        operation,
                        site,
                        analysis: ReceiverQueryAnalysis::MemberTargets(
                            member_report.analysis.outcome,
                        ),
                        work: member_report.analysis.work,
                        candidates_truncated: member_report.analysis.candidates_truncated,
                    },
                    gate,
                )
            }
        };
        check_cancelled(cancellation)?;
        let mut report = report;
        report.work.setup_nodes = setup_nodes;
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
            return Ok(SemanticReceiverGate::Available {
                work: ReceiverAnalysisWork::default(),
                points_to: None,
                truncated: false,
            });
        };
        let cancellation = cancellation.cloned().unwrap_or_default();
        let mut semantic = ReceiverSemanticBridge::new(budget);
        let outcome = semantic
            .oracle(workspace)
            .pointees_at_source(
                file,
                range,
                &mut SemanticRequest::new(&mut semantic.budget, &cancellation),
            )
            .map_err(ReceiverQueryError::SemanticProvider)?;
        let work = semantic.work();
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
                    points_to: Some(points_to.clone()),
                    truncated: points_to.coverage().is_truncated(),
                }),
                Some(_) | None => Ok(SemanticReceiverGate::Unavailable { work }),
            },
        }
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

        let mut setup_nodes = 0;
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
            setup_nodes = match walk_named_tree_preorder_bounded(
                tree.root_node(),
                true,
                budget.max_scope_nodes,
                cancellation,
                |_| {},
            ) {
                BoundedNamedTreeWalk::Complete { visited } => visited,
                BoundedNamedTreeWalk::Exceeded { visited } => {
                    return Ok(setup_budget_report(
                        operation,
                        file,
                        Language::Java,
                        range,
                        &source,
                        visited,
                    ));
                }
                BoundedNamedTreeWalk::Cancelled => return Err(ReceiverQueryError::Cancelled),
            };
            self.java_class_ranges
                .borrow_mut()
                .insert(file.clone(), ClassRangeIndex::build(self.analyzer, file));
            self.prepared_java_files
                .borrow_mut()
                .insert(file.clone(), PreparedJavaReceiverFile { source, tree });
        }
        let budget = ReceiverAnalysisBudget {
            max_scope_nodes: budget.max_scope_nodes.saturating_sub(setup_nodes),
            ..budget
        };

        let prepared_files = self.prepared_java_files.borrow();
        let prepared = prepared_files
            .get(file)
            .expect("Java receiver file was prepared above");
        let Some(input_node) = smallest_named_node_covering(
            prepared.tree.root_node(),
            range.start_byte,
            range.end_byte,
        ) else {
            let mut report = unsupported_report(
                operation,
                file,
                Language::Java,
                range,
                "receiver_input_range_unavailable",
                Some(&prepared.source),
            );
            report.work.setup_nodes = setup_nodes;
            return Ok(report);
        };
        let query_node = match operation {
            ReceiverQueryOperation::PointsTo => input_node,
            ReceiverQueryOperation::ReceiverTargets | ReceiverQueryOperation::MemberTargets
                if input == ReceiverQueryInput::ContainingSite =>
            {
                let Some(receiver) = java_receiver_at_site(input_node) else {
                    let mut report = unsupported_report(
                        operation,
                        file,
                        Language::Java,
                        range,
                        "receiver_site_without_receiver",
                        Some(&prepared.source),
                    );
                    report.work.setup_nodes = setup_nodes;
                    return Ok(report);
                };
                receiver
            }
            ReceiverQueryOperation::ReceiverTargets | ReceiverQueryOperation::MemberTargets => {
                input_node
            }
        };
        let query_range = node_range(query_node);
        let member_node = java_member_node_at_site(input_node);
        let member_name = member_node.and_then(|member| {
            prepared
                .source
                .get(member.start_byte()..member.end_byte())
                .map(str::to_string)
        });
        let semantic = self.semantic_receiver_gate(file, query_range, budget, cancellation)?;
        let (points_to, mut work, mut candidates_truncated) = match semantic {
            SemanticReceiverGate::Available {
                work,
                points_to: Some(points_to),
                truncated,
            } => (points_to, work, truncated),
            SemanticReceiverGate::Available {
                work,
                points_to: None,
                ..
            }
            | SemanticReceiverGate::Unavailable { work } => {
                let mut report =
                    java_unknown_report(operation, file, query_node, &prepared.source, member_name);
                report.work = work;
                report.work.setup_nodes = setup_nodes;
                return Ok(report);
            }
            SemanticReceiverGate::Exceeded { mut work, limit } => {
                work.setup_nodes = setup_nodes;
                return Ok(budget_report(
                    operation,
                    site(
                        file,
                        Language::Java,
                        node_range(query_node),
                        &prepared.source,
                        query_node.kind(),
                        member_name,
                    ),
                    work,
                    limit,
                ));
            }
        };

        self.definitions.set_language(Language::Java);
        work.setup_nodes = setup_nodes;
        if operation == ReceiverQueryOperation::MemberTargets {
            let Some(member_node) = member_node else {
                let mut report =
                    java_unknown_report(operation, file, query_node, &prepared.source, member_name);
                report.work = work;
                return Ok(report);
            };
            let Some(outcome) = java_definition_at(
                self.analyzer,
                &self.definitions,
                file,
                &prepared.source,
                &prepared.tree,
                member_node,
            ) else {
                let mut report =
                    java_unknown_report(operation, file, query_node, &prepared.source, member_name);
                report.work = work;
                return Ok(report);
            };
            let (outcome, truncated) = java_definition_outcome(outcome, budget.max_targets);
            candidates_truncated |= truncated;
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
                analysis: ReceiverQueryAnalysis::MemberTargets(outcome),
                work,
                candidates_truncated,
            });
        }

        let mut type_outcome = java_type_outcome_at(
            self.analyzer,
            &self.definitions,
            file,
            &prepared.source,
            &prepared.tree,
            query_node,
        );
        if type_outcome.types.is_empty() {
            let receiver_owners =
                java_current_receiver_owners(workspace, &self.java_class_ranges, &points_to);
            if !receiver_owners.is_empty() {
                let fqn = receiver_owners[0].fq_name();
                type_outcome.status = TypeLookupStatus::Resolved;
                type_outcome.types.push(TypeLookupType {
                    fqn,
                    definitions: receiver_owners,
                });
            }
        }
        if type_outcome.types.is_empty()
            && let Some(context_node) = java_contextual_type_node(query_node)
        {
            type_outcome = java_type_outcome_at(
                self.analyzer,
                &self.definitions,
                file,
                &prepared.source,
                &prepared.tree,
                context_node,
            );
        }
        candidates_truncated |= type_outcome
            .types
            .iter()
            .map(|ty| ty.definitions.len())
            .sum::<usize>()
            > budget.max_targets;

        let analysis = match operation {
            ReceiverQueryOperation::ReceiverTargets | ReceiverQueryOperation::PointsTo => {
                let (values, truncated) = java_receiver_values(
                    workspace,
                    &points_to,
                    &type_outcome,
                    java_factory_definition(
                        self.analyzer,
                        &self.definitions,
                        file,
                        &prepared.source,
                        &prepared.tree,
                        query_node,
                    ),
                    java_type_reference(
                        self.analyzer,
                        &self.definitions,
                        file,
                        &prepared.source,
                        &prepared.tree,
                        query_node,
                    ),
                    budget.max_targets,
                );
                candidates_truncated |= truncated;
                ReceiverQueryAnalysis::Values(java_type_outcome(type_outcome.status, values))
            }
            ReceiverQueryOperation::MemberTargets => {
                unreachable!("member targets return through the exact Java resolver above")
            }
        };

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
            work,
            candidates_truncated,
        })
    }

    #[cfg(test)]
    fn prepared_file_count(&self) -> usize {
        self.prepared_files.borrow().len() + self.prepared_java_files.borrow().len()
    }
}

fn apply_semantic_gate(
    mut report: ReceiverQueryReport,
    gate: SemanticReceiverGate,
) -> ReceiverQueryReport {
    let gate_work = match gate {
        SemanticReceiverGate::Available {
            work,
            points_to,
            truncated,
        } => {
            if let Some(points_to) = points_to {
                let removed = retain_neutral_backed_values(&mut report.analysis, &points_to);
                report.candidates_truncated |= removed;
            }
            report.candidates_truncated |= truncated;
            work
        }
        SemanticReceiverGate::Unavailable { work } => {
            neutral_unknown(&mut report.analysis);
            work
        }
        SemanticReceiverGate::Exceeded { work, limit } => {
            neutral_exceeded(&mut report.analysis, limit);
            work
        }
    };
    report.work.scope_nodes = report
        .work
        .scope_nodes
        .saturating_add(gate_work.scope_nodes);
    report.work.summary_expansions = report
        .work
        .summary_expansions
        .saturating_add(gate_work.summary_expansions);
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

struct ReceiverSemanticBridge {
    budget: SemanticBudget,
    oracle_limits: OracleLimits,
}

impl ReceiverSemanticBridge {
    fn new(receiver: ReceiverAnalysisBudget) -> Self {
        let scope = receiver.max_scope_nodes.max(1);
        let summaries = receiver.max_summary_expansions.max(1);
        let targets = receiver.max_targets.max(1);
        // Oracle limits are positive by contract. Source projections always
        // start with an empty OracleCallContext, so this representational
        // minimum does not retain a call frame when receiver context depth is
        // explicitly zero.
        let context = receiver.context_depth.max(1);
        let traversal = scope
            .saturating_mul(context.saturating_add(1))
            .saturating_add(summaries.saturating_mul(targets))
            .max(1);
        let text = scope.saturating_mul(1_024).max(1);
        let budget = SemanticBudget::new(SemanticWork {
            source_bytes: text,
            procedures: scope,
            blocks: scope,
            program_points: scope,
            values: scope,
            allocations: scope,
            call_sites: summaries,
            memory_locations: summaries,
            captures: summaries,
            source_mappings: scope,
            evidence: scope,
            gaps: scope,
            events: traversal,
            control_edges: traversal,
            nested_entries: traversal,
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
        Self {
            budget,
            oracle_limits,
        }
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
                .saturating_add(work.captures)
                .saturating_add(work.nested_entries),
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
                .saturating_add(work.control_edges),
        }
    }

    fn receiver_limit(exceeded: SemanticBudgetExceeded) -> ReceiverBudgetLimit {
        match exceeded.dimension() {
            SemanticBudgetDimension::CallSites
            | SemanticBudgetDimension::MemoryLocations
            | SemanticBudgetDimension::Captures
            | SemanticBudgetDimension::NestedEntries => ReceiverBudgetLimit::SummaryExpansions,
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
            | SemanticBudgetDimension::OwnedTextBytes => ReceiverBudgetLimit::ScopeNodes,
        }
    }
}

fn java_receiver_values(
    workspace: &WorkspaceAnalyzer,
    points_to: &SourcePointsToResult,
    type_outcome: &crate::analyzer::usages::get_type::TypeLookupOutcome,
    factory: Option<CodeUnit>,
    type_reference: bool,
    limit: usize,
) -> (Vec<ReceiverValue>, bool) {
    let mut allocations = Vec::new();
    for allocation in
        points_to
            .object_candidates()
            .filter_map(|candidate| match candidate.value().identity() {
                AbstractObjectIdentity::Allocation(allocation) => Some(allocation),
                _ => None,
            })
    {
        if !allocations.contains(&allocation) {
            allocations.push(allocation);
        }
    }
    let current_receiver = points_to.object_candidates().any(|candidate| {
        matches!(
            candidate.value().identity(),
            AbstractObjectIdentity::ProcedurePort(port)
                if port.kind() == crate::analyzer::semantic::ProcedurePortKind::Receiver
        )
    });
    let projected_count = type_outcome
        .types
        .iter()
        .map(|ty| ty.definitions.len())
        .sum::<usize>()
        .saturating_mul(if current_receiver || allocations.is_empty() {
            1
        } else {
            allocations.len()
        });
    let mut values = Vec::new();
    for definition in type_outcome
        .types
        .iter()
        .flat_map(|ty| ty.definitions.iter())
    {
        let value = if current_receiver {
            ReceiverValue::CurrentReceiver(definition.clone())
        } else if matches!(
            type_outcome.target_kind,
            crate::analyzer::usages::target_kind::TypeLookupTargetKind::TypeReference
        ) || type_reference
        {
            ReceiverValue::ClassOrStaticObject(definition.clone())
        } else if allocations.is_empty() {
            ReceiverValue::InstanceType(definition.clone())
        } else {
            for allocation in &allocations {
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
            if values.len() >= limit {
                break;
            }
            continue;
        };
        values.push(if let Some(factory) = &factory {
            ReceiverValue::FactoryReturn {
                factory: factory.clone(),
                value: Box::new(value),
            }
        } else {
            value
        });
        if values.len() >= limit {
            break;
        }
    }
    values.truncate(limit);
    (values, projected_count > limit)
}

fn java_factory_definition(
    analyzer: &dyn IAnalyzer,
    definitions: &AnalyzerDefinitionLookup<'_>,
    file: &ProjectFile,
    source: &str,
    tree: &tree_sitter::Tree,
    node: Node<'_>,
) -> Option<CodeUnit> {
    if node.kind() != "method_invocation" {
        return None;
    }
    let name = node.child_by_field_name("name")?;
    let outcome = java_definition_at(analyzer, definitions, file, source, tree, name)?;
    (outcome.definitions.len() == 1)
        .then(|| outcome.definitions.into_iter().next())
        .flatten()
}

fn java_type_reference(
    analyzer: &dyn IAnalyzer,
    definitions: &AnalyzerDefinitionLookup<'_>,
    file: &ProjectFile,
    source: &str,
    tree: &tree_sitter::Tree,
    node: Node<'_>,
) -> bool {
    let Some(outcome) = java_definition_at(analyzer, definitions, file, source, tree, node) else {
        return false;
    };
    !outcome.definitions.is_empty() && outcome.definitions.iter().all(CodeUnit::is_class)
}

fn java_definition_at(
    analyzer: &dyn IAnalyzer,
    definitions: &AnalyzerDefinitionLookup<'_>,
    file: &ProjectFile,
    source: &str,
    tree: &tree_sitter::Tree,
    node: Node<'_>,
) -> Option<crate::analyzer::usages::get_definition::DefinitionLookupOutcome> {
    let site = java_reference_site(file, source, node)?;
    Some(resolve_java(
        analyzer,
        definitions,
        file,
        source,
        Some(tree),
        &site,
    ))
}

fn java_type_outcome_at(
    analyzer: &dyn IAnalyzer,
    definitions: &AnalyzerDefinitionLookup<'_>,
    file: &ProjectFile,
    source: &str,
    tree: &tree_sitter::Tree,
    node: Node<'_>,
) -> TypeLookupOutcome {
    let Some(site) = java_reference_site(file, source, node) else {
        return TypeLookupOutcome {
            status: TypeLookupStatus::InvalidLocation,
            reference: None,
            types: Vec::new(),
            diagnostics: Vec::new(),
            target_kind: TypeLookupTargetKind::ValueExpression,
        };
    };
    resolve_java_type(analyzer, definitions, file, source, Some(tree), &site)
}

fn java_reference_site(
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
) -> Option<crate::analyzer::usages::reference_site::ResolvedReferenceSite> {
    resolve_reference_site(
        &SourceLocationRequest {
            file: file.clone(),
            line: None,
            column: None,
            start_byte: Some(node.start_byte()),
            end_byte: Some(node.end_byte()),
        },
        source,
    )
    .ok()
}

fn java_contextual_type_node(mut node: Node<'_>) -> Option<Node<'_>> {
    while let Some(parent) = node.parent() {
        if parent.kind() == "variable_declarator"
            && parent.child_by_field_name("value").is_some_and(|value| {
                value.start_byte() <= node.start_byte() && value.end_byte() >= node.end_byte()
            })
        {
            return parent.child_by_field_name("name");
        }
        if matches!(
            parent.kind(),
            "statement" | "expression_statement" | "return_statement" | "block"
        ) {
            return None;
        }
        node = parent;
    }
    None
}

fn java_definition_outcome(
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

fn java_current_receiver_owners(
    workspace: &WorkspaceAnalyzer,
    class_ranges: &RefCell<HashMap<ProjectFile, ClassRangeIndex>>,
    points_to: &SourcePointsToResult,
) -> Vec<CodeUnit> {
    let analyzer = workspace.analyzer();
    let mut owners = Vec::new();
    for port in
        points_to
            .object_candidates()
            .filter_map(|candidate| match candidate.value().identity() {
                AbstractObjectIdentity::ProcedurePort(port)
                    if port.kind() == crate::analyzer::semantic::ProcedurePortKind::Receiver =>
                {
                    Some(port)
                }
                _ => None,
            })
    {
        let file = ProjectFile::new(
            analyzer.project().root().to_path_buf(),
            port.procedure().artifact().key().path().as_path(),
        );
        if !class_ranges.borrow().contains_key(&file) {
            class_ranges
                .borrow_mut()
                .insert(file.clone(), ClassRangeIndex::build(analyzer, &file));
        }
        let byte = port
            .procedure()
            .semantics()
            .locator()
            .anchor()
            .span()
            .start_byte() as usize;
        if let Some(owner) = class_ranges
            .borrow()
            .get(&file)
            .and_then(|ranges| ranges.enclosing_unit(byte))
            && !owners.contains(owner)
        {
            owners.push(owner.clone());
        }
    }
    owners
}

fn java_type_outcome<T>(status: TypeLookupStatus, values: Vec<T>) -> ReceiverAnalysisOutcome<T> {
    if values.is_empty() {
        return ReceiverAnalysisOutcome::Unknown;
    }
    match status {
        TypeLookupStatus::Resolved => ReceiverAnalysisOutcome::Precise(values),
        TypeLookupStatus::Ambiguous => ReceiverAnalysisOutcome::Ambiguous(values),
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
    }
}

fn java_receiver_at_site(mut node: Node<'_>) -> Option<Node<'_>> {
    loop {
        match node.kind() {
            "method_invocation" => return node.child_by_field_name("object"),
            "field_access" => return node.child_by_field_name("object"),
            _ => node = node.parent()?,
        }
    }
}

fn java_member_node_at_site(mut node: Node<'_>) -> Option<Node<'_>> {
    loop {
        let member = match node.kind() {
            "method_invocation" => node.child_by_field_name("name"),
            "field_access" => node.child_by_field_name("field"),
            _ => None,
        };
        if let Some(member) = member {
            return Some(member);
        }
        node = node.parent()?;
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
    }
}

fn setup_budget_report(
    operation: ReceiverQueryOperation,
    file: &ProjectFile,
    language: Language,
    range: Range,
    source: &str,
    setup_nodes: usize,
) -> ReceiverQueryReport {
    budget_report(
        operation,
        site(file, language, range, source, "setup", None),
        ReceiverAnalysisWork {
            setup_nodes,
            ..ReceiverAnalysisWork::default()
        },
        ReceiverBudgetLimit::ScopeNodes,
    )
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
mod tests {
    use super::*;
    use crate::analyzer::{TestProject, TypescriptAnalyzer};
    use crate::{AnalyzerConfig, WorkspaceAnalyzer};
    use std::path::PathBuf;

    fn test_project(source: &str) -> (tempfile::TempDir, ProjectFile, TypescriptAnalyzer) {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = ProjectFile::new(root.clone(), PathBuf::from("src/app.ts"));
        file.write(source).expect("write source");
        let analyzer =
            TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));
        (temp, file, analyzer)
    }

    fn marker_range(source: &str, marker: &str) -> Range {
        let start_byte = source.find(marker).expect("marker");
        range_at(source, marker, start_byte)
    }

    fn last_marker_range(source: &str, marker: &str) -> Range {
        let start_byte = source.rfind(marker).expect("marker");
        range_at(source, marker, start_byte)
    }

    fn range_at(source: &str, marker: &str, start_byte: usize) -> Range {
        Range {
            start_byte,
            end_byte: start_byte + marker.len(),
            start_line: source[..start_byte]
                .bytes()
                .filter(|byte| *byte == b'\n')
                .count(),
            end_line: source[..start_byte + marker.len()]
                .bytes()
                .filter(|byte| *byte == b'\n')
                .count(),
        }
    }

    #[test]
    fn points_to_reports_factory_and_allocation_provenance_with_work() {
        let source = r#"
class Service { run() {} }
function makeService() { return new Service(); }
export function caller() {
  const service = makeService();
  service.run();
}
"#;
        let (_temp, file, analyzer) = test_project(source);

        let report = ReceiverQueryService::new(&analyzer)
            .analyze(
                ReceiverQueryOperation::PointsTo,
                &file,
                last_marker_range(source, "makeService()"),
                ReceiverQueryInput::Expression,
                ReceiverAnalysisBudget::default(),
                None,
            )
            .expect("receiver query");

        assert_eq!(report.operation.as_str(), "points_to");
        assert_eq!(report.site.text, "makeService()");
        assert!(report.work.scope_nodes > 0);
        assert!(!report.candidates_truncated);
        assert!(
            matches!(
                &report.analysis,
                ReceiverQueryAnalysis::Values(ReceiverAnalysisOutcome::Precise(values))
                    if matches!(
                        values.as_slice(),
                        [ReceiverValue::FactoryReturn { factory, value }]
                            if factory.fq_name().ends_with("makeService")
                                && matches!(value.as_ref(), ReceiverValue::AllocationSite { ty, .. } if ty.fq_name().ends_with("Service"))
                    )
            ),
            "unexpected analysis: {:?}",
            report.analysis
        );
    }

    #[test]
    fn member_targets_only_returns_the_receiver_owner_member() {
        let source = r#"
class Service { run() {} }
class Other { run() {} }
export function caller() {
  const service = new Service();
  service.run();
}
"#;
        let (_temp, file, analyzer) = test_project(source);

        let report = ReceiverQueryService::new(&analyzer)
            .analyze(
                ReceiverQueryOperation::MemberTargets,
                &file,
                marker_range(source, "service.run"),
                ReceiverQueryInput::ContainingSite,
                ReceiverAnalysisBudget::default(),
                None,
            )
            .expect("member target query");

        assert_eq!(report.site.member_name.as_deref(), Some("run"));
        assert!(matches!(
            report.analysis,
            ReceiverQueryAnalysis::MemberTargets(ReceiverAnalysisOutcome::Precise(ref targets))
                if targets.len() == 1
                    && targets[0].fq_name().contains("Service")
                    && !targets[0].fq_name().contains("Other")
        ));
    }

    #[test]
    fn repeated_queries_reuse_prepared_file_context_and_charge_setup_once() {
        let source = r#"
class Service { run() {} }
export function caller() {
  const first = new Service();
  const second = new Service();
  first.run();
  second.run();
}
"#;
        let (_temp, file, analyzer) = test_project(source);
        let service = ReceiverQueryService::new(&analyzer);

        let first = service
            .analyze(
                ReceiverQueryOperation::PointsTo,
                &file,
                marker_range(source, "first.run"),
                ReceiverQueryInput::ContainingSite,
                ReceiverAnalysisBudget::default(),
                None,
            )
            .expect("first receiver query");
        let second = service
            .analyze(
                ReceiverQueryOperation::PointsTo,
                &file,
                marker_range(source, "second.run"),
                ReceiverQueryInput::ContainingSite,
                ReceiverAnalysisBudget::default(),
                None,
            )
            .expect("second receiver query");

        assert_eq!(service.prepared_file_count(), 1);
        assert!(first.work.setup_nodes > 0);
        assert_eq!(second.work.setup_nodes, 0);
    }

    #[test]
    fn unsupported_language_returns_an_explicit_row() {
        let source = "value = object.member\n";
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = ProjectFile::new(root.clone(), PathBuf::from("app.py"));
        file.write(source).expect("write source");
        let analyzer =
            TypescriptAnalyzer::from_project(TestProject::new(root, Language::TypeScript));

        let report = ReceiverQueryService::new(&analyzer)
            .analyze(
                ReceiverQueryOperation::ReceiverTargets,
                &file,
                marker_range(source, "object.member"),
                ReceiverQueryInput::ContainingSite,
                ReceiverAnalysisBudget::default(),
                None,
            )
            .expect("unsupported result");

        assert_eq!(report.site.language, Language::Python);
        assert!(matches!(
            report.analysis,
            ReceiverQueryAnalysis::Values(ReceiverAnalysisOutcome::Unsupported {
                reason: "receiver_analysis_language_unsupported"
            })
        ));
    }

    #[test]
    fn java_queries_reuse_prepared_context_and_honor_bounds() {
        let source = r#"
class Service { void run() {} void run(int value) {} }
class Sample {
    void caller() {
        Service service = new Service();
        service.run();
    }
}
"#;
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = ProjectFile::new(root.clone(), PathBuf::from("Sample.java"));
        file.write(source).expect("write source");
        let workspace = WorkspaceAnalyzer::build(
            Arc::new(TestProject::new(root, Language::Java)),
            AnalyzerConfig::default(),
        );
        let service = ReceiverQueryService::from_workspace(&workspace);
        let range = marker_range(source, "service.run");

        let first = service
            .analyze(
                ReceiverQueryOperation::MemberTargets,
                &file,
                range,
                ReceiverQueryInput::ContainingSite,
                ReceiverAnalysisBudget::default(),
                None,
            )
            .expect("first Java receiver query");
        let second = service
            .analyze(
                ReceiverQueryOperation::MemberTargets,
                &file,
                range,
                ReceiverQueryInput::ContainingSite,
                ReceiverAnalysisBudget::default(),
                None,
            )
            .expect("second Java receiver query");

        assert_eq!(service.prepared_file_count(), 1);
        assert_eq!(service.java_class_ranges.borrow().len(), 1);
        assert!(first.work.setup_nodes > 0);
        assert_eq!(second.work.setup_nodes, 0);
        for report in [&first, &second] {
            assert!(matches!(
                report.analysis,
                ReceiverQueryAnalysis::MemberTargets(ReceiverAnalysisOutcome::Precise(ref targets))
                    if targets.len() == 1
            ));
        }

        let capped = service
            .analyze(
                ReceiverQueryOperation::MemberTargets,
                &file,
                range,
                ReceiverQueryInput::ContainingSite,
                ReceiverAnalysisBudget {
                    max_targets: 1,
                    ..ReceiverAnalysisBudget::default()
                },
                None,
            )
            .expect("candidate-capped Java receiver query");
        assert!(!capped.candidates_truncated);
        assert!(matches!(
            capped.analysis,
            ReceiverQueryAnalysis::MemberTargets(ReceiverAnalysisOutcome::Precise(ref targets))
                if targets.len() == 1
        ));

        let bounded_service = ReceiverQueryService::from_workspace(&workspace);
        let bounded = bounded_service
            .analyze(
                ReceiverQueryOperation::MemberTargets,
                &file,
                range,
                ReceiverQueryInput::ContainingSite,
                ReceiverAnalysisBudget::tiny(),
                None,
            )
            .expect("tiny-budget Java receiver query");
        assert!(matches!(
            bounded.analysis,
            ReceiverQueryAnalysis::MemberTargets(ReceiverAnalysisOutcome::ExceededBudget {
                limit: "scope_nodes"
            })
        ));
        assert_eq!(bounded.work.setup_nodes, 2);

        let cancellation = CancellationToken::default();
        cancellation.cancel();
        assert_eq!(
            service.analyze(
                ReceiverQueryOperation::MemberTargets,
                &file,
                range,
                ReceiverQueryInput::ContainingSite,
                ReceiverAnalysisBudget::default(),
                Some(&cancellation),
            ),
            Err(ReceiverQueryError::Cancelled)
        );
    }

    #[test]
    fn java_current_receiver_keeps_exact_nested_owner_identity() {
        let source = r#"
class Left {
    static class Worker {
        void helper() {}
        void caller() { this.helper(); }
    }
}
class Right {
    static class Worker {
        void helper() {}
        void caller() { this.helper(); }
    }
}
"#;
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = ProjectFile::new(root.clone(), PathBuf::from("Nested.java"));
        file.write(source).expect("write source");
        let workspace = WorkspaceAnalyzer::build(
            Arc::new(TestProject::new(root, Language::Java)),
            AnalyzerConfig::default(),
        );
        let report = ReceiverQueryService::from_workspace(&workspace)
            .analyze(
                ReceiverQueryOperation::ReceiverTargets,
                &file,
                marker_range(source, "this.helper"),
                ReceiverQueryInput::ContainingSite,
                ReceiverAnalysisBudget::default(),
                None,
            )
            .expect("nested current-receiver query");

        assert!(matches!(
            report.analysis,
            ReceiverQueryAnalysis::Values(ReceiverAnalysisOutcome::Precise(ref values))
                if matches!(values.as_slice(), [ReceiverValue::CurrentReceiver(owner)]
                    if owner.fq_name().contains("Left.Worker")
                        && !owner.fq_name().contains("Right.Worker"))
        ));
    }

    #[test]
    fn tiny_budget_and_cancellation_are_deterministic() {
        let source = r#"
class Service { run() {} }
function makeService() { return new Service(); }
export function caller() {
  const service = makeService();
  service.run();
}
"#;
        let (_temp, file, analyzer) = test_project(source);
        let service = ReceiverQueryService::new(&analyzer);
        let range = marker_range(source, "service.run");

        let report = service
            .analyze(
                ReceiverQueryOperation::MemberTargets,
                &file,
                range,
                ReceiverQueryInput::ContainingSite,
                ReceiverAnalysisBudget::tiny(),
                None,
            )
            .expect("tiny-budget result");
        assert!(matches!(
            report.analysis,
            ReceiverQueryAnalysis::MemberTargets(ReceiverAnalysisOutcome::ExceededBudget {
                limit: "scope_nodes"
            })
        ));
        assert_eq!(report.work.setup_nodes, 2);
        assert!(
            report
                .work
                .setup_nodes
                .saturating_add(report.work.scope_nodes)
                > ReceiverAnalysisBudget::tiny().max_scope_nodes
        );

        let cancellation = CancellationToken::default();
        cancellation.cancel();
        assert_eq!(
            service.analyze(
                ReceiverQueryOperation::MemberTargets,
                &file,
                range,
                ReceiverQueryInput::ContainingSite,
                ReceiverAnalysisBudget::default(),
                Some(&cancellation),
            ),
            Err(ReceiverQueryError::Cancelled)
        );
    }

    #[test]
    fn receiver_semantic_bridge_uses_every_receiver_limit() {
        let bridge = ReceiverSemanticBridge::new(ReceiverAnalysisBudget {
            context_depth: 2,
            max_targets: 3,
            max_summary_expansions: 5,
            max_scope_nodes: 7,
        });
        let semantic = bridge.budget.limits();
        assert_eq!(semantic.procedures, 7);
        assert_eq!(semantic.call_sites, 5);
        assert_eq!(semantic.source_bytes, 7 * 1_024);
        assert_eq!(semantic.nested_entries, 7 * 3 + 5 * 3);

        let oracle = bridge.oracle_limits.values();
        assert_eq!(oracle.dispatch_targets, 3);
        assert_eq!(oracle.objects_per_value, 3);
        assert_eq!(oracle.alias_breadth, 3);
        assert_eq!(oracle.source_observations, 3);
        assert_eq!(oracle.call_context_depth, 2);
        assert_eq!(oracle.summary_depth, 5);
        assert_eq!(oracle.call_binding_entries, 5);

        let zero_context = ReceiverSemanticBridge::new(ReceiverAnalysisBudget {
            context_depth: 0,
            ..ReceiverAnalysisBudget::default()
        });
        assert_eq!(zero_context.oracle_limits.call_context_depth(), 1);
    }

    #[test]
    fn receiver_semantic_bridge_translates_all_row_work_and_limit_kinds() {
        let translated = ReceiverSemanticBridge::receiver_work(SemanticWork {
            source_bytes: usize::MAX,
            procedures: 1,
            blocks: 1,
            program_points: 1,
            values: 1,
            allocations: 1,
            call_sites: 1,
            memory_locations: 1,
            captures: 1,
            source_mappings: 1,
            evidence: 1,
            gaps: 1,
            events: 1,
            control_edges: 1,
            nested_entries: 1,
            owned_text_bytes: usize::MAX,
        });
        assert_eq!(translated.setup_nodes, 0);
        assert_eq!(translated.summary_expansions, 4);
        assert_eq!(translated.scope_nodes, 10);

        let budget = SemanticBudget::uniform(1).unwrap();
        let summary = budget
            .check(SemanticWork {
                call_sites: 2,
                ..SemanticWork::default()
            })
            .unwrap_err();
        assert_eq!(
            ReceiverSemanticBridge::receiver_limit(summary),
            ReceiverBudgetLimit::SummaryExpansions
        );
        let scope = budget
            .check(SemanticWork {
                events: 2,
                ..SemanticWork::default()
            })
            .unwrap_err();
        assert_eq!(
            ReceiverSemanticBridge::receiver_limit(scope),
            ReceiverBudgetLimit::ScopeNodes
        );
    }

    #[test]
    fn semantic_receiver_gate_preserves_provider_identity_failures() {
        let source = "export const value = {};\n";
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical root");
        let file = ProjectFile::new(root.clone(), PathBuf::from("app.ts"));
        file.write(source).expect("write source");
        let workspace = WorkspaceAnalyzer::build(
            Arc::new(TestProject::new(root, Language::TypeScript)),
            AnalyzerConfig::default(),
        );
        let foreign = tempfile::tempdir().expect("foreign temp dir");
        let foreign_file = ProjectFile::new(
            foreign.path().canonicalize().expect("foreign root"),
            PathBuf::from("app.ts"),
        );

        let result = ReceiverQueryService::from_workspace(&workspace).semantic_receiver_gate(
            &foreign_file,
            Range {
                start_byte: 0,
                end_byte: 1,
                start_line: 0,
                end_line: 0,
            },
            ReceiverAnalysisBudget::default(),
            None,
        );

        assert!(matches!(
            result,
            Err(ReceiverQueryError::SemanticProvider(
                SemanticProviderError::InvalidIdentity(_)
            ))
        ));
    }
}
