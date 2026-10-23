//! Java receiver-query route, registered through LanguageSupport.

use brokk_bifrost_core::cancellation::CancellationToken;

use brokk_bifrost_analysis::analyzer::semantic::AbstractObjectIdentity;
use brokk_bifrost_semantic::analyzer::semantic::workspace_oracle::source::SourcePointsToResult;

use brokk_bifrost_core::analyzer::tree_walk::BoundedNamedTreeWalk;

use brokk_bifrost_core::analyzer::tree_walk::walk_named_tree_preorder_bounded;

use crate::analyzer::usages::get_definition::java::JavaResolutionSession;

use crate::analyzer::usages::get_definition::java::resolve_java_bounded;

use brokk_bifrost_core::analyzer::usages::resolution_session::BoundedResolution;

use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupOutcome;

use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupStatus;

use brokk_bifrost_analysis::analyzer::usages::get_definition::parse_tree_for_language;

use crate::analyzer::usages::get_type::java::resolve_java_type_bounded;

use brokk_bifrost_analysis::analyzer::usages::get_type::TypeLookupOutcome;

use brokk_bifrost_analysis::analyzer::usages::get_type::TypeLookupStatus;

use brokk_bifrost_analysis::analyzer::usages::get_type::TypeLookupType;

use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget;

use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisWork;

use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverBudgetLimit;

use brokk_bifrost_analysis::analyzer::usages::receiver_query::*;

use brokk_bifrost_core::analyzer::usages::reference_site::node_range;

use brokk_bifrost_core::analyzer::usages::reference_site::{
    SourceLocationRequest, resolve_reference_site_with_line_starts,
};

use brokk_bifrost_analysis::analyzer::usages::target_kind::TypeLookupTargetKind;

use brokk_bifrost_analysis::analyzer::analyzer_definition_lookup::AnalyzerDefinitionLookup;

use brokk_bifrost_core::analyzer::model::CodeUnit;

use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

use brokk_bifrost_core::analyzer::model::Language;

use brokk_bifrost_core::analyzer::model::ProjectFile;

use brokk_bifrost_core::analyzer::model::Range;

use brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer;

use brokk_bifrost_core::text_utils::compute_line_starts;
use tree_sitter::Node;

#[allow(clippy::too_many_arguments)]
pub(crate) trait JavaReceiverQueryService {
    fn analyze_java(
        &self,
        operation: ReceiverQueryOperation,
        file: &ProjectFile,
        range: Range,
        input: ReceiverQueryInput,
        budget: ReceiverAnalysisBudget,
        cancellation: Option<&CancellationToken>,
        indexed_source: Option<String>,
    ) -> Result<ReceiverQueryReport, ReceiverQueryError>;
}

impl JavaReceiverQueryService for ReceiverQueryService<'_> {
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
            let outcome = match charge_bounded_resolution(&mut ledger, outcome)? {
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
            let mut analysis =
                ReceiverQueryAnalysis::MemberTargets(unowned_workspace_member_targets(outcome));
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
                member_range: Some(node_range(member_node)),
                work: ledger.work(),
                candidates_truncated,
                semantic_unsupported,
                points_to: None,
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
        let mut type_outcome = match charge_bounded_resolution(&mut ledger, type_resolution)? {
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
                    semantic_model_id: None,
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
                type_outcome = match charge_bounded_resolution(&mut ledger, contextual)? {
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
            match charge_bounded_resolution(&mut ledger, factory_resolution)? {
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
        let type_reference = match charge_bounded_resolution(&mut ledger, type_resolution)? {
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
        if (!supports_precise || candidates_truncated) && !is_exact_current_receiver(&analysis) {
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
            member_range: None,
            work: ledger.work(),
            candidates_truncated,
            semantic_unsupported,
            points_to: if operation == ReceiverQueryOperation::PointsTo {
                Some(points_to.clone())
            } else {
                None
            },
        })
    }
}

trait PreparedJavaReceiverFileExt {
    fn resolution_input(&self) -> JavaReceiverResolutionInput<'_>;
}
impl PreparedJavaReceiverFileExt for PreparedJavaReceiverFile {
    fn resolution_input(&self) -> JavaReceiverResolutionInput<'_> {
        JavaReceiverResolutionInput {
            source: &self.source,
            tree: &self.tree,
            line_starts: &self.line_starts,
        }
    }
}
#[derive(Clone, Copy)]
struct JavaReceiverResolutionInput<'a> {
    source: &'a str,
    tree: &'a tree_sitter::Tree,
    line_starts: &'a [usize],
}

fn java_factory_name_node(node: Node<'_>) -> Option<Node<'_>> {
    if node.kind() != "method_invocation" {
        return None;
    }
    node.child_by_field_name("name")
}

fn java_definition_at(
    analyzer: &dyn IAnalyzer,
    definitions: &AnalyzerDefinitionLookup<'_>,
    file: &ProjectFile,
    input: JavaReceiverResolutionInput<'_>,
    node: Node<'_>,
    budget: ReceiverAnalysisBudget,
    cancellation: Option<&CancellationToken>,
) -> BoundedResolution<DefinitionLookupOutcome> {
    java_resolution_outcome_at(
        definitions,
        file,
        input,
        node,
        budget,
        cancellation,
        DefinitionLookupOutcome {
            modeled_definitions: Vec::new(),
            status: DefinitionLookupStatus::InvalidLocation,
            reference: None,
            definitions: Vec::new(),
            lexical_definition: None,
            diagnostics: Vec::new(),
        },
        |session, site| {
            resolve_java_bounded(
                analyzer,
                session,
                file,
                input.source,
                Some(input.tree),
                site,
            )
        },
    )
}

fn java_type_outcome_at(
    analyzer: &dyn IAnalyzer,
    definitions: &AnalyzerDefinitionLookup<'_>,
    file: &ProjectFile,
    input: JavaReceiverResolutionInput<'_>,
    node: Node<'_>,
    budget: ReceiverAnalysisBudget,
    cancellation: Option<&CancellationToken>,
) -> BoundedResolution<TypeLookupOutcome> {
    java_resolution_outcome_at(
        definitions,
        file,
        input,
        node,
        budget,
        cancellation,
        TypeLookupOutcome {
            status: TypeLookupStatus::InvalidLocation,
            reference: None,
            types: Vec::new(),
            diagnostics: Vec::new(),
            target_kind: TypeLookupTargetKind::ValueExpression,
        },
        |session, site| {
            resolve_java_type_bounded(
                analyzer,
                session,
                file,
                input.source,
                Some(input.tree),
                site,
            )
        },
    )
}

#[allow(clippy::too_many_arguments)]
fn java_resolution_outcome_at<T>(
    definitions: &AnalyzerDefinitionLookup<'_>,
    file: &ProjectFile,
    input: JavaReceiverResolutionInput<'_>,
    node: Node<'_>,
    budget: ReceiverAnalysisBudget,
    cancellation: Option<&CancellationToken>,
    invalid_location: T,
    resolve: impl FnOnce(
        &JavaResolutionSession<'_>,
        &brokk_bifrost_core::analyzer::usages::reference_site::ResolvedReferenceSite,
    ) -> BoundedResolution<T>,
) -> BoundedResolution<T> {
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        return BoundedResolution::Cancelled {
            work: ReceiverAnalysisWork::default(),
        };
    }
    if budget.max_scope_nodes == 0 {
        return BoundedResolution::Exceeded {
            work: ReceiverAnalysisWork::default(),
            limit: ReceiverBudgetLimit::ScopeNodes,
        };
    }
    let preprocessing_work = ReceiverAnalysisWork {
        scope_nodes: 1,
        ..ReceiverAnalysisWork::default()
    };
    let Some(site) = java_reference_site(
        file,
        input.source,
        input.line_starts,
        input.tree.root_node(),
        node,
    ) else {
        return BoundedResolution::Complete {
            value: invalid_location,
            work: preprocessing_work,
        };
    };
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        return BoundedResolution::Cancelled {
            work: preprocessing_work,
        };
    }
    let mut compatibility_budget = budget;
    compatibility_budget.max_scope_nodes -= 1;
    let session = JavaResolutionSession::bounded(definitions, compatibility_budget, cancellation);
    prepend_java_preprocessing_work(resolve(&session, &site))
}

fn prepend_java_preprocessing_work<T>(resolution: BoundedResolution<T>) -> BoundedResolution<T> {
    let add_preprocessing = |mut work: ReceiverAnalysisWork| {
        work.scope_nodes = work.scope_nodes.saturating_add(1);
        work
    };
    match resolution {
        BoundedResolution::Complete { value, work } => BoundedResolution::Complete {
            value,
            work: add_preprocessing(work),
        },
        BoundedResolution::Exceeded { work, limit } => BoundedResolution::Exceeded {
            work: add_preprocessing(work),
            limit,
        },
        BoundedResolution::Cancelled { work } => BoundedResolution::Cancelled {
            work: add_preprocessing(work),
        },
    }
}

fn java_reference_site(
    file: &ProjectFile,
    source: &str,
    line_starts: &[usize],
    root: Node<'_>,
    node: Node<'_>,
) -> Option<brokk_bifrost_core::analyzer::usages::reference_site::ResolvedReferenceSite> {
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
        Some(root),
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
        if port.kind() != brokk_bifrost_analysis::analyzer::semantic::ProcedurePortKind::Receiver {
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

fn java_unknown_report(
    operation: ReceiverQueryOperation,
    file: &ProjectFile,
    node: Node<'_>,
    source: &str,
    member_name: Option<String>,
) -> ReceiverQueryReport {
    unknown_report(
        operation,
        site(
            file,
            Language::Java,
            node_range(node),
            source,
            node.kind(),
            member_name,
        ),
        ReceiverAnalysisWork::default(),
        false,
    )
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

#[cfg(test)]
#[path = "receiver_query_tests.rs"]
mod tests;
