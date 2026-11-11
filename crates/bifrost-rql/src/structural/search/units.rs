//! Per-seed-file query execution: the narrowed execution scope and the entry
//! point one evaluation unit runs through.
//!
//! An incremental policy evaluation executes one unit per seed file instead of
//! one whole-workspace query, so every unit's recorded reads and rendered rows
//! belong to exactly one seed file (issue: impact-sliced `--diff-base`,
//! Milestone 2). Only the seed enumeration is narrowed: a step that asks for
//! callers, importers, descendants, dispatch, or references still sees the
//! whole workspace, because those answers are what make a finding in an
//! unedited file change.

use super::*;
use crate::analyzer::semantic::SemanticBudgetDimension;
use crate::query::PlanPartitioning;
use crate::structural::execution::plan::StepOutputCap;
use crate::structural::identifier_dictionary::IdentifierDictionary;
use crate::structural::identifier_typos::IdentifierTypoTable;
use std::path::Path;

// An exactly empty set prefix makes every later operand irrelevant to the answer.
pub(super) const EXACT_SHORT_CIRCUIT_DEPTH_STATUS: DepthBoundStatus = DepthBoundStatus::NotReached;

/// Whether a certified empty operand ends this set in authored order.
pub(super) fn empty_operand_ends_set(operator: SetOperator, operand: usize) -> bool {
    match operator {
        SetOperator::Intersect => true,
        SetOperator::Except => operand == 0,
        SetOperator::Union => false,
    }
}

fn skipped_depth_answers_at(plan: &CodeQueryPlan, path: &[usize]) -> Vec<BoundedCallAnswer> {
    let mut answers = unknown_depth_answers_at(plan, path);
    for answer in &mut answers {
        answer.membership_unknown = EXACT_SHORT_CIRCUIT_DEPTH_STATUS == DepthBoundStatus::Unknown;
    }
    answers
}

fn replace_skipped_depth_answers(
    answers: &mut Vec<BoundedCallAnswer>,
    plan: &CodeQueryPlan,
    operands: &[CodeQueryPlan],
) {
    for operand in operands {
        let skipped = skipped_depth_answers_at(operand, &authored_subplan_path(plan, operand));
        let keys = skipped
            .iter()
            .map(|answer| answer.traversal.as_str())
            .collect::<HashSet<_>>();
        answers.retain(|answer| !keys.contains(answer.traversal.as_str()));
        answers.extend(skipped);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct BoundedMemberRow {
    pub(crate) identity: UnitRowKey,
    pub(crate) depth: usize,
}

/// The bounded traversal's own member rows, retained before suffix projection.
/// Only stable declaration identities are retained, not duplicate rendered rows,
/// provenance or evidence. Depth-zero seeds are member rows too.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoundedCallAnswer {
    pub(crate) traversal: String,
    pub(crate) members: Vec<BoundedMemberRow>,
    pub(crate) bound: usize,
    pub(crate) frontier: Vec<(UnitRowKey, UnitRowKey)>,
    pub(crate) undecided_frontier: Vec<UnitRowKey>,
    pub(crate) membership_unknown: bool,
    #[serde(default)]
    pub(crate) budget_stopped: bool,
}

impl BoundedCallAnswer {
    pub(crate) fn status(&self) -> DepthBoundStatus {
        if self.membership_unknown {
            DepthBoundStatus::Unknown
        } else if !self.frontier.is_empty() {
            DepthBoundStatus::Reached
        } else if !self.undecided_frontier.is_empty() || self.budget_stopped {
            DepthBoundStatus::Unknown
        } else {
            DepthBoundStatus::NotReached
        }
    }
}

pub(super) fn bounded_member_row(unit: &CodeUnit) -> UnitRowKey {
    // Traversal membership is declaration identity, not a rendered source range.
    key("bounded_declaration").declaration(unit).finish()
}

pub(super) fn authored_plan_nodes(plan: &CodeQueryPlan) -> Vec<(&CodeQueryPlan, Vec<usize>)> {
    let mut pending = vec![(plan, Vec::new())];
    let mut nodes = Vec::new();
    while let Some((node, path)) = pending.pop() {
        for (index, child) in node.source.child_plans().into_iter().enumerate() {
            let mut child_path = path.clone();
            child_path.push(index);
            pending.push((child, child_path));
        }
        nodes.push((node, path));
    }
    nodes
}

fn authored_subplan_path(root: &CodeQueryPlan, subplan: &CodeQueryPlan) -> Vec<usize> {
    authored_plan_nodes(root)
        .into_iter()
        .find(|(node, _)| std::ptr::eq(*node, subplan))
        .expect("the cut operand is an authored subtree")
        .1
}

fn unknown_depth_answers_at(plan: &CodeQueryPlan, base_path: &[usize]) -> Vec<BoundedCallAnswer> {
    let mut answers = Vec::new();
    for (node, path) in authored_plan_nodes(plan) {
        let mut absolute = base_path.to_vec();
        absolute.extend(path);
        for (position, step) in node.steps.iter().enumerate() {
            if let QueryStep::Callers(filter) | QueryStep::Callees(filter) = step {
                answers.push(BoundedCallAnswer {
                    traversal: traversal_key(node, position, &absolute),
                    members: Vec::new(),
                    frontier: Vec::new(),
                    bound: filter.depth.get(),
                    undecided_frontier: Vec::new(),
                    membership_unknown: true,
                    budget_stopped: false,
                });
            }
        }
    }
    answers
}

fn unknown_depth_answers(plan: &CodeQueryPlan) -> Vec<BoundedCallAnswer> {
    unknown_depth_answers_at(plan, &[])
}

fn rebased_traversal_keys(plan: &CodeQueryPlan, base_path: &[usize]) -> HashMap<String, String> {
    let mut rewrites = HashMap::default();
    for (node, path) in authored_plan_nodes(plan) {
        let mut absolute = base_path.to_vec();
        absolute.extend_from_slice(&path);
        for (position, step) in node.steps.iter().enumerate() {
            if matches!(step, QueryStep::Callers(_) | QueryStep::Callees(_)) {
                rewrites.insert(
                    traversal_key(node, position, &path),
                    traversal_key(node, position, &absolute),
                );
            }
        }
    }
    rewrites
}

/// Reconcile each authored traversal independently. A locally depth-N witness
/// survives exactly when its target is outside the union of the bounded answers.
/// If another seed reaches the source earlier, it must already include that
/// target within N, so no second merged-depth test is necessary.
fn reconciled_depth_status(answers: &[BoundedCallAnswer]) -> Option<DepthBoundStatus> {
    let mut groups: HashMap<&str, Vec<&BoundedCallAnswer>> = HashMap::default();
    for answer in answers {
        groups.entry(&answer.traversal).or_default().push(answer);
    }
    let mut status = None;
    for group in groups.values() {
        let mut members: HashMap<&UnitRowKey, usize> = HashMap::default();
        for member in group.iter().flat_map(|answer| &answer.members) {
            members
                .entry(&member.identity)
                .and_modify(|depth| *depth = (*depth).min(member.depth))
                .or_insert(member.depth);
        }
        let observed = if group.iter().any(|answer| answer.membership_unknown) {
            DepthBoundStatus::Unknown
        } else if group
            .iter()
            .flat_map(|answer| &answer.frontier)
            .any(|(_, target)| !members.contains_key(target))
        {
            DepthBoundStatus::Reached
        // Uncertainty needs a frontier at the merged depth. Witnesses above
        // deliberately use only target membership, never a source-depth test.
        } else if group.iter().any(|answer| {
            answer.budget_stopped
                || answer.undecided_frontier.iter().any(|source| {
                    members
                        .get(source)
                        .is_none_or(|depth| *depth >= answer.bound)
                })
        }) {
            DepthBoundStatus::Unknown
        } else {
            DepthBoundStatus::NotReached
        };
        join_depth_bound_status(&mut status, Some(observed));
    }
    status
}

/// Native operand rows from one seed at a root intersect cut. The rows remain
/// typed until the physical set operator and its suffix consume them.
#[derive(Debug)]
pub struct IntersectPrefixProduct {
    seed: ProjectFile,
    pub(super) operands: Vec<Vec<PipelineRow>>,
    operand_step_outputs: Vec<Vec<u64>>,
    pub work: CodeQueryExecutionWork,
    pub budgeted_work: CodeQueryBudgetedWork,
    pub completion: CodeQueryCompletion,
    pub depth_bound_status: Option<DepthBoundStatus>,
    pub depth_answers: Vec<BoundedCallAnswer>,
    pub diagnostics: Vec<CodeQueryDiagnostic>,
    pub reads: Vec<crate::analyzer::read_ledger::ReadKey>,
    pub reads_closed: bool,
}

impl IntersectPrefixProduct {
    /// Check the complete stored prefix against this run's residual physical
    /// grant, including summed shared lanes and its whole-plan step slots.
    pub fn reached_limit(
        &self,
        query: &CodeQuery,
        limits: &CodeQueryExecutionLimits,
    ) -> Option<MergedLimit> {
        let PlanPartitioning::Prefix { cut } = PlanPartitioning::classify_for_prefix(&query.plan)
        else {
            return Some(MergedLimit::UnitTruncated);
        };
        let whole = select_physical_plan(query, UnionExecutionStrategy::Sequential, 1, 0)
            .expect("eligible intersect has a physical plan");
        let mut cut_node = whole.node(whole.root()).dependencies()[0];
        while matches!(
            whole.node(cut_node).operator(),
            PhysicalQueryOperator::PipelineStep
        ) {
            cut_node = whole.node(cut_node).dependencies()[0];
        }
        let mut steps = vec![0_u64; unit_step_output_caps(query).len()];
        for (branch, operand) in cut.operands(&query.plan).iter().enumerate() {
            let branch_query = CodeQuery {
                plan: operand.clone(),
                limit: usize::MAX,
                ..query.clone()
            };
            let branch_plan =
                select_physical_plan(&branch_query, UnionExecutionStrategy::Sequential, 1, 0)
                    .expect("eligible operand has a physical plan");
            let mut pending = vec![(
                branch_plan.node(branch_plan.root()).dependencies()[0],
                whole.node(cut_node).dependencies()[branch],
            )];
            while let Some((source, target)) = pending.pop() {
                steps[target.index()] = steps[target.index()]
                    .saturating_add(self.operand_step_outputs[branch][source.index()]);
                pending.extend(
                    branch_plan
                        .node(source)
                        .dependencies()
                        .iter()
                        .copied()
                        .zip(whole.node(target).dependencies().iter().copied()),
                );
            }
        }
        let mut budgeted = self.budgeted_work.clone();
        budgeted.step_outputs = steps;
        reached_limit_counters(
            &self.work,
            &budgeted,
            self.completion != CodeQueryCompletion::Complete,
            0,
            1,
            &unit_step_output_caps(query),
            limits,
            limits.max_pipeline_rows,
            usize::MAX,
        )
    }
    /// Require the exact blob-pinned receipt before hydrating any value named
    /// by a file. A trace may name a caller file other than the seed.
    fn require_file_receipt(
        &self,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
    ) -> Result<(), CorruptIntersectProduct> {
        let provider = analyzer
            .structural_fact_providers()
            .into_iter()
            .find(|provider| provider.structural_language() == file.language())
            .ok_or(CorruptIntersectProduct)?;
        let read = provider
            .structural_file_read_key(file)
            .ok_or(CorruptIntersectProduct)?;
        if !self.reads.contains(&read) {
            return Err(CorruptIntersectProduct);
        }
        analyzer.record_read(read);
        Ok(())
    }

    fn named_file(&self, rel_path: &str) -> Result<ProjectFile, CorruptIntersectProduct> {
        let file = self.seed.with_rel_path(Path::new(rel_path));
        (rel_path_string(&file) == rel_path)
            .then_some(file)
            .ok_or(CorruptIntersectProduct)
    }

    fn hydrate_declaration(
        &self,
        analyzer: &dyn IAnalyzer,
        rel_path: &str,
        declaration_id: &str,
        start_byte: usize,
        end_byte: usize,
        structural_kind: Option<NormalizedKind>,
    ) -> Result<DeclarationValue, CorruptIntersectProduct> {
        let file = self.named_file(rel_path)?;
        self.require_file_receipt(analyzer, &file)?;
        let mut matches = analyzer
            .get_declarations(&file)
            .into_iter()
            .flat_map(|unit| {
                analyzer
                    .ranges_of(&unit)
                    .into_iter()
                    .map(move |range| (unit.clone(), range))
            })
            .filter(|(unit, range)| {
                unit.declaration_id().to_string() == declaration_id
                    && range.start_byte == start_byte
                    && range.end_byte == end_byte
            });
        let (unit, range) = matches.next().ok_or(CorruptIntersectProduct)?;
        if matches.next().is_some() {
            return Err(CorruptIntersectProduct);
        }
        Ok(DeclarationValue {
            unit,
            range,
            structural_kind,
        })
    }

    fn hydrate_occurrence(
        &self,
        analyzer: &dyn IAnalyzer,
        rel_path: &str,
        node: u32,
        role: &str,
    ) -> Result<OccurrenceValue, CorruptIntersectProduct> {
        let file = self.named_file(rel_path)?;
        self.require_file_receipt(analyzer, &file)?;
        let role = OccurrenceRole::from_label(role).ok_or(CorruptIntersectProduct)?;
        let mut cache =
            OccurrenceTraversalCache::with_options(OccurrenceDerivationOptions::IDENTITY_ONLY);
        let result = cache
            .rows_for_file(
                analyzer,
                &file,
                &OccurrenceFilter {
                    roles: vec![role],
                    ..OccurrenceFilter::default()
                },
                None,
            )
            .ok_or(CorruptIntersectProduct)?;
        let mut matches = result
            .rows
            .iter()
            .filter(|row| row.node == node && row.role == role);
        let row = matches.next().ok_or(CorruptIntersectProduct)?;
        if matches.next().is_some() {
            return Err(CorruptIntersectProduct);
        }
        Ok(OccurrenceValue {
            row: Arc::new(row.clone()),
        })
    }

    fn hydrate_trace_value(
        &self,
        analyzer: &dyn IAnalyzer,
        workspace: Option<&WorkspaceAnalyzer>,
        limits: CodeQueryExecutionLimits,
        identity: IntersectTraceValueIdentity,
    ) -> Result<PipelineTraceValue, CorruptIntersectProduct> {
        match identity {
            IntersectTraceValueIdentity::StructuralMatch { rel_path, node } => {
                let file = self.named_file(&rel_path)?;
                self.require_file_receipt(analyzer, &file)?;
                let provider = analyzer
                    .structural_fact_providers()
                    .into_iter()
                    .find(|provider| provider.structural_language() == file.language())
                    .ok_or(CorruptIntersectProduct)?;
                let facts = provider
                    .structural_facts(&file)
                    .ok_or(CorruptIntersectProduct)?;
                facts
                    .nodes()
                    .get(node as usize)
                    .ok_or(CorruptIntersectProduct)?;
                Ok(PipelineTraceValue::StructuralMatch(Arc::new(SeedMatch {
                    language: file.language(),
                    file,
                    facts,
                    fact_match: FactMatch {
                        node,
                        captures: Arc::from([]),
                        reported_range: None,
                        heuristic: None,
                    },
                    python_import: None,
                })))
            }
            IntersectTraceValueIdentity::Declaration {
                rel_path,
                declaration_id,
                start_byte,
                end_byte,
                structural_kind,
            } => Ok(PipelineTraceValue::Declaration(self.hydrate_declaration(
                analyzer,
                &rel_path,
                &declaration_id,
                start_byte,
                end_byte,
                structural_kind,
            )?)),
            IntersectTraceValueIdentity::Occurrence {
                rel_path,
                node,
                role,
                identity_only: true,
            } => Ok(PipelineTraceValue::Occurrence(
                self.hydrate_occurrence(analyzer, &rel_path, node, &role)?,
            )),
            IntersectTraceValueIdentity::Occurrence { .. } => Err(CorruptIntersectProduct),
            IntersectTraceValueIdentity::Binding {
                rel_path,
                index,
                id,
                shadowed,
                reached_from,
            } => {
                let file = self.named_file(&rel_path)?;
                self.require_file_receipt(analyzer, &file)?;
                let result = Arc::new(super::super::lexical_environment::environment_for_file(
                    analyzer, &file,
                ));
                result.bindings.get(index).ok_or(CorruptIntersectProduct)?;
                let value = BindingValue {
                    file,
                    result,
                    index,
                    shadowed,
                    reached_from,
                };
                if value.id() != id {
                    return Err(CorruptIntersectProduct);
                }
                Ok(PipelineTraceValue::Binding(value))
            }
            IntersectTraceValueIdentity::DispatchTarget {
                rel_path,
                site_id,
                root_id,
                start_byte,
                end_byte,
                ordinal,
                target_id,
            } => {
                let workspace = workspace.ok_or(CorruptIntersectProduct)?;
                let file = self.named_file(&rel_path)?;
                self.require_file_receipt(analyzer, &file)?;
                let provider = analyzer
                    .structural_fact_providers()
                    .into_iter()
                    .find(|provider| provider.structural_language() == file.language())
                    .ok_or(CorruptIntersectProduct)?;
                let facts = provider
                    .structural_facts(&file)
                    .ok_or(CorruptIntersectProduct)?;
                if start_byte >= end_byte || end_byte > facts.source().len() {
                    return Err(CorruptIntersectProduct);
                }
                let range = Range {
                    start_byte,
                    end_byte,
                    start_line: facts.line_column_of_byte(start_byte).0,
                    end_line: facts.line_column_of_byte(end_byte).0,
                };
                let (computed_id, site_ast_id) =
                    super::dispatch::dispatch_site_identity(analyzer, &file, range, Some(&facts))
                        .ok_or(CorruptIntersectProduct)?;
                if computed_id != site_id {
                    return Err(CorruptIntersectProduct);
                }
                let mut semantic = SemanticQueryContext::new_with_analysis(
                    workspace,
                    None,
                    limits.semantic,
                    limits.typestate,
                    limits.value_flow,
                    limits.taint,
                    0,
                    None,
                    analyzer.active_semantic_model_snapshot(),
                    None,
                    None,
                    super::type_flow::CodeQueryRootAllotment::from_execution_limits(&limits),
                );
                let (answer, incompleteness) = semantic.dispatch_at_source_with_cause(&file, range);
                if incompleteness.execution_cause().is_some() {
                    return Err(CorruptIntersectProduct);
                }
                let answer = Arc::new(answer);
                if answer
                    .arms
                    .get(ordinal)
                    .is_none_or(|arm| arm.target_id != target_id)
                {
                    return Err(CorruptIntersectProduct);
                }
                Ok(PipelineTraceValue::DispatchTarget(Box::new(
                    DispatchTargetValue {
                        site: DispatchSiteValue {
                            file,
                            range,
                            site_id,
                            site_ast_id,
                            answer,
                        },
                        root_id,
                        ordinal,
                    },
                )))
            }
        }
    }

    fn hydrate_call_site(
        &self,
        analyzer: &dyn IAnalyzer,
        identity: IntersectTraceViaIdentity,
    ) -> Result<PipelineVia, CorruptIntersectProduct> {
        let IntersectTraceViaIdentity::CallSite {
            rel_path,
            site_id,
            start_byte,
            end_byte,
            caller_id,
            callee_rel_path,
            callee_id,
        } = identity;
        let file = self.named_file(&rel_path)?;
        let callee_file = self.named_file(&callee_rel_path)?;
        self.require_file_receipt(analyzer, &file)?;
        self.require_file_receipt(analyzer, &callee_file)?;
        let callers: Vec<_> = analyzer
            .get_declarations(&file)
            .into_iter()
            .filter(|unit| unit.declaration_id().to_string() == caller_id)
            .collect();
        let [caller] = callers.as_slice() else {
            return Err(CorruptIntersectProduct);
        };
        let scope = crate::analyzer::AnalyzerQueryScope::new(analyzer);
        let result = CallRelationService::outgoing(analyzer, scope.token(), caller, usize::MAX);
        if result.truncated || result.cancelled {
            return Err(CorruptIntersectProduct);
        }
        let mut matches = result.sites.into_iter().filter(|site| {
            site.file == file
                && site.range.start_byte == start_byte
                && site.range.end_byte == end_byte
                && site.caller.declaration_id().to_string() == caller_id
                && site.callee.source() == &callee_file
                && site.callee.declaration_id().to_string() == callee_id
        });
        let site = matches.next().ok_or(CorruptIntersectProduct)?;
        if matches.next().is_some() {
            return Err(CorruptIntersectProduct);
        }
        let value = CallSiteValue::new(
            site,
            CallBindingStatus::Unavailable,
            None,
            CallSiteIdentityFacts::default(),
        );
        if value.2 != site_id {
            return Err(CorruptIntersectProduct);
        }
        Ok(PipelineVia::CallSite(Box::new(value)))
    }

    /// Number of native rows in each authored operand.
    pub fn operand_row_counts(&self) -> impl Iterator<Item = usize> + '_ {
        self.operands.iter().map(Vec::len)
    }

    /// The persisted product envelope. The read keys live in the unit's
    /// relational read ledger; the digest binds this JSONB value to that
    /// receipt without copying a second serialized key vocabulary into it.
    pub fn encode_product_json(
        &self,
        plan: &crate::query::CodeQueryPlan,
    ) -> Result<serde_json::Value, CorruptIntersectProduct> {
        let crate::query::PlanPartitioning::Prefix { cut } =
            PlanPartitioning::classify_for_prefix(plan)
        else {
            return Err(CorruptIntersectProduct);
        };
        if self.operands.len() != cut.operands(plan).len() {
            return Err(CorruptIntersectProduct);
        }
        let envelope = IntersectPrefixEnvelope {
            seed: rel_path_string(&self.seed),
            operator: cut.operator(plan).label().to_string(),
            operands: self.encode_rows_json(plan)?,
            operand_step_outputs: self.operand_step_outputs.clone(),
            work: self.work,
            budgeted_work: self.budgeted_work.clone(),
            completion: self.completion.clone(),
            depth_bound_status: self.depth_bound_status,
            depth_answers: self.depth_answers.clone(),
            diagnostics: self.diagnostics.clone(),
            diagnostic_causes: self
                .diagnostics
                .iter()
                .map(|diagnostic| diagnostic.incompleteness.into())
                .collect(),
            reads_closed: self.reads_closed,
            read_set_digest: crate::analyzer::read_ledger::read_set_digest(&self.reads).to_string(),
        };
        serde_json::to_value(envelope).map_err(|_| CorruptIntersectProduct)
    }

    /// Load one product after the policy reader has verified its read set.
    /// Any mismatch is a cache miss, including an invalid row identity.
    pub fn decode_product_json(
        analyzer: &dyn IAnalyzer,
        plan: &crate::query::CodeQueryPlan,
        seed: ProjectFile,
        reads: Vec<crate::analyzer::read_ledger::ReadKey>,
        encoded: serde_json::Value,
    ) -> Result<Self, CorruptIntersectProduct> {
        Self::decode_product_json_with_workspace(analyzer, None, plan, seed, reads, encoded)
    }

    /// Hydrate semantic trace values using this request's workspace oracle.
    pub fn decode_product_json_with_workspace(
        analyzer: &dyn IAnalyzer,
        workspace: Option<&WorkspaceAnalyzer>,
        plan: &crate::query::CodeQueryPlan,
        seed: ProjectFile,
        reads: Vec<crate::analyzer::read_ledger::ReadKey>,
        encoded: serde_json::Value,
    ) -> Result<Self, CorruptIntersectProduct> {
        Self::decode_product_json_with_limits(
            analyzer,
            workspace,
            CodeQueryExecutionLimits::default(),
            plan,
            seed,
            reads,
            encoded,
        )
    }

    /// Decode with the originating policy's limits so a dispatch rederivation
    /// uses the same semantic allowance as the prefix that published it.
    #[allow(clippy::too_many_arguments)]
    pub fn decode_product_json_with_limits(
        analyzer: &dyn IAnalyzer,
        workspace: Option<&WorkspaceAnalyzer>,
        limits: CodeQueryExecutionLimits,
        plan: &crate::query::CodeQueryPlan,
        seed: ProjectFile,
        reads: Vec<crate::analyzer::read_ledger::ReadKey>,
        encoded: serde_json::Value,
    ) -> Result<Self, CorruptIntersectProduct> {
        let envelope: IntersectPrefixEnvelope =
            serde_json::from_value(encoded).map_err(|_| CorruptIntersectProduct)?;
        let crate::query::PlanPartitioning::Prefix { cut } =
            PlanPartitioning::classify_for_prefix(plan)
        else {
            return Err(CorruptIntersectProduct);
        };
        if envelope.operator != cut.operator(plan).label()
            || envelope.seed != rel_path_string(&seed)
            || !envelope.reads_closed
            || reads.is_empty()
            || envelope.read_set_digest
                != crate::analyzer::read_ledger::read_set_digest(&reads).to_string()
            || envelope.completion != CodeQueryCompletion::Complete
        {
            return Err(CorruptIntersectProduct);
        }
        let rows = envelope
            .operands
            .as_array()
            .ok_or(CorruptIntersectProduct)?;
        if rows.len() != envelope.operand_step_outputs.len()
            || rows.len() != cut.operands(plan).len()
        {
            return Err(CorruptIntersectProduct);
        }
        for (operand, slots) in cut
            .operands(plan)
            .iter()
            .zip(&envelope.operand_step_outputs)
        {
            let operand_query = CodeQuery {
                schema_version: 1,
                plan: operand.clone(),
                limit: usize::MAX,
                result_detail: crate::query::CodeQueryResultDetail::Compact,
                execution_mode: Default::default(),
            };
            let physical =
                select_physical_plan(&operand_query, UnionExecutionStrategy::Sequential, 1, 0)
                    .map_err(|_| CorruptIntersectProduct)?;
            if slots.len() != physical.step_output_caps().len() {
                return Err(CorruptIntersectProduct);
            }
        }
        if envelope.diagnostics.len() != envelope.diagnostic_causes.len() {
            return Err(CorruptIntersectProduct);
        }
        let mut diagnostics = envelope.diagnostics;
        for (diagnostic, cause) in diagnostics.iter_mut().zip(envelope.diagnostic_causes) {
            diagnostic.incompleteness = cause.into();
        }
        let mut product = Self {
            seed,
            operands: vec![Vec::new(); rows.len()],
            operand_step_outputs: envelope.operand_step_outputs,
            work: envelope.work,
            budgeted_work: envelope.budgeted_work,
            completion: envelope.completion,
            depth_bound_status: envelope.depth_bound_status,
            depth_answers: envelope.depth_answers,
            diagnostics,
            reads,
            reads_closed: true,
        };
        product.decode_rows_json_with_limits(
            analyzer,
            workspace,
            limits,
            plan,
            envelope.operands,
        )?;
        Ok(product)
    }

    /// SQL-readable identities for the admitted intersect operands.
    pub fn encode_rows_json(
        &self,
        plan: &crate::query::CodeQueryPlan,
    ) -> Result<serde_json::Value, CorruptIntersectProduct> {
        if !self.reads_closed || self.completion != CodeQueryCompletion::Complete {
            return Err(CorruptIntersectProduct);
        }
        let mut operands = Vec::with_capacity(self.operands.len());
        for rows in &self.operands {
            let mut encoded = Vec::with_capacity(rows.len());
            for row in rows {
                if row.provenance_truncated
                    || row.traces.is_empty()
                    || !row.row_projection.is_empty()
                    || row.traces.iter().any(|trace| {
                        trace.window_order.is_some()
                            || trace.seed.file != self.seed
                            || trace.seed.python_import.is_some()
                            || !trace.seed.fact_match.captures.is_empty()
                            || trace.seed.fact_match.reported_range.is_some()
                            || trace.seed.fact_match.heuristic.is_some()
                    })
                {
                    return Err(CorruptIntersectProduct);
                }
                let traces = row
                    .traces
                    .iter()
                    .map(|trace| {
                        Ok(IntersectTraceIdentity {
                            branch: trace.branch.clone(),
                            seed_rel_path: rel_path_string(&trace.seed.file),
                            seed_node: trace.seed.fact_match.node,
                            steps: encode_trace_steps(plan, trace)?,
                        })
                    })
                    .collect::<Result<Vec<_>, CorruptIntersectProduct>>()?;
                let identity = match &row.value {
                    PipelineValue::StructuralMatch(seed) => {
                        if seed.file != self.seed {
                            return Err(CorruptIntersectProduct);
                        }
                        let node = seed.facts.node(seed.fact_match.node);
                        IntersectRowIdentity::StructuralMatch {
                            rel_path: rel_path_string(&seed.file),
                            node: seed.fact_match.node,
                            kind: node.kind,
                            span: node.span(),
                            traces,
                        }
                    }
                    PipelineValue::Declaration(value) => IntersectRowIdentity::Declaration {
                        rel_path: rel_path_string(value.unit.source()),
                        declaration_id: value.declaration_id(),
                        start_byte: value.range.start_byte,
                        end_byte: value.range.end_byte,
                        structural_kind: value.structural_kind,
                        traces,
                    },
                    PipelineValue::Occurrence(value) => {
                        if !occurrence_is_identity_only(&value.row) {
                            return Err(CorruptIntersectProduct);
                        }
                        IntersectRowIdentity::Occurrence {
                            rel_path: rel_path_string(value.file()),
                            node: value.row.node,
                            role: value.row.role.label().to_owned(),
                            identity_only: true,
                            traces,
                        }
                    }
                    PipelineValue::Semantic(_)
                    | PipelineValue::File(_)
                    | PipelineValue::ReferenceSite(_)
                    | PipelineValue::CallSite(_)
                    | PipelineValue::ExpressionSite(_)
                    | PipelineValue::JsxAttributeValue(_)
                    | PipelineValue::ReceiverAnalysis(_)
                    | PipelineValue::MemberTargetAnalysis(_)
                    | PipelineValue::ReceiverOutcome(_)
                    | PipelineValue::ReceiverEvidence(_)
                    | PipelineValue::PointsToCandidate(_)
                    | PipelineValue::FieldWriteValue(_)
                    | PipelineValue::RuntimeKeyedReadValue(_)
                    | PipelineValue::CallShape(_)
                    | PipelineValue::CallArgumentGroup(_)
                    | PipelineValue::CallArgument(_)
                    | PipelineValue::CallBinding(_)
                    | PipelineValue::CallEffect(_)
                    | PipelineValue::CallResultContract(_)
                    | PipelineValue::CallResultObligation(_)
                    | PipelineValue::ResultSubjectUse(_)
                    | PipelineValue::ResultContractUse(_)
                    | PipelineValue::ResultContractFailureUse(_)
                    | PipelineValue::NilnessOperation(_)
                    | PipelineValue::SwitchCoverage(_)
                    | PipelineValue::AssignmentRelation(_)
                    | PipelineValue::ClassSetRow(_)
                    | PipelineValue::AbsentMemberFinding(_)
                    | PipelineValue::DetachedTaskTransfer(_)
                    | PipelineValue::ProcedureEffect(_)
                    | PipelineValue::CallableSignature(_)
                    | PipelineValue::LiteralOccurrence(_)
                    | PipelineValue::CallableMetrics(_)
                    | PipelineValue::SignatureParameter(_)
                    | PipelineValue::DecoratedParameter(_)
                    | PipelineValue::CallableApplicability(_)
                    | PipelineValue::OverloadSelection(_)
                    | PipelineValue::MemberSelection(_)
                    | PipelineValue::DispatchOutcome(_)
                    | PipelineValue::DispatchTarget(_)
                    | PipelineValue::MemberFamily(_)
                    | PipelineValue::MemberFamilyEdge(_)
                    | PipelineValue::PythonHierarchyFact(_)
                    | PipelineValue::LexicalScope(_)
                    | PipelineValue::Binding(_)
                    | PipelineValue::ResolutionCandidate(_)
                    | PipelineValue::CandidateHop(_)
                    | PipelineValue::GenerationSite(_)
                    | PipelineValue::Export(_)
                    | PipelineValue::DeclarationState(_)
                    | PipelineValue::ReferenceEdge(_)
                    | PipelineValue::StateEvent(_)
                    | PipelineValue::BindingInitializerCall(_)
                    | PipelineValue::FlowRelation(_)
                    | PipelineValue::ControlRelation(_)
                    | PipelineValue::BranchRelation(_)
                    | PipelineValue::LoopRelation(_)
                    | PipelineValue::CppExpression(_)
                    | PipelineValue::FailureHandlerState(_)
                    | PipelineValue::StatementReachability(_)
                    | PipelineValue::PendingCleanupFlow(_)
                    | PipelineValue::PythonRuleFact(_)
                    | PipelineValue::Guard(_)
                    | PipelineValue::SourceSet(_)
                    | PipelineValue::BuildTarget(_)
                    | PipelineValue::TopologyEdge(_)
                    | PipelineValue::BuildConfiguration(_)
                    | PipelineValue::RewritePath(_)
                    | PipelineValue::QualifiedPath(_)
                    | PipelineValue::PathSegment(_)
                    | PipelineValue::ConfigurationFact(_)
                    | PipelineValue::CrossDomain(_)
                    | PipelineValue::DependencyEvidence(_) => return Err(CorruptIntersectProduct),
                };
                encoded.push(identity);
            }
            operands.push(encoded);
        }
        serde_json::to_value(operands).map_err(|_| CorruptIntersectProduct)
    }

    /// Hydrate a persisted product against the exact seed blob. A malformed
    /// or stale row is a cache miss; callers recompute its prefix.
    pub fn decode_rows_json(
        &mut self,
        analyzer: &dyn IAnalyzer,
        plan: &crate::query::CodeQueryPlan,
        encoded: serde_json::Value,
    ) -> Result<(), CorruptIntersectProduct> {
        self.decode_rows_json_with_workspace(analyzer, None, plan, encoded)
    }

    pub fn decode_rows_json_with_workspace(
        &mut self,
        analyzer: &dyn IAnalyzer,
        workspace: Option<&WorkspaceAnalyzer>,
        plan: &crate::query::CodeQueryPlan,
        encoded: serde_json::Value,
    ) -> Result<(), CorruptIntersectProduct> {
        self.decode_rows_json_with_limits(
            analyzer,
            workspace,
            CodeQueryExecutionLimits::default(),
            plan,
            encoded,
        )
    }

    pub fn decode_rows_json_with_limits(
        &mut self,
        analyzer: &dyn IAnalyzer,
        workspace: Option<&WorkspaceAnalyzer>,
        limits: CodeQueryExecutionLimits,
        plan: &crate::query::CodeQueryPlan,
        encoded: serde_json::Value,
    ) -> Result<(), CorruptIntersectProduct> {
        let operands: Vec<Vec<IntersectRowIdentity>> =
            serde_json::from_value(encoded).map_err(|_| CorruptIntersectProduct)?;
        if operands.len() != self.operands.len() {
            return Err(CorruptIntersectProduct);
        }
        let provider = analyzer
            .structural_fact_providers()
            .into_iter()
            .find(|provider| provider.structural_language() == self.seed.language())
            .ok_or(CorruptIntersectProduct)?;
        self.require_file_receipt(analyzer, &self.seed)?;
        let facts = provider
            .structural_facts(&self.seed)
            .ok_or(CorruptIntersectProduct)?;
        let mut hydrated = Vec::with_capacity(operands.len());
        for (branch, rows) in operands.into_iter().enumerate() {
            let mut output = Vec::with_capacity(rows.len());
            for row in rows {
                let (value, traces) = match row {
                    IntersectRowIdentity::StructuralMatch {
                        rel_path,
                        node: node_id,
                        kind,
                        span,
                        traces,
                    } => {
                        let node = facts
                            .nodes()
                            .get(node_id as usize)
                            .ok_or(CorruptIntersectProduct)?;
                        if rel_path != rel_path_string(&self.seed)
                            || kind != node.kind
                            || span != node.span()
                        {
                            return Err(CorruptIntersectProduct);
                        }
                        let seed = Arc::new(SeedMatch {
                            language: self.seed.language(),
                            file: self.seed.clone(),
                            facts: Arc::clone(&facts),
                            fact_match: FactMatch {
                                node: node_id,
                                captures: Arc::from([]),
                                reported_range: None,
                                heuristic: None,
                            },
                            python_import: None,
                        });
                        (PipelineValue::StructuralMatch(seed), traces)
                    }
                    IntersectRowIdentity::Declaration {
                        rel_path,
                        declaration_id,
                        start_byte,
                        end_byte,
                        structural_kind,
                        traces,
                    } => (
                        PipelineValue::Declaration(self.hydrate_declaration(
                            analyzer,
                            &rel_path,
                            &declaration_id,
                            start_byte,
                            end_byte,
                            structural_kind,
                        )?),
                        traces,
                    ),
                    IntersectRowIdentity::Occurrence {
                        rel_path,
                        node,
                        role,
                        identity_only: true,
                        traces,
                    } => (
                        PipelineValue::Occurrence(
                            self.hydrate_occurrence(analyzer, &rel_path, node, &role)?,
                        ),
                        traces,
                    ),
                    IntersectRowIdentity::Occurrence { .. } => return Err(CorruptIntersectProduct),
                };
                if traces.is_empty()
                    || traces.iter().any(|trace| {
                        trace.branch.first() != Some(&branch)
                            || trace.seed_rel_path != rel_path_string(&self.seed)
                            || trace.steps.iter().any(|step| {
                                !trace.branch.starts_with(&step.source_path)
                                    || resolve_intersect_step_slot(
                                        plan,
                                        &step.source_path,
                                        step.index,
                                    )
                                    .is_none()
                            })
                    })
                {
                    return Err(CorruptIntersectProduct);
                }
                output.push(PipelineRow {
                    value,
                    traces: traces
                        .into_iter()
                        .map(|trace| {
                            facts
                                .nodes()
                                .get(trace.seed_node as usize)
                                .ok_or(CorruptIntersectProduct)?;
                            let steps = trace
                                .steps
                                .into_iter()
                                .map(|step| {
                                    let op = resolve_intersect_step_slot(
                                        plan,
                                        &step.source_path,
                                        step.index,
                                    )
                                    .ok_or(CorruptIntersectProduct)?
                                    .clone();
                                    let value = self.hydrate_trace_value(
                                        analyzer, workspace, limits, step.value,
                                    )?;
                                    let via = match step.via {
                                        None => None,
                                        Some(identity) => {
                                            Some(self.hydrate_call_site(analyzer, identity)?)
                                        }
                                    };
                                    Ok(PipelineTraceStep { op, value, via })
                                })
                                .collect::<Result<Vec<_>, CorruptIntersectProduct>>()?;
                            Ok(PipelineTrace {
                                window_order: None,
                                branch: trace.branch,
                                seed: Arc::new(SeedMatch {
                                    language: self.seed.language(),
                                    file: self.seed.clone(),
                                    facts: Arc::clone(&facts),
                                    fact_match: FactMatch {
                                        node: trace.seed_node,
                                        captures: Arc::from([]),
                                        reported_range: None,
                                        heuristic: None,
                                    },
                                    python_import: None,
                                }),
                                steps,
                            })
                        })
                        .collect::<Result<Vec<_>, CorruptIntersectProduct>>()?,
                    provenance_truncated: false,
                    row_projection: Vec::new(),
                });
            }
            hydrated.push(output);
        }
        self.operands = hydrated;
        Ok(())
    }
}

fn occurrence_is_identity_only(row: &OccurrenceRow) -> bool {
    row.resolution_status.is_none()
        && row.candidates.is_none()
        && matches!(
            row.target,
            OccurrenceTarget::None | OccurrenceTarget::NotDerived
        )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CorruptIntersectProduct;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IntersectPrefixEnvelope {
    seed: String,
    operator: String,
    operands: serde_json::Value,
    operand_step_outputs: Vec<Vec<u64>>,
    work: CodeQueryExecutionWork,
    budgeted_work: CodeQueryBudgetedWork,
    completion: CodeQueryCompletion,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    depth_bound_status: Option<DepthBoundStatus>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    depth_answers: Vec<BoundedCallAnswer>,
    diagnostics: Vec<CodeQueryDiagnostic>,
    diagnostic_causes: Vec<IntersectDiagnosticCause>,
    reads_closed: bool,
    read_set_digest: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum IntersectDiagnosticCause {
    Content,
    Cancelled,
    Budget,
    Snapshot,
    Provider,
}

impl From<brokk_bifrost_rql::Incompleteness> for IntersectDiagnosticCause {
    fn from(value: brokk_bifrost_rql::Incompleteness) -> Self {
        match value {
            brokk_bifrost_rql::Incompleteness::Content => Self::Content,
            brokk_bifrost_rql::Incompleteness::Operational(DiagnosticExecutionCause::Cancelled) => {
                Self::Cancelled
            }
            brokk_bifrost_rql::Incompleteness::Operational(DiagnosticExecutionCause::Budget) => {
                Self::Budget
            }
            brokk_bifrost_rql::Incompleteness::Operational(DiagnosticExecutionCause::Snapshot) => {
                Self::Snapshot
            }
            brokk_bifrost_rql::Incompleteness::Operational(DiagnosticExecutionCause::Provider) => {
                Self::Provider
            }
        }
    }
}

impl From<IntersectDiagnosticCause> for brokk_bifrost_rql::Incompleteness {
    fn from(value: IntersectDiagnosticCause) -> Self {
        match value {
            IntersectDiagnosticCause::Content => Self::Content,
            IntersectDiagnosticCause::Cancelled => {
                Self::Operational(DiagnosticExecutionCause::Cancelled)
            }
            IntersectDiagnosticCause::Budget => Self::Operational(DiagnosticExecutionCause::Budget),
            IntersectDiagnosticCause::Snapshot => {
                Self::Operational(DiagnosticExecutionCause::Snapshot)
            }
            IntersectDiagnosticCause::Provider => {
                Self::Operational(DiagnosticExecutionCause::Provider)
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum IntersectRowIdentity {
    StructuralMatch {
        rel_path: String,
        node: u32,
        kind: NormalizedKind,
        span: Span,
        traces: Vec<IntersectTraceIdentity>,
    },
    Declaration {
        rel_path: String,
        declaration_id: String,
        start_byte: usize,
        end_byte: usize,
        structural_kind: Option<NormalizedKind>,
        traces: Vec<IntersectTraceIdentity>,
    },
    Occurrence {
        rel_path: String,
        node: u32,
        role: String,
        identity_only: bool,
        traces: Vec<IntersectTraceIdentity>,
    },
}

/// One provenance path stays separate from row identity: an intersect keeps
/// the first representative but may merge traces from several authored arms.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IntersectTraceIdentity {
    branch: Vec<usize>,
    seed_rel_path: String,
    seed_node: u32,
    steps: Vec<IntersectTraceStepIdentity>,
}

/// The step slot is the path from the query root through authored set branches
/// and the index within that plan's `steps`, not a serialized `QueryStep`.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IntersectTraceStepIdentity {
    source_path: Vec<usize>,
    index: usize,
    value: IntersectTraceValueIdentity,
    via: Option<IntersectTraceViaIdentity>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum IntersectTraceValueIdentity {
    StructuralMatch {
        rel_path: String,
        node: u32,
    },
    Declaration {
        rel_path: String,
        declaration_id: String,
        start_byte: usize,
        end_byte: usize,
        structural_kind: Option<NormalizedKind>,
    },
    DispatchTarget {
        rel_path: String,
        site_id: String,
        root_id: String,
        start_byte: usize,
        end_byte: usize,
        ordinal: usize,
        target_id: String,
    },
    Occurrence {
        rel_path: String,
        node: u32,
        role: String,
        identity_only: bool,
    },
    Binding {
        rel_path: String,
        index: usize,
        id: String,
        shadowed: bool,
        reached_from: Option<String>,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum IntersectTraceViaIdentity {
    CallSite {
        rel_path: String,
        site_id: String,
        start_byte: usize,
        end_byte: usize,
        caller_id: String,
        callee_rel_path: String,
        callee_id: String,
    },
}

fn encode_trace_steps(
    plan: &crate::query::CodeQueryPlan,
    trace: &PipelineTrace,
) -> Result<Vec<IntersectTraceStepIdentity>, CorruptIntersectProduct> {
    let mut slots = Vec::new();
    for depth in (1..=trace.branch.len()).rev() {
        let path = &trace.branch[..depth];
        let mut current = plan;
        for &branch in path {
            let crate::query::CodeQueryPlanSource::Set { branches, .. } = &current.source else {
                return Err(CorruptIntersectProduct);
            };
            current = branches.get(branch).ok_or(CorruptIntersectProduct)?;
        }
        slots.extend((0..current.steps.len()).map(|index| (path.to_vec(), index)));
    }
    let mut cursor = 0;
    let mut encoded = Vec::with_capacity(trace.steps.len());
    for step in &trace.steps {
        let found = slots[cursor..]
            .iter()
            .position(|(path, index)| {
                resolve_intersect_step_slot(plan, path, *index) == Some(&step.op)
            })
            .ok_or(CorruptIntersectProduct)?;
        cursor += found;
        let (source_path, index) = slots[cursor].clone();
        encoded.push(IntersectTraceStepIdentity {
            source_path,
            index,
            value: encode_trace_value(&step.value)?,
            via: step.via.as_ref().map(encode_trace_via).transpose()?,
        });
        if cursor + 1 < slots.len() && slots[cursor + 1].1 == index + 1 {
            cursor += 1;
        }
    }
    Ok(encoded)
}

fn encode_trace_value(
    value: &PipelineTraceValue,
) -> Result<IntersectTraceValueIdentity, CorruptIntersectProduct> {
    Ok(match value {
        PipelineTraceValue::StructuralMatch(seed)
            if seed.python_import.is_none()
                && seed.fact_match.captures.is_empty()
                && seed.fact_match.reported_range.is_none()
                && seed.fact_match.heuristic.is_none() =>
        {
            IntersectTraceValueIdentity::StructuralMatch {
                rel_path: rel_path_string(&seed.file),
                node: seed.fact_match.node,
            }
        }
        PipelineTraceValue::StructuralMatch(_) => return Err(CorruptIntersectProduct),
        PipelineTraceValue::Declaration(value) => IntersectTraceValueIdentity::Declaration {
            rel_path: rel_path_string(value.unit.source()),
            declaration_id: value.declaration_id(),
            start_byte: value.range.start_byte,
            end_byte: value.range.end_byte,
            structural_kind: value.structural_kind,
        },
        PipelineTraceValue::DispatchTarget(value) => IntersectTraceValueIdentity::DispatchTarget {
            rel_path: rel_path_string(value.file()),
            site_id: value.site.site_id.clone(),
            root_id: value.root_id.clone(),
            start_byte: value.site.range.start_byte,
            end_byte: value.site.range.end_byte,
            ordinal: value.ordinal,
            target_id: value.arm().target_id.clone(),
        },
        PipelineTraceValue::Occurrence(value) => {
            if !occurrence_is_identity_only(&value.row) {
                return Err(CorruptIntersectProduct);
            }
            IntersectTraceValueIdentity::Occurrence {
                rel_path: rel_path_string(value.file()),
                node: value.row.node,
                role: value.row.role.label().to_owned(),
                identity_only: true,
            }
        }
        PipelineTraceValue::Binding(value) => IntersectTraceValueIdentity::Binding {
            rel_path: rel_path_string(value.file()),
            index: value.index,
            id: value.id(),
            shadowed: value.shadowed,
            reached_from: value.reached_from.clone(),
        },
        PipelineTraceValue::Semantic(_)
        | PipelineTraceValue::File(_)
        | PipelineTraceValue::ReferenceSite(_)
        | PipelineTraceValue::CallSite(_)
        | PipelineTraceValue::ExpressionSite(_)
        | PipelineTraceValue::JsxAttributeValue(_)
        | PipelineTraceValue::ReceiverAnalysis(_)
        | PipelineTraceValue::MemberTargetAnalysis(_)
        | PipelineTraceValue::ReceiverOutcome(_)
        | PipelineTraceValue::ReceiverEvidence(_)
        | PipelineTraceValue::PointsToCandidate(_)
        | PipelineTraceValue::FieldWriteValue(_)
        | PipelineTraceValue::RuntimeKeyedReadValue(_)
        | PipelineTraceValue::CallShape(_)
        | PipelineTraceValue::CallArgumentGroup(_)
        | PipelineTraceValue::CallArgument(_)
        | PipelineTraceValue::CallBinding(_)
        | PipelineTraceValue::CallEffect(_)
        | PipelineTraceValue::CallResultContract(_)
        | PipelineTraceValue::CallResultObligation(_)
        | PipelineTraceValue::ResultSubjectUse(_)
        | PipelineTraceValue::ResultContractUse(_)
        | PipelineTraceValue::ResultContractFailureUse(_)
        | PipelineTraceValue::NilnessOperation(_)
        | PipelineTraceValue::SwitchCoverage(_)
        | PipelineTraceValue::AssignmentRelation(_)
        | PipelineTraceValue::ClassSetRow(_)
        | PipelineTraceValue::AbsentMemberFinding(_)
        | PipelineTraceValue::DetachedTaskTransfer(_)
        | PipelineTraceValue::ProcedureEffect(_)
        | PipelineTraceValue::CallableSignature(_)
        | PipelineTraceValue::LiteralOccurrence(_)
        | PipelineTraceValue::CallableMetrics(_)
        | PipelineTraceValue::SignatureParameter(_)
        | PipelineTraceValue::DecoratedParameter(_)
        | PipelineTraceValue::CallableApplicability(_)
        | PipelineTraceValue::OverloadSelection(_)
        | PipelineTraceValue::MemberSelection(_)
        | PipelineTraceValue::DispatchOutcome(_)
        | PipelineTraceValue::MemberFamily(_)
        | PipelineTraceValue::MemberFamilyEdge(_)
        | PipelineTraceValue::PythonHierarchyFact(_)
        | PipelineTraceValue::LexicalScope(_)
        | PipelineTraceValue::ResolutionCandidate(_)
        | PipelineTraceValue::CandidateHop(_)
        | PipelineTraceValue::GenerationSite(_)
        | PipelineTraceValue::Export(_)
        | PipelineTraceValue::DeclarationState(_)
        | PipelineTraceValue::ReferenceEdge(_)
        | PipelineTraceValue::StateEvent(_)
        | PipelineTraceValue::BindingInitializerCall(_)
        | PipelineTraceValue::FlowRelation(_)
        | PipelineTraceValue::ControlRelation(_)
        | PipelineTraceValue::BranchRelation(_)
        | PipelineTraceValue::LoopRelation(_)
        | PipelineTraceValue::CppExpression(_)
        | PipelineTraceValue::FailureHandlerState(_)
        | PipelineTraceValue::StatementReachability(_)
        | PipelineTraceValue::PendingCleanupFlow(_)
        | PipelineTraceValue::PythonRuleFact(_)
        | PipelineTraceValue::Guard(_)
        | PipelineTraceValue::SourceSet(_)
        | PipelineTraceValue::BuildTarget(_)
        | PipelineTraceValue::TopologyEdge(_)
        | PipelineTraceValue::BuildConfiguration(_)
        | PipelineTraceValue::RewritePath(_)
        | PipelineTraceValue::QualifiedPath(_)
        | PipelineTraceValue::PathSegment(_)
        | PipelineTraceValue::ConfigurationFact(_)
        | PipelineTraceValue::CrossDomain(_)
        | PipelineTraceValue::DependencyEvidence(_) => return Err(CorruptIntersectProduct),
    })
}

fn encode_trace_via(
    via: &PipelineVia,
) -> Result<IntersectTraceViaIdentity, CorruptIntersectProduct> {
    match via {
        PipelineVia::CallSite(value)
            if value.1 == CallBindingStatus::Unavailable
                && value.3.is_none()
                && value.4.is_none()
                && value.5 == CallSiteIdentityFacts::default() =>
        {
            Ok(IntersectTraceViaIdentity::CallSite {
                rel_path: rel_path_string(&value.0.file),
                site_id: value.2.clone(),
                start_byte: value.0.range.start_byte,
                end_byte: value.0.range.end_byte,
                caller_id: value.0.caller.declaration_id().to_string(),
                callee_rel_path: rel_path_string(value.0.callee.source()),
                callee_id: value.0.callee.declaration_id().to_string(),
            })
        }
        PipelineVia::CallSite(_) => Err(CorruptIntersectProduct),
        PipelineVia::ReferenceSite(_) => Err(CorruptIntersectProduct),
    }
}

fn resolve_intersect_step_slot<'a>(
    plan: &'a crate::query::CodeQueryPlan,
    source_path: &[usize],
    index: usize,
) -> Option<&'a crate::query::QueryStep> {
    let mut current = plan;
    for &branch in source_path {
        let crate::query::CodeQueryPlanSource::Set { branches, .. } = &current.source else {
            return None;
        };
        current = branches.get(branch)?;
    }
    current.steps.get(index)
}

// Every native variant must choose a persisted shape before admission.

/// A continuation either yields a complete detailed answer or withholds it.
/// An incomplete prefix never contributes a partial intersect membership.
#[derive(Debug)]
pub struct IntersectContinuationResult {
    pub detailed: Option<DetailedCodeQueryResult>,
    pub completion: CodeQueryCompletion,
    pub depth_bound_status: Option<DepthBoundStatus>,
    pub diagnostics: Vec<CodeQueryDiagnostic>,
    pub work: CodeQueryExecutionWork,
    pub budgeted_work: CodeQueryBudgetedWork,
}

impl IntersectContinuationResult {
    /// Project the once-executed suffix into the existing policy merge port.
    /// A withheld continuation carries no rows and remains incomplete.
    pub fn into_merged_rows(self, query: &CodeQuery) -> MergedUnitRows {
        match self.detailed {
            Some(detailed) => MergedUnitRows {
                items: detailed
                    .result
                    .results
                    .iter()
                    .map(UnitRowItem::project)
                    .collect(),
                evidence: detailed
                    .evidence
                    .iter()
                    .map(UnitRowEvidence::project)
                    .collect(),
                work: detailed.work,
                budgeted_work: detailed.budgeted_work,
                diagnostics: detailed.result.diagnostics,
                truncated: detailed.result.truncated,
                depth_bound_status: detailed.result.depth_bound_status,
                fair_share_divisor: 1,
                step_output_caps: unit_step_output_caps(query),
            },
            None => MergedUnitRows {
                items: Vec::new(),
                evidence: Vec::new(),
                work: self.work,
                budgeted_work: self.budgeted_work,
                diagnostics: self.diagnostics,
                truncated: true,
                depth_bound_status: self.depth_bound_status,
                fair_share_divisor: 1,
                step_output_caps: unit_step_output_caps(query),
            },
        }
    }
}

/// A caller-certified complete, empty operand-zero result for every seed.
/// Its rows have no set members; only physical work and diagnostics survive.
#[derive(Debug)]
pub struct CompleteEmptyFromOperandZero {
    pub probes: Vec<(
        UnitExecutionResult,
        Vec<crate::analyzer::read_ledger::ReadKey>,
    )>,
}

#[allow(clippy::too_many_arguments)]
pub fn continue_empty_operand_zero(
    analyzer: &dyn IAnalyzer,
    flow_state: impl Into<SemanticFlowResources> + Clone,
    workspace: Option<&WorkspaceAnalyzer>,
    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
    cancellation: Option<&CancellationToken>,
    seeds: &[ProjectFile],
    empty: CompleteEmptyFromOperandZero,
    scope: CodeQueryExecutionScope<'_>,
) -> IntersectContinuationResult {
    let PlanPartitioning::Prefix { cut } = PlanPartitioning::classify_for_prefix(&query.plan)
    else {
        panic!("empty operand continuation requires a prefix cut");
    };
    assert!(matches!(
        cut.operator(&query.plan),
        SetOperator::Intersect | SetOperator::Except
    ));
    assert_eq!(empty.probes.len(), seeds.len());
    let operands = cut.operands(&query.plan);
    let prefixes = seeds
        .iter()
        .cloned()
        .zip(empty.probes)
        .map(|(seed, (probe, reads))| {
            assert!(probe.rows.is_empty() && !probe.truncated);
            assert_eq!(probe.completion, CodeQueryCompletion::Complete);
            let mut slots = operands
                .iter()
                .map(|operand| {
                    let branch_query = CodeQuery {
                        plan: operand.clone(),
                        limit: usize::MAX,
                        ..query.clone()
                    };
                    let branch_plan = select_physical_plan(
                        &branch_query,
                        UnionExecutionStrategy::Sequential,
                        1,
                        0,
                    )
                    .expect("eligible operand has a physical plan");
                    vec![0; branch_plan.step_output_caps().len()]
                })
                .collect::<Vec<_>>();
            assert_eq!(slots[0].len(), probe.budgeted_work.step_outputs.len());
            slots[0] = probe.budgeted_work.step_outputs.clone();
            let mut status = probe.depth_bound_status;
            let mut depth_answers = probe.depth_answers;
            let rewrites = rebased_traversal_keys(
                &operands[0],
                &authored_subplan_path(&query.plan, &operands[0]),
            );
            for answer in &mut depth_answers {
                if let Some(key) = rewrites.get(&answer.traversal) {
                    answer.traversal = key.clone();
                }
            }
            for operand in operands[1..]
                .iter()
                .filter(|_| scope.computes_depth_bound_status())
            {
                depth_answers.extend(skipped_depth_answers_at(
                    operand,
                    &authored_subplan_path(&query.plan, operand),
                ));
            }
            if scope.computes_depth_bound_status()
                && operands[1..]
                    .iter()
                    .any(super::query_plan_has_bounded_call_step)
            {
                join_depth_bound_status(&mut status, Some(EXACT_SHORT_CIRCUIT_DEPTH_STATUS));
            }
            IntersectPrefixProduct {
                seed,
                operands: vec![Vec::new(); operands.len()],
                operand_step_outputs: slots,
                work: probe.work,
                budgeted_work: probe.budgeted_work,
                completion: probe.completion,
                depth_bound_status: status,
                depth_answers,
                diagnostics: probe.diagnostics,
                reads,
                reads_closed: true,
            }
        })
        .collect();
    continue_intersect_prefix(
        analyzer,
        flow_state,
        workspace,
        query,
        limits,
        cancellation,
        seeds,
        prefixes,
        scope,
    )
}

/// Merge every seed's native operands in whole-run order, evaluate the
/// intersect once, then let the physical executor run the ancestor suffix.
#[allow(clippy::too_many_arguments)]
pub fn continue_intersect_prefix(
    analyzer: &dyn IAnalyzer,
    flow_state: impl Into<SemanticFlowResources> + Clone,
    workspace: Option<&WorkspaceAnalyzer>,
    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
    cancellation: Option<&CancellationToken>,
    seeds: &[ProjectFile],
    prefixes: Vec<IntersectPrefixProduct>,
    scope: CodeQueryExecutionScope<'_>,
) -> IntersectContinuationResult {
    let crate::query::PlanPartitioning::Prefix { cut } =
        PlanPartitioning::classify_for_prefix(&query.plan)
    else {
        panic!("intersect continuation requires an eligible cut");
    };
    // Structural seeds use relative-path string order, which differs from
    // ProjectFile's component order for paths such as stats.rs/stats/client.rs.
    assert_eq!(seeds, plan_seed_files(&query.plan, seeds));
    assert!(seeds.windows(2).all(|pair| pair[0] != pair[1]));
    let mut diagnostics = Vec::new();
    let mut charged_work = CodeQueryExecutionWork::default();
    let mut charged_budgeted = CodeQueryBudgetedWork::default();
    let mut depth_bound_status = if seeds.is_empty() && scope.computes_depth_bound_status() {
        empty_partition_depth_status(&query.plan)
    } else {
        None
    };
    let mut depth_answers = prefixes
        .iter()
        .flat_map(|prefix| prefix.depth_answers.iter().cloned())
        .collect::<Vec<_>>();
    for prefix in &prefixes {
        if prefix.depth_answers.is_empty() {
            join_depth_bound_status(&mut depth_bound_status, prefix.depth_bound_status);
        }
        charged_work = charged_work.saturating_add(prefix.work);
        if charged_budgeted.step_outputs.is_empty() {
            charged_budgeted
                .step_outputs
                .resize(prefix.budgeted_work.step_outputs.len(), 0);
        }
        charged_budgeted = charged_budgeted.saturating_add(&prefix.budgeted_work);
    }
    join_depth_bound_status(
        &mut depth_bound_status,
        reconciled_depth_status(&depth_answers),
    );
    let complete = prefixes.len() == seeds.len()
        && prefixes.iter().zip(seeds).all(|(prefix, seed)| {
            prefix.seed == *seed
                && prefix.reads_closed
                && prefix.completion == CodeQueryCompletion::Complete
                && !prefix.reads.is_empty()
        });
    if !complete || cancellation.is_some_and(CancellationToken::is_cancelled) {
        // Withholding the continuation does not create a second cause when a
        // prefix already reported why its rows could not be enumerated. A
        // missing seed or read proof is a separate discovery failure.
        let missing_proof = prefixes.len() != seeds.len()
            || prefixes.iter().zip(seeds).any(|(prefix, seed)| {
                prefix.seed != *seed || !prefix.reads_closed || prefix.reads.is_empty()
            });
        let unreported_prefix = prefixes.iter().any(|prefix| {
            prefix.completion != CodeQueryCompletion::Complete
                && !prefix.diagnostics.iter().any(|diagnostic| {
                    matches!(
                        diagnostic.impact,
                        CodeQueryDiagnosticImpact::Incomplete | CodeQueryDiagnosticImpact::Invalid
                    )
                })
        });
        for prefix in prefixes {
            diagnostics.extend(prefix.diagnostics);
        }
        if missing_proof
            || unreported_prefix
            || cancellation.is_some_and(CancellationToken::is_cancelled)
        {
            diagnostics.push(CodeQueryDiagnostic::new(CodeQueryDiagnostic {
            incompleteness: brokk_bifrost_rql::Incompleteness::Content,
            code: CodeQueryDiagnosticCode::SemanticResultsOmitted,
            impact: CodeQueryDiagnosticImpact::Incomplete,
            branch: Vec::new(),
            language: "workspace",
            message:
                "intersect continuation withheld because a seed prefix or read proof is incomplete"
                    .to_string(),
            source: None,
            related: Vec::new(),
            exhausted_roots: Vec::new(),
            withheld_rows_path: None,
            }));
        }
        // Unseen seed members can cancel an available local witness. A
        // withheld global traversal has no complete membership proof.
        if scope.computes_depth_bound_status()
            && super::query_plan_has_bounded_call_step(&query.plan)
        {
            depth_bound_status = Some(DepthBoundStatus::Unknown);
        }
        return IntersectContinuationResult {
            detailed: None,
            completion: code_query_completion(true, &diagnostics),
            depth_bound_status,
            diagnostics,
            work: charged_work,
            budgeted_work: charged_budgeted,
        };
    }
    let mut merged_operands = Vec::new();
    for (branch, plan) in cut.operands(&query.plan).iter().enumerate() {
        let mut rows = Vec::new();
        if PlanPartitioning::classify(plan).is_seed_union() {
            let mut traces_by_key: HashMap<PipelineKey, Vec<(usize, usize, PipelineTrace)>> =
                HashMap::default();
            for (seed_index, prefix) in prefixes.iter().enumerate() {
                for (row_index, row) in prefix.operands[branch].iter().enumerate() {
                    traces_by_key.entry(row.value.key()).or_default().extend(
                        row.traces
                            .iter()
                            .cloned()
                            .map(|trace| (seed_index, row_index, trace)),
                    );
                    rows.push(row.clone());
                }
            }
            // Whole visits outer operand, nested branch, ProjectFile-sorted seed,
            // then scan row. Prefixes can already cap a row's traces at 16, so
            // a capped trace subset may differ even though rows and answers agree.
            rows.sort_by(|left, right| {
                left.traces
                    .first()
                    .map(|trace| &trace.branch[1..])
                    .cmp(&right.traces.first().map(|trace| &trace.branch[1..]))
            });
            rows = combine_set_rows(SetOperator::Union, vec![rows], false).0;
            for row in &mut rows {
                let mut traces = traces_by_key
                    .remove(&row.value.key())
                    .expect("merged union row has input traces");
                traces.sort_by(|left, right| {
                    left.2.branch[1..]
                        .cmp(&right.2.branch[1..])
                        .then_with(|| left.0.cmp(&right.0))
                        .then_with(|| left.1.cmp(&right.1))
                });
                row.provenance_truncated |= traces.len() > MAX_PROVENANCE_TRACES;
                row.traces = traces
                    .into_iter()
                    .take(MAX_PROVENANCE_TRACES)
                    .map(|(_, _, trace)| trace)
                    .collect();
            }
        } else {
            for prefix in &prefixes {
                rows.extend(prefix.operands[branch].iter().cloned());
            }
        }
        merged_operands.push(rows);
    }
    if scope.computes_depth_bound_status()
        && let Some(empty) = merged_operands.iter().position(Vec::is_empty)
        && empty_operand_ends_set(cut.operator(&query.plan), empty)
    {
        // Capture evaluates all operands. Only their merged, certified prefix
        // can reproduce the whole executor's exact short-circuit.
        replace_skipped_depth_answers(
            &mut depth_answers,
            &query.plan,
            &cut.operands(&query.plan)[empty + 1..],
        );
        depth_bound_status = reconciled_depth_status(&depth_answers);
        for prefix in &prefixes {
            if prefix.depth_answers.is_empty() {
                join_depth_bound_status(&mut depth_bound_status, prefix.depth_bound_status);
            }
        }
    }
    let mut row_keys = Vec::new();
    let mut prefix_work = CodeQueryExecutionWork::default();
    let mut prefix_budgeted = CodeQueryBudgetedWork::default();
    for prefix in &prefixes {
        prefix_work = prefix_work.saturating_add(prefix.work);
        prefix_budgeted.provenance_steps = prefix_budgeted
            .provenance_steps
            .saturating_add(prefix.budgeted_work.provenance_steps);
        prefix_budgeted.import_files_resolved = prefix_budgeted
            .import_files_resolved
            .saturating_add(prefix.budgeted_work.import_files_resolved);
        prefix_budgeted.import_edges_resolved = prefix_budgeted
            .import_edges_resolved
            .saturating_add(prefix.budgeted_work.import_edges_resolved);
    }
    let Some(suffix_limits) = remaining_unit_limits(limits, &prefix_work, &prefix_budgeted) else {
        push_budget_diagnostic(&mut diagnostics, &CodeQueryExecutionBudget::default());
        if scope.computes_depth_bound_status()
            && super::query_plan_has_bounded_call_step(&query.plan)
            && depth_bound_status != Some(DepthBoundStatus::Reached)
        {
            depth_bound_status = Some(DepthBoundStatus::Unknown);
        }
        return IntersectContinuationResult {
            detailed: None,
            completion: code_query_completion(true, &diagnostics),
            depth_bound_status,
            diagnostics,
            work: charged_work,
            budgeted_work: charged_budgeted,
        };
    };
    let mut detailed = execute_detailed_unit(
        analyzer,
        flow_state,
        workspace,
        query,
        suffix_limits,
        cancellation,
        scope.with_intersect_operands(merged_operands),
        &mut row_keys,
        None,
    );
    let whole_plan = select_physical_plan(query, UnionExecutionStrategy::Sequential, 1, 0)
        .expect("eligible intersect has a physical plan");
    let mut cut_node = whole_plan.node(whole_plan.root()).dependencies()[0];
    while matches!(
        whole_plan.node(cut_node).operator(),
        PhysicalQueryOperator::PipelineStep
    ) {
        cut_node = whole_plan.node(cut_node).dependencies()[0];
    }
    assert_eq!(
        whole_plan.node(cut_node).operator(),
        match cut.operator(&query.plan) {
            SetOperator::Union => PhysicalQueryOperator::SequentialUnion,
            SetOperator::Intersect => PhysicalQueryOperator::SequentialIntersection,
            SetOperator::Except => PhysicalQueryOperator::SequentialExcept,
        }
    );
    // The injected cut output is charged while rendering the continuation so
    // its retained rows have budget evidence. The ordinary set operator does
    // not add that charge to published work.
    detailed.work.pipeline_rows = detailed
        .work
        .pipeline_rows
        .saturating_sub(detailed.budgeted_work.step_outputs[cut_node.index()]);
    for (branch, operand) in cut.operands(&query.plan).iter().enumerate() {
        let branch_query = CodeQuery {
            plan: operand.clone(),
            limit: usize::MAX,
            ..query.clone()
        };
        let branch_plan =
            select_physical_plan(&branch_query, UnionExecutionStrategy::Sequential, 1, 0)
                .expect("eligible operand has a physical plan");
        for prefix in &prefixes {
            let slots = &prefix.operand_step_outputs[branch];
            let mut pending = vec![(
                branch_plan.node(branch_plan.root()).dependencies()[0],
                whole_plan.node(cut_node).dependencies()[branch],
            )];
            while let Some((source, target)) = pending.pop() {
                detailed.budgeted_work.step_outputs[target.index()] =
                    detailed.budgeted_work.step_outputs[target.index()]
                        .saturating_add(slots[source.index()]);
                let source_children = branch_plan.node(source).dependencies();
                let target_children = whole_plan.node(target).dependencies();
                assert_eq!(source_children.len(), target_children.len());
                pending.extend(
                    source_children
                        .iter()
                        .copied()
                        .zip(target_children.iter().copied()),
                );
            }
        }
    }
    for prefix in &prefixes {
        detailed.work = detailed.work.saturating_add(prefix.work);
        detailed.budgeted_work.provenance_steps = detailed
            .budgeted_work
            .provenance_steps
            .saturating_add(prefix.budgeted_work.provenance_steps);
        detailed.budgeted_work.import_files_resolved = detailed
            .budgeted_work
            .import_files_resolved
            .saturating_add(prefix.budgeted_work.import_files_resolved);
        detailed.budgeted_work.import_edges_resolved = detailed
            .budgeted_work
            .import_edges_resolved
            .saturating_add(prefix.budgeted_work.import_edges_resolved);
    }
    for branch in 0..cut.operands(&query.plan).len() {
        for prefix in &prefixes {
            diagnostics.extend(
                prefix
                    .diagnostics
                    .iter()
                    .filter(|diagnostic| diagnostic.branch.first() == Some(&branch))
                    .cloned(),
            );
        }
    }
    for prefix in &prefixes {
        diagnostics.extend(
            prefix
                .diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.branch.is_empty())
                .cloned(),
        );
    }
    diagnostics.extend(detailed.result.diagnostics.iter().cloned());
    detailed.result.diagnostics = diagnostics.clone();
    let suffix_depth_status = if detailed.depth_answers.is_empty() {
        detailed.result.depth_bound_status
    } else {
        None
    };
    detailed.depth_answers.extend(depth_answers);
    join_depth_bound_status(&mut depth_bound_status, suffix_depth_status);
    join_depth_bound_status(
        &mut depth_bound_status,
        reconciled_depth_status(&detailed.depth_answers),
    );
    detailed.result.depth_bound_status = depth_bound_status;
    let completion = detailed.result.completion();
    if detailed.result.depth_bound_status == Some(DepthBoundStatus::NotReached)
        && !matches!(
            completion,
            CodeQueryCompletion::Complete | CodeQueryCompletion::ProvenSubset { .. }
        )
    {
        // Reconciliation must preserve the whole executor's uncertainty when
        // a later suffix stops before completion.
        detailed.result.depth_bound_status = Some(DepthBoundStatus::Unknown);
    }
    IntersectContinuationResult {
        depth_bound_status: detailed.result.depth_bound_status,
        detailed: Some(detailed),
        completion,
        diagnostics,
        work: charged_work,
        budgeted_work: charged_budgeted,
    }
}

/// Execute every operand below a root intersect for one narrowed seed. The
/// returned port preserves native values and branch order for continuation.
/// A caller must still prove complete seed enumeration before reuse.
#[allow(clippy::too_many_arguments)]
pub fn execute_intersect_prefix(
    analyzer: &dyn IAnalyzer,
    flow_state: impl Into<SemanticFlowResources> + Clone,
    workspace: Option<&WorkspaceAnalyzer>,
    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
    cancellation: Option<&CancellationToken>,
    scope: CodeQueryExecutionScope<'_>,
) -> IntersectPrefixProduct {
    let crate::query::PlanPartitioning::Prefix { cut } =
        PlanPartitioning::classify_for_prefix(&query.plan)
    else {
        panic!("intersect prefix requires an eligible cut");
    };
    assert_eq!(
        scope.seed_files().expect("prefix requires one seed").len(),
        1
    );
    let seed_file = scope.seed_files().expect("one seed")[0].clone();
    let ledger = std::sync::Arc::new(crate::analyzer::read_ledger::ReadLedger::new());
    let _read_scope = crate::analyzer::AnalyzerQueryScope::with_read_ledger(
        analyzer,
        std::sync::Arc::clone(&ledger),
    );
    // Continuation checks the current seed list and merges every seed's operand
    // rows on each run. Membership therefore needs no per-prefix read key.
    // Pin this seed's content even when its operands produce no other reads.
    let seed_read = analyzer
        .structural_fact_providers()
        .into_iter()
        .find(|provider| provider.structural_language() == seed_file.language())
        .and_then(|provider| provider.structural_file_read_key(&seed_file))
        .expect("prefix seed must have a structural file read key");
    analyzer.record_read(seed_read);
    let capture = std::sync::Arc::new(std::sync::Mutex::new(None));
    let mut prefix_query = query.clone();
    prefix_query.plan.steps.clear();
    prefix_query.limit = usize::MAX;
    let mut row_keys = Vec::new();
    let detailed = execute_detailed_unit(
        analyzer,
        flow_state,
        workspace,
        &prefix_query,
        limits,
        cancellation,
        scope.with_intersect_prefix_capture(std::sync::Arc::clone(&capture)),
        &mut row_keys,
        None,
    );
    let operands = capture
        .lock()
        .expect("prefix capture lock is not poisoned")
        .take()
        .unwrap_or_default();
    let physical = select_physical_plan(&prefix_query, UnionExecutionStrategy::Sequential, 1, 0)
        .expect("eligible intersect has a physical plan");
    let cut_node = physical.node(physical.root()).dependencies()[0];
    assert_eq!(
        physical.node(cut_node).operator(),
        match cut.operator(&query.plan) {
            SetOperator::Union => PhysicalQueryOperator::SequentialUnion,
            SetOperator::Intersect => PhysicalQueryOperator::SequentialIntersection,
            SetOperator::Except => PhysicalQueryOperator::SequentialExcept,
        }
    );
    let mut operand_step_outputs = Vec::with_capacity(cut.operands(&query.plan).len());
    for (branch, operand) in cut.operands(&query.plan).iter().enumerate() {
        let branch_query = CodeQuery {
            plan: operand.clone(),
            limit: usize::MAX,
            ..query.clone()
        };
        let branch_plan =
            select_physical_plan(&branch_query, UnionExecutionStrategy::Sequential, 1, 0)
                .expect("eligible operand has a physical plan");
        let mut slots = vec![0_u64; branch_plan.step_output_caps().len()];
        let mut pending = vec![(
            branch_plan.node(branch_plan.root()).dependencies()[0],
            physical.node(cut_node).dependencies()[branch],
        )];
        while let Some((source, target)) = pending.pop() {
            slots[source.index()] = detailed.budgeted_work.step_outputs[target.index()];
            pending.extend(
                branch_plan
                    .node(source)
                    .dependencies()
                    .iter()
                    .copied()
                    .zip(physical.node(target).dependencies().iter().copied()),
            );
        }
        operand_step_outputs.push(slots);
    }
    let complete = detailed.result.completion() == CodeQueryCompletion::Complete
        && operands.len() == cut.operands(&query.plan).len();
    let reads_closed =
        ledger.is_bounded() && ledger.first_refusal().is_none() && !ledger.is_empty();
    IntersectPrefixProduct {
        seed: seed_file,
        operands,
        operand_step_outputs,
        work: detailed.work,
        budgeted_work: detailed.budgeted_work,
        completion: if complete && reads_closed {
            CodeQueryCompletion::Complete
        } else {
            CodeQueryCompletion::Incomplete {
                codes: vec![CodeQueryDiagnosticCode::SemanticResultsOmitted],
            }
        },
        depth_bound_status: detailed.result.depth_bound_status,
        depth_answers: detailed.depth_answers,
        diagnostics: detailed.result.diagnostics,
        reads: ledger.keys(),
        reads_closed,
    }
}

/// Which files a query's seed enumeration runs over.
///
/// The default is the whole analyzed file set, which is byte for byte the
/// behavior every existing entry point has. A narrowed scope replaces the
/// enumeration only: `seed_files` is the exact file set the seed scanners
/// consider (still filtered by language and `where_globs`, still ordered by
/// each family's own comparator), and `workspace_files` is the whole-workspace
/// enumeration those scanners still need for answers a slice must not narrow --
/// the structural seed's diagnostic-only language walk and its per-provider
/// file counts. The caller computes `workspace_files` once and hands the same
/// slice to every unit, which is what keeps unit-wise execution linear in the
/// file count instead of quadratic.
type IntersectPrefixCapture = std::sync::Arc<std::sync::Mutex<Option<Vec<Vec<PipelineRow>>>>>;

/// Test-only count of call-shape candidates presented to binding prefetch.
/// The owning query scope carries this probe across execution workers.
#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, Clone, Default)]
pub struct CallBindingCandidateProbe(Arc<std::sync::atomic::AtomicU64>);

#[cfg(any(test, feature = "test-support"))]
impl CallBindingCandidateProbe {
    pub fn count(&self) -> u64 {
        self.0.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub(super) fn record(&self, count: usize) {
        self.0.fetch_add(
            u64::try_from(count).unwrap_or(u64::MAX),
            std::sync::atomic::Ordering::Relaxed,
        );
    }
}

/// Request-local split receipts from the call-bindings step. An absent value
/// means the route could not supply independently captured setup evidence.
type SplitCallBindingReceipt = (
    brokk_bifrost_analysis::analyzer::i_analyzer::QueryReadReceipt,
    brokk_bifrost_analysis::analyzer::i_analyzer::QueryReadReceipt,
);

#[derive(Clone, Default)]
pub struct CallBindingReadReceipts {
    split: Arc<std::sync::Mutex<Option<SplitCallBindingReceipt>>>,
    isolated: Arc<
        std::sync::Mutex<Option<brokk_bifrost_analysis::analyzer::i_analyzer::QueryReadReceipt>>,
    >,
    rejected: Arc<std::sync::Mutex<Vec<(ProjectFile, Range)>>>,
}

impl std::fmt::Debug for CallBindingReadReceipts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CallBindingReadReceipts")
            .finish_non_exhaustive()
    }
}

impl CallBindingReadReceipts {
    /// Consume the pair once execution has finished. None is a refusal, not
    /// evidence of complete setup or an empty request union.
    pub fn take(&self) -> Option<SplitCallBindingReceipt> {
        self.split
            .lock()
            .expect("call binding receipt sink poisoned")
            .take()
    }

    /// Full isolated binding-step receipt, captured after call-shape.
    pub fn take_isolated(
        &self,
    ) -> Option<brokk_bifrost_analysis::analyzer::i_analyzer::QueryReadReceipt> {
        self.isolated
            .lock()
            .expect("candidate receipt poisoned")
            .take()
    }

    pub fn take_rejected(&self) -> Vec<(ProjectFile, Range)> {
        std::mem::take(&mut *self.rejected.lock().expect("candidate proofs poisoned"))
    }

    pub(super) fn reject(&self, file: ProjectFile, range: Range) {
        self.rejected
            .lock()
            .expect("candidate proofs poisoned")
            .push((file, range));
    }

    pub(super) fn store_isolated(
        &self,
        receipt: brokk_bifrost_analysis::analyzer::i_analyzer::QueryReadReceipt,
    ) {
        *self.isolated.lock().expect("candidate receipt poisoned") = Some(receipt);
    }

    pub(super) fn store(&self, receipts: Option<SplitCallBindingReceipt>) {
        *self
            .split
            .lock()
            .expect("call binding receipt sink poisoned") = receipts;
    }
}

#[derive(Debug, Clone)]
pub struct CodeQueryExecutionScope<'a> {
    isolated_call_binding_receipts: Option<CallBindingReadReceipts>,
    call_binding_receipts: Option<CallBindingReadReceipts>,
    owned_call_anchors: Option<Arc<OwnedCallAnchors>>,
    #[cfg(any(test, feature = "test-support"))]
    binding_candidate_probe: Option<CallBindingCandidateProbe>,
    seed_files: Option<&'a [ProjectFile]>,
    depth_bound_status: bool,
    workspace_files: Option<&'a [ProjectFile]>,
    branch_path: &'a [usize],
    /// Ancestor union suffix steps appended to a flattened leaf. They run on
    /// rows normally but cannot narrow diagnostics across the original set.
    inherited_suffix_steps: usize,
    depth_key_rewrites: Option<Arc<HashMap<String, String>>>,
    /// Optional compilation-local call-target outcomes shared by selector
    /// scans. The analyzer and model authority are rechecked at query entry.
    shared_call_target_outcomes:
        Option<crate::analyzer::usages::call_relations::CallTargetOutcomeCache>,
    intersect_operands: Option<std::sync::Arc<Vec<Vec<PipelineRow>>>>,
    intersect_prefix_capture: Option<IntersectPrefixCapture>,
    except_left_capture: Option<Arc<std::sync::Mutex<Option<bool>>>>,
    /// Words the host accepts as spelled correctly, for relations that guess
    /// at misspellings. A result that consulted it is valid only for this
    /// dictionary, so a host that caches results keys them by its digest.
    identifier_dictionary: Option<&'a IdentifierDictionary>,
    /// The run's known identifier misspellings, which a rules pack supplies.
    /// Without one, relations that report misspellings report nothing and
    /// say so; a host that caches results keys them by its digest.
    identifier_typos: Option<&'a IdentifierTypoTable>,
    /// The file whose call sites a reverse-in-file plan answers. Seeds then
    /// range over the workspace: the operand denotes the targets everywhere.
    reverse_entered_file: Option<&'a ProjectFile>,
}

impl Default for CodeQueryExecutionScope<'_> {
    fn default() -> Self {
        Self::whole_workspace()
    }
}

impl<'a> CodeQueryExecutionScope<'a> {
    /// Opt in only after proving a complete structural call inventory. The
    /// sink belongs to this execution; default queries do not capture it.
    #[doc(hidden)]
    pub fn with_call_binding_receipts(mut self, receipts: CallBindingReadReceipts) -> Self {
        self.call_binding_receipts = Some(receipts);
        self
    }

    /// Run only the binding step inside a candidate boundary. The caller
    /// must restrict this execution to exactly one certified syntax candidate.
    #[doc(hidden)]
    pub fn with_isolated_call_binding_receipts(
        mut self,
        receipts: CallBindingReadReceipts,
    ) -> Self {
        self.isolated_call_binding_receipts = Some(receipts.clone());
        self.call_binding_receipts = Some(receipts);
        self
    }

    pub(super) fn isolated_call_binding_receipts(&self) -> Option<CallBindingReadReceipts> {
        self.isolated_call_binding_receipts.clone()
    }

    pub(super) fn call_binding_receipts(&self) -> Option<CallBindingReadReceipts> {
        self.call_binding_receipts.clone()
    }

    /// Restrict only structurally proven site-local call selectors. Lookup
    /// authority and file-wide uncertainty remain the whole workspace/file.
    #[doc(hidden)]
    pub fn with_owned_call_anchors(mut self, anchors: Arc<OwnedCallAnchors>) -> Self {
        self.owned_call_anchors = Some(anchors);
        self
    }

    pub(super) fn owned_call_anchors(&self) -> Option<&Arc<OwnedCallAnchors>> {
        self.owned_call_anchors.as_ref()
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn with_binding_candidate_probe(mut self, probe: CallBindingCandidateProbe) -> Self {
        self.binding_candidate_probe = Some(probe);
        self
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(super) fn binding_candidate_probe(&self) -> Option<CallBindingCandidateProbe> {
        self.binding_candidate_probe.clone()
    }

    /// Answer a reverse-in-file plan for the call sites in `file`. Only a
    /// caller that partitions such a plan by caller file creates this scope;
    /// a one-file seed restriction keeps its ordinary meaning.
    pub const fn for_reverse_entered_file(
        file: &'a ProjectFile,
        workspace_files: &'a [ProjectFile],
    ) -> Self {
        let mut scope = Self::whole_workspace();
        scope.workspace_files = Some(workspace_files);
        scope.reverse_entered_file = Some(file);
        scope
    }

    pub(super) const fn reverse_entered_file(&self) -> Option<&'a ProjectFile> {
        self.reverse_entered_file
    }

    /// Compute traversal completion evidence for a consumer that requests it.
    /// Direct RQL defaults to enabled; policy hosts use their completion declaration.
    #[doc(hidden)]
    pub const fn with_depth_bound_status(mut self, enabled: bool) -> Self {
        self.depth_bound_status = enabled;
        self
    }

    pub(super) const fn computes_depth_bound_status(&self) -> bool {
        self.depth_bound_status
    }

    pub(super) fn depth_bound_key(&self, key: &str) -> String {
        self.depth_key_rewrites
            .as_ref()
            .and_then(|rewrites| rewrites.get(key))
            .cloned()
            .unwrap_or_else(|| key.to_owned())
    }

    /// Enumerate seeds over the analyzer's whole analyzed file set.
    pub const fn whole_workspace() -> Self {
        Self {
            #[cfg(any(test, feature = "test-support"))]
            binding_candidate_probe: None,
            isolated_call_binding_receipts: None,
            call_binding_receipts: None,
            owned_call_anchors: None,
            seed_files: None,
            depth_bound_status: true,
            workspace_files: None,
            branch_path: &[],
            inherited_suffix_steps: 0,
            depth_key_rewrites: None,
            shared_call_target_outcomes: None,
            intersect_operands: None,
            intersect_prefix_capture: None,
            except_left_capture: None,
            identifier_dictionary: None,
            identifier_typos: None,
            reverse_entered_file: None,
        }
    }

    /// Enumerate seeds over exactly `seed_files`, with `workspace_files` as the
    /// already-computed whole-workspace enumeration.
    pub const fn for_seed_files(
        seed_files: &'a [ProjectFile],
        workspace_files: &'a [ProjectFile],
    ) -> Self {
        Self::for_seed_files_with_branch_path(seed_files, workspace_files, &[])
    }

    /// Narrow starting files while retaining the original workspace view for
    /// diagnostics and dependency resolution, and all other execution options.
    #[doc(hidden)]
    pub fn restrict_seed_files<'b>(
        self,
        seed_files: &'b [ProjectFile],
    ) -> CodeQueryExecutionScope<'b>
    where
        'a: 'b,
    {
        let mut scope: CodeQueryExecutionScope<'b> = self;
        assert!(
            scope
                .seed_files
                .is_none_or(|original| { seed_files.iter().all(|file| original.contains(file)) })
        );
        scope.seed_files = Some(seed_files);
        scope
    }

    /// Enumerate one seed file while retaining the authored union branch path.
    pub(super) const fn for_seed_files_with_branch_path(
        seed_files: &'a [ProjectFile],
        workspace_files: &'a [ProjectFile],
        branch_path: &'a [usize],
    ) -> Self {
        Self {
            #[cfg(any(test, feature = "test-support"))]
            binding_candidate_probe: None,
            isolated_call_binding_receipts: None,
            call_binding_receipts: None,
            owned_call_anchors: None,
            seed_files: Some(seed_files),
            depth_bound_status: true,
            workspace_files: Some(workspace_files),
            branch_path,
            inherited_suffix_steps: 0,
            depth_key_rewrites: None,
            shared_call_target_outcomes: None,
            intersect_operands: None,
            intersect_prefix_capture: None,
            except_left_capture: None,
            identifier_dictionary: None,
            identifier_typos: None,
            reverse_entered_file: None,
        }
    }

    /// Attach the policy compilation's call-target cache when it has an
    /// attested workspace authority.
    #[doc(hidden)]
    pub fn with_optional_shared_call_target_outcomes(
        mut self,
        outcomes: Option<&crate::analyzer::usages::call_relations::CallTargetOutcomeCache>,
    ) -> Self {
        self.shared_call_target_outcomes = outcomes.cloned();
        self
    }

    pub(super) fn with_shared_call_target_outcomes_from(mut self, source: &Self) -> Self {
        self.shared_call_target_outcomes = source.shared_call_target_outcomes.clone();
        self.owned_call_anchors = source.owned_call_anchors.clone();
        self.call_binding_receipts = source.call_binding_receipts.clone();
        self.isolated_call_binding_receipts = source.isolated_call_binding_receipts.clone();
        self
    }

    /// Accept `dictionary`'s words in relations that guess at misspellings.
    pub const fn with_identifier_dictionary(
        mut self,
        dictionary: &'a IdentifierDictionary,
    ) -> Self {
        self.identifier_dictionary = Some(dictionary);
        self
    }

    /// Report the misspellings `typos` lists in relations that look for them.
    pub const fn with_identifier_typos(mut self, typos: &'a IdentifierTypoTable) -> Self {
        self.identifier_typos = Some(typos);
        self
    }

    /// Carry the host's spelling inputs, the dictionary and the typo table,
    /// into a scope derived from `source`.
    pub(super) fn with_spelling_inputs_from(mut self, source: &Self) -> Self {
        self.identifier_dictionary = source.identifier_dictionary;
        self.identifier_typos = source.identifier_typos;
        self
    }

    /// The known misspellings, absent when the host activated no table.
    pub(super) const fn identifier_typos(&self) -> Option<&'a IdentifierTypoTable> {
        self.identifier_typos
    }

    /// The accepted identifier words, empty when the host supplied none.
    pub(super) fn identifier_dictionary(&self) -> &'a IdentifierDictionary {
        static EMPTY: IdentifierDictionary = IdentifierDictionary::EMPTY;
        self.identifier_dictionary.unwrap_or(&EMPTY)
    }

    /// The exact files seed enumeration is restricted to, if any.
    pub const fn seed_files(&self) -> Option<&'a [ProjectFile]> {
        self.seed_files
    }

    /// The whole-workspace enumeration, if the caller already computed it.
    pub(super) const fn workspace_files(&self) -> Option<&'a [ProjectFile]> {
        self.workspace_files
    }

    /// The authored branch path for a narrowed union leaf.
    pub(super) const fn branch_path(&self) -> &'a [usize] {
        self.branch_path
    }

    pub(super) const fn inherited_suffix_steps(&self) -> usize {
        self.inherited_suffix_steps
    }

    pub(super) fn shared_call_target_outcomes(
        &self,
    ) -> Option<&crate::analyzer::usages::call_relations::CallTargetOutcomeCache> {
        // This cache replays one accumulated read set for the whole file.
        // A procedure-owned query must neither import foreign call-resolution
        // reads nor make its accounting depend on earlier procedure visits.
        // Keep its call-target cache query-local instead; ordinary file queries
        // retain the existing compilation-wide sharing.
        if self.owned_call_anchors.is_some() {
            None
        } else {
            self.shared_call_target_outcomes.as_ref()
        }
    }

    fn capture_except_left(
        &mut self,
        query: &CodeQuery,
    ) -> Option<Arc<std::sync::Mutex<Option<bool>>>> {
        if !self.computes_depth_bound_status()
            || !matches!(
                query.plan.source,
                CodeQueryPlanSource::Set {
                    op: SetOperator::Except,
                    ..
                }
            )
        {
            return None;
        }
        let capture = Arc::new(std::sync::Mutex::new(None));
        self.except_left_capture = Some(capture.clone());
        Some(capture)
    }

    pub(super) fn record_except_left(&self, complete_empty: bool) {
        if let Some(capture) = &self.except_left_capture {
            *capture.lock().expect("except capture lock is not poisoned") = Some(complete_empty);
        }
    }

    pub(super) fn with_intersect_operands(mut self, rows: Vec<Vec<PipelineRow>>) -> Self {
        self.intersect_operands = Some(std::sync::Arc::new(rows));
        self
    }

    pub(super) fn intersect_operands(&self) -> Option<&[Vec<PipelineRow>]> {
        self.intersect_operands.as_deref().map(Vec::as_slice)
    }

    pub(super) fn with_intersect_prefix_capture(mut self, capture: IntersectPrefixCapture) -> Self {
        self.intersect_prefix_capture = Some(capture);
        self
    }

    pub(super) fn intersect_prefix_capture(&self) -> Option<&IntersectPrefixCapture> {
        self.intersect_prefix_capture.as_ref()
    }
}

/// Execute one evaluation unit: `query` over exactly `scope`'s seed files.
///
/// This is `execute_code_query_detailed_eager_index` with a seed scope: the
/// `EagerAuto` access mode and full result detail the policy match path uses,
/// so a unit and the whole execution it partitions agree on everything except
/// which files the seed enumeration walked. The result carries each rendered
/// row's dedup key and evidence projection, every budgeted counter lane, and
/// the completion the whole run would derive, which is everything
/// [`merge_unit_rows`] needs.
///
/// `workspace` is the generation-bound workspace oracles, when the caller
/// holds them. It is not a mode: it is exactly the difference between
/// `execute_code_query_detailed_eager_index` and its `_workspace` sibling, and
/// a unit must run under whichever of the two its whole execution would have
/// used, or its rows would not be that execution's rows.
pub fn execute_code_query_unit(
    analyzer: &dyn IAnalyzer,
    flow_state: impl Into<SemanticFlowResources> + Clone,
    workspace: Option<&WorkspaceAnalyzer>,
    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
    cancellation: Option<&CancellationToken>,
    mut scope: CodeQueryExecutionScope<'_>,
) -> UnitExecutionResult {
    if PlanPartitioning::classify(&query.plan).is_seed_union()
        && let Some(seed_files) = scope.seed_files()
    {
        assert_eq!(
            seed_files.len(),
            1,
            "a seed-union unit must narrow exactly one seed file"
        );
        if !PlanPartitioning::union_has_post_merge_suffix(&query.plan) {
            return execute_seed_union_unit(
                analyzer,
                flow_state.clone(),
                workspace,
                query,
                limits,
                cancellation,
                scope,
            );
        }
    }
    let unit_query = if PlanPartitioning::classify(&query.plan) == PlanPartitioning::BySeedSetUnion
        || (PlanPartitioning::classify(&query.plan).is_seed_union()
            && PlanPartitioning::union_has_post_merge_suffix(&query.plan))
    {
        Some(CodeQuery {
            limit: usize::MAX,
            ..query.clone()
        })
    } else {
        None
    };
    let except_left = scope.capture_except_left(query);
    let mut row_keys = Vec::new();
    let detailed = execute_detailed_unit(
        analyzer,
        flow_state.clone(),
        workspace,
        unit_query.as_ref().unwrap_or(query),
        limits,
        cancellation,
        scope,
        &mut row_keys,
        None,
    );
    let mut unit = project_unit_result(&detailed, row_keys);
    unit.except_left_complete_empty = except_left
        .and_then(|capture| *capture.lock().expect("except capture lock is not poisoned"));
    unit
}

/// Remaining physical allowance for sequential units or union leaves.
/// Semantic limits pass through: SemanticBudget's contract bounds resident
/// admission; its cumulative work is telemetry, not a cumulative limit.
pub fn remaining_unit_limits(
    limits: CodeQueryExecutionLimits,
    work: &CodeQueryExecutionWork,
    budgeted: &CodeQueryBudgetedWork,
) -> Option<CodeQueryExecutionLimits> {
    let subtract =
        |cap: usize, used: u64| cap.saturating_sub(usize::try_from(used).unwrap_or(usize::MAX));
    let remaining = CodeQueryExecutionLimits {
        max_scanned_files: subtract(
            limits.max_scanned_files,
            work.scanned_files.max(budgeted.import_files_resolved),
        ),
        max_scanned_source_bytes: subtract(
            limits.max_scanned_source_bytes,
            work.scanned_source_bytes,
        ),
        max_fact_nodes: subtract(
            limits.max_fact_nodes,
            work.fact_nodes.saturating_add(work.examined_references),
        ),
        max_pipeline_rows: subtract(
            limits.max_pipeline_rows,
            work.pipeline_rows
                .max(budgeted.provenance_steps)
                .max(budgeted.import_edges_resolved),
        ),
        ..limits
    };
    (remaining.max_scanned_files > 0
        && remaining.max_scanned_source_bytes > 0
        && remaining.max_fact_nodes > 0
        && remaining.max_pipeline_rows > 0)
        .then_some(remaining)
}

/// Name an exhausted unit budget as the cause of a truncated merge whose
/// remaining physical limits left no room for further units.
pub fn push_unit_budget_diagnostic(diagnostics: &mut Vec<CodeQueryDiagnostic>) {
    push_budget_diagnostic(diagnostics, &CodeQueryExecutionBudget::default());
}

/// Report units or leaves omitted after a physical allowance ran out.
pub fn push_skipped_unit_diagnostic(diagnostics: &mut Vec<CodeQueryDiagnostic>, skipped: usize) {
    push_unit_budget_diagnostic(diagnostics);
    let diagnostic = diagnostics
        .iter_mut()
        .find(|diagnostic| diagnostic.code == CodeQueryDiagnosticCode::ExecutionBudgetExhausted)
        .expect("budget diagnostic was installed");
    diagnostic
        .message
        .push_str(&format!("; skipped {skipped} units"));
}

fn traversal_key(plan: &CodeQueryPlan, position: usize, path: &[usize]) -> String {
    crate::structural::execution::plan::depth_bound_traversal_key(plan, position, path)
}

fn leaf_traversal_rewrites(
    original: &CodeQueryPlan,
    leaf: &CodeQueryPlan,
    path: &[usize],
) -> HashMap<String, String> {
    let mut current = original;
    let mut current_path = Vec::new();
    let mut inherited = Vec::new();
    for &branch in path {
        let mut suffix = (0..current.steps.len())
            .map(|position| traversal_key(current, position, &current_path))
            .collect::<Vec<_>>();
        suffix.extend(inherited);
        inherited = suffix;
        let CodeQueryPlanSource::Set { branches, .. } = &current.source else {
            unreachable!("union branch path addresses a set")
        };
        current = &branches[branch];
        current_path.push(branch);
    }
    let mut rewrites = rebased_traversal_keys(leaf, path);
    let local_count = leaf.steps.len() - inherited.len();
    for (offset, global) in inherited.into_iter().enumerate() {
        rewrites.insert(traversal_key(leaf, local_count + offset, &[]), global);
    }
    rewrites
}

/// Execute one eligible union unit leaf by leaf, preserving branch rows until
/// the global unit merge. A leaf receives no result limit of its own: the
/// query's limit is a cap on the union after all branches have been composed.
fn execute_seed_union_unit(
    analyzer: &dyn IAnalyzer,
    flow_state: impl Into<SemanticFlowResources> + Clone,
    workspace: Option<&WorkspaceAnalyzer>,
    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
    cancellation: Option<&CancellationToken>,
    scope: CodeQueryExecutionScope<'_>,
) -> UnitExecutionResult {
    let leaves = PlanPartitioning::union_leaf_plans(&query.plan)
        .expect("seed-union execution requires an eligible union plan");
    let mut rows = Vec::new();
    let mut work = CodeQueryExecutionWork::default();
    let mut budgeted_work = CodeQueryBudgetedWork::default();
    let mut diagnostics = Vec::new();
    let mut truncated = false;

    let mut depth_answers = Vec::new();
    let mut depth_bound_status = None;

    let leaf_count = leaves.len();
    for (index, (leaf, branch_path, inherited_suffix_steps)) in leaves.into_iter().enumerate() {
        let Some(remaining) = remaining_unit_limits(limits, &work, &budgeted_work) else {
            push_skipped_unit_diagnostic(&mut diagnostics, leaf_count - index);
            truncated = true;
            if scope.computes_depth_bound_status() {
                depth_answers.extend(unknown_depth_answers(&query.plan));
            }
            break;
        };
        let leaf_query = CodeQuery {
            schema_version: query.schema_version,
            plan: leaf,
            // A branch cannot apply the union's global result cap. The
            // physical pipeline cap still bounds intermediate output.
            limit: usize::MAX,
            result_detail: query.result_detail,
            execution_mode: query.execution_mode,
        };
        let mut row_keys = Vec::new();
        let mut leaf_scope = CodeQueryExecutionScope::for_seed_files_with_branch_path(
            scope
                .seed_files()
                .expect("a seed-union unit requires narrowed seed files"),
            scope
                .workspace_files()
                .expect("a seed-union unit requires whole-workspace files"),
            &branch_path,
        )
        .with_depth_bound_status(scope.computes_depth_bound_status())
        .with_shared_call_target_outcomes_from(&scope)
        .with_spelling_inputs_from(&scope);
        leaf_scope.inherited_suffix_steps = inherited_suffix_steps;
        leaf_scope.depth_key_rewrites = Some(Arc::new(leaf_traversal_rewrites(
            &query.plan,
            &leaf_query.plan,
            &branch_path,
        )));
        let detailed = execute_detailed_unit(
            analyzer,
            flow_state.clone(),
            workspace,
            &leaf_query,
            remaining,
            cancellation,
            leaf_scope,
            &mut row_keys,
            None,
        );
        let mut leaf_result = project_unit_result(&detailed, row_keys);
        if leaf_result.depth_answers.is_empty() {
            join_depth_bound_status(&mut depth_bound_status, leaf_result.depth_bound_status);
        }
        depth_answers.append(&mut leaf_result.depth_answers);
        work = work.saturating_add(leaf_result.work);
        budgeted_work.provenance_steps = budgeted_work
            .provenance_steps
            .saturating_add(leaf_result.budgeted_work.provenance_steps);
        budgeted_work.import_files_resolved = budgeted_work
            .import_files_resolved
            .saturating_add(leaf_result.budgeted_work.import_files_resolved);
        budgeted_work.import_edges_resolved = budgeted_work
            .import_edges_resolved
            .saturating_add(leaf_result.budgeted_work.import_edges_resolved);
        budgeted_work
            .step_outputs
            .extend(leaf_result.budgeted_work.step_outputs);
        diagnostics.append(&mut leaf_result.diagnostics);
        truncated |= leaf_result.truncated;
        rows.append(&mut leaf_result.rows);
    }

    super::execution::discharge_decided_qualifying_sites(
        unit_qualifying_sites(&rows, &diagnostics),
        &mut diagnostics,
        0,
    );

    // Skipped suffix leaves still occupy their physical-plan counter slots.
    budgeted_work
        .step_outputs
        .resize(unit_step_output_caps(query).len(), 0);
    join_depth_bound_status(
        &mut depth_bound_status,
        reconciled_depth_status(&depth_answers),
    );
    UnitExecutionResult {
        except_left_complete_empty: None,
        rows,
        work,
        budgeted_work,
        completion: code_query_completion(truncated, &diagnostics),
        depth_bound_status,
        depth_answers,
        diagnostics,
        truncated,
    }
}

/// One selector unit's execution, both ways.
///
/// `unit` is the publishable projection of the rows -- what the merge sums,
/// what the caps are checked against, and what is stored under the unit's read
/// set. `detailed` is the same execution's live rows and evidence, which the
/// selector compiler reads instead because a selected site is derived from a
/// row's own typed value rather than from the projection's scalars, and it
/// still carries the one-shot semantic receipt the caller must charge.
pub struct SelectorUnitExecution {
    pub unit: UnitExecutionResult,
    pub detailed: DetailedCodeQueryResult,
}

/// Execute one selector unit: `query` over exactly `scope`'s seed files, under
/// the caller's own semantic ledgers.
///
/// This is
/// [`execute_code_query_detailed_eager_index_workspace_with_semantic_receipt`]
/// with a seed scope and a unit projection, which is exactly what a policy
/// selector compiled one seed file at a time needs: the receipt is what lets
/// the session charge each unit's semantic work cumulatively, in seed order,
/// so the compile's remaining budget after the last unit is the budget one
/// whole-workspace selector execution would have left.
#[allow(clippy::too_many_arguments)]
pub fn execute_code_query_selector_unit(
    workspace: &WorkspaceAnalyzer,
    flow_state: impl Into<SemanticFlowResources> + Clone,
    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
    root_allotment: super::CodeQueryRootAllotment,
    cancellation: Option<&CancellationToken>,
    parent_semantic: &SemanticBudget,
    parent_execution: &SemanticExecutionBudget,
    artifact_leases: SemanticArtifactLeaseSnapshot,
    mut scope: CodeQueryExecutionScope<'_>,
) -> SelectorUnitExecution {
    let except_left = scope.capture_except_left(query);
    let mut row_keys = Vec::new();
    let detailed = execute_detailed_selector_unit(
        workspace,
        flow_state.clone(),
        query,
        limits,
        root_allotment,
        cancellation,
        parent_semantic,
        parent_execution,
        artifact_leases,
        scope,
        &mut row_keys,
    );
    let mut unit = project_unit_result(&detailed, row_keys);
    unit.except_left_complete_empty = except_left
        .and_then(|capture| *capture.lock().expect("except capture lock is not poisoned"));
    SelectorUnitExecution { unit, detailed }
}

/// Project one detailed execution onto the product a unit publishes.
fn project_unit_result(
    detailed: &DetailedCodeQueryResult,
    row_keys: Vec<UnitRowKey>,
) -> UnitExecutionResult {
    let completion = detailed.result.completion();
    assert_eq!(
        detailed.result.results.len(),
        row_keys.len(),
        "one dedup key is rendered for every rendered row"
    );
    assert_eq!(
        detailed.result.results.len(),
        detailed.evidence.len(),
        "detailed evidence stays aligned with rendered rows"
    );
    let rows = detailed
        .result
        .results
        .iter()
        .zip(&detailed.evidence)
        .zip(row_keys)
        .map(|((item, evidence), key)| UnitRow {
            item: UnitRowItem::project(item),
            evidence: UnitRowEvidence::project(evidence),
            key,
        })
        .collect();
    UnitExecutionResult {
        except_left_complete_empty: None,
        rows,
        work: detailed.work,
        budgeted_work: detailed.budgeted_work.clone(),
        completion,
        depth_bound_status: detailed.result.depth_bound_status,
        depth_answers: detailed.depth_answers.clone(),
        diagnostics: detailed.result.diagnostics.clone(),
        truncated: detailed.result.truncated,
    }
}

/// The detailed execution one selector unit runs, with its rows' dedup keys.
///
/// The whole-workspace sibling is
/// `execute_code_query_detailed_eager_index_workspace_with_semantic_receipt`;
/// only the seed scope and the dedup keys differ, and both must stay that way
/// or a unit would not be a partition of the execution it replaces.
#[allow(clippy::too_many_arguments)]
fn execute_detailed_selector_unit(
    workspace: &WorkspaceAnalyzer,
    flow_state: impl Into<SemanticFlowResources> + Clone,
    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
    root_allotment: super::CodeQueryRootAllotment,
    cancellation: Option<&CancellationToken>,
    parent_semantic: &SemanticBudget,
    parent_execution: &SemanticExecutionBudget,
    artifact_leases: SemanticArtifactLeaseSnapshot,
    scope: CodeQueryExecutionScope<'_>,
    row_keys: &mut Vec<UnitRowKey>,
) -> DetailedCodeQueryResult {
    let parent_scope = parent_semantic.scope_snapshot();
    let (execution_before, execution_child) =
        parent_execution.fork_with_materialized_file_limit(limits.semantic.max_materialized_files);
    let query_scope = AnalyzerQueryScope::new(workspace.analyzer());
    let token = query_scope.token();
    let access_mode = super::eager_structural_access_mode();
    execute_internal_with_analysis_strategy(
        workspace.analyzer(),
        token,
        None,
        Some(workspace),
        Some(flow_state.into()),
        None,
        0,
        query,
        limits,
        cancellation,
        None,
        false,
        UnionExecutionStrategy::Auto,
        CODE_QUERY_SCHEDULER_WORKERS,
        access_mode,
        OccurrenceDerivationOptions::IDENTITY_ONLY,
        Some(SemanticQueryContinuation {
            parent_scope,
            child_semantic_limits: parent_semantic.remaining(),
            root_allotment,
            execution_before,
            execution_child,
            artifact_leases,
        }),
        None,
        scope,
        Some(row_keys),
        None,
    )
}

/// The detailed execution one unit runs, with its rows' dedup keys.
#[allow(clippy::too_many_arguments)]
fn execute_detailed_unit(
    analyzer: &dyn IAnalyzer,
    flow_state: impl Into<SemanticFlowResources> + Clone,
    workspace: Option<&WorkspaceAnalyzer>,
    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
    cancellation: Option<&CancellationToken>,
    scope: CodeQueryExecutionScope<'_>,
    row_keys: &mut Vec<UnitRowKey>,
    native_rows: Option<&mut Vec<PipelineRow>>,
) -> DetailedCodeQueryResult {
    let query_scope = AnalyzerQueryScope::new(analyzer);
    let token = query_scope.token();
    let access_mode = super::eager_structural_access_mode();
    execute_internal_with_analysis_strategy(
        analyzer,
        token,
        None,
        workspace,
        Some(flow_state.into()),
        None,
        0,
        query,
        limits,
        cancellation,
        None,
        false,
        UnionExecutionStrategy::Auto,
        CODE_QUERY_SCHEDULER_WORKERS,
        access_mode,
        OccurrenceDerivationOptions::IDENTITY_ONLY,
        None,
        None,
        scope,
        Some(row_keys),
        native_rows,
    )
}

/// The dedup identity of one rendered row, over stable identities only.
///
/// This is the projection of the executor's private `PipelineKey`: every arm
/// is rendered over workspace-relative paths, content-derived declaration
/// identities, mount-free semantic wire ids, and the typed keys' own stable
/// fields. Nothing that carries a workspace root or a process-local handle
/// address enters it, so the same row keyed at two different roots -- a head
/// workspace and a base revision exported to a temporary directory -- projects
/// to the same key.
///
/// The rendering is structured rather than concatenated: `arm` names the row
/// family and `parts` are that family's identity fields in a fixed order, so
/// no separator convention can make two different rows compare equal.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UnitRowKey {
    arm: Box<str>,
    parts: Vec<Box<str>>,
}

impl UnitRowKey {
    /// The row family this key addresses.
    pub fn arm(&self) -> &str {
        &self.arm
    }

    /// The family's identity fields, in the family's own declared order.
    pub fn parts(&self) -> &[Box<str>] {
        &self.parts
    }
}

/// Builder for one `UnitRowKey` arm.
struct UnitRowKeyBuilder {
    arm: &'static str,
    parts: Vec<Box<str>>,
}

/// Start one key arm.
fn key(arm: &'static str) -> UnitRowKeyBuilder {
    UnitRowKeyBuilder {
        arm,
        parts: Vec::new(),
    }
}

impl UnitRowKeyBuilder {
    fn text(mut self, value: impl AsRef<str>) -> Self {
        self.parts.push(Box::from(value.as_ref()));
        self
    }

    /// Another family's complete key, length-prefixed so two nested keys
    /// cannot run into each other.
    fn nested(mut self, inner: UnitRowKey) -> Self {
        self.parts.push(inner.arm);
        self.parts.push(Box::from(inner.parts.len().to_string()));
        self.parts.extend(inner.parts);
        self
    }

    /// A component whose only rendering is its variant name.
    ///
    /// Used exclusively for field-less enumerations, whose `Debug` output is
    /// that name. Never for a value that carries a path, a root, or a handle.
    fn variant(self, value: impl std::fmt::Debug) -> Self {
        self.text(format!("{value:?}"))
    }

    fn number(self, value: impl std::fmt::Display) -> Self {
        self.text(value.to_string())
    }

    fn flag(self, value: bool) -> Self {
        self.text(if value { "true" } else { "false" })
    }

    /// A file, as its workspace-relative path: the one spelling of a file that
    /// is the same in every workspace holding the same content.
    fn path(self, file: &ProjectFile) -> Self {
        self.text(rel_path_string(file))
    }

    /// A declaration, as its content-derived declaration id.
    fn declaration(self, unit: &CodeUnit) -> Self {
        self.text(unit.declaration_id().as_str())
    }

    fn range(self, range: Range) -> Self {
        self.text(format!(
            "{}:{}:{}:{}",
            range.start_byte, range.end_byte, range.start_line, range.end_line
        ))
    }

    /// An optional component. `None` renders empty and `Some` renders with a
    /// leading `=`, so no value can collide with the absence of one.
    fn optional(self, value: Option<impl AsRef<str>>) -> Self {
        match value {
            Some(value) => self.text(format!("={}", value.as_ref())),
            None => self.text(""),
        }
    }

    fn declaration_value(self, value: &DeclarationValue) -> Self {
        // A declaration's stable row identity is the declaration and the range
        // it covers. The optional leaf kind a structural projection proved is
        // presentation metadata the executor merges into the surviving row, so
        // projecting it here would key two spellings of one declaration apart
        // again at the unit boundary.
        self.declaration(&value.unit).range(value.range)
    }

    fn call_site_value(self, value: &CallSiteValue) -> Self {
        let CallSiteValue(site, binding, site_id, _, _, _, target) = value;
        // A call site is identified by the exact call expression it covers and
        // the two declarations it connects. The argument rows the pipeline key
        // also holds are derived from that same expression. Source-backed
        // dispatch can publish several external arms at one expression with
        // the same placeholder callee, so retain the per-arm target evidence.
        let key = self
            .path(&site.file)
            .range(site.range)
            .range(site.callee_range)
            .text(site_id)
            .declaration(&site.caller)
            .declaration(&site.callee)
            .variant(site.kind)
            .text(usage_proof_label(site.proof))
            .optional(site.receiver.map(|range| {
                format!(
                    "{}:{}:{}:{}",
                    range.start_byte, range.end_byte, range.start_line, range.end_line
                )
            }))
            .number(site.arguments.len())
            .variant(binding);
        match target {
            None => key,
            Some(target) => key
                .text("target")
                .optional(target.target_id.as_deref())
                .optional(target.target_fq_name.as_deref())
                .optional(target.boundary_kind)
                .text(target.proof)
                .text(target.completeness)
                .text(target.coverage)
                .optional(target.reason.as_deref()),
        }
    }

    fn finish(self) -> UnitRowKey {
        UnitRowKey {
            arm: Box::from(self.arm),
            parts: self.parts,
        }
    }
}

/// Project one pipeline dedup key onto stable identities.
///
/// Exhaustive by construction: a new row family cannot reach the merge with a
/// key that silently equals another family's.
pub(super) fn unit_row_key(key_value: &PipelineKey) -> UnitRowKey {
    match key_value {
        PipelineKey::StructuralMatch(file, node, reported_range) => key("structural_match")
            .path(file)
            .number(node)
            .optional(reported_range.map(|range| {
                format!(
                    "{}:{}:{}:{}",
                    range.start_byte, range.end_byte, range.start_line, range.end_line
                )
            }))
            .finish(),
        PipelineKey::Declaration(value) => key("declaration").declaration_value(value).finish(),
        PipelineKey::Semantic(value) => semantic_unit_row_key(value),
        PipelineKey::File(file) => key("file").path(file).finish(),
        PipelineKey::DependencyEvidence(id) => key("dependency_evidence").text(id).finish(),
        PipelineKey::ConfigurationFact(value) => key("configuration_fact")
            .path(&value.file)
            .number(value.fact_index)
            .finish(),
        PipelineKey::CrossDomain(value) => {
            let fact_key = |fact: &ConfigurationFactKey| {
                unit_row_key(&PipelineKey::ConfigurationFact(fact.clone()))
            };
            match value.as_ref() {
                CrossDomainKey::DependencyConfiguration(code, mapping) => key("cross_domain")
                    .text("dependency_configuration")
                    .nested(unit_row_key(code))
                    .text(mapping)
                    .finish(),
                CrossDomainKey::Correlated(code, fact) => key("cross_domain")
                    .text("correlated")
                    .nested(unit_row_key(code))
                    .nested(fact_key(fact))
                    .finish(),
                CrossDomainKey::ConfigurationCode(code, fact) => key("cross_domain")
                    .text("configuration_code")
                    .nested(unit_row_key(code))
                    .nested(fact_key(fact))
                    .finish(),
                CrossDomainKey::ConfigurationCodeAbsent(fact) => key("cross_domain")
                    .text("configuration_code_absent")
                    .nested(fact_key(fact))
                    .finish(),
                CrossDomainKey::CodeWitness(code) => key("cross_domain")
                    .text("code")
                    .nested(unit_row_key(code))
                    .finish(),
                CrossDomainKey::ConfigurationWitness(fact) => key("cross_domain")
                    .text("configuration")
                    .nested(fact_key(fact))
                    .finish(),
            }
        }
        PipelineKey::ReferenceSite(site) => key("reference_site")
            .path(&site.file)
            .range(site.range)
            .declaration_value(&site.target)
            .optional(
                site.enclosing
                    .as_ref()
                    .map(|enclosing| enclosing.unit.declaration_id().as_str().to_string()),
            )
            .text(site.usage_kind.wire_label())
            .text(usage_proof_label(site.proof))
            .finish(),
        PipelineKey::CallSite(value) => key("call_site").call_site_value(value).finish(),
        PipelineKey::ExpressionSite(value) => key("expression_site")
            .call_site_value(&value.call_site)
            .range(value.range)
            .text(match &value.input {
                ExpressionInput::Receiver => "receiver".to_string(),
                ExpressionInput::Parameter { index, name } => match name {
                    Some(name) => format!("parameter:{index}:{name}"),
                    None => format!("parameter:{index}"),
                },
            })
            .finish(),
        PipelineKey::JsxAttributeValue(id) => key("jsx_attribute_value").text(id).finish(),
        PipelineKey::ReceiverAnalysis(operation, file, range) => key("receiver_analysis")
            .variant(operation)
            .path(file)
            .range(*range)
            .finish(),
        PipelineKey::MemberTargetAnalysis(operation, file, range) => key("member_target_analysis")
            .variant(operation)
            .path(file)
            .range(*range)
            .finish(),
        PipelineKey::ReceiverOutcome(id) => key("receiver_outcome").text(id).finish(),
        PipelineKey::ReceiverEvidence(id) => key("receiver_evidence").text(id).finish(),
        PipelineKey::PointsToCandidate(id) => key("points_to_candidate").text(id).finish(),
        PipelineKey::FieldWriteValue(id) => key("field_write_value").text(id).finish(),
        PipelineKey::RuntimeKeyedReadValue(id) => key("keyed_read_value").text(id).finish(),
        PipelineKey::CallShape(id) => key("call_shape").text(id).finish(),
        PipelineKey::CallArgumentGroup(id) => key("call_argument_group").text(id).finish(),
        PipelineKey::CallArgument(id) => key("call_argument").text(id).finish(),
        PipelineKey::CallBinding(id) => key("call_binding").text(id).finish(),
        PipelineKey::CallEffect(id) => key("call_effect").text(id).finish(),
        PipelineKey::CallResultContract(id) => key("call_result_contract").text(id).finish(),
        PipelineKey::CallResultObligation(id) => key("call_result_obligation").text(id).finish(),
        PipelineKey::PythonRuleFact(id) => key("python_rule_fact").text(id).finish(),
        PipelineKey::ResultSubjectUse(id) => key("result_subject_use").text(id).finish(),
        PipelineKey::ResultContractUse(id) => key("result_contract_use").text(id).finish(),
        PipelineKey::ResultContractFailureUse(id) => {
            key("result_contract_failure_use").text(id).finish()
        }
        PipelineKey::NilnessOperation(id) => key("nilness_operation").text(id).finish(),
        PipelineKey::SwitchCoverage(id) => key("switch_coverage").text(id).finish(),
        PipelineKey::AssignmentRelation(id) => key("assignment_relation").text(id).finish(),
        PipelineKey::DetachedTaskTransfer(id) => key("detached_task_transfer").text(id).finish(),
        PipelineKey::ProcedureEffect(id) => key("procedure_effect").text(id).finish(),
        PipelineKey::CallableSignature(id) => key("callable_signature").text(id).finish(),
        PipelineKey::LiteralOccurrence(id) => key("literal_occurrence").text(id).finish(),
        PipelineKey::CallableMetrics(id) => key("callable_metrics").text(id).finish(),
        PipelineKey::SignatureParameter(id) => key("signature_parameter").text(id).finish(),
        PipelineKey::DecoratedParameter(id) => key("decorated_parameter").text(id).finish(),
        PipelineKey::CallableApplicability(id) => key("callable_applicability").text(id).finish(),
        PipelineKey::OverloadSelection(id) => key("overload_selection").text(id).finish(),
        PipelineKey::MemberSelection(id) => key("member_selection").text(id).finish(),
        PipelineKey::DispatchOutcome(id) => key("dispatch_outcome").text(id).finish(),
        PipelineKey::DispatchTarget(id, root_id) => {
            key("dispatch_target").text(id).text(root_id).finish()
        }
        PipelineKey::MemberFamily(id) => key("member_family").text(id).finish(),
        PipelineKey::MemberFamilyEdge(id) => key("member_family_edge").text(id).finish(),
        PipelineKey::PythonHierarchyFact(id) => key("python_hierarchy_fact").text(id).finish(),
        PipelineKey::Occurrence(occurrence) => key("occurrence")
            .path(&occurrence.file)
            .number(occurrence.node)
            .text(occurrence.role.label())
            .finish(),
        PipelineKey::LexicalScope(scope) => key("lexical_scope")
            .path(&scope.file)
            .number(scope.index)
            .finish(),
        PipelineKey::Binding(binding) => key("binding")
            .path(&binding.file)
            .number(binding.index)
            .flag(binding.shadowed)
            .optional(binding.reached_from.as_deref())
            .finish(),
        PipelineKey::ResolutionCandidate(candidate) => key("resolution_candidate")
            .path(&candidate.file)
            .number(candidate.node)
            .text(candidate.role.label())
            .number(candidate.ordinal)
            .finish(),
        PipelineKey::CandidateHop(hop) => key("candidate_hop")
            .path(&hop.file)
            .number(hop.node)
            .text(hop.role.label())
            .number(hop.ordinal)
            .number(hop.hop)
            .finish(),
        PipelineKey::GenerationSite(site) => key("generation_site")
            .path(&site.file)
            .number(site.index)
            .finish(),
        PipelineKey::Export(export) => key("export")
            .path(&export.file)
            .number(export.index)
            .finish(),
        PipelineKey::DeclarationState(state) => key("declaration_state")
            .path(&state.file)
            .number(state.index)
            .finish(),
        PipelineKey::ReferenceEdge(edge) => key("reference_edge")
            .path(&edge.file)
            .number(edge.start_byte)
            .number(edge.end_byte)
            .declaration(&edge.target)
            .optional(
                edge.source
                    .as_ref()
                    .map(|source| source.declaration_id().as_str().to_string()),
            )
            .text(edge.provenance.label())
            .finish(),
        PipelineKey::StateEvent(event) => key("state_event")
            .path(&event.file)
            .text(&event.procedure)
            .number(event.event)
            .finish(),
        PipelineKey::BindingInitializerCall(id) => {
            key("binding_initializer_call").text(id).finish()
        }
        PipelineKey::FlowRelation(relation) => key("flow_relation")
            .path(&relation.file)
            .text(&relation.procedure)
            .number(relation.relation)
            .finish(),
        PipelineKey::ControlRelation(relation) => key("control_relation")
            .text(&relation.procedure)
            .number(relation.index)
            .finish(),
        PipelineKey::BranchRelation(id) => key("branch_relation").text(id).finish(),
        PipelineKey::LoopRelation(id) => key("loop_relation").text(id).finish(),
        PipelineKey::CppExpression(id) => key("cpp_expression").text(id).finish(),
        PipelineKey::FailureHandlerState(id) => key("failure_handler_state").text(id).finish(),
        PipelineKey::StatementReachability(id) => key("statement_reachability").text(id).finish(),
        PipelineKey::PendingCleanupFlow(id) => key("pending_cleanup_flow").text(id).finish(),
        PipelineKey::Guard(guard) => key("guard")
            .text(&guard.procedure)
            .number(guard.guard.index())
            .finish(),
        PipelineKey::SourceSet(entity) => key("source_set").text(&entity.id).finish(),
        PipelineKey::BuildTarget(entity) => key("build_target").text(&entity.id).finish(),
        PipelineKey::TopologyEdge(edge) => key("topology_edge").text(&edge.id).finish(),
        PipelineKey::BuildConfiguration(id) => key("build_configuration").text(id).finish(),
        PipelineKey::ClassSetRow(id) => key("class_set_row").text(id).finish(),
        PipelineKey::AbsentMemberFinding(id) => key("absent_member_finding").text(id).finish(),
        PipelineKey::RewritePath(path) => key("rewrite_path")
            .path(&path.file)
            .number(path.index)
            .finish(),
        PipelineKey::QualifiedPath(path) => key("qualified_path")
            .path(&path.file)
            .number(path.terminal_node)
            .finish(),
        PipelineKey::PathSegment(segment) => key("path_segment")
            .path(&segment.file)
            .number(segment.path_terminal_node)
            .number(segment.ordinal)
            .finish(),
    }
}

/// Project one semantic dedup key onto its mount-free wire identity.
///
/// The three handle-bearing arms are keyed by the same public wire ids the
/// rendered rows publish, which fold the artifact's public fingerprint rather
/// than its mount-bearing durable key.
fn semantic_unit_row_key(key_value: &SemanticPipelineKey) -> UnitRowKey {
    match key_value {
        SemanticPipelineKey::ProgramPointReference(id) => {
            key("semantic_program_point").text(id.clone()).finish()
        }
        SemanticPipelineKey::ControlEdgeReference(id) => {
            key("semantic_control_edge").text(id.clone()).finish()
        }
        SemanticPipelineKey::ProcedureReference(reference) => key("semantic_procedure")
            .text(reference.public_digest().to_string())
            .finish(),
        SemanticPipelineKey::Procedure(handle) => key("semantic_procedure")
            .text(semantic::procedure_wire_id(handle))
            .finish(),
        SemanticPipelineKey::ProgramPoint(handle) => key("semantic_program_point")
            .text(semantic::program_point_wire_id(handle))
            .finish(),
        SemanticPipelineKey::ControlEdge(handle) => key("semantic_control_edge")
            .text(semantic::control_edge_wire_id(handle))
            .finish(),
        SemanticPipelineKey::CallResult(id) => key("semantic_call_result").text(id).finish(),
        SemanticPipelineKey::TypestateFinding(id) => {
            key("semantic_typestate_finding").text(id).finish()
        }
        SemanticPipelineKey::TypestateWitness(id) => {
            key("semantic_typestate_witness").text(id).finish()
        }
        SemanticPipelineKey::FlowEndpoint(id) => key("semantic_flow_endpoint").text(id).finish(),
        SemanticPipelineKey::FlowWitness(id) => key("semantic_flow_witness").text(id).finish(),
        SemanticPipelineKey::AbsentMemberWitness(id) => {
            key("semantic_absent_member_witness").text(id).finish()
        }
        SemanticPipelineKey::TaintFinding(id) => key("semantic_taint_finding").text(id).finish(),
        SemanticPipelineKey::RustMarkerImpl(id) => {
            key("semantic_rust_marker_impl").text(id).finish()
        }
        SemanticPipelineKey::RustPointerFinding(id) => {
            key("semantic_rust_pointer_finding").text(id).finish()
        }
    }
}

/// One rendered row's evidence, projected onto values that survive
/// serialization and a change of workspace root.
///
/// This is `DetailedCodeQueryEvidence` with two changes. The `ProjectFile` of
/// every level becomes the workspace-relative path it denotes, because a
/// `ProjectFile` carries an absolute root and a unit produced under one root
/// is reused under another. `decorated_parameter` is dropped: it is
/// runtime-only semantic identity, documented as outside the serializable row
/// model, which is why a plan carrying it classifies as `Whole`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnitRowEvidence {
    pub domain: DetailedCodeQueryDomain,
    pub key: DetailedCodeQueryKey,
    pub rel_path: Box<str>,
    pub byte_span: Option<std::ops::Range<usize>>,
    pub stable_owner_candidate: Option<CodeQueryStableOwnerCandidate>,
    pub identities: UnitRowIdentities,
    pub source_slice_sha256: Option<[u8; 32]>,
    pub provenance: Vec<UnitRowProvenance>,
}

/// One provenance trace of a row, projected like its evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnitRowProvenance {
    pub branch: Vec<usize>,
    pub seed: UnitRowProvenanceRef,
    pub steps: Vec<UnitRowProvenanceStep>,
}

/// One step of a provenance trace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnitRowProvenanceStep {
    pub op: String,
    pub result: UnitRowProvenanceRef,
    pub via: Option<UnitRowProvenanceRef>,
}

/// One value a provenance trace passed through.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnitRowProvenanceRef {
    pub domain: DetailedCodeQueryDomain,
    pub key: DetailedCodeQueryKey,
    pub rel_path: Box<str>,
    pub byte_span: Option<std::ops::Range<usize>>,
    pub display_range: Option<CodeQueryRange>,
    pub identities: UnitRowIdentities,
    pub source_slice_sha256: Option<[u8; 32]>,
}

/// The provenance identities a row or trace value carries.
// Adjacently tagged rather than internally tagged like its siblings: two of
// these variants are newtypes over an optional, and an internally tagged
// newtype variant containing an optional has no map form to write the tag
// into. The alternative -- giving those two variants a named field -- would
// rename the same value at twenty call sites to change one serialization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "identities", content = "identity", rename_all = "snake_case")]
pub enum UnitRowIdentities {
    None,
    Primary(Option<UnitRowIdentityCandidate>),
    ReferenceTarget(Option<UnitRowIdentityCandidate>),
    Call {
        caller: Option<UnitRowIdentityCandidate>,
        callee: Option<UnitRowIdentityCandidate>,
    },
}

/// One stable owner candidate and the file it was found in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnitRowIdentityCandidate {
    pub rel_path: Box<str>,
    pub candidate: CodeQueryStableOwnerCandidate,
}

fn project_provenance_ref_fields(
    domain: DetailedCodeQueryDomain,
    key: &DetailedCodeQueryKey,
    file: &ProjectFile,
    byte_span: &Option<std::ops::Range<usize>>,
    display_range: Option<CodeQueryRange>,
    identities: &DetailedCodeQueryProvenanceIdentities,
    source_slice_sha256: Option<[u8; 32]>,
) -> UnitRowProvenanceRef {
    UnitRowProvenanceRef {
        domain,
        key: key.clone(),
        rel_path: Box::from(rel_path_string(file).as_str()),
        byte_span: byte_span.clone(),
        display_range,
        identities: UnitRowIdentities::project(identities),
        source_slice_sha256,
    }
}

#[allow(clippy::too_many_arguments)]
fn detailed_provenance_ref_fields(
    domain: DetailedCodeQueryDomain,
    key: &DetailedCodeQueryKey,
    rel_path: &str,
    byte_span: &Option<std::ops::Range<usize>>,
    display_range: Option<CodeQueryRange>,
    identities: &UnitRowIdentities,
    source_slice_sha256: Option<[u8; 32]>,
    root: &Path,
) -> DetailedCodeQueryProvenanceRefEvidence {
    DetailedCodeQueryProvenanceRefEvidence {
        domain,
        key: key.clone(),
        file: ProjectFile::new(root, Path::new(rel_path)),
        byte_span: byte_span.clone(),
        display_range,
        identities: identities.clone().into_detailed(root),
        source_slice_sha256,
    }
}

impl UnitRowEvidence {
    /// Project one execution's evidence row.
    pub fn project(evidence: &DetailedCodeQueryEvidence) -> Self {
        let reference = project_provenance_ref_fields(
            evidence.domain,
            &evidence.key,
            &evidence.file,
            &evidence.byte_span,
            None,
            &evidence.identities,
            evidence.source_slice_sha256,
        );
        Self {
            domain: reference.domain,
            key: reference.key,
            rel_path: reference.rel_path,
            byte_span: reference.byte_span,
            stable_owner_candidate: evidence.stable_owner_candidate.clone(),
            identities: reference.identities,
            source_slice_sha256: reference.source_slice_sha256,
            provenance: evidence
                .provenance
                .iter()
                .map(UnitRowProvenance::project)
                .collect(),
        }
    }

    /// Rebuild the executor's evidence row against a workspace root.
    ///
    /// `decorated_parameter` is always `None`: a plan whose rows need it is
    /// never partitioned, so no unit row ever carried one to lose.
    pub fn to_detailed(&self, root: &Path, result_index: usize) -> DetailedCodeQueryEvidence {
        let reference = detailed_provenance_ref_fields(
            self.domain,
            &self.key,
            &self.rel_path,
            &self.byte_span,
            None,
            &self.identities,
            self.source_slice_sha256,
            root,
        );
        DetailedCodeQueryEvidence {
            result_index,
            domain: reference.domain,
            key: reference.key,
            file: reference.file,
            byte_span: reference.byte_span,
            stable_owner_candidate: self.stable_owner_candidate.clone(),
            identities: reference.identities,
            source_slice_sha256: reference.source_slice_sha256,
            provenance: self
                .provenance
                .iter()
                .map(|provenance| provenance.to_detailed(root))
                .collect(),
            decorated_parameter: None,
            runtime_keyed_read: None,
        }
    }
}

impl UnitRowProvenance {
    /// Project one execution's provenance trace.
    pub fn project(provenance: &DetailedCodeQueryProvenanceEvidence) -> Self {
        let (branch, seed, steps) = project_provenance_trace(
            &provenance.branch,
            &provenance.seed,
            provenance.steps.iter(),
            UnitRowProvenanceRef::project,
            |step| UnitRowProvenanceStep {
                op: step.op.clone(),
                result: UnitRowProvenanceRef::project(&step.result),
                via: step.via.as_ref().map(UnitRowProvenanceRef::project),
            },
        );
        Self {
            branch,
            seed,
            steps,
        }
    }

    fn to_detailed(&self, root: &Path) -> DetailedCodeQueryProvenanceEvidence {
        DetailedCodeQueryProvenanceEvidence {
            branch: self.branch.clone(),
            seed: self.seed.to_detailed(root),
            steps: self
                .steps
                .iter()
                .map(|step| DetailedCodeQueryProvenanceStepEvidence {
                    op: step.op.clone(),
                    result: step.result.to_detailed(root),
                    via: step.via.as_ref().map(|via| via.to_detailed(root)),
                })
                .collect(),
        }
    }
}

fn project_provenance_trace<Seed, Step, ProjectedSeed, ProjectedStep>(
    branch: &[usize],
    seed: &Seed,
    steps: impl Iterator<Item = Step>,
    project_seed: impl Fn(&Seed) -> ProjectedSeed,
    project_step: impl FnMut(Step) -> ProjectedStep,
) -> (Vec<usize>, ProjectedSeed, Vec<ProjectedStep>) {
    (
        branch.to_vec(),
        project_seed(seed),
        steps.map(project_step).collect(),
    )
}

impl UnitRowProvenanceRef {
    fn project(reference: &DetailedCodeQueryProvenanceRefEvidence) -> Self {
        project_provenance_ref_fields(
            reference.domain,
            &reference.key,
            &reference.file,
            &reference.byte_span,
            reference.display_range,
            &reference.identities,
            reference.source_slice_sha256,
        )
    }

    fn to_detailed(&self, root: &Path) -> DetailedCodeQueryProvenanceRefEvidence {
        detailed_provenance_ref_fields(
            self.domain,
            &self.key,
            &self.rel_path,
            &self.byte_span,
            self.display_range,
            &self.identities,
            self.source_slice_sha256,
            root,
        )
    }
}

impl UnitRowIdentities {
    fn project(identities: &DetailedCodeQueryProvenanceIdentities) -> Self {
        let candidate = |candidate: &Option<DetailedCodeQueryIdentityCandidate>| {
            candidate
                .as_ref()
                .map(|candidate| UnitRowIdentityCandidate {
                    rel_path: Box::from(rel_path_string(&candidate.file).as_str()),
                    candidate: candidate.candidate.clone(),
                })
        };
        match identities {
            DetailedCodeQueryProvenanceIdentities::None => Self::None,
            DetailedCodeQueryProvenanceIdentities::Primary(value) => {
                Self::Primary(candidate(value))
            }
            DetailedCodeQueryProvenanceIdentities::ReferenceTarget(value) => {
                Self::ReferenceTarget(candidate(value))
            }
            DetailedCodeQueryProvenanceIdentities::Call { caller, callee } => Self::Call {
                caller: candidate(caller),
                callee: candidate(callee),
            },
        }
    }

    fn into_detailed(self, root: &Path) -> DetailedCodeQueryProvenanceIdentities {
        let candidate = |candidate: Option<UnitRowIdentityCandidate>| {
            candidate.map(|candidate| DetailedCodeQueryIdentityCandidate {
                file: ProjectFile::new(root, Path::new(candidate.rel_path.as_ref())),
                candidate: candidate.candidate,
            })
        };
        match self {
            Self::None => DetailedCodeQueryProvenanceIdentities::None,
            Self::Primary(value) => {
                DetailedCodeQueryProvenanceIdentities::Primary(candidate(value))
            }
            Self::ReferenceTarget(value) => {
                DetailedCodeQueryProvenanceIdentities::ReferenceTarget(candidate(value))
            }
            Self::Call { caller, callee } => DetailedCodeQueryProvenanceIdentities::Call {
                caller: candidate(caller),
                callee: candidate(callee),
            },
        }
    }
}

/// One rendered row's public value and provenance, projected onto exactly the
/// fields the policy match adapter reads.
///
/// `CodeQueryResultItem` cannot round-trip: its value tree spells 196 static
/// labels across 118 public wire types, so a `Deserialize` implementation
/// would mean re-interning every one of them. The adapter reads a small,
/// closed subset of that tree -- a domain, a path, a display range, and a
/// handful of per-family identity and status fields -- so a unit's product
/// carries that subset and nothing else. The projection is exhaustive by
/// construction: a new row family cannot reach the adapter as a silently
/// unsupported row.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UnitRowItem {
    pub domain: DetailedCodeQueryDomain,
    pub path: Box<str>,
    pub range: Option<CodeQueryRange>,
    /// The row-level semantic evidence object exactly as live query transports
    /// publish it. Absent for row families whose status fields describe a
    /// different domain fact rather than analysis evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<CodeQuerySemanticEvidence>,
    /// What the analysis that produced this row proves about the rows of the
    /// same partition it did not return, and which partition that is (#3205).
    ///
    /// Carried unconditionally rather than derived from `fields`: a query
    /// projection may drop the status column the coverage was derived from, and
    /// a relation whose projection hid its solver outcome must not read as
    /// exhaustive. Absent for a family that runs no solver, whose coverage is
    /// the executed query's own envelope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coverage: Option<CodeQueryRowCoverage>,
    /// Every scalar the row's domain declares and this row carries, in the
    /// domain's own declaration order.
    ///
    /// Together with `unknown_fields`, this is the row's whole addressable
    /// surface -- exactly what [`CodeQueryRowRef::field`] answers. It is carried because a relational
    /// assertion reads its bindings' rows by field name, and it reads them
    /// from the merged product of units rather than from a live execution.
    /// Optional fields the row does not carry are absent rather than null, the
    /// same answer the live row gives.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<UnitRowField>,
    /// Projected output names in schema order. Empty means the domain's native
    /// public schema; a non-empty list is the exact query projection schema.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub projected_field_names: Vec<Box<str>>,
    /// Registered fields whose evidence is unavailable. Preserve this across
    /// unit reuse so a cached unknown cannot become an ordinary absent value.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unknown_fields: Vec<UnitRowUnknownField>,
    /// The per-family fields the policy match adapter reads, or `None` for an
    /// analysis-only row the adapter refuses before reading any field of it.
    pub terminal: Option<UnitRowItemTerminal>,
    pub provenance: Vec<UnitRowItemProvenance>,
    pub provenance_truncated: bool,
}

impl UnitRowItem {
    /// Project one rendered row.
    pub fn project(item: &CodeQueryResultItem) -> Self {
        let domain = item.value.detailed_domain();
        let row = item.value.row();
        let mut fields = Vec::new();
        let mut unknown_fields = Vec::new();
        let projected_field_names = item
            .row_projection
            .iter()
            .map(|column| boxed(&column.name))
            .collect::<Vec<_>>();
        let columns = if item.row_projection.is_empty() {
            domain
                .row_fields()
                .iter()
                .map(|field| (field.name, field.name))
                .collect::<Vec<_>>()
        } else {
            item.row_projection
                .iter()
                .map(|column| (column.source.as_str(), column.name.as_str()))
                .collect()
        };
        for (source, name) in columns {
            match row.field(source) {
                Ok(Some(value)) => fields.push(UnitRowField {
                    name: boxed(name),
                    value: UnitRowScalar::project(value),
                }),
                Ok(None) => {}
                Err(error) => unknown_fields.push(UnitRowUnknownField {
                    name: boxed(name),
                    reason: error
                        .unknown_reason()
                        .expect("registered fields fail only for unavailable evidence"),
                }),
            }
        }
        Self {
            domain,
            path: boxed(row_path(&item.value)),
            range: item.value.display_range(),
            evidence: row_semantic_evidence(&item.value).cloned(),
            coverage: item.value.row_coverage(),
            fields,
            projected_field_names,
            unknown_fields,
            terminal: UnitRowItemTerminal::project(&item.value),
            provenance: item
                .provenance
                .iter()
                .map(UnitRowItemProvenance::project)
                .collect(),
            provenance_truncated: item.provenance_truncated,
        }
    }

    /// One scalar of this row, by the field name its domain declares.
    ///
    /// The same answer [`CodeQueryRowRef::field`] gives for the row this was
    /// projected from: `Err` for an unregistered field or unavailable evidence,
    /// and `Ok(None)` for a genuinely absent optional value. Unknown evidence
    /// carries a typed reason and must not be interpreted as null.
    pub fn field(
        &self,
        name: &str,
    ) -> Result<Option<CodeQueryRowScalarRef<'_>>, CodeQueryRowFieldError> {
        let registered = if self.projected_field_names.is_empty() {
            self.domain
                .row_fields()
                .iter()
                .any(|field| field.name == name)
        } else {
            self.projected_field_names
                .iter()
                .any(|field| field.as_ref() == name)
        };
        if !registered {
            return Err(CodeQueryRowFieldError::unregistered(self.domain, name));
        }
        if let Some(field) = self
            .unknown_fields
            .iter()
            .find(|field| field.name.as_ref() == name)
        {
            return Err(CodeQueryRowFieldError::unknown(
                self.domain,
                name,
                field.reason,
            ));
        }
        Ok(self
            .fields
            .iter()
            .find(|field| field.name.as_ref() == name)
            .map(|field| field.value.borrowed()))
    }
}

fn row_semantic_evidence(value: &CodeQueryResultValue) -> Option<&CodeQuerySemanticEvidence> {
    match value {
        CodeQueryResultValue::Procedure { value } => Some(&value.evidence),
        CodeQueryResultValue::ProgramPoint { value } => Some(&value.evidence),
        CodeQueryResultValue::ControlEdge { value } => Some(&value.evidence),
        CodeQueryResultValue::TypestateWitness { value } => Some(&value.evidence),
        CodeQueryResultValue::FlowWitness { value } => Some(&value.evidence),
        CodeQueryResultValue::AbsentMemberWitness { value } => Some(&value.evidence),
        CodeQueryResultValue::TaintFinding { value } => Some(&value.evidence),
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnitRowUnknownField {
    pub name: Box<str>,
    pub reason: CodeQueryRowFieldUnknownReason,
}

/// One scalar of a row's addressable field surface, owned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnitRowField {
    pub name: Box<str>,
    pub value: UnitRowScalar,
}

/// The owned form of [`CodeQueryRowScalarRef`].
///
/// The borrowed form is what a live row answers with and what every reader
/// consumes; this is the same value in a shape that survives serialization,
/// and the two convert without loss in either direction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "scalar", content = "value", rename_all = "snake_case")]
pub enum UnitRowScalar {
    StableId(Box<str>),
    String(Box<str>),
    StringList(Vec<String>),
    IntegerList(Vec<u64>),
    Integer(u64),
    Boolean(bool),
    ConstrainedEnum(Box<str>),
    DeclarationIdentity(Box<str>),
}

impl UnitRowScalar {
    fn project(value: CodeQueryRowScalarRef<'_>) -> Self {
        match value {
            CodeQueryRowScalarRef::StableId(value) => Self::StableId(boxed(value)),
            CodeQueryRowScalarRef::String(value) => Self::String(boxed(value)),
            CodeQueryRowScalarRef::StringList(value) => Self::StringList(value.to_vec()),
            CodeQueryRowScalarRef::IntegerList(value) => Self::IntegerList(value.to_vec()),
            CodeQueryRowScalarRef::Integer(value) => Self::Integer(value),
            CodeQueryRowScalarRef::Boolean(value) => Self::Boolean(value),
            CodeQueryRowScalarRef::ConstrainedEnum(value) => Self::ConstrainedEnum(boxed(value)),
            CodeQueryRowScalarRef::DeclarationIdentity(value) => {
                Self::DeclarationIdentity(boxed(value))
            }
        }
    }

    fn borrowed(&self) -> CodeQueryRowScalarRef<'_> {
        match self {
            Self::StableId(value) => CodeQueryRowScalarRef::StableId(value),
            Self::String(value) => CodeQueryRowScalarRef::String(value),
            Self::StringList(value) => CodeQueryRowScalarRef::StringList(value),
            Self::IntegerList(value) => CodeQueryRowScalarRef::IntegerList(value),
            Self::Integer(value) => CodeQueryRowScalarRef::Integer(*value),
            Self::Boolean(value) => CodeQueryRowScalarRef::Boolean(*value),
            Self::ConstrainedEnum(value) => CodeQueryRowScalarRef::ConstrainedEnum(value),
            Self::DeclarationIdentity(value) => CodeQueryRowScalarRef::DeclarationIdentity(value),
        }
    }
}

/// The per-family fields a presented row carries beyond its domain, path and
/// display range.
///
/// `SourcePosition` is the shared case: a row whose presentation is decided by
/// its domain, path and range alone, and which no terminal result shape names.
/// An analysis-only row gets a source-position terminal only when it has an
/// exact display range; the policy adapter also verifies its paired evidence
/// before using that range as a finding anchor.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "terminal_kind", rename_all = "snake_case")]
pub enum UnitRowItemTerminal {
    PythonHierarchyFact {
        id: String,
        root_id: String,
        declaration_id: Option<String>,
        owner_id: Option<String>,
        target_id: Option<String>,
        target_owner_id: Option<String>,
        fact_kind: String,
        outcome: String,
        coverage: String,
        reason: Option<String>,
        ancestry_basis: crate::analyzer::usages::python_class_hierarchy::PythonAncestryBasis,
    },
    SourcePosition,
    GenerationSite {
        id: Box<str>,
        ast_id: Option<Box<str>>,
        kind: Box<str>,
    },
    /// A cross-domain row (#3284). The row itself is anchored at its code
    /// row (or at the configuration fact of a configuration witness); the
    /// configuration fact's own exact anchor travels here so a correlated
    /// finding keeps both sides' evidence.
    CrossDomain {
        operator: Box<str>,
        domain: Box<str>,
        configuration: Option<UnitRowConfigurationAnchor>,
        dependency_mitigation: Option<Box<UnitRowDependencyMitigation>>,
    },
    StructuralMatch {
        kind: Box<str>,
        /// The matched node's own range, which is where an assertion subject
        /// row is anchored. Absent when the match carried no node range.
        node_range: Option<CodeQueryRange>,
        /// Every capture the pattern bound, which is the whole of an assertion
        /// subject's join: an assert names a capture, and the capture's AST id
        /// is what the row families are joined on.
        captures: Vec<UnitRowCapture>,
        /// Why the selecting language relation is only a heuristic, when it
        /// is one; the match adapter then reports the finding as possible.
        heuristic: Option<Box<str>>,
    },
    Declaration {
        kind: Box<str>,
        fq_name: Box<str>,
    },
    Binding {
        id: Box<str>,
        ast_id: Option<Box<str>>,
        name: Box<str>,
        kind: Box<str>,
    },
    Occurrence {
        id: Box<str>,
        ast_id: Box<str>,
        class: Box<str>,
        role: Box<str>,
        namespace: Box<str>,
    },
    File,
    ReferenceSite {
        proof: Box<str>,
        target_fq_name: Box<str>,
        usage_kind: Box<str>,
        reference_facets: UnitRowReferenceFacets,
    },
    ReferenceEdge {
        id: Box<str>,
        reference_facets: UnitRowReferenceFacets,
        proof: Box<str>,
        usage_kind: Box<str>,
        site_class: Box<str>,
        owner_relation: Box<str>,
        edge_provenance: Box<str>,
        generation: u64,
    },
    CallSite {
        proof: Box<str>,
        caller_fq_name: Box<str>,
        callee_fq_name: Box<str>,
    },
    ExpressionSite {
        input_kind: Box<str>,
        parameter_index: Option<usize>,
        parameter_name: Option<Box<str>>,
    },
    DecoratedParameter {
        id: Box<str>,
        parameter_id: Box<str>,
        terminal: bool,
        completion: Box<str>,
        coverage: Box<str>,
    },
    JsxAttributeValue {
        id: Box<str>,
        ast_id: Box<str>,
        element_identity: Box<str>,
        coverage: Box<str>,
        reason: Option<Box<str>>,
    },
    FieldWriteValue {
        id: Box<str>,
        assignment_ast_id: Box<str>,
        rhs_ast_id: Box<str>,
        receiver_identity_id: Box<str>,
        member_target_id: Box<str>,
        proof: Box<str>,
        completeness: Box<str>,
        coverage: Box<str>,
    },
    CallResult {
        proof: Box<str>,
    },
    /// A call-effect row selected from a structural seed. It keeps the
    /// effect-domain terminal distinct while exposing the seed captures to
    /// assertion policies that join loop/input evidence after filtering.
    CallEffect {
        captures: Vec<UnitRowCapture>,
    },
    ResultSubjectUse {
        proof: Box<str>,
        completeness: Box<str>,
        outcome: Box<str>,
    },
    AbsentMemberFinding {
        also_fails_at: Vec<UnitRowLocation>,
    },
}

/// Exact source location retained with an absent-member policy row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnitRowLocation {
    pub path: Box<str>,
    pub range: CodeQueryRange,
    pub start_byte: u64,
    pub end_byte: u64,
}

/// One capture of a structural match, projected onto the fields a policy joins
/// on.
///
/// The captured text and its start line are not carried: nothing that consumes
/// a projected row reads them, and a row's own evidence already locates it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UnitRowCapture {
    pub name: Box<str>,
    pub ast_id: Option<Box<str>>,
    /// The captured node's normalized kind, which says whether the capture is
    /// an identifier occurrence at all.
    pub kind: Option<Box<str>>,
    /// The captured node's display region, which is what a containment assert
    /// compares a declaring scope against.
    pub range: Option<CodeQueryRange>,
}

impl UnitRowCapture {
    fn project(capture: &CodeQueryCapture) -> Self {
        Self {
            name: boxed(&capture.name),
            ast_id: capture.ast_id.as_deref().map(boxed),
            kind: capture.kind.map(boxed),
            range: capture.range,
        }
    }
}

/// The exact anchor of the configuration fact a cross-domain row carries.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UnitRowConfigurationAnchor {
    pub path: Box<str>,
    pub start_byte: usize,
    pub end_byte: usize,
    pub range: CodeQueryRange,
}

/// Query-lifetime/persisted unit projection of the dependency relation proof.
/// This carries explicit reviewed mapping and bounded effective-file evidence,
/// never a runtime safety assertion.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UnitRowDependencyMitigation {
    pub dependency_id: String,
    pub owner: String,
    pub mapping_id: String,
    pub mitigated: bool,
    pub effective: Option<serde_json::Value>,
    pub contributors: Vec<UnitRowConfigurationAnchor>,
}

/// Borrow a public row string as the projection's owned form.
fn boxed(value: &str) -> Box<str> {
    Box::from(value)
}

impl UnitRowItemTerminal {
    fn project(value: &CodeQueryResultValue) -> Option<Self> {
        let terminal = match value {
            CodeQueryResultValue::PythonHierarchyFact { value } => Self::PythonHierarchyFact {
                id: value.id.clone(),
                root_id: value.root_id.clone(),
                declaration_id: value.declaration_id.clone(),
                owner_id: value.owner_id.clone(),
                target_id: value.target_id.clone(),
                target_owner_id: value.target_owner_id.clone(),
                fact_kind: value.fact_kind.to_owned(),
                outcome: value.outcome.to_owned(),
                coverage: value.coverage.to_owned(),
                reason: value.reason.map(str::to_owned),
                ancestry_basis: value.ancestry_basis.clone(),
            },
            CodeQueryResultValue::StructuralMatch { value } => {
                UnitRowItemTerminal::StructuralMatch {
                    kind: boxed(value.kind),
                    node_range: value.node_range,
                    captures: value.captures.iter().map(UnitRowCapture::project).collect(),
                    heuristic: value.heuristic.map(boxed),
                }
            }
            CodeQueryResultValue::Declaration { value } => UnitRowItemTerminal::Declaration {
                kind: boxed(value.kind),
                fq_name: boxed(&value.fq_name),
            },
            CodeQueryResultValue::Binding { value } => UnitRowItemTerminal::Binding {
                id: boxed(&value.id),
                ast_id: value.ast_id.as_deref().map(boxed),
                name: boxed(&value.name),
                kind: boxed(value.kind),
            },
            CodeQueryResultValue::Occurrence { value } => UnitRowItemTerminal::Occurrence {
                id: boxed(&value.id),
                ast_id: boxed(&value.ast_id),
                class: boxed(value.class),
                role: boxed(value.role),
                namespace: boxed(value.namespace),
            },
            CodeQueryResultValue::File { .. } => UnitRowItemTerminal::File,
            CodeQueryResultValue::GenerationSite { value } => UnitRowItemTerminal::GenerationSite {
                id: boxed(&value.id),
                ast_id: value.ast_id.as_deref().map(boxed),
                kind: boxed(value.kind),
            },
            CodeQueryResultValue::ReferenceSite { value } => UnitRowItemTerminal::ReferenceSite {
                proof: boxed(value.proof),
                target_fq_name: boxed(&value.target.fq_name),
                usage_kind: boxed(value.usage_kind),
                reference_facets: (&value.reference_facets).into(),
            },
            CodeQueryResultValue::ReferenceEdge { value } => UnitRowItemTerminal::ReferenceEdge {
                id: boxed(&value.id),
                reference_facets: (&value.reference_facets).into(),
                proof: boxed(value.proof),
                usage_kind: boxed(value.usage_kind),
                site_class: boxed(value.site_class),
                owner_relation: boxed(value.owner_relation),
                edge_provenance: boxed(value.provenance),
                generation: value.generation,
            },
            CodeQueryResultValue::CallSite { value } => UnitRowItemTerminal::CallSite {
                proof: boxed(value.proof),
                caller_fq_name: boxed(&value.caller.fq_name),
                callee_fq_name: boxed(value.callee.as_ref().map_or(
                    value.target_fq_name.as_deref().unwrap_or("<unresolved>"),
                    |callee| callee.fq_name.as_str(),
                )),
            },
            CodeQueryResultValue::ExpressionSite { value } => UnitRowItemTerminal::ExpressionSite {
                input_kind: boxed(value.input_kind),
                parameter_index: value.parameter_index,
                parameter_name: value.parameter_name.as_deref().map(boxed),
            },
            CodeQueryResultValue::DecoratedParameter { value } => {
                UnitRowItemTerminal::DecoratedParameter {
                    id: boxed(&value.id),
                    parameter_id: boxed(&value.parameter_id),
                    terminal: value.terminal,
                    completion: boxed(value.completion),
                    coverage: boxed(value.coverage),
                }
            }
            CodeQueryResultValue::JsxAttributeValue { value } => {
                UnitRowItemTerminal::JsxAttributeValue {
                    id: boxed(&value.id),
                    ast_id: boxed(&value.ast_id),
                    element_identity: boxed(value.element_identity),
                    coverage: boxed(value.coverage),
                    reason: value.reason.map(boxed),
                }
            }
            CodeQueryResultValue::FieldWriteValue { value } => {
                UnitRowItemTerminal::FieldWriteValue {
                    id: boxed(&value.id),
                    assignment_ast_id: boxed(&value.assignment_ast_id),
                    rhs_ast_id: boxed(&value.rhs_ast_id),
                    receiver_identity_id: boxed(&value.receiver_identity_id),
                    member_target_id: boxed(&value.member_target_id),
                    proof: boxed(value.proof),
                    completeness: boxed(value.completeness),
                    coverage: boxed(value.coverage),
                }
            }
            CodeQueryResultValue::RuntimeKeyedReadValue { .. } => {
                UnitRowItemTerminal::SourcePosition
            }
            CodeQueryResultValue::CallResult { value } => UnitRowItemTerminal::CallResult {
                proof: boxed(value.proof),
            },
            CodeQueryResultValue::CallEffect { value } => {
                if value.captures.is_empty() {
                    return None;
                }
                UnitRowItemTerminal::CallEffect {
                    captures: value.captures.iter().map(UnitRowCapture::project).collect(),
                }
            }
            CodeQueryResultValue::ResultSubjectUse { value } => {
                UnitRowItemTerminal::ResultSubjectUse {
                    proof: boxed(value.proof),
                    completeness: boxed(value.completeness),
                    outcome: boxed(value.outcome.label()),
                }
            }
            CodeQueryResultValue::AbsentMemberFinding { value } => {
                UnitRowItemTerminal::AbsentMemberFinding {
                    also_fails_at: value
                        .also_fails_at_locations
                        .iter()
                        .map(|location| UnitRowLocation {
                            path: boxed(&location.path),
                            range: location.range,
                            start_byte: u64::try_from(location.start_byte)
                                .expect("source byte offsets fit in u64"),
                            end_byte: u64::try_from(location.end_byte)
                                .expect("source byte offsets fit in u64"),
                        })
                        .collect(),
                }
            }
            CodeQueryResultValue::LexicalScope { .. }
            | CodeQueryResultValue::ResolutionCandidate { .. }
            | CodeQueryResultValue::StateEvent { .. }
            | CodeQueryResultValue::BindingInitializerCall { .. }
            | CodeQueryResultValue::RewritePath { .. }
            | CodeQueryResultValue::FlowRelation { .. }
            | CodeQueryResultValue::ControlRelation { .. }
            | CodeQueryResultValue::BranchRelation { .. }
            | CodeQueryResultValue::CppExpression { .. }
            | CodeQueryResultValue::LoopRelation { .. }
            | CodeQueryResultValue::FailureHandlerState { .. }
            | CodeQueryResultValue::StatementReachability { .. }
            | CodeQueryResultValue::PendingCleanupFlow { .. }
            | CodeQueryResultValue::PythonRuleFact { .. }
            | CodeQueryResultValue::RustMarkerImpl { .. }
            | CodeQueryResultValue::RustPointerFinding { .. }
            | CodeQueryResultValue::Guard { .. }
            | CodeQueryResultValue::QualifiedPath { .. }
            | CodeQueryResultValue::Export { .. }
            | CodeQueryResultValue::DeclarationState { .. }
            | CodeQueryResultValue::PathSegment { .. }
            | CodeQueryResultValue::SourceSet { .. }
            | CodeQueryResultValue::BuildTarget { .. }
            | CodeQueryResultValue::TopologyEdge { .. }
            | CodeQueryResultValue::BuildConfiguration { .. }
            | CodeQueryResultValue::DependencyEvidence { .. }
            | CodeQueryResultValue::ConfigurationFact { .. } => UnitRowItemTerminal::SourcePosition,
            CodeQueryResultValue::CrossDomain { value } => UnitRowItemTerminal::CrossDomain {
                operator: boxed(value.operator),
                domain: boxed(value.domain),
                dependency_mitigation: value.mitigated.map(|mitigated| {
                    Box::new(UnitRowDependencyMitigation {
                        dependency_id: value
                            .dependency_id
                            .clone()
                            .expect("dependency mitigation witnesses carry dependency identity"),
                        owner: value
                            .owner
                            .clone()
                            .expect("dependency mitigation witnesses carry owner mapping"),
                        mapping_id: value
                            .mapping_id
                            .clone()
                            .expect("dependency mitigation witnesses carry mapping identity"),
                        mitigated,
                        effective: value.effective_configuration.as_ref().map(|effective| {
                            serde_json::to_value(effective)
                                .expect("canonical effective configuration serializes")
                        }),
                        contributors: value
                            .configuration_contributors
                            .iter()
                            .map(|fact| UnitRowConfigurationAnchor {
                                path: boxed(&fact.path),
                                start_byte: fact.start_byte,
                                end_byte: fact.end_byte,
                                range: fact.range,
                            })
                            .collect(),
                    })
                }),
                configuration: value.configuration.as_ref().map(|configuration| {
                    UnitRowConfigurationAnchor {
                        path: boxed(&configuration.path),
                        start_byte: configuration.start_byte,
                        end_byte: configuration.end_byte,
                        range: configuration.range,
                    }
                }),
            },
            CodeQueryResultValue::Procedure { .. }
            | CodeQueryResultValue::ProgramPoint { .. }
            | CodeQueryResultValue::ControlEdge { .. }
            | CodeQueryResultValue::TypestateFinding { .. }
            | CodeQueryResultValue::TypestateWitness { .. }
            | CodeQueryResultValue::FlowEndpoint { .. }
            | CodeQueryResultValue::FlowWitness { .. }
            | CodeQueryResultValue::AbsentMemberWitness { .. }
            | CodeQueryResultValue::TaintFinding { .. }
            | CodeQueryResultValue::ClassSetRow { .. }
            | CodeQueryResultValue::ReceiverAnalysis { .. }
            | CodeQueryResultValue::MemberTargetAnalysis { .. }
            | CodeQueryResultValue::ReceiverOutcome { .. }
            | CodeQueryResultValue::ReceiverEvidence { .. }
            | CodeQueryResultValue::PointsToCandidate { .. }
            | CodeQueryResultValue::CallShape { .. }
            | CodeQueryResultValue::CallArgumentGroup { .. }
            | CodeQueryResultValue::CallArgument { .. }
            | CodeQueryResultValue::CallBinding { .. }
            | CodeQueryResultValue::CallResultContract { .. }
            | CodeQueryResultValue::CallResultObligation { .. }
            | CodeQueryResultValue::ResultContractUse { .. }
            | CodeQueryResultValue::ResultContractFailureUse { .. }
            | CodeQueryResultValue::NilnessOperation { .. }
            | CodeQueryResultValue::SwitchCoverage { .. }
            | CodeQueryResultValue::AssignmentRelation { .. }
            | CodeQueryResultValue::DetachedTaskTransfer { .. }
            | CodeQueryResultValue::ProcedureEffect { .. }
            | CodeQueryResultValue::CallableSignature { .. }
            | CodeQueryResultValue::LiteralOccurrence { .. }
            | CodeQueryResultValue::CallableMetrics { .. }
            | CodeQueryResultValue::SignatureParameter { .. }
            | CodeQueryResultValue::CallableApplicability { .. }
            | CodeQueryResultValue::OverloadSelection { .. }
            | CodeQueryResultValue::MemberSelection { .. }
            | CodeQueryResultValue::CandidateHop { .. }
            | CodeQueryResultValue::DispatchOutcome { .. }
            | CodeQueryResultValue::DispatchTarget { .. }
            | CodeQueryResultValue::MemberFamily { .. }
            | CodeQueryResultValue::MemberFamilyEdge { .. } => {
                if value.display_range().is_some() {
                    UnitRowItemTerminal::SourcePosition
                } else {
                    return None;
                }
            }
        };
        Some(terminal)
    }
}

/// The path a presented row's own terminal presentation compares against the
/// evidence file.
///
/// A topology row's claim is about the build file it read, so that is its
/// path; every other family spells its own source file. Exhaustive, so a new
/// row family must state which of the two it is.
fn row_path(value: &CodeQueryResultValue) -> &str {
    match value {
        CodeQueryResultValue::StructuralMatch { value } => &value.path,
        CodeQueryResultValue::Declaration { value } => &value.path,
        CodeQueryResultValue::File { value } => &value.path,
        CodeQueryResultValue::ReferenceSite { value } => &value.path,
        CodeQueryResultValue::CallSite { value } => &value.path,
        CodeQueryResultValue::ExpressionSite { value } => &value.path,
        CodeQueryResultValue::DecoratedParameter { value } => &value.path,
        CodeQueryResultValue::JsxAttributeValue { value } => &value.path,
        CodeQueryResultValue::FieldWriteValue { value } => &value.path,
        CodeQueryResultValue::RuntimeKeyedReadValue { value } => &value.path,
        CodeQueryResultValue::CallResult { value } => &value.path,
        CodeQueryResultValue::Occurrence { value } => &value.path,
        CodeQueryResultValue::LexicalScope { value } => &value.path,
        CodeQueryResultValue::Binding { value } => &value.path,
        CodeQueryResultValue::ResolutionCandidate { value } => &value.path,
        CodeQueryResultValue::GenerationSite { value } => &value.path,
        CodeQueryResultValue::StateEvent { value } => &value.path,
        CodeQueryResultValue::BindingInitializerCall { value } => &value.path,
        CodeQueryResultValue::RewritePath { value } => &value.path,
        CodeQueryResultValue::FlowRelation { value } => &value.path,
        CodeQueryResultValue::ControlRelation { value } => &value.path,
        CodeQueryResultValue::BranchRelation { value } => &value.path,
        CodeQueryResultValue::CppExpression { value } => &value.path,
        CodeQueryResultValue::LoopRelation { value } => &value.path,
        CodeQueryResultValue::FailureHandlerState { value } => &value.path,
        CodeQueryResultValue::StatementReachability { value } => &value.path,
        CodeQueryResultValue::PendingCleanupFlow { value } => &value.path,
        CodeQueryResultValue::PythonRuleFact { value } => &value.path,
        CodeQueryResultValue::Guard { value } => &value.path,
        CodeQueryResultValue::ReferenceEdge { value } => &value.path,
        CodeQueryResultValue::QualifiedPath { value } => &value.path,
        CodeQueryResultValue::Export { value } => &value.path,
        CodeQueryResultValue::DeclarationState { value } => &value.path,
        CodeQueryResultValue::PathSegment { value } => &value.path,
        CodeQueryResultValue::DependencyEvidence { value } => &value.path,
        CodeQueryResultValue::ConfigurationFact { value } => &value.path,
        CodeQueryResultValue::CrossDomain { value } => &value.path,
        CodeQueryResultValue::SourceSet { value } => &value.build_file,
        CodeQueryResultValue::BuildTarget { value } => &value.build_file,
        CodeQueryResultValue::TopologyEdge { value } => &value.build_file,
        CodeQueryResultValue::BuildConfiguration { value } => &value.path,
        CodeQueryResultValue::Procedure { value } => &value.path,
        CodeQueryResultValue::ProgramPoint { value } => &value.path,
        CodeQueryResultValue::ControlEdge { value } => &value.path,
        CodeQueryResultValue::TypestateFinding { value } => &value.path,
        CodeQueryResultValue::TypestateWitness { value } => &value.path,
        CodeQueryResultValue::FlowEndpoint { value } => &value.path,
        CodeQueryResultValue::FlowWitness { value } => &value.path,
        CodeQueryResultValue::AbsentMemberWitness { value } => &value.path,
        CodeQueryResultValue::TaintFinding { value } => &value.path,
        CodeQueryResultValue::RustMarkerImpl { value } => &value.path,
        CodeQueryResultValue::RustPointerFinding { value } => &value.path,
        CodeQueryResultValue::ClassSetRow { value } => &value.file,
        CodeQueryResultValue::AbsentMemberFinding { value } => &value.file,
        CodeQueryResultValue::ReceiverAnalysis { value } => &value.path,
        CodeQueryResultValue::MemberTargetAnalysis { value } => &value.path,
        CodeQueryResultValue::ReceiverOutcome { value } => &value.path,
        CodeQueryResultValue::ReceiverEvidence { value } => &value.path,
        CodeQueryResultValue::PointsToCandidate { value } => &value.path,
        CodeQueryResultValue::CallShape { value } => &value.path,
        CodeQueryResultValue::CallArgumentGroup { value } => &value.path,
        CodeQueryResultValue::CallArgument { value } => &value.path,
        CodeQueryResultValue::CallBinding { value } => &value.path,
        CodeQueryResultValue::CallEffect { value } => &value.path,
        CodeQueryResultValue::CallResultContract { value } => &value.path,
        CodeQueryResultValue::CallResultObligation { value } => &value.path,
        CodeQueryResultValue::ResultSubjectUse { value } => &value.path,
        CodeQueryResultValue::ResultContractUse { value } => &value.path,
        CodeQueryResultValue::ResultContractFailureUse { value } => &value.path,
        CodeQueryResultValue::NilnessOperation { value } => &value.path,
        CodeQueryResultValue::SwitchCoverage { value } => &value.path,
        CodeQueryResultValue::AssignmentRelation { value } => &value.path,
        CodeQueryResultValue::DetachedTaskTransfer { value } => &value.path,
        CodeQueryResultValue::ProcedureEffect { value } => &value.path,
        CodeQueryResultValue::CallableSignature { value } => &value.path,
        CodeQueryResultValue::LiteralOccurrence { value } => &value.path,
        CodeQueryResultValue::CallableMetrics { value } => &value.path,
        CodeQueryResultValue::SignatureParameter { value } => &value.path,
        CodeQueryResultValue::CallableApplicability { value } => &value.path,
        CodeQueryResultValue::OverloadSelection { value } => &value.path,
        CodeQueryResultValue::MemberSelection { value } => &value.path,
        CodeQueryResultValue::CandidateHop { value } => &value.path,
        CodeQueryResultValue::DispatchOutcome { value } => &value.path,
        CodeQueryResultValue::DispatchTarget { value } => &value.path,
        CodeQueryResultValue::MemberFamily { value } => &value.path,
        CodeQueryResultValue::MemberFamilyEdge { value } => &value.path,
        CodeQueryResultValue::PythonHierarchyFact { value } => &value.path,
    }
}

/// One provenance trace of a rendered row, projected like the row itself.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UnitRowItemProvenance {
    pub branch: Vec<usize>,
    pub seed: UnitRowItemRef,
    pub steps: Vec<UnitRowItemProvenanceStep>,
}

/// One step of a projected provenance trace.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UnitRowItemProvenanceStep {
    pub op: Box<str>,
    pub result: UnitRowItemRef,
    pub via: Option<UnitRowItemRef>,
}

/// One value a projected provenance trace passed through.
///
/// `kind` and `path` are the two fields every reference carries and the
/// adapter reads for every family, including the ones it can only publish as
/// unsupported; `value` is the per-family payload of the arms it adapts.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UnitRowItemRef {
    pub kind: Box<str>,
    pub path: Box<str>,
    pub value: UnitRowItemRefValue,
}

/// Owned reference facets retained in unit rows and policy findings.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnitRowReferenceFacets {
    pub known: Vec<Box<str>>,
    pub undecided: Vec<Box<str>>,
}

impl From<&CodeQueryReferenceFacets> for UnitRowReferenceFacets {
    fn from(facets: &CodeQueryReferenceFacets) -> Self {
        Self {
            known: facets.known.iter().map(|label| boxed(label)).collect(),
            undecided: facets.undecided.iter().map(|label| boxed(label)).collect(),
        }
    }
}

/// The per-family fields of one projected provenance reference.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "ref", rename_all = "snake_case")]
pub enum UnitRowItemRefValue {
    PythonHierarchyFact {
        id: String,
        root_id: String,
        declaration_id: Option<String>,
        owner_id: Option<String>,
        target_id: Option<String>,
        target_owner_id: Option<String>,
        fact_kind: String,
        outcome: String,
        coverage: String,
        reason: Option<String>,
        range: CodeQueryRange,
        ancestry_basis: crate::analyzer::usages::python_class_hierarchy::PythonAncestryBasis,
    },
    Unsupported,
    StructuralMatch {
        kind: Box<str>,
        node_range: Option<CodeQueryRange>,
    },
    Binding {
        id: Box<str>,
        ast_id: Option<Box<str>>,
        name: Box<str>,
        kind: Box<str>,
        range: CodeQueryRange,
    },
    LexicalScope {
        id: Box<str>,
        ast_id: Option<Box<str>>,
        index: u32,
        range: CodeQueryRange,
    },
    Occurrence {
        id: Box<str>,
        ast_id: Box<str>,
        class: Box<str>,
        role: Box<str>,
        namespace: Box<str>,
        range: CodeQueryRange,
    },
    Declaration {
        kind: Box<str>,
        fq_name: Box<str>,
        node_range: Option<CodeQueryRange>,
    },
    File,
    GenerationSite {
        id: Box<str>,
        ast_id: Option<Box<str>>,
        kind: Box<str>,
        range: CodeQueryRange,
    },
    ReferenceSite {
        range: CodeQueryRange,
        target_fq_name: Box<str>,
        usage_kind: Option<Box<str>>,
        proof: Box<str>,
        reference_facets: UnitRowReferenceFacets,
    },
    ReferenceEdge {
        id: Box<str>,
        range: CodeQueryRange,
        proof: Box<str>,
        reference_facets: UnitRowReferenceFacets,
    },
    CallSite {
        range: CodeQueryRange,
        caller_fq_name: Box<str>,
        callee_fq_name: Box<str>,
        proof: Box<str>,
    },
    ExpressionSite {
        range: CodeQueryRange,
        input_kind: Box<str>,
        parameter_index: Option<usize>,
        parameter_name: Option<Box<str>>,
    },
    JsxAttributeValue {
        id: Box<str>,
        ast_id: Box<str>,
        range: CodeQueryRange,
        element_identity: Box<str>,
        coverage: Box<str>,
    },
    MemberTargetAnalysis {
        site_id: Box<str>,
        receiver_range: CodeQueryRange,
        outcome: Box<str>,
        coverage: Box<str>,
        capture: Option<Box<str>>,
    },
    FieldWriteValue {
        id: Box<str>,
        assignment_ast_id: Box<str>,
        rhs_ast_id: Box<str>,
        receiver_identity_id: Box<str>,
        member_target_id: Box<str>,
        range: CodeQueryRange,
        proof: Box<str>,
        completeness: Box<str>,
        coverage: Box<str>,
    },
    ReceiverAnalysis {
        range: CodeQueryRange,
        analysis_kind: Box<str>,
        outcome: Box<str>,
        capture: Option<Box<str>>,
    },
    CallableSignature {
        id: Box<str>,
        declaration_id: Option<Box<str>>,
        site_id: Box<str>,
        role: Box<str>,
        coverage: Box<str>,
        range: CodeQueryRange,
    },
    SignatureParameter {
        id: Box<str>,
        signature_id: Box<str>,
        parameter_index: usize,
        range: CodeQueryRange,
    },
    DecoratedParameter {
        id: Box<str>,
        parameter_id: Box<str>,
        range: CodeQueryRange,
    },
}

impl UnitRowItemProvenance {
    fn project(provenance: &CodeQueryProvenance) -> Self {
        let (branch, seed, steps) = project_provenance_trace(
            &provenance.branch,
            &provenance.seed,
            provenance.steps.iter(),
            UnitRowItemRef::project,
            |step| UnitRowItemProvenanceStep {
                op: boxed(step.op),
                result: UnitRowItemRef::project(&step.result),
                via: step.via.as_ref().map(UnitRowItemRef::project),
            },
        );
        Self {
            branch,
            seed,
            steps,
        }
    }
}

impl UnitRowItemRef {
    fn project(reference: &CodeQueryResultRef) -> Self {
        let value = match reference {
            CodeQueryResultRef::StructuralMatch {
                kind, node_range, ..
            } => UnitRowItemRefValue::StructuralMatch {
                kind: boxed(kind),
                node_range: *node_range,
            },
            CodeQueryResultRef::PythonHierarchyFact {
                id,
                root_id,
                declaration_id,
                owner_id,
                target_id,
                target_owner_id,
                range,
                fact_kind,
                outcome,
                coverage,
                reason,
                ancestry_basis,
                ..
            } => UnitRowItemRefValue::PythonHierarchyFact {
                id: id.clone(),
                root_id: root_id.clone(),
                declaration_id: declaration_id.clone(),
                owner_id: owner_id.clone(),
                target_id: target_id.clone(),
                target_owner_id: target_owner_id.clone(),
                fact_kind: (*fact_kind).to_owned(),
                outcome: (*outcome).to_owned(),
                coverage: (*coverage).to_owned(),
                reason: reason.map(str::to_owned),
                range: *range,
                ancestry_basis: ancestry_basis.clone(),
            },
            CodeQueryResultRef::Binding {
                id,
                ast_id,
                name,
                kind,
                range,
                ..
            } => UnitRowItemRefValue::Binding {
                id: boxed(id),
                ast_id: ast_id.as_deref().map(boxed),
                name: boxed(name),
                kind: boxed(kind),
                range: *range,
            },
            CodeQueryResultRef::LexicalScope {
                id,
                ast_id,
                index,
                range,
                ..
            } => UnitRowItemRefValue::LexicalScope {
                id: boxed(id),
                ast_id: ast_id.as_deref().map(boxed),
                index: *index,
                range: *range,
            },
            CodeQueryResultRef::Occurrence {
                id,
                ast_id,
                class,
                role,
                namespace,
                range,
                ..
            } => UnitRowItemRefValue::Occurrence {
                id: boxed(id),
                ast_id: boxed(ast_id),
                class: boxed(class),
                role: boxed(role),
                namespace: boxed(namespace),
                range: *range,
            },
            CodeQueryResultRef::Declaration {
                kind,
                fq_name,
                node_range,
                ..
            } => UnitRowItemRefValue::Declaration {
                kind: boxed(kind),
                fq_name: boxed(fq_name),
                node_range: *node_range,
            },
            CodeQueryResultRef::File { .. } => UnitRowItemRefValue::File,
            CodeQueryResultRef::GenerationSite {
                id,
                ast_id,
                range,
                kind,
                ..
            } => UnitRowItemRefValue::GenerationSite {
                id: boxed(id),
                ast_id: ast_id.as_deref().map(boxed),
                kind: boxed(kind),
                range: *range,
            },
            CodeQueryResultRef::ReferenceSite {
                range,
                target_fq_name,
                usage_kind,
                proof,
                reference_facets,
                ..
            } => UnitRowItemRefValue::ReferenceSite {
                range: *range,
                target_fq_name: boxed(target_fq_name),
                usage_kind: usage_kind.map(boxed),
                proof: boxed(proof),
                reference_facets: reference_facets.into(),
            },
            CodeQueryResultRef::ReferenceEdge {
                id,
                range,
                proof,
                reference_facets,
                ..
            } => UnitRowItemRefValue::ReferenceEdge {
                id: boxed(id),
                range: *range,
                proof: boxed(proof),
                reference_facets: reference_facets.into(),
            },
            CodeQueryResultRef::CallSite {
                range,
                caller_fq_name,
                callee_fq_name,
                proof,
                ..
            } => UnitRowItemRefValue::CallSite {
                range: *range,
                caller_fq_name: boxed(caller_fq_name),
                callee_fq_name: boxed(callee_fq_name),
                proof: boxed(proof),
            },
            CodeQueryResultRef::ExpressionSite {
                range,
                input_kind,
                parameter_index,
                parameter_name,
                ..
            } => UnitRowItemRefValue::ExpressionSite {
                range: *range,
                input_kind: boxed(input_kind),
                parameter_index: *parameter_index,
                parameter_name: parameter_name.as_deref().map(boxed),
            },
            CodeQueryResultRef::JsxAttributeValue {
                id,
                ast_id,
                range,
                element_identity,
                coverage,
                ..
            } => UnitRowItemRefValue::JsxAttributeValue {
                id: boxed(id),
                ast_id: boxed(ast_id),
                range: *range,
                element_identity: boxed(element_identity),
                coverage: boxed(coverage),
            },
            CodeQueryResultRef::MemberTargetAnalysis {
                site_id,
                receiver_range,
                outcome,
                coverage,
                capture,
                ..
            } => UnitRowItemRefValue::MemberTargetAnalysis {
                site_id: boxed(site_id),
                receiver_range: *receiver_range,
                outcome: boxed(outcome),
                coverage: boxed(coverage),
                capture: capture.as_deref().map(boxed),
            },
            CodeQueryResultRef::FieldWriteValue {
                id,
                assignment_ast_id,
                rhs_ast_id,
                receiver_identity_id,
                member_target_id,
                range,
                proof,
                completeness,
                coverage,
                ..
            } => UnitRowItemRefValue::FieldWriteValue {
                id: boxed(id),
                assignment_ast_id: boxed(assignment_ast_id),
                rhs_ast_id: boxed(rhs_ast_id),
                receiver_identity_id: boxed(receiver_identity_id),
                member_target_id: boxed(member_target_id),
                range: *range,
                proof: boxed(proof),
                completeness: boxed(completeness),
                coverage: boxed(coverage),
            },
            CodeQueryResultRef::ReceiverAnalysis {
                range,
                analysis_kind,
                outcome,
                capture,
                ..
            } => UnitRowItemRefValue::ReceiverAnalysis {
                range: *range,
                analysis_kind: boxed(analysis_kind),
                outcome: boxed(outcome),
                capture: capture.as_deref().map(boxed),
            },
            CodeQueryResultRef::PythonRuleFact {
                range, relation, ..
            } => UnitRowItemRefValue::StructuralMatch {
                kind: boxed(relation),
                node_range: Some(*range),
            },
            CodeQueryResultRef::RustMarkerImpl {
                range, relation, ..
            } => UnitRowItemRefValue::StructuralMatch {
                kind: boxed(relation),
                node_range: Some(*range),
            },
            CodeQueryResultRef::RustPointerFinding {
                range, relation, ..
            } => UnitRowItemRefValue::StructuralMatch {
                kind: boxed(relation),
                node_range: Some(*range),
            },
            CodeQueryResultRef::CallableSignature {
                id,
                declaration_id,
                site_id,
                role,
                coverage,
                range,
                ..
            } => UnitRowItemRefValue::CallableSignature {
                id: boxed(id),
                declaration_id: declaration_id.as_deref().map(boxed),
                site_id: boxed(site_id),
                role: boxed(role),
                coverage: boxed(coverage),
                range: *range,
            },
            CodeQueryResultRef::SignatureParameter {
                id,
                signature_id,
                parameter_index,
                range,
                ..
            } => UnitRowItemRefValue::SignatureParameter {
                id: boxed(id),
                signature_id: boxed(signature_id),
                parameter_index: *parameter_index,
                range: *range,
            },
            CodeQueryResultRef::DecoratedParameter {
                id,
                parameter_id,
                range,
                ..
            } => UnitRowItemRefValue::DecoratedParameter {
                id: boxed(id),
                parameter_id: boxed(parameter_id),
                range: *range,
            },
            CodeQueryResultRef::CppExpression { kind, range, .. } => {
                UnitRowItemRefValue::StructuralMatch {
                    kind: boxed(kind),
                    node_range: Some(*range),
                }
            }
            _ => UnitRowItemRefValue::Unsupported,
        };
        Self {
            kind: boxed(reference.kind_label()),
            path: boxed(reference.path()),
            value,
        }
    }
}

/// One rendered row of a unit execution, with the identity a merge deduplicates
/// it by.
///
/// `item` is the row every existing consumer reads; `evidence` is the same
/// evidence the detailed result carries, projected; `key` is the row's dedup
/// identity over stable identities. The three travel together because the
/// policy adapter zips results with evidence positionally, so nothing may
/// reorder one without the other.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UnitRow {
    pub item: UnitRowItem,
    pub evidence: UnitRowEvidence,
    pub key: UnitRowKey,
}

/// What one evaluation unit produced.
///
/// `work` is the caller-facing measurement and `budgeted_work` the lanes it
/// drops; a merge sums both, because a cap the merge cannot see is a
/// truncation the sliced run cannot detect.
///
/// `Clone` because a published unit is reused by merging its product again on
/// a later run, and the merge consumes what it merges; serde because a
/// published unit outlives its process in the analyzer cache (Milestone 3),
/// where this is the whole of the row's product column.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnitExecutionResult {
    /// Exact operand-zero emptiness, before exclusion and suffix projection.
    /// A merge requires this proof from every seed before skipping the rights.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub except_left_complete_empty: Option<bool>,
    pub rows: Vec<UnitRow>,
    pub work: CodeQueryExecutionWork,
    pub budgeted_work: CodeQueryBudgetedWork,
    pub completion: CodeQueryCompletion,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub depth_bound_status: Option<DepthBoundStatus>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub depth_answers: Vec<BoundedCallAnswer>,
    pub diagnostics: Vec<CodeQueryDiagnostic>,
    pub truncated: bool,
}

impl UnitExecutionResult {
    /// Member identities and frontier endpoints count toward batch retention,
    /// even when the final selector projects an empty answer.
    #[doc(hidden)]
    pub fn depth_answer_row_count(&self) -> usize {
        self.depth_answers.iter().fold(0_usize, |count, answer| {
            count
                .saturating_add(1)
                .saturating_add(answer.members.len())
                .saturating_add(answer.frontier.len().saturating_mul(2))
                .saturating_add(answer.undecided_frontier.len())
        })
    }

    /// Persisted unit products must retain one work slot per physical step.
    pub fn has_valid_step_outputs(&self, query: &CodeQuery) -> bool {
        self.budgeted_work.step_outputs.len() == unit_step_output_caps(query).len()
    }
}

/// The rows several units produced, merged into the vector one whole execution
/// would have produced.
#[derive(Debug)]
pub struct MergedUnitRows {
    pub items: Vec<UnitRowItem>,
    pub evidence: Vec<UnitRowEvidence>,
    pub work: CodeQueryExecutionWork,
    pub budgeted_work: CodeQueryBudgetedWork,
    pub diagnostics: Vec<CodeQueryDiagnostic>,
    pub truncated: bool,
    pub depth_bound_status: Option<DepthBoundStatus>,
    fair_share_divisor: usize,
    step_output_caps: Vec<Option<StepOutputCap>>,
}

pub(super) fn join_depth_bound_status(
    target: &mut Option<DepthBoundStatus>,
    observed: Option<DepthBoundStatus>,
) {
    if let Some(observed) = observed {
        *target = Some(target.map_or(observed, |prior| prior.join(observed)));
    }
}

impl MergedUnitRows {
    /// The completion these merged rows support, derived exactly as
    /// `CodeQueryResult::completion` derives one.
    pub fn completion(&self) -> CodeQueryCompletion {
        code_query_completion(self.truncated, &self.diagnostics)
    }

    /// Stop a merged product without certifying an absent frontier.
    pub fn mark_truncated(&mut self) {
        self.truncated = true;
        if self.depth_bound_status == Some(DepthBoundStatus::NotReached) {
            self.depth_bound_status = Some(DepthBoundStatus::Unknown);
        }
    }

    /// Apply the root result limit after merging all seed partitions.
    pub fn apply_result_limit(&mut self, limit: usize) {
        let mut has_result_limit = false;
        self.diagnostics.retain(|diagnostic| {
            if diagnostic.code != CodeQueryDiagnosticCode::ResultLimitReached {
                return true;
            }
            let first = !has_result_limit;
            has_result_limit = true;
            first
        });
        if self.items.len() > limit {
            self.items.truncate(limit);
            self.evidence.truncate(limit);
            self.mark_truncated();
            if !has_result_limit {
                push_truncation_diagnostic(
                    &mut self.diagnostics,
                    &CodeQueryExecutionBudget::default(),
                    limit,
                );
            }
        }
    }

    /// The merged evidence as the executor's own type, against `root`.
    pub fn detailed_evidence(&self, root: &Path) -> Vec<DetailedCodeQueryEvidence> {
        self.evidence
            .iter()
            .enumerate()
            .map(|(result_index, evidence)| evidence.to_detailed(root, result_index))
            .collect()
    }
}

fn unit_step_output_caps(query: &CodeQuery) -> Vec<Option<StepOutputCap>> {
    let partitioning = PlanPartitioning::classify(&query.plan);
    let union = partitioning.is_seed_union() || partitioning == PlanPartitioning::BySeedSetUnion;
    let flattened_union =
        partitioning.is_seed_union() && !PlanPartitioning::union_has_post_merge_suffix(&query.plan);
    let mut caps = Vec::new();
    let plans = if flattened_union {
        PlanPartitioning::union_leaf_plans(&query.plan)
            .expect("a seed union has flattened leaves")
            .into_iter()
            .map(|(plan, _, inherited)| {
                (
                    CodeQuery {
                        plan,
                        limit: usize::MAX,
                        ..query.clone()
                    },
                    inherited,
                )
            })
            .collect::<Vec<_>>()
    } else {
        vec![(
            if union {
                CodeQuery {
                    limit: usize::MAX,
                    ..query.clone()
                }
            } else {
                query.clone()
            },
            0,
        )]
    };
    for (query, inherited) in plans {
        let plan = select_physical_plan(&query, UnionExecutionStrategy::Sequential, 1, inherited)
            .expect("executed unit queries have valid physical plans");
        caps.extend(plan.step_output_caps().into_iter().map(|cap| {
            cap.map(|cap| {
                if flattened_union {
                    StepOutputCap::PipelineRows
                } else {
                    cap
                }
            })
        }));
    }
    caps
}

/// Expected physical counter slots in a persisted query-unit product.
pub fn unit_plan_node_count(query: &CodeQuery) -> usize {
    unit_step_output_caps(query).len()
}

// With no seed files, executed traversals have empty bounded sets. Later
// intersect/except operands can still be skipped rather than executed.
fn empty_partition_depth_status(plan: &CodeQueryPlan) -> Option<DepthBoundStatus> {
    if !super::query_plan_has_bounded_call_step(plan) {
        return None;
    }
    // With zero units, both executed empty traversals and exact skips are NotReached.
    Some(DepthBoundStatus::NotReached)
}

/// Merge the rows of several unit executions into one deterministic answer.
///
/// `units` must cover the complete `plan_seed_files` inventory. In particular,
/// complete-empty except proofs cannot establish absence for omitted seeds.
/// Callers report any omitted units as incomplete rather than publishing a
/// complete merged answer.
///
/// `units` must arrive in seed order -- the order the family's own comparator
/// puts their seed files in, which [`seed_file_order`] and
/// [`structural_seed_file_order`] expose. A leaf plan's whole row vector is
/// the concatenation of its per-seed-file row vectors in that order. A set
/// minuend in an except preserves authored branch order within each file;
/// its cross-file result order need not equal the whole executor's order.
/// An eligible union unit contains leaf rows in seed-major order,
/// so this function stably sorts those raw rows by their full branch path
/// before applying the same first-writer deduplication as the executor.
///
/// Every counter lane is summed and diagnostics are concatenated in order. The
/// per-key equivalence this reproduces is claimed only while no cumulative
/// cap was reached, which is what the summed lanes let a caller check.
pub fn merge_unit_rows(
    query: &CodeQuery,
    units: impl IntoIterator<Item = UnitExecutionResult>,
) -> MergedUnitRows {
    merge_unit_rows_in_scope(query, units, CodeQueryExecutionScope::whole_workspace())
}

/// Merge with the consumer's depth-completion setting, including when there
/// are no seed products from which that setting could be inferred.
#[doc(hidden)]
pub fn merge_unit_rows_in_scope(
    query: &CodeQuery,
    units: impl IntoIterator<Item = UnitExecutionResult>,
    scope: CodeQueryExecutionScope<'_>,
) -> MergedUnitRows {
    let mut items: Vec<UnitRowItem> = Vec::new();
    let mut evidence: Vec<UnitRowEvidence> = Vec::new();
    let mut indexes: HashMap<UnitRowKey, usize> = HashMap::default();
    let mut work = CodeQueryExecutionWork::default();
    let mut budgeted_work: Option<CodeQueryBudgetedWork> = None;
    let mut diagnostics: Vec<CodeQueryDiagnostic> = Vec::new();
    let mut truncated = false;
    let mut depth_bound_status = None;
    let mut any_units = false;
    let mut except_left_complete_empty = true;
    let mut depth_answers = Vec::new();
    let partitioning = PlanPartitioning::classify(&query.plan);
    let union = partitioning.is_seed_union() || partitioning == PlanPartitioning::BySeedSetUnion;
    let fair_share_divisor = match partitioning {
        PlanPartitioning::BySeedUnion
        | PlanPartitioning::BySeedSetUnion
        | PlanPartitioning::BySeedExcept => PlanPartitioning::fair_share_divisor(&query.plan)
            .expect("a seed-partitioned set has a checked fair-share divisor"),
        PlanPartitioning::BySeed | PlanPartitioning::Prefix { .. } | PlanPartitioning::Whole(_) => {
            1
        }
    };
    let mut step_output_caps = unit_step_output_caps(query);
    let mut raw_rows = Vec::new();

    for unit in units {
        any_units = true;
        except_left_complete_empty &= unit.except_left_complete_empty == Some(true);
        if unit.depth_answers.is_empty() {
            join_depth_bound_status(&mut depth_bound_status, unit.depth_bound_status);
        }
        depth_answers.extend(unit.depth_answers);
        work = work.saturating_add(unit.work);
        budgeted_work = Some(match budgeted_work {
            Some(summed) => summed.saturating_add(&unit.budgeted_work),
            None => unit.budgeted_work,
        });
        diagnostics.extend(unit.diagnostics); // Policy adaptation sorts in normalize_policy_diagnostics_bounded.
        truncated |= unit.truncated;
        raw_rows.extend(unit.rows);
    }

    if any_units
        && except_left_complete_empty
        && scope.computes_depth_bound_status()
        && let CodeQueryPlanSource::Set {
            op: SetOperator::Except,
            branches,
        } = &query.plan.source
    {
        replace_skipped_depth_answers(&mut depth_answers, &query.plan, &branches[1..]);
        depth_bound_status = reconciled_depth_status(&depth_answers);
    }
    if !any_units && scope.computes_depth_bound_status() {
        depth_bound_status = empty_partition_depth_status(&query.plan);
    }
    join_depth_bound_status(
        &mut depth_bound_status,
        reconciled_depth_status(&depth_answers),
    );
    // Selector units execute the union as one scoped physical plan, whereas
    // ordinary row units execute its leaves separately. Both retain the same
    // typed rows. Select the counter layout actually carried by the products;
    // if layouts have equal length, use the stricter cap in each slot so an
    // ambiguous layout can only widen early.
    if union
        && !budgeted_work
            .as_ref()
            .is_none_or(|work| work.step_outputs.is_empty())
    {
        let whole = select_physical_plan(query, UnionExecutionStrategy::Sequential, 1, 0)
            .expect("an eligible union has a physical plan")
            .step_output_caps();
        let count = budgeted_work.as_ref().unwrap().step_outputs.len();
        if count == whole.len() && count == step_output_caps.len() {
            for (cap, whole_cap) in step_output_caps.iter_mut().zip(whole) {
                *cap = match (*cap, whole_cap) {
                    (Some(left), Some(right)) => {
                        Some(if left.resolve(usize::MAX) <= right.resolve(usize::MAX) {
                            left
                        } else {
                            right
                        })
                    }
                    (Some(left), None) => Some(left),
                    (None, Some(right)) => Some(right),
                    (None, None) => None,
                };
            }
        } else if count == whole.len() {
            step_output_caps = whole;
        }
    }

    if union {
        for row in &raw_rows {
            row_representative_branch(row);
        }
        // A post-merge unit can carry traces from several branches. Its first
        // trace names the retained representative chosen by the shared set
        // executor. Stable sorting keeps seed and output order for ties.
        raw_rows.sort_by(|left, right| {
            left.item.provenance[0]
                .branch
                .cmp(&right.item.provenance[0].branch)
        });
    }
    if union {
        super::execution::discharge_decided_qualifying_sites(
            unit_qualifying_sites(&raw_rows, &diagnostics),
            &mut diagnostics,
            0,
        );
    }
    for row in raw_rows {
        match indexes.get(&row.key) {
            Some(&index) => merge_duplicate_row(&mut items[index], &mut evidence[index], row),
            None => {
                indexes.insert(row.key, items.len());
                items.push(row.item);
                evidence.push(row.evidence);
            }
        }
    }

    if depth_bound_status == Some(DepthBoundStatus::NotReached)
        && !matches!(
            code_query_completion(truncated, &diagnostics),
            CodeQueryCompletion::Complete | CodeQueryCompletion::ProvenSubset { .. }
        )
    {
        depth_bound_status = Some(DepthBoundStatus::Unknown);
    }
    MergedUnitRows {
        items,
        evidence,
        work,
        budgeted_work: budgeted_work.unwrap_or_default(),
        diagnostics,
        truncated,
        depth_bound_status,
        fair_share_divisor,
        step_output_caps,
    }
}

/// Visit only the first row for each key, exactly as the subsequent union
/// merge does. A later capture-free row cannot decide an earlier captured
/// representative. The existing structural key records custom projections.
fn unit_qualifying_sites<'rows>(
    rows: &'rows [UnitRow],
    diagnostics: &[CodeQueryDiagnostic],
) -> impl Iterator<Item = super::execution::QualifyingDischargeSite> + use<'rows> {
    // Rendering can erase every capture in a row once its response budget is
    // exhausted. Existing unit diagnostics preserve that loss across replay;
    // without complete rendering, an empty list is no capture-absence proof.
    let captures_complete = !diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code == CodeQueryDiagnosticCode::RenderedCapturesTruncated);
    let mut seen = std::collections::HashSet::new();
    rows.iter()
        .filter(move |row| seen.insert(&row.key))
        .filter_map(move |row| {
            if row.key.arm.as_ref() != "structural_match"
                || row.key.parts.len() != 3
                || !row.key.parts[2].is_empty()
            {
                return None;
            }
            let Some(UnitRowItemTerminal::StructuralMatch { captures, .. }) = &row.item.terminal
            else {
                return None;
            };
            let span = row.evidence.byte_span.as_ref()?;
            Some(super::execution::QualifyingDischargeSite {
                path: row.evidence.rel_path.to_string(),
                start_byte: span.start,
                end_byte: span.end,
                empty_captures: captures_complete && captures.is_empty(),
                first_branch: row
                    .item
                    .provenance
                    .iter()
                    .map(|trace| &trace.branch)
                    .min()
                    .cloned(),
            })
        })
}

fn row_representative_branch(row: &UnitRow) -> &[usize] {
    assert!(
        !row.item.provenance.is_empty(),
        "union rows require provenance"
    );
    assert_eq!(
        row.item.provenance.len(),
        row.evidence.provenance.len(),
        "item and evidence provenance remain aligned"
    );
    let branch = &row.item.provenance[0].branch;
    assert!(!branch.is_empty(), "union rows require a full branch path");
    for (item_trace, evidence_trace) in row.item.provenance.iter().zip(&row.evidence.provenance) {
        assert_eq!(
            item_trace.branch, evidence_trace.branch,
            "item and evidence traces must carry the same branch"
        );
    }
    branch
}

/// Fold a repeated row into the row that first claimed its key.
///
/// This is `insert_pipeline_row`'s duplicate arm at the rendered level: the
/// first row wins, the later row contributes only its provenance traces, and
/// the same `MAX_PROVENANCE_TRACES` bound decides how many fit and whether the
/// row must report its provenance as truncated. Item and evidence traces are
/// extended together because the policy adapter rejects a row whose two
/// provenance vectors differ in length.
fn merge_duplicate_row(item: &mut UnitRowItem, evidence: &mut UnitRowEvidence, row: UnitRow) {
    assert_eq!(
        item.unknown_fields, row.item.unknown_fields,
        "duplicate rows in one query snapshot have the same field evidence"
    );
    debug_assert_eq!(
        item.provenance.len(),
        evidence.provenance.len(),
        "a rendered row's provenance and its evidence provenance are one list"
    );
    assert_eq!(
        row.item.provenance.len(),
        row.evidence.provenance.len(),
        "a duplicate row's item and evidence provenance remain aligned"
    );
    let remaining = MAX_PROVENANCE_TRACES.saturating_sub(item.provenance.len());
    if row.item.provenance.len() > remaining {
        item.provenance_truncated = true;
    }
    item.provenance
        .extend(row.item.provenance.into_iter().take(remaining));
    evidence
        .provenance
        .extend(row.evidence.provenance.into_iter().take(remaining));
    item.provenance_truncated |= row.item.provenance_truncated;
}

/// The order the five `analyzed_files()` seed families enumerate files in.
///
/// Exposed so a caller that executes one unit per seed file can put its units
/// in the order the merge requires without restating the comparator.
pub fn seed_file_order(left: &ProjectFile, right: &ProjectFile) -> std::cmp::Ordering {
    left.cmp(right)
}

/// The order the structural seed enumerates files in: the workspace-relative
/// path string, then the language.
///
/// This is deliberately not [`seed_file_order`]: the two comparators can
/// disagree, and a merge must use the family's own.
pub fn structural_seed_file_order(left: &ProjectFile, right: &ProjectFile) -> std::cmp::Ordering {
    rel_path_string(left)
        .cmp(&rel_path_string(right))
        .then_with(|| {
            crate::analyzer::common::language_for_file(left)
                .cmp(&crate::analyzer::common::language_for_file(right))
        })
}

/// The files one plan's seed enumeration walks, in that family's own order.
///
/// A caller that executes one unit per seed file must enumerate exactly the
/// files the whole execution's seed scan would have enumerated, in exactly the
/// order the merge requires. Both answers are properties of the plan's source
/// -- which languages it admits and which comparator its scanner sorts by --
/// so they are stated here rather than restated by every caller.
///
/// `files` is the analyzer's whole analyzed file set. Only the language filter
/// is applied: a seed's `where` globs narrow the enumeration too, but the
/// scanner applies them itself on every unit, and a unit that yields no row
/// still records the reads that prove it yields none.
///
/// An eligible union enumerates the union of its leaf language filters and
/// uses their common comparator. An eligible except enumerates the union of
/// every branch's language filters, because the whole execution evaluates
/// each subtrahend over its own files and a unit must account for that work
/// and its diagnostics, and orders them by its innermost minuend's
/// comparator, which is the order its rows merge in. Other `Set` sources are [`Whole`] by
/// classification and never reach this function.
///
/// [`Whole`]: crate::query::PlanPartitioning::Whole
pub fn plan_seed_files(plan: &CodeQueryPlan, files: &[ProjectFile]) -> Vec<ProjectFile> {
    let (leaves, structural) = match PlanPartitioning::classify_for_prefix(plan) {
        PlanPartitioning::BySeedUnion => {
            let leaves = PlanPartitioning::union_leaf_plans(plan)
                .expect("seed-union enumeration requires an eligible union plan")
                .into_iter()
                .map(|(leaf, _, _)| leaf)
                .collect::<Vec<_>>();
            let structural = seed_languages(
                leaves
                    .first()
                    .expect("an eligible union has at least one leaf"),
            )
            .1;
            (leaves, structural)
        }
        PlanPartitioning::BySeedExcept | PlanPartitioning::BySeedSetUnion => {
            let mut minuend =
                if PlanPartitioning::classify(plan) == PlanPartitioning::BySeedSetUnion {
                    plan
                } else {
                    PlanPartitioning::except_minuend_leaf(plan)
                        .expect("an eligible except has a minuend")
                };
            // The classifier proved that every leaf uses this comparator.
            // An admitted union minuend has no comparator of its own; select its first
            // authored leaf without changing the tree executed in each unit.
            while let CodeQueryPlanSource::Set { branches, .. } = &minuend.source {
                minuend = branches.first().expect("a set has branches");
            }
            let structural = seed_languages(minuend).1;
            let mut leaves = Vec::new();
            let mut pending = vec![plan];
            while let Some(current) = pending.pop() {
                match &current.source {
                    CodeQueryPlanSource::Set { branches, .. } => pending.extend(branches),
                    _ => leaves.push(current.clone()),
                }
            }
            (leaves, structural)
        }
        PlanPartitioning::Prefix { cut } => {
            let mut leaves = Vec::new();
            let mut pending: Vec<_> = cut.operands(plan).iter().collect();
            while let Some(current) = pending.pop() {
                match &current.source {
                    CodeQueryPlanSource::Set {
                        op: SetOperator::Union,
                        branches,
                    } => pending.extend(branches),
                    _ => leaves.push(current.clone()),
                }
            }
            let structural = seed_languages(
                leaves
                    .first()
                    .expect("an eligible intersect has at least one seed leaf"),
            )
            .1;
            (leaves, structural)
        }
        PlanPartitioning::BySeed | PlanPartitioning::Whole(_) => {
            let structural = seed_languages(plan).1;
            (vec![plan.clone()], structural)
        }
    };
    let mut languages = Vec::new();
    let mut accepts_all_languages = false;
    for leaf in &leaves {
        let leaf_languages = seed_languages(leaf).0;
        if leaf_languages.is_empty() {
            accepts_all_languages = true;
        }
        for language in leaf_languages {
            if !languages.contains(language) {
                languages.push(*language);
            }
        }
    }
    let mut selected = files
        .iter()
        .filter(|file| {
            accepts_all_languages
                || languages.contains(&crate::analyzer::common::language_for_file(file))
        })
        .cloned()
        .collect::<Vec<_>>();
    if structural {
        selected.sort_by(structural_seed_file_order);
    } else {
        selected.sort_by(seed_file_order);
    }
    selected
}

/// Return a seed's language filter and its seed-file comparator family.
fn seed_languages(plan: &CodeQueryPlan) -> (&[Language], bool) {
    match &plan.source {
        CodeQueryPlanSource::Seed(seed) => (&seed.languages, true),
        CodeQueryPlanSource::Occurrences(seed) => (&seed.languages, false),
        CodeQueryPlanSource::Scopes(seed) => (&seed.languages, false),
        CodeQueryPlanSource::Bindings(seed) => (&seed.languages, false),
        CodeQueryPlanSource::Paths(seed) => (&seed.languages, false),
        CodeQueryPlanSource::GenerationSites(seed) => (&seed.languages, false),
        CodeQueryPlanSource::Exports(seed) => (&seed.languages, false),
        CodeQueryPlanSource::DependencyEvidence(_) | CodeQueryPlanSource::ConfigurationFacts(_) => {
            (&[], false)
        }
        CodeQueryPlanSource::Set { .. } => {
            unreachable!("a seed enumeration leaf has no set source")
        }
        CodeQueryPlanSource::Correlate(_) | CodeQueryPlanSource::RequireBoth(_) => {
            unreachable!("cross-domain plans are whole and never union leaves")
        }
    }
}

/// The cumulative cap a merged product reached, if it reached one.
///
/// Every arm names one lane the executor enforces globally over a whole
/// execution. A merge of per-seed executions equals the whole execution only
/// while none of them was reached: at the cap the whole run could have
/// truncated somewhere in its own order, and a sum that over-counts what two
/// units both reached cannot say where. So a caller that sees any arm here
/// must evaluate the whole query instead of merging.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergedLimit {
    /// At least one unit reported its own truncation.
    UnitTruncated,
    /// The merged rows reached the query's own root limit.
    ResultLimit,
    ScannedFiles,
    ScannedSourceBytes,
    FactNodes,
    PipelineRows,
    StepOutputs,
    SemanticMaterializedFiles,
    SemanticSourceBytes,
    SemanticRetainedBytes,
    SemanticRows(SemanticBudgetDimension),
    SemanticBudgetExhausted,
}

impl MergedLimit {
    /// The stable label of this lane, for diagnostics and persisted rows.
    pub const fn stable_label(self) -> &'static str {
        match self {
            Self::UnitTruncated => "unit_truncated",
            Self::ResultLimit => "result_limit",
            Self::ScannedFiles => "scanned_files",
            Self::ScannedSourceBytes => "scanned_source_bytes",
            Self::FactNodes => "fact_nodes",
            Self::PipelineRows => "pipeline_rows",
            Self::StepOutputs => "step_outputs",
            Self::SemanticMaterializedFiles => "semantic_materialized_files",
            Self::SemanticSourceBytes => "semantic_source_bytes",
            Self::SemanticRetainedBytes => "semantic_retained_bytes",
            Self::SemanticRows(_) => "semantic_rows",
            Self::SemanticBudgetExhausted => "semantic_budget_exhausted",
        }
    }
}

impl MergedUnitRows {
    /// Whether any summed lane reached the cap a whole execution enforces.
    ///
    /// `limits` and `result_limit` are the caller's own budget -- the budget
    /// the merged product must be as good as -- not whatever budget each unit
    /// happened to execute under. The comparisons are `>=` rather than `>` at
    /// every lane the executor tests with `>`, because a sum that exactly
    /// reaches a cap is already a sum that cannot prove the whole run had
    /// headroom. An eligible union's leaves bypass fair branch shares, so
    /// physical lanes are compared with the original cap divided by the
    /// maximum nested fair-share divisor. Semantic lanes remain unchanged.
    ///
    /// The lanes are paired the way the executor charges them:
    /// `import_files_resolved` shares `max_scanned_files` with the seed scan,
    /// `provenance_steps` and `import_edges_resolved` share
    /// `max_pipeline_rows` with the pipeline, and `examined_references`
    /// shares `max_fact_nodes` with fact loading.
    pub fn reached_limit(
        &self,
        limits: &CodeQueryExecutionLimits,
        result_limit: usize,
    ) -> Option<MergedLimit> {
        reached_limit_counters(
            &self.work,
            &self.budgeted_work,
            self.truncated,
            self.items.len(),
            self.fair_share_divisor,
            &self.step_output_caps,
            limits,
            limits.max_pipeline_rows,
            result_limit,
        )
    }
}

impl UnitExecutionResult {
    /// Check a stored unit's own work without copying its rows.
    pub fn reached_limit(
        &self,
        query: &CodeQuery,
        limits: &CodeQueryExecutionLimits,
        step_pipeline_rows: usize,
        result_limit: usize,
    ) -> Option<MergedLimit> {
        let partitioning = PlanPartitioning::classify(&query.plan);
        let fair_share_divisor = match partitioning {
            PlanPartitioning::BySeedUnion
            | PlanPartitioning::BySeedSetUnion
            | PlanPartitioning::BySeedExcept => PlanPartitioning::fair_share_divisor(&query.plan)
                .expect("a seed-partitioned set has a checked fair-share divisor"),
            PlanPartitioning::BySeed
            | PlanPartitioning::Prefix { .. }
            | PlanPartitioning::Whole(_) => 1,
        };
        reached_limit_counters(
            &self.work,
            &self.budgeted_work,
            self.truncated,
            self.rows.len(),
            fair_share_divisor,
            &unit_step_output_caps(query),
            limits,
            step_pipeline_rows,
            result_limit,
        )
    }
}

#[allow(clippy::too_many_arguments)]
fn reached_limit_counters(
    work: &CodeQueryExecutionWork,
    budgeted_work: &CodeQueryBudgetedWork,
    truncated: bool,
    item_count: usize,
    fair_share_divisor: usize,
    step_output_caps: &[Option<StepOutputCap>],
    limits: &CodeQueryExecutionLimits,
    step_pipeline_rows: usize,
    result_limit: usize,
) -> Option<MergedLimit> {
    let reached = |lane: u64, cap: usize| lane >= cap as u64;
    let physical_cap = |cap: usize| cap / fair_share_divisor;
    if truncated {
        return Some(MergedLimit::UnitTruncated);
    }
    if item_count >= result_limit {
        return Some(MergedLimit::ResultLimit);
    }
    if reached(
        work.scanned_files
            .saturating_add(budgeted_work.import_files_resolved),
        physical_cap(limits.max_scanned_files),
    ) {
        return Some(MergedLimit::ScannedFiles);
    }
    if reached(
        work.scanned_source_bytes,
        physical_cap(limits.max_scanned_source_bytes),
    ) {
        return Some(MergedLimit::ScannedSourceBytes);
    }
    if reached(
        work.fact_nodes.saturating_add(work.examined_references),
        physical_cap(limits.max_fact_nodes),
    ) {
        return Some(MergedLimit::FactNodes);
    }
    if reached(
        work.pipeline_rows
            .saturating_add(budgeted_work.provenance_steps)
            .saturating_add(budgeted_work.import_edges_resolved),
        physical_cap(limits.max_pipeline_rows),
    ) {
        return Some(MergedLimit::PipelineRows);
    }
    assert!(
        budgeted_work.step_outputs.is_empty()
            || budgeted_work.step_outputs.len() == step_output_caps.len(),
        "step output counters follow the executed physical plan layout"
    );
    // The executor can stop at equality, before examining another input.
    // Set plans retain the existing conservative branch-share allowance.
    if budgeted_work
        .step_outputs
        .iter()
        .zip(step_output_caps)
        .any(|(&outputs, cap)| {
            cap.is_some_and(|cap| reached(outputs, cap.resolve(physical_cap(step_pipeline_rows))))
        })
    {
        return Some(MergedLimit::StepOutputs);
    }
    reached_semantic_limit(&work.semantic, &limits.semantic)
}

/// The semantic half of the merged limit check.
fn reached_semantic_limit(
    semantic: &CodeQuerySemanticWork,
    limits: &CodeQuerySemanticLimits,
) -> Option<MergedLimit> {
    let reached = |lane: u64, cap: usize| lane >= cap as u64;
    if semantic.budget_exhausted {
        return Some(MergedLimit::SemanticBudgetExhausted);
    }
    if reached(
        semantic.unique_materialized_files,
        limits.max_materialized_files,
    ) {
        return Some(MergedLimit::SemanticMaterializedFiles);
    }
    if reached(
        semantic.resident_peaks.source_bytes as u64,
        limits.max_source_bytes,
    ) {
        return Some(MergedLimit::SemanticSourceBytes);
    }
    if reached(
        semantic.resident_retained_bytes_peak,
        limits.max_retained_bytes,
    ) {
        return Some(MergedLimit::SemanticRetainedBytes);
    }

    for dimension in CodeQuerySemanticRowLimits::ROW_DIMENSIONS {
        let cap = limits
            .rows_per_dimension
            .map_or(limits.max_rows_per_dimension, |rows| rows.get(dimension));
        if reached(semantic_row_work(semantic, dimension), cap) {
            return Some(MergedLimit::SemanticRows(dimension));
        }
    }
    None
}

/// One semantic row lane of a merged product, by the dimension it is capped
/// under.
///
/// The two byte dimensions are not row lanes: `SourceBytes` is capped by
/// `max_source_bytes` and `OwnedTextBytes` by `max_retained_bytes`, both
/// checked by name above. Independent units contribute the largest resident
/// or root-work balance, never the sum of visits across unrelated roots.
fn semantic_row_work(work: &CodeQuerySemanticWork, dimension: SemanticBudgetDimension) -> u64 {
    work.resident_peaks.get(dimension) as u64
}
