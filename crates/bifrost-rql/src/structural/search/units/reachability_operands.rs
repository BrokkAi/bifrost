//! Ordinary-plan operands retained independently of per-seed traversal answers.
use super::super::call_reachability::{SinkEndpoint, sink_endpoints};
use super::*;

pub(in crate::structural::search) fn operand_key(plan: &CodeQueryPlan) -> String {
    serde_json::to_string(&operand_query(plan).to_canonical_query_plan_json())
        .expect("canonical plans are JSON")
}

fn operand_query(plan: &CodeQueryPlan) -> CodeQuery {
    CodeQuery {
        schema_version: 1,
        plan: plan.clone(),
        limit: usize::MAX,
        result_detail: CodeQueryResultDetail::Full,
        execution_mode: CodeQueryExecutionMode::Results,
    }
}

fn source_wrapper(plan: &CodeQueryPlan) -> CodeQueryPlan {
    CodeQueryPlan {
        source: CodeQueryPlanSource::Set {
            op: SetOperator::Union,
            branches: vec![plan.clone()],
        },
        steps: Vec::new(),
    }
}

/// One source file's native rows and their typed public projection. Native
/// values are hydrated only after the unit's ordinary read receipts validate.
#[derive(Debug)]
pub struct CallReachabilitySourceProduct {
    pub result: UnitExecutionResult,
    native: IntersectPrefixProduct,
}

/// Portable sink endpoints and provenance; no analyzer handles or file facts.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallReachabilitySinkProduct {
    #[serde(
        serialize_with = "serialize_operand_result",
        deserialize_with = "deserialize_operand_result"
    )]
    pub result: UnitExecutionResult,
    pub(in crate::structural::search) endpoints: Vec<SinkEndpoint>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceEnvelope {
    #[serde(
        serialize_with = "serialize_operand_result",
        deserialize_with = "deserialize_operand_result"
    )]
    result: UnitExecutionResult,
    rows: serde_json::Value,
    certificates: Vec<Option<CallPathEvidence>>,
}

impl CallReachabilitySinkProduct {
    /// Only endpoint membership and contributing provenance are consumed by
    /// the continuation. Rendered selector rows may carry blob-local AST ids
    /// unrelated to that membership; they are not an output dependency.
    pub fn output_binding(&self) -> serde_json::Value {
        let mut result = self.result.clone();
        result.rows.clear();
        result.work = Default::default();
        result.budgeted_work = Default::default();
        #[derive(Serialize)]
        struct Binding<'a> {
            endpoints: &'a [SinkEndpoint],
            #[serde(serialize_with = "serialize_operand_result")]
            result: &'a UnitExecutionResult,
        }
        serde_json::to_value(Binding {
            endpoints: &self.endpoints,
            result: &result,
        })
        .expect("typed endpoint output is JSON")
    }

    /// Stored endpoint order is part of the binary-search correlation contract.
    pub fn has_valid_endpoint_order(&self) -> bool {
        self.endpoints
            .windows(2)
            .all(|pair| pair[0].site <= pair[1].site)
    }
}

impl CallReachabilitySourceProduct {
    /// Retain only this operand's validated input receipts for hydration.
    pub fn set_reads(&mut self, reads: &[crate::analyzer::read_ledger::ReadKey]) {
        self.native.reads = reads.to_vec();
        self.native.completion = self.result.completion.clone();
    }

    pub fn encode(
        &self,
        plan: &CodeQueryPlan,
    ) -> Result<serde_json::Value, CorruptIntersectProduct> {
        serde_json::to_value(SourceEnvelope {
            result: self.result.clone(),
            rows: self.native.encode_rows_json(&source_wrapper(plan))?,
            certificates: self.native.operands[0]
                .iter()
                .map(|row| row.call_path_evidence.clone())
                .collect(),
        })
        .map_err(|_| CorruptIntersectProduct)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn decode(
        analyzer: &dyn IAnalyzer,
        workspace: Option<&WorkspaceAnalyzer>,
        limits: CodeQueryExecutionLimits,
        plan: &CodeQueryPlan,
        seed: ProjectFile,
        reads: Vec<crate::analyzer::read_ledger::ReadKey>,
        encoded: serde_json::Value,
    ) -> Result<Self, CorruptIntersectProduct> {
        let envelope: SourceEnvelope =
            serde_json::from_value(encoded).map_err(|_| CorruptIntersectProduct)?;
        if envelope.result.completion != CodeQueryCompletion::Complete || envelope.result.truncated
        {
            return Err(CorruptIntersectProduct);
        }
        let mut native = IntersectPrefixProduct {
            seed,
            operands: vec![Vec::new()],
            operand_step_outputs: vec![
                envelope
                    .result
                    .budgeted_work
                    .step_outputs
                    .clone()
                    .ok_or(CorruptIntersectProduct)?,
            ],
            work: envelope.result.work,
            budgeted_work: envelope.result.budgeted_work.clone(),
            completion: envelope.result.completion.clone(),
            depth_bound_status: envelope.result.depth_bound_status,
            depth_answers: envelope.result.depth_answers.clone(),
            diagnostics: envelope.result.diagnostics.clone(),
            reads,
            reads_closed: true,
            // A stored source operand is complete.
            reuse: ReuseVerdict::Content,
        };
        native.decode_rows_json_with_limits(
            analyzer,
            workspace,
            limits,
            &source_wrapper(plan),
            envelope.rows,
        )?;
        if native.operands[0].len() != envelope.certificates.len() {
            return Err(CorruptIntersectProduct);
        }
        for (row, certificate) in native.operands[0].iter_mut().zip(envelope.certificates) {
            if let Some(certificate) = &certificate {
                let PipelineValue::Declaration(root) = &row.value else {
                    return Err(CorruptIntersectProduct);
                };
                if !certificate.validate()
                    || certificate.paths.iter().any(|path| {
                        path.root_identity != root.declaration_id()
                            || path.primary_root.rel_path != rel_path_string(root.unit.source())
                            || path.primary_root.byte_span
                                != (root.range.start_byte..root.range.end_byte)
                    })
                {
                    return Err(CorruptIntersectProduct);
                }
            }
            row.call_path_evidence = certificate;
        }
        Ok(Self {
            result: envelope.result,
            native,
        })
    }
}

/// Query-local typed inputs. Cloning a scope shares this one owned set, never
/// copies workspace facts into each continuation and never forwards operand reads.
#[derive(Debug, Default)]
pub struct CallReachabilityOperands {
    pub(in crate::structural::search) sources:
        BTreeMap<String, (Vec<PipelineRow>, UnitExecutionResult)>,
    pub(in crate::structural::search) sinks: BTreeMap<String, Arc<CallReachabilitySinkProduct>>,
}

impl CallReachabilityOperands {
    pub fn insert_source(&mut self, plan: &CodeQueryPlan, product: CallReachabilitySourceProduct) {
        let mut rows = product
            .native
            .operands
            .into_iter()
            .next()
            .unwrap_or_default();
        for row in &mut rows {
            for trace in &mut row.traces {
                assert_eq!(trace.branch.first(), Some(&0));
                trace.branch.remove(0);
            }
        }
        self.sources
            .insert(operand_key(plan), (rows, product.result));
    }

    pub fn insert_sink(&mut self, plan: &CodeQueryPlan, product: Arc<CallReachabilitySinkProduct>) {
        self.sinks.insert(operand_key(plan), product);
    }
}

#[allow(clippy::too_many_arguments)]
pub fn execute_call_reachability_source(
    analyzer: &dyn IAnalyzer,
    flow_state: impl Into<SemanticFlowResources> + Clone,
    workspace: Option<&WorkspaceAnalyzer>,
    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
    cancellation: Option<&CancellationToken>,
    scope: CodeQueryExecutionScope<'_>,
) -> CallReachabilitySourceProduct {
    let seed = scope
        .seed_files()
        .expect("source operand requires one seed")[0]
        .clone();
    let mut row_keys = Vec::new();
    let mut rows = Vec::new();
    let detailed = execute_detailed_unit(
        analyzer,
        flow_state,
        workspace,
        query,
        limits,
        cancellation,
        scope,
        &mut row_keys,
        Some(&mut rows),
    );
    let result = project_unit_result(&detailed, row_keys);
    for row in &mut rows {
        for trace in &mut row.traces {
            trace.branch.insert(0, 0);
        }
    }
    CallReachabilitySourceProduct {
        native: IntersectPrefixProduct {
            seed,
            operands: vec![rows],
            operand_step_outputs: vec![
                result
                    .budgeted_work
                    .step_outputs
                    .clone()
                    .unwrap_or_default(),
            ],
            work: result.work,
            budgeted_work: result.budgeted_work.clone(),
            completion: result.completion.clone(),
            depth_bound_status: result.depth_bound_status,
            depth_answers: result.depth_answers.clone(),
            diagnostics: result.diagnostics.clone(),
            reads: Vec::new(),
            reads_closed: true,
            reuse: result.reuse,
        },
        result,
    }
}

#[allow(clippy::too_many_arguments)]
pub fn execute_call_reachability_sink(
    analyzer: &dyn IAnalyzer,
    flow_state: impl Into<SemanticFlowResources> + Clone,
    workspace: Option<&WorkspaceAnalyzer>,
    query: &CodeQuery,
    limits: CodeQueryExecutionLimits,
    cancellation: Option<&CancellationToken>,
    scope: CodeQueryExecutionScope<'_>,
) -> CallReachabilitySinkProduct {
    // Sinks are the far end of a relation, not candidates for any finding.
    let scope = scope.without_candidate_census();
    let mut row_keys = Vec::new();
    let mut rows = Vec::new();
    let detailed = execute_detailed_unit(
        analyzer,
        flow_state,
        workspace,
        query,
        limits,
        cancellation,
        scope,
        &mut row_keys,
        Some(&mut rows),
    );
    let mut endpoints = sink_endpoints(&rows);
    endpoints.sort_by(|left, right| left.site.cmp(&right.site));
    CallReachabilitySinkProduct {
        result: project_unit_result(&detailed, row_keys),
        endpoints,
    }
}

// Public diagnostics deliberately discard execution provenance on decoding.
// A typed operand receipt must preserve it separately, just like the existing
// set-prefix envelope, so memo replay has the same output digest as a fresh run.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum OperandDiagnosticCause {
    Content,
    ConfiguredCap,
    Cancelled,
    Budget,
    Snapshot,
    Provider,
}

fn serialize_operand_result<S: serde::Serializer>(
    rows: &UnitExecutionResult,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    #[derive(Serialize)]
    struct Envelope<'a> {
        rows: &'a UnitExecutionResult,
        causes: Vec<OperandDiagnosticCause>,
    }
    let causes = rows
        .diagnostics
        .iter()
        .map(|diagnostic| match diagnostic.incompleteness {
            Incompleteness::Content => OperandDiagnosticCause::Content,
            Incompleteness::ConfiguredCap => OperandDiagnosticCause::ConfiguredCap,
            Incompleteness::Operational(cause) => match cause {
                DiagnosticExecutionCause::Cancelled => OperandDiagnosticCause::Cancelled,
                DiagnosticExecutionCause::Budget => OperandDiagnosticCause::Budget,
                DiagnosticExecutionCause::Snapshot => OperandDiagnosticCause::Snapshot,
                DiagnosticExecutionCause::Provider => OperandDiagnosticCause::Provider,
            },
        })
        .collect();
    Envelope { rows, causes }.serialize(serializer)
}

fn deserialize_operand_result<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<UnitExecutionResult, D::Error> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Envelope {
        rows: UnitExecutionResult,
        causes: Vec<OperandDiagnosticCause>,
    }
    let mut envelope = Envelope::deserialize(deserializer)?;
    if envelope.rows.diagnostics.len() != envelope.causes.len() {
        return Err(serde::de::Error::custom(
            "operand diagnostic cause count differs",
        ));
    }
    for (diagnostic, cause) in envelope.rows.diagnostics.iter_mut().zip(envelope.causes) {
        diagnostic.incompleteness = match cause {
            OperandDiagnosticCause::Content => Incompleteness::Content,
            OperandDiagnosticCause::ConfiguredCap => Incompleteness::ConfiguredCap,
            OperandDiagnosticCause::Cancelled => {
                Incompleteness::Operational(DiagnosticExecutionCause::Cancelled)
            }
            OperandDiagnosticCause::Budget => {
                Incompleteness::Operational(DiagnosticExecutionCause::Budget)
            }
            OperandDiagnosticCause::Snapshot => {
                Incompleteness::Operational(DiagnosticExecutionCause::Snapshot)
            }
            OperandDiagnosticCause::Provider => {
                Incompleteness::Operational(DiagnosticExecutionCause::Provider)
            }
        };
    }
    Ok(envelope.rows)
}
