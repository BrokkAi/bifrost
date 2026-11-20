// Private acceptance boundary: no production knob or alternate execution mode.
use super::*;
use crate::analyzer::semantic::{
    SemanticArtifact, SemanticArtifactLeaseSet, SemanticBudget, SemanticBudgetDimension,
    SemanticExecutionBudget, SemanticWork,
};

#[derive(Debug, PartialEq, Eq)]
enum ScalarValue {
    StableId(String),
    String(String),
    Strings(Vec<String>),
    Integers(Vec<u64>),
    Integer(u64),
    Boolean(bool),
    Enum(String),
    Declaration(String),
}

fn scalar(value: CodeQueryRowScalarRef<'_>) -> ScalarValue {
    match value {
        CodeQueryRowScalarRef::StableId(value) => ScalarValue::StableId(value.to_owned()),
        CodeQueryRowScalarRef::String(value) => ScalarValue::String(value.to_owned()),
        CodeQueryRowScalarRef::StringList(value) => ScalarValue::Strings(value.to_vec()),
        CodeQueryRowScalarRef::IntegerList(value) => ScalarValue::Integers(value.to_vec()),
        CodeQueryRowScalarRef::Integer(value) => ScalarValue::Integer(value),
        CodeQueryRowScalarRef::Boolean(value) => ScalarValue::Boolean(value),
        CodeQueryRowScalarRef::ConstrainedEnum(value) => ScalarValue::Enum(value.to_owned()),
        CodeQueryRowScalarRef::DeclarationIdentity(value) => {
            ScalarValue::Declaration(value.to_owned())
        }
    }
}

type ScalarFacts = Vec<(
    String,
    Vec<(
        &'static str,
        Result<Option<ScalarValue>, CodeQueryRowFieldUnknownReason>,
    )>,
)>;

fn scalar_facts(analyzer: &dyn IAnalyzer, rows: &[PipelineRow]) -> ScalarFacts {
    rows.iter()
        .filter(|row| matches!(row.value, PipelineValue::CallBinding(_)))
        .map(|row| {
            let view = scalar_projection::PipelineScalarRow::new(analyzer, row);
            let fields = view
                .fields()
                .iter()
                .map(|field| {
                    let value = view
                        .field(field.name)
                        .map(|value| value.map(scalar))
                        .map_err(|error| {
                            error
                                .unknown_reason()
                                .expect("registered unknown evidence stays typed")
                        });
                    (field.name, value)
                })
                .collect();
            (format!("{:?}", unit_row_key(&row.value.key())), fields)
        })
        .collect()
}

struct Observed<T> {
    product: T,
    // Protect actual selected backings across normal cache eviction. Saturating
    // the owner must not turn a genuine semantic eviction into output evidence.
    _native_pins: Vec<PipelineRow>,
    artifacts: Vec<Arc<SemanticArtifact>>,
    pressure: Option<HeldPressure>,
    native_semantic_used: SemanticWork,
}

struct AfterExecution<F> {
    finalizer: F,
    owner: RetentionBudget,
    headroom: Option<u64>,
}

impl<F: QueryRowsFinalizer> QueryRowsFinalizer for AfterExecution<F> {
    type Output = Observed<F::Output>;

    fn unexecuted(self, detailed: DetailedCodeQueryResult) -> Self::Output {
        panic!("acceptance fixture never executed: {detailed:?}")
    }

    fn finish(
        self,
        rows: ExecutedQueryRows<'_>,
        context: QueryFinalizationContext<'_, '_>,
    ) -> Self::Output {
        assert!(
            rows.owner
                .as_ref()
                .is_some_and(|owner| owner.ptr_eq(&self.owner))
        );
        assert!(!rows.execution.rows.is_empty());
        assert!(!rows.execution.is_cancelled() && !rows.execution.is_truncated());
        assert!(
            rows.diagnostics.iter().all(|diagnostic| !matches!(
                diagnostic.impact,
                CodeQueryDiagnosticImpact::Incomplete | CodeQueryDiagnosticImpact::Invalid
            )),
            "semantic failure before pressure: {:?}",
            rows.diagnostics
        );
        let native_semantic_used = rows
            .state
            .semantic
            .as_ref()
            .expect("call-results executes the semantic lane")
            .work()
            .cumulative;
        assert!(native_semantic_used.source_bytes > 0 && native_semantic_used.program_points > 0);
        let decorated = rows
            .execution
            .rows
            .iter()
            .filter_map(|row| match &row.value {
                PipelineValue::DecoratedParameter(value) => Some(value),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            decorated.len(),
            1,
            "one real decorated parameter must promote its file window"
        );
        let semantic = decorated[0]
            .semantic
            .as_ref()
            .expect("the decorated parameter must own semantic procedure/value/port evidence");
        assert!(
            !semantic.procedure_id.is_empty()
                && !semantic.value_id.is_empty()
                && !semantic.port_id.is_empty()
        );
        assert_eq!(
            decorated[0].row.procedure_id.as_deref(),
            Some(semantic.procedure_id.as_str())
        );
        assert_eq!(
            decorated[0].row.value_id.as_deref(),
            Some(semantic.value_id.as_str())
        );
        assert_eq!(
            decorated[0].row.port_id.as_deref(),
            Some(semantic.port_id.as_str())
        );
        let pins = rows.execution.rows.clone();
        let artifacts = pins
            .iter()
            .filter_map(|row| match &row.value {
                PipelineValue::Semantic(SemanticPipelineValue::CallResult(result)) => {
                    Some(Arc::clone(result.handle.procedure().artifact()))
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            artifacts.len(),
            1,
            "a real materialized call-result must exercise the receipt; reference-only or empty paths do not count"
        );
        let before = scalar_facts(context.analyzer, &rows.execution.rows);
        assert_eq!(
            before.len(),
            2,
            "both written bindings must be selected before pressure"
        );
        let pressure = self
            .headroom
            .map(|bytes| HeldPressure::after_execution(&self.owner, bytes));
        assert_eq!(
            before,
            scalar_facts(context.analyzer, &rows.execution.rows),
            "owner pressure cannot change native scalar/null/unavailable facts"
        );
        let product = self.finalizer.finish(rows, context);
        Observed {
            product,
            _native_pins: pins,
            artifacts,
            pressure,
            native_semantic_used,
        }
    }
}

struct LedgerRun<T> {
    observed: Observed<T>,
    semantic: SemanticBudget,
    execution: SemanticExecutionBudget,
    leases: SemanticArtifactLeaseSet,
}

fn execute_receipted<F: QueryRowsFinalizer>(
    workspace: &WorkspaceAnalyzer,
    query: &CodeQuery,
    finalizer: F,
    headroom: Option<u64>,
) -> LedgerRun<F::Output> {
    let limits = CodeQueryExecutionLimits::default();
    let root = CodeQueryRootAllotment::from_execution_limits(&limits);
    let semantic = root.semantic_budget();
    let execution = SemanticExecutionBudget::new(limits.semantic.max_materialized_files);
    let leases = SemanticArtifactLeaseSet::new(limits.semantic.max_retained_bytes);
    let observed = execute_code_query_detailed_eager_index_workspace_with_semantic_receipt_core(
        workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::default(),
        query,
        limits,
        root,
        None,
        &semantic,
        &execution,
        leases.snapshot(),
        CodeQueryExecutionScope::whole_workspace(),
        None,
        AfterExecution {
            finalizer,
            owner: workspace.retention_budget().clone(),
            headroom,
        },
    );
    LedgerRun {
        observed,
        semantic,
        execution,
        leases,
    }
}

fn import_receipt<T>(run: &mut LedgerRun<T>, receipt: CodeQuerySemanticReceipt) -> Vec<String> {
    let (charge, before, execution_charge, artifact_charge) = receipt.into_parts();
    assert!(
        !artifact_charge.is_empty(),
        "the actual receipt must promote physical dependencies, not only paid identities"
    );
    // The charge is authoritative: apply_child_charge takes component_max with
    // its performed census. No synthetic scalar work replaces that census.
    run.semantic
        .apply_child_charge(SemanticWork::default(), charge)
        .expect("actual semantic charge imports");
    assert!(run.execution.replay_charge(&before, &execution_charge));
    run.leases
        .try_apply_charge(artifact_charge, 0)
        .expect("actual dependency charge imports");
    assert!(
        run.semantic.charged_artifact_count() > 0,
        "Some(empty receipt) is not proof"
    );
    assert!(run.execution.work().materialized_files > 0);
    assert_eq!(
        run.semantic.used(),
        run.observed.native_semantic_used,
        "the actual imported receipt must equal this execution before output pressure"
    );
    assert!(run.semantic.used().source_bytes > 0 && run.semantic.used().program_points > 0);
    let mut identities = Vec::new();
    for artifact in &run.observed.artifacts {
        // Keep this accounting-only snapshot local: no snapshot may outlive
        // a later mutation of the originating lease authority.
        assert!(
            run.leases.snapshot().contains_exact(artifact),
            "the parent dependency leases must own this exact selected allocation"
        );
        let identity = artifact.key().fingerprint();
        assert!(
            run.semantic.has_charged_artifact(identity),
            "the exact selected artifact identity must be paid"
        );
        identities.push(identity.to_string());
        let before = run.semantic.used();
        run.semantic
            .charge_complete_artifact(artifact)
            .expect("immediate reuse of paid allocation");
        for dimension in SemanticBudgetDimension::ALL {
            assert_eq!(
                run.semantic.used().get(dimension),
                before.get(dimension)
                    + usize::from(dimension == SemanticBudgetDimension::NestedEntries),
                "a paid artifact may charge only the repeat lookup: {dimension:?}"
            );
        }
    }
    identities
}

fn semantic_clean<I>(detailed: &DetailedQueryResult<I>) {
    assert!(detailed.result.diagnostics.iter().all(|diagnostic| !matches!(diagnostic, DiagnosticRef::Semantic(raw) if matches!(raw.impact, CodeQueryDiagnosticImpact::Incomplete | CodeQueryDiagnosticImpact::Invalid))), "late Snapshot/provider/cancel failures must not masquerade as presentation pressure: {:?}", detailed.result.diagnostics);
}

fn assert_binding_surface(execution: &SelectorUnitExecution) -> Vec<serde_json::Value> {
    assert_eq!(execution.unit.completion, CodeQueryCompletion::Complete);
    assert_eq!(execution.detailed.reuse, ReuseVerdict::Content);
    semantic_clean(&execution.detailed);
    let bindings = execution
        .unit
        .rows
        .iter()
        .filter(|row| row.item.domain == DetailedCodeQueryDomain::CallBinding)
        .collect::<Vec<_>>();
    assert_eq!(bindings.len(), 2);
    assert!(
        bindings
            .iter()
            .all(|row| row.item.field("label").unwrap().is_none()),
        "optional actual-name alias is null"
    );
    assert!(
        bindings.iter().all(|row| row
            .item
            .field("converted")
            .unwrap_err()
            .unknown_reason()
            .is_some()),
        "conversion evidence is unavailable, not null"
    );
    assert!(
        bindings.iter().any(|row| row.item.field("literal").unwrap()
            == Some(CodeQueryRowScalarRef::String("payload")))
    );
    assert!(
        bindings
            .iter()
            .any(|row| row.item.field("literal").unwrap().is_none()),
        "integer actual is genuinely absent from the string scalar"
    );
    assert!(
        bindings
            .iter()
            .all(|row| row.item.field("literal_value").is_err()),
        "projection exposes aliases only"
    );
    let facts = execution
        .detailed
        .result
        .results
        .iter()
        .filter_map(|row| match &row.value {
            SelectorResultValue::CallBinding { value } => {
                assert!(value.has_source_target && !value.terminal);
                assert!(value.argument_id.is_some() && value.formal_layout_id.is_some());
                assert!(
                    value.selector_exact
                        && value.mapping == "exact"
                        && value.coverage == "exhaustive"
                );
                Some(serde_json::to_value(value).unwrap())
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(facts.len(), 2, "cold selected binding facts are nonempty");
    facts
}

#[test]
#[hardwon("#14068: output refusal must not contaminate selected scalars or paid semantic receipts")]
fn output_refusal_preserves_native_scalars_selected_units_and_nonempty_receipt() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file("app.ts", "import { Query } from '@nestjs/common';\nclass Controller { method(@Query() value: string) {} }\nfunction sink(value: string, count: number): string { return value; }\nfunction subject() { const result = sink(\"payload\", 7); return result; }\n")
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig {
        parallelism: Some(1),
        ..AnalyzerConfig::default()
    });
    let query = CodeQuery::from_sexp(
        r#"(union
        (decorator-bindings (parameter))
        (call-results (call-shape (call :callee "sink")))
        (project :columns (id (literal_value literal) (actual_name label) (conversion converted))
          (call-bindings (call-shape (call :callee "sink")))))"#,
    )
    .expect("receipt and binding projection query");
    // Warm only query/provider caches. No persisted-unit reuse is claimed here.
    drop(execute_receipted(
        &workspace,
        &query,
        ProjectSelectorRows,
        None,
    ));
    let mut control = execute_receipted(&workspace, &query, ProjectSelectorRows, None);
    let facts = assert_binding_surface(&control.observed.product);
    let receipt = control
        .observed
        .product
        .detailed
        .take_semantic_receipt()
        .expect("control receipt is real");
    let paid = import_receipt(&mut control, receipt);
    let mut pressured = execute_receipted(&workspace, &query, ProjectSelectorRows, Some(1));
    assert_eq!(facts, assert_binding_surface(&pressured.observed.product));
    assert_eq!(
        control.observed.product.unit.rows, pressured.observed.product.unit.rows,
        "all scalar aliases, typed unknowns, identities, evidence and provenance survive"
    );
    let receipt = pressured
        .observed
        .product
        .detailed
        .take_semantic_receipt()
        .expect("pressured semantic receipt is real");
    let pressure_paid = import_receipt(&mut pressured, receipt);
    assert_eq!(paid, pressure_paid);
    // Cross-run cache eviction may legitimately change performed counters.
    // import_receipt checks exact pre-pressure work within each execution.
    let stored: UnitExecutionResult =
        serde_json::from_value(serde_json::to_value(&pressured.observed.product.unit).unwrap())
            .unwrap();
    assert_eq!(
        stored.rows, control.observed.product.unit.rows,
        "persisted shape keeps aliases, absent values and typed unknowns"
    );
    assert_eq!(stored.completion, CodeQueryCompletion::Complete);
    pressured.observed.pressure.take().unwrap().assert_refund();
    let mut output = execute_receipted(&workspace, &query, PresentQueryRows, Some(1));
    semantic_clean(&output.observed.product);
    assert!(output.observed.product.result.truncated);
    assert!(
        output.observed.product.result.results.is_empty(),
        "bookkeeping refuses before publishing the mixed batch"
    );
    assert!(output.observed.product.evidence.is_empty());
    assert_eq!(
        output
            .observed
            .product
            .result
            .diagnostics
            .iter()
            .filter(|diagnostic| matches!(
                diagnostic,
                DiagnosticRef::Presentation(PresentationDiagnostic::RowsRefused)
            ))
            .count(),
        1
    );
    assert!(
        matches!(
            output.observed.product.reuse,
            ReuseVerdict::ExecutionDependent(_)
        ),
        "only public output reuse becomes execution-dependent"
    );
    let receipt = output
        .observed
        .product
        .take_semantic_receipt()
        .expect("output refusal must retain the real semantic receipt");
    let output_paid = import_receipt(&mut output, receipt);
    assert_eq!(paid, output_paid);
    output.observed.pressure.take().unwrap().assert_refund();
    let again = execute_receipted(&workspace, &query, ProjectSelectorRows, None);
    assert_eq!(facts, assert_binding_surface(&again.observed.product));
    assert_eq!(
        control.observed.product.unit.rows,
        again.observed.product.unit.rows
    );
}
