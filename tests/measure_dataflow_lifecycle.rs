//! Fresh-process lifecycle benchmark for bounded data-flow state.
//!
//! The benchmark measures request-local ICFG construction and solver state. It
//! deliberately does not build a serialized candidate: concrete seeds,
//! run-local fact IDs, worklists, truncations, and results are not reusable
//! summaries. Use `scripts/run-dataflow-lifecycle-benchmarks.sh` for the
//! decision-grade nine-process-per-dataset matrix.

mod common;

use std::collections::BTreeMap;
use std::fs;
use std::hash::{Hash, Hasher};
use std::hint::black_box;
use std::mem::{size_of, size_of_val};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Instant;

use brokk_bifrost::analyzer::dataflow::{
    BoundedSnapshotDataflowProblem, DataflowEdge, DataflowOutput, DataflowRequest, DataflowResult,
    DataflowSeed, DirectFlowProblem, DistributiveDataflowProblem, IcfgSolveInput, SolverBudget,
    SolverTermination, SolverWork, solve,
};
use brokk_bifrost::analyzer::semantic::{
    CancellationToken, DeclarationSegmentKind, IcfgProvider, IcfgSnapshot, IcfgSnapshotLimits,
    ProcedureHandle, ProcedureKind, SemanticArtifact, SemanticBudget, SemanticOutcome,
    SemanticRequest, StableDigest,
};
use brokk_bifrost::{
    AnalyzerConfig, Language, Project, ProjectFile, TestProject, WorkspaceAnalyzer,
};
use serde::{Deserialize, Serialize};

use common::{InlineTestProject, semantic_graph::reachable_icfg_nodes};

const RESULT_PREFIX: &str = "BIFROST_DATAFLOW_LIFECYCLE_BENCHMARK=";
const DATASET_ENV: &str = "BIFROST_DATAFLOW_LIFECYCLE_DATASET";
const ROUND_ENV: &str = "BIFROST_DATAFLOW_LIFECYCLE_ROUND";
const SAMPLES_FILE_ENV: &str = "BIFROST_DATAFLOW_LIFECYCLE_SAMPLES_FILE";
const TS_REPO_ENV: &str = "BIFROST_SEMANTIC_TS_REPO";
const JAVA_REPO_ENV: &str = "BIFROST_SEMANTIC_JAVA_REPO";
const VSCODE_COMMIT: &str = "19e0f9e681ecb8e5c09d8784acaa601316ca4571";
const SPRING_PETCLINIC_COMMIT: &str = "f182358d02e4a68e52bdbabf55ca7800288511e7";
const FORMAT: &str = "bifrost_dataflow_lifecycle_benchmark/v1";
const AGGREGATE_FORMAT: &str = "bifrost_dataflow_lifecycle_benchmark_aggregate/v1";
const RECOMMENDATION: &str =
    "ephemeral_not_eligible; persist reusable summaries only after #823 defines and measures them";
const REQUIRED_DATASETS: [&str; 8] = [
    "external_spring_petclinic_java",
    "external_vscode_typescript",
    "generated_typescript_branches_512",
    "generated_typescript_branches_64",
    "generated_typescript_calls_32",
    "generated_typescript_calls_8",
    "inline_java",
    "inline_typescript",
];
const FINITE_FACT_COUNT: usize = 16;
const MAX_FINITE_FACT: u8 = 15;
const ICFG_LIMITS: IcfgSnapshotLimits = IcfgSnapshotLimits {
    max_call_depth: 8,
    max_nodes: 50_000,
    max_edges: 200_000,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct BenchmarkProvenance {
    bifrost_commit: Option<String>,
    bifrost_dirty: Option<bool>,
    bifrost_tree_fingerprint: Option<String>,
    rustc_version_verbose: Option<String>,
    operating_system: String,
    architecture: String,
    system_identity: Option<String>,
    cpu_model: Option<String>,
    logical_parallelism: Option<usize>,
    build_profile: String,
    crate_version: String,
    timer: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DatasetProvenance {
    origin: String,
    language: String,
    root_file: String,
    root_procedure: String,
    repository_commit: Option<String>,
    repository_dirty: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct IcfgMeasurement {
    status: String,
    limits: IcfgLimitsReport,
    nodes: usize,
    reachable_nodes: usize,
    edges: usize,
    boundaries: usize,
    semantic_work: SemanticWorkReport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct IcfgLimitsReport {
    max_call_depth: u32,
    max_nodes: usize,
    max_edges: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct SemanticWorkReport {
    procedures: usize,
    blocks: usize,
    program_points: usize,
    values: usize,
    allocations: usize,
    call_sites: usize,
    memory_locations: usize,
    captures: usize,
    source_mappings: usize,
    evidence: usize,
    gaps: usize,
    events: usize,
    control_edges: usize,
    nested_entries: usize,
    owned_text_bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct SolverWorkReport {
    interned_facts: usize,
    reached_states: usize,
    flow_evaluations: usize,
    callback_rows: usize,
    propagated_outputs: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ClientMeasurement {
    client: String,
    first_solve_ms: f64,
    repeat_solve_ms: f64,
    facts: usize,
    reached: usize,
    work: SolverWorkReport,
    termination: String,
    complete: bool,
    checksum: u64,
    estimated_shallow_result_bytes: u64,
    cache_status: String,
    serialized_bytes: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DatasetMeasurement {
    name: String,
    provenance: DatasetProvenance,
    workspace_build_ms: f64,
    semantic_materialization_ms: f64,
    icfg_materialization_ms: f64,
    process_peak_rss_bytes: Option<u64>,
    icfg: IcfgMeasurement,
    clients: Vec<ClientMeasurement>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SampleResult {
    format: String,
    kind: String,
    provenance: BenchmarkProvenance,
    round: usize,
    datasets: Vec<DatasetMeasurement>,
}

#[derive(Debug, Clone, Serialize)]
struct MedianMeasurement {
    dataset: String,
    client: String,
    workspace_build_ms: f64,
    semantic_materialization_ms: f64,
    icfg_materialization_ms: f64,
    first_solve_ms: f64,
    repeat_solve_ms: f64,
    process_peak_rss_bytes: Option<u64>,
    estimated_shallow_result_bytes: u64,
    nodes: usize,
    reachable_nodes: usize,
    edges: usize,
    boundaries: usize,
    facts: usize,
    reached: usize,
    work: SolverWorkReport,
    status: String,
    termination: String,
    complete: bool,
    checksum: u64,
}

#[derive(Debug, Serialize)]
struct AggregateResult {
    format: &'static str,
    kind: &'static str,
    aggregation_provenance: BenchmarkProvenance,
    sample_provenance: BenchmarkProvenance,
    dataset_groups: usize,
    fresh_processes_per_dataset: usize,
    discarded_warmups_per_dataset: usize,
    retained_samples_per_dataset: usize,
    raw_samples: Vec<SampleResult>,
    medians: Vec<MedianMeasurement>,
    recommendation: &'static str,
}

#[derive(Debug, Clone, Copy)]
struct FiniteFactProblem {
    seed: brokk_bifrost::analyzer::semantic::IcfgNodeId,
}

impl FiniteFactProblem {
    fn transfer(fact: u8, out: &mut dyn DataflowOutput<u8>) {
        if !out.emit(fact) {
            return;
        }
        if fact < MAX_FINITE_FACT {
            let _ = out.emit(fact + 1);
        }
    }
}

impl DistributiveDataflowProblem for FiniteFactProblem {
    type Fact = u8;

    fn zero_fact(&self) -> Self::Fact {
        0
    }

    fn normal_flow(
        &self,
        _edge: DataflowEdge<'_>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        Self::transfer(fact, out);
    }

    fn call_flow(
        &self,
        _edge: DataflowEdge<'_>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        Self::transfer(fact, out);
    }

    fn return_flow(
        &self,
        _edge: DataflowEdge<'_>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        Self::transfer(fact, out);
    }

    fn call_to_return_flow(
        &self,
        _edge: DataflowEdge<'_>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        Self::transfer(fact, out);
    }

    fn exceptional_flow(
        &self,
        _edge: DataflowEdge<'_>,
        fact: Self::Fact,
        out: &mut dyn DataflowOutput<Self::Fact>,
    ) {
        Self::transfer(fact, out);
    }
}

impl BoundedSnapshotDataflowProblem for FiniteFactProblem {
    fn seeds(&self, out: &mut dyn DataflowOutput<DataflowSeed<Self::Fact>>) {
        let _ = out.emit(DataflowSeed::new(self.seed, 1));
    }
}

#[test]
#[ignore = "decision-grade fresh-process benchmark; run through the repository script"]
fn dataflow_lifecycle_measurement() {
    let result = match std::env::var_os(SAMPLES_FILE_ENV) {
        Some(samples_file) => serde_json::to_string(&aggregate(Path::new(&samples_file)))
            .expect("serialize data-flow lifecycle aggregate"),
        None => serde_json::to_string(&sample())
            .expect("serialize data-flow lifecycle benchmark sample"),
    };
    println!("{RESULT_PREFIX}{result}");
}

#[test]
fn generated_sources_expose_unique_roots() {
    let branch_source = generated_branch_source(8);
    assert_eq!(
        branch_source.matches("export function branchRoot").count(),
        1
    );
    assert_eq!(branch_source.matches("if (input ===").count(), 8);

    let call_source = generated_call_source(8);
    assert_eq!(call_source.matches("export function callRoot").count(), 1);
    assert_eq!(call_source.matches("function callStep").count(), 8);
}

#[test]
fn median_helpers_select_the_middle_retained_sample() {
    assert_eq!(median_f64(vec![7.0, 1.0, 5.0, 3.0, 9.0]), 5.0);
    assert_eq!(median_u64(vec![7, 1, 5, 3, 9]), 5);
}

#[test]
fn benchmark_clients_are_deterministic_and_bounded_on_a_real_icfg() {
    let measurement = measure_generated_branches("generated_typescript_branches_8", 8);
    let direct = &measurement.clients[0];
    let finite = &measurement.clients[1];

    assert_eq!(direct.client, "direct");
    assert_eq!(direct.facts, 1);
    assert_eq!(direct.reached, measurement.icfg.reachable_nodes);
    assert_eq!(direct.termination, "fixed_point");
    assert_eq!(finite.client, "finite_16");
    assert_eq!(finite.facts, FINITE_FACT_COUNT);
    assert_eq!(finite.termination, "fixed_point");
}

fn sample() -> SampleResult {
    let round = std::env::var(ROUND_ENV)
        .ok()
        .map(|value| {
            value
                .parse::<usize>()
                .unwrap_or_else(|_| panic!("{ROUND_ENV} must be a non-negative integer"))
        })
        .unwrap_or(0);
    let dataset_name =
        std::env::var(DATASET_ENV).unwrap_or_else(|_| "inline_typescript".to_owned());
    let dataset = match dataset_name.as_str() {
        "generated_typescript_branches_64" => {
            measure_generated_branches("generated_typescript_branches_64", 64)
        }
        "generated_typescript_branches_512" => {
            measure_generated_branches("generated_typescript_branches_512", 512)
        }
        "generated_typescript_calls_8" => {
            measure_generated_calls("generated_typescript_calls_8", 8)
        }
        "generated_typescript_calls_32" => {
            measure_generated_calls("generated_typescript_calls_32", 32)
        }
        "inline_typescript" => {
            let project = InlineTestProject::with_language(Language::TypeScript)
                .file(
                    "main.ts",
                    r#"
                function helper(value: number): number {
                    if (value < 0) {
                        throw new Error("negative");
                    }
                    return value + 1;
                }

                export function lifecycleRoot(value: number): number {
                    try {
                        return helper(value);
                    } catch (_error) {
                        return 0;
                    }
                }
            "#,
                )
                .build();
            measure_workspace(
                "inline_typescript",
                "inline_fixture",
                project.root(),
                Language::TypeScript,
                "main.ts",
                &[(DeclarationSegmentKind::Function, "lifecycleRoot")],
                ProcedureKind::Function,
                None,
            )
        }
        "inline_java" => {
            let project = InlineTestProject::with_language(Language::Java)
                .file(
                    "LifecycleSample.java",
                    r#"
                class LifecycleSample {
                    static int helper(int value) {
                        if (value < 0) {
                            throw new IllegalArgumentException();
                        }
                        return value + 1;
                    }

                    static int lifecycleRoot(int value) {
                        try {
                            return helper(value);
                        } catch (IllegalArgumentException error) {
                            return 0;
                        }
                    }
                }
            "#,
                )
                .build();
            measure_workspace(
                "inline_java",
                "inline_fixture",
                project.root(),
                Language::Java,
                "LifecycleSample.java",
                &[
                    (DeclarationSegmentKind::Type, "LifecycleSample"),
                    (DeclarationSegmentKind::Method, "lifecycleRoot"),
                ],
                ProcedureKind::Method,
                None,
            )
        }
        "external_vscode_typescript" => measure_workspace(
            "external_vscode_typescript",
            "pinned_external_repository",
            &required_repo(TS_REPO_ENV),
            Language::TypeScript,
            "src/vs/base/common/arrays.ts",
            &[(DeclarationSegmentKind::Function, "quickSelect")],
            ProcedureKind::Function,
            Some(VSCODE_COMMIT),
        ),
        "external_spring_petclinic_java" => measure_workspace(
            "external_spring_petclinic_java",
            "pinned_external_repository",
            &required_repo(JAVA_REPO_ENV),
            Language::Java,
            "src/main/java/org/springframework/samples/petclinic/owner/OwnerController.java",
            &[
                (DeclarationSegmentKind::Type, "OwnerController"),
                (DeclarationSegmentKind::Method, "processFindForm"),
            ],
            ProcedureKind::Method,
            Some(SPRING_PETCLINIC_COMMIT),
        ),
        other => panic!("unknown {DATASET_ENV} value {other:?}"),
    };

    SampleResult {
        format: FORMAT.to_owned(),
        kind: "sample".to_owned(),
        provenance: benchmark_provenance(),
        round,
        datasets: vec![dataset],
    }
}

fn measure_generated_branches(name: &str, branches: usize) -> DatasetMeasurement {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file("generated.ts", generated_branch_source(branches))
        .build();
    measure_workspace(
        name,
        "generated",
        project.root(),
        Language::TypeScript,
        "generated.ts",
        &[(DeclarationSegmentKind::Function, "branchRoot")],
        ProcedureKind::Function,
        None,
    )
}

fn measure_generated_calls(name: &str, calls: usize) -> DatasetMeasurement {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file("generated.ts", generated_call_source(calls))
        .build();
    measure_workspace(
        name,
        "generated",
        project.root(),
        Language::TypeScript,
        "generated.ts",
        &[(DeclarationSegmentKind::Function, "callRoot")],
        ProcedureKind::Function,
        None,
    )
}

fn required_repo(variable: &str) -> PathBuf {
    std::env::var_os(variable)
        .map(PathBuf::from)
        .unwrap_or_else(|| panic!("{variable} is required for the selected external dataset"))
}

#[allow(clippy::too_many_arguments)]
fn measure_workspace(
    name: impl Into<String>,
    origin: &str,
    root: &Path,
    language: Language,
    root_file: &str,
    root_locator_suffix: &[(DeclarationSegmentKind, &str)],
    root_kind: ProcedureKind,
    expected_commit: Option<&str>,
) -> DatasetMeasurement {
    let name = name.into();
    let root = root
        .canonicalize()
        .unwrap_or_else(|error| panic!("canonicalize benchmark root {}: {error}", root.display()));
    let repository_commit = git_commit(&root);
    let repository_dirty = git_dirty(&root);
    if let Some(expected) = expected_commit {
        assert_eq!(
            repository_commit.as_deref(),
            Some(expected),
            "dataset {name} must use its pinned repository commit"
        );
        assert_eq!(
            repository_dirty,
            Some(false),
            "dataset {name} must use a clean pinned repository"
        );
    }

    let source_project = Arc::new(TestProject::new(root.clone(), language));
    let project: Arc<dyn Project> = Arc::clone(&source_project) as Arc<dyn Project>;
    let workspace_started = Instant::now();
    let workspace = WorkspaceAnalyzer::build(
        project,
        AnalyzerConfig {
            parallelism: Some(1),
            ..AnalyzerConfig::default()
        },
    );
    let workspace_build_ms = elapsed_ms(workspace_started);
    let file = ProjectFile::new(root, root_file);
    assert!(file.exists(), "benchmark root file must exist: {root_file}");
    let cancellation = CancellationToken::default();

    let semantic_started = Instant::now();
    let mut semantic_budget = SemanticBudget::default();
    let semantic_outcome = workspace
        .materialize_program_semantics(
            &file,
            &mut SemanticRequest::new(&mut semantic_budget, &cancellation),
        )
        .unwrap_or_else(|error| panic!("materialize {name} semantic artifact: {error}"));
    let semantic_materialization_ms = elapsed_ms(semantic_started);
    let artifact = match semantic_outcome {
        SemanticOutcome::Complete { value, .. } => value,
        other => panic!(
            "benchmark root {name} must produce a complete semantic artifact; got {:?}",
            semantic_outcome_label(&other)
        ),
    };
    let root_handle = select_procedure(&artifact, root_locator_suffix, root_kind);

    let icfg_started = Instant::now();
    let mut icfg_budget = SemanticBudget::default();
    let icfg_outcome = workspace
        .icfg_provider()
        .snapshot(
            &root_handle,
            ICFG_LIMITS,
            &mut SemanticRequest::new(&mut icfg_budget, &cancellation),
        )
        .unwrap_or_else(|error| panic!("materialize {name} ICFG: {error}"));
    let icfg_materialization_ms = elapsed_ms(icfg_started);
    let solve_input = IcfgSolveInput::from_outcome(&icfg_outcome)
        .unwrap_or_else(|error| panic!("{name} ICFG is not traversable: {error}"));
    let snapshot = solve_input.snapshot();
    let root_node = root_node(snapshot, &root_handle);
    let reachable_nodes = reachable_icfg_nodes(snapshot, [root_node]).len();

    let direct = DirectFlowProblem::new([root_node]);
    let finite = FiniteFactProblem { seed: root_node };
    let clients = vec![
        measure_client("direct", solve_input, &direct),
        measure_client("finite_16", solve_input, &finite),
    ];
    assert_eq!(
        clients[0].reached, reachable_nodes,
        "direct data-flow client must match ordinary ICFG reachability"
    );
    let process_peak_rss_bytes = peak_rss_bytes();

    DatasetMeasurement {
        name,
        provenance: DatasetProvenance {
            origin: origin.to_owned(),
            language: language.config_label().to_owned(),
            root_file: root_file.to_owned(),
            root_procedure: format_locator_suffix(root_locator_suffix),
            repository_commit,
            repository_dirty,
        },
        workspace_build_ms,
        semantic_materialization_ms,
        icfg_materialization_ms,
        process_peak_rss_bytes,
        icfg: IcfgMeasurement {
            status: solve_input.status().label().to_owned(),
            limits: IcfgLimitsReport {
                max_call_depth: ICFG_LIMITS.max_call_depth,
                max_nodes: ICFG_LIMITS.max_nodes,
                max_edges: ICFG_LIMITS.max_edges,
            },
            nodes: snapshot.node_count(),
            reachable_nodes,
            edges: snapshot.edge_count(),
            boundaries: snapshot.boundaries().len(),
            semantic_work: semantic_work_report(icfg_outcome.work()),
        },
        clients,
    }
}

fn select_procedure(
    artifact: &Arc<SemanticArtifact>,
    suffix: &[(DeclarationSegmentKind, &str)],
    expected_kind: ProcedureKind,
) -> ProcedureHandle {
    assert!(
        !suffix.is_empty(),
        "procedure locator suffix must not be empty"
    );
    let matches = artifact
        .procedures()
        .iter()
        .filter(|procedure| {
            let segments = procedure.locator().declaration().segments();
            procedure.kind() == expected_kind
                && segments.len() >= suffix.len()
                && segments[segments.len() - suffix.len()..]
                    .iter()
                    .zip(suffix)
                    .all(|(segment, (kind, name))| {
                        segment.kind() == *kind && segment.name() == Some(*name)
                    })
        })
        .map(|procedure| procedure.id())
        .collect::<Vec<_>>();
    assert_eq!(
        matches.len(),
        1,
        "expected exactly one semantic procedure matching {:?}, found {}",
        format_locator_suffix(suffix),
        matches.len()
    );
    artifact
        .procedure_handle(matches[0])
        .expect("selected semantic procedure remains in its artifact")
}

fn format_locator_suffix(suffix: &[(DeclarationSegmentKind, &str)]) -> String {
    suffix
        .iter()
        .map(|(kind, name)| format!("{kind:?}({name})"))
        .collect::<Vec<_>>()
        .join("::")
}

fn root_node(
    snapshot: &IcfgSnapshot,
    root: &ProcedureHandle,
) -> brokk_bifrost::analyzer::semantic::IcfgNodeId {
    let entry = root
        .point_handle(root.semantics().entry_point())
        .expect("root entry point remains in its procedure");
    let matches = snapshot
        .node_ids()
        .filter(|node| {
            snapshot
                .node(*node)
                .is_some_and(|key| key.call_context().is_empty() && key.point() == &entry)
        })
        .collect::<Vec<_>>();
    assert_eq!(
        matches.len(),
        1,
        "bounded ICFG must contain exactly one root-context entry node"
    );
    matches[0]
}

fn measure_client<P>(label: &str, input: IcfgSolveInput<'_>, problem: &P) -> ClientMeasurement
where
    P: BoundedSnapshotDataflowProblem,
{
    let cancellation = CancellationToken::default();
    let mut first_budget = SolverBudget::default();
    let first_started = Instant::now();
    let first = solve(
        input,
        problem,
        &mut DataflowRequest::new(&mut first_budget, &cancellation),
    )
    .unwrap_or_else(|error| panic!("solve {label} data-flow workload: {error}"));
    let first_solve_ms = elapsed_ms(first_started);

    let mut repeat_budget = SolverBudget::default();
    let repeat_started = Instant::now();
    let repeat = solve(
        input,
        problem,
        &mut DataflowRequest::new(&mut repeat_budget, &cancellation),
    )
    .unwrap_or_else(|error| panic!("repeat {label} data-flow workload: {error}"));
    let repeat_solve_ms = elapsed_ms(repeat_started);
    assert!(
        first == repeat,
        "repeated request-local solve must reproduce the exact deterministic result"
    );
    assert_eq!(
        first.termination(),
        SolverTermination::FixedPoint,
        "benchmark client {label} must reach a fixed point"
    );
    if label == "finite_16" {
        assert_eq!(
            first.facts().len(),
            FINITE_FACT_COUNT,
            "finite stress client must retain zero plus facts one through fifteen"
        );
    }
    black_box(&repeat);

    ClientMeasurement {
        client: label.to_owned(),
        first_solve_ms,
        repeat_solve_ms,
        facts: first.facts().len(),
        reached: first.reached().len(),
        work: solver_work_report(first.work()),
        termination: termination_label(first.termination()).to_owned(),
        complete: first.is_complete(),
        checksum: result_checksum(&first),
        estimated_shallow_result_bytes: estimated_shallow_result_bytes(&first),
        cache_status: "not_applicable_run_local".to_owned(),
        serialized_bytes: None,
    }
}

fn semantic_work_report(
    work: brokk_bifrost::analyzer::semantic::SemanticWork,
) -> SemanticWorkReport {
    SemanticWorkReport {
        procedures: work.procedures,
        blocks: work.blocks,
        program_points: work.program_points,
        values: work.values,
        allocations: work.allocations,
        call_sites: work.call_sites,
        memory_locations: work.memory_locations,
        captures: work.captures,
        source_mappings: work.source_mappings,
        evidence: work.evidence,
        gaps: work.gaps,
        events: work.events,
        control_edges: work.control_edges,
        nested_entries: work.nested_entries,
        owned_text_bytes: work.owned_text_bytes,
    }
}

fn solver_work_report(work: SolverWork) -> SolverWorkReport {
    SolverWorkReport {
        interned_facts: work.interned_facts,
        reached_states: work.reached_states,
        flow_evaluations: work.flow_evaluations,
        callback_rows: work.callback_rows,
        propagated_outputs: work.propagated_outputs,
    }
}

fn semantic_outcome_label<T>(outcome: &SemanticOutcome<T>) -> &'static str {
    match outcome {
        SemanticOutcome::Complete { .. } => "complete",
        SemanticOutcome::Ambiguous { .. } => "ambiguous",
        SemanticOutcome::Unknown { .. } => "unknown",
        SemanticOutcome::Unsupported { .. } => "unsupported",
        SemanticOutcome::Unproven { .. } => "unproven",
        SemanticOutcome::ExceededBudget { .. } => "exceeded_budget",
        SemanticOutcome::Cancelled { .. } => "cancelled",
    }
}

fn termination_label(termination: SolverTermination) -> &'static str {
    match termination {
        SolverTermination::FixedPoint => "fixed_point",
        SolverTermination::Cancelled => "cancelled",
        SolverTermination::ExceededBudget(_) => "exceeded_budget",
    }
}

fn result_checksum<Fact: Hash>(result: &DataflowResult<Fact>) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    result.facts().hash(&mut hasher);
    for reached in result.reached() {
        reached.node().get().hash(&mut hasher);
        reached.fact().get().hash(&mut hasher);
        for quality in reached.path_qualities().iter() {
            quality.is_proven().hash(&mut hasher);
            quality.is_complete().hash(&mut hasher);
        }
    }
    result.coverage().input_status().hash(&mut hasher);
    for edge in result.coverage().unproven_edges() {
        edge.get().hash(&mut hasher);
    }
    for edge in result.coverage().partial_edges() {
        edge.get().hash(&mut hasher);
    }
    for boundary in result.coverage().boundaries() {
        boundary.at.get().hash(&mut hasher);
    }
    termination_label(result.termination()).hash(&mut hasher);
    solver_work_report(result.work()).hash(&mut hasher);
    hasher.finish()
}

fn estimated_shallow_result_bytes<Fact>(result: &DataflowResult<Fact>) -> u64 {
    let bytes = size_of::<DataflowResult<Fact>>()
        .saturating_add(size_of_val(result.facts()))
        .saturating_add(size_of_val(result.reached()))
        .saturating_add(size_of_val(result.coverage().unproven_edges()))
        .saturating_add(size_of_val(result.coverage().partial_edges()))
        .saturating_add(size_of_val(result.coverage().boundaries()));
    u64::try_from(bytes).unwrap_or(u64::MAX)
}

fn generated_branch_source(branches: usize) -> String {
    let mut source =
        String::from("export function branchRoot(input: number): number {\n  let value = 0;\n");
    for branch in 0..branches {
        source.push_str(&format!(
            "  if (input === {branch}) {{ value += {branch}; }} else {{ value -= 1; }}\n"
        ));
    }
    source.push_str("  return value;\n}\n");
    source
}

fn generated_call_source(calls: usize) -> String {
    assert!(calls > 0);
    let mut source = String::new();
    for call in 0..calls {
        if call + 1 == calls {
            source.push_str(&format!(
                "function callStep{call}(value: number): number {{ return value + 1; }}\n"
            ));
        } else {
            source.push_str(&format!(
                "function callStep{call}(value: number): number {{ return callStep{}(value) + 1; }}\n",
                call + 1
            ));
        }
    }
    source
        .push_str("export function callRoot(value: number): number { return callStep0(value); }\n");
    source
}

fn aggregate(samples_file: &Path) -> AggregateResult {
    let contents = fs::read_to_string(samples_file).unwrap_or_else(|error| {
        panic!(
            "read data-flow lifecycle samples {}: {error}",
            samples_file.display()
        )
    });
    let mut raw_samples = contents
        .lines()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty())
        .map(|(line_number, line)| {
            serde_json::from_str::<SampleResult>(line).unwrap_or_else(|error| {
                panic!(
                    "parse data-flow lifecycle sample line {}: {error}",
                    line_number + 1
                )
            })
        })
        .collect::<Vec<_>>();
    assert!(
        !raw_samples.is_empty(),
        "must retain data-flow lifecycle samples"
    );
    raw_samples.sort_by(|left, right| {
        sample_dataset(left)
            .name
            .cmp(&sample_dataset(right).name)
            .then_with(|| left.round.cmp(&right.round))
    });
    let sample_provenance = raw_samples[0].provenance.clone();
    let mut groups = BTreeMap::<String, Vec<usize>>::new();
    for (index, sample) in raw_samples.iter().enumerate() {
        assert_eq!(sample.format, FORMAT, "sample format drift");
        assert_eq!(sample.kind, "sample", "sample kind drift");
        assert_eq!(
            sample.provenance, sample_provenance,
            "sample execution provenance drift"
        );
        assert_eq!(
            sample.datasets.len(),
            1,
            "every fresh process must measure exactly one dataset"
        );
        groups
            .entry(sample_dataset(sample).name.clone())
            .or_default()
            .push(index);
    }
    assert_eq!(
        groups.keys().map(String::as_str).collect::<Vec<_>>(),
        REQUIRED_DATASETS,
        "aggregate requires the complete generated, inline, and pinned external matrix"
    );

    let mut medians = Vec::new();
    for (dataset_name, sample_indices) in &groups {
        assert_eq!(
            sample_indices.len(),
            7,
            "dataset {dataset_name} must retain seven fresh-process samples"
        );
        assert_eq!(
            sample_indices
                .iter()
                .map(|index| raw_samples[*index].round)
                .collect::<Vec<_>>(),
            (2..9).collect::<Vec<_>>(),
            "dataset {dataset_name} must discard rounds zero and one"
        );
        let datasets = sample_indices
            .iter()
            .map(|index| sample_dataset(&raw_samples[*index]))
            .collect::<Vec<_>>();
        let reference_dataset = datasets[0];
        validate_required_dataset(reference_dataset);
        for dataset in &datasets[1..] {
            assert_dataset_stable(reference_dataset, dataset);
        }
        let process_peak_rss_bytes = median_optional_rss(
            datasets
                .iter()
                .map(|dataset| dataset.process_peak_rss_bytes)
                .collect(),
        );
        for (client_index, reference_client) in reference_dataset.clients.iter().enumerate() {
            let clients = datasets
                .iter()
                .map(|dataset| &dataset.clients[client_index])
                .collect::<Vec<_>>();
            for client in &clients[1..] {
                assert_client_stable(reference_client, client);
            }
            medians.push(MedianMeasurement {
                dataset: reference_dataset.name.clone(),
                client: reference_client.client.clone(),
                workspace_build_ms: median_f64(
                    datasets
                        .iter()
                        .map(|dataset| dataset.workspace_build_ms)
                        .collect(),
                ),
                semantic_materialization_ms: median_f64(
                    datasets
                        .iter()
                        .map(|dataset| dataset.semantic_materialization_ms)
                        .collect(),
                ),
                icfg_materialization_ms: median_f64(
                    datasets
                        .iter()
                        .map(|dataset| dataset.icfg_materialization_ms)
                        .collect(),
                ),
                first_solve_ms: median_f64(
                    clients.iter().map(|client| client.first_solve_ms).collect(),
                ),
                repeat_solve_ms: median_f64(
                    clients
                        .iter()
                        .map(|client| client.repeat_solve_ms)
                        .collect(),
                ),
                process_peak_rss_bytes,
                estimated_shallow_result_bytes: reference_client.estimated_shallow_result_bytes,
                nodes: reference_dataset.icfg.nodes,
                reachable_nodes: reference_dataset.icfg.reachable_nodes,
                edges: reference_dataset.icfg.edges,
                boundaries: reference_dataset.icfg.boundaries,
                facts: reference_client.facts,
                reached: reference_client.reached,
                work: reference_client.work,
                status: reference_dataset.icfg.status.clone(),
                termination: reference_client.termination.clone(),
                complete: reference_client.complete,
                checksum: reference_client.checksum,
            });
        }
    }

    AggregateResult {
        format: AGGREGATE_FORMAT,
        kind: "aggregate",
        aggregation_provenance: benchmark_provenance(),
        sample_provenance,
        dataset_groups: groups.len(),
        fresh_processes_per_dataset: 9,
        discarded_warmups_per_dataset: 2,
        retained_samples_per_dataset: 7,
        raw_samples,
        medians,
        recommendation: RECOMMENDATION,
    }
}

fn sample_dataset(sample: &SampleResult) -> &DatasetMeasurement {
    assert_eq!(
        sample.datasets.len(),
        1,
        "every fresh process must measure exactly one dataset"
    );
    &sample.datasets[0]
}

fn validate_required_dataset(dataset: &DatasetMeasurement) {
    match dataset.name.as_str() {
        "external_vscode_typescript" => {
            assert_eq!(
                dataset.provenance.repository_commit.as_deref(),
                Some(VSCODE_COMMIT),
                "VS Code dataset commit drift"
            );
            assert_eq!(
                dataset.provenance.repository_dirty,
                Some(false),
                "VS Code dataset must be clean"
            );
        }
        "external_spring_petclinic_java" => {
            assert_eq!(
                dataset.provenance.repository_commit.as_deref(),
                Some(SPRING_PETCLINIC_COMMIT),
                "Spring PetClinic dataset commit drift"
            );
            assert_eq!(
                dataset.provenance.repository_dirty,
                Some(false),
                "Spring PetClinic dataset must be clean"
            );
        }
        name => assert!(
            REQUIRED_DATASETS.contains(&name),
            "unexpected dataset {name:?}"
        ),
    }
}

fn median_optional_rss(values: Vec<Option<u64>>) -> Option<u64> {
    if values.iter().all(Option::is_none) {
        return None;
    }
    Some(median_u64(
        values
            .into_iter()
            .map(|value| value.expect("RSS availability must be stable within a group"))
            .collect(),
    ))
}

fn assert_dataset_stable(reference: &DatasetMeasurement, candidate: &DatasetMeasurement) {
    assert_eq!(candidate.name, reference.name, "dataset order/name drift");
    assert_eq!(
        candidate.provenance, reference.provenance,
        "dataset provenance drift for {}",
        reference.name
    );
    assert_eq!(
        candidate.icfg, reference.icfg,
        "ICFG topology/work drift for {}",
        reference.name
    );
    assert_eq!(
        candidate.clients.len(),
        reference.clients.len(),
        "client count drift for {}",
        reference.name
    );
    assert_eq!(
        candidate.process_peak_rss_bytes.is_some(),
        reference.process_peak_rss_bytes.is_some(),
        "RSS availability drift for {}",
        reference.name
    );
}

fn assert_client_stable(reference: &ClientMeasurement, candidate: &ClientMeasurement) {
    assert_eq!(
        candidate.client, reference.client,
        "client order/name drift"
    );
    assert_eq!(candidate.facts, reference.facts, "fact count drift");
    assert_eq!(candidate.reached, reference.reached, "reached count drift");
    assert_eq!(candidate.work, reference.work, "solver work drift");
    assert_eq!(
        candidate.termination, reference.termination,
        "termination drift"
    );
    assert_eq!(candidate.complete, reference.complete, "completeness drift");
    assert_eq!(candidate.checksum, reference.checksum, "checksum drift");
    assert_eq!(
        candidate.estimated_shallow_result_bytes, reference.estimated_shallow_result_bytes,
        "retained-byte drift"
    );
    assert_eq!(
        candidate.cache_status, reference.cache_status,
        "cache classification drift"
    );
    assert_eq!(
        candidate.serialized_bytes, reference.serialized_bytes,
        "serialized-size classification drift"
    );
}

fn median_f64(mut values: Vec<f64>) -> f64 {
    assert!(!values.is_empty(), "median requires retained samples");
    values.sort_by(f64::total_cmp);
    values[values.len() / 2]
}

fn median_u64(mut values: Vec<u64>) -> u64 {
    assert!(!values.is_empty(), "median requires retained samples");
    values.sort_unstable();
    values[values.len() / 2]
}

fn elapsed_ms(started: Instant) -> f64 {
    started.elapsed().as_secs_f64() * 1_000.0
}

#[cfg(unix)]
fn peak_rss_bytes() -> Option<u64> {
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    let result = unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };
    assert_eq!(result, 0, "getrusage failed");
    let max_rss = usage.ru_maxrss.max(0) as u64;
    Some(if cfg!(target_os = "macos") {
        max_rss
    } else {
        max_rss.saturating_mul(1024)
    })
}

#[cfg(not(unix))]
fn peak_rss_bytes() -> Option<u64> {
    None
}

fn benchmark_provenance() -> BenchmarkProvenance {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_owned());
    BenchmarkProvenance {
        bifrost_commit: git_commit(root),
        bifrost_dirty: git_dirty(root),
        bifrost_tree_fingerprint: bifrost_tree_fingerprint(root),
        rustc_version_verbose: command_output(&rustc, &["--version", "--verbose"]),
        operating_system: std::env::consts::OS.to_owned(),
        architecture: std::env::consts::ARCH.to_owned(),
        system_identity: command_output("uname", &["-a"]),
        cpu_model: cpu_model(),
        logical_parallelism: std::thread::available_parallelism()
            .ok()
            .map(std::num::NonZeroUsize::get),
        build_profile: if cfg!(debug_assertions) {
            "debug".to_owned()
        } else {
            "release".to_owned()
        },
        crate_version: env!("CARGO_PKG_VERSION").to_owned(),
        timer: "std::time::Instant monotonic elapsed wall time".to_owned(),
    }
}

fn git_commit(root: &Path) -> Option<String> {
    command_output_in(root, "git", &["rev-parse", "HEAD"])
}

fn git_dirty(root: &Path) -> Option<bool> {
    command_output_in(
        root,
        "git",
        &["status", "--porcelain", "--untracked-files=normal"],
    )
    .map(|status| !status.is_empty())
}

fn bifrost_tree_fingerprint(root: &Path) -> Option<String> {
    let diff = Command::new("git")
        .current_dir(root)
        .args(["diff", "--binary", "HEAD", "--"])
        .output()
        .ok()
        .filter(|output| output.status.success())?;
    let untracked = Command::new("git")
        .current_dir(root)
        .args(["ls-files", "--others", "--exclude-standard", "-z"])
        .output()
        .ok()
        .filter(|output| output.status.success())?;
    let mut material = Vec::with_capacity(diff.stdout.len() + untracked.stdout.len());
    material.extend_from_slice(git_commit(root)?.as_bytes());
    material.extend_from_slice(&diff.stdout);
    for raw_path in untracked.stdout.split(|byte| *byte == 0) {
        if raw_path.is_empty() {
            continue;
        }
        let relative = std::str::from_utf8(raw_path).ok()?;
        let contents = fs::read(root.join(relative)).ok()?;
        material.extend_from_slice(&u64::try_from(raw_path.len()).ok()?.to_le_bytes());
        material.extend_from_slice(raw_path);
        material.extend_from_slice(&u64::try_from(contents.len()).ok()?.to_le_bytes());
        material.extend_from_slice(&contents);
    }
    Some(StableDigest::sha256(material).to_string())
}

fn command_output_in(root: &Path, program: &str, arguments: &[&str]) -> Option<String> {
    Command::new(program)
        .current_dir(root)
        .args(arguments)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|output| output.trim().to_owned())
}

fn command_output(program: &str, arguments: &[&str]) -> Option<String> {
    Command::new(program)
        .args(arguments)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|output| output.trim().to_owned())
}

fn cpu_model() -> Option<String> {
    if cfg!(target_os = "macos") {
        command_output("sysctl", &["-n", "machdep.cpu.brand_string"])
            .or_else(|| command_output("sysctl", &["-n", "hw.model"]))
            .filter(|model| !model.is_empty())
    } else if cfg!(target_os = "linux") {
        fs::read_to_string("/proc/cpuinfo")
            .ok()
            .and_then(|contents| {
                contents.lines().find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    matches!(name.trim(), "model name" | "Hardware")
                        .then(|| value.trim().to_owned())
                })
            })
    } else {
        std::env::var("PROCESSOR_IDENTIFIER").ok()
    }
}

impl Hash for SolverWorkReport {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.interned_facts.hash(state);
        self.reached_states.hash(state);
        self.flow_evaluations.hash(state);
        self.callback_rows.hash(state);
        self.propagated_outputs.hash(state);
    }
}
