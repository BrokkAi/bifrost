//! Generation-local semantic-oracle lifecycle measurement for issue #816.
//!
//! Run one release-process sample directly with:
//!
//! ```text
//! BIFROST_SEMANTIC_TS_REPO=/path/to/pinned/vscode \
//! BIFROST_SEMANTIC_JAVA_REPO=/path/to/pinned/spring-petclinic \
//!   cargo test --release --test measure_semantic_oracles -- --ignored --nocapture
//! ```
//!
//! The benchmark deliberately measures the existing complete-only in-memory
//! artifact cache and request-local oracle projections. It does not introduce
//! an oracle-result cache or a persistence candidate.

use std::collections::BTreeSet;
use std::fs;
use std::hint::black_box;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Instant;

use brokk_bifrost::analyzer::semantic::{
    AccessPath, AccessPathAtPoint, AccessPathRoot, AccessPathTail, AliasQuery, AliasRelation,
    CancellationToken, CandidateCoverage, HeapOracle, ObservationPhase, OracleCallContext,
    SemanticBudget, SemanticEffect, SemanticOutcome, SemanticProviderError, SemanticRequest,
    SemanticValueKind, StableDigest, ValueAtPoint, ValueFlowEndpoint, ValueFlowOracle,
    ValueFlowRelationKind,
};
use brokk_bifrost::analyzer::structural::{CodeQuery, execute_workspace};
use brokk_bifrost::{
    AnalyzerConfig, Language, OverlayProject, Project, ProjectFile, TestProject, WorkspaceAnalyzer,
};
use serde::Serialize;
use serde_json::json;

const RESULT_PREFIX: &str = "BIFROST_SEMANTIC_ORACLE_BENCHMARK=";
const ROUND_ENV: &str = "BIFROST_SEMANTIC_ORACLE_BENCH_ROUND";
const TS_REPO_ENV: &str = "BIFROST_SEMANTIC_TS_REPO";
const JAVA_REPO_ENV: &str = "BIFROST_SEMANTIC_JAVA_REPO";
const VSCODE_COMMIT: &str = "19e0f9e681ecb8e5c09d8784acaa601316ca4571";
const SPRING_PETCLINIC_COMMIT: &str = "f182358d02e4a68e52bdbabf55ca7800288511e7";
const MAX_VALUE_QUERIES: usize = 4_096;
const MAX_ALIAS_QUERIES: usize = 1_024;

const TYPESCRIPT_FIXTURE: &str = r#"
class Leaf { value = 1; }
class Boxed {
  constructor(public child: Leaf) {}
  touch() { return this.child.value; }
}
function choose(flag: boolean) {
  let value;
  if (flag) value = new Boxed(new Leaf());
  else value = new Boxed(new Leaf());
  value.child.value = 2;
  return value;
}
export function caller(flag: boolean) {
  const first = choose(flag);
  const alias = first;
  const direct = new Boxed(new Leaf());
  alias.child.value = first.child.value;
  direct.touch();
  alias.touch();
  return alias;
}
"#;

const JAVA_FIXTURE: &str = r#"
final class Leaf { int value; }
final class Boxed {
    final Leaf child;
    Boxed(Leaf child) { this.child = child; }
    int touch() { return this.child.value; }
}
class Sample {
    static Boxed choose(boolean flag) {
        Boxed value;
        if (flag) value = new Boxed(new Leaf());
        else value = new Boxed(new Leaf());
        value.child.value = 2;
        return value;
    }
    Boxed caller(boolean flag) {
        Boxed first = choose(flag);
        Boxed alias = first;
        Boxed direct = new Boxed(new Leaf());
        alias.child.value = first.child.value;
        direct.touch();
        alias.touch();
        return alias;
    }
}
"#;

#[derive(Debug, Clone, Serialize)]
struct BenchmarkProvenance {
    bifrost_commit: Option<String>,
    bifrost_dirty: Option<bool>,
    bifrost_tree_fingerprint: Option<String>,
    rustc_version_verbose: Option<String>,
    operating_system: String,
    architecture: String,
    cpu_model: Option<String>,
    logical_parallelism: Option<usize>,
    build_profile: &'static str,
    timer: &'static str,
}

#[derive(Debug, Default, Clone, Serialize)]
struct IrCounts {
    artifacts: usize,
    procedures: usize,
    points: usize,
    values: usize,
    calls: usize,
    allocations: usize,
    memory_locations: usize,
    memory_loads: usize,
    memory_stores: usize,
    evidence_rows: usize,
    gaps: usize,
}

#[derive(Debug, Default, Clone, Serialize)]
struct OracleCounts {
    value_flow_queries: usize,
    value_flow_relations: usize,
    max_relations_per_procedure: usize,
    points_to_queries: usize,
    points_to_candidates: usize,
    max_points_to_candidates: usize,
    location_queries: usize,
    location_candidates: usize,
    max_location_candidates: usize,
    max_alias_breadth_observed: usize,
    exact_access_paths: usize,
    summary_access_paths: usize,
    max_access_path_length: usize,
    alias_queries: usize,
    must_alias: usize,
    may_alias: usize,
    disjoint: usize,
    retained_provenance_handles: usize,
    open_sets: usize,
    truncated_sets: usize,
    value_queries_capped: bool,
    alias_queries_capped: bool,
}

#[derive(Debug, Clone, Serialize)]
struct ReceiverMeasurement {
    structural_baseline_ms: f64,
    receiver_projection_ms: f64,
    compatibility_overhead_ms: f64,
    compatibility_overhead_ratio: Option<f64>,
    baseline_results: usize,
    receiver_results: usize,
    receiver_value_candidates: usize,
    receiver_member_candidates: usize,
    receiver_truncated: bool,
}

#[derive(Debug, Clone, Serialize)]
struct DatasetMeasurement {
    name: String,
    origin: String,
    language: String,
    repository_commit: Option<String>,
    repository_dirty: Option<bool>,
    files_seen: usize,
    files_materialized: usize,
    unavailable_files: usize,
    cold_materialization_ms: f64,
    warm_materialization_ms: f64,
    warm_arc_reuse_count: usize,
    ir: IrCounts,
    oracle_projection_ms: f64,
    oracle: OracleCounts,
    receiver: ReceiverMeasurement,
}

#[derive(Debug, Clone, Serialize)]
struct InvalidationMeasurement {
    disk_update_ms: f64,
    disk_key_changed: bool,
    disk_warm_arc_reused: bool,
    overlay_update_ms: f64,
    overlay_key_changed: bool,
    overlay_warm_arc_reused: bool,
    incomplete_request_followed_by_complete: bool,
}

#[derive(Debug, Clone, Serialize)]
struct SampleResult {
    format: &'static str,
    kind: &'static str,
    round: usize,
    provenance: BenchmarkProvenance,
    query_caps: QueryCaps,
    datasets: Vec<DatasetMeasurement>,
    invalidation: InvalidationMeasurement,
    recommendation: &'static str,
}

#[derive(Debug, Clone, Copy, Serialize)]
struct QueryCaps {
    max_value_queries_per_dataset: usize,
    max_alias_queries_per_dataset: usize,
}

struct MaterializedCorpus {
    artifacts: Vec<Arc<brokk_bifrost::analyzer::semantic::SemanticArtifact>>,
    files_seen: usize,
    unavailable_files: usize,
    cold_ms: f64,
    warm_ms: f64,
    warm_arc_reuse_count: usize,
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
        cpu_model: if cfg!(target_os = "macos") {
            command_output("sysctl", &["-n", "machdep.cpu.brand_string"])
                .or_else(|| command_output("sysctl", &["-n", "hw.model"]))
        } else {
            None
        },
        logical_parallelism: std::thread::available_parallelism()
            .ok()
            .map(std::num::NonZeroUsize::get),
        build_profile: if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        },
        timer: "std::time::Instant monotonic elapsed wall time",
    }
}

fn complete_artifact(
    outcome: SemanticOutcome<Arc<brokk_bifrost::analyzer::semantic::SemanticArtifact>>,
) -> Option<Arc<brokk_bifrost::analyzer::semantic::SemanticArtifact>> {
    match outcome {
        SemanticOutcome::Complete { value, .. } => Some(value),
        SemanticOutcome::Ambiguous { .. }
        | SemanticOutcome::Unknown { .. }
        | SemanticOutcome::Unsupported { .. }
        | SemanticOutcome::Unproven { .. }
        | SemanticOutcome::ExceededBudget { .. } => None,
        SemanticOutcome::Cancelled { .. } => panic!("benchmark cancellation was not requested"),
    }
}

fn materialize_corpus(
    workspace: &WorkspaceAnalyzer,
    project: &dyn Project,
    files: &[ProjectFile],
) -> MaterializedCorpus {
    let cancellation = CancellationToken::default();
    let started = Instant::now();
    let mut artifacts = Vec::new();
    let mut materialized_files = Vec::new();
    let mut unavailable_files = 0usize;
    for file in files {
        let mut budget = SemanticBudget::default();
        let outcome = match workspace.materialize_program_semantics(
            file,
            &mut SemanticRequest::new(&mut budget, &cancellation),
        ) {
            Ok(outcome) => outcome,
            Err(SemanticProviderError::SourceAccess(_)) => {
                project
                    .read_source(file)
                    .expect("enumerated benchmark source must remain readable");
                unavailable_files += 1;
                continue;
            }
            Err(error) => panic!("materialize {}: {error}", file.rel_path().display()),
        };
        let Some(artifact) = complete_artifact(outcome) else {
            unavailable_files += 1;
            continue;
        };
        materialized_files.push(file.clone());
        artifacts.push(artifact);
    }
    let cold_ms = started.elapsed().as_secs_f64() * 1_000.0;

    let warm_started = Instant::now();
    let mut warm_arc_reuse_count = 0usize;
    for (file, cold) in materialized_files.iter().zip(&artifacts) {
        let mut budget = SemanticBudget::default();
        let warm = workspace
            .materialize_program_semantics(
                file,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .unwrap_or_else(|error| {
                panic!("warm materialize {}: {error}", file.rel_path().display())
            });
        let warm = complete_artifact(warm).expect("complete cold artifact must remain complete");
        warm_arc_reuse_count += usize::from(Arc::ptr_eq(cold, &warm));
        black_box(warm);
    }
    let warm_ms = warm_started.elapsed().as_secs_f64() * 1_000.0;
    MaterializedCorpus {
        artifacts,
        files_seen: files.len(),
        unavailable_files,
        cold_ms,
        warm_ms,
        warm_arc_reuse_count,
    }
}

fn coverage(counts: &mut OracleCounts, coverage: CandidateCoverage) {
    match coverage {
        CandidateCoverage::Exhaustive => {}
        CandidateCoverage::Open => counts.open_sets += 1,
        CandidateCoverage::Truncated => counts.truncated_sets += 1,
    }
}

fn observe_access_path(counts: &mut OracleCounts, path: &AccessPath) {
    counts.max_access_path_length = counts.max_access_path_length.max(path.selectors().len());
    match path.tail() {
        AccessPathTail::Exact => counts.exact_access_paths += 1,
        AccessPathTail::Summary => counts.summary_access_paths += 1,
    }
}

fn count_ir(artifacts: &[Arc<brokk_bifrost::analyzer::semantic::SemanticArtifact>]) -> IrCounts {
    let mut counts = IrCounts {
        artifacts: artifacts.len(),
        ..IrCounts::default()
    };
    for artifact in artifacts {
        for procedure in artifact.procedures() {
            counts.procedures += 1;
            counts.points += procedure.points().len();
            counts.values += procedure.values().len();
            counts.calls += procedure.call_sites().len();
            counts.allocations += procedure.allocations().len();
            counts.memory_locations += procedure.memory_locations().len();
            counts.evidence_rows += procedure.evidence_rows().len();
            counts.gaps += procedure.gaps().len();
            for point in procedure.points() {
                for event in &point.events {
                    match event.effect {
                        SemanticEffect::MemoryLoad { .. } => counts.memory_loads += 1,
                        SemanticEffect::MemoryStore { .. } => counts.memory_stores += 1,
                        _ => {}
                    }
                }
            }
        }
    }
    counts
}

fn measure_oracles(
    workspace: &WorkspaceAnalyzer,
    artifacts: &[Arc<brokk_bifrost::analyzer::semantic::SemanticArtifact>],
) -> (f64, OracleCounts) {
    let oracle = workspace.semantic_oracle_provider();
    let cancellation = CancellationToken::default();
    let mut counts = OracleCounts::default();
    let started = Instant::now();
    let mut alias_inputs = Vec::<AccessPathAtPoint>::new();

    for artifact in artifacts {
        let procedure_ids = artifact
            .procedures()
            .iter()
            .map(|procedure| procedure.id())
            .collect::<Vec<_>>();
        for procedure_id in procedure_ids {
            let procedure = artifact
                .procedure_handle(procedure_id)
                .expect("artifact procedure handle");
            let mut budget = SemanticBudget::default();
            let flow = oracle
                .procedure_relations(
                    &procedure,
                    &OracleCallContext::empty(),
                    &mut SemanticRequest::new(&mut budget, &cancellation),
                )
                .expect("value-flow projection");
            counts.value_flow_queries += 1;
            if let Some(snapshot) = flow.available_value() {
                counts.value_flow_relations += snapshot.relations().len();
                counts.max_relations_per_procedure = counts
                    .max_relations_per_procedure
                    .max(snapshot.relations().len());
                counts.retained_provenance_handles += snapshot.relations().len();
                coverage(&mut counts, snapshot.coverage());
                for relation in snapshot.relations() {
                    for endpoint in [&relation.source, &relation.target] {
                        if let ValueFlowEndpoint::Location(location) = endpoint {
                            observe_access_path(&mut counts, location.path());
                        }
                    }
                }
            }

            let exit = procedure
                .point_handle(procedure.semantics().normal_exit_point())
                .expect("normal exit point handle");
            for value in procedure.semantics().values() {
                if counts.points_to_queries >= MAX_VALUE_QUERIES {
                    counts.value_queries_capped = true;
                    break;
                }
                if !matches!(
                    value.kind,
                    SemanticValueKind::Local
                        | SemanticValueKind::Receiver
                        | SemanticValueKind::Return
                        | SemanticValueKind::Temporary
                ) {
                    continue;
                }
                let value_handle = procedure
                    .value_handle(value.id)
                    .expect("semantic value handle");
                let value_query = ValueAtPoint::new(
                    value_handle.clone(),
                    exit.clone(),
                    ObservationPhase::BeforeEffects,
                    OracleCallContext::empty(),
                )
                .expect("same-procedure points-to query");
                let mut budget = SemanticBudget::default();
                let pointees = oracle
                    .pointees(
                        &value_query,
                        &mut SemanticRequest::new(&mut budget, &cancellation),
                    )
                    .expect("points-to projection");
                counts.points_to_queries += 1;
                if let Some(result) = pointees.available_value() {
                    let candidates = result.objects().candidates();
                    counts.points_to_candidates += candidates.len();
                    counts.max_points_to_candidates =
                        counts.max_points_to_candidates.max(candidates.len());
                    counts.retained_provenance_handles += candidates
                        .iter()
                        .map(|candidate| candidate.provenance().len())
                        .sum::<usize>();
                    coverage(&mut counts, result.objects().coverage());
                }

                let path = AccessPath::exact(
                    AccessPathRoot::Value(value_handle),
                    Vec::new(),
                    *oracle.limits(),
                )
                .expect("empty value-root path");
                let access = AccessPathAtPoint::new(
                    path,
                    exit.clone(),
                    ObservationPhase::BeforeEffects,
                    OracleCallContext::empty(),
                )
                .expect("same-procedure location query");
                let mut budget = SemanticBudget::default();
                let locations = oracle
                    .locations(
                        &access,
                        &mut SemanticRequest::new(&mut budget, &cancellation),
                    )
                    .expect("location projection");
                counts.location_queries += 1;
                if let Some(result) = locations.available_value() {
                    let candidates = result.locations().candidates();
                    counts.location_candidates += candidates.len();
                    counts.max_location_candidates =
                        counts.max_location_candidates.max(candidates.len());
                    counts.max_alias_breadth_observed =
                        counts.max_alias_breadth_observed.max(candidates.len());
                    counts.retained_provenance_handles += candidates
                        .iter()
                        .map(|candidate| candidate.provenance().len())
                        .sum::<usize>();
                    coverage(&mut counts, result.locations().coverage());
                    for candidate in candidates {
                        observe_access_path(&mut counts, candidate.value().path());
                    }
                    if !candidates.is_empty() {
                        alias_inputs.push(access);
                    }
                }
            }
        }
    }

    for left_index in 0..alias_inputs.len() {
        for right_index in left_index..alias_inputs.len() {
            if counts.alias_queries >= MAX_ALIAS_QUERIES {
                counts.alias_queries_capped = true;
                break;
            }
            let left = &alias_inputs[left_index];
            let right = &alias_inputs[right_index];
            if left.point() != right.point() {
                continue;
            }
            let query = AliasQuery::new(left.clone(), right.clone()).expect("matched observation");
            let mut budget = SemanticBudget::default();
            let alias = oracle
                .alias(
                    &query,
                    &mut SemanticRequest::new(&mut budget, &cancellation),
                )
                .expect("alias projection");
            counts.alias_queries += 1;
            if let Some(result) = alias.available_value() {
                counts.retained_provenance_handles += result.answer().provenance().len();
                match result.answer().value() {
                    AliasRelation::MustAlias => counts.must_alias += 1,
                    AliasRelation::MayAlias => counts.may_alias += 1,
                    AliasRelation::Disjoint => counts.disjoint += 1,
                }
            }
        }
        if counts.alias_queries_capped {
            break;
        }
    }

    (started.elapsed().as_secs_f64() * 1_000.0, counts)
}

fn receiver_query() -> CodeQuery {
    CodeQuery::from_json(&json!({
        "match": { "kind": "call" },
        "steps": [{ "op": "receiver_targets" }],
        "limit": 200
    }))
    .expect("receiver benchmark query")
}

fn structural_query() -> CodeQuery {
    CodeQuery::from_json(&json!({
        "match": { "kind": "call" },
        "limit": 200
    }))
    .expect("structural receiver baseline")
}

fn measure_receiver(workspace: &WorkspaceAnalyzer) -> ReceiverMeasurement {
    black_box(execute_workspace(workspace, &structural_query()));
    black_box(execute_workspace(workspace, &receiver_query()));

    let baseline_started = Instant::now();
    let baseline = execute_workspace(workspace, &structural_query());
    let structural_baseline_ms = baseline_started.elapsed().as_secs_f64() * 1_000.0;
    black_box(&baseline);

    let receiver_started = Instant::now();
    let receiver = execute_workspace(workspace, &receiver_query());
    let receiver_projection_ms = receiver_started.elapsed().as_secs_f64() * 1_000.0;
    let serialized = serde_json::to_value(&receiver).expect("serialize receiver result");
    let receiver_value_candidates = serialized["results"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|row| row["values"].as_array().map_or(0, Vec::len))
        .sum();
    let receiver_member_candidates = serialized["results"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|row| row["member_targets"].as_array().map_or(0, Vec::len))
        .sum();
    let compatibility_overhead_ms = receiver_projection_ms - structural_baseline_ms;
    ReceiverMeasurement {
        structural_baseline_ms,
        receiver_projection_ms,
        compatibility_overhead_ms,
        compatibility_overhead_ratio: (structural_baseline_ms > 0.0)
            .then_some(receiver_projection_ms / structural_baseline_ms),
        baseline_results: baseline.results.len(),
        receiver_results: receiver.results.len(),
        receiver_value_candidates,
        receiver_member_candidates,
        receiver_truncated: receiver.truncated,
    }
}

fn measure_dataset(
    name: &str,
    origin: &str,
    root: &Path,
    language: Language,
    expected_commit: Option<&str>,
) -> DatasetMeasurement {
    let root = root.canonicalize().expect("canonical benchmark root");
    let repository_commit = git_commit(&root);
    let repository_dirty = git_dirty(&root);
    if let Some(expected) = expected_commit {
        assert_eq!(repository_commit.as_deref(), Some(expected));
        assert_eq!(repository_dirty, Some(false));
    }
    let project = Arc::new(TestProject::new(root, language));
    let files = project
        .analyzable_files(language)
        .expect("enumerate benchmark files");
    let files = files.into_iter().collect::<Vec<_>>();
    let project_dyn = Arc::clone(&project) as Arc<dyn Project>;
    let workspace = WorkspaceAnalyzer::build(
        Arc::clone(&project_dyn),
        AnalyzerConfig {
            parallelism: Some(1),
            ..AnalyzerConfig::default()
        },
    );
    let materialized = materialize_corpus(&workspace, project_dyn.as_ref(), &files);
    let ir = count_ir(&materialized.artifacts);
    let (oracle_projection_ms, oracle) = measure_oracles(&workspace, &materialized.artifacts);
    let receiver = measure_receiver(&workspace);
    DatasetMeasurement {
        name: name.to_owned(),
        origin: origin.to_owned(),
        language: language.config_label().to_owned(),
        repository_commit,
        repository_dirty,
        files_seen: materialized.files_seen,
        files_materialized: materialized.artifacts.len(),
        unavailable_files: materialized.unavailable_files,
        cold_materialization_ms: materialized.cold_ms,
        warm_materialization_ms: materialized.warm_ms,
        warm_arc_reuse_count: materialized.warm_arc_reuse_count,
        ir,
        oracle_projection_ms,
        oracle,
        receiver,
    }
}

fn inline_dataset(
    name: &str,
    language: Language,
    file_name: &str,
    source: &str,
) -> DatasetMeasurement {
    let temp = tempfile::tempdir().expect("inline benchmark tempdir");
    fs::write(temp.path().join(file_name), source).expect("write inline benchmark source");
    measure_dataset(name, "inline_fixture", temp.path(), language, None)
}

fn materialize_one(
    workspace: &WorkspaceAnalyzer,
    file: &ProjectFile,
) -> Arc<brokk_bifrost::analyzer::semantic::SemanticArtifact> {
    let cancellation = CancellationToken::default();
    let mut budget = SemanticBudget::default();
    complete_artifact(
        workspace
            .materialize_program_semantics(
                file,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("materialize invalidation fixture"),
    )
    .expect("invalidation fixture must materialize completely")
}

fn measure_invalidation() -> InvalidationMeasurement {
    let temp = tempfile::tempdir().expect("invalidation tempdir");
    let root = temp
        .path()
        .canonicalize()
        .expect("canonical invalidation root");
    let file = ProjectFile::new(root.clone(), PathBuf::from("sample.ts"));
    file.write("export function value() { return { before: 1 }; }\n")
        .expect("write disk invalidation source");
    let project = Arc::new(TestProject::new(root.clone(), Language::TypeScript));
    let workspace = WorkspaceAnalyzer::build(project, AnalyzerConfig::default());

    let cancelled = CancellationToken::default();
    cancelled.cancel();
    let mut cancelled_budget = SemanticBudget::default();
    let incomplete = workspace
        .materialize_program_semantics(
            &file,
            &mut SemanticRequest::new(&mut cancelled_budget, &cancelled),
        )
        .expect("cancelled materialization");
    assert!(matches!(incomplete, SemanticOutcome::Cancelled { .. }));
    let first = materialize_one(&workspace, &file);

    file.write("export function value() { return { after: 2 }; }\n")
        .expect("update disk invalidation source");
    let disk_started = Instant::now();
    let disk_workspace = workspace.update(&BTreeSet::from([file.clone()]));
    let disk = materialize_one(&disk_workspace, &file);
    let disk_update_ms = disk_started.elapsed().as_secs_f64() * 1_000.0;
    let disk_warm = materialize_one(&disk_workspace, &file);

    let overlay_base = Arc::new(TestProject::new(root, Language::TypeScript));
    let overlay = Arc::new(OverlayProject::new(overlay_base));
    assert!(overlay.set(
        file.abs_path(),
        "export function value() { return { overlayOne: 3 }; }\n".to_owned(),
    ));
    let overlay_project = Arc::clone(&overlay) as Arc<dyn Project>;
    let overlay_workspace = WorkspaceAnalyzer::build(overlay_project, AnalyzerConfig::default());
    let overlay_first = materialize_one(&overlay_workspace, &file);
    assert!(overlay.set(
        file.abs_path(),
        "export function value() { return { overlayTwo: 4 }; }\n".to_owned(),
    ));
    let overlay_started = Instant::now();
    let overlay_updated = overlay_workspace.update(&BTreeSet::from([file.clone()]));
    let overlay_second = materialize_one(&overlay_updated, &file);
    let overlay_update_ms = overlay_started.elapsed().as_secs_f64() * 1_000.0;
    let overlay_warm = materialize_one(&overlay_updated, &file);

    InvalidationMeasurement {
        disk_update_ms,
        disk_key_changed: first.key() != disk.key(),
        disk_warm_arc_reused: Arc::ptr_eq(&disk, &disk_warm),
        overlay_update_ms,
        overlay_key_changed: overlay_first.key() != overlay_second.key(),
        overlay_warm_arc_reused: Arc::ptr_eq(&overlay_second, &overlay_warm),
        incomplete_request_followed_by_complete: !incomplete.is_complete(),
    }
}

fn sample() -> SampleResult {
    let provenance = benchmark_provenance();
    assert!(
        provenance.bifrost_tree_fingerprint.is_some(),
        "oracle samples require an exact Bifrost tree fingerprint"
    );
    let mut datasets = vec![
        inline_dataset(
            "inline_typescript",
            Language::TypeScript,
            "fixture.ts",
            TYPESCRIPT_FIXTURE,
        ),
        inline_dataset("inline_java", Language::Java, "Sample.java", JAVA_FIXTURE),
    ];
    if let Some(root) = std::env::var_os(TS_REPO_ENV) {
        datasets.push(measure_dataset(
            "external_vscode_typescript",
            "pinned_external_repository",
            Path::new(&root),
            Language::TypeScript,
            Some(VSCODE_COMMIT),
        ));
    }
    if let Some(root) = std::env::var_os(JAVA_REPO_ENV) {
        datasets.push(measure_dataset(
            "external_spring_petclinic_java",
            "pinned_external_repository",
            Path::new(&root),
            Language::Java,
            Some(SPRING_PETCLINIC_COMMIT),
        ));
    }
    SampleResult {
        format: "bifrost_semantic_oracle_benchmark/v1",
        kind: "sample",
        round: std::env::var(ROUND_ENV)
            .ok()
            .map(|value| value.parse().expect("non-negative benchmark round"))
            .unwrap_or(0),
        provenance,
        query_caps: QueryCaps {
            max_value_queries_per_dataset: MAX_VALUE_QUERIES,
            max_alias_queries_per_dataset: MAX_ALIAS_QUERIES,
        },
        datasets,
        invalidation: measure_invalidation(),
        recommendation: "retain complete semantic artifacts in generation-local memory; keep oracle projections request-local; do not add SQLite persistence under issue #816",
    }
}

#[test]
fn incomplete_materialization_and_source_changes_preserve_complete_only_reuse() {
    let measurement = measure_invalidation();
    assert!(measurement.incomplete_request_followed_by_complete);
    assert!(measurement.disk_key_changed);
    assert!(measurement.disk_warm_arc_reused);
    assert!(measurement.overlay_key_changed);
    assert!(measurement.overlay_warm_arc_reused);
}

#[test]
fn rust_control_adapter_stays_behind_the_neutral_oracle_boundary() {
    let temp = tempfile::tempdir().expect("Rust pressure-test tempdir");
    let root = temp.path().canonicalize().expect("canonical Rust root");
    let file = ProjectFile::new(root.clone(), PathBuf::from("lib.rs"));
    file.write(
        "struct Item;\nimpl Item { fn make() -> Self { Self } fn use_it(&self) {} }\nfn caller() { let item = Item::make(); item.use_it(); }\n",
    )
    .expect("write Rust pressure-test source");
    let workspace = WorkspaceAnalyzer::build(
        Arc::new(TestProject::new(root, Language::Rust)),
        AnalyzerConfig::default(),
    );
    let artifact = materialize_one(&workspace, &file);
    let oracle = workspace.semantic_oracle_provider();
    let cancellation = CancellationToken::default();
    let mut heap_queries = 0usize;
    let mut value_relations = 0usize;
    for procedure in artifact.procedures() {
        let handle = artifact
            .procedure_handle(procedure.id())
            .expect("Rust procedure handle");
        let mut budget = SemanticBudget::default();
        let outcome = oracle
            .procedure_relations(
                &handle,
                &OracleCallContext::empty(),
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("generic value-flow query on Rust control artifact");
        let snapshot = outcome
            .available_value()
            .expect("Rust control artifact keeps an explicit partial value-flow answer");
        for relation in snapshot.relations() {
            assert_ne!(
                relation.kind,
                ValueFlowRelationKind::LanguageDefined,
                "Rust value flow must stay behind the neutral oracle relation contract"
            );
            assert!(
                relation.is_proven_complete(),
                "retained Rust value-flow evidence must be proven and complete: {relation:#?}"
            );
            value_relations += 1;
        }
        assert_eq!(snapshot.coverage(), CandidateCoverage::Open);

        if let Some(value) = procedure.values().first() {
            let point = handle
                .point_handle(procedure.normal_exit_point())
                .expect("Rust normal-exit handle");
            let query = ValueAtPoint::new(
                handle.value_handle(value.id).expect("Rust value handle"),
                point,
                ObservationPhase::BeforeEffects,
                OracleCallContext::empty(),
            )
            .expect("Rust heap pressure-test query");
            let mut budget = SemanticBudget::default();
            let outcome = oracle
                .pointees(
                    &query,
                    &mut SemanticRequest::new(&mut budget, &cancellation),
                )
                .expect("generic points-to query on Rust control artifact");
            let coverage = outcome
                .available_value()
                .expect("Rust points-to answer retains an explicit bounded set")
                .objects()
                .coverage();
            assert!(
                !coverage.is_truncated(),
                "default-budget Rust points-to pressure queries must not truncate"
            );
            heap_queries += 1;
        }
    }
    assert!(
        heap_queries > 0,
        "Rust fixture must pressure-test heap coverage"
    );
    assert!(
        value_relations > 0,
        "Rust fixture must pressure-test neutral value-flow projection"
    );
}

#[test]
#[ignore = "measure-first semantic-oracle lifecycle benchmark; run explicitly in release mode"]
fn semantic_oracle_lifecycle_measurement() {
    println!(
        "{RESULT_PREFIX}{}",
        serde_json::to_string(&sample()).expect("serialize semantic-oracle benchmark")
    );
}
