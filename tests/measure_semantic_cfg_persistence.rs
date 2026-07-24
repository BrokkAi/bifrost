//! Optimistic packed-CFG persistence benchmark for issue #817.
//!
//! This benchmark deliberately keeps the candidate outside production.  It
//! stores the language-neutral control/call slice in one packed SQLite payload
//! per source file, then hydrates the exact bidirectional edge-ID layout used
//! by the in-memory CFG. Because the DTO is a lossy control/call projection,
//! its hydration time is an optimistic lower bound: a latency failure is
//! sufficient evidence not to add production persistence, while a pass is
//! explicitly inconclusive until an equivalent usable artifact is measured.
//!
//! Use `scripts/run-semantic-cfg-benchmarks.sh persistence` for the
//! decision-grade fresh-process matrix.

use std::collections::BTreeMap;
use std::fs;
use std::hint::black_box;
use std::io::Read;
use std::mem::size_of;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Instant;

use bincode::Options;
use brokk_bifrost::analyzer::semantic::{
    CancellationToken, CapabilitySupport, ControlContinuation, SemanticArtifact, SemanticBudget,
    SemanticOutcome, SemanticProviderError, SemanticRequest, StableDigest,
};
use brokk_bifrost::benchmark::{
    ArtifactPromotionGateStatus, ArtifactPromotionMeasurement, ArtifactPromotionThresholds,
    evaluate_artifact_promotion,
};
use brokk_bifrost::{
    AnalyzerConfig, Language, Project, ProjectFile, TestProject, WorkspaceAnalyzer,
};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};

const RESULT_PREFIX: &str = "BIFROST_SEMANTIC_CFG_PERSISTENCE_BENCHMARK=";
const MODE_ENV: &str = "BIFROST_SEMANTIC_CFG_PERSIST_MODE";
const DATASET_ENV: &str = "BIFROST_SEMANTIC_CFG_PERSIST_DATASET";
const DATABASE_ENV: &str = "BIFROST_SEMANTIC_CFG_PERSIST_DB";
const ROUND_ENV: &str = "BIFROST_SEMANTIC_CFG_BENCH_ROUND";
const SAMPLES_FILE_ENV: &str = "BIFROST_SEMANTIC_CFG_PERSIST_SAMPLES_FILE";
const TS_REPO_ENV: &str = "BIFROST_SEMANTIC_TS_REPO";
const JAVA_REPO_ENV: &str = "BIFROST_SEMANTIC_JAVA_REPO";
const VSCODE_COMMIT: &str = "19e0f9e681ecb8e5c09d8784acaa601316ca4571";
const SPRING_PETCLINIC_COMMIT: &str = "f182358d02e4a68e52bdbabf55ca7800288511e7";
const SNAPSHOT_VERSION: u32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Seed,
    Rebuild,
    BuildWrite,
    Hydrate,
    HydrateCold,
}

impl Mode {
    fn from_env() -> Self {
        match std::env::var(MODE_ENV).as_deref() {
            Ok("seed") => Self::Seed,
            Ok("rebuild") => Self::Rebuild,
            Ok("build_write") => Self::BuildWrite,
            Ok("hydrate") => Self::Hydrate,
            Ok("hydrate_cold") => Self::HydrateCold,
            Ok(other) => {
                panic!(
                    "{MODE_ENV} must be seed, rebuild, build_write, hydrate, or hydrate_cold; got {other:?}"
                )
            }
            Err(_) => Self::Rebuild,
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Seed => "seed",
            Self::Rebuild => "rebuild",
            Self::BuildWrite => "build_write",
            Self::Hydrate => "hydrate",
            Self::HydrateCold => "hydrate_cold",
        }
    }
}

#[derive(Debug, Clone)]
struct DatasetSpec {
    name: &'static str,
    root: PathBuf,
    language: Language,
    expected_commit: Option<&'static str>,
}

struct RebuiltDataset {
    analyzer: WorkspaceAnalyzer,
    files: Vec<ProjectFile>,
    artifacts: Vec<Arc<SemanticArtifact>>,
    operation_ms: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct PackedPoint {
    block: u32,
    source: u32,
    evidence: u32,
    event_count: u32,
    event_hash: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct PackedEdge {
    source: u32,
    target: u32,
    source_mapping: u32,
    evidence: u32,
    kind: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct PackedCall {
    point: u32,
    normal: i64,
    exceptional: i64,
    source: u32,
    evidence: u32,
    argument_count: u32,
    target_resolution: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct PackedGap {
    point: u32,
    source: u32,
    evidence: u32,
    subject: u64,
    capability: u64,
    kind: u64,
    detail: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PackedProcedure {
    kind: u64,
    properties: u8,
    lexical_parent: Option<u32>,
    entry: u32,
    normal_exit: u32,
    exceptional_exit: u32,
    value_count: u32,
    allocation_count: u32,
    memory_location_count: u32,
    capture_count: u32,
    source_mapping_count: u32,
    evidence_count: u32,
    points: Vec<PackedPoint>,
    edges: Vec<PackedEdge>,
    outgoing_offsets: Vec<u32>,
    incoming_offsets: Vec<u32>,
    incoming_edge_ids: Vec<u32>,
    calls: Vec<PackedCall>,
    gaps: Vec<PackedGap>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PackedFile {
    version: u32,
    artifact_key: [u8; 32],
    path: String,
    language: String,
    capabilities: Vec<u8>,
    procedures: Vec<PackedProcedure>,
}

#[derive(Debug)]
struct HydratedProcedure {
    point_count: usize,
    points: Box<[PackedPoint]>,
    edges: Box<[PackedEdge]>,
    outgoing_offsets: Box<[u32]>,
    incoming_offsets: Box<[u32]>,
    incoming_edge_ids: Box<[u32]>,
    calls: Box<[PackedCall]>,
    gaps: Box<[PackedGap]>,
}

#[derive(Debug)]
struct HydratedFile {
    path: Box<str>,
    artifact_key: [u8; 32],
    procedures: Box<[HydratedProcedure]>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct BenchmarkProvenance {
    bifrost_commit: Option<String>,
    bifrost_dirty: Option<bool>,
    bifrost_tree_fingerprint: Option<String>,
    repository_commit: Option<String>,
    repository_dirty: Option<bool>,
    rustc_version_verbose: Option<String>,
    operating_system: String,
    architecture: String,
    system_identity: Option<String>,
    cpu_model: Option<String>,
    logical_parallelism: Option<usize>,
    build_profile: String,
    pointer_width_bits: usize,
    endianness: String,
    crate_version: String,
    timer: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ExecutionProvenance {
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
    pointer_width_bits: usize,
    endianness: String,
    crate_version: String,
    timer: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct DatasetRepositoryProvenance {
    repository_commit: Option<String>,
    repository_dirty: Option<bool>,
}

impl BenchmarkProvenance {
    fn execution(&self) -> ExecutionProvenance {
        ExecutionProvenance {
            bifrost_commit: self.bifrost_commit.clone(),
            bifrost_dirty: self.bifrost_dirty,
            bifrost_tree_fingerprint: self.bifrost_tree_fingerprint.clone(),
            rustc_version_verbose: self.rustc_version_verbose.clone(),
            operating_system: self.operating_system.clone(),
            architecture: self.architecture.clone(),
            system_identity: self.system_identity.clone(),
            cpu_model: self.cpu_model.clone(),
            logical_parallelism: self.logical_parallelism,
            build_profile: self.build_profile.clone(),
            pointer_width_bits: self.pointer_width_bits,
            endianness: self.endianness.clone(),
            crate_version: self.crate_version.clone(),
            timer: self.timer.clone(),
        }
    }

    fn repository(&self) -> DatasetRepositoryProvenance {
        DatasetRepositoryProvenance {
            repository_commit: self.repository_commit.clone(),
            repository_dirty: self.repository_dirty,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SampleResult {
    format: String,
    kind: String,
    provenance: BenchmarkProvenance,
    round: usize,
    mode: String,
    cache_control: String,
    dataset: String,
    files: usize,
    procedures: usize,
    points: usize,
    edges: usize,
    calls: usize,
    gaps: usize,
    operation_ms: f64,
    repeat_materialization_ms: Option<f64>,
    packed_payload_bytes: u64,
    database_bytes: u64,
    estimated_hydrated_bytes: u64,
    peak_rss_bytes: u64,
    checksum: u64,
}

#[derive(Debug, Serialize)]
struct MedianMeasurement {
    mode: String,
    dataset: String,
    cache_control: String,
    operation_ms: f64,
    repeat_materialization_ms: Option<f64>,
    packed_payload_bytes: u64,
    database_bytes: u64,
    estimated_hydrated_bytes: u64,
    peak_rss_bytes: u64,
}

#[derive(Debug, Serialize)]
struct GateDatasetResult {
    dataset: String,
    hydration_speedup_percent: f64,
    hydration_saved_ms: f64,
    hydration_fast_enough: bool,
    hydration_absolute_saving_met: bool,
    rss_measurement_available: bool,
    rss_within_limit: bool,
    packed_size_within_limit: bool,
    cold_write_within_percent: bool,
    cold_write_absolute_overhead_met: bool,
    passed: bool,
}

#[derive(Debug, Serialize)]
struct AggregateResult {
    format: &'static str,
    kind: &'static str,
    aggregation_provenance: ExecutionProvenance,
    sample_execution_provenance: ExecutionProvenance,
    dataset_provenance: BTreeMap<String, DatasetRepositoryProvenance>,
    fresh_processes_per_mode: usize,
    discarded_warmups_per_mode: usize,
    retained_samples_per_mode: usize,
    raw_samples: BTreeMap<String, Vec<SampleResult>>,
    medians: Vec<MedianMeasurement>,
    external_gate: Vec<GateDatasetResult>,
    recommendation: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SnapshotError {
    Version,
    Identity,
    PointRows,
    EdgeRows,
    IncomingRows,
}

fn stable_hash(bytes: impl AsRef<[u8]>) -> u64 {
    bytes
        .as_ref()
        .iter()
        .fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
            (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3)
        })
}

fn continuation_code(continuation: ControlContinuation) -> i64 {
    match continuation {
        ControlContinuation::Target(target) => i64::from(target.get()),
        ControlContinuation::Absent => -1,
        ControlContinuation::Unknown => -2,
        ControlContinuation::Unsupported => -3,
        ControlContinuation::Unproven => -4,
        ControlContinuation::ExceededBudget => -5,
    }
}

fn u32_len(length: usize, label: &str) -> u32 {
    u32::try_from(length).unwrap_or_else(|_| panic!("{label} count must fit u32"))
}

fn edge_kind_code(label: &str) -> u8 {
    match label {
        "normal" => 0,
        "conditional_true" => 1,
        "conditional_false" => 2,
        "switch_case" => 3,
        "loop_back" => 4,
        "exceptional" => 5,
        "cleanup" => 6,
        "async_normal" => 7,
        "async_exceptional" => 8,
        other => panic!("unregistered control edge kind {other}"),
    }
}

fn pack_artifact(artifact: &SemanticArtifact) -> PackedFile {
    let procedures = artifact
        .procedures()
        .iter()
        .map(|procedure| {
            let points = procedure
                .points()
                .iter()
                .map(|point| {
                    let mut event_hash = 0u64;
                    for event in &point.events {
                        event_hash = event_hash
                            .rotate_left(7)
                            .wrapping_add(stable_hash(event.effect.label()))
                            .wrapping_add(u64::from(event.source.get()) << 1)
                            .wrapping_add(u64::from(event.evidence.get()) << 17);
                    }
                    PackedPoint {
                        block: point.block.get(),
                        source: point.source.get(),
                        evidence: point.evidence.get(),
                        event_count: u32_len(point.events.len(), "event"),
                        event_hash,
                    }
                })
                .collect::<Vec<_>>();
            let edges = procedure
                .cfg()
                .edges()
                .iter()
                .map(|edge| PackedEdge {
                    source: edge.source_point.get(),
                    target: edge.target_point.get(),
                    source_mapping: edge.source.get(),
                    evidence: edge.evidence.get(),
                    kind: edge_kind_code(edge.kind.label()),
                })
                .collect::<Vec<_>>();
            let mut outgoing_offsets = Vec::with_capacity(points.len() + 1);
            outgoing_offsets.push(0);
            let mut edge_cursor = 0usize;
            for point in 0..points.len() {
                while edge_cursor < edges.len() && edges[edge_cursor].source as usize == point {
                    edge_cursor += 1;
                }
                outgoing_offsets.push(u32_len(edge_cursor, "outgoing edge"));
            }
            assert_eq!(edge_cursor, edges.len());
            let mut incoming_counts = vec![0u32; points.len()];
            for edge in &edges {
                incoming_counts[edge.target as usize] += 1;
            }
            let mut incoming_offsets = Vec::with_capacity(points.len() + 1);
            incoming_offsets.push(0u32);
            for count in incoming_counts {
                incoming_offsets.push(incoming_offsets.last().copied().unwrap() + count);
            }
            let mut incoming_cursors = incoming_offsets[..points.len()].to_vec();
            let mut incoming_edge_ids = vec![0u32; edges.len()];
            for (edge_id, edge) in edges.iter().enumerate() {
                let target = edge.target as usize;
                let destination = incoming_cursors[target] as usize;
                incoming_edge_ids[destination] = u32_len(edge_id, "incoming edge ID");
                incoming_cursors[target] += 1;
            }
            let calls = procedure
                .call_sites()
                .iter()
                .map(|call| PackedCall {
                    point: call.point.get(),
                    normal: continuation_code(call.normal_continuation),
                    exceptional: continuation_code(call.exceptional_continuation),
                    source: call.source.get(),
                    evidence: call.evidence.get(),
                    argument_count: u32_len(call.arguments.len(), "call argument"),
                    target_resolution: stable_hash(call.declared_targets.label()),
                })
                .collect();
            let gaps = procedure
                .gaps()
                .iter()
                .map(|gap| PackedGap {
                    point: gap.point.get(),
                    source: gap.source.get(),
                    evidence: gap.evidence.get(),
                    subject: stable_hash(gap.subject.label()),
                    capability: stable_hash(gap.capability.label()),
                    kind: stable_hash(gap.kind.label()),
                    detail: stable_hash(gap.detail.as_bytes()),
                })
                .collect();
            let properties = procedure.properties();
            PackedProcedure {
                kind: stable_hash(procedure.kind().label()),
                properties: u8::from(properties.is_async)
                    | (u8::from(properties.is_generator) << 1)
                    | (u8::from(properties.is_static) << 2)
                    | (u8::from(properties.is_synthetic) << 3)
                    | (u8::from(properties.invocation.label() == "deferred") << 4),
                lexical_parent: procedure.lexical_parent().map(|id| id.get()),
                entry: procedure.entry_point().get(),
                normal_exit: procedure.normal_exit_point().get(),
                exceptional_exit: procedure.exceptional_exit_point().get(),
                value_count: u32_len(procedure.values().len(), "value"),
                allocation_count: u32_len(procedure.allocations().len(), "allocation"),
                memory_location_count: u32_len(
                    procedure.memory_locations().len(),
                    "memory location",
                ),
                capture_count: u32_len(procedure.captures().len(), "capture"),
                source_mapping_count: u32_len(procedure.source_mappings().len(), "source mapping"),
                evidence_count: u32_len(procedure.evidence_rows().len(), "evidence"),
                points,
                edges,
                outgoing_offsets,
                incoming_offsets,
                incoming_edge_ids,
                calls,
                gaps,
            }
        })
        .collect();
    PackedFile {
        version: SNAPSHOT_VERSION,
        artifact_key: *artifact.key().fingerprint().as_bytes(),
        path: artifact.key().path().as_str().to_owned(),
        language: artifact.key().language().stable_label().to_owned(),
        capabilities: artifact
            .capabilities()
            .iter()
            .map(|(_, support)| match support {
                CapabilitySupport::Unsupported => 0,
                CapabilitySupport::Partial => 1,
                CapabilitySupport::Complete => 2,
            })
            .collect(),
        procedures,
    }
}

fn hydrate_file(
    packed: PackedFile,
    expected_identity: Option<[u8; 32]>,
) -> Result<HydratedFile, SnapshotError> {
    if packed.version != SNAPSHOT_VERSION {
        return Err(SnapshotError::Version);
    }
    if expected_identity.is_some_and(|identity| identity != packed.artifact_key) {
        return Err(SnapshotError::Identity);
    }
    let mut procedures = Vec::with_capacity(packed.procedures.len());
    for procedure in packed.procedures {
        let point_count = procedure.points.len();
        let edge_count = procedure.edges.len();
        if point_count < 3
            || [
                procedure.entry,
                procedure.normal_exit,
                procedure.exceptional_exit,
            ]
            .into_iter()
            .any(|point| point as usize >= point_count)
        {
            return Err(SnapshotError::PointRows);
        }
        if procedure.edges.iter().any(|edge| {
            edge.source as usize >= point_count
                || edge.target as usize >= point_count
                || edge.kind > 8
        }) {
            return Err(SnapshotError::EdgeRows);
        }
        if procedure.outgoing_offsets.len() != point_count + 1
            || procedure.outgoing_offsets.first() != Some(&0)
            || procedure.outgoing_offsets.last().copied() != Some(u32_len(edge_count, "edge"))
            || !procedure
                .outgoing_offsets
                .windows(2)
                .all(|pair| pair[0] <= pair[1])
        {
            return Err(SnapshotError::EdgeRows);
        }
        for (point, row) in procedure.outgoing_offsets.windows(2).enumerate() {
            if procedure.edges[row[0] as usize..row[1] as usize]
                .iter()
                .any(|edge| edge.source as usize != point)
            {
                return Err(SnapshotError::EdgeRows);
            }
        }
        if procedure.incoming_offsets.len() != point_count + 1
            || procedure.incoming_offsets.first() != Some(&0)
            || procedure.incoming_offsets.last().copied() != Some(u32_len(edge_count, "edge"))
            || procedure.incoming_edge_ids.len() != edge_count
            || !procedure
                .incoming_offsets
                .windows(2)
                .all(|pair| pair[0] <= pair[1])
            || procedure
                .incoming_edge_ids
                .iter()
                .any(|edge| *edge as usize >= edge_count)
        {
            return Err(SnapshotError::IncomingRows);
        }
        let mut seen_incoming_edge_ids = vec![false; edge_count];
        for edge_id in &procedure.incoming_edge_ids {
            let seen = &mut seen_incoming_edge_ids[*edge_id as usize];
            if *seen {
                return Err(SnapshotError::IncomingRows);
            }
            *seen = true;
        }
        if seen_incoming_edge_ids.iter().any(|seen| !seen) {
            return Err(SnapshotError::IncomingRows);
        }
        for (point, row) in procedure.incoming_offsets.windows(2).enumerate() {
            if procedure.incoming_edge_ids[row[0] as usize..row[1] as usize]
                .iter()
                .any(|edge_id| procedure.edges[*edge_id as usize].target as usize != point)
            {
                return Err(SnapshotError::IncomingRows);
            }
        }
        procedures.push(HydratedProcedure {
            point_count,
            points: procedure.points.into_boxed_slice(),
            edges: procedure.edges.into_boxed_slice(),
            outgoing_offsets: procedure.outgoing_offsets.into_boxed_slice(),
            incoming_offsets: procedure.incoming_offsets.into_boxed_slice(),
            incoming_edge_ids: procedure.incoming_edge_ids.into_boxed_slice(),
            calls: procedure.calls.into_boxed_slice(),
            gaps: procedure.gaps.into_boxed_slice(),
        });
    }
    Ok(HydratedFile {
        path: packed.path.into_boxed_str(),
        artifact_key: packed.artifact_key,
        procedures: procedures.into_boxed_slice(),
    })
}

fn encode_snapshot(snapshot: &PackedFile) -> Vec<u8> {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .serialize(snapshot)
        .expect("serialize benchmark semantic CFG snapshot")
}

fn decode_snapshot(bytes: &[u8]) -> Result<PackedFile, bincode::Error> {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(512 * 1024 * 1024)
        .reject_trailing_bytes()
        .deserialize(bytes)
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

fn dataset_spec() -> DatasetSpec {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    match std::env::var(DATASET_ENV).as_deref() {
        Ok("fixture_typescript") => DatasetSpec {
            name: "fixture_typescript",
            root: manifest.join("tests/fixtures/testcode-ts"),
            language: Language::TypeScript,
            expected_commit: None,
        },
        Ok("fixture_java") => DatasetSpec {
            name: "fixture_java",
            root: manifest.join("tests/fixtures/testcode-java"),
            language: Language::Java,
            expected_commit: None,
        },
        Ok("external_vscode_typescript") => DatasetSpec {
            name: "external_vscode_typescript",
            root: PathBuf::from(
                std::env::var_os(TS_REPO_ENV)
                    .unwrap_or_else(|| panic!("{TS_REPO_ENV} is required for the VS Code corpus")),
            ),
            language: Language::TypeScript,
            expected_commit: Some(VSCODE_COMMIT),
        },
        Ok("external_spring_petclinic_java") => DatasetSpec {
            name: "external_spring_petclinic_java",
            root: PathBuf::from(std::env::var_os(JAVA_REPO_ENV).unwrap_or_else(|| {
                panic!("{JAVA_REPO_ENV} is required for the Spring Petclinic corpus")
            })),
            language: Language::Java,
            expected_commit: Some(SPRING_PETCLINIC_COMMIT),
        },
        Ok(other) => panic!("unknown {DATASET_ENV} value {other:?}"),
        Err(_) => DatasetSpec {
            name: "fixture_typescript",
            root: manifest.join("tests/fixtures/testcode-ts"),
            language: Language::TypeScript,
            expected_commit: None,
        },
    }
}

impl DatasetSpec {
    fn canonicalize(mut self) -> Self {
        self.root = self.root.canonicalize().unwrap_or_else(|error| {
            panic!(
                "canonicalize benchmark corpus {}: {error}",
                self.root.display()
            )
        });
        if let Some(expected) = self.expected_commit {
            assert_eq!(
                git_commit(&self.root).as_deref(),
                Some(expected),
                "{} must be at its pinned commit",
                self.name
            );
            assert_eq!(
                git_dirty(&self.root),
                Some(false),
                "{} must be clean at its pinned commit",
                self.name
            );
        }
        self
    }
}

fn materialize_dataset(spec: &DatasetSpec) -> RebuiltDataset {
    let source_project = Arc::new(TestProject::new(spec.root.clone(), spec.language));
    let files = source_project
        .analyzable_files(spec.language)
        .expect("list semantic persistence benchmark files");
    assert!(
        !files.is_empty(),
        "benchmark corpus must contain source files"
    );
    let project: Arc<dyn Project> = Arc::clone(&source_project) as Arc<dyn Project>;
    let started = Instant::now();
    let analyzer = WorkspaceAnalyzer::build(
        project,
        AnalyzerConfig {
            parallelism: Some(1),
            memo_cache_budget_bytes: Some(2 * 1024 * 1024 * 1024),
            ..AnalyzerConfig::default()
        },
    );
    let cancellation = CancellationToken::default();
    let mut materialized_files = Vec::with_capacity(files.len());
    let mut artifacts = Vec::with_capacity(files.len());
    for file in &files {
        let mut budget = SemanticBudget::default();
        let outcome = match analyzer.materialize_program_semantics(
            file,
            &mut SemanticRequest::new(&mut budget, &cancellation),
        ) {
            Ok(outcome) => outcome,
            Err(SemanticProviderError::SourceAccess(_)) => {
                source_project.read_source(file).unwrap_or_else(|error| {
                    panic!(
                        "semantic persistence source {} became unreadable after enumeration: {error}",
                        file.rel_path().display()
                    )
                });
                continue;
            }
            Err(error) => {
                panic!(
                    "materialize semantic persistence corpus {}: {error}",
                    file.rel_path().display()
                )
            }
        };
        match outcome {
            SemanticOutcome::Complete { value, .. } => {
                materialized_files.push(file.clone());
                artifacts.push(value);
            }
            SemanticOutcome::Unsupported { .. }
            | SemanticOutcome::Ambiguous { .. }
            | SemanticOutcome::Unknown { .. }
            | SemanticOutcome::Unproven { .. }
            | SemanticOutcome::ExceededBudget { .. } => {}
            SemanticOutcome::Cancelled { .. } => {
                panic!("semantic persistence benchmark cancellation was not requested")
            }
        }
    }
    assert!(
        !artifacts.is_empty(),
        "semantic persistence corpus must contain at least one parse-safe source file"
    );
    let operation_ms = started.elapsed().as_secs_f64() * 1_000.0;
    RebuiltDataset {
        analyzer,
        files: materialized_files,
        artifacts,
        operation_ms,
    }
}

fn measure_repeat_materialization(rebuilt: &RebuiltDataset) -> f64 {
    let cancellation = CancellationToken::default();
    let repeat_started = Instant::now();
    for (file, expected) in rebuilt.files.iter().zip(&rebuilt.artifacts) {
        let mut budget = SemanticBudget::default();
        let outcome = rebuilt
            .analyzer
            .materialize_program_semantics(
                file,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("repeat semantic materialization");
        let SemanticOutcome::Complete { value, .. } = outcome else {
            panic!("repeated semantic materialization must remain complete");
        };
        assert_eq!(
            value.key(),
            expected.key(),
            "repeated semantic materialization must preserve exact artifact identity"
        );
        assert_eq!(
            value.work(),
            expected.work(),
            "repeated semantic materialization must preserve the retained-work census"
        );
        // A whole-corpus sweep can exceed the production byte-bounded cache and
        // legitimately rebuild evicted artifacts. Pointer reuse is covered by
        // the cache's focused contract tests; this benchmark measures the
        // repeated provider operation under the configured lifecycle policy.
        black_box(value);
    }
    repeat_started.elapsed().as_secs_f64() * 1_000.0
}

fn database_path() -> PathBuf {
    PathBuf::from(
        std::env::var_os(DATABASE_ENV)
            .unwrap_or_else(|| panic!("{DATABASE_ENV} is required for persistence modes")),
    )
}

fn initialize_database(connection: &Connection) {
    connection
        .execute_batch(
            "PRAGMA journal_mode=DELETE;
             PRAGMA synchronous=FULL;
             CREATE TABLE IF NOT EXISTS benchmark_metadata (
                 dataset TEXT PRIMARY KEY NOT NULL,
                 repository_commit TEXT,
                 bifrost_tree_fingerprint TEXT NOT NULL,
                 snapshot_version INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS semantic_cfg_snapshots (
                 path TEXT PRIMARY KEY NOT NULL,
                 artifact_key BLOB NOT NULL,
                 payload BLOB NOT NULL
             );
             DELETE FROM benchmark_metadata;
             DELETE FROM semantic_cfg_snapshots;",
        )
        .expect("initialize benchmark semantic CFG database");
}

fn write_database(
    database: &Path,
    spec: &DatasetSpec,
    repository_commit: Option<&str>,
    bifrost_tree_fingerprint: &str,
    snapshots: &[PackedFile],
) -> (u64, u64) {
    if let Some(parent) = database.parent() {
        fs::create_dir_all(parent).expect("create semantic CFG benchmark database parent");
    }
    let mut connection = Connection::open(database).expect("open semantic CFG benchmark database");
    initialize_database(&connection);
    let transaction = connection
        .transaction()
        .expect("begin semantic CFG benchmark transaction");
    transaction
        .execute(
            "INSERT INTO benchmark_metadata(
                 dataset,
                 repository_commit,
                 bifrost_tree_fingerprint,
                 snapshot_version
             ) VALUES (?1, ?2, ?3, ?4)",
            params![
                spec.name,
                repository_commit,
                bifrost_tree_fingerprint,
                SNAPSHOT_VERSION
            ],
        )
        .expect("insert semantic CFG benchmark metadata");
    let mut payload_bytes = 0u64;
    {
        let mut statement = transaction
            .prepare(
                "INSERT INTO semantic_cfg_snapshots(path, artifact_key, payload)
                 VALUES (?1, ?2, ?3)",
            )
            .expect("prepare semantic CFG benchmark insert");
        for snapshot in snapshots {
            let payload = encode_snapshot(snapshot);
            payload_bytes = payload_bytes
                .checked_add(u64::try_from(payload.len()).expect("payload length must fit u64"))
                .expect("aggregate payload bytes must fit u64");
            statement
                .execute(params![snapshot.path, &snapshot.artifact_key[..], payload])
                .expect("insert semantic CFG benchmark snapshot");
        }
    }
    transaction
        .commit()
        .expect("commit semantic CFG benchmark transaction");
    connection
        .execute_batch("PRAGMA optimize;")
        .expect("optimize semantic CFG benchmark database");
    drop(connection);
    let database_bytes = database
        .metadata()
        .expect("stat semantic CFG benchmark database")
        .len();
    (payload_bytes, database_bytes)
}

fn read_database(
    database: &Path,
    spec: &DatasetSpec,
    expected_repository_commit: Option<&str>,
    expected_bifrost_tree_fingerprint: &str,
) -> (Vec<HydratedFile>, u64) {
    let connection =
        Connection::open(database).expect("open seeded semantic CFG benchmark database");
    let (dataset, repository_commit, tree_fingerprint, version): (
        String,
        Option<String>,
        String,
        u32,
    ) = connection
        .query_row(
            "SELECT dataset, repository_commit, bifrost_tree_fingerprint, snapshot_version
             FROM benchmark_metadata",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .expect("read semantic CFG benchmark metadata");
    assert_eq!(dataset, spec.name, "seeded dataset identity drifted");
    assert_eq!(
        repository_commit.as_deref(),
        expected_repository_commit,
        "seeded repository identity drifted"
    );
    assert_eq!(
        tree_fingerprint, expected_bifrost_tree_fingerprint,
        "seeded Bifrost tree identity drifted"
    );
    assert_eq!(version, SNAPSHOT_VERSION, "seeded snapshot version drifted");
    let mut statement = connection
        .prepare("SELECT artifact_key, payload FROM semantic_cfg_snapshots ORDER BY path")
        .expect("prepare semantic CFG benchmark read");
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
        })
        .expect("query semantic CFG benchmark snapshots");
    let mut payload_bytes = 0u64;
    let mut files = Vec::new();
    for row in rows {
        let (identity, payload) = row.expect("read semantic CFG benchmark snapshot row");
        let identity: [u8; 32] = identity
            .try_into()
            .expect("stored semantic artifact key must contain 32 bytes");
        payload_bytes += u64::try_from(payload.len()).expect("payload length must fit u64");
        let packed = decode_snapshot(&payload).expect("decode semantic CFG benchmark snapshot");
        files.push(
            hydrate_file(packed, Some(identity))
                .expect("validate and hydrate semantic CFG benchmark snapshot"),
        );
    }
    assert!(!files.is_empty(), "seeded database must contain snapshots");
    (files, payload_bytes)
}

#[cfg(unix)]
fn peak_rss_bytes() -> u64 {
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    let result = unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };
    assert_eq!(result, 0, "getrusage failed");
    let max_rss = usage.ru_maxrss.max(0) as u64;
    if cfg!(target_os = "macos") {
        max_rss
    } else {
        max_rss * 1024
    }
}

#[cfg(not(unix))]
fn peak_rss_bytes() -> u64 {
    0
}

enum ColdReadGuard {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    Enabled {
        #[cfg(target_os = "macos")]
        file: fs::File,
        label: &'static str,
    },
    Unavailable,
}

impl ColdReadGuard {
    fn enable(database: &Path) -> Self {
        #[cfg(target_os = "macos")]
        {
            use std::os::fd::AsRawFd;

            let Ok(file) = fs::OpenOptions::new().read(true).write(true).open(database) else {
                return Self::Unavailable;
            };
            if file.sync_all().is_err() {
                return Self::Unavailable;
            }
            let result = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GLOBAL_NOCACHE, 1) };
            if result == 0 {
                return Self::Enabled {
                    file,
                    label: "macos_f_global_nocache",
                };
            }
            Self::Unavailable
        }
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;

            let Ok(file) = fs::OpenOptions::new().read(true).write(true).open(database) else {
                return Self::Unavailable;
            };
            if file.sync_all().is_err() {
                return Self::Unavailable;
            }
            let result =
                unsafe { libc::posix_fadvise(file.as_raw_fd(), 0, 0, libc::POSIX_FADV_DONTNEED) };
            if result == 0 {
                return Self::Enabled {
                    label: "linux_posix_fadvise_dontneed",
                };
            }
            Self::Unavailable
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            let _ = database;
            Self::Unavailable
        }
    }

    const fn label(&self) -> &'static str {
        match self {
            #[cfg(any(target_os = "macos", target_os = "linux"))]
            Self::Enabled { label, .. } => label,
            Self::Unavailable => "unavailable",
        }
    }

    const fn is_available(&self) -> bool {
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        {
            matches!(self, Self::Enabled { .. })
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            false
        }
    }
}

impl Drop for ColdReadGuard {
    fn drop(&mut self) {
        #[cfg(target_os = "macos")]
        if let Self::Enabled { file, .. } = self {
            use std::os::fd::AsRawFd;

            let _ = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GLOBAL_NOCACHE, 0) };
        }
    }
}

fn prime_database_pages(database: &Path) {
    let mut file = fs::File::open(database).expect("open semantic CFG database for cache priming");
    let mut buffer = [0u8; 64 * 1024];
    let mut checksum = 0u64;
    loop {
        let read = file
            .read(&mut buffer)
            .expect("prime semantic CFG database pages");
        if read == 0 {
            break;
        }
        checksum = checksum
            .rotate_left(7)
            .wrapping_add(stable_hash(&buffer[..read]));
    }
    black_box(checksum);
}

fn hydrated_counts(files: &[HydratedFile]) -> (usize, usize, usize, usize, usize) {
    let mut procedures = 0usize;
    let mut points = 0usize;
    let mut edges = 0usize;
    let mut calls = 0usize;
    let mut gaps = 0usize;
    for file in files {
        procedures += file.procedures.len();
        for procedure in &file.procedures {
            points += procedure.point_count;
            edges += procedure.edges.len();
            calls += procedure.calls.len();
            gaps += procedure.gaps.len();
        }
    }
    (procedures, points, edges, calls, gaps)
}

fn checksum(files: &[HydratedFile]) -> u64 {
    let mut checksum = 0u64;
    let mut canonical_files = files.iter().collect::<Vec<_>>();
    canonical_files.sort_unstable_by(|left, right| left.path.cmp(&right.path));
    for file in canonical_files {
        checksum = checksum
            .rotate_left(11)
            .wrapping_add(stable_hash(file.path.as_bytes()))
            .wrapping_add(u64::from_le_bytes(
                file.artifact_key[..8].try_into().expect("eight key bytes"),
            ));
        for procedure in &file.procedures {
            for point in 0..procedure.point_count {
                let point_row = procedure.points[point];
                checksum = checksum
                    .rotate_left(5)
                    .wrapping_add(u64::from(point_row.block))
                    .wrapping_add(point_row.event_hash);
                let outgoing = procedure.outgoing_offsets[point] as usize
                    ..procedure.outgoing_offsets[point + 1] as usize;
                for edge in &procedure.edges[outgoing] {
                    checksum = checksum
                        .rotate_left(7)
                        .wrapping_add(u64::from(edge.source) << 32 | u64::from(edge.target))
                        .wrapping_add(u64::from(edge.kind));
                }
                let incoming = procedure.incoming_offsets[point] as usize
                    ..procedure.incoming_offsets[point + 1] as usize;
                for edge_id in &procedure.incoming_edge_ids[incoming] {
                    checksum = checksum.rotate_left(3).wrapping_add(u64::from(*edge_id));
                }
            }
            for call in &procedure.calls {
                checksum = checksum
                    .rotate_left(13)
                    .wrapping_add(u64::from(call.point))
                    .wrapping_add(call.target_resolution);
            }
            for gap in &procedure.gaps {
                checksum = checksum
                    .rotate_left(17)
                    .wrapping_add(u64::from(gap.point))
                    .wrapping_add(gap.capability)
                    .wrapping_add(gap.detail);
            }
        }
    }
    black_box(checksum)
}

fn estimated_hydrated_bytes(files: &[HydratedFile]) -> u64 {
    let mut bytes = 0usize;
    for file in files {
        bytes = bytes
            .saturating_add(file.path.len())
            .saturating_add(size_of::<HydratedFile>())
            .saturating_add(
                file.procedures
                    .len()
                    .saturating_mul(size_of::<HydratedProcedure>()),
            );
        for procedure in &file.procedures {
            bytes = bytes
                .saturating_add(
                    procedure
                        .points
                        .len()
                        .saturating_mul(size_of::<PackedPoint>()),
                )
                .saturating_add(
                    procedure
                        .edges
                        .len()
                        .saturating_mul(size_of::<PackedEdge>()),
                )
                .saturating_add(
                    procedure
                        .outgoing_offsets
                        .len()
                        .saturating_mul(size_of::<u32>()),
                )
                .saturating_add(
                    procedure
                        .incoming_offsets
                        .len()
                        .saturating_mul(size_of::<u32>()),
                )
                .saturating_add(
                    procedure
                        .incoming_edge_ids
                        .len()
                        .saturating_mul(size_of::<u32>()),
                )
                .saturating_add(
                    procedure
                        .calls
                        .len()
                        .saturating_mul(size_of::<PackedCall>()),
                )
                .saturating_add(procedure.gaps.len().saturating_mul(size_of::<PackedGap>()));
        }
    }
    u64::try_from(bytes).expect("estimated hydrated bytes must fit u64")
}

fn round() -> usize {
    std::env::var(ROUND_ENV)
        .ok()
        .map(|value| {
            value
                .parse::<usize>()
                .unwrap_or_else(|_| panic!("{ROUND_ENV} must be a non-negative integer"))
        })
        .unwrap_or(0)
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
            .or_else(|| {
                command_output("system_profiler", &["SPHardwareDataType"]).and_then(|profile| {
                    profile.lines().find_map(|line| {
                        line.trim()
                            .strip_prefix("Chip:")
                            .map(|chip| chip.trim().to_owned())
                    })
                })
            })
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

fn current_execution_provenance() -> ExecutionProvenance {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_owned());
    ExecutionProvenance {
        bifrost_commit: git_commit(manifest),
        bifrost_dirty: git_dirty(manifest),
        bifrost_tree_fingerprint: bifrost_tree_fingerprint(manifest),
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
        pointer_width_bits: usize::BITS as usize,
        endianness: if cfg!(target_endian = "little") {
            "little".to_owned()
        } else {
            "big".to_owned()
        },
        crate_version: env!("CARGO_PKG_VERSION").to_owned(),
        timer: "std::time::Instant monotonic elapsed wall time".to_owned(),
    }
}

fn provenance(spec: &DatasetSpec) -> BenchmarkProvenance {
    let execution = current_execution_provenance();
    BenchmarkProvenance {
        bifrost_commit: execution.bifrost_commit,
        bifrost_dirty: execution.bifrost_dirty,
        bifrost_tree_fingerprint: execution.bifrost_tree_fingerprint,
        repository_commit: git_commit(&spec.root),
        repository_dirty: git_dirty(&spec.root),
        rustc_version_verbose: execution.rustc_version_verbose,
        operating_system: execution.operating_system,
        architecture: execution.architecture,
        system_identity: execution.system_identity,
        cpu_model: execution.cpu_model,
        logical_parallelism: execution.logical_parallelism,
        build_profile: execution.build_profile,
        pointer_width_bits: execution.pointer_width_bits,
        endianness: execution.endianness,
        crate_version: execution.crate_version,
        timer: execution.timer,
    }
}

fn sample() -> SampleResult {
    let mode = Mode::from_env();
    let spec = dataset_spec().canonicalize();
    let sample_provenance = provenance(&spec);
    let repository_commit = sample_provenance.repository_commit.as_deref();
    let tree_fingerprint = sample_provenance
        .bifrost_tree_fingerprint
        .as_deref()
        .expect("decision-grade persistence samples require an exact Bifrost tree fingerprint");
    let mut packed_payload_bytes = 0u64;
    let mut database_bytes = 0u64;
    let (
        files,
        operation_ms,
        repeat_materialization_ms,
        expected_files,
        peak_rss_bytes,
        cache_control,
    ) = match mode {
        Mode::Seed | Mode::BuildWrite => {
            let rebuilt = materialize_dataset(&spec);
            let persistence_started = Instant::now();
            let snapshots = rebuilt
                .artifacts
                .iter()
                .map(|artifact| pack_artifact(artifact))
                .collect::<Vec<_>>();
            let database = database_path();
            (packed_payload_bytes, database_bytes) = write_database(
                &database,
                &spec,
                repository_commit,
                tree_fingerprint,
                &snapshots,
            );
            let operation_ms =
                rebuilt.operation_ms + persistence_started.elapsed().as_secs_f64() * 1_000.0;
            let peak_rss_bytes = peak_rss_bytes();
            let repeat_ms = measure_repeat_materialization(&rebuilt);
            let files = snapshots
                .into_iter()
                .map(|snapshot| {
                    let identity = snapshot.artifact_key;
                    hydrate_file(snapshot, Some(identity)).expect("hydrate freshly packed snapshot")
                })
                .collect();
            (
                files,
                operation_ms,
                Some(repeat_ms),
                rebuilt.files.len(),
                peak_rss_bytes,
                "not_requested".to_owned(),
            )
        }
        Mode::Rebuild => {
            let rebuilt = materialize_dataset(&spec);
            let peak_rss_bytes = peak_rss_bytes();
            let repeat_ms = measure_repeat_materialization(&rebuilt);
            let files = rebuilt
                .artifacts
                .iter()
                .map(|artifact| {
                    let snapshot = pack_artifact(artifact);
                    let identity = snapshot.artifact_key;
                    hydrate_file(snapshot, Some(identity)).expect("hydrate rebuilt snapshot")
                })
                .collect();
            (
                files,
                rebuilt.operation_ms,
                Some(repeat_ms),
                rebuilt.files.len(),
                peak_rss_bytes,
                "not_requested".to_owned(),
            )
        }
        Mode::Hydrate | Mode::HydrateCold => {
            let database = database_path();
            let cold_guard = if mode == Mode::HydrateCold {
                let guard = ColdReadGuard::enable(&database);
                if cfg!(any(target_os = "macos", target_os = "linux")) {
                    assert!(
                        guard.is_available(),
                        "cold hydration requires supported cache control on this host"
                    );
                }
                Some(guard)
            } else {
                prime_database_pages(&database);
                None
            };
            let cache_control = cold_guard
                .as_ref()
                .map_or("primed_sequential_read", |guard| guard.label());
            let started = Instant::now();
            let (files, payload_bytes) =
                read_database(&database, &spec, repository_commit, tree_fingerprint);
            packed_payload_bytes = payload_bytes;
            database_bytes = database
                .metadata()
                .expect("stat hydrated semantic CFG database")
                .len();
            let operation_ms = started.elapsed().as_secs_f64() * 1_000.0;
            let expected_files = files.len();
            let peak_rss_bytes = peak_rss_bytes();
            (
                files,
                operation_ms,
                None,
                expected_files,
                peak_rss_bytes,
                cache_control.to_owned(),
            )
        }
    };
    assert_eq!(files.len(), expected_files);
    let (procedures, points, edges, calls, gaps) = hydrated_counts(&files);
    let checksum = checksum(&files);
    SampleResult {
        format: "bifrost_semantic_cfg_persistence_benchmark/v4".to_owned(),
        kind: "sample".to_owned(),
        provenance: sample_provenance,
        round: round(),
        mode: mode.label().to_owned(),
        cache_control,
        dataset: spec.name.to_owned(),
        files: files.len(),
        procedures,
        points,
        edges,
        calls,
        gaps,
        operation_ms,
        repeat_materialization_ms,
        packed_payload_bytes,
        database_bytes,
        estimated_hydrated_bytes: estimated_hydrated_bytes(&files),
        peak_rss_bytes,
        checksum,
    }
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

fn assert_same_group(reference: &SampleResult, candidate: &SampleResult, group: &str) {
    assert_eq!(candidate.format, reference.format, "format drift: {group}");
    assert_eq!(candidate.kind, reference.kind, "kind drift: {group}");
    assert_eq!(
        candidate.provenance, reference.provenance,
        "provenance drift: {group}"
    );
    assert_eq!(candidate.mode, reference.mode, "mode drift: {group}");
    assert_eq!(
        candidate.cache_control, reference.cache_control,
        "cache-control drift: {group}"
    );
    assert_eq!(
        candidate.dataset, reference.dataset,
        "dataset drift: {group}"
    );
    assert_eq!(candidate.files, reference.files, "file drift: {group}");
    assert_eq!(
        candidate.procedures, reference.procedures,
        "procedure drift: {group}"
    );
    assert_eq!(candidate.points, reference.points, "point drift: {group}");
    assert_eq!(candidate.edges, reference.edges, "edge drift: {group}");
    assert_eq!(candidate.calls, reference.calls, "call drift: {group}");
    assert_eq!(candidate.gaps, reference.gaps, "gap drift: {group}");
    assert_eq!(
        candidate.packed_payload_bytes, reference.packed_payload_bytes,
        "payload drift: {group}"
    );
    assert_eq!(
        candidate.database_bytes, reference.database_bytes,
        "database drift: {group}"
    );
    assert_eq!(
        candidate.estimated_hydrated_bytes, reference.estimated_hydrated_bytes,
        "retained-byte drift: {group}"
    );
    assert_eq!(
        candidate.checksum, reference.checksum,
        "topology checksum drift: {group}"
    );
}

fn median_measurement(mode: &str, dataset: &str, samples: &[SampleResult]) -> MedianMeasurement {
    MedianMeasurement {
        mode: mode.to_owned(),
        dataset: dataset.to_owned(),
        cache_control: samples
            .first()
            .expect("median requires retained samples")
            .cache_control
            .clone(),
        operation_ms: median_f64(samples.iter().map(|sample| sample.operation_ms).collect()),
        repeat_materialization_ms: if samples
            .iter()
            .all(|sample| sample.repeat_materialization_ms.is_none())
        {
            None
        } else {
            Some(median_f64(
                samples
                    .iter()
                    .map(|sample| {
                        sample
                            .repeat_materialization_ms
                            .expect("repeat measurement presence must be stable within a mode")
                    })
                    .collect(),
            ))
        },
        packed_payload_bytes: median_u64(
            samples
                .iter()
                .map(|sample| sample.packed_payload_bytes)
                .collect(),
        ),
        database_bytes: median_u64(samples.iter().map(|sample| sample.database_bytes).collect()),
        estimated_hydrated_bytes: median_u64(
            samples
                .iter()
                .map(|sample| sample.estimated_hydrated_bytes)
                .collect(),
        ),
        peak_rss_bytes: median_u64(samples.iter().map(|sample| sample.peak_rss_bytes).collect()),
    }
}

fn gate_for_dataset(dataset: &str, medians: &[MedianMeasurement]) -> GateDatasetResult {
    let get = |mode: &str| {
        medians
            .iter()
            .find(|measurement| measurement.dataset == dataset && measurement.mode == mode)
            .unwrap_or_else(|| panic!("missing {dataset}/{mode} median"))
    };
    let rebuild = get("rebuild");
    let build_write = get("build_write");
    let hydrate = get("hydrate");
    let thresholds = ArtifactPromotionThresholds::default();
    assert_eq!(thresholds.minimum_hydration_speedup_percent, 30.0);
    assert_eq!(thresholds.minimum_hydration_saved_ms, 50.0);
    assert_eq!(thresholds.maximum_hydration_rss_ratio, 1.10);
    assert_eq!(thresholds.maximum_serialized_to_hydrated_bytes_ratio, 2.0);
    assert_eq!(thresholds.maximum_build_write_time_ratio, 1.25);
    assert_eq!(thresholds.maximum_build_write_overhead_ms, 250.0);
    let evaluation = evaluate_artifact_promotion(
        thresholds,
        ArtifactPromotionMeasurement {
            rebuild_ms: rebuild.operation_ms,
            build_write_ms: build_write.operation_ms,
            hydrate_ms: hydrate.operation_ms,
            rebuild_peak_rss_bytes: cfg!(unix).then_some(rebuild.peak_rss_bytes),
            hydrate_peak_rss_bytes: cfg!(unix).then_some(hydrate.peak_rss_bytes),
            serialized_bytes: hydrate.database_bytes,
            estimated_hydrated_bytes: hydrate.estimated_hydrated_bytes,
        },
    )
    .expect("retained semantic CFG persistence samples must be valid promotion measurements");
    let rss_measurement_available =
        evaluation.hydration_rss != ArtifactPromotionGateStatus::Unavailable;
    GateDatasetResult {
        dataset: dataset.to_owned(),
        hydration_speedup_percent: evaluation.hydration_speedup_percent,
        hydration_saved_ms: evaluation.hydration_saved_ms,
        hydration_fast_enough: evaluation.hydration_speedup.passed(),
        hydration_absolute_saving_met: evaluation.hydration_absolute_saving.passed(),
        rss_measurement_available,
        rss_within_limit: evaluation.hydration_rss.passed(),
        packed_size_within_limit: evaluation.serialized_size.passed(),
        cold_write_within_percent: evaluation.build_write_time.passed(),
        cold_write_absolute_overhead_met: evaluation.build_write_absolute_overhead.passed(),
        passed: evaluation.passed(),
    }
}

fn aggregate(samples_file: &Path) -> AggregateResult {
    let contents = fs::read_to_string(samples_file).unwrap_or_else(|error| {
        panic!(
            "read semantic CFG persistence samples {}: {error}",
            samples_file.display()
        )
    });
    let mut raw_samples: BTreeMap<String, Vec<SampleResult>> = BTreeMap::new();
    for (line_number, line) in contents.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let sample: SampleResult = serde_json::from_str(line).unwrap_or_else(|error| {
            panic!(
                "parse semantic CFG persistence sample line {}: {error}",
                line_number + 1
            )
        });
        assert_eq!(
            sample.format,
            "bifrost_semantic_cfg_persistence_benchmark/v4"
        );
        assert_eq!(sample.kind, "sample");
        assert_ne!(sample.mode, "seed", "seed samples are not retained");
        raw_samples
            .entry(format!("{}/{}", sample.dataset, sample.mode))
            .or_default()
            .push(sample);
    }

    let datasets = [
        "fixture_typescript",
        "fixture_java",
        "external_vscode_typescript",
        "external_spring_petclinic_java",
    ];
    let modes = ["rebuild", "build_write", "hydrate", "hydrate_cold"];
    let mut sample_execution_provenance = None;
    let mut dataset_provenance = BTreeMap::new();
    for dataset in datasets {
        for mode in modes {
            let group = format!("{dataset}/{mode}");
            let samples = raw_samples
                .get_mut(&group)
                .unwrap_or_else(|| panic!("missing retained samples for {group}"));
            samples.sort_by_key(|sample| sample.round);
            assert_eq!(samples.len(), 7, "{group} must retain seven samples");
            assert_eq!(
                samples
                    .iter()
                    .map(|sample| sample.round)
                    .collect::<Vec<_>>(),
                (2..9).collect::<Vec<_>>(),
                "{group} must discard rounds zero and one"
            );
            let reference = &samples[0];
            for sample in &samples[1..] {
                assert_same_group(reference, sample, &group);
            }
        }
        let reference = &raw_samples[&format!("{dataset}/rebuild")][0];
        let execution = reference.provenance.execution();
        if let Some(expected) = &sample_execution_provenance {
            assert_eq!(
                &execution, expected,
                "sample execution provenance drifted for {dataset}"
            );
        } else {
            sample_execution_provenance = Some(execution);
        }
        assert!(
            dataset_provenance
                .insert(dataset.to_owned(), reference.provenance.repository())
                .is_none(),
            "duplicate dataset provenance for {dataset}"
        );
        for mode in ["build_write", "hydrate", "hydrate_cold"] {
            let candidate = &raw_samples[&format!("{dataset}/{mode}")][0];
            let context = format!("{dataset}/{mode} versus rebuild");
            assert_eq!(candidate.provenance, reference.provenance, "{context}");
            assert_eq!(candidate.files, reference.files, "{context}");
            assert_eq!(candidate.procedures, reference.procedures, "{context}");
            assert_eq!(candidate.points, reference.points, "{context}");
            assert_eq!(candidate.edges, reference.edges, "{context}");
            assert_eq!(candidate.calls, reference.calls, "{context}");
            assert_eq!(candidate.gaps, reference.gaps, "{context}");
            assert_eq!(
                candidate.estimated_hydrated_bytes, reference.estimated_hydrated_bytes,
                "{context}"
            );
            assert_eq!(candidate.checksum, reference.checksum, "{context}");
        }
    }

    let mut medians = Vec::new();
    for dataset in datasets {
        for mode in modes {
            let group = format!("{dataset}/{mode}");
            medians.push(median_measurement(mode, dataset, &raw_samples[&group]));
        }
    }
    let external_gate = [
        "external_vscode_typescript",
        "external_spring_petclinic_java",
    ]
    .into_iter()
    .map(|dataset| gate_for_dataset(dataset, &medians))
    .collect::<Vec<_>>();
    let recommendation = if external_gate.iter().all(|result| result.passed) {
        "inconclusive; benchmark an equivalent artifact before persistence promotion"
    } else {
        "no_go; the optimistic control-call projection misses a predeclared promotion gate"
    };
    AggregateResult {
        format: "bifrost_semantic_cfg_persistence_benchmark_aggregate/v5",
        kind: "aggregate",
        aggregation_provenance: current_execution_provenance(),
        sample_execution_provenance: sample_execution_provenance
            .expect("retained samples have execution provenance"),
        dataset_provenance,
        fresh_processes_per_mode: 9,
        discarded_warmups_per_mode: 2,
        retained_samples_per_mode: 7,
        raw_samples,
        medians,
        external_gate,
        recommendation,
    }
}

fn synthetic_snapshot() -> PackedFile {
    PackedFile {
        version: SNAPSHOT_VERSION,
        artifact_key: [7; 32],
        path: "src/example.ts".to_owned(),
        language: "typescript".to_owned(),
        capabilities: vec![2; 4],
        procedures: vec![PackedProcedure {
            kind: stable_hash("function"),
            properties: 0,
            lexical_parent: None,
            entry: 0,
            normal_exit: 1,
            exceptional_exit: 2,
            value_count: 0,
            allocation_count: 0,
            memory_location_count: 0,
            capture_count: 0,
            source_mapping_count: 1,
            evidence_count: 1,
            points: vec![
                PackedPoint {
                    block: 0,
                    source: 0,
                    evidence: 0,
                    event_count: 1,
                    event_hash: stable_hash("entry"),
                },
                PackedPoint {
                    block: 1,
                    source: 0,
                    evidence: 0,
                    event_count: 1,
                    event_hash: stable_hash("normal_exit"),
                },
                PackedPoint {
                    block: 2,
                    source: 0,
                    evidence: 0,
                    event_count: 1,
                    event_hash: stable_hash("exceptional_exit"),
                },
            ],
            edges: vec![PackedEdge {
                source: 0,
                target: 1,
                source_mapping: 0,
                evidence: 0,
                kind: 0,
            }],
            outgoing_offsets: vec![0, 1, 1, 1],
            incoming_offsets: vec![0, 0, 1, 1],
            incoming_edge_ids: vec![0],
            calls: Vec::new(),
            gaps: Vec::new(),
        }],
    }
}

#[test]
fn packed_cfg_round_trip_preserves_bidirectional_topology() {
    let expected = synthetic_snapshot();
    let encoded = encode_snapshot(&expected);
    let decoded = decode_snapshot(&encoded).expect("decode synthetic packed CFG");
    assert_eq!(decoded, expected);
    let hydrated = hydrate_file(decoded, Some([7; 32])).expect("hydrate synthetic packed CFG");
    assert_eq!(
        hydrated_counts(std::slice::from_ref(&hydrated)),
        (1, 3, 1, 0, 0)
    );
    assert_ne!(checksum(std::slice::from_ref(&hydrated)), 0);
}

#[test]
fn packed_cfg_checksum_is_independent_of_file_container_order() {
    let mut first = synthetic_snapshot();
    first.path = "src/a.ts".to_owned();
    first.artifact_key = [1; 32];
    let mut second = synthetic_snapshot();
    second.path = "src/b.ts".to_owned();
    second.artifact_key = [2; 32];
    let first = hydrate_file(first, Some([1; 32])).expect("hydrate first synthetic CFG");
    let second = hydrate_file(second, Some([2; 32])).expect("hydrate second synthetic CFG");
    let forward = checksum(&[first, second]);

    let mut first = synthetic_snapshot();
    first.path = "src/a.ts".to_owned();
    first.artifact_key = [1; 32];
    let mut second = synthetic_snapshot();
    second.path = "src/b.ts".to_owned();
    second.artifact_key = [2; 32];
    let first = hydrate_file(first, Some([1; 32])).expect("hydrate first synthetic CFG");
    let second = hydrate_file(second, Some([2; 32])).expect("hydrate second synthetic CFG");
    let reverse = checksum(&[second, first]);

    assert_eq!(forward, reverse);
}

#[test]
fn packed_cfg_rejects_identity_version_and_adjacency_corruption() {
    let snapshot = synthetic_snapshot();
    assert_eq!(
        hydrate_file(snapshot.clone(), Some([8; 32])).unwrap_err(),
        SnapshotError::Identity
    );
    let mut wrong_version = snapshot.clone();
    wrong_version.version += 1;
    assert_eq!(
        hydrate_file(wrong_version, None).unwrap_err(),
        SnapshotError::Version
    );
    let mut bad_edge = snapshot.clone();
    bad_edge.procedures[0].edges[0].target = 9;
    assert_eq!(
        hydrate_file(bad_edge, None).unwrap_err(),
        SnapshotError::EdgeRows
    );
    let mut bad_incoming = snapshot;
    bad_incoming.procedures[0].incoming_offsets = vec![0, 1, 1, 1];
    assert_eq!(
        hydrate_file(bad_incoming, None).unwrap_err(),
        SnapshotError::IncomingRows
    );

    let mut duplicate_incoming = synthetic_snapshot();
    duplicate_incoming.procedures[0].edges.push(PackedEdge {
        source: 0,
        target: 1,
        source_mapping: 0,
        evidence: 1,
        kind: 1,
    });
    duplicate_incoming.procedures[0].outgoing_offsets = vec![0, 2, 2, 2];
    duplicate_incoming.procedures[0].incoming_offsets = vec![0, 0, 2, 2];
    duplicate_incoming.procedures[0].incoming_edge_ids = vec![0, 0];
    assert_eq!(
        hydrate_file(duplicate_incoming, None).unwrap_err(),
        SnapshotError::IncomingRows
    );
}

#[test]
#[should_panic(expected = "seeded Bifrost tree identity drifted")]
fn seeded_database_rejects_a_different_bifrost_tree() {
    let directory = tempfile::tempdir().expect("semantic CFG benchmark temp directory");
    let database = directory.path().join("seed.db");
    let spec = DatasetSpec {
        name: "synthetic",
        root: directory.path().to_path_buf(),
        language: Language::TypeScript,
        expected_commit: None,
    };
    write_database(
        &database,
        &spec,
        Some("repository-commit"),
        "bifrost-tree-a",
        &[synthetic_snapshot()],
    );
    let _ = read_database(
        &database,
        &spec,
        Some("repository-commit"),
        "bifrost-tree-b",
    );
}

#[test]
#[ignore = "decision-grade semantic CFG persistence benchmark; run through the benchmark runner"]
fn semantic_cfg_persistence_measurement() {
    if let Some(samples_file) = std::env::var_os(SAMPLES_FILE_ENV) {
        let result = aggregate(Path::new(&samples_file));
        println!(
            "{RESULT_PREFIX}{}",
            serde_json::to_string(&result)
                .expect("serialize aggregate semantic CFG persistence benchmark")
        );
    } else {
        let result = sample();
        println!(
            "{RESULT_PREFIX}{}",
            serde_json::to_string(&result)
                .expect("serialize semantic CFG persistence benchmark sample")
        );
    }
}
