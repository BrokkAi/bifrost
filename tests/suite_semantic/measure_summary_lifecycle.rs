//! Lifecycle benchmark for the reusable summaries introduced by issue #823.
//!
//! The current summary types deliberately have no portable DTO. This benchmark
//! therefore measures real in-memory construction and lookup, then measures a
//! fresh-process diagnostic-envelope lower bound separately. The envelope can
//! validate identity, counts, completeness, retained bytes, and a canonical
//! checksum, but it cannot reconstruct or apply a summary. Aggregation runs the
//! shared #817 promotion gates without weakening them and records every
//! candidate as insufficient evidence while exact equivalence is unavailable.
//!
//! Use `scripts/run-summary-lifecycle-benchmarks.sh` for the decision-grade
//! two-warmup, seven-retained-process matrix.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::hash::{Hash, Hasher};
use std::hint::black_box;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Instant;

use brokk_bifrost::analyzer::LanguageDialect;
use brokk_bifrost::analyzer::dataflow::{
    CompleteSummaryRepository, DataflowRequest, ProcedureSummaryIdentity, ProcedureSummaryKey,
    SemanticInputStatus, SemanticProcedureSummary, SolverBudget, SummaryBehaviorKey,
    SummaryCompleteness, SummaryContextKey, SummaryDependencyKey, SummaryEffect, SummaryEffectKey,
    SummaryEventKey, SummaryEvidence, SummaryOrigin, SummarySchemaVersion, SummarySemanticsVersion,
};
use brokk_bifrost::analyzer::semantic::{
    AbstractObject, AccessPathRoot, AdapterSemanticsVersion, CallBindings, CancellationToken,
    CandidateCoverage, ContentIdentity, DeclarationLocator, DeclarationSegment,
    DeclarationSegmentKind, DependencyFingerprint, DispatchOracle, EvidenceCompleteness,
    ObjectCardinality, OracleCallContext, OracleLimits, ProcedureHandle, ProcedureKind,
    ProofStatus, SemanticArtifact, SemanticArtifactKey, SemanticBudget, SemanticIrVersion,
    SemanticRequest, SourceAnchor, SourcePosition, SourceRevision, SourceSpan, ValueFlowOracle,
    ValueFlowRelationKind, ValueFlowSnapshot, WorkspaceMountId, WorkspaceRelativePath,
};
use brokk_bifrost::analyzer::taint::{
    CompleteTaintTransferSummaryRepository, SourceClassId, SourceEventKey, TaintAnalysisPlan,
    TaintClassSet, TaintSemanticSummarySet, TaintSinkBinding, TaintSourceBinding, TaintUniverse,
    solve_taint_with_reusable_summaries,
};
use brokk_bifrost::analyzer::typestate::{
    BoundTypestateSubjectSpec, CompleteProtocolSummaryRepository, ProtocolEventKey,
    ProtocolEventOccurrence, ProtocolExpectationKey, ProtocolObservationPhase, ProtocolSpec,
    ProtocolStateKey, ProtocolSummaryKey, ProtocolSummarySolveResult, TypestateBindingContext,
    TypestateBindingPlan, TypestateBindingQuality, TypestateEventBindingSpec,
    TypestateInitialSeedSpec, TypestateObjectRole, TypestateObservationSite,
    TypestateSubjectClassKey, TypestateSubjectKey, TypestateTerminalBindingSpec,
    solve_typestate_with_reusable_summaries,
};
use brokk_bifrost::analyzer::value_flow::{
    ValueFlowCarrier, ValueFlowEventKey, ValueFlowEventKind, ValueFlowInput,
    ValueFlowObservationPhase, ValueFlowPlan, ValueFlowSinkSpec, ValueFlowSourceSpec,
};
use brokk_bifrost::benchmark::{
    ArtifactPromotionMeasurement, ArtifactPromotionThresholds, evaluate_artifact_promotion,
};
use brokk_bifrost::{AnalyzerConfig, Language, ProjectFile, TestProject, WorkspaceAnalyzer};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::common::semantic_graph::mapped_source;

const RESULT_PREFIX: &str = "BIFROST_SUMMARY_LIFECYCLE_BENCHMARK=";
const CANDIDATE_ENV: &str = "BIFROST_SUMMARY_LIFECYCLE_CANDIDATE";
const DATASET_ENV: &str = "BIFROST_SUMMARY_LIFECYCLE_DATASET";
const MODE_ENV: &str = "BIFROST_SUMMARY_LIFECYCLE_MODE";
const ROUND_ENV: &str = "BIFROST_SUMMARY_LIFECYCLE_ROUND";
const PAYLOAD_FILE_ENV: &str = "BIFROST_SUMMARY_LIFECYCLE_PAYLOAD_FILE";
const SAMPLES_FILE_ENV: &str = "BIFROST_SUMMARY_LIFECYCLE_SAMPLES_FILE";
const FIXTURE_ROOT_ENV: &str = "BIFROST_SUMMARY_LIFECYCLE_FIXTURE_ROOT";
const TS_REPO_ENV: &str = "BIFROST_SEMANTIC_TS_REPO";
const JAVA_REPO_ENV: &str = "BIFROST_SEMANTIC_JAVA_REPO";
const VSCODE_COMMIT: &str = "19e0f9e681ecb8e5c09d8784acaa601316ca4571";
const SPRING_PETCLINIC_COMMIT: &str = "f182358d02e4a68e52bdbabf55ca7800288511e7";
const FORMAT: &str = "bifrost_summary_lifecycle_benchmark/v1";
const AGGREGATE_FORMAT: &str = "bifrost_summary_lifecycle_benchmark_aggregate/v1";
const DIAGNOSTIC_FORMAT: &str = "bifrost_summary_diagnostic_envelope/v1";
const EXACT_EQUIVALENCE: bool = false;
const REQUIRED_RETAINED_SAMPLES: usize = 7;

const JAVA_PROTOCOL_SOURCE: &str = r#"
final class ProtocolResource {}
final class ProtocolLifecycleFixture {
  static ProtocolResource acquire() { return null; }
  static void use(ProtocolResource resource) {}
  static void close(ProtocolResource resource) {}
  static void lifecycle() {
    ProtocolResource resource = acquire();
    ProtocolResource alias = resource;
    use(alias);
    close(alias);
    return;
  }
}
"#;

const JAVA_TAINT_SOURCE: &str = r#"
final class TaintFixture {
  static String helper(String input) {
    String copy = input;
    return copy;
  }

  static String caller(String input) {
    return helper(input);
  }
}
"#;

const TYPE_SCRIPT_INLINE_SOURCE: &str = r#"
export function helper(value: string): string { return value.trim(); }
export function caller(value: string): string { return helper(value); }
"#;

const JAVA_INLINE_SOURCE: &str = r#"
final class SummaryFixture {
  static String helper(String value) { return value.trim(); }
  static String caller(String value) { return helper(value); }
}
"#;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct BenchmarkProvenance {
    bifrost_commit: Option<String>,
    bifrost_tracked_dirty: Option<bool>,
    benchmark_source_checksum: Option<String>,
    rustc_version: Option<String>,
    operating_system: String,
    architecture: String,
    logical_parallelism: Option<usize>,
    build_profile: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DatasetProvenance {
    origin: String,
    language: String,
    source_items: usize,
    repository_commit: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DiagnosticEnvelope {
    format: String,
    candidate: String,
    dataset: String,
    artifact_count: usize,
    row_count: usize,
    effect_count: usize,
    complete: bool,
    retained_bytes: u64,
    result_checksum: String,
    validity_checksum: String,
    exact_equivalence: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SampleResult {
    format: String,
    provenance: BenchmarkProvenance,
    candidate: String,
    dataset: String,
    dataset_provenance: DatasetProvenance,
    mode: String,
    round: usize,
    rebuild_ms: Option<f64>,
    same_process_reuse_ms: Option<f64>,
    build_write_ms: Option<f64>,
    hydrate_ms: Option<f64>,
    peak_rss_bytes: Option<u64>,
    serialized_bytes: u64,
    retained_bytes: u64,
    artifact_count: usize,
    row_count: usize,
    effect_count: usize,
    complete: bool,
    lookup_hit: bool,
    invalidation_miss: bool,
    result_checksum: String,
    validity_checksum: String,
    exact_equivalence: bool,
}

#[derive(Debug, Serialize)]
struct AggregateResult {
    format: &'static str,
    provenance: BenchmarkProvenance,
    thresholds: ThresholdReport,
    discarded_warmups_per_case: usize,
    retained_samples_per_case: usize,
    medians: Vec<MedianResult>,
}

#[derive(Debug, Clone, Copy, Serialize)]
struct ThresholdReport {
    minimum_hydration_speedup_percent: f64,
    minimum_hydration_saved_ms: f64,
    maximum_hydration_rss_ratio: f64,
    maximum_serialized_to_hydrated_bytes_ratio: f64,
    maximum_build_write_time_ratio: f64,
    maximum_build_write_overhead_ms: f64,
}

impl From<ArtifactPromotionThresholds> for ThresholdReport {
    fn from(value: ArtifactPromotionThresholds) -> Self {
        Self {
            minimum_hydration_speedup_percent: value.minimum_hydration_speedup_percent,
            minimum_hydration_saved_ms: value.minimum_hydration_saved_ms,
            maximum_hydration_rss_ratio: value.maximum_hydration_rss_ratio,
            maximum_serialized_to_hydrated_bytes_ratio: value
                .maximum_serialized_to_hydrated_bytes_ratio,
            maximum_build_write_time_ratio: value.maximum_build_write_time_ratio,
            maximum_build_write_overhead_ms: value.maximum_build_write_overhead_ms,
        }
    }
}

#[derive(Debug, Serialize)]
struct MedianResult {
    candidate: String,
    dataset: String,
    dataset_provenance: DatasetProvenance,
    rebuild_ms: f64,
    same_process_reuse_ms: f64,
    build_write_ms: f64,
    hydrate_ms: f64,
    rebuild_peak_rss_bytes: Option<u64>,
    hydrate_peak_rss_bytes: Option<u64>,
    serialized_bytes: u64,
    retained_bytes: u64,
    artifact_count: usize,
    row_count: usize,
    effect_count: usize,
    complete: bool,
    lookup_hit: bool,
    invalidation_miss: bool,
    result_checksum: String,
    validity_checksum: String,
    exact_equivalence: bool,
    hydration_speedup_percent: f64,
    hydration_saved_ms: f64,
    gates_passed: bool,
    hydration_speedup_gate: String,
    hydration_absolute_saving_gate: String,
    hydration_rss_gate: String,
    serialized_size_gate: String,
    build_write_time_gate: String,
    build_write_absolute_overhead_gate: String,
    decision: &'static str,
    reason: &'static str,
}

#[derive(Debug)]
enum MeasuredArtifact {
    Semantic {
        repository: CompleteSummaryRepository,
        keys: Vec<ProcedureSummaryKey>,
        invalid_key: ProcedureSummaryKey,
        rows: usize,
        effects: usize,
    },
    Protocol {
        repository: CompleteProtocolSummaryRepository,
        key: ProtocolSummaryKey,
        invalid_key: Box<ProtocolSummaryKey>,
    },
    Taint {
        repository: CompleteTaintTransferSummaryRepository,
        keys: Vec<brokk_bifrost::analyzer::taint::TaintTransferSummaryKey>,
        invalid_key: Option<brokk_bifrost::analyzer::taint::TaintTransferSummaryKey>,
    },
}

impl MeasuredArtifact {
    fn artifact_count(&self) -> usize {
        match self {
            Self::Semantic { repository, .. } => repository.len(),
            Self::Protocol { repository, .. } => repository.len(),
            Self::Taint { repository, .. } => repository.len(),
        }
    }

    fn retained_bytes(&self) -> usize {
        match self {
            Self::Semantic { repository, .. } => repository.retained_bytes(),
            Self::Protocol { repository, .. } => repository.retained_bytes(),
            Self::Taint { repository, .. } => repository.retained_bytes(),
        }
    }

    fn rows(&self) -> usize {
        match self {
            Self::Semantic { rows, .. } => *rows,
            Self::Protocol {
                repository, key, ..
            } => repository
                .get(key)
                .map_or(0, |summary| summary.rows().len()),
            Self::Taint {
                repository, keys, ..
            } => keys
                .iter()
                .filter_map(|key| repository.get(key))
                .map(|summary| summary.rows().len())
                .sum(),
        }
    }

    fn effects(&self) -> usize {
        match self {
            Self::Semantic { effects, .. } => *effects,
            Self::Protocol {
                repository, key, ..
            } => repository
                .get(key)
                .map_or(0, |summary| summary.effects().len()),
            Self::Taint {
                repository, keys, ..
            } => keys
                .iter()
                .filter_map(|key| repository.get(key))
                .map(|summary| summary.observations().len())
                .sum(),
        }
    }

    fn lookup_all(&self) -> bool {
        match self {
            Self::Semantic {
                repository, keys, ..
            } => keys
                .iter()
                .all(|key| repository.get(black_box(key)).is_some()),
            Self::Protocol {
                repository, key, ..
            } => repository.get(black_box(key)).is_some(),
            Self::Taint {
                repository, keys, ..
            } => keys
                .iter()
                .all(|key| repository.get(black_box(key)).is_some()),
        }
    }

    fn invalidation_miss(&self) -> bool {
        match self {
            Self::Semantic {
                repository,
                invalid_key,
                ..
            } => repository.get(invalid_key).is_none(),
            Self::Protocol {
                repository,
                invalid_key,
                ..
            } => repository.get(invalid_key).is_none(),
            Self::Taint {
                repository,
                invalid_key,
                ..
            } => repository
                .get(
                    invalid_key
                        .as_ref()
                        .expect("taint invalidation key must be prepared"),
                )
                .is_none(),
        }
    }

    fn prepare_invalidation(&mut self) {
        if let Self::Taint {
            keys, invalid_key, ..
        } = self
        {
            let (_, invalid_keys) =
                solve_taint_fixture(&format!("{JAVA_TAINT_SOURCE}\n// changed source revision"));
            *invalid_key = Some(
                invalid_keys
                    .into_iter()
                    .find(|key| !keys.contains(key))
                    .expect("changed source revision must change the taint key"),
            );
        }
    }

    fn result_checksum(&self) -> String {
        let mut digest = Sha256::new();
        digest.update(b"bifrost-summary-lifecycle-result/v1");
        digest.update(self.artifact_count().to_le_bytes());
        digest.update(self.rows().to_le_bytes());
        digest.update(self.effects().to_le_bytes());
        digest.update(self.retained_bytes().to_le_bytes());
        match self {
            Self::Semantic { keys, .. } => {
                for key in keys {
                    digest.update(key.fingerprint().as_bytes());
                }
            }
            Self::Protocol {
                repository, key, ..
            } => {
                let summary = repository.get(key).expect("measured protocol summary");
                digest.update(structural_checksum(&(
                    key,
                    summary.rows(),
                    summary.effects(),
                )));
            }
            Self::Taint {
                repository, keys, ..
            } => {
                let mut summaries = keys
                    .iter()
                    .map(|key| {
                        let summary = repository.get(key).expect("measured taint summary");
                        structural_checksum(&(key, summary.rows(), summary.observations()))
                    })
                    .collect::<Vec<_>>();
                summaries.sort_unstable();
                for summary in summaries {
                    digest.update(summary);
                }
            }
        }
        hex_digest(digest.finalize())
    }

    fn validity_checksum(&self) -> String {
        let mut digest = Sha256::new();
        digest.update(b"bifrost-summary-lifecycle-validity/v1");
        match self {
            Self::Semantic { keys, .. } => {
                for key in keys {
                    digest.update(key.fingerprint().as_bytes());
                }
            }
            Self::Protocol { key, .. } => {
                digest.update(structural_checksum(key));
            }
            Self::Taint { keys, .. } => {
                let mut keys = keys.iter().map(structural_checksum).collect::<Vec<_>>();
                keys.sort_unstable();
                for key in keys {
                    digest.update(key);
                }
            }
        }
        hex_digest(digest.finalize())
    }
}

#[test]
#[ignore = "run through scripts/run-summary-lifecycle-benchmarks.sh"]
fn summary_lifecycle_measurement() {
    if let Ok(samples_file) = std::env::var(SAMPLES_FILE_ENV) {
        emit(&aggregate_samples(Path::new(&samples_file)));
        return;
    }

    let candidate = required_env(CANDIDATE_ENV);
    let dataset = required_env(DATASET_ENV);
    let mode = required_env(MODE_ENV);
    let round = required_env(ROUND_ENV).parse::<usize>().unwrap();
    let sample = match mode.as_str() {
        "build" => measure_build(&candidate, &dataset, round),
        "hydrate" => measure_hydrate(&candidate, &dataset, round),
        other => panic!("unsupported lifecycle mode {other:?}"),
    };
    emit(&sample);
}

fn measure_build(candidate: &str, dataset: &str, round: usize) -> SampleResult {
    let provenance = benchmark_provenance();
    let started = Instant::now();
    let mut artifact = build_candidate(candidate, dataset);
    let rebuild_ms = elapsed_ms(started);
    let rebuild_peak_rss_bytes = peak_rss_bytes();
    artifact.prepare_invalidation();
    let dataset_provenance =
        dataset_provenance(candidate, dataset, artifact.artifact_count().max(1));

    let reuse_started = Instant::now();
    let lookup_hit = (0..100).all(|_| artifact.lookup_all());
    let same_process_reuse_ms = elapsed_ms(reuse_started) / 100.0;
    let invalidation_miss = artifact.invalidation_miss();
    let envelope = DiagnosticEnvelope {
        format: DIAGNOSTIC_FORMAT.to_owned(),
        candidate: candidate.to_owned(),
        dataset: dataset.to_owned(),
        artifact_count: artifact.artifact_count(),
        row_count: artifact.rows(),
        effect_count: artifact.effects(),
        complete: true,
        retained_bytes: u64::try_from(artifact.retained_bytes()).unwrap(),
        result_checksum: artifact.result_checksum(),
        validity_checksum: artifact.validity_checksum(),
        exact_equivalence: EXACT_EQUIVALENCE,
    };
    assert!(lookup_hit, "complete summary lookup must hit");
    assert!(invalidation_miss, "changed validity key must miss");

    let write_started = Instant::now();
    let bytes = serde_json::to_vec(&envelope).unwrap();
    fs::write(required_env(PAYLOAD_FILE_ENV), &bytes).unwrap();
    let build_write_ms = rebuild_ms + elapsed_ms(write_started);
    SampleResult {
        format: FORMAT.to_owned(),
        provenance,
        candidate: candidate.to_owned(),
        dataset: dataset.to_owned(),
        dataset_provenance,
        mode: "build".to_owned(),
        round,
        rebuild_ms: Some(rebuild_ms),
        same_process_reuse_ms: Some(same_process_reuse_ms),
        build_write_ms: Some(build_write_ms),
        hydrate_ms: None,
        peak_rss_bytes: rebuild_peak_rss_bytes,
        serialized_bytes: u64::try_from(bytes.len()).unwrap(),
        retained_bytes: envelope.retained_bytes,
        artifact_count: envelope.artifact_count,
        row_count: envelope.row_count,
        effect_count: envelope.effect_count,
        complete: envelope.complete,
        lookup_hit,
        invalidation_miss,
        result_checksum: envelope.result_checksum,
        validity_checksum: envelope.validity_checksum,
        exact_equivalence: envelope.exact_equivalence,
    }
}

fn measure_hydrate(candidate: &str, dataset: &str, round: usize) -> SampleResult {
    let provenance = benchmark_provenance();
    let payload = PathBuf::from(required_env(PAYLOAD_FILE_ENV));
    let started = Instant::now();
    let bytes = fs::read(payload).unwrap();
    let envelope: DiagnosticEnvelope = serde_json::from_slice(&bytes).unwrap();
    black_box(&envelope);
    let hydrate_ms = elapsed_ms(started);
    assert_eq!(envelope.format, DIAGNOSTIC_FORMAT);
    assert_eq!(envelope.candidate, candidate);
    assert_eq!(envelope.dataset, dataset);
    assert!(!envelope.exact_equivalence);
    let dataset_provenance = dataset_provenance(candidate, dataset, envelope.artifact_count.max(1));
    SampleResult {
        format: FORMAT.to_owned(),
        provenance,
        candidate: candidate.to_owned(),
        dataset: dataset.to_owned(),
        dataset_provenance,
        mode: "hydrate".to_owned(),
        round,
        rebuild_ms: None,
        same_process_reuse_ms: None,
        build_write_ms: None,
        hydrate_ms: Some(hydrate_ms),
        peak_rss_bytes: peak_rss_bytes(),
        serialized_bytes: u64::try_from(bytes.len()).unwrap(),
        retained_bytes: envelope.retained_bytes,
        artifact_count: envelope.artifact_count,
        row_count: envelope.row_count,
        effect_count: envelope.effect_count,
        complete: envelope.complete,
        lookup_hit: false,
        invalidation_miss: false,
        result_checksum: envelope.result_checksum,
        validity_checksum: envelope.validity_checksum,
        exact_equivalence: envelope.exact_equivalence,
    }
}

fn build_candidate(candidate: &str, dataset: &str) -> MeasuredArtifact {
    match candidate {
        "semantic" => build_semantic_candidate(dataset),
        "protocol" if dataset == "inline_java" => build_protocol_candidate(),
        "taint" if dataset == "inline_java" => build_taint_candidate(JAVA_TAINT_SOURCE),
        _ => panic!("unsupported summary lifecycle case {candidate}:{dataset}"),
    }
}

fn build_semantic_candidate(dataset: &str) -> MeasuredArtifact {
    let sources = semantic_dataset_sources(dataset);
    let mut repository = CompleteSummaryRepository::new();
    let mut keys = Vec::with_capacity(sources.len());
    let mut rows = 0;
    let mut effects = 0;
    for (index, (path, source)) in sources.iter().enumerate() {
        let summary = semantic_summary(path, source, index, b"summary-lifecycle-context");
        rows += summary.transfers().len();
        effects += summary.effects().len();
        keys.push(summary.key().clone());
        repository.publish(summary).unwrap();
    }
    let invalid_summary = semantic_summary(
        &sources[0].0,
        &sources[0].1,
        0,
        b"summary-lifecycle-changed-context",
    );
    MeasuredArtifact::Semantic {
        repository,
        keys,
        invalid_key: invalid_summary.key().clone(),
        rows,
        effects,
    }
}

fn semantic_summary(
    path: &str,
    source: &[u8],
    index: usize,
    context: &[u8],
) -> SemanticProcedureSummary {
    let portable_path = WorkspaceRelativePath::new(path.replace('\\', "/")).unwrap();
    let language = if path.ends_with(".java") {
        Language::Java
    } else {
        Language::TypeScript
    };
    let artifact = SemanticArtifactKey::new(
        WorkspaceMountId::hash_bytes(b"summary-lifecycle-mount"),
        portable_path,
        LanguageDialect::Standard(language),
        SourceRevision::Disk {
            content: ContentIdentity::hash_bytes(source),
        },
        AdapterSemanticsVersion::hash_bytes("summary-lifecycle", b"adapter-v1").unwrap(),
        SemanticIrVersion::current(),
        brokk_bifrost::analyzer::semantic::ConfigurationFingerprint::hash_bytes(b"default"),
        DependencyFingerprint::hash_bytes(b"no-dependencies"),
    );
    let position = SourcePosition::new(u32::try_from(index).unwrap_or(u32::MAX), 0, 0);
    let anchor = SourceAnchor::new(SourceSpan::new(position, position).unwrap(), 0);
    let declaration = DeclarationLocator::new(vec![
        DeclarationSegment::named(
            DeclarationSegmentKind::Function,
            format!("summary_{index}"),
            anchor,
            0,
        )
        .unwrap(),
    ])
    .unwrap();
    let identity = ProcedureSummaryIdentity::new(
        artifact,
        declaration,
        SummarySchemaVersion::CURRENT,
        SummarySemanticsVersion::hash_bytes(b"summary-lifecycle-v1"),
        SummaryContextKey::hash_bytes(context),
        SummaryBehaviorKey::hash_bytes(b"conservative"),
        SummaryOrigin::Inferred,
    );
    let key = ProcedureSummaryKey::try_new(identity, &[], None).unwrap();
    SemanticProcedureSummary::try_new(
        key,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        SummaryCompleteness::Complete,
    )
    .unwrap()
}

fn semantic_dataset_sources(dataset: &str) -> Vec<(String, Vec<u8>)> {
    match dataset {
        "generated_typescript_512" => (0..512)
            .map(|index| {
                let path = format!("generated/summary_{index}.ts");
                let source = format!(
                    "export function summary_{index}(value: string): string {{ return value; }}"
                )
                .into_bytes();
                (path, source)
            })
            .collect(),
        "inline_typescript" => vec![(
            "inline/summary.ts".to_owned(),
            TYPE_SCRIPT_INLINE_SOURCE.as_bytes().to_vec(),
        )],
        "inline_java" => vec![(
            "inline/SummaryFixture.java".to_owned(),
            JAVA_INLINE_SOURCE.as_bytes().to_vec(),
        )],
        "external_vscode_typescript" => collect_external_sources(
            Path::new(&required_env(TS_REPO_ENV)),
            VSCODE_COMMIT,
            &["ts", "tsx"],
            512,
        ),
        "external_spring_petclinic_java" => collect_external_sources(
            Path::new(&required_env(JAVA_REPO_ENV)),
            SPRING_PETCLINIC_COMMIT,
            &["java"],
            512,
        ),
        _ => panic!("unsupported semantic dataset {dataset:?}"),
    }
}

fn collect_external_sources(
    root: &Path,
    expected_commit: &str,
    extensions: &[&str],
    limit: usize,
) -> Vec<(String, Vec<u8>)> {
    assert_external_tree(root, expected_commit);
    let output = Command::new("git")
        .args(["-C"])
        .arg(root)
        .args(["ls-tree", "-r", "--name-only", "-z", "HEAD", "--"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "failed to enumerate pinned Git tree"
    );
    let mut paths = output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|bytes| !bytes.is_empty())
        .map(|bytes| String::from_utf8(bytes.to_vec()).unwrap())
        .filter(|path| {
            Path::new(path)
                .extension()
                .and_then(|value| value.to_str())
                .is_some_and(|extension| extensions.contains(&extension))
        })
        .collect::<Vec<_>>();
    paths.sort_unstable();
    paths.truncate(limit);
    assert!(
        !paths.is_empty(),
        "external dataset must contain source files"
    );
    let sources = paths
        .into_iter()
        .map(|relative| {
            let path = root.join(&relative);
            let metadata = fs::symlink_metadata(&path).unwrap();
            assert!(
                metadata.file_type().is_file(),
                "tracked lifecycle source must be a regular file: {relative}"
            );
            (relative, fs::read(path).unwrap())
        })
        .collect();
    assert_external_tree(root, expected_commit);
    sources
}

fn assert_external_tree(root: &Path, expected_commit: &str) {
    let head = Command::new("git")
        .args(["-C"])
        .arg(root)
        .args(["rev-parse", "HEAD"])
        .output()
        .unwrap();
    assert!(head.status.success());
    assert_eq!(
        String::from_utf8_lossy(&head.stdout).trim(),
        expected_commit
    );
    let clean = Command::new("git")
        .args(["-C"])
        .arg(root)
        .args(["diff", "--quiet", "--no-ext-diff", "HEAD", "--"])
        .status()
        .unwrap();
    assert!(
        clean.success(),
        "pinned external Git tree changed during collection"
    );
}

fn build_protocol_candidate() -> MeasuredArtifact {
    let (analyzer, artifact) = materialize_fixed_fixture(
        "protocol",
        "src/ProtocolLifecycleFixture.java",
        JAVA_PROTOCOL_SOURCE,
        Language::Java,
    );
    let root = procedure_named(&artifact, "lifecycle", ProcedureKind::Method);
    let procedure = root.semantics();
    let use_call = procedure
        .call_sites()
        .iter()
        .find(|call| {
            call.arguments.len() == 1
                && mapped_source(procedure, JAVA_PROTOCOL_SOURCE, call.source)
                    .contains("use(alias)")
        })
        .unwrap();
    let close_call = procedure
        .call_sites()
        .iter()
        .find(|call| {
            call.arguments.len() == 1
                && mapped_source(procedure, JAVA_PROTOCOL_SOURCE, call.source)
                    .contains("close(alias)")
        })
        .unwrap();
    let object = AbstractObject::new(
        AccessPathRoot::Value(root.value_handle(close_call.arguments[0].value).unwrap()),
        ObjectCardinality::Singleton,
    )
    .unwrap();
    let subject_class = TypestateSubjectClassKey::new("resource").unwrap();
    let subject = TypestateSubjectKey::for_object(subject_class.clone(), &object);
    let entry = root.point_handle(procedure.entry_point()).unwrap();
    let exit = root.point_handle(procedure.normal_exit_point()).unwrap();
    let use_point = root.point_handle(use_call.point).unwrap();
    let close_point = root.point_handle(close_call.point).unwrap();
    let context = TypestateBindingContext::root();
    let exact = TypestateBindingQuality::proven_unique();
    let mut protocol_spec = ProtocolSpec::from_json(include_bytes!(
        "../fixtures/typestate/resource-lifecycle.protocol.json"
    ))
    .unwrap();
    protocol_spec.states.push("used".to_owned());
    for transition in &mut protocol_spec.transitions {
        if transition.from == "open" && transition.on == "use" {
            transition.to = "used".to_owned();
        } else if transition.from == "open" && transition.on == "close" {
            transition.from = "used".to_owned();
        }
    }
    for event in &mut protocol_spec.events {
        if matches!(event.id.as_str(), "use" | "close") {
            event.observation.occurrence = ProtocolEventOccurrence::Endpoint {
                phase: ProtocolObservationPhase::AtMatch,
            };
        }
    }
    let protocol = protocol_spec.compile().unwrap();
    let bindings = TypestateBindingPlan::try_new(
        &protocol,
        vec![BoundTypestateSubjectSpec::new(
            subject_class,
            object,
            exact.clone(),
        )],
        vec![TypestateInitialSeedSpec::new(
            subject.clone(),
            ProtocolStateKey::new("unallocated").unwrap(),
            TypestateObservationSite::program_point(entry.clone(), context.clone()),
            TypestateObjectRole::MatchedValue,
            exact.clone(),
        )],
        vec![
            TypestateEventBindingSpec::new(
                ProtocolEventKey::new("acquire").unwrap(),
                subject.clone(),
                TypestateObservationSite::program_point(entry, context.clone()),
                0,
                TypestateObjectRole::AllocationResult,
                exact.clone(),
            ),
            TypestateEventBindingSpec::new(
                ProtocolEventKey::new("use").unwrap(),
                subject.clone(),
                TypestateObservationSite::program_point(use_point, context.clone()),
                0,
                TypestateObjectRole::MatchedValue,
                exact.clone(),
            ),
            TypestateEventBindingSpec::new(
                ProtocolEventKey::new("close").unwrap(),
                subject.clone(),
                TypestateObservationSite::program_point(close_point, context.clone()),
                0,
                TypestateObjectRole::MatchedValue,
                exact.clone(),
            ),
        ],
        vec![TypestateTerminalBindingSpec::new(
            ProtocolExpectationKey::new("normal-exit-closed").unwrap(),
            subject,
            TypestateObservationSite::program_point(exit, context),
            TypestateObjectRole::CurrentObject,
            exact,
        )],
    )
    .unwrap();
    let semantic = semantic_summary_for_handle(&root, b"protocol-summary-context");
    let semantic_set =
        brokk_bifrost::analyzer::typestate::ProtocolSemanticSummarySet::try_new(vec![&semantic])
            .unwrap();
    let key = ProtocolSummaryKey::try_from_semantic_summary(
        &semantic,
        protocol.hash(),
        bindings.summary_hash_for(
            root.artifact().key(),
            root.semantics().locator().declaration(),
        ),
        Vec::new(),
    )
    .unwrap();
    let invalid_semantic = semantic_summary_for_handle(&root, b"protocol-summary-changed-context");
    let invalid_key = ProtocolSummaryKey::try_from_semantic_summary(
        &invalid_semantic,
        protocol.hash(),
        bindings.summary_hash_for(
            root.artifact().key(),
            root.semantics().locator().declaration(),
        ),
        Vec::new(),
    )
    .unwrap();
    let mut repository = CompleteProtocolSummaryRepository::default();
    let result = solve_protocol(
        &root,
        &analyzer,
        &protocol,
        &bindings,
        &semantic_set,
        &mut repository,
    );
    assert!(result.computed_result().is_summary_publication_complete());
    assert_eq!(result.published_summaries(), 1);
    assert!(repository.get(&key).is_some());
    MeasuredArtifact::Protocol {
        repository,
        key,
        invalid_key: Box::new(invalid_key),
    }
}

fn solve_protocol(
    root: &ProcedureHandle,
    analyzer: &brokk_bifrost::WorkspaceAnalyzer,
    protocol: &brokk_bifrost::analyzer::typestate::CompiledProtocol,
    bindings: &TypestateBindingPlan,
    semantic_set: &brokk_bifrost::analyzer::typestate::ProtocolSemanticSummarySet<'_>,
    repository: &mut CompleteProtocolSummaryRepository,
) -> ProtocolSummarySolveResult {
    let cancellation = CancellationToken::default();
    let mut solver_budget = SolverBudget::default();
    let mut semantic_budget = SemanticBudget::default();
    solve_typestate_with_reusable_summaries(
        root,
        &[],
        &analyzer.icfg_provider(),
        protocol,
        bindings,
        semantic_set,
        repository,
        &mut semantic_budget,
        &mut DataflowRequest::new(&mut solver_budget, &cancellation),
    )
    .unwrap()
}

fn build_taint_candidate(source: &str) -> MeasuredArtifact {
    let (repository, keys) = solve_taint_fixture(source);
    assert!(!keys.is_empty());
    MeasuredArtifact::Taint {
        repository,
        keys,
        invalid_key: None,
    }
}

fn solve_taint_fixture(
    source: &str,
) -> (
    CompleteTaintTransferSummaryRepository,
    Vec<brokk_bifrost::analyzer::taint::TaintTransferSummaryKey>,
) {
    let fixture_name = if source == JAVA_TAINT_SOURCE {
        "taint-current"
    } else {
        "taint-changed"
    };
    let (analyzer, artifact) = materialize_fixed_fixture(
        fixture_name,
        "src/TaintFixture.java",
        source,
        Language::Java,
    );
    let helper = procedure_named(&artifact, "helper", ProcedureKind::Method);
    let root = procedure_named(&artifact, "caller", ProcedureKind::Method);
    let cancellation = CancellationToken::default();
    let mut semantic_budget = SemanticBudget::default();
    let oracle = analyzer.semantic_oracle_provider();
    let call = root
        .call_site_handle(root.semantics().call_sites().first().unwrap().id)
        .unwrap();
    let dispatch = oracle
        .resolve_call(
            &call,
            &mut SemanticRequest::new(&mut semantic_budget, &cancellation),
        )
        .unwrap();
    let candidate = dispatch
        .available_value()
        .unwrap()
        .candidates()
        .iter()
        .find(|candidate| candidate.target() == &helper)
        .unwrap()
        .clone();
    let live_bindings = oracle
        .call_bindings(
            &call,
            &candidate,
            &OracleCallContext::empty(),
            &mut SemanticRequest::new(&mut semantic_budget, &cancellation),
        )
        .unwrap();
    let live_bindings = live_bindings.available_value().unwrap();
    let bindings = ValueFlowInput::new(
        CallBindings::new(
            call,
            &candidate,
            OracleCallContext::empty(),
            live_bindings.bindings().to_vec(),
            CandidateCoverage::Exhaustive,
            OracleLimits::default(),
        )
        .unwrap(),
        SemanticInputStatus::Complete,
    );
    let mut snapshots = Vec::new();
    for procedure in [&root, &helper] {
        let outcome = oracle
            .procedure_relations(
                procedure,
                &OracleCallContext::empty(),
                &mut SemanticRequest::new(&mut semantic_budget, &cancellation),
            )
            .unwrap();
        let snapshot = outcome.available_value().unwrap();
        snapshots.push(ValueFlowInput::new(
            ValueFlowSnapshot::new(
                procedure.clone(),
                OracleCallContext::empty(),
                snapshot.relations().to_vec(),
                CandidateCoverage::Exhaustive,
                OracleLimits::default(),
            )
            .unwrap(),
            SemanticInputStatus::Complete,
        ));
    }
    let helper_snapshot = snapshots
        .iter()
        .find(|snapshot| snapshot.value().procedure() == &helper)
        .unwrap();
    let relation = helper_snapshot
        .value()
        .relations()
        .iter()
        .find(|relation| relation.kind == ValueFlowRelationKind::Assignment)
        .unwrap();
    let source_spec = ValueFlowSourceSpec::new(
        ValueFlowEventKey::at_point(relation.point(), 0, ValueFlowEventKind::Source).unwrap(),
        relation.point().clone(),
        ValueFlowObservationPhase::BeforeEffects,
        ValueFlowCarrier::from(&relation.source),
        ProofStatus::Proven,
        EvidenceCompleteness::Complete,
    );
    let sink_spec = ValueFlowSinkSpec::new(
        ValueFlowEventKey::at_point(relation.point(), 0, ValueFlowEventKind::Sink).unwrap(),
        relation.point().clone(),
        ValueFlowObservationPhase::AfterEffects,
        ValueFlowCarrier::from(&relation.target),
        ProofStatus::Proven,
        EvidenceCompleteness::Complete,
    );
    let value_flow = ValueFlowPlan::try_new(
        root.clone(),
        snapshots,
        vec![bindings],
        vec![source_spec],
        vec![sink_spec],
    )
    .unwrap();
    let source_class = SourceClassId::new("summary-lifecycle").unwrap();
    let universe = TaintUniverse::new(vec![source_class.clone()]).unwrap();
    let classes: TaintClassSet = universe.class_set([&source_class]).unwrap();
    let source_binding = {
        let (source_id, source) = value_flow.sources().next().unwrap();
        TaintSourceBinding::new(
            source_id,
            classes.clone(),
            SourceEventKey::new(source.key().clone()),
        )
    };
    let sink_binding = {
        let (sink_id, _) = value_flow.sinks().next().unwrap();
        TaintSinkBinding::new(sink_id, classes)
    };
    let plan = TaintAnalysisPlan::new(
        value_flow,
        universe,
        vec![source_binding],
        vec![sink_binding],
        Vec::new(),
        Vec::new(),
    )
    .unwrap();
    let helper_semantic = semantic_summary_for_handle(&helper, b"taint-summary-context");
    let root_semantic = semantic_summary_with_dependencies_for_handle(
        &root,
        b"taint-summary-context",
        &[&helper_semantic],
    );
    let semantic_set =
        TaintSemanticSummarySet::try_new(vec![&helper_semantic, &root_semantic]).unwrap();
    let mut repository = CompleteTaintTransferSummaryRepository::default();
    let mut solver_budget = SolverBudget::default();
    let mut semantic_budget = SemanticBudget::default();
    let cancellation = CancellationToken::default();
    let result = solve_taint_with_reusable_summaries(
        &root,
        &analyzer.icfg_provider(),
        &plan,
        &semantic_set,
        &mut repository,
        &mut semantic_budget,
        &mut DataflowRequest::new(&mut solver_budget, &cancellation),
    )
    .unwrap();
    assert!(
        result.computed_result().is_complete(),
        "cache={:?} termination={:?} coverage={:?}",
        result.cache_status(),
        result.computed_result().termination(),
        result.computed_result().coverage(),
    );
    assert_eq!(result.published_summaries(), 2);
    let keys = repository.keys().cloned().collect();
    (repository, keys)
}

fn semantic_summary_for_handle(root: &ProcedureHandle, context: &[u8]) -> SemanticProcedureSummary {
    semantic_summary_with_dependencies_for_handle(root, context, &[])
}

fn semantic_summary_with_dependencies_for_handle(
    root: &ProcedureHandle,
    context: &[u8],
    dependencies: &[&SemanticProcedureSummary],
) -> SemanticProcedureSummary {
    let identity = ProcedureSummaryIdentity::new(
        root.artifact().key().clone(),
        root.semantics().locator().declaration().clone(),
        SummarySchemaVersion::CURRENT,
        SummarySemanticsVersion::hash_bytes(b"summary-lifecycle-client-v1"),
        SummaryContextKey::hash_bytes(context),
        SummaryBehaviorKey::hash_bytes(b"conservative"),
        SummaryOrigin::Inferred,
    );
    let dependencies = dependencies
        .iter()
        .map(|summary| SummaryDependencyKey::complete(summary.key().clone()))
        .collect::<Vec<_>>();
    let key = ProcedureSummaryKey::try_new(identity, &dependencies, None).unwrap();
    let effects = dependencies
        .iter()
        .enumerate()
        .map(|(index, dependency)| {
            SummaryEffect::new(
                SummaryEffectKey::Call {
                    event: SummaryEventKey::hash_bytes(index.to_le_bytes()),
                    callee: Box::new(dependency.clone()),
                },
                SummaryEvidence::proven_complete(),
            )
        })
        .collect();
    SemanticProcedureSummary::try_new(
        key,
        Vec::new(),
        effects,
        dependencies,
        SummaryCompleteness::Complete,
    )
    .unwrap()
}

fn materialize_fixed_fixture(
    name: &str,
    relative_path: &str,
    source: &str,
    language: Language,
) -> (WorkspaceAnalyzer, Arc<SemanticArtifact>) {
    let root = PathBuf::from(required_env(FIXTURE_ROOT_ENV)).join(name);
    fs::create_dir_all(&root).unwrap();
    let file = ProjectFile::new(root.clone(), relative_path);
    file.write(source).unwrap();
    let project = Arc::new(TestProject::new(root, language));
    let analyzer = WorkspaceAnalyzer::build(project, AnalyzerConfig::default());
    let cancellation = CancellationToken::default();
    let mut budget = SemanticBudget::default();
    let outcome = analyzer
        .materialize_program_semantics(&file, &mut SemanticRequest::new(&mut budget, &cancellation))
        .unwrap();
    let artifact = outcome
        .available_value()
        .expect("fixed lifecycle fixture must materialize")
        .clone();
    (analyzer, artifact)
}

fn procedure_named(
    artifact: &Arc<SemanticArtifact>,
    name: &str,
    kind: ProcedureKind,
) -> ProcedureHandle {
    let procedure = artifact
        .procedures()
        .iter()
        .find(|procedure| {
            procedure.kind() == kind
                && procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some(name)
        })
        .unwrap();
    artifact.procedure_handle(procedure.id()).unwrap()
}

fn dataset_provenance(candidate: &str, dataset: &str, artifact_count: usize) -> DatasetProvenance {
    let (origin, language, commit) = match dataset {
        "generated_typescript_512" => ("generated", "typescript", None),
        "inline_typescript" => ("inline", "typescript", None),
        "inline_java" => ("inline", "java", None),
        "external_vscode_typescript" => ("external_vscode", "typescript", Some(VSCODE_COMMIT)),
        "external_spring_petclinic_java" => (
            "external_spring_petclinic",
            "java",
            Some(SPRING_PETCLINIC_COMMIT),
        ),
        _ => panic!("unknown dataset {dataset:?}"),
    };
    DatasetProvenance {
        origin: origin.to_owned(),
        language: language.to_owned(),
        source_items: if candidate == "semantic" {
            artifact_count
        } else {
            1
        },
        repository_commit: commit.map(str::to_owned),
    }
}

fn aggregate_samples(path: &Path) -> AggregateResult {
    let contents = fs::read_to_string(path).unwrap();
    let mut groups: BTreeMap<(String, String), Vec<SampleResult>> = BTreeMap::new();
    for line in contents.lines().filter(|line| !line.trim().is_empty()) {
        let sample: SampleResult = serde_json::from_str(line).unwrap();
        assert_eq!(sample.format, FORMAT);
        groups
            .entry((sample.candidate.clone(), sample.dataset.clone()))
            .or_default()
            .push(sample);
    }
    let expected_cases = [
        ("semantic", "generated_typescript_512"),
        ("semantic", "inline_typescript"),
        ("semantic", "inline_java"),
        ("semantic", "external_vscode_typescript"),
        ("semantic", "external_spring_petclinic_java"),
        ("protocol", "inline_java"),
        ("taint", "inline_java"),
    ]
    .into_iter()
    .map(|(candidate, dataset)| (candidate.to_owned(), dataset.to_owned()))
    .collect::<BTreeSet<_>>();
    assert_eq!(
        groups.keys().cloned().collect::<BTreeSet<_>>(),
        expected_cases,
        "samples must contain the exact declared case matrix",
    );
    let thresholds = ArtifactPromotionThresholds::default();
    let mut medians = Vec::new();
    let mut aggregate_provenance = None;
    for ((candidate, dataset), samples) in groups {
        assert_eq!(
            samples.len(),
            REQUIRED_RETAINED_SAMPLES * 2,
            "one build and one hydrate record are required per retained round",
        );
        let builds = samples
            .iter()
            .filter(|sample| sample.mode == "build")
            .collect::<Vec<_>>();
        let hydrates = samples
            .iter()
            .filter(|sample| sample.mode == "hydrate")
            .collect::<Vec<_>>();
        assert_eq!(builds.len(), REQUIRED_RETAINED_SAMPLES);
        assert_eq!(hydrates.len(), REQUIRED_RETAINED_SAMPLES);
        let reference = builds[0];
        let expected_rounds = (2..=8).collect::<BTreeSet<_>>();
        assert_eq!(
            builds
                .iter()
                .map(|sample| sample.round)
                .collect::<BTreeSet<_>>(),
            expected_rounds,
            "build rounds must be unique and complete for {candidate}:{dataset}",
        );
        assert_eq!(
            hydrates
                .iter()
                .map(|sample| sample.round)
                .collect::<BTreeSet<_>>(),
            expected_rounds,
            "hydrate rounds must be unique and complete for {candidate}:{dataset}",
        );
        match &aggregate_provenance {
            Some(provenance) => assert_eq!(
                provenance, &reference.provenance,
                "all lifecycle cases must share exact provenance",
            ),
            None => aggregate_provenance = Some(reference.provenance.clone()),
        }
        for sample in samples.iter().skip(1) {
            assert_eq!(sample.provenance, reference.provenance);
            assert_eq!(sample.dataset_provenance, reference.dataset_provenance);
            assert_eq!(sample.result_checksum, reference.result_checksum);
            assert_eq!(sample.validity_checksum, reference.validity_checksum);
            assert_eq!(sample.artifact_count, reference.artifact_count);
            assert_eq!(sample.row_count, reference.row_count);
            assert_eq!(sample.effect_count, reference.effect_count);
            assert_eq!(sample.serialized_bytes, reference.serialized_bytes);
            assert_eq!(sample.retained_bytes, reference.retained_bytes);
            assert_eq!(sample.complete, reference.complete);
            assert_eq!(sample.exact_equivalence, reference.exact_equivalence);
        }
        assert!(builds.iter().all(|sample| sample.lookup_hit));
        assert!(builds.iter().all(|sample| sample.invalidation_miss));
        assert!(samples.iter().all(|sample| sample.complete));
        assert!(samples.iter().all(|sample| !sample.exact_equivalence));
        let rebuild_ms = median_f64(
            builds
                .iter()
                .map(|sample| sample.rebuild_ms.unwrap())
                .collect(),
        );
        let same_process_reuse_ms = median_f64(
            builds
                .iter()
                .map(|sample| sample.same_process_reuse_ms.unwrap())
                .collect(),
        );
        let build_write_ms = median_f64(
            builds
                .iter()
                .map(|sample| sample.build_write_ms.unwrap())
                .collect(),
        );
        let hydrate_ms = median_f64(
            hydrates
                .iter()
                .map(|sample| sample.hydrate_ms.unwrap())
                .collect(),
        );
        let rebuild_peak_rss_bytes =
            median_optional_u64(builds.iter().map(|sample| sample.peak_rss_bytes).collect());
        let hydrate_peak_rss_bytes = median_optional_u64(
            hydrates
                .iter()
                .map(|sample| sample.peak_rss_bytes)
                .collect(),
        );
        let serialized_bytes = median_u64(
            builds
                .iter()
                .map(|sample| sample.serialized_bytes)
                .collect(),
        );
        let retained_bytes =
            median_u64(builds.iter().map(|sample| sample.retained_bytes).collect());
        let evaluation = evaluate_artifact_promotion(
            thresholds,
            ArtifactPromotionMeasurement {
                rebuild_ms,
                build_write_ms,
                hydrate_ms,
                rebuild_peak_rss_bytes,
                hydrate_peak_rss_bytes,
                serialized_bytes,
                estimated_hydrated_bytes: retained_bytes,
            },
        )
        .unwrap();
        medians.push(MedianResult {
            candidate,
            dataset,
            dataset_provenance: reference.dataset_provenance.clone(),
            rebuild_ms,
            same_process_reuse_ms,
            build_write_ms,
            hydrate_ms,
            rebuild_peak_rss_bytes,
            hydrate_peak_rss_bytes,
            serialized_bytes,
            retained_bytes,
            artifact_count: reference.artifact_count,
            row_count: reference.row_count,
            effect_count: reference.effect_count,
            complete: reference.complete,
            lookup_hit: true,
            invalidation_miss: true,
            result_checksum: reference.result_checksum.clone(),
            validity_checksum: reference.validity_checksum.clone(),
            exact_equivalence: reference.exact_equivalence,
            hydration_speedup_percent: evaluation.hydration_speedup_percent,
            hydration_saved_ms: evaluation.hydration_saved_ms,
            gates_passed: evaluation.passed(),
            hydration_speedup_gate: format!("{:?}", evaluation.hydration_speedup),
            hydration_absolute_saving_gate: format!("{:?}", evaluation.hydration_absolute_saving),
            hydration_rss_gate: format!("{:?}", evaluation.hydration_rss),
            serialized_size_gate: format!("{:?}", evaluation.serialized_size),
            build_write_time_gate: format!("{:?}", evaluation.build_write_time),
            build_write_absolute_overhead_gate: format!(
                "{:?}",
                evaluation.build_write_absolute_overhead
            ),
            decision: promotion_decision(reference.exact_equivalence, evaluation.passed()),
            reason: "diagnostic envelope does not reconstruct an applicable summary",
        });
    }
    assert_eq!(
        medians.len(),
        7,
        "runner must supply the declared seven cases"
    );
    AggregateResult {
        format: AGGREGATE_FORMAT,
        provenance: aggregate_provenance.expect("at least one lifecycle case"),
        thresholds: thresholds.into(),
        discarded_warmups_per_case: 2,
        retained_samples_per_case: REQUIRED_RETAINED_SAMPLES,
        medians,
    }
}

fn promotion_decision(exact_equivalence: bool, gates_passed: bool) -> &'static str {
    if !exact_equivalence {
        "insufficient_evidence"
    } else if gates_passed {
        "promote_to_sqlite"
    } else {
        "remain_in_memory"
    }
}

fn benchmark_provenance() -> BenchmarkProvenance {
    BenchmarkProvenance {
        bifrost_commit: command_output("git", &["rev-parse", "HEAD"]),
        bifrost_tracked_dirty: command_output(
            "git",
            &["status", "--porcelain", "--untracked-files=no"],
        )
        .map(|value| !value.is_empty()),
        benchmark_source_checksum: benchmark_source_checksum(),
        rustc_version: command_output("rustc", &["--version"]),
        operating_system: std::env::consts::OS.to_owned(),
        architecture: std::env::consts::ARCH.to_owned(),
        logical_parallelism: std::thread::available_parallelism().ok().map(usize::from),
        build_profile: if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        }
        .to_owned(),
    }
}

fn benchmark_source_checksum() -> Option<String> {
    let mut digest = Sha256::new();
    for path in [
        "tests/measure_summary_lifecycle.rs",
        "scripts/run-summary-lifecycle-benchmarks.sh",
    ] {
        let bytes = fs::read(path).ok()?;
        digest.update(path.as_bytes());
        digest.update(bytes.len().to_le_bytes());
        digest.update(bytes);
    }
    Some(hex_digest(digest.finalize()))
}

fn command_output(program: &str, arguments: &[&str]) -> Option<String> {
    let output = Command::new(program).args(arguments).output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn required_env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is required"))
}

fn elapsed_ms(started: Instant) -> f64 {
    started.elapsed().as_secs_f64() * 1_000.0
}

struct StructuralSha256(Sha256);

impl StructuralSha256 {
    fn new() -> Self {
        let mut digest = Sha256::new();
        digest.update(b"bifrost-summary-structural-hash/v1");
        Self(digest)
    }

    fn finalize(self) -> [u8; 32] {
        self.0.finalize().into()
    }
}

impl Hasher for StructuralSha256 {
    fn finish(&self) -> u64 {
        0
    }

    fn write(&mut self, bytes: &[u8]) {
        self.0.update(bytes.len().to_le_bytes());
        self.0.update(bytes);
    }

    fn write_u8(&mut self, value: u8) {
        self.write(&value.to_le_bytes());
    }

    fn write_u16(&mut self, value: u16) {
        self.write(&value.to_le_bytes());
    }

    fn write_u32(&mut self, value: u32) {
        self.write(&value.to_le_bytes());
    }

    fn write_u64(&mut self, value: u64) {
        self.write(&value.to_le_bytes());
    }

    fn write_u128(&mut self, value: u128) {
        self.write(&value.to_le_bytes());
    }

    fn write_usize(&mut self, value: usize) {
        self.write(&u64::try_from(value).unwrap().to_le_bytes());
    }

    fn write_i8(&mut self, value: i8) {
        self.write(&value.to_le_bytes());
    }

    fn write_i16(&mut self, value: i16) {
        self.write(&value.to_le_bytes());
    }

    fn write_i32(&mut self, value: i32) {
        self.write(&value.to_le_bytes());
    }

    fn write_i64(&mut self, value: i64) {
        self.write(&value.to_le_bytes());
    }

    fn write_i128(&mut self, value: i128) {
        self.write(&value.to_le_bytes());
    }

    fn write_isize(&mut self, value: isize) {
        self.write(&i64::try_from(value).unwrap().to_le_bytes());
    }
}

fn structural_checksum<Value: Hash + ?Sized>(value: &Value) -> [u8; 32] {
    let mut digest = StructuralSha256::new();
    value.hash(&mut digest);
    digest.finalize()
}

fn hex_digest(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn median_f64(mut values: Vec<f64>) -> f64 {
    assert!(!values.is_empty());
    values.sort_unstable_by(f64::total_cmp);
    values[values.len() / 2]
}

fn median_u64(mut values: Vec<u64>) -> u64 {
    assert!(!values.is_empty());
    values.sort_unstable();
    values[values.len() / 2]
}

fn median_optional_u64(values: Vec<Option<u64>>) -> Option<u64> {
    values
        .into_iter()
        .collect::<Option<Vec<_>>>()
        .map(median_u64)
}

fn emit(value: &impl Serialize) {
    println!("{RESULT_PREFIX}{}", serde_json::to_string(value).unwrap());
}

#[cfg(unix)]
fn peak_rss_bytes() -> Option<u64> {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::zeroed();
    // SAFETY: `getrusage` initializes the provided `rusage` on success.
    let status = unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) };
    if status != 0 {
        return None;
    }
    // SAFETY: successful `getrusage` initialized the value.
    let usage = unsafe { usage.assume_init() };
    let peak = u64::try_from(usage.ru_maxrss).ok()?;
    if cfg!(target_os = "macos") {
        Some(peak)
    } else {
        peak.checked_mul(1024)
    }
}

#[cfg(not(unix))]
fn peak_rss_bytes() -> Option<u64> {
    None
}
