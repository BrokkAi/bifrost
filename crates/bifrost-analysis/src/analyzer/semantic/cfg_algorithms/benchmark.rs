//! Ignored release benchmark for the issue #819 algorithm lifecycle decision.

use std::hint::black_box;
use std::io::Write;
use std::mem::size_of;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use tempfile::NamedTempFile;

use super::test_support::{SyntheticEdgeId, SyntheticGraph};
use super::*;
use crate::analyzer::benchmark_provenance::{
    command_output_in as command_output, git_tree_fingerprint,
};
use crate::analyzer::semantic::{SemanticBudget, SemanticOutcome, SemanticRequest, StableDigest};
use crate::{AnalyzerConfig, Language, Project, TestProject, WorkspaceAnalyzer};

const OUTPUT_ENV: &str = "BIFROST_CFG_ALGORITHM_BENCHMARK_OUTPUT";
const REPEATS_ENV: &str = "BIFROST_CFG_ALGORITHM_BENCHMARK_REPEATS";
const TS_REPO_ENV: &str = "BIFROST_SEMANTIC_TS_REPO";
const JAVA_REPO_ENV: &str = "BIFROST_SEMANTIC_JAVA_REPO";
const VSCODE_COMMIT: &str = "19e0f9e681ecb8e5c09d8784acaa601316ca4571";
const SPRING_PETCLINIC_COMMIT: &str = "f182358d02e4a68e52bdbabf55ca7800288511e7";
const MAX_REPEATS: usize = 10;

trait BenchmarkGraph: DenseBidirectionalGraph {
    fn benchmark_edge_index(&self, edge: Self::Edge) -> Option<usize>;
}

impl BenchmarkGraph for SyntheticGraph {
    fn benchmark_edge_index(&self, edge: SyntheticEdgeId) -> Option<usize> {
        self.edge_endpoints(edge).map(|_| edge.0)
    }
}

impl BenchmarkGraph for ProcedureSemantics {
    fn benchmark_edge_index(&self, edge: ControlEdgeId) -> Option<usize> {
        self.control_edge(edge).map(|_| edge.index())
    }
}

#[derive(Debug, Clone, Copy)]
enum Algorithm {
    ForwardReachability,
    ReverseReachability,
    DfsAndReversePostorder,
    KosarajuScc,
    LoopRegions,
    ShortestPath,
}

impl Algorithm {
    const ALL: [Self; 6] = [
        Self::ForwardReachability,
        Self::ReverseReachability,
        Self::DfsAndReversePostorder,
        Self::KosarajuScc,
        Self::LoopRegions,
        Self::ShortestPath,
    ];

    const fn label(self) -> &'static str {
        match self {
            Self::ForwardReachability => "forward_reachability",
            Self::ReverseReachability => "reverse_reachability",
            Self::DfsAndReversePostorder => "dfs_reverse_postorder",
            Self::KosarajuScc => "kosaraju_scc",
            Self::LoopRegions => "loop_regions",
            Self::ShortestPath => "shortest_path",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RunResult {
    work: CfgAlgorithmWork,
    retained_bytes: u64,
    digest: String,
}

#[derive(Debug, Serialize)]
struct AlgorithmMeasurement {
    algorithm: String,
    cold_ms: f64,
    repeated_total_ms: f64,
    repeated_recomputations: usize,
    visited_nodes: usize,
    visited_edges: usize,
    retained_result_bytes: u64,
    result_digest: String,
}

#[derive(Debug, Serialize)]
struct DatasetMeasurement {
    name: String,
    origin: String,
    language: Option<String>,
    repository_commit: Option<String>,
    repository_dirty: Option<bool>,
    status: String,
    files_seen: usize,
    files_materialized: usize,
    graphs: usize,
    nodes: usize,
    edges: usize,
    algorithms: Vec<AlgorithmMeasurement>,
}

#[derive(Debug, Serialize)]
struct CorpusProvenance {
    environment_variable: &'static str,
    expected_commit: &'static str,
    configured: bool,
}

#[derive(Debug, Serialize)]
struct Provenance {
    bifrost_commit: Option<String>,
    bifrost_dirty: Option<bool>,
    bifrost_tree_fingerprint: Option<String>,
    rustc_version_verbose: Option<String>,
    cargo_version: Option<String>,
    operating_system: &'static str,
    architecture: &'static str,
    build_profile: &'static str,
    crate_version: &'static str,
    timer: &'static str,
    generated_unix_seconds: u64,
    corpora: [CorpusProvenance; 2],
}

#[derive(Debug, Serialize)]
struct BenchmarkReport {
    format: &'static str,
    schema_version: u32,
    purpose: &'static str,
    provenance: Provenance,
    repeats_per_graph: usize,
    datasets: Vec<DatasetMeasurement>,
}

#[derive(Debug, Default)]
struct AlgorithmAccumulator {
    cold: Duration,
    repeated: Duration,
    work: CfgAlgorithmWork,
    retained_bytes: u64,
    digests: Vec<String>,
}

struct DatasetAccumulator {
    name: String,
    origin: String,
    language: Option<String>,
    repository_commit: Option<String>,
    repository_dirty: Option<bool>,
    status: String,
    files_seen: usize,
    files_materialized: usize,
    graphs: usize,
    nodes: usize,
    edges: usize,
    algorithms: [AlgorithmAccumulator; 6],
    repeats: usize,
}

impl DatasetAccumulator {
    fn new(name: impl Into<String>, origin: impl Into<String>, repeats: usize) -> Self {
        Self {
            name: name.into(),
            origin: origin.into(),
            language: None,
            repository_commit: None,
            repository_dirty: None,
            status: "complete".to_owned(),
            files_seen: 0,
            files_materialized: 0,
            graphs: 0,
            nodes: 0,
            edges: 0,
            algorithms: std::array::from_fn(|_| AlgorithmAccumulator::default()),
            repeats,
        }
    }

    fn measure<G>(&mut self, graph: &G, start: G::Node, goal: G::Node)
    where
        G: BenchmarkGraph,
    {
        let edge_count = (0..graph.node_count())
            .map(|index| graph.successors(required_node(graph, index)).len())
            .sum::<usize>();
        self.graphs += 1;
        self.nodes = self.nodes.saturating_add(graph.node_count());
        self.edges = self.edges.saturating_add(edge_count);

        for (index, algorithm) in Algorithm::ALL.into_iter().enumerate() {
            let (cold_duration, cold) = run_algorithm(graph, start, goal, edge_count, algorithm);
            self.algorithms[index].cold += cold_duration;
            black_box(&cold);

            for _ in 0..self.repeats {
                let (repeated_duration, repeated) =
                    run_algorithm(graph, start, goal, edge_count, algorithm);
                assert_eq!(
                    repeated,
                    cold,
                    "{} changed across recomputation in {}",
                    algorithm.label(),
                    self.name
                );
                self.algorithms[index].repeated += repeated_duration;
                black_box(repeated);
            }
            self.algorithms[index].work.node_visits = self.algorithms[index]
                .work
                .node_visits
                .saturating_add(cold.work.node_visits);
            self.algorithms[index].work.edge_visits = self.algorithms[index]
                .work
                .edge_visits
                .saturating_add(cold.work.edge_visits);
            self.algorithms[index].retained_bytes = self.algorithms[index]
                .retained_bytes
                .saturating_add(cold.retained_bytes);
            self.algorithms[index].digests.push(cold.digest);
        }
    }

    fn finish(self) -> DatasetMeasurement {
        let algorithms = Algorithm::ALL
            .into_iter()
            .zip(self.algorithms)
            .map(|(algorithm, accumulator)| AlgorithmMeasurement {
                algorithm: algorithm.label().to_owned(),
                cold_ms: milliseconds(accumulator.cold),
                repeated_total_ms: milliseconds(accumulator.repeated),
                repeated_recomputations: self.repeats.saturating_mul(self.graphs),
                visited_nodes: accumulator.work.node_visits,
                visited_edges: accumulator.work.edge_visits,
                retained_result_bytes: accumulator.retained_bytes,
                result_digest: digest_strings(&accumulator.digests),
            })
            .collect();
        DatasetMeasurement {
            name: self.name,
            origin: self.origin,
            language: self.language,
            repository_commit: self.repository_commit,
            repository_dirty: self.repository_dirty,
            status: self.status,
            files_seen: self.files_seen,
            files_materialized: self.files_materialized,
            graphs: self.graphs,
            nodes: self.nodes,
            edges: self.edges,
            algorithms,
        }
    }
}

fn run_algorithm<G>(
    graph: &G,
    start: G::Node,
    goal: G::Node,
    edge_count: usize,
    algorithm: Algorithm,
) -> (Duration, RunResult)
where
    G: BenchmarkGraph,
{
    let mut budget = CfgAlgorithmBudget::new(CfgAlgorithmWork {
        node_visits: graph.node_count().saturating_add(1).saturating_mul(8),
        edge_visits: edge_count.saturating_add(1).saturating_mul(8),
    });
    let cancellation = CancellationToken::default();
    let mut request = CfgAlgorithmRequest::new(&mut budget, &cancellation);
    let mut material = Vec::new();
    let retained_bytes;
    let work;
    let elapsed;

    match algorithm {
        Algorithm::ForwardReachability => {
            let started = Instant::now();
            let result = forward_reachability(graph, start, &mut request).unwrap();
            elapsed = started.elapsed();
            push_nodes(graph, result.iter(graph), &mut material, b'n');
            work = result.work();
            retained_bytes = bytes(result.membership().len(), size_of::<bool>());
        }
        Algorithm::ReverseReachability => {
            let started = Instant::now();
            let result = reverse_reachability(graph, goal, &mut request).unwrap();
            elapsed = started.elapsed();
            push_nodes(graph, result.iter(graph), &mut material, b'n');
            work = result.work();
            retained_bytes = bytes(result.membership().len(), size_of::<bool>());
        }
        Algorithm::DfsAndReversePostorder => {
            let started = Instant::now();
            let result = depth_first_order(graph, &mut request).unwrap();
            elapsed = started.elapsed();
            push_nodes(graph, result.preorder.iter().copied(), &mut material, b'p');
            push_nodes(
                graph,
                result.reverse_postorder.iter().copied(),
                &mut material,
                b'r',
            );
            push_edges(
                graph,
                result.back_edges.iter().copied(),
                &mut material,
                b'b',
            );
            work = result.work;
            retained_bytes = bytes(
                result
                    .preorder
                    .len()
                    .saturating_add(result.postorder.len())
                    .saturating_add(result.reverse_postorder.len()),
                size_of::<G::Node>(),
            )
            .saturating_add(bytes(result.back_edges.len(), size_of::<G::Edge>()));
        }
        Algorithm::KosarajuScc => {
            let started = Instant::now();
            let result = strongly_connected_components(graph, &mut request).unwrap();
            elapsed = started.elapsed();
            push_count(&mut material, b'c', result.components.len());
            for component in &result.components {
                push_nodes(graph, component.iter().copied(), &mut material, b'm');
            }
            work = result.work;
            retained_bytes = bytes(graph.node_count(), size_of::<usize>())
                .saturating_add(bytes(graph.node_count(), size_of::<G::Node>()))
                .saturating_add(bytes(result.components.len(), size_of::<Box<[G::Node]>>()));
        }
        Algorithm::LoopRegions => {
            let started = Instant::now();
            let result = loop_regions(graph, &mut request).unwrap();
            elapsed = started.elapsed();
            push_count(&mut material, b'r', result.regions.len());
            let mut retained = bytes(
                result.regions.len(),
                size_of::<LoopRegion<G::Node, G::Edge>>(),
            );
            for region in &result.regions {
                push_nodes(graph, region.members.iter().copied(), &mut material, b'm');
                push_nodes(graph, region.entries.iter().copied(), &mut material, b'e');
                push_edges(
                    graph,
                    region.back_edges.iter().copied(),
                    &mut material,
                    b'b',
                );
                push_field(&mut material, b'h', &[u8::from(region.has_self_loop)]);
                push_field(
                    &mut material,
                    b's',
                    &[match region.entry_structure {
                        LoopEntryStructure::None => 0,
                        LoopEntryStructure::Single => 1,
                        LoopEntryStructure::Multiple => 2,
                    }],
                );
                retained = retained
                    .saturating_add(bytes(region.members.len(), size_of::<G::Node>()))
                    .saturating_add(bytes(region.entries.len(), size_of::<G::Node>()))
                    .saturating_add(bytes(region.back_edges.len(), size_of::<G::Edge>()));
            }
            work = result.work;
            retained_bytes = retained;
        }
        Algorithm::ShortestPath => {
            let started = Instant::now();
            let result = shortest_path(graph, start, goal, &mut request).unwrap();
            elapsed = started.elapsed();
            if let Some(path) = result {
                push_field(&mut material, b'o', &[1]);
                push_nodes(graph, path.nodes.iter().copied(), &mut material, b'n');
                push_edges(graph, path.edges.iter().copied(), &mut material, b'e');
                retained_bytes = bytes(path.nodes.len(), size_of::<G::Node>())
                    .saturating_add(bytes(path.edges.len(), size_of::<G::Edge>()));
            } else {
                push_field(&mut material, b'o', &[0]);
                retained_bytes = 0;
            }
            work = budget.used();
        }
    }
    (
        elapsed,
        RunResult {
            work,
            retained_bytes,
            digest: StableDigest::sha256(material).to_string(),
        },
    )
}

fn push_nodes<G>(
    graph: &G,
    nodes: impl IntoIterator<Item = G::Node>,
    material: &mut Vec<u8>,
    tag: u8,
) where
    G: DenseBidirectionalGraph,
{
    let mut encoded = Vec::new();
    let mut count = 0usize;
    for node in nodes {
        encoded.extend_from_slice(
            &u64::try_from(
                graph
                    .node_index(node)
                    .expect("result node belongs to graph"),
            )
            .unwrap()
            .to_le_bytes(),
        );
        count = count.saturating_add(1);
    }
    push_sequence(material, tag, count, &encoded);
}

fn push_edges<G>(
    graph: &G,
    edges: impl IntoIterator<Item = G::Edge>,
    material: &mut Vec<u8>,
    tag: u8,
) where
    G: BenchmarkGraph,
{
    let mut encoded = Vec::new();
    let mut count = 0usize;
    for edge in edges {
        encoded.extend_from_slice(
            &u64::try_from(
                graph
                    .benchmark_edge_index(edge)
                    .expect("result edge belongs to graph"),
            )
            .unwrap()
            .to_le_bytes(),
        );
        count = count.saturating_add(1);
    }
    push_sequence(material, tag, count, &encoded);
}

fn push_count(material: &mut Vec<u8>, tag: u8, count: usize) {
    push_field(material, tag, &u64::try_from(count).unwrap().to_le_bytes());
}

fn push_sequence(material: &mut Vec<u8>, tag: u8, count: usize, encoded: &[u8]) {
    material.push(tag);
    material.extend_from_slice(&u64::try_from(count).unwrap().to_le_bytes());
    material.extend_from_slice(&u64::try_from(encoded.len()).unwrap().to_le_bytes());
    material.extend_from_slice(encoded);
}

fn push_field(material: &mut Vec<u8>, tag: u8, bytes: &[u8]) {
    material.push(tag);
    material.extend_from_slice(&u64::try_from(bytes.len()).unwrap().to_le_bytes());
    material.extend_from_slice(bytes);
}

fn synthetic_datasets(repeats: usize) -> Vec<DatasetMeasurement> {
    let chain_nodes = 100_000;
    let chain = SyntheticGraph::from_edges(
        chain_nodes,
        (0..chain_nodes - 1).map(|source| (source, source + 1, 0)),
    );
    let mut branch_edges = Vec::new();
    for source in 0..19_999 {
        branch_edges.push((source, source + 1, 0));
        if source % 3 == 0 && source + 2 < 20_000 {
            branch_edges.push((source, source + 2, 1));
        }
    }
    let branch = SyntheticGraph::from_edges(20_000, branch_edges);
    let reducible = SyntheticGraph::from_edges(
        9,
        edges(&[
            (0, 1),
            (1, 2),
            (2, 3),
            (3, 1),
            (2, 4),
            (4, 5),
            (5, 4),
            (5, 8),
        ]),
    );
    let multi_entry =
        SyntheticGraph::from_edges(7, edges(&[(0, 2), (1, 3), (2, 3), (3, 4), (4, 2), (4, 6)]));
    let disconnected =
        SyntheticGraph::from_edges(10, edges(&[(0, 1), (1, 2), (3, 4), (4, 3), (6, 6), (8, 9)]));
    let exceptional = SyntheticGraph::from_edges(
        8,
        vec![(0, 1, 0), (1, 2, 0), (1, 7, 9), (2, 5, 0), (2, 6, 9)],
    );

    [
        ("deep_chain_100000", chain, 0, chain_nodes - 1),
        ("branch_heavy_20000", branch, 0, 19_999),
        ("reducible_nested_cycles", reducible, 0, 8),
        ("multi_entry_irreducible_cycle", multi_entry, 0, 6),
        ("disconnected_regions_and_self_loop", disconnected, 0, 9),
        ("exceptional_and_multiple_exits", exceptional, 0, 7),
    ]
    .into_iter()
    .map(|(name, graph, start, goal)| {
        let mut dataset = DatasetAccumulator::new(name, "generated", repeats);
        dataset.measure(&graph, start, goal);
        dataset.finish()
    })
    .collect()
}

fn edges(pairs: &[(usize, usize)]) -> Vec<(usize, usize, u8)> {
    pairs
        .iter()
        .enumerate()
        .map(|(label, &(source, target))| (source, target, u8::try_from(label).unwrap()))
        .collect()
}

fn corpus_dataset(
    env_name: &'static str,
    name: &str,
    language: Language,
    expected_commit: &str,
    repeats: usize,
) -> DatasetMeasurement {
    let Some(configured) = std::env::var_os(env_name) else {
        let mut missing = DatasetAccumulator::new(name, "pinned_external_repository", repeats);
        missing.language = Some(language.config_label().to_owned());
        missing.status = format!("unavailable: {env_name} is not configured");
        return missing.finish();
    };
    let root = PathBuf::from(configured)
        .canonicalize()
        .expect("canonicalize configured corpus");
    let commit = command_output(&root, "git", &["rev-parse", "HEAD"]);
    let dirty = command_output(
        &root,
        "git",
        &["status", "--porcelain", "--untracked-files=normal"],
    )
    .map(|status| !status.is_empty());
    assert_eq!(commit.as_deref(), Some(expected_commit));
    assert_eq!(dirty, Some(false));

    let source_project = Arc::new(TestProject::new(root, language));
    let files = source_project
        .analyzable_files(language)
        .expect("enumerate benchmark corpus");
    let project: Arc<dyn Project> = Arc::clone(&source_project) as Arc<dyn Project>;
    let analyzer = WorkspaceAnalyzer::build(
        project,
        AnalyzerConfig {
            parallelism: Some(1),
            ..AnalyzerConfig::default()
        },
    );
    let cancellation = CancellationToken::default();
    let mut dataset = DatasetAccumulator::new(name, "pinned_external_repository", repeats);
    dataset.language = Some(language.config_label().to_owned());
    dataset.repository_commit = commit;
    dataset.repository_dirty = dirty;
    dataset.files_seen = files.len();
    let mut unavailable = 0usize;

    for file in files {
        let mut budget = SemanticBudget::default();
        let outcome = analyzer
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .unwrap_or_else(|error| {
                panic!(
                    "materialize benchmark corpus {}: {error}",
                    file.rel_path().display()
                )
            });
        let SemanticOutcome::Complete { value, .. } = outcome else {
            unavailable += 1;
            continue;
        };
        dataset.files_materialized += 1;
        for procedure in value.procedures() {
            dataset.measure(
                procedure,
                procedure.entry_point(),
                procedure.normal_exit_point(),
            );
        }
    }
    if unavailable > 0 {
        dataset.status = format!("partial: {unavailable} files lacked complete semantics");
    }
    dataset.finish()
}

fn provenance(output: &Path) -> Provenance {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    Provenance {
        bifrost_commit: command_output(root, "git", &["rev-parse", "HEAD"]),
        bifrost_dirty: command_output(
            root,
            "git",
            &["status", "--porcelain", "--untracked-files=normal"],
        )
        .map(|status| !status.is_empty()),
        bifrost_tree_fingerprint: git_tree_fingerprint(root, &[output]),
        rustc_version_verbose: command_output(root, "rustc", &["-Vv"]),
        cargo_version: command_output(root, "cargo", &["-V"]),
        operating_system: std::env::consts::OS,
        architecture: std::env::consts::ARCH,
        build_profile: if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        },
        crate_version: env!("CARGO_PKG_VERSION"),
        timer: "std::time::Instant monotonic elapsed wall time",
        generated_unix_seconds: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock after Unix epoch")
            .as_secs(),
        corpora: [
            CorpusProvenance {
                environment_variable: TS_REPO_ENV,
                expected_commit: VSCODE_COMMIT,
                configured: std::env::var_os(TS_REPO_ENV).is_some(),
            },
            CorpusProvenance {
                environment_variable: JAVA_REPO_ENV,
                expected_commit: SPRING_PETCLINIC_COMMIT,
                configured: std::env::var_os(JAVA_REPO_ENV).is_some(),
            },
        ],
    }
}

fn digest_strings(digests: &[String]) -> String {
    let mut material = Vec::new();
    for digest in digests {
        material.extend_from_slice(&u64::try_from(digest.len()).unwrap().to_le_bytes());
        material.extend_from_slice(digest.as_bytes());
    }
    StableDigest::sha256(material).to_string()
}

const fn bytes(rows: usize, row_size: usize) -> u64 {
    (rows as u64).saturating_mul(row_size as u64)
}

fn milliseconds(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1_000.0
}

#[test]
fn framed_result_digest_distinguishes_field_boundaries() {
    let mut first = Vec::new();
    push_sequence(&mut first, b'e', 3, &[1, 2, 3]);
    push_sequence(&mut first, b'b', 1, &[7]);

    let mut second = Vec::new();
    push_sequence(&mut second, b'e', 2, &[1, 2]);
    push_sequence(&mut second, b'b', 2, &[3, 7]);

    assert_ne!(
        StableDigest::sha256(first),
        StableDigest::sha256(second),
        "field framing must prevent structurally different loop results from colliding"
    );
}

#[test]
#[ignore = "release-only measurement; run scripts/run-cfg-algorithm-benchmarks.sh"]
fn cfg_algorithm_release_measurement() {
    if cfg!(debug_assertions) {
        panic!("CFG algorithm benchmark must run with --release");
    }
    let repeats = std::env::var(REPEATS_ENV)
        .ok()
        .map(|value| value.parse::<usize>().expect("positive benchmark repeats"))
        .unwrap_or(3);
    assert!((1..=MAX_REPEATS).contains(&repeats));
    let output = std::env::var_os(OUTPUT_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join(".agents/docs/issue-819-cfg-algorithm-benchmark-2026-07-24.json")
        });
    let run_provenance = provenance(&output);

    let parent = output
        .parent()
        .expect("benchmark output must have a parent directory");
    let mut temporary_output =
        NamedTempFile::new_in(parent).expect("create benchmark output beside destination");

    let mut datasets = synthetic_datasets(repeats);
    datasets.push(corpus_dataset(
        TS_REPO_ENV,
        "pinned_vscode_typescript",
        Language::TypeScript,
        VSCODE_COMMIT,
        repeats,
    ));
    datasets.push(corpus_dataset(
        JAVA_REPO_ENV,
        "pinned_spring_petclinic_java",
        Language::Java,
        SPRING_PETCLINIC_COMMIT,
        repeats,
    ));
    let report = BenchmarkReport {
        format: "bifrost-cfg-algorithm-benchmark",
        schema_version: 1,
        purpose: "issue-819 on-demand immutable CFG algorithm lifecycle evidence",
        provenance: run_provenance,
        repeats_per_graph: repeats,
        datasets,
    };
    let json = serde_json::to_string_pretty(&report).expect("serialize benchmark report");
    temporary_output
        .write_all(json.as_bytes())
        .expect("write temporary CFG algorithm benchmark");
    temporary_output
        .as_file_mut()
        .sync_all()
        .expect("sync temporary CFG algorithm benchmark");
    temporary_output.persist(&output).unwrap_or_else(|error| {
        panic!(
            "atomically persist CFG algorithm benchmark {}: {}",
            output.display(),
            error.error
        )
    });
    println!("BIFROST_CFG_ALGORITHM_BENCHMARK={}", output.display());
}
