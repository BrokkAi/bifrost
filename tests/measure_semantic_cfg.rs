//! Representation-neutral semantic CFG layout benchmark for issue #815.
//!
//! Run one release-process sample directly with:
//!
//! ```text
//! BIFROST_SEMANTIC_CFG_LAYOUT=bidirectional \
//!   cargo test --release --test measure_semantic_cfg -- --ignored --nocapture
//! ```
//!
//! Use `scripts/run-semantic-cfg-benchmarks.sh layout` for the decision-grade
//! matrix of nine fresh processes per layout. The runner discards two warmups
//! per layout and asks this test to aggregate the seven retained samples.

use std::collections::BTreeMap;
use std::fs;
use std::hint::black_box;
use std::mem::size_of;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Instant;

use brokk_bifrost::analyzer::semantic::{
    CancellationToken, ControlEdgeKind, SemanticBudget, SemanticOutcome, SemanticProviderError,
    SemanticRequest, StableDigest,
};
use brokk_bifrost::{AnalyzerConfig, Language, Project, TestProject, WorkspaceAnalyzer};
use serde::{Deserialize, Serialize};

const RESULT_PREFIX: &str = "BIFROST_SEMANTIC_CFG_BENCHMARK=";
const LAYOUT_ENV: &str = "BIFROST_SEMANTIC_CFG_LAYOUT";
const ROUND_ENV: &str = "BIFROST_SEMANTIC_CFG_BENCH_ROUND";
const SAMPLES_FILE_ENV: &str = "BIFROST_SEMANTIC_CFG_SAMPLES_FILE";
const TS_REPO_ENV: &str = "BIFROST_SEMANTIC_TS_REPO";
const JAVA_REPO_ENV: &str = "BIFROST_SEMANTIC_JAVA_REPO";
const VSCODE_COMMIT: &str = "19e0f9e681ecb8e5c09d8784acaa601316ca4571";
const SPRING_PETCLINIC_COMMIT: &str = "f182358d02e4a68e52bdbabf55ca7800288511e7";
const GENERATED_POINT_COUNTS: [usize; 2] = [10_000, 100_000];

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BenchEdge {
    source: u32,
    target: u32,
    source_mapping: u32,
    evidence: u32,
    kind: ControlEdgeKind,
}

#[derive(Debug, Clone)]
struct ProcedureDataset {
    point_count: usize,
    edges: Vec<BenchEdge>,
}

#[derive(Debug)]
struct Dataset {
    name: String,
    origin: String,
    language: Option<String>,
    repository_commit: Option<String>,
    repository_dirty: Option<bool>,
    files_seen: usize,
    files_materialized: usize,
    procedure_graphs: Vec<ProcedureDataset>,
    semantic_materialization_ms: Option<f64>,
    semantic_repeat_materialization_ms: Option<f64>,
    status: String,
}

#[derive(Debug)]
struct CompactRows {
    offsets: Box<[u32]>,
    edge_ids: Box<[u32]>,
}

#[derive(Debug)]
enum FrozenLayout {
    Flat {
        edges: Box<[BenchEdge]>,
    },
    Outgoing {
        edges: Box<[BenchEdge]>,
        outgoing_offsets: Box<[u32]>,
    },
    Bidirectional {
        edges: Box<[BenchEdge]>,
        outgoing_offsets: Box<[u32]>,
        incoming: CompactRows,
    },
}

#[derive(Debug)]
struct FrozenProcedure {
    point_count: usize,
    layout: FrozenLayout,
}

#[derive(Debug)]
struct FrozenDataset {
    procedures: Vec<FrozenProcedure>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Layout {
    Flat,
    Outgoing,
    Bidirectional,
}

impl Layout {
    fn from_env() -> Self {
        match std::env::var(LAYOUT_ENV).as_deref() {
            Ok("flat") => Self::Flat,
            Ok("outgoing") => Self::Outgoing,
            Ok("bidirectional") => Self::Bidirectional,
            Ok(other) => {
                panic!("{LAYOUT_ENV} must be flat, outgoing, or bidirectional; got {other:?}")
            }
            Err(_) => Self::Bidirectional,
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Flat => "flat",
            Self::Outgoing => "outgoing",
            Self::Bidirectional => "bidirectional",
        }
    }

    const fn contract(self) -> LayoutContract {
        match self {
            Self::Flat => LayoutContract {
                predecessor_index_retained: false,
                full_forward_strategy: "scan the canonical edge table for every successor point",
                full_reverse_strategy: "scan the canonical edge table for every predecessor point",
                successor_query_complexity: "O(E) per point; O(VE) for a full forward traversal",
                predecessor_query_complexity: "O(E) per point; O(VE) for a full reverse traversal",
                retained_slice_owners_per_cfg: 1,
                retained_bytes_accounting: "payload plus one Box<[T]> fat-pointer owner per retained slice per procedure; allocator-private metadata excluded",
                promotion_eligible: false,
            },
            Self::Outgoing => LayoutContract {
                predecessor_index_retained: false,
                full_forward_strategy: "retained outgoing CSR rows",
                full_reverse_strategy: "scan the canonical edge table for every predecessor point",
                successor_query_complexity: "O(outdegree) per point; O(V+E) for a full forward traversal",
                predecessor_query_complexity: "O(E) per point; O(VE) for a full reverse traversal",
                retained_slice_owners_per_cfg: 2,
                retained_bytes_accounting: "payload plus one Box<[T]> fat-pointer owner per retained slice per procedure; allocator-private metadata excluded",
                promotion_eligible: true,
            },
            Self::Bidirectional => LayoutContract {
                predecessor_index_retained: true,
                full_forward_strategy: "retained outgoing CSR rows",
                full_reverse_strategy: "retained incoming edge-ID rows",
                successor_query_complexity: "O(outdegree) per point; O(V+E) for a full forward traversal",
                predecessor_query_complexity: "O(indegree) per point; O(V+E) for a full reverse traversal",
                retained_slice_owners_per_cfg: 4,
                retained_bytes_accounting: "payload plus one Box<[T]> fat-pointer owner per retained slice per procedure; allocator-private metadata excluded",
                promotion_eligible: true,
            },
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
struct LayoutContract {
    predecessor_index_retained: bool,
    full_forward_strategy: &'static str,
    full_reverse_strategy: &'static str,
    successor_query_complexity: &'static str,
    predecessor_query_complexity: &'static str,
    retained_slice_owners_per_cfg: usize,
    retained_bytes_accounting: &'static str,
    promotion_eligible: bool,
}

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
    pointer_width_bits: usize,
    endianness: String,
    crate_version: String,
    timer: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RetainedMemoryEstimate {
    edge_payload_bytes: u64,
    outgoing_offsets_bytes: u64,
    incoming_offsets_bytes: u64,
    incoming_edge_ids_bytes: u64,
    cfg_slice_owner_header_bytes: u64,
    retained_slice_owners: usize,
    outgoing_offset_entries: usize,
    incoming_offset_entries: usize,
    incoming_edge_id_entries: usize,
    total_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DatasetMeasurement {
    name: String,
    origin: String,
    language: Option<String>,
    repository_commit: Option<String>,
    repository_dirty: Option<bool>,
    status: String,
    files_seen: usize,
    files_materialized: usize,
    procedures: usize,
    points: usize,
    edges: usize,
    procedure_row_boundaries: usize,
    semantic_materialization_ms: Option<f64>,
    semantic_repeat_materialization_ms: Option<f64>,
    construction_freeze_ms: Option<f64>,
    full_forward_traversal_ms: Option<f64>,
    full_reverse_traversal_ms: Option<f64>,
    forward_traversal_iterations: usize,
    reverse_traversal_iterations: usize,
    retained_memory: Option<RetainedMemoryEstimate>,
    estimated_retained_bytes: Option<u64>,
    checksum: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SampleResult {
    format: String,
    kind: String,
    provenance: BenchmarkProvenance,
    round: usize,
    layout: String,
    layout_contract: LayoutContractOwned,
    datasets: Vec<DatasetMeasurement>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct LayoutContractOwned {
    predecessor_index_retained: bool,
    full_forward_strategy: String,
    full_reverse_strategy: String,
    successor_query_complexity: String,
    predecessor_query_complexity: String,
    retained_slice_owners_per_cfg: usize,
    retained_bytes_accounting: String,
    promotion_eligible: bool,
}

impl From<LayoutContract> for LayoutContractOwned {
    fn from(value: LayoutContract) -> Self {
        Self {
            predecessor_index_retained: value.predecessor_index_retained,
            full_forward_strategy: value.full_forward_strategy.to_owned(),
            full_reverse_strategy: value.full_reverse_strategy.to_owned(),
            successor_query_complexity: value.successor_query_complexity.to_owned(),
            predecessor_query_complexity: value.predecessor_query_complexity.to_owned(),
            retained_slice_owners_per_cfg: value.retained_slice_owners_per_cfg,
            retained_bytes_accounting: value.retained_bytes_accounting.to_owned(),
            promotion_eligible: value.promotion_eligible,
        }
    }
}

#[derive(Debug, Serialize)]
struct AggregateResult {
    format: &'static str,
    kind: &'static str,
    aggregation_provenance: BenchmarkProvenance,
    sample_provenance: BenchmarkProvenance,
    dataset_provenance: BTreeMap<String, DatasetRepositoryProvenance>,
    fresh_processes_per_layout: usize,
    discarded_warmups_per_layout: usize,
    retained_samples_per_layout: usize,
    raw_samples: BTreeMap<String, Vec<SampleResult>>,
    medians: Vec<MedianMeasurement>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct DatasetRepositoryProvenance {
    origin: String,
    repository_commit: Option<String>,
    repository_dirty: Option<bool>,
}

#[derive(Debug, Serialize)]
struct MedianMeasurement {
    layout: String,
    dataset: String,
    status: String,
    procedures: usize,
    points: usize,
    edges: usize,
    procedure_row_boundaries: usize,
    semantic_materialization_ms: Option<f64>,
    semantic_repeat_materialization_ms: Option<f64>,
    construction_freeze_ms: Option<f64>,
    full_forward_traversal_ms: Option<f64>,
    full_reverse_traversal_ms: Option<f64>,
    edge_payload_bytes: Option<u64>,
    cfg_slice_owner_header_bytes: Option<u64>,
    estimated_retained_bytes: Option<u64>,
}

fn edge_sort_key(edge: &BenchEdge) -> (u32, &'static str, u32, u32, u32) {
    (
        edge.source,
        edge.kind.label(),
        edge.target,
        edge.source_mapping,
        edge.evidence,
    )
}

fn outgoing_offsets(edges: &[BenchEdge], point_count: usize) -> Vec<u32> {
    let row_boundaries = point_count
        .checked_add(1)
        .expect("benchmark row-boundary count must fit usize");
    let mut offsets = Vec::with_capacity(row_boundaries);
    offsets.push(0);
    let mut edge = 0usize;
    for point in 0..point_count {
        while edge < edges.len() && edges[edge].source as usize == point {
            edge += 1;
        }
        offsets.push(u32::try_from(edge).expect("benchmark edge count must fit u32"));
    }
    assert_eq!(edge, edges.len(), "all benchmark edges need a source row");
    offsets
}

fn compact_rows(
    edges: &[BenchEdge],
    point_count: usize,
    key: impl Fn(&BenchEdge) -> u32,
) -> CompactRows {
    let mut counts = vec![0u32; point_count];
    for edge in edges {
        let point = key(edge) as usize;
        counts[point] = counts[point]
            .checked_add(1)
            .expect("benchmark row count must fit u32");
    }
    let row_boundaries = point_count
        .checked_add(1)
        .expect("benchmark row-boundary count must fit usize");
    let mut offsets = Vec::with_capacity(row_boundaries);
    offsets.push(0u32);
    for count in counts {
        offsets.push(
            offsets
                .last()
                .copied()
                .expect("offset zero exists")
                .checked_add(count)
                .expect("benchmark edge count must fit u32"),
        );
    }
    let mut cursors = offsets[..point_count].to_vec();
    let mut edge_ids = vec![0u32; edges.len()];
    for (edge_id, edge) in edges.iter().enumerate() {
        let point = key(edge) as usize;
        let destination = cursors[point] as usize;
        edge_ids[destination] = u32::try_from(edge_id).expect("benchmark edge ID must fit u32");
        cursors[point] += 1;
    }
    CompactRows {
        offsets: offsets.into_boxed_slice(),
        edge_ids: edge_ids.into_boxed_slice(),
    }
}

fn freeze(layout: Layout, point_count: usize, mut edges: Vec<BenchEdge>) -> FrozenLayout {
    edges.sort_unstable_by_key(edge_sort_key);
    assert!(
        !edges
            .windows(2)
            .any(|pair| edge_sort_key(&pair[0]) == edge_sort_key(&pair[1])),
        "benchmark inputs must obey the production rich-edge uniqueness contract"
    );
    match layout {
        Layout::Flat => FrozenLayout::Flat {
            edges: edges.into_boxed_slice(),
        },
        Layout::Outgoing => FrozenLayout::Outgoing {
            outgoing_offsets: outgoing_offsets(&edges, point_count).into_boxed_slice(),
            edges: edges.into_boxed_slice(),
        },
        Layout::Bidirectional => FrozenLayout::Bidirectional {
            outgoing_offsets: outgoing_offsets(&edges, point_count).into_boxed_slice(),
            incoming: compact_rows(&edges, point_count, |edge| edge.target),
            edges: edges.into_boxed_slice(),
        },
    }
}

fn mix(checksum: u64, edge: &BenchEdge, reverse: bool) -> u64 {
    let (left, right) = if reverse {
        (edge.target, edge.source)
    } else {
        (edge.source, edge.target)
    };
    checksum
        .rotate_left(7)
        .wrapping_add(u64::from(left) << 32 | u64::from(right))
        .wrapping_mul(0x9e37_79b1_85eb_ca87)
        .wrapping_add(edge.kind as u64)
        .rotate_left(11)
        .wrapping_add(u64::from(edge.source_mapping))
        .wrapping_mul(0xc2b2_ae3d_27d4_eb4f)
        .wrapping_add(u64::from(edge.evidence))
}

fn visit_id_rows(
    edges: &[BenchEdge],
    rows: &CompactRows,
    point_count: usize,
    reverse: bool,
) -> u64 {
    let mut checksum = 0u64;
    for point in 0..point_count {
        let start = rows.offsets[point] as usize;
        let end = rows.offsets[point + 1] as usize;
        for edge_id in &rows.edge_ids[start..end] {
            checksum = mix(checksum, &edges[*edge_id as usize], reverse);
        }
    }
    checksum
}

fn visit_contiguous_rows(edges: &[BenchEdge], offsets: &[u32], point_count: usize) -> u64 {
    let mut checksum = 0u64;
    for point in 0..point_count {
        let start = offsets[point] as usize;
        let end = offsets[point + 1] as usize;
        for edge in &edges[start..end] {
            checksum = mix(checksum, edge, false);
        }
    }
    checksum
}

fn visit_pointwise_scans(
    edges: &[BenchEdge],
    point_count: usize,
    key: impl Fn(&BenchEdge) -> u32,
    reverse: bool,
) -> u64 {
    let mut checksum = 0u64;
    for point in 0..point_count {
        for edge in edges {
            if key(edge) as usize == point {
                checksum = mix(checksum, edge, reverse);
            }
        }
    }
    checksum
}

impl FrozenLayout {
    fn full_forward(&self, point_count: usize) -> u64 {
        match self {
            Self::Flat { edges } => {
                visit_pointwise_scans(edges, point_count, |edge| edge.source, false)
            }
            Self::Outgoing {
                edges,
                outgoing_offsets,
            }
            | Self::Bidirectional {
                edges,
                outgoing_offsets,
                ..
            } => visit_contiguous_rows(edges, outgoing_offsets, point_count),
        }
    }

    fn full_reverse(&self, point_count: usize) -> u64 {
        match self {
            Self::Flat { edges } | Self::Outgoing { edges, .. } => {
                visit_pointwise_scans(edges, point_count, |edge| edge.target, true)
            }
            Self::Bidirectional {
                edges, incoming, ..
            } => visit_id_rows(edges, incoming, point_count, true),
        }
    }

    fn retained_memory(&self) -> RetainedMemoryEstimate {
        let edge_bytes = |edges: &[BenchEdge]| {
            u64::try_from(edges.len().saturating_mul(size_of::<BenchEdge>()))
                .expect("benchmark retained edge bytes must fit u64")
        };
        let u32_bytes = |length: usize| {
            u64::try_from(length.saturating_mul(size_of::<u32>()))
                .expect("benchmark retained row bytes must fit u64")
        };
        let slice_owner_bytes =
            u64::try_from(size_of::<Box<[u8]>>()).expect("boxed-slice owner size must fit u64");
        let (
            edge_payload_bytes,
            outgoing_offsets_bytes,
            incoming_offsets_bytes,
            incoming_edge_ids_bytes,
            retained_slice_owners,
            outgoing_offset_entries,
            incoming_offset_entries,
            incoming_edge_id_entries,
        ) = match self {
            Self::Flat { edges } => (edge_bytes(edges), 0, 0, 0, 1, 0, 0, 0),
            Self::Outgoing {
                edges,
                outgoing_offsets,
            } => (
                edge_bytes(edges),
                u32_bytes(outgoing_offsets.len()),
                0,
                0,
                2,
                outgoing_offsets.len(),
                0,
                0,
            ),
            Self::Bidirectional {
                edges,
                outgoing_offsets,
                incoming,
            } => (
                edge_bytes(edges),
                u32_bytes(outgoing_offsets.len()),
                u32_bytes(incoming.offsets.len()),
                u32_bytes(incoming.edge_ids.len()),
                4,
                outgoing_offsets.len(),
                incoming.offsets.len(),
                incoming.edge_ids.len(),
            ),
        };
        let cfg_slice_owner_header_bytes = slice_owner_bytes
            .checked_mul(
                u64::try_from(retained_slice_owners).expect("slice owner count must fit u64"),
            )
            .expect("slice owner bytes must fit u64");
        let total_bytes = edge_payload_bytes
            .checked_add(outgoing_offsets_bytes)
            .and_then(|value| value.checked_add(incoming_offsets_bytes))
            .and_then(|value| value.checked_add(incoming_edge_ids_bytes))
            .and_then(|value| value.checked_add(cfg_slice_owner_header_bytes))
            .expect("retained CFG bytes must fit u64");
        RetainedMemoryEstimate {
            edge_payload_bytes,
            outgoing_offsets_bytes,
            incoming_offsets_bytes,
            incoming_edge_ids_bytes,
            cfg_slice_owner_header_bytes,
            retained_slice_owners,
            outgoing_offset_entries,
            incoming_offset_entries,
            incoming_edge_id_entries,
            total_bytes,
        }
    }
}

impl RetainedMemoryEstimate {
    const fn zero() -> Self {
        Self {
            edge_payload_bytes: 0,
            outgoing_offsets_bytes: 0,
            incoming_offsets_bytes: 0,
            incoming_edge_ids_bytes: 0,
            cfg_slice_owner_header_bytes: 0,
            retained_slice_owners: 0,
            outgoing_offset_entries: 0,
            incoming_offset_entries: 0,
            incoming_edge_id_entries: 0,
            total_bytes: 0,
        }
    }

    fn add_assign(&mut self, other: &Self) {
        let add_u64 = |left: u64, right: u64| {
            left.checked_add(right)
                .expect("aggregate retained CFG bytes must fit u64")
        };
        let add_usize = |left: usize, right: usize| {
            left.checked_add(right)
                .expect("aggregate retained CFG entries must fit usize")
        };
        self.edge_payload_bytes = add_u64(self.edge_payload_bytes, other.edge_payload_bytes);
        self.outgoing_offsets_bytes = self
            .outgoing_offsets_bytes
            .checked_add(other.outgoing_offsets_bytes)
            .expect("aggregate outgoing-offset bytes must fit u64");
        self.incoming_offsets_bytes = self
            .incoming_offsets_bytes
            .checked_add(other.incoming_offsets_bytes)
            .expect("aggregate incoming-offset bytes must fit u64");
        self.incoming_edge_ids_bytes = self
            .incoming_edge_ids_bytes
            .checked_add(other.incoming_edge_ids_bytes)
            .expect("aggregate incoming-edge-ID bytes must fit u64");
        self.cfg_slice_owner_header_bytes = self
            .cfg_slice_owner_header_bytes
            .checked_add(other.cfg_slice_owner_header_bytes)
            .expect("aggregate slice-owner bytes must fit u64");
        self.retained_slice_owners =
            add_usize(self.retained_slice_owners, other.retained_slice_owners);
        self.outgoing_offset_entries =
            add_usize(self.outgoing_offset_entries, other.outgoing_offset_entries);
        self.incoming_offset_entries =
            add_usize(self.incoming_offset_entries, other.incoming_offset_entries);
        self.incoming_edge_id_entries = add_usize(
            self.incoming_edge_id_entries,
            other.incoming_edge_id_entries,
        );
        self.total_bytes = add_u64(self.total_bytes, other.total_bytes);
    }
}

fn procedure_counts(procedures: &[ProcedureDataset]) -> (usize, usize, usize) {
    procedures.iter().fold(
        (0usize, 0usize, 0usize),
        |(points, edges, row_boundaries), procedure| {
            let procedure_boundaries = procedure
                .point_count
                .checked_add(1)
                .expect("procedure row-boundary count must fit usize");
            (
                points
                    .checked_add(procedure.point_count)
                    .expect("dataset point count must fit usize"),
                edges
                    .checked_add(procedure.edges.len())
                    .expect("dataset edge count must fit usize"),
                row_boundaries
                    .checked_add(procedure_boundaries)
                    .expect("dataset row-boundary count must fit usize"),
            )
        },
    )
}

impl FrozenDataset {
    fn full_forward(&self) -> u64 {
        self.procedures
            .iter()
            .enumerate()
            .fold(0u64, |checksum, (index, procedure)| {
                combine_procedure_checksum(
                    checksum,
                    index,
                    procedure.point_count,
                    procedure.layout.full_forward(procedure.point_count),
                )
            })
    }

    fn full_reverse(&self) -> u64 {
        self.procedures
            .iter()
            .enumerate()
            .fold(0u64, |checksum, (index, procedure)| {
                combine_procedure_checksum(
                    checksum,
                    index,
                    procedure.point_count,
                    procedure.layout.full_reverse(procedure.point_count),
                )
            })
    }

    fn retained_memory(&self) -> RetainedMemoryEstimate {
        let mut total = RetainedMemoryEstimate::zero();
        for procedure in &self.procedures {
            total.add_assign(&procedure.layout.retained_memory());
        }
        total
    }
}

fn combine_procedure_checksum(
    checksum: u64,
    procedure_index: usize,
    point_count: usize,
    procedure_checksum: u64,
) -> u64 {
    checksum
        .rotate_left(17)
        .wrapping_add(u64::try_from(procedure_index).expect("procedure index must fit u64"))
        .wrapping_mul(0x1656_6791_9e37_79f9)
        .wrapping_add(u64::try_from(point_count).expect("point count must fit u64"))
        .wrapping_add(procedure_checksum.rotate_left(23))
}

fn freeze_dataset(layout: Layout, procedures: Vec<ProcedureDataset>) -> FrozenDataset {
    FrozenDataset {
        procedures: procedures
            .into_iter()
            .map(|procedure| FrozenProcedure {
                point_count: procedure.point_count,
                layout: freeze(layout, procedure.point_count, procedure.edges),
            })
            .collect(),
    }
}

fn generated_branch_heavy(point_count: usize) -> Dataset {
    let mut edges = Vec::with_capacity(point_count.saturating_mul(2));
    for source in 0..point_count.saturating_sub(1) {
        edges.push(bench_edge(source, source + 1, ControlEdgeKind::Normal));
        if source % 3 == 0 && source + 2 < point_count {
            edges.push(bench_edge(
                source,
                source + 2,
                ControlEdgeKind::ConditionalTrue,
            ));
            edges.push(bench_edge(
                source,
                source + 1,
                ControlEdgeKind::ConditionalFalse,
            ));
        }
        if source >= 8 && source % 17 == 0 {
            edges.push(bench_edge(source, source - 7, ControlEdgeKind::LoopBack));
        }
    }
    Dataset {
        name: format!("generated_branch_heavy_{point_count}"),
        origin: "generated".to_owned(),
        language: None,
        repository_commit: None,
        repository_dirty: None,
        files_seen: 0,
        files_materialized: 0,
        procedure_graphs: vec![ProcedureDataset { point_count, edges }],
        semantic_materialization_ms: None,
        semantic_repeat_materialization_ms: None,
        status: "complete".to_owned(),
    }
}

fn generated_call_heavy(point_count: usize) -> Dataset {
    let mut edges = Vec::with_capacity(point_count.saturating_mul(2));
    let exceptional_exit = point_count.saturating_sub(1);
    for source in 0..point_count.saturating_sub(1) {
        edges.push(bench_edge(source, source + 1, ControlEdgeKind::Normal));
        if source % 4 == 0 {
            edges.push(bench_edge(
                source,
                exceptional_exit,
                ControlEdgeKind::Exceptional,
            ));
        }
        if source % 11 == 0 && source + 3 < point_count {
            edges.push(bench_edge(source, source + 3, ControlEdgeKind::Normal));
        }
    }
    Dataset {
        name: format!("generated_call_heavy_{point_count}"),
        origin: "generated".to_owned(),
        language: None,
        repository_commit: None,
        repository_dirty: None,
        files_seen: 0,
        files_materialized: 0,
        procedure_graphs: vec![ProcedureDataset { point_count, edges }],
        semantic_materialization_ms: None,
        semantic_repeat_materialization_ms: None,
        status: "complete".to_owned(),
    }
}

fn bench_edge(source: usize, target: usize, kind: ControlEdgeKind) -> BenchEdge {
    BenchEdge {
        source: u32::try_from(source).expect("generated point must fit u32"),
        target: u32::try_from(target).expect("generated point must fit u32"),
        source_mapping: u32::try_from(source % 4_096).expect("mapping must fit u32"),
        evidence: u32::try_from(source % 1_024).expect("evidence must fit u32"),
        kind,
    }
}

fn corpus_dataset(
    name: &str,
    root: &Path,
    language: Language,
    origin: &str,
    expected_commit: Option<&str>,
) -> Dataset {
    let root = root
        .canonicalize()
        .unwrap_or_else(|error| panic!("canonicalize corpus {}: {error}", root.display()));
    let repository_commit = git_commit(&root);
    let repository_dirty = git_dirty(&root);
    if let Some(expected) = expected_commit {
        assert_eq!(
            repository_commit.as_deref(),
            Some(expected),
            "corpus {} must be checked out at the predeclared commit",
            root.display()
        );
        assert_eq!(
            repository_dirty,
            Some(false),
            "pinned external corpus {} must have a clean worktree",
            root.display()
        );
    }
    let source_project = Arc::new(TestProject::new(root, language));
    let files = source_project
        .analyzable_files(language)
        .expect("list semantic CFG corpus files");
    let files_seen = files.len();
    let project: Arc<dyn Project> = Arc::clone(&source_project) as Arc<dyn Project>;
    let analyzer = WorkspaceAnalyzer::build(
        project,
        AnalyzerConfig {
            parallelism: Some(1),
            ..AnalyzerConfig::default()
        },
    );
    let cancellation = CancellationToken::default();
    let started = Instant::now();
    let mut procedure_graphs = Vec::new();
    let mut files_materialized = 0usize;
    let mut materialized_files = Vec::new();
    let mut unavailable = Vec::new();
    for file in &files {
        let mut budget = SemanticBudget::default();
        let outcome = match analyzer.materialize_program_semantics(
            file,
            &mut SemanticRequest::new(&mut budget, &cancellation),
        ) {
            Ok(outcome) => outcome,
            Err(SemanticProviderError::SourceAccess(detail)) => {
                source_project.read_source(file).unwrap_or_else(|error| {
                    panic!(
                        "benchmark corpus source {} became unreadable after enumeration: {error}",
                        file.rel_path().display()
                    )
                });
                unavailable.push(format!(
                    "{}:parse-safety:{}",
                    file.rel_path().display(),
                    detail
                ));
                continue;
            }
            Err(error) => {
                panic!(
                    "materialize benchmark corpus {}: {error}",
                    file.rel_path().display()
                )
            }
        };
        let artifact = match outcome {
            SemanticOutcome::Complete { value, .. } => value,
            SemanticOutcome::Unsupported { capability, .. } => {
                unavailable.push(format!(
                    "{}:unsupported:{}",
                    file.rel_path().display(),
                    capability.label()
                ));
                continue;
            }
            SemanticOutcome::Ambiguous { .. } => {
                unavailable.push(format!("{}:ambiguous", file.rel_path().display()));
                continue;
            }
            SemanticOutcome::Unknown { .. } => {
                unavailable.push(format!("{}:unknown", file.rel_path().display()));
                continue;
            }
            SemanticOutcome::Unproven { .. } => {
                unavailable.push(format!("{}:unproven", file.rel_path().display()));
                continue;
            }
            SemanticOutcome::ExceededBudget { exceeded, .. } => {
                unavailable.push(format!(
                    "{}:budget:{}",
                    file.rel_path().display(),
                    exceeded.dimension().label()
                ));
                continue;
            }
            SemanticOutcome::Cancelled { .. } => panic!("benchmark cancellation was not requested"),
        };
        files_materialized += 1;
        materialized_files.push(file.clone());
        for procedure in artifact.procedures() {
            let edges = procedure
                .cfg()
                .edges()
                .iter()
                .map(|edge| BenchEdge {
                    source: edge.source_point.get(),
                    target: edge.target_point.get(),
                    source_mapping: edge.source.get(),
                    evidence: edge.evidence.get(),
                    kind: edge.kind,
                })
                .collect();
            procedure_graphs.push(ProcedureDataset {
                point_count: procedure.points().len(),
                edges,
            });
        }
    }
    let semantic_materialization_ms = started.elapsed().as_secs_f64() * 1_000.0;
    let repeat_started = Instant::now();
    let mut repeat_materialized = 0usize;
    for file in &materialized_files {
        let mut budget = SemanticBudget::default();
        let outcome = analyzer
            .materialize_program_semantics(
                file,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .unwrap_or_else(|error| {
                panic!(
                    "repeat benchmark corpus materialization {}: {error}",
                    file.rel_path().display()
                )
            });
        if matches!(outcome, SemanticOutcome::Complete { .. }) {
            repeat_materialized += 1;
        }
        black_box(outcome);
    }
    assert_eq!(
        repeat_materialized,
        materialized_files.len(),
        "repeated materialization must preserve the completed-file count"
    );
    let semantic_repeat_materialization_ms = repeat_started.elapsed().as_secs_f64() * 1_000.0;
    let unavailable_summary = || {
        let examples = unavailable
            .iter()
            .take(5)
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join(", ");
        if unavailable.len() <= 5 {
            examples
        } else {
            format!("{examples}, ... ({} more)", unavailable.len() - 5)
        }
    };
    let status = if unavailable.is_empty() {
        "complete".to_owned()
    } else if files_materialized == 0 {
        format!(
            "unavailable ({} files): {}",
            unavailable.len(),
            unavailable_summary()
        )
    } else {
        format!(
            "partial ({} files): {}",
            unavailable.len(),
            unavailable_summary()
        )
    };
    Dataset {
        name: name.to_owned(),
        origin: origin.to_owned(),
        language: Some(language.config_label().to_owned()),
        repository_commit,
        repository_dirty,
        files_seen,
        files_materialized,
        procedure_graphs,
        semantic_materialization_ms: Some(semantic_materialization_ms),
        semantic_repeat_materialization_ms: Some(semantic_repeat_materialization_ms),
        status,
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

fn checked_in_corpus(name: &str, relative: &str, language: Language) -> Dataset {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join(relative);
    corpus_dataset(name, &root, language, "checked_in_fixture", None)
}

fn external_corpus(
    env_name: &str,
    name: &str,
    language: Language,
    expected_commit: &str,
) -> Option<Dataset> {
    let root = std::env::var_os(env_name).map(PathBuf::from)?;
    Some(corpus_dataset(
        name,
        &root,
        language,
        "pinned_external_repository",
        Some(expected_commit),
    ))
}

fn datasets() -> Vec<Dataset> {
    let mut datasets = Vec::new();
    for point_count in GENERATED_POINT_COUNTS {
        datasets.push(generated_branch_heavy(point_count));
        datasets.push(generated_call_heavy(point_count));
    }
    datasets.push(checked_in_corpus(
        "fixture_typescript",
        "tests/fixtures/testcode-ts",
        Language::TypeScript,
    ));
    datasets.push(checked_in_corpus(
        "fixture_java",
        "tests/fixtures/testcode-java",
        Language::Java,
    ));
    if let Some(dataset) = external_corpus(
        TS_REPO_ENV,
        "external_vscode_typescript",
        Language::TypeScript,
        VSCODE_COMMIT,
    ) {
        datasets.push(dataset);
    }
    if let Some(dataset) = external_corpus(
        JAVA_REPO_ENV,
        "external_spring_petclinic_java",
        Language::Java,
        SPRING_PETCLINIC_COMMIT,
    ) {
        datasets.push(dataset);
    }
    datasets
}

fn indexed_traversal_iterations(point_count: usize) -> usize {
    match point_count {
        0 => 0,
        1..=5_000 => 101,
        5_001..=20_000 => 21,
        _ => 5,
    }
}

fn measure_dataset(layout: Layout, dataset: Dataset) -> DatasetMeasurement {
    let Dataset {
        name,
        origin,
        language,
        repository_commit,
        repository_dirty,
        files_seen,
        files_materialized,
        procedure_graphs,
        semantic_materialization_ms,
        semantic_repeat_materialization_ms,
        status,
    } = dataset;
    let procedures = procedure_graphs.len();
    let (point_count, edge_count, procedure_row_boundaries) = procedure_counts(&procedure_graphs);
    if procedures == 0 {
        return DatasetMeasurement {
            name,
            origin,
            language,
            repository_commit,
            repository_dirty,
            status,
            files_seen,
            files_materialized,
            procedures,
            points: point_count,
            edges: edge_count,
            procedure_row_boundaries,
            semantic_materialization_ms,
            semantic_repeat_materialization_ms,
            construction_freeze_ms: None,
            full_forward_traversal_ms: None,
            full_reverse_traversal_ms: None,
            forward_traversal_iterations: 0,
            reverse_traversal_iterations: 0,
            retained_memory: None,
            estimated_retained_bytes: None,
            checksum: None,
        };
    }
    let construction_started = Instant::now();
    let frozen = freeze_dataset(layout, procedure_graphs);
    let construction_freeze_ms = construction_started.elapsed().as_secs_f64() * 1_000.0;
    let indexed_iterations = indexed_traversal_iterations(point_count).max(1);
    let forward_iterations = if layout == Layout::Flat {
        1
    } else {
        indexed_iterations
    };
    let reverse_iterations = if layout == Layout::Bidirectional {
        indexed_iterations
    } else {
        1
    };

    let forward_started = Instant::now();
    let mut forward_checksum = 0u64;
    let mut topology_forward_checksum = None;
    for iteration in 0..forward_iterations {
        let iteration_checksum = black_box(frozen.full_forward());
        topology_forward_checksum.get_or_insert(iteration_checksum);
        forward_checksum = forward_checksum.wrapping_add(
            iteration_checksum
                .rotate_left(u32::try_from(iteration % 64).expect("rotation fits u32")),
        );
    }
    let full_forward_traversal_ms =
        forward_started.elapsed().as_secs_f64() * 1_000.0 / forward_iterations as f64;

    let reverse_started = Instant::now();
    let mut reverse_checksum = 0u64;
    let mut topology_reverse_checksum = None;
    for iteration in 0..reverse_iterations {
        let iteration_checksum = black_box(frozen.full_reverse());
        topology_reverse_checksum.get_or_insert(iteration_checksum);
        reverse_checksum = reverse_checksum.wrapping_add(
            iteration_checksum
                .rotate_left(u32::try_from(iteration % 64).expect("rotation fits u32")),
        );
    }
    let full_reverse_traversal_ms =
        reverse_started.elapsed().as_secs_f64() * 1_000.0 / reverse_iterations as f64;
    let checksum = topology_forward_checksum.expect("at least one forward traversal")
        ^ topology_reverse_checksum
            .expect("at least one reverse traversal")
            .rotate_left(13);
    black_box(checksum);
    black_box(forward_checksum ^ reverse_checksum.rotate_left(13));
    let retained_memory = frozen.retained_memory();
    assert_eq!(
        retained_memory.outgoing_offset_entries,
        match layout {
            Layout::Flat => 0,
            Layout::Outgoing | Layout::Bidirectional => procedure_row_boundaries,
        },
        "outgoing row storage must charge sum(V_i + 1)"
    );
    assert_eq!(
        retained_memory.incoming_offset_entries,
        if layout == Layout::Bidirectional {
            procedure_row_boundaries
        } else {
            0
        },
        "incoming row storage must charge sum(V_i + 1)"
    );

    DatasetMeasurement {
        name,
        origin,
        language,
        repository_commit,
        repository_dirty,
        status,
        files_seen,
        files_materialized,
        procedures,
        points: point_count,
        edges: edge_count,
        procedure_row_boundaries,
        semantic_materialization_ms,
        semantic_repeat_materialization_ms,
        construction_freeze_ms: Some(construction_freeze_ms),
        full_forward_traversal_ms: Some(full_forward_traversal_ms),
        full_reverse_traversal_ms: Some(full_reverse_traversal_ms),
        forward_traversal_iterations: forward_iterations,
        reverse_traversal_iterations: reverse_iterations,
        estimated_retained_bytes: Some(retained_memory.total_bytes),
        retained_memory: Some(retained_memory),
        checksum: Some(checksum),
    }
}

fn positive_round() -> usize {
    std::env::var(ROUND_ENV)
        .ok()
        .map(|raw| {
            raw.parse::<usize>()
                .unwrap_or_else(|_| panic!("{ROUND_ENV} must be a non-negative integer"))
        })
        .unwrap_or(0)
}

fn sample() -> SampleResult {
    let layout = Layout::from_env();
    let provenance = benchmark_provenance();
    assert!(
        provenance.bifrost_tree_fingerprint.is_some(),
        "decision-grade layout samples require an exact Bifrost tree fingerprint"
    );
    let datasets = datasets()
        .into_iter()
        .map(|dataset| measure_dataset(layout, dataset))
        .collect();
    SampleResult {
        format: "bifrost_semantic_cfg_benchmark/v4".to_owned(),
        kind: "sample".to_owned(),
        provenance,
        round: positive_round(),
        layout: layout.label().to_owned(),
        layout_contract: layout.contract().into(),
        datasets,
    }
}

fn median_f64(mut values: Vec<f64>) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    values.sort_by(f64::total_cmp);
    Some(values[values.len() / 2])
}

fn median_u64(mut values: Vec<u64>) -> Option<u64> {
    if values.is_empty() {
        return None;
    }
    values.sort_unstable();
    Some(values[values.len() / 2])
}

fn assert_dataset_topology_matches(
    reference: &DatasetMeasurement,
    candidate: &DatasetMeasurement,
    context: &str,
) {
    assert_eq!(
        candidate.name, reference.name,
        "dataset name drift: {context}"
    );
    assert_eq!(
        candidate.origin, reference.origin,
        "origin drift: {context}"
    );
    assert_eq!(
        candidate.language, reference.language,
        "language drift: {context}"
    );
    assert_eq!(
        candidate.repository_commit, reference.repository_commit,
        "repository commit drift: {context}"
    );
    assert_eq!(
        candidate.repository_dirty, reference.repository_dirty,
        "repository dirty-state drift: {context}"
    );
    assert_eq!(
        candidate.status, reference.status,
        "status drift: {context}"
    );
    assert_eq!(
        candidate.files_seen, reference.files_seen,
        "file-count drift: {context}"
    );
    assert_eq!(
        candidate.files_materialized, reference.files_materialized,
        "materialized-file drift: {context}"
    );
    assert_eq!(
        candidate.procedures, reference.procedures,
        "procedure-count drift: {context}"
    );
    assert_eq!(
        candidate.points, reference.points,
        "point-count drift: {context}"
    );
    assert_eq!(
        candidate.edges, reference.edges,
        "edge-count drift: {context}"
    );
    assert_eq!(
        candidate.procedure_row_boundaries, reference.procedure_row_boundaries,
        "per-procedure row-boundary drift: {context}"
    );
    assert_eq!(
        candidate.checksum, reference.checksum,
        "rich-topology checksum drift: {context}"
    );
}

fn assert_same_layout_sample(reference: &SampleResult, candidate: &SampleResult, layout: &str) {
    assert_eq!(
        candidate.provenance, reference.provenance,
        "machine, Rust, runtime, commit, or dirty-tree provenance drift for {layout}"
    );
    assert_eq!(candidate.layout_contract, reference.layout_contract);
    assert_eq!(candidate.datasets.len(), reference.datasets.len());
    for (index, (reference_dataset, dataset)) in reference
        .datasets
        .iter()
        .zip(&candidate.datasets)
        .enumerate()
    {
        let context = format!("{layout} dataset {index} round {}", candidate.round);
        assert_dataset_topology_matches(reference_dataset, dataset, &context);
        assert_eq!(
            dataset.forward_traversal_iterations, reference_dataset.forward_traversal_iterations,
            "forward iteration drift: {context}"
        );
        assert_eq!(
            dataset.reverse_traversal_iterations, reference_dataset.reverse_traversal_iterations,
            "reverse iteration drift: {context}"
        );
        assert_eq!(
            dataset.retained_memory, reference_dataset.retained_memory,
            "retained-memory accounting drift: {context}"
        );
        assert_eq!(
            dataset.estimated_retained_bytes, reference_dataset.estimated_retained_bytes,
            "retained-byte drift: {context}"
        );
    }
}

fn validate_required_corpora(sample: &SampleResult) {
    for required in ["fixture_typescript", "fixture_java"] {
        let dataset = sample
            .datasets
            .iter()
            .find(|dataset| dataset.name == required)
            .unwrap_or_else(|| panic!("required checked-in corpus {required} is missing"));
        assert_eq!(dataset.origin, "checked_in_fixture");
        assert_eq!(
            dataset.status, "complete",
            "required checked-in corpus {required} must be complete"
        );
        assert!(
            dataset.files_seen > 0,
            "{required} must contain source files"
        );
        assert_eq!(
            dataset.files_materialized, dataset.files_seen,
            "required checked-in corpus {required} must materialize every file"
        );
        assert!(dataset.procedures > 0, "{required} must contain procedures");
        assert!(dataset.points > 0, "{required} must contain program points");
        assert!(dataset.edges > 0, "{required} must contain control edges");
        assert_eq!(
            dataset.repository_commit, sample.provenance.bifrost_commit,
            "checked-in corpus commit must match Bifrost provenance"
        );
        assert_eq!(
            dataset.repository_dirty, sample.provenance.bifrost_dirty,
            "checked-in corpus dirty state must match Bifrost provenance"
        );
    }
    for dataset in &sample.datasets {
        if dataset.origin == "pinned_external_repository" {
            assert_eq!(
                dataset.repository_dirty,
                Some(false),
                "pinned external corpus {} must be clean",
                dataset.name
            );
        }
        match dataset.name.as_str() {
            "external_vscode_typescript" => assert_eq!(
                dataset.repository_commit.as_deref(),
                Some(VSCODE_COMMIT),
                "VS Code corpus commit drifted"
            ),
            "external_spring_petclinic_java" => assert_eq!(
                dataset.repository_commit.as_deref(),
                Some(SPRING_PETCLINIC_COMMIT),
                "Spring Petclinic corpus commit drifted"
            ),
            _ => {}
        }
    }
}

fn aggregate(samples_file: &Path) -> AggregateResult {
    let contents = fs::read_to_string(samples_file).unwrap_or_else(|error| {
        panic!("read benchmark samples {}: {error}", samples_file.display())
    });
    let mut raw_samples: BTreeMap<String, Vec<SampleResult>> = BTreeMap::new();
    for (line_number, line) in contents.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let sample: SampleResult = serde_json::from_str(line).unwrap_or_else(|error| {
            panic!("parse benchmark sample line {}: {error}", line_number + 1)
        });
        assert_eq!(sample.format, "bifrost_semantic_cfg_benchmark/v4");
        assert_eq!(sample.kind, "sample");
        validate_required_corpora(&sample);
        raw_samples
            .entry(sample.layout.clone())
            .or_default()
            .push(sample);
    }
    for layout in ["flat", "outgoing", "bidirectional"] {
        let samples = raw_samples
            .get_mut(layout)
            .unwrap_or_else(|| panic!("missing retained samples for {layout}"));
        samples.sort_by_key(|sample| sample.round);
        assert_eq!(
            samples.len(),
            7,
            "runner must retain seven samples for {layout}"
        );
        assert_eq!(
            samples
                .iter()
                .map(|sample| sample.round)
                .collect::<Vec<_>>(),
            (2..9).collect::<Vec<_>>(),
            "runner must discard rounds zero and one for {layout}"
        );
        let reference = samples.first().expect("seven samples are present");
        for sample in samples.iter().skip(1) {
            assert_same_layout_sample(reference, sample, layout);
        }
    }

    let reference_samples = raw_samples
        .get("bidirectional")
        .expect("bidirectional samples are present");
    for layout in ["flat", "outgoing"] {
        for (reference, sample) in reference_samples.iter().zip(
            raw_samples
                .get(layout)
                .expect("all layout samples are present"),
        ) {
            assert_eq!(
                sample.provenance, reference.provenance,
                "provenance drift between {layout} and bidirectional in round {}",
                sample.round
            );
            assert_eq!(sample.datasets.len(), reference.datasets.len());
            for (index, (reference_dataset, dataset)) in
                reference.datasets.iter().zip(&sample.datasets).enumerate()
            {
                let context = format!(
                    "{layout} versus bidirectional dataset {index} round {}",
                    sample.round
                );
                assert_dataset_topology_matches(reference_dataset, dataset, &context);
            }
        }
    }

    let mut medians = Vec::new();
    for (layout, samples) in &raw_samples {
        let first = samples.first().expect("seven samples are present");
        for (index, dataset) in first.datasets.iter().enumerate() {
            for sample in samples.iter().skip(1) {
                assert_eq!(sample.datasets[index].name, dataset.name);
                assert_eq!(sample.datasets[index].points, dataset.points);
                assert_eq!(sample.datasets[index].edges, dataset.edges);
            }
            medians.push(MedianMeasurement {
                layout: layout.clone(),
                dataset: dataset.name.clone(),
                status: dataset.status.clone(),
                procedures: dataset.procedures,
                points: dataset.points,
                edges: dataset.edges,
                procedure_row_boundaries: dataset.procedure_row_boundaries,
                semantic_materialization_ms: median_f64(
                    samples
                        .iter()
                        .filter_map(|sample| sample.datasets[index].semantic_materialization_ms)
                        .collect(),
                ),
                semantic_repeat_materialization_ms: median_f64(
                    samples
                        .iter()
                        .filter_map(|sample| {
                            sample.datasets[index].semantic_repeat_materialization_ms
                        })
                        .collect(),
                ),
                construction_freeze_ms: median_f64(
                    samples
                        .iter()
                        .filter_map(|sample| sample.datasets[index].construction_freeze_ms)
                        .collect(),
                ),
                full_forward_traversal_ms: median_f64(
                    samples
                        .iter()
                        .filter_map(|sample| sample.datasets[index].full_forward_traversal_ms)
                        .collect(),
                ),
                full_reverse_traversal_ms: median_f64(
                    samples
                        .iter()
                        .filter_map(|sample| sample.datasets[index].full_reverse_traversal_ms)
                        .collect(),
                ),
                edge_payload_bytes: median_u64(
                    samples
                        .iter()
                        .filter_map(|sample| {
                            sample.datasets[index]
                                .retained_memory
                                .as_ref()
                                .map(|memory| memory.edge_payload_bytes)
                        })
                        .collect(),
                ),
                cfg_slice_owner_header_bytes: median_u64(
                    samples
                        .iter()
                        .filter_map(|sample| {
                            sample.datasets[index]
                                .retained_memory
                                .as_ref()
                                .map(|memory| memory.cfg_slice_owner_header_bytes)
                        })
                        .collect(),
                ),
                estimated_retained_bytes: median_u64(
                    samples
                        .iter()
                        .filter_map(|sample| sample.datasets[index].estimated_retained_bytes)
                        .collect(),
                ),
            });
        }
    }
    let reference_sample = reference_samples
        .first()
        .expect("bidirectional reference sample exists");
    let sample_provenance = reference_sample.provenance.clone();
    let dataset_provenance = reference_sample
        .datasets
        .iter()
        .map(|dataset| {
            (
                dataset.name.clone(),
                DatasetRepositoryProvenance {
                    origin: dataset.origin.clone(),
                    repository_commit: dataset.repository_commit.clone(),
                    repository_dirty: dataset.repository_dirty,
                },
            )
        })
        .collect();
    AggregateResult {
        format: "bifrost_semantic_cfg_benchmark_aggregate/v5",
        kind: "aggregate",
        aggregation_provenance: benchmark_provenance(),
        sample_provenance,
        dataset_provenance,
        fresh_processes_per_layout: 9,
        discarded_warmups_per_layout: 2,
        retained_samples_per_layout: 7,
        raw_samples,
        medians,
    }
}

#[test]
fn representation_models_preserve_procedure_and_rich_edge_contracts() {
    let mut procedure_graphs = generated_branch_heavy(32).procedure_graphs;
    procedure_graphs.extend(generated_call_heavy(32).procedure_graphs);
    let (_, _, procedure_row_boundaries) = procedure_counts(&procedure_graphs);
    for procedure in &procedure_graphs {
        let mut edges = procedure.edges.clone();
        edges.sort_unstable_by_key(edge_sort_key);
        assert!(
            !edges
                .windows(2)
                .any(|pair| edge_sort_key(&pair[0]) == edge_sort_key(&pair[1]))
        );
    }

    let flat = freeze_dataset(Layout::Flat, procedure_graphs.clone());
    let outgoing = freeze_dataset(Layout::Outgoing, procedure_graphs.clone());
    let bidirectional = freeze_dataset(Layout::Bidirectional, procedure_graphs);
    assert_eq!(flat.full_forward(), outgoing.full_forward());
    assert_eq!(flat.full_forward(), bidirectional.full_forward());
    assert_eq!(flat.full_reverse(), outgoing.full_reverse());
    assert_eq!(flat.full_reverse(), bidirectional.full_reverse());

    let flat_memory = flat.retained_memory();
    let outgoing_memory = outgoing.retained_memory();
    let bidirectional_memory = bidirectional.retained_memory();
    assert_eq!(flat_memory.outgoing_offset_entries, 0);
    assert_eq!(
        outgoing_memory.outgoing_offset_entries,
        procedure_row_boundaries
    );
    assert_eq!(
        bidirectional_memory.outgoing_offset_entries,
        procedure_row_boundaries
    );
    assert_eq!(
        bidirectional_memory.incoming_offset_entries,
        procedure_row_boundaries
    );
    assert_eq!(flat_memory.retained_slice_owners, 2);
    assert_eq!(outgoing_memory.retained_slice_owners, 4);
    assert_eq!(bidirectional_memory.retained_slice_owners, 8);

    let edge = bench_edge(1, 2, ControlEdgeKind::Normal);
    let mut different_mapping = edge;
    different_mapping.source_mapping += 1;
    let mut different_evidence = edge;
    different_evidence.evidence += 1;
    assert_ne!(mix(0, &edge, false), mix(0, &different_mapping, false));
    assert_ne!(mix(0, &edge, false), mix(0, &different_evidence, false));
}

#[test]
#[ignore = "measure-first semantic CFG representation benchmark; run explicitly in release mode"]
fn semantic_cfg_representation_measurement() {
    if let Some(samples_file) = std::env::var_os(SAMPLES_FILE_ENV) {
        let result = aggregate(Path::new(&samples_file));
        println!(
            "{RESULT_PREFIX}{}",
            serde_json::to_string(&result).expect("serialize aggregate semantic CFG benchmark")
        );
    } else {
        let result = sample();
        println!(
            "{RESULT_PREFIX}{}",
            serde_json::to_string(&result).expect("serialize semantic CFG benchmark sample")
        );
    }
}
