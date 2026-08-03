//! Reproducible SQLite-BLOB versus content-addressed-file measurements for semantic packs.
//!
//! Run with:
//!   cargo test --release --test suite_semantic -- \
//!     measure_semantic_pack_catalog::measure_inline_and_file_storage \
//!     --ignored --exact --nocapture

use brokk_bifrost::analyzer::semantic_model::{
    CompiledSemanticModelPack, CompilerOptions, CompressionPolicy, DecodeLimits, SourceFormat,
    compile_source, decode_shard_for_manifest,
};
use rusqlite::{Connection, params};
use serde::Serialize;
use serde_json::json;
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use std::process::Command;
use std::time::Instant;
use tempfile::TempDir;

const TARGET_RAW_BYTES: [usize; 5] = [1 << 10, 8 << 10, 32 << 10, 64 << 10, 256 << 10];
const ITERATIONS: usize = 9;
const WARM_READS_PER_ITERATION: usize = 7;
const CANDIDATE_THRESHOLDS: [u64; 6] = [0, 8 << 10, 32 << 10, 64 << 10, 256 << 10, u64::MAX];

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum StorageKind {
    Inline,
    File,
}

#[derive(Debug, Serialize)]
struct StorageMeasurement {
    target_raw_bytes: usize,
    actual_raw_bytes: u64,
    stored_bytes: u64,
    encoding: String,
    storage_kind: StorageKind,
    iterations: usize,
    install_median_ms: f64,
    install_p95_ms: f64,
    cold_verified_read_median_ms: f64,
    cold_verified_read_p95_ms: f64,
    warm_verified_read_median_ms: f64,
    warm_verified_read_p95_ms: f64,
    total_storage_median_bytes: u64,
}

#[derive(Debug, Serialize)]
struct ThresholdDecision {
    threshold_bytes: u64,
    eligible: bool,
    evaluated_payloads: usize,
    inline_read_improvement_met: bool,
    install_overhead_met: bool,
    storage_overhead_met: bool,
}

#[derive(Debug, Serialize)]
struct BenchmarkReport {
    format: &'static str,
    bifrost_commit: Option<String>,
    operating_system: &'static str,
    architecture: &'static str,
    sqlite_version: &'static str,
    iterations: usize,
    warm_reads_per_iteration: usize,
    measurements: Vec<StorageMeasurement>,
    threshold_decisions: Vec<ThresholdDecision>,
    selected_inline_threshold_bytes: u64,
}

#[derive(Debug, Default)]
struct Samples {
    install_ms: Vec<f64>,
    cold_ms: Vec<f64>,
    warm_ms: Vec<f64>,
    total_storage_bytes: Vec<u64>,
}

#[test]
#[ignore = "release-mode storage benchmark"]
fn measure_inline_and_file_storage() {
    let fixture_source =
        include_bytes!("../fixtures/semantic-model-packs/declarations-v1.json").as_slice();
    let raw_options = CompilerOptions {
        compression: CompressionPolicy::AlwaysRaw,
        ..CompilerOptions::default()
    };
    let fixture_pack = compile_source(SourceFormat::Json, fixture_source, &raw_options)
        .unwrap_or_else(|diagnostics| panic!("compile raw fixture pack: {diagnostics:#?}"));
    assert_eq!(fixture_pack.shards.len(), 1);
    assert_eq!(
        fixture_pack.shards[0].descriptor.encoding,
        brokk_bifrost::analyzer::semantic_model::ArtifactEncoding::Raw
    );
    let mut packs = vec![(
        fixture_pack.shards[0].descriptor.raw_size as usize,
        fixture_pack,
    )];
    for target in TARGET_RAW_BYTES {
        packs.push((target, compiled_pack_at_least(target)));
    }

    let mut measurements = Vec::new();
    for (target, pack) in &packs {
        measurements.push(measure_pack(*target, pack, StorageKind::Inline));
        measurements.push(measure_pack(*target, pack, StorageKind::File));
    }
    let (threshold_decisions, selected_inline_threshold_bytes) =
        choose_inline_threshold(&measurements);
    let report = BenchmarkReport {
        format: "bifrost.semantic-pack-catalog-storage-benchmark.v1",
        bifrost_commit: git_commit(),
        operating_system: std::env::consts::OS,
        architecture: std::env::consts::ARCH,
        sqlite_version: rusqlite::version(),
        iterations: ITERATIONS,
        warm_reads_per_iteration: WARM_READS_PER_ITERATION,
        measurements,
        threshold_decisions,
        selected_inline_threshold_bytes,
    };

    println!(
        "{}",
        serde_json::to_string_pretty(&report).expect("serialize benchmark report")
    );
}

fn compiled_pack_at_least(target_raw_bytes: usize) -> CompiledSemanticModelPack {
    let mut type_count = (target_raw_bytes / 256).max(1);
    loop {
        let types = (0..type_count)
            .map(|index| {
                let entropy = deterministic_hex(index as u64, 96);
                json!({
                    "id": format!("type.measurement.{index:08x}"),
                    "name": format!("benchmark.measurement.Type{index:08x}{entropy}"),
                    "type_kind": "class",
                    "visibility": "public",
                    "locator": {
                        "kind": "artifact",
                        "path": format!("benchmark/{index:08x}/{entropy}.class"),
                        "symbol": format!("benchmark.measurement.Type{index:08x}{entropy}")
                    }
                })
            })
            .collect::<Vec<_>>();
        let source = serde_json::to_vec(&json!({
            "schema_version": 1,
            "pack_id": format!("benchmark.catalog.{target_raw_bytes}"),
            "version": "1.0.0",
            "producer": {
                "name": "catalog-storage-benchmark",
                "version": "1.0.0"
            },
            "language": "java",
            "ecosystem": "maven",
            "compatibility": {
                "bifrost": ">=0.8.0, <1.0.0",
                "toolchains": []
            },
            "provenance": {
                "source": "generated:semantic-pack-catalog-storage-benchmark"
            },
            "license": "MIT",
            "completeness": "complete",
            "safety": {
                "generated_code_only": false,
                "review_required": false
            },
            "shards": [{
                "id": "declarations.measurement",
                "activation": [{
                    "package": {
                        "name": "benchmark:catalog",
                        "version": ">=1.0.0, <2.0.0"
                    },
                    "targets": ["jvm"],
                    "configurations": ["release"]
                }],
                "payload": {
                    "kind": "declaration_facts",
                    "types": types,
                    "members": [],
                    "relations": []
                }
            }]
        }))
        .expect("serialize benchmark source");
        let options = CompilerOptions {
            compression: CompressionPolicy::Automatic,
            ..CompilerOptions::default()
        };
        let pack = compile_source(SourceFormat::Json, &source, &options)
            .unwrap_or_else(|diagnostics| panic!("compile benchmark pack: {diagnostics:#?}"));
        assert_eq!(pack.shards.len(), 1);
        if pack.shards[0].descriptor.raw_size >= target_raw_bytes as u64 {
            return pack;
        }
        type_count = type_count.saturating_mul(2);
        assert!(
            type_count <= options.max_records_per_shard,
            "could not reach target raw size {target_raw_bytes}"
        );
    }
}

fn deterministic_hex(mut state: u64, bytes: usize) -> String {
    let mut result = String::with_capacity(bytes * 2);
    for _ in 0..bytes {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        result.push_str(&format!("{:02x}", state as u8));
    }
    result
}

fn measure_pack(
    target_raw_bytes: usize,
    pack: &CompiledSemanticModelPack,
    storage_kind: StorageKind,
) -> StorageMeasurement {
    let shard = &pack.shards[0];
    let mut samples = Samples::default();
    for iteration in 0..ITERATIONS {
        let temp = TempDir::new().expect("create benchmark temp directory");
        let database = temp.path().join("catalog.db");
        let object = temp.path().join(&shard.descriptor.stored_sha256);
        let started = Instant::now();
        let mut connection = benchmark_connection(&database);
        if matches!(storage_kind, StorageKind::File) {
            write_synced(&object, &shard.bytes);
        }
        let transaction = connection.transaction().expect("start install transaction");
        transaction
            .execute(
                "INSERT INTO pack_object(
                   id, manifest, stored_digest, inline_bytes, relative_path
                 ) VALUES(1, ?1, ?2, ?3, ?4)",
                params![
                    &pack.manifest_bytes,
                    &shard.descriptor.stored_sha256,
                    matches!(storage_kind, StorageKind::Inline).then_some(shard.bytes.as_slice()),
                    matches!(storage_kind, StorageKind::File)
                        .then_some(shard.descriptor.stored_sha256.as_str()),
                ],
            )
            .expect("insert benchmark object");
        transaction.commit().expect("commit install transaction");
        connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .expect("checkpoint benchmark database");
        samples.install_ms.push(elapsed_ms(started));
        drop(connection);

        let cold_started = Instant::now();
        verified_read(&database, temp.path(), pack);
        samples.cold_ms.push(elapsed_ms(cold_started));
        for _ in 0..WARM_READS_PER_ITERATION {
            let warm_started = Instant::now();
            verified_read(&database, temp.path(), pack);
            samples.warm_ms.push(elapsed_ms(warm_started));
        }
        samples
            .total_storage_bytes
            .push(directory_regular_file_bytes(temp.path()));

        if iteration % 2 == 1 {
            std::hint::black_box(&shard.bytes);
        }
    }

    StorageMeasurement {
        target_raw_bytes,
        actual_raw_bytes: shard.descriptor.raw_size,
        stored_bytes: shard.descriptor.stored_size,
        encoding: format!("{:?}", shard.descriptor.encoding).to_ascii_lowercase(),
        storage_kind,
        iterations: ITERATIONS,
        install_median_ms: percentile(&samples.install_ms, 50),
        install_p95_ms: percentile(&samples.install_ms, 95),
        cold_verified_read_median_ms: percentile(&samples.cold_ms, 50),
        cold_verified_read_p95_ms: percentile(&samples.cold_ms, 95),
        warm_verified_read_median_ms: percentile(&samples.warm_ms, 50),
        warm_verified_read_p95_ms: percentile(&samples.warm_ms, 95),
        total_storage_median_bytes: percentile_u64(&samples.total_storage_bytes, 50),
    }
}

fn benchmark_connection(path: &Path) -> Connection {
    let connection = Connection::open(path).expect("open benchmark database");
    connection
        .execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = FULL;
             CREATE TABLE pack_object(
               id INTEGER PRIMARY KEY,
               manifest BLOB NOT NULL,
               stored_digest TEXT NOT NULL,
               inline_bytes BLOB,
               relative_path TEXT,
               CHECK ((inline_bytes IS NOT NULL) != (relative_path IS NOT NULL))
             ) STRICT;",
        )
        .expect("configure benchmark database");
    connection
}

fn write_synced(path: &Path, bytes: &[u8]) {
    let mut file = File::create(path).expect("create benchmark object");
    file.write_all(bytes).expect("write benchmark object");
    file.sync_all().expect("sync benchmark object");
}

fn verified_read(database: &Path, root: &Path, pack: &CompiledSemanticModelPack) {
    let connection = Connection::open(database).expect("reopen benchmark database");
    let (inline, relative): (Option<Vec<u8>>, Option<String>) = connection
        .query_row(
            "SELECT inline_bytes, relative_path FROM pack_object WHERE id = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("load benchmark object location");
    let bytes = match (inline, relative) {
        (Some(bytes), None) => bytes,
        (None, Some(relative)) => fs::read(root.join(relative)).expect("read benchmark object"),
        _ => panic!("benchmark object location invariant failed"),
    };
    decode_shard_for_manifest(
        &pack.manifest,
        &pack.shards[0].descriptor,
        &bytes,
        &DecodeLimits::default(),
    )
    .expect("verify benchmark object");
}

fn choose_inline_threshold(measurements: &[StorageMeasurement]) -> (Vec<ThresholdDecision>, u64) {
    let mut decisions = Vec::new();
    let mut selected = 0;
    for threshold in CANDIDATE_THRESHOLDS {
        let pairs = measurements
            .chunks_exact(2)
            .filter(|pair| pair[0].stored_bytes <= threshold)
            .collect::<Vec<_>>();
        let inline_read_improvement_met = pairs.iter().all(|pair| {
            pair[0].cold_verified_read_median_ms <= pair[1].cold_verified_read_median_ms * 0.9
        });
        let install_overhead_met = pairs
            .iter()
            .all(|pair| pair[0].install_p95_ms <= pair[1].install_p95_ms * 1.25);
        let storage_overhead_met = pairs.iter().all(|pair| {
            pair[0].total_storage_median_bytes
                <= (pair[1].total_storage_median_bytes as f64 * 1.1) as u64
        });
        let eligible = !pairs.is_empty()
            && inline_read_improvement_met
            && install_overhead_met
            && storage_overhead_met;
        if eligible {
            selected = threshold.min(256 << 10);
        }
        decisions.push(ThresholdDecision {
            threshold_bytes: threshold,
            eligible,
            evaluated_payloads: pairs.len(),
            inline_read_improvement_met,
            install_overhead_met,
            storage_overhead_met,
        });
    }
    (decisions, selected)
}

fn percentile(samples: &[f64], percentile: usize) -> f64 {
    assert!(!samples.is_empty());
    let mut sorted = samples.to_vec();
    sorted.sort_by(f64::total_cmp);
    sorted[percentile_index(sorted.len(), percentile)]
}

fn percentile_u64(samples: &[u64], percentile: usize) -> u64 {
    assert!(!samples.is_empty());
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    sorted[percentile_index(sorted.len(), percentile)]
}

fn percentile_index(length: usize, percentile: usize) -> usize {
    assert!(length > 0);
    assert!(percentile <= 100);
    ((length - 1) * percentile).div_ceil(100)
}

fn elapsed_ms(started: Instant) -> f64 {
    started.elapsed().as_secs_f64() * 1000.0
}

fn directory_regular_file_bytes(root: &Path) -> u64 {
    fs::read_dir(root)
        .expect("read benchmark directory")
        .map(|entry| entry.expect("read benchmark entry"))
        .filter_map(|entry| {
            entry
                .metadata()
                .expect("read benchmark metadata")
                .is_file()
                .then(|| entry.metadata().expect("read benchmark metadata").len())
        })
        .sum()
}

fn git_commit() -> Option<String> {
    Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|commit| commit.trim().to_owned())
}
