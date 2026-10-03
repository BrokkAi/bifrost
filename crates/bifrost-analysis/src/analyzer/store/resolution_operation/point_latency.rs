//! R2.3 measurement harness: warm point latency on the ten #2767 sites, and
//! the unrelated-mount constancy pin for the three work axes.
//!
//! Two things are measured here, deliberately from two places.
//!
//! Latency is measured through the public `get_definitions_by_location`,
//! because that is the call the 100 ms gate is about, over a warm persisted
//! index of the pinned #2767 corpus revision. Nothing in that path consults
//! the workspace usage-graph cache, and the harness proves it rather than
//! asserting it in prose: it reads the cache's retained size before and after
//! the whole run.
//!
//! The three work axes -- charged prefix evaluations, hydrations and candidate
//! reads -- are measured on the scale fixture, because the production point
//! path builds a `ResolutionBatchMetrics` per query and drops it
//! (`analyzer/rust/native_points.rs`), so no per-site engine counters are
//! reachable from `get_definitions_by_location` today. Recording them per
//! corpus site needs a metrics sink at that seam. Until then the constancy pin
//! is where the axes live, and it is the pin R2.3 actually asks for: the same
//! request against 256, 1,024 and 2,048 unrelated mounts.

use std::time::{Duration, Instant};

use super::*;

use crate::analyzer::FilesystemProject;
use crate::analyzer::workspace::WorkspaceAnalyzer;
use crate::analyzer::{AnalyzerConfig, IAnalyzer};
use crate::searchtools::{
    DefinitionReferenceQuery, GetDefinitionParams, get_definitions_by_location_with_cancellation,
};

/// One adjudicated #2767 candidate, addressed by the exact reference that
/// reaches it.
///
/// The ledger (`.agents/docs/stack-graph-2767-ledger.md`) names each changed
/// callable and the caller path that reaches it. A latency site is that
/// caller's reference token, because a point query is issued at a reference,
/// not at a declaration. `token` is checked against the corpus source before
/// any measurement runs, so a site that drifted fails loudly instead of
/// silently measuring a different call.
#[derive(Debug, Clone, Copy)]
struct PointLatencySite {
    /// Ledger row number, 1 to 10.
    row: usize,
    /// Repository-relative path of the reference.
    path: &'static str,
    /// One-based line of the reference token.
    line: usize,
    /// One-based column of the reference token's first character.
    column: usize,
    /// The identifier the reference must spell at that position.
    token: &'static str,
    /// The ledger's changed callable this reference resolves to.
    callable: &'static str,
    /// Repository-relative path of that callable's declaration.
    callable_path: &'static str,
    language: &'static str,
}

/// The ten #2767 sites at `57fb66322ce75c1612b7ce5a426e1797d5ba9935`.
///
/// Rows 1 to 5 are Rust and rows 6 to 10 are Python, exactly as the ledger
/// partitions them. Row 4 is the ledger's one missing candidate: its only Rust
/// caller is production CLI setup, which is still an ordinary reference and
/// therefore still a latency site.
const SITES_2767: [PointLatencySite; 10] = [
    PointLatencySite {
        row: 1,
        path: "crates/bifrost-analysis/src/blast_radius/missing_tests.rs",
        line: 369,
        column: 29,
        token: "scan_target",
        callable: "blast_radius::missing_tests::scan_target",
        callable_path: "crates/bifrost-analysis/src/blast_radius/missing_tests.rs",
        language: "rust",
    },
    PointLatencySite {
        row: 2,
        path: "crates/bifrost-mcp/src/mcp_registry.rs",
        line: 146,
        column: 36,
        token: "diff_tool_descriptors",
        callable: "mcp_diff::diff_tool_descriptors",
        callable_path: "crates/bifrost-mcp/src/mcp_diff.rs",
        language: "rust",
    },
    PointLatencySite {
        row: 3,
        path: "crates/bifrost-mcp/src/mcp_registry.rs",
        line: 45,
        column: 9,
        token: "discovery_instructions",
        callable: "mcp_registry::discovery_instructions",
        callable_path: "crates/bifrost-mcp/src/mcp_registry.rs",
        language: "rust",
    },
    PointLatencySite {
        row: 4,
        path: "crates/bifrost-mcp/src/scoped_project.rs",
        line: 101,
        column: 28,
        token: "tool_is_workspace_independent",
        callable: "SearchToolsService::tool_is_workspace_independent",
        callable_path: "crates/bifrost-mcp/src/searchtools_service.rs",
        language: "rust",
    },
    PointLatencySite {
        row: 5,
        path: "crates/bifrost-mcp/src/searchtools_service.rs",
        line: 2583,
        column: 27,
        token: "call_tool_output_with_transport_queue_wait_inner",
        callable: "SearchToolsService::call_tool_output_with_transport_queue_wait_inner",
        callable_path: "crates/bifrost-mcp/src/searchtools_service.rs",
        language: "rust",
    },
    PointLatencySite {
        row: 6,
        path: "python_tests/test_searchtools_client.py",
        line: 1533,
        column: 25,
        token: "missing_tests",
        callable: "SearchToolsClient.missing_tests",
        callable_path: "bifrost_searchtools/client.py",
        language: "python",
    },
    PointLatencySite {
        row: 7,
        path: "bifrost_searchtools/models.py",
        line: 5965,
        column: 43,
        token: "from_dict",
        callable: "MissingTestsAnalysis.from_dict",
        callable_path: "bifrost_searchtools/models.py",
        language: "python",
    },
    PointLatencySite {
        row: 8,
        path: "bifrost_searchtools/models.py",
        line: 5967,
        column: 37,
        token: "from_dict",
        callable: "MissingTestFunction.from_dict",
        callable_path: "bifrost_searchtools/models.py",
        language: "python",
    },
    PointLatencySite {
        row: 9,
        path: "bifrost_searchtools/client.py",
        line: 772,
        column: 35,
        token: "from_dict",
        callable: "MissingTestsResult.from_dict",
        callable_path: "bifrost_searchtools/models.py",
        language: "python",
    },
    PointLatencySite {
        row: 10,
        path: "python_tests/test_searchtools_client.py",
        line: 1545,
        column: 67,
        token: "render_text",
        callable: "MissingTestsResult.render_text",
        callable_path: "bifrost_searchtools/models.py",
        language: "python",
    },
];

const CORPUS_REVISION_2767: &str = "57fb66322ce75c1612b7ce5a426e1797d5ba9935";

/// Content identity of the measured site table.
///
/// The receipt names an artifact so a later run can prove it measured the same
/// ten sites. The artifact is the table above, not the ledger prose: the prose
/// is the oracle for the adjudication, while these coordinates are what the
/// harness actually queries.
fn sites_artifact_sha256() -> String {
    let mut rendered = String::new();
    for site in &SITES_2767 {
        rendered.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
            site.row,
            site.path,
            site.line,
            site.column,
            site.token,
            site.callable,
            site.callable_path,
            site.language,
        ));
    }
    brokk_bifrost_core::analyzer::canonical_hash::lower_hex_string(
        &brokk_bifrost_core::analyzer::canonical_hash::sha256_bytes(rendered.as_bytes()),
    )
}

/// Warm latency of one site over a stated sample count.
#[derive(Debug)]
struct PointLatencySample {
    row: usize,
    status: String,
    complete: bool,
    definitions: Vec<String>,
    diagnostics: Vec<String>,
    samples: Vec<Duration>,
    /// Set when the per-site wall-clock bound cancelled a call. The samples
    /// recorded up to that point are kept, and the last one is the bound.
    timed_out: bool,
}

impl PointLatencySample {
    fn percentile(&self, percentile: f64) -> Duration {
        assert!((0.0..=100.0).contains(&percentile));
        assert!(!self.samples.is_empty(), "a latency site has samples");
        let mut sorted = self.samples.clone();
        sorted.sort_unstable();
        // Nearest-rank: the smallest sample at or above the requested share of
        // the run. With a stated sample count this is reproducible and needs no
        // interpolation policy.
        let rank = (percentile / 100.0 * sorted.len() as f64).ceil() as usize;
        sorted[rank.clamp(1, sorted.len()) - 1]
    }
}

fn site_query(site: &PointLatencySite) -> GetDefinitionParams {
    GetDefinitionParams {
        references: vec![DefinitionReferenceQuery {
            path: site.path.to_owned(),
            line: Some(site.line),
            column: Some(site.column),
        }],
    }
}

/// Fail before measuring if a site no longer names its recorded token.
///
/// The corpus is pinned to one revision, so a mismatch means the table drifted
/// from the ledger, not that the source changed under us.
fn assert_site_token(root: &std::path::Path, site: &PointLatencySite) {
    let source = std::fs::read_to_string(root.join(site.path))
        .unwrap_or_else(|error| panic!("read #2767 site source {}: {error}", site.path));
    let line = source
        .lines()
        .nth(site.line - 1)
        .unwrap_or_else(|| panic!("#2767 site {} has no line {}", site.path, site.line));
    let column = line
        .char_indices()
        .nth(site.column - 1)
        .unwrap_or_else(|| {
            panic!(
                "#2767 site {}:{} has no column {}",
                site.path, site.line, site.column
            )
        })
        .0;
    assert!(
        line[column..].starts_with(site.token),
        "#2767 site row {} drifted: {}:{}:{} does not start with {:?}, line is {:?}",
        site.row,
        site.path,
        site.line,
        site.column,
        site.token,
        line
    );
}

/// One bounded point call: the answer, how long it took, and whether the
/// bound cut it short.
struct BoundedPointCall {
    status: String,
    complete: bool,
    definitions: Vec<String>,
    diagnostics: Vec<String>,
    elapsed: Duration,
    timed_out: bool,
}

/// Issue one point query under a wall-clock bound.
///
/// The bound is the query's own cancellation deadline rather than a watchdog
/// on the outside, so an over-running request stops inside the engine at its
/// next cancellation check and the harness keeps the thread it started with.
/// That is what makes the run safe to leave in the exclusive build slot: no
/// single site can hold the machine past its bound, and a site that hits the
/// bound is recorded rather than hidden.
fn bounded_point_call(
    analyzer: &dyn IAnalyzer,
    site: &PointLatencySite,
    bound: Duration,
) -> BoundedPointCall {
    let token = crate::CancellationToken::new().with_timeout(bound);
    let started = Instant::now();
    let result =
        get_definitions_by_location_with_cancellation(analyzer, site_query(site), Some(&token));
    let elapsed = started.elapsed();
    assert_eq!(result.results.len(), 1, "one reference query, one result");
    BoundedPointCall {
        status: result.results[0].status.clone(),
        complete: result.results[0].complete,
        // A site that does not resolve has to say why in the receipt. An
        // unexplained `exceeded_budget` is a latency number nobody can act on.
        diagnostics: result.results[0]
            .diagnostics
            .iter()
            .map(|diagnostic| format!("{}: {}", diagnostic.kind, diagnostic.message))
            .collect::<Vec<_>>(),
        definitions: result.results[0]
            .definitions
            .iter()
            .map(|candidate| {
                format!(
                    "{}:{}:{}",
                    candidate.path,
                    candidate.start_line,
                    candidate.fqn.as_deref().unwrap_or(&candidate.name)
                )
            })
            .collect::<Vec<_>>(),
        elapsed,
        timed_out: token.is_timed_out(),
    }
}

fn measure_site(
    analyzer: &dyn IAnalyzer,
    site: &PointLatencySite,
    samples: usize,
    bound: Duration,
) -> PointLatencySample {
    assert!(samples > 0, "a latency measurement needs samples");
    eprintln!(
        "[r23] site row {} {}:{}:{} {:?} start, bound {:.1}s",
        site.row,
        site.path,
        site.line,
        site.column,
        site.token,
        bound.as_secs_f64(),
    );
    // One unmeasured call warms every per-query structure this site touches,
    // so the recorded samples measure a warm index rather than first touch.
    let warm = bounded_point_call(analyzer, site, bound);
    eprintln!(
        "[r23] site row {} warm {} in {:.1} ms{}",
        site.row,
        warm.status,
        warm.elapsed.as_secs_f64() * 1_000.0,
        if warm.timed_out { " (TIMED OUT)" } else { "" },
    );
    if warm.timed_out {
        return PointLatencySample {
            row: site.row,
            status: "timed_out".to_owned(),
            complete: warm.complete,
            definitions: warm.definitions,
            diagnostics: warm.diagnostics,
            samples: vec![warm.elapsed],
            timed_out: true,
        };
    }

    let mut timings = Vec::with_capacity(samples);
    for sample in 0..samples {
        let call = bounded_point_call(analyzer, site, bound);
        timings.push(call.elapsed);
        eprintln!(
            "[r23] site row {} sample {}/{} {} in {:.1} ms{}",
            site.row,
            sample + 1,
            samples,
            call.status,
            call.elapsed.as_secs_f64() * 1_000.0,
            if call.timed_out { " (TIMED OUT)" } else { "" },
        );
        if call.timed_out {
            return PointLatencySample {
                row: site.row,
                status: "timed_out".to_owned(),
                complete: call.complete,
                definitions: call.definitions,
                diagnostics: call.diagnostics,
                samples: timings,
                timed_out: true,
            };
        }
        assert_eq!(
            call.status, warm.status,
            "#2767 site row {} changed status between warm samples",
            site.row
        );
    }
    PointLatencySample {
        row: site.row,
        status: warm.status,
        complete: warm.complete,
        definitions: warm.definitions,
        diagnostics: warm.diagnostics,
        samples: timings,
        timed_out: false,
    }
}

/// R2.3 warm point latency over the pinned #2767 corpus.
///
/// Set `BIFROST_2767_CORPUS` to a checkout of
/// `57fb66322ce75c1612b7ce5a426e1797d5ba9935`, and optionally
/// `BIFROST_2767_SAMPLES` (default 30) and `BIFROST_2767_RECEIPT` (a file to
/// write the receipt to; it is printed either way). Record host load and
/// concurrent activity alongside the receipt when interpreting latency.
///
/// Run it with `cargo test`, not `cargo nextest run`. The repository's default
/// nextest profile terminates a test after ten minutes, which is a hang
/// detector, and a first index build of this corpus is legitimately longer than
/// that. A warm rerun is well inside it, but the first build is not, and a
/// measurement harness should not depend on the cache already being warm.
///
/// Run it with `--release` for any number that is compared against a latency
/// threshold. The workspace dev profile is unoptimized, so a debug run measures
/// the build, not the product; the receipt records which profile produced it so
/// a debug number can never be mistaken for an acceptance number. The persisted
/// index is content-addressed and independent of the build profile, so a debug
/// run may be used to warm the cache for a release measurement.
///
/// Every call runs under a per-call wall-clock bound,
/// `BIFROST_2767_SITE_TIMEOUT_MS` (default 120000). The bound is the query's
/// own cancellation deadline, so an over-running request stops inside the
/// engine; the site is recorded as `timed_out` with the samples it did take and
/// the run continues to the next one. Progress for every site and every sample
/// goes to stderr, so a run in the exclusive slot can always be seen to be
/// making progress.
///
/// Set `BIFROST_PARALLELISM` and `RAYON_NUM_THREADS` explicitly. The repository
/// Cargo configuration pins both to 1 for tests so an ordinary suite does not
/// oversubscribe the machine, and those defaults survive into a Cargo-launched
/// measurement: a first index build of this corpus then runs on one core, which
/// measures the pin rather than the product. The receipt records both values.
#[test]
#[ignore = "operator tool: needs BIFROST_2767_CORPUS pointing at a 57fb66322 checkout; run under cargo test, not nextest"]
fn ignored_rust_point_latency_on_the_2767_sites() {
    let Some(root) = std::env::var_os("BIFROST_2767_CORPUS") else {
        return;
    };
    let root = std::path::PathBuf::from(root);
    let samples = std::env::var("BIFROST_2767_SAMPLES")
        .ok()
        .map(|value| {
            value
                .parse::<usize>()
                .expect("BIFROST_2767_SAMPLES must be a positive integer")
        })
        .unwrap_or(30);
    // Every call runs under this wall-clock bound. Without it one site can hold
    // the exclusive build slot for hours with no output: that is exactly what
    // happened on the first re-measurement after the budget fix, when a single
    // reference ran for 2 h 28 min at 99% CPU and had to be killed from
    // outside. A bounded call records `timed_out` with its elapsed time and the
    // run moves on.
    let site_bound = Duration::from_millis(
        std::env::var("BIFROST_2767_SITE_TIMEOUT_MS")
            .ok()
            .map(|value| {
                value
                    .parse::<u64>()
                    .expect("BIFROST_2767_SITE_TIMEOUT_MS must be a positive integer")
            })
            .unwrap_or(120_000),
    );
    assert!(
        !site_bound.is_zero(),
        "the per-site bound must leave time to answer"
    );
    // An acceptance run measures all ten rows. An attribution run measures one,
    // because the question there is where one site's work goes and a full run
    // costs ten times as much of the exclusive slot to answer it. The receipt
    // records which rows were measured, so a one-row run can never be read as
    // an acceptance number.
    let measured_rows = std::env::var("BIFROST_2767_ROWS")
        .ok()
        .map(|value| {
            value
                .split(',')
                .map(|row| {
                    row.trim()
                        .parse::<usize>()
                        .expect("BIFROST_2767_ROWS must be comma-separated row numbers")
                })
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_else(|| SITES_2767.iter().map(|site| site.row).collect());
    let sites = SITES_2767
        .iter()
        .filter(|site| measured_rows.contains(&site.row))
        .collect::<Vec<_>>();
    assert!(
        !sites.is_empty(),
        "BIFROST_2767_ROWS selected no site: {measured_rows:?}"
    );
    let exclusive_slot = std::env::var("BIFROST_BUILD_SLOT").unwrap_or_else(|_| "unset".to_owned());
    // A baseline run and an acceptance run differ only in when they are taken,
    // so the label is an input and the receipt records it rather than the
    // harness deciding.
    let label = std::env::var("BIFROST_2767_LABEL").unwrap_or_else(|_| "baseline".to_owned());

    for site in &sites {
        assert_site_token(&root, site);
    }

    let project = std::sync::Arc::new(
        FilesystemProject::new(&root).expect("open the #2767 corpus as a filesystem project"),
    );
    // The ten sites are five Rust and five Python, and none of them crosses a
    // language boundary, so the other nine parsers are pure setup cost. They
    // also make the receipt less reproducible: a language whose adapter changes
    // would move the index build time of a measurement that never asks it
    // anything. The languages are named in the receipt.
    let languages = BTreeSet::from([Language::Rust, Language::Python]);
    eprintln!(
        "[r23] index build start: {} ({} sites, {} samples each, bound {:.1}s)",
        root.display(),
        sites.len(),
        samples,
        site_bound.as_secs_f64(),
    );
    let build_started = Instant::now();
    let workspace = WorkspaceAnalyzer::build_persisted_for_languages(
        project,
        AnalyzerConfig::default(),
        &languages,
    )
    .expect("build a persisted analyzer over the #2767 corpus");
    let build_elapsed = build_started.elapsed();
    eprintln!("[r23] index ready in {:.1} s", build_elapsed.as_secs_f64());
    let analyzer = workspace.analyzer();

    let graph_cache_before = analyzer
        .snapshot_caches()
        .expect("a workspace analyzer retains snapshot caches")
        .usage_graphs()
        .len_for_test();

    let measurements = sites
        .iter()
        .map(|site| measure_site(analyzer, site, samples, site_bound))
        .collect::<Vec<_>>();

    let graph_cache_after = analyzer
        .snapshot_caches()
        .expect("a workspace analyzer retains snapshot caches")
        .usage_graphs()
        .len_for_test();
    // "Graph cache disabled" is a measurement condition, not a claim: a point
    // query must never populate the workspace usage-graph cache, so a nonzero
    // delta means the measurement was contaminated by graph work.
    assert_eq!(
        graph_cache_before, graph_cache_after,
        "a point-latency run must not populate the workspace usage-graph cache"
    );

    let mut all = measurements
        .iter()
        .flat_map(|measurement| measurement.samples.iter().copied())
        .collect::<Vec<_>>();
    all.sort_unstable();
    let overall_rank = (0.95 * all.len() as f64).ceil() as usize;
    let overall_p95 = all[overall_rank.clamp(1, all.len()) - 1];

    let rows = measurements
        .iter()
        .zip(sites.iter())
        .map(|(measurement, site)| {
            format!(
                "{{\"row\":{},\"path\":\"{}\",\"line\":{},\"column\":{},\"token\":\"{}\",\"callable\":\"{}\",\"language\":\"{}\",\"status\":\"{}\",\"timed_out\":{},\"samples_taken\":{},\"complete\":{},\"definitions\":{:?},\"diagnostics\":{:?},\"p50_ms\":{:.3},\"p95_ms\":{:.3},\"max_ms\":{:.3}}}",
                measurement.row,
                site.path,
                site.line,
                site.column,
                site.token,
                site.callable,
                site.language,
                measurement.status,
                measurement.timed_out,
                measurement.samples.len(),
                measurement.complete,
                measurement.definitions,
                measurement.diagnostics,
                measurement.percentile(50.0).as_secs_f64() * 1_000.0,
                measurement.percentile(95.0).as_secs_f64() * 1_000.0,
                measurement.percentile(100.0).as_secs_f64() * 1_000.0,
            )
        })
        .collect::<Vec<_>>();

    let receipt = format!(
        "{{\"receipt\":\"rust_point_latency_2767\",\"label\":\"{}\",\"corpus_revision\":\"{}\",\"corpus_root\":\"{}\",\"languages\":{:?},\"sites_artifact_sha256\":\"{}\",\"site_count\":{},\"samples_per_site\":{},\"site_bound_ms\":{},\"timed_out_rows\":{:?},\"total_samples\":{},\"build_slot\":\"{}\",\"exclusive\":{},\"profile\":\"{}\",\"bifrost_parallelism\":\"{}\",\"rayon_num_threads\":\"{}\",\"warm_index_build_ms\":{:.3},\"usage_graph_cache_bytes_before\":{},\"usage_graph_cache_bytes_after\":{},\"overall_p95_ms\":{:.3},\"sites\":[{}]}}",
        label,
        CORPUS_REVISION_2767,
        root.display(),
        languages
            .iter()
            .map(|language| language.config_label())
            .collect::<Vec<_>>(),
        sites_artifact_sha256(),
        sites.len(),
        samples,
        site_bound.as_millis(),
        measurements
            .iter()
            .filter(|measurement| measurement.timed_out)
            .map(|measurement| measurement.row)
            .collect::<Vec<_>>(),
        all.len(),
        exclusive_slot,
        exclusive_slot == "exclusive",
        if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        },
        std::env::var("BIFROST_PARALLELISM").unwrap_or_else(|_| "unset".to_owned()),
        std::env::var("RAYON_NUM_THREADS").unwrap_or_else(|_| "unset".to_owned()),
        build_elapsed.as_secs_f64() * 1_000.0,
        graph_cache_before,
        graph_cache_after,
        overall_p95.as_secs_f64() * 1_000.0,
        rows.join(","),
    );
    println!("{receipt}");
    if let Some(path) = std::env::var_os("BIFROST_2767_RECEIPT") {
        std::fs::write(&path, format!("{receipt}\n"))
            .unwrap_or_else(|error| panic!("write the #2767 latency receipt: {error}"));
    }

    // This harness measures; it does not adjudicate. The 100 ms acceptance
    // threshold belongs to the run the integrator labels acceptance, after the
    // schema batch lands, so a baseline run reports rather than fails.
    assert_eq!(measurements.len(), sites.len());
}

/// The three R2.3 work axes for one point request.
///
/// Named here rather than read off `ResolutionBatchMetrics` at each call site,
/// because the pin is about these three quantities and nothing else. The full
/// metrics are still printed beside them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PointWorkAxes {
    /// Charged prefix and receiver evaluation steps for this request.
    prefix_evaluations: usize,
    /// Distinct candidate partial paths hydrated.
    hydrations: usize,
    /// Distinct candidate matches read from the source.
    candidate_reads: usize,
}

fn point_work_axes(measurement: &ProductionRustPointScaleMeasurement) -> PointWorkAxes {
    PointWorkAxes {
        prefix_evaluations: measurement.receiver_work.scope_nodes,
        hydrations: measurement.point_metrics.distinct_path_hydrations(),
        candidate_reads: measurement.point_metrics.distinct_candidate_matches(),
    }
}

/// R2.3 work axes for the same request against growing unrelated inventory.
///
/// All three axes are constant now: candidate reads and hydrations remain
/// four and charged scope work remains 330 at 256, 1,024 and 2,048 mounts.
/// The pin asserted a linear bound while the interior's candidate index was
/// keyed by the endpoint node alone, which charged a request two rejected
/// root halves per selected mount. The index is keyed by the first fixed
/// symbol admission checks as well, so nothing here scales with the
/// inventory and the assertion is constancy. Row-backed preparation issues no
/// SQL. Search statement/row counts are recorded separately and still include
/// selected-inventory work; they are not asserted constant.
///
/// The open column is the *cold* open: each size gets a fresh fixture, so this
/// is the first open of that workspace and it is expected to scale. R2.1's
/// retained selection is about the second and later opens of the same
/// workspace, which this pin does not exercise and must not be read as
/// contradicting.
#[test]
#[ignore = "explicit stack-graph R2.3 unrelated-inventory point work pin"]
fn ignored_rust_point_work_axes_across_unrelated_mounts() {
    let mut rows = Vec::new();
    for source_mount_count in [256, 1_024, 2_048] {
        let measurement = measure_production_rust_point_scale(
            &RustRootResolutionOperationFixture::new_with_source_mount_count(source_mount_count),
        );
        let axes = point_work_axes(&measurement);
        println!(
            "{{\"pin\":\"rust_point_work_axes\",\"source_mounts\":{source_mount_count},\"prefix_evaluations\":{},\"hydrations\":{},\"candidate_reads\":{},\"cold_open_statements\":{},\"cold_open_decoded_rows\":{},\"context_statements\":{},\"context_decoded_rows\":{},\"resolve_statements\":{},\"resolve_decoded_rows\":{},\"search_statements\":{},\"search_decoded_rows\":{},\"reference_seeds\":{},\"composition_attempts\":{},\"successful_stitches\":{},\"worklist_rounds\":{}}}",
            axes.prefix_evaluations,
            axes.hydrations,
            axes.candidate_reads,
            measurement.open.statement_count(),
            measurement.open.decoded_rows,
            measurement.context.statement_count(),
            measurement.context.decoded_rows,
            measurement.resolve.statement_count(),
            measurement.resolve.decoded_rows,
            measurement.search.statement_count(),
            measurement.search.decoded_rows,
            measurement.point_metrics.reference_seeds(),
            measurement.point_metrics.composition_attempts(),
            measurement.point_metrics.successful_stitches(),
            measurement.point_metrics.worklist_rounds(),
        );
        rows.push((source_mount_count, axes));
    }
    for window in rows.windows(2) {
        let (smaller, small_axes) = window[0];
        let (larger, large_axes) = window[1];
        assert_eq!(
            small_axes.hydrations, large_axes.hydrations,
            "hydrations moved between {smaller} and {larger} unrelated mounts"
        );
        assert_eq!(
            small_axes.candidate_reads, large_axes.candidate_reads,
            "candidate reads moved between {smaller} and {larger} unrelated mounts"
        );
        // The request's charged work does not depend on how much unrelated
        // inventory the workspace holds. A linear bound used to be the most
        // this could claim; nothing on the path scales with the inventory
        // now, so equality is the property and a linear bound would hide a
        // regression back into per-mount work.
        assert_eq!(
            small_axes.prefix_evaluations, large_axes.prefix_evaluations,
            "charged prefix evaluations moved between {smaller} and {larger} unrelated mounts"
        );
    }
}

// Thread-local accounting follows the bridge-inventory constancy pin: reset
// neither process-wide counters nor other tests' work. These fixtures build
// selected contexts synchronously. SQLite's C allocator is intentionally out
// of scope: this measures Rust heap residency, not RSS or allocator overhead.
struct HeapPinAllocator;
thread_local! {
    static HEAP_PIN_BYTES: std::cell::Cell<i64> = const { std::cell::Cell::new(0) };
}
#[global_allocator]
static HEAP_PIN_ALLOCATOR: HeapPinAllocator = HeapPinAllocator;

unsafe impl std::alloc::GlobalAlloc for HeapPinAllocator {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        let pointer = unsafe { std::alloc::System.alloc(layout) };
        if !pointer.is_null() {
            HEAP_PIN_BYTES.with(|bytes| bytes.set(bytes.get() + layout.size() as i64));
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: std::alloc::Layout) {
        HEAP_PIN_BYTES.with(|bytes| bytes.set(bytes.get() - layout.size() as i64));
        unsafe { std::alloc::System.dealloc(pointer, layout) };
    }

    unsafe fn realloc(
        &self,
        pointer: *mut u8,
        layout: std::alloc::Layout,
        new_size: usize,
    ) -> *mut u8 {
        let result = unsafe { std::alloc::System.realloc(pointer, layout, new_size) };
        if !result.is_null() {
            HEAP_PIN_BYTES.with(|bytes| {
                bytes.set(bytes.get() + new_size as i64 - layout.size() as i64);
            });
        }
        result
    }
}

pub(crate) fn heap_pin_bytes() -> i64 {
    HEAP_PIN_BYTES.with(std::cell::Cell::get)
}

// Reuse the persisted inline source harness with distinct existing target
// roots. Each target has normal and test profiles. This varies profiles
// independently of files, without introducing detached-file profiles.
fn heap_pin_fixture(files: usize, profiles: usize) -> RustRootResolutionOperationFixture {
    assert!(profiles >= 4 && profiles.is_multiple_of(2));
    assert_eq!(
        AnalyzerConfig::default().parallelism(),
        1,
        "heap pins require synchronous context construction (BIFROST_PARALLELISM=1)"
    );
    let mut fixture = RustRootResolutionOperationFixture::new_with_source_mount_count(files);
    let mut manifest = String::from(
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2024\"\nautobins = false\n[dependencies]\nengine = { path = \"../engine\" }\n",
    );
    for index in 0..profiles / 2 - 2 {
        manifest.push_str(&format!(
            "[[bin]]\nname = \"profile_{index}\"\npath = \"src/scale_{index:04}.rs\"\n"
        ));
    }
    fixture.selected_manifests[0] =
        RustSelectedManifestMount::from_source("app/Cargo.toml", &manifest)
            .expect("heap pin manifest");
    let snapshot = sync_rust_operation_inputs(
        &fixture.store,
        &fixture.workspace_id,
        fixture.generation,
        fixture._project_root.path(),
        &fixture.source_rows(),
        &fixture.selected_manifests,
    )
    .expect("publish heap pin profiles");
    fixture.snapshots.get_mut("rust").unwrap().revision = snapshot.revision;
    fixture
}

/// A lexical source retains nothing that scales with the selection.
///
/// Source construction formerly retained maps sized by the mount count. The
/// inventory now owns ordinal/path authority and both row readers use
/// SelectedResolutionAuthority. Subtract the typed reader's construction
/// cost to isolate the lexical reader's additional retained bytes; this
/// amount must not grow with the selected mount count.
#[test]
fn rust_lexical_source_retained_bytes_are_independent_of_the_selection() {
    let rows = [8_usize, 64].map(|files| {
        let fixture = RustRootResolutionOperationFixture::new_with_source_mount_count(files);
        let cancellation = CancellationToken::default();
        let operation = fixture.open_ready(&cancellation);
        let mounts = operation.mount_table().mount_count();

        let before_typed = heap_pin_bytes();
        let typed = operation.ready.typed_source();
        let typed_retained = heap_pin_bytes() - before_typed;
        drop(typed);

        let before_lexical = heap_pin_bytes();
        let lexical = operation.ready.lexical_source();
        let lexical_retained = heap_pin_bytes() - before_lexical;
        drop(lexical);

        (files, mounts, lexical_retained - typed_retained)
    });
    eprintln!(
        "lexical source retained beyond its typed source (files, selected mounts, bytes): {rows:?}"
    );
    assert!(
        rows[1].1 > rows[0].1,
        "the larger workspace must hold more selected mounts for this pin to mean anything: {rows:?}"
    );
    assert_eq!(
        rows[0].2, rows[1].2,
        "lexical source construction must retain the same bytes whatever the selection holds: {rows:?}"
    );
}

/// A query's rebaser learns nothing from a persisted mount.
///
/// It used to learn everything. `register_identity_catalog` walked a blob's
/// whole identity catalog into the rebaser the first time any reader opened
/// that mount, and a frontier opens every blob that carries a candidate site,
/// so one tract reverse frontier taught it 1,974,097 semantics, 394,894
/// nodes, 432,242 paths and 156,273 stack variables and held 1.24 GiB of live
/// heap (RM-2). A fragment-local runtime ID now names its own mount in bytes
/// 0..8 and a persisted node, path or stack variable carries its storage-local
/// key in its last eight bytes, so a reader that wants a coordinate decodes
/// one, and a fragment-local semantic's key is the position it occupies in its
/// mount's persisted identity catalog, read by its requested key.
///
/// The measurement is the rebaser's own fragment-local entry count at the end
/// of a whole-workspace point request, and the oracle is the one every other
/// pin here uses: run the same request over selections of different sizes and
/// require the number not to move. Files and crates vary independently, so a
/// per-mount or per-crate residue shows up as growth.
#[test]
fn rust_whole_workspace_point_rebaser_identities_are_independent_of_the_selection() {
    let rows = [(32, 8), (64, 8), (64, 16)].map(|(files, profiles)| {
        let fixture = heap_pin_fixture(files, profiles);
        let reference = site_for_identifier(
            &fixture.consumer_facts,
            "alias",
            ResolutionIdentifierRole::Reference,
            ResolutionNamespace::Value,
        );
        let range = fixture
            .consumer_facts
            .sites
            .iter()
            .find(|site| site.id == reference)
            .unwrap();
        let locator = SelectedSemanticLocator::for_reference_range(
            "rust",
            RUST_ROOT_CONSUMER_PATH,
            range.start_byte,
            range.end_byte,
        );
        let cancellation = CancellationToken::default();
        let operation = fixture.open_ready(&cancellation);
        let mounts = operation.mount_table().mount_count();
        let _ = super::take_rebaser_identities_at_handback_for_test();
        operation
            .resolve_rust_reference_for_caller_bounded(
                Path::new(RUST_ROOT_CONSUMER_PATH),
                &locator,
                ReceiverAnalysisBudget::default(),
                &cancellation,
                &mut SelectedResolutionContextMetrics,
                &mut ResolutionBatchMetrics::default(),
            )
            .expect("the whole-workspace point request answers");
        let identities = super::take_rebaser_identities_at_handback_for_test();
        (files, profiles / 2, mounts, identities)
    });
    eprintln!(
        "whole-workspace point rebaser fragment-local identities \
         (files, crates, selected mounts, [semantics, nodes, paths, variables]): {rows:?}"
    );
    assert!(
        rows[1].2 > rows[0].2,
        "the larger workspace must hold more selected mounts for this pin to mean anything: {rows:?}"
    );
    assert_eq!(
        rows[0].3, rows[1].3,
        "a point request must retain the same rebaser identities whatever the file count: {rows:?}"
    );
    assert_eq!(
        rows[1].3, rows[2].3,
        "a point request must retain the same rebaser identities whatever the crate count: {rows:?}"
    );
}

#[test]
fn rust_whole_workspace_point_retained_bytes_are_bounded_by_shared_name_cache() {
    fn statement_storage_release(reader: crate::analyzer::store::ReaderGuard<'_>) -> (usize, i64) {
        // Called only after original retained bytes have been captured. This
        // diagnostic measures Rust destructor releases, not SQLite C memory,
        // and does not use post-disposal heap as the acceptance measurement.
        let mut statements = 0;
        unsafe {
            let mut statement =
                rusqlite::ffi::sqlite3_next_stmt(reader.handle(), std::ptr::null_mut());
            while !statement.is_null() {
                statements += 1;
                statement = rusqlite::ffi::sqlite3_next_stmt(reader.handle(), statement);
            }
        }
        // cache_db.rs configures this existing production cache with 256
        // entries. This is a pin of that cap, not a new retention allowance.
        assert!(
            statements <= 256,
            "existing prepared statement entry cap: {statements}"
        );
        let before = heap_pin_bytes();
        reader.flush_prepared_statement_cache();
        let released = before - heap_pin_bytes();
        (statements, released)
    }

    let rows = [(32, 8), (64, 8), (64, 16)].map(|(files, profiles)| {
        let control = heap_pin_fixture(files, profiles);
        let control_statements =
            statement_storage_release(control.store.active_read_conn().unwrap());
        drop(control);
        let fixture = heap_pin_fixture(files, profiles);
        let reference = site_for_identifier(
            &fixture.consumer_facts,
            "alias",
            ResolutionIdentifierRole::Reference,
            ResolutionNamespace::Value,
        );
        let range = fixture
            .consumer_facts
            .sites
            .iter()
            .find(|site| site.id == reference)
            .unwrap();
        let locator = SelectedSemanticLocator::for_reference_range(
            "rust",
            RUST_ROOT_CONSUMER_PATH,
            range.start_byte,
            range.end_byte,
        );
        let cancellation = CancellationToken::default();
        let shared_names = fixture.store.resolution_shared_name_cache().clone();
        let cache_before = shared_names.allocated_bytes();
        let static_sql_before = crate::analyzer::store::resolution_selection::selected_static_sql_capacities();
        let before = heap_pin_bytes();
        let operation = fixture.open_ready(&cancellation);
        let request_reader_handle =
            unsafe { operation.ready.inventory.connection().handle() as usize };
        let SelectedRustContextOutcome::Ready(context) = operation
            .rust_context_for_all_crates(&cancellation)
            .unwrap()
        else {
            panic!("fixture has a complete selected Rust workspace");
        };
        // The context is the whole workspace's, but the request still answers
        // one file's reference, so the scope it binds inside is that file's
        // crates, exactly as a production point request's is.
        let crate_keys = operation
            .rust_crate_keys_for_file(Path::new(RUST_ROOT_CONSUMER_PATH), &cancellation)
            .unwrap();
        let outcome = operation
            .with_rust_forward_queries_in_session(
                context,
                &crate_keys,
                &[Path::new(RUST_ROOT_CONSUMER_PATH)],
                &cancellation,
                &mut SelectedResolutionContextMetrics,
                &ResolutionSession::unbounded(),
                |queries| {
                    let SelectedResolutionOperationOutcome::Native(
                        SelectedResolutionLocated::Found(answer),
                    ) = queries
                        .resolve_reference(&locator, &mut ResolutionBatchMetrics::default())?
                    else {
                        panic!("whole-workspace point must produce a native answer");
                    };
                    assert_eq!(answer.definitions.len(), 1);
                    Ok(())
                },
            )
            .unwrap();
        assert!(matches!(
            outcome,
            SelectedResolutionOperationOutcome::Native(())
        ));
        // Capture the original post-request measurement before diagnostic
        // disposal. Attribute only measured growth of bounded caches and
        // naturally initialized fixed SQL, never a capacity allowance or
        // post-flush heap value.
        let retained = heap_pin_bytes() - before;
        let cache_growth = shared_names.allocated_bytes() - cache_before;
        let raw_outside_shared = retained - cache_growth;
        let diagnostic_reader = fixture.store.active_read_conn().unwrap();
        assert_eq!(
            unsafe { diagnostic_reader.handle() as usize },
            request_reader_handle,
            "statement storage attribution must inspect the completed request's SQLite reader"
        );
        let request_statements = statement_storage_release(diagnostic_reader);
        let static_sql_after = crate::analyzer::store::resolution_selection::selected_static_sql_capacities();
        eprintln!("static SQL allocation ownership files={files} profiles={profiles}: before={static_sql_before:?}, after={static_sql_after:?}");
        let statement_growth = request_statements.1 - control_statements.1;
        let static_sql_growth: i64 = static_sql_before
            .into_iter()
            .zip(static_sql_after)
            .map(|((before_name, before), (after_name, after))| {
                assert_eq!(before_name, after_name);
                (after as i64 - before as i64).max(0)
            })
            .sum();
        let outside_owned_storage =
            (raw_outside_shared - statement_growth.max(0) - static_sql_growth).max(0);
        (
            files,
            profiles / 2,
            retained,
            cache_growth,
            control_statements,
            request_statements,
            statement_growth,
            raw_outside_shared,
            static_sql_growth,
            outside_owned_storage,
        )
    });
    eprintln!(
        "whole-workspace point retained (files, crates, raw bytes, shared growth, control statement(count,bytes), request statement(count,bytes), signed statement growth, raw outside shared, natural fixed SQL growth, adjusted outside bounded caches and fixed SQL; statement cap=64): {rows:?}"
    );
    let minimum_outside_storage = rows.iter().map(|row| row.9).min().unwrap();
    let maximum_outside_storage = rows.iter().map(|row| row.9).max().unwrap();
    assert!(
        maximum_outside_storage <= 16 * 1024
            && maximum_outside_storage - minimum_outside_storage <= 16 * 1024,
        "query-retained bytes beyond measured growth of the existing shared-name cache, 64-entry statement cache, and naturally initialized fixed SQL strings must have only the existing 16 KiB allowance independent of workspace files and crates: {rows:?}"
    );
}

/// One point request's SQL work is independent of unrelated workspace files.
#[test]
fn rust_point_request_sql_work_does_not_grow_with_the_workspace() {
    let rows = [32usize, 64].map(|files| {
        let fixture = RustRootResolutionOperationFixture::new_with_source_mount_count(files);
        let reference = site_for_identifier(
            &fixture.consumer_facts,
            "alias",
            ResolutionIdentifierRole::Reference,
            ResolutionNamespace::Value,
        );
        let range = fixture
            .consumer_facts
            .sites
            .iter()
            .find(|site| site.id == reference)
            .expect("the consumer reference site");
        let locator = SelectedSemanticLocator::for_reference_range(
            "rust",
            RUST_ROOT_CONSUMER_PATH,
            range.start_byte,
            range.end_byte,
        );
        let cancellation = CancellationToken::default();
        begin_production_selected_sql_trace(&fixture.store);
        let operation = fixture.open_ready(&cancellation);
        let _open = checkpoint_production_selected_sql_trace();
        let answer = operation
            .resolve_rust_reference_for_caller_bounded(
                Path::new(RUST_ROOT_CONSUMER_PATH),
                &locator,
                ReceiverAnalysisBudget::default(),
                &cancellation,
                &mut SelectedResolutionContextMetrics,
                &mut ResolutionBatchMetrics::default(),
            )
            .expect("the point request answers");
        assert!(
            matches!(answer, BoundedResolution::Complete { .. }),
            "the point fixture must answer inside its budget at {files} files"
        );
        let work = finish_production_selected_sql_trace(&fixture.store);
        (files, work.statement_count(), work.decoded_rows)
    });
    eprintln!("request SQL work (files, statements, decoded rows): {rows:?}");
    assert_eq!(
        (rows[0].1, rows[0].2),
        (rows[1].1, rows[1].2),
        "unrelated files must not add request SQL statements or decoded rows: {rows:?}"
    );
}

/// A member call whose receiver type is unknown opens the blobs that declare
/// that member, not the blobs that mention its name.
///
/// `visit_deferred_member_owner_pages_for_lookup_names` used to take its mounts
/// from a name-mention relation that said which blobs mention an identity
/// anywhere. For an ordinary member name that is most of the workspace, and
/// lane CP measured the read opening those interiors as 88 percent of a
/// reverse confirmation's productions. It now takes them from the
/// `DeferredMemberOwnerLookup` rows of `resolution_typed_fact_lookups`, one row
/// per blob per lookup a deferred member owner is actually declared under.
///
/// The fixture separates the two sets on purpose: every scale blob calls
/// `shared_member` on a receiver it cannot resolve, so every scale blob
/// mentions the name, and exactly one declares a member under it. Under the
/// membership relation the productions grow with the file count; under the
/// declaring relation they do not, which is what this pins.
#[test]
fn deferred_member_lookup_sql_work_does_not_grow_with_the_workspace() {
    let rows = [8usize, 24].map(|files| {
        let fixture =
            RustRootResolutionOperationFixture::new_with_deferred_member_lookup_scale(files);
        let reference = site_for_identifier(
            &fixture.consumer_facts,
            "shared_member",
            ResolutionIdentifierRole::Reference,
            ResolutionNamespace::Callable,
        );
        let range = fixture
            .consumer_facts
            .sites
            .iter()
            .find(|site| site.id == reference)
            .expect("the consumer member reference site");
        let locator = SelectedSemanticLocator::for_reference_range(
            "rust",
            RUST_ROOT_CONSUMER_PATH,
            range.start_byte,
            range.end_byte,
        );
        let cancellation = CancellationToken::default();
        begin_production_selected_sql_trace(&fixture.store);
        let operation = fixture.open_ready(&cancellation);
        let _open = checkpoint_production_selected_sql_trace();
        let mount_callers = SelectedMountCallerTrace::begin();
        operation
            .resolve_rust_reference_for_caller_bounded(
                Path::new(RUST_ROOT_CONSUMER_PATH),
                &locator,
                ReceiverAnalysisBudget::default(),
                &cancellation,
                &mut SelectedResolutionContextMetrics,
                &mut ResolutionBatchMetrics::default(),
            )
            .expect("the member point request answers");
        let work = finish_production_selected_sql_trace(&fixture.store);
        drop(mount_callers);
        eprintln!(
            "deferred member SQL families at {files} files: {:?}",
            work.rows_by_shape()
        );
        (files, work.statement_count(), work.decoded_rows)
    });
    eprintln!("request SQL work (files, statements, decoded rows): {rows:?}");
    assert_eq!(
        (rows[0].1, rows[0].2),
        (rows[1].1, rows[1].2),
        "unrelated files must not add request SQL statements or decoded rows: {rows:?}"
    );
}

/// A member call on a primitive receiver opens only the blobs that can answer.
///
/// The forward member evaluation reaches the intrinsic-seed read with every
/// owner that has no member scope, because `usize` has none either and an
/// intrinsic owner is a boundary the route may decide rather than a producer
/// shortfall. It also asks that owner for its visibility, its member scope,
/// its construction requirements and its property gaps. For a primitive
/// receiver all five requests name the same workspace-shared identity, so all
/// five take `semantic_coordinates`' shared branch, and this is what each of
/// them now resolves to:
///
/// - `IntrinsicSeedTypeIdentity` names the blobs that seed `usize`, which in
///   this fixture is every scale blob, and it grows with the workspace. That
///   is correct and no header family can bound it: an intrinsic identity
///   enters a blob's catalog only where the seed loop puts it, so the blobs
///   that mention one are the blobs that seed one. Lane G1 measured that
///   equality on the Bifrost store; this measures it from a point request.
/// - the four definition-keyed relations name **no blob at all**, at either
///   size. An intrinsic identity is no blob's definition, so no blob holds a
///   visibility, member scope, construction requirement or property gap row
///   under it. Through the name-mention relation each of these four opened
///   the same set the intrinsic read opens, because for an intrinsic identity
///   mention and seed are the same set. The point request's shared reads
///   therefore go from five mount sets of that size to one.
///
/// This is the call lane G1 looked for and did not find. G1 wrote a standalone
/// intrinsic-seed family, measured it as answering nothing, and removed it;
/// what the generic family buys here is not on the intrinsic read at all, it
/// is on the four reads asked the same question that cannot possibly answer.
#[test]
fn an_intrinsic_owner_opens_only_the_blobs_that_seed_it() {
    use crate::analyzer::store::resolution::TypedFactRelation;
    use crate::analyzer::store::resolution_typed::shared_request_probe;

    const CANNOT_ANSWER: [TypedFactRelation; 4] = [
        TypedFactRelation::DeclarationVisibilityDefinition,
        TypedFactRelation::MemberScopeDefinition,
        TypedFactRelation::ConstructionRequirementDefinition,
        TypedFactRelation::DefinitionPropertyGapDefinition,
    ];

    let rows = [8usize, 24].map(|files| {
        let fixture = RustRootResolutionOperationFixture::new_with_intrinsic_owner_scale(files);
        let reference = site_for_identifier(
            &fixture.consumer_facts,
            "shared_member",
            ResolutionIdentifierRole::Reference,
            ResolutionNamespace::Callable,
        );
        let range = fixture
            .consumer_facts
            .sites
            .iter()
            .find(|site| site.id == reference)
            .expect("the consumer member reference site");
        let locator = SelectedSemanticLocator::for_reference_range(
            "rust",
            RUST_ROOT_CONSUMER_PATH,
            range.start_byte,
            range.end_byte,
        );
        let cancellation = CancellationToken::default();
        let operation = fixture.open_ready(&cancellation);
        shared_request_probe::reset();
        operation
            .resolve_rust_reference_for_caller_bounded(
                Path::new(RUST_ROOT_CONSUMER_PATH),
                &locator,
                ReceiverAnalysisBudget::default(),
                &cancellation,
                &mut SelectedResolutionContextMetrics,
                &mut ResolutionBatchMetrics::default(),
            )
            .expect("the member point request answers");
        let entered = shared_request_probe::observed_all();
        let seed = shared_request_probe::observed(TypedFactRelation::IntrinsicSeedTypeIdentity);
        let cannot = CANNOT_ANSWER.map(shared_request_probe::observed);
        (files, entered, seed, cannot)
    });
    for (files, entered, seed, cannot) in &rows {
        eprintln!(
            "intrinsic owner, {files} files: shared reads {entered:?}; \
             intrinsic seed {seed:?}; cannot answer {cannot:?}"
        );
        assert!(
            seed.0 > 0,
            "the intrinsic-seed read must be entered with a shared owner \
             identity at {files} files, or this pin measures nothing"
        );
        for (relation, observed) in CANNOT_ANSWER.into_iter().zip(*cannot) {
            assert!(
                observed.0 > 0,
                "{} must be asked about the same owner at {files} files",
                relation.label()
            );
            assert_eq!(
                observed.1,
                0,
                "{} must name no blob for an intrinsic owner at {files} files",
                relation.label()
            );
        }
    }
    assert!(
        rows[1].2.1 > rows[0].2.1,
        "the blobs that seed the owner grow with the workspace, and the \
         intrinsic read must open them: {:?} then {:?}",
        rows[0].2,
        rows[1].2
    );
}

/// Every statement one point request issues against `rust_crate_container_sources`.
///
/// The table is where a Rust file's crate placement lives, and the textual
/// macro walk is what reads it by path. On tract a median warm definition
/// request issued 323 of these statements and a slow one 10,468, so the
/// question this measurement answers is what those counts are a function of.
fn macro_walk_statements(project: &crate::inline_project::BuiltInlineTestProject) -> usize {
    use crate::searchtools::GetDefinitionParams;
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let query = || GetDefinitionParams {
        references: vec![DefinitionReferenceQuery {
            path: "src/host0.rs".to_owned(),
            line: Some(1),
            column: Some(32),
        }],
    };
    // One unmeasured call builds the index and every per-file preparation the
    // request retains, so what is counted below is a warm request.
    let warm = get_definitions_by_location_with_cancellation(analyzer.analyzer(), query(), None);
    assert_eq!(warm.results.len(), 1, "one reference query, one result");
    let store = analyzer.store().expect("the inline workspace has a store");
    begin_production_selected_sql_trace(store);
    let measured =
        get_definitions_by_location_with_cancellation(analyzer.analyzer(), query(), None);
    let cost = finish_production_selected_sql_trace(store);
    assert_eq!(measured.results[0].status, warm.results[0].status);
    cost.statements
        .iter()
        .filter(|sql| sql.contains("rust_crate_container_sources"))
        .count()
}

/// One crate, one macro host per file, `hosts` files, one invocation each.
/// The point request is always at the same reference in `src/host0.rs`.
fn macro_host_project(
    hosts: usize,
    invocations: usize,
) -> crate::inline_project::BuiltInlineTestProject {
    use crate::inline_project::InlineTestProject;
    assert!(hosts >= 1 && invocations >= 1);
    let mut lib = String::from("#[macro_use]\nmod macros;\npub fn target() -> i32 { 1 }\n");
    for host in 0..hosts {
        lib.push_str(&format!("pub mod host{host};\n"));
    }
    let mut project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"demo\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .file(
            "src/macros.rs",
            "macro_rules! shout { ($value:expr) => { $value }; }\n",
        )
        .file("src/lib.rs", lib);
    for host in 0..hosts {
        // Line 1 of every host is the reference the query asks about, so the
        // same position works whatever `hosts` is.
        let mut source = String::from("pub fn entry() -> i32 { crate::target() }\n");
        for invocation in 0..invocations {
            source.push_str(&format!(
                "pub fn call{invocation}() -> i32 {{ shout!(crate::target()) }}\n"
            ));
        }
        project = project.file(format!("src/host{host}.rs"), source);
    }
    project.build()
}

/// A point request's crate-placement reads are a function of its own file.
///
/// `prepare_selected_macro_reference_overlay` prepares the files a request
/// names, and the walk under it reads `rust_crate_container_sources` by path.
/// Neither may become a function of how many other files in the crate host a
/// macro: those files are not what the request asked about, and on a crate
/// with hundreds of macro hosts that difference is the request's whole cost.
#[test]
fn rust_point_request_macro_walk_is_independent_of_the_crate_s_macro_hosts() {
    let rows =
        [1_usize, 40].map(|hosts| (hosts, macro_walk_statements(&macro_host_project(hosts, 1))));
    eprintln!("point request crate-placement statements (macro hosts, statements): {rows:?}");
    assert!(
        rows[0].1 > 0,
        "the request must read crate placements at all for this pin to mean anything: {rows:?}"
    );
    assert_eq!(
        rows[0].1, rows[1].1,
        "a point request must issue the same crate-placement statements whatever \
         else in its crate hosts a macro: {rows:?}"
    );
}

/// What one more macro invocation in the request's own file costs it.
///
/// The walk climbs the crate's macro-visible module ancestry, and it used to
/// climb it once per invocation and then again for the same invocation,
/// because nothing held the answer: `linalg/src/generic/rounding.rs` holds 214
/// invocations and one request at that file issued 286,574 of these
/// statements, 1,339 per invocation. The answers now belong to the request, so
/// the ancestry is walked once and an invocation adds only its own frame.
///
/// The bound is deliberately a bound and not an exact count: what must not
/// come back is the multiplication, and a fixture's module tree is not the
/// quantity this pin is about.
#[test]
fn rust_point_request_macro_walk_costs_a_bounded_amount_per_invocation() {
    const MAXIMUM_STATEMENTS_PER_INVOCATION: usize = 6;
    let rows = [1_usize, 40].map(|invocations| {
        (
            invocations,
            macro_walk_statements(&macro_host_project(1, invocations)),
        )
    });
    eprintln!("point request crate-placement statements (invocations, statements): {rows:?}");
    let slope = (rows[1].1 - rows[0].1) as f64 / (rows[1].0 - rows[0].0) as f64;
    assert!(
        slope <= MAXIMUM_STATEMENTS_PER_INVOCATION as f64,
        "one more macro invocation in the caller must cost at most \
         {MAXIMUM_STATEMENTS_PER_INVOCATION} crate-placement statements, not a \
         walk of the crate's module ancestry: {rows:?}, slope {slope:.1}"
    );
}
