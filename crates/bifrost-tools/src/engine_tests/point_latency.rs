#[cfg(test)]
mod surface_tests {
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

    use std::collections::BTreeSet;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::selected_sql_trace::begin_production_selected_sql_trace;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::selected_sql_trace::finish_production_selected_sql_trace;

    use brokk_bifrost_core::analyzer::project::FilesystemProject;

    use brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer;

    use brokk_bifrost_core::analyzer::config::AnalyzerConfig;

    use crate::searchtools::{
        DefinitionReferenceQuery, GetDefinitionParams,
        get_definitions_by_location_with_cancellation,
    };
    use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

    /// One adjudicated #2767 candidate, addressed by the exact reference that
    /// reaches it.
    ///
    /// A latency site is the caller's reference token, because a point query is
    /// issued at a reference, not at a declaration. `token` is checked against
    /// the corpus source before any measurement runs, so a site that drifted fails
    /// loudly instead of silently measuring a different call.
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
        let token = brokk_bifrost_core::cancellation::CancellationToken::new().with_timeout(bound);
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
        let exclusive_slot =
            std::env::var("BIFROST_BUILD_SLOT").unwrap_or_else(|_| "unset".to_owned());
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
        let warm =
            get_definitions_by_location_with_cancellation(analyzer.analyzer(), query(), None);
        assert_eq!(warm.results.len(), 1, "one reference query, one result");
        let store = analyzer.store().expect("the inline workspace has a store");
        begin_production_selected_sql_trace(store);
        let measured =
            get_definitions_by_location_with_cancellation(analyzer.analyzer(), query(), None);
        let cost = finish_production_selected_sql_trace(store);
        assert_eq!(measured.results[0].status, warm.results[0].status);
        cost.statements
            .iter()
            // The summary placement rows are the crate-placement reads now; the
            // legacy `rust_crate_container_sources` table is no longer read here.
            .filter(|sql| sql.contains("rust_unit_summary_placements"))
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
    /// names, and the walk under it reads the summary placement rows by member.
    /// Neither may become a function of how many other files in the crate host a
    /// macro: those files are not what the request asked about, and on a crate
    /// with hundreds of macro hosts that difference is the request's whole cost.
    #[test]
    fn rust_point_request_macro_walk_is_independent_of_the_crate_s_macro_hosts() {
        let rows = [1_usize, 40]
            .map(|hosts| (hosts, macro_walk_statements(&macro_host_project(hosts, 1))));
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
}
