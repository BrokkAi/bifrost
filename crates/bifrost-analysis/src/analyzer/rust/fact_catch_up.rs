//! Bringing the persisted Rust facts up to date before a usage query reads
//! them.
//!
//! Milestone 3 of `.agents/plans/rust-usage-index-v2.md`. Under v2 a usage
//! answer is composed from the `rust_*` fact rows of live blobs, so a live file
//! whose blob carries no rows is not merely slow to answer -- it is invisible.
//! Analysis persists those rows for every file it reconciles, so the gap is
//! narrow: a store write that failed and left a dirty in-memory state, or a
//! blob that reached the live set without ever being persisted.
//!
//! The policy is IntelliJ's small-change lazy catch-up (research report section
//! 5.2, `ChangedFilesCollector.ensureUpToDateAsync`, whose own threshold is
//! twenty): below [`RUST_FACT_CATCH_UP_INLINE_LIMIT`] files, re-parse and
//! persist them on the querying thread, so a single-file edit never surfaces a
//! readiness state at all; at or above it, hand the batch to the dedicated
//! build pool and report the readiness probe false until it drains.
//!
//! There is no index to build here, which is the whole point: the "warm" is
//! this same catch-up, and on a healthy workspace it finds nothing to do.

use std::sync::Mutex;

use crate::analyzer::{PoolSafeMemo, ProjectFile, spawn_on_dedicated_build_pool};

use super::RustAnalyzer;

/// The changed-file count at which catch-up stops being inline work.
///
/// Twenty is IntelliJ's own boundary between "bring these up to date on the
/// asking thread" and "hand this to the background pass". Below it a query
/// blocks for a handful of re-parses, which is cheaper than the round trip a
/// caller would need to discover it should wait.
pub(super) const RUST_FACT_CATCH_UP_INLINE_LIMIT: usize = 20;

/// One analyzer generation's catch-up state.
///
/// Lives behind an `Arc` on [`RustAnalyzer`] and is created fresh by `update` /
/// `update_all`, like every other cache there: a new generation has a new live
/// file set, so its catch-up question is a new question.
pub(super) struct RustFactCatchUp {
    /// Single-flight for the scan plus whatever it decides to do. A
    /// `PoolSafeMemo` because a usage query reaches this from inside its own
    /// rayon fan-out, where blocking on a builder can deadlock the pool
    /// (issue #549); the pool-safe rule there is a duplicate serial run, which
    /// for this side-effecting work costs at most a repeated parse of the same
    /// files and cannot produce a wrong row.
    settled: PoolSafeMemo<()>,
    /// Completing a scheduling attempt is not proof that publication succeeded.
    readiness: Mutex<RustFactReadiness>,
    /// Test hook: a deferred batch waits here before it runs, so a test can
    /// observe the probe in its false state without a sleep. Follows the
    /// injection hooks the persistence path already carries
    /// (`should_inject_preparation_failure_for_test`).
    #[cfg(test)]
    gate: std::sync::Mutex<Option<std::sync::Arc<std::sync::Barrier>>>,
}

#[derive(Clone, Debug)]
enum RustFactReadiness {
    Unverified,
    Pending,
    Ready,
    Unavailable(crate::analyzer::store::StoreError),
}

impl RustFactCatchUp {
    pub(super) fn new() -> Self {
        Self {
            settled: PoolSafeMemo::new(),
            readiness: Mutex::new(RustFactReadiness::Unverified),
            #[cfg(test)]
            gate: std::sync::Mutex::new(None),
        }
    }
}

impl RustAnalyzer {
    /// Ensure every live Rust file's blob carries fact rows before a query
    /// reads them. Runs at most once per analyzer generation.
    ///
    /// Called by explicit background preparation, never by a route read.
    /// Repeated preparation retains and reports a prior publication failure.
    pub(super) fn ensure_rust_facts_caught_up(&self) {
        self.fact_catch_up.settled.get_or_build(
            || self.run_rust_fact_catch_up(),
            || self.run_rust_fact_catch_up(),
        );
        if let RustFactReadiness::Unavailable(error) = &*self
            .fact_catch_up
            .readiness
            .lock()
            .expect("Rust fact readiness lock poisoned")
        {
            self.inner.record_store_error(error.clone());
        }
    }

    /// Whether this generation's live facts have been verified as published.
    /// An unverified generation, pending repair, or failed repair is not ready.
    ///
    /// This is what `get_active_workspace` reports as `usage_index_ready`.
    pub(crate) fn rust_usage_facts_ready(&self) -> bool {
        matches!(
            *self
                .fact_catch_up
                .readiness
                .lock()
                .expect("Rust fact readiness lock poisoned"),
            RustFactReadiness::Ready
        )
    }

    /// A route reader checked the same exact live publication as preparation.
    /// This verifies an initially unknown generation without starting repair;
    /// it does not override an explicit pending or failed preparation.
    pub(super) fn note_rust_publication_verified(&self) {
        let mut readiness = self
            .fact_catch_up
            .readiness
            .lock()
            .expect("Rust fact readiness lock poisoned");
        if matches!(*readiness, RustFactReadiness::Unverified) {
            *readiness = RustFactReadiness::Ready;
        }
    }

    /// Whether catch-up has settled and verified publication for this generation.
    pub(crate) fn rust_usage_facts_warm(&self) -> bool {
        self.fact_catch_up.settled.is_ready() && self.rust_usage_facts_ready()
    }

    /// Run the catch-up now, from a background warm.
    ///
    /// The v1 counterpart built a seventeen-map workspace index here, which on
    /// a large workspace took minutes and 10.8 GB (#1758). Under v2 there is
    /// nothing to build: analysis already wrote the rows, so a warm start's
    /// only job is to notice the files it did not write.
    pub fn warm_usage_facts(&self) {
        let _scope = crate::profiling::scope("RustAnalyzer::warm_usage_facts");
        self.ensure_rust_facts_caught_up();
    }

    /// Scan for live blobs without fact rows and apply the threshold policy.
    fn run_rust_fact_catch_up(&self) {
        let _scope = crate::profiling::scope("RustAnalyzer::rust_fact_catch_up");
        self.set_rust_fact_readiness(RustFactReadiness::Pending);
        let stale = match self.rust_files_without_facts() {
            Ok(stale) => stale,
            // The probe is the only thing that can say which live blobs lack
            // rows, so a failed probe is not "nothing to catch up" -- reporting
            // it as such leaves the facts stale and the answer silently
            // incomplete (#2325). Record it on the request boundary that
            // already inspects store failures before presenting a successful
            // response, and catch nothing up.
            Err(error) => {
                let error = error.context("rust fact catch-up live-blob probe");
                self.set_rust_fact_readiness(RustFactReadiness::Unavailable(error.clone()));
                self.inner.record_store_error(error);
                return;
            }
        };
        if stale.is_empty() {
            self.set_rust_fact_readiness(RustFactReadiness::Ready);
            return;
        }
        if stale.len() < RUST_FACT_CATCH_UP_INLINE_LIMIT {
            self.inner.persist_live_blobs(&stale);
            self.verify_rust_fact_catch_up();
            return;
        }
        let analyzer = self.clone();
        spawn_on_dedicated_build_pool(move || {
            #[cfg(test)]
            {
                let gate = analyzer
                    .fact_catch_up
                    .gate
                    .lock()
                    .expect("catch-up gate poisoned")
                    .clone();
                if let Some(gate) = gate {
                    gate.wait();
                }
            }
            analyzer.inner.persist_live_blobs(&stale);
            analyzer.verify_rust_fact_catch_up();
        });
    }

    fn set_rust_fact_readiness(&self, readiness: RustFactReadiness) {
        *self
            .fact_catch_up
            .readiness
            .lock()
            .expect("Rust fact readiness lock poisoned") = readiness;
    }

    /// Persistence may skip content that no longer matches its live identity.
    /// Only the publication probe, never completion of the worker, proves ready.
    fn verify_rust_fact_catch_up(&self) {
        let error = match self.rust_files_without_facts() {
            Ok(stale) if stale.is_empty() => {
                self.set_rust_fact_readiness(RustFactReadiness::Ready);
                return;
            }
            Ok(stale) => crate::analyzer::store::StoreError::new(format!(
                "Rust fact catch-up could not publish live files: {stale:?}"
            )),
            Err(error) => error.context("verifying Rust fact catch-up publication"),
        };
        self.set_rust_fact_readiness(RustFactReadiness::Unavailable(error.clone()));
        self.inner.record_store_error(error);
    }

    /// The live Rust files whose current blob carries no persisted facts.
    ///
    /// Indexed batch queries against the store, never a parse. The frozen live
    /// inventory includes incomplete publications; the display-oriented analyzed
    /// file listing would filter out exactly the missing metadata we must repair.
    ///
    /// Catch-up owns the workspace question: it repairs every live file, so it
    /// must ask about every live file. A query's preflight asks
    /// [`Self::rust_files_without_facts_among`] instead.
    pub(super) fn rust_files_without_facts(
        &self,
    ) -> Result<Vec<ProjectFile>, crate::analyzer::store::StoreError> {
        let mounts = self
            .inner
            .live_file_mounts_for_fact_publication_while(&|| true)
            .expect("uninterrupted Rust publication probe");
        self.rust_mounts_without_facts(mounts)
    }

    /// Which of `request_files` carry no persisted Rust facts.
    ///
    /// This is the per-request form of [`Self::rust_files_without_facts`], and
    /// it is what a `usage_graph` preflight asks. A request resolves the files
    /// it named, so a file it never named can neither contribute an edge nor
    /// withhold one, and reading the whole workspace to decide a rooted
    /// request's availability was both a workspace-sized read on every request
    /// and a wrong answer: one factless blob anywhere marked the whole Rust
    /// pass unavailable and cost the request every Rust edge.
    ///
    /// The store read is the same `blobs_with_rust_facts` set membership
    /// restricted to these files' blobs. It stays one statement per 400 oids
    /// rather than an indexed seek per file because the probe is already a
    /// batch of index seeks over `rust_published_fact_blobs`' primary key: a
    /// rooted request of a handful of files issues exactly one statement, and
    /// per-file statements would only add round trips.
    ///
    /// A file with no live blob is not a publication failure. It is the
    /// missing-source case `RustAnalyzer::selected_rust_source` reports when
    /// the projection reaches it, and a file of another language never had a
    /// Rust blob to begin with.
    pub(super) fn rust_files_without_facts_among(
        &self,
        request_files: &[ProjectFile],
    ) -> Result<Vec<ProjectFile>, crate::analyzer::store::StoreError> {
        let snapshot = self.inner.live_path_snapshot();
        let mounts = request_files
            .iter()
            .filter(|file| {
                crate::analyzer::common::language_for_file(file) == crate::analyzer::Language::Rust
            })
            .filter_map(|file| snapshot.oid_for_path(file).map(|oid| (file.clone(), oid)))
            .collect();
        self.rust_mounts_without_facts(mounts)
    }

    /// The members of `mounts` whose blob is absent from the current Rust
    /// publication witness.
    fn rust_mounts_without_facts(
        &self,
        mounts: Vec<(ProjectFile, git2::Oid)>,
    ) -> Result<Vec<ProjectFile>, crate::analyzer::store::StoreError> {
        let oids: Vec<git2::Oid> = mounts.iter().map(|(_, oid)| *oid).collect();
        let generation = self
            .inner
            .language_generation("rust")
            .expect("Rust analyzer has a Rust storage generation");
        let present = self
            .analyzer_store()
            .blobs_with_rust_facts("rust", generation, &oids)?;
        Ok(mounts
            .into_iter()
            .filter(|(_, oid)| !present.contains(oid))
            .map(|(file, _)| file)
            .collect())
    }

    /// Test hook: hold the next deferred batch until the returned barrier is
    /// released, so the false state of the readiness probe is observable
    /// without a timing assumption.
    #[cfg(test)]
    pub(super) fn hold_rust_fact_catch_up_for_test(&self) -> std::sync::Arc<std::sync::Barrier> {
        let gate = std::sync::Arc::new(std::sync::Barrier::new(2));
        *self
            .fact_catch_up
            .gate
            .lock()
            .expect("catch-up gate poisoned") = Some(std::sync::Arc::clone(&gate));
        gate
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::QueryScope;
    use crate::analyzer::{CodeUnitIndex, IAnalyzer, Language, TestProject};
    use std::collections::BTreeSet;
    use std::time::{Duration, Instant};

    fn project(files: &[(String, String)]) -> (tempfile::TempDir, RustAnalyzer) {
        project_with_config(files, crate::analyzer::AnalyzerConfig::default())
    }

    fn project_with_config(
        files: &[(String, String)],
        config: crate::analyzer::AnalyzerConfig,
    ) -> (tempfile::TempDir, RustAnalyzer) {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        for (rel, body) in files {
            ProjectFile::new(root.clone(), rel)
                .write(body)
                .expect("write fixture file");
        }
        let analyzer = RustAnalyzer::new_with_config(
            std::sync::Arc::new(TestProject::new(root, Language::Rust)),
            config,
        );
        // Force the analysis pass that persists the per-file fact rows.
        let _ = analyzer.get_analyzed_files();
        (temp, analyzer)
    }

    fn workspace_of(size: usize) -> (tempfile::TempDir, RustAnalyzer) {
        project(&workspace_files(size))
    }

    fn workspace_files(size: usize) -> Vec<(String, String)> {
        let mut files = vec![(
            "src/lib.rs".to_string(),
            (0..size)
                .map(|index| format!("pub mod part{index};\n"))
                .collect::<String>()
                + "pub struct Widget;\n",
        )];
        for index in 0..size {
            files.push((
                format!("src/part{index}.rs"),
                format!("use crate::Widget;\npub fn take{index}(_: Widget) {{}}\n"),
            ));
        }
        files
    }

    fn importers(analyzer: &RustAnalyzer) -> crate::hash::HashSet<ProjectFile> {
        let lib = ProjectFile::new(analyzer.project().root().to_path_buf(), "src/lib.rs");
        let target = analyzer
            .declarations(&lib)
            .into_iter()
            .find(|declaration| declaration.identifier() == "Widget")
            .expect("Widget declaration");
        let scope = crate::analyzer::AnalyzerQueryScope::new(analyzer);
        let token = scope.token();
        brokk_bifrost_rust::usage::usage_importers(
            analyzer,
            token,
            &brokk_bifrost_rust::usage::usage_binding_seeds(
                analyzer,
                token,
                &BTreeSet::from([target]),
            )
            .expect("published binding seeds"),
        )
        .expect("published usage importers")
    }

    /// A file whose blob lost its fact rows is invisible to a store-backed
    /// query. Below the threshold explicit preparation repairs it inline,
    /// without making an ordinary query start workspace-wide parser work.
    #[test]
    fn a_below_threshold_catch_up_runs_inline_and_never_reports_a_wait() {
        let (_temp, analyzer) = workspace_of(1);
        let part = ProjectFile::new(analyzer.project().root().to_path_buf(), "src/part0.rs");
        assert!(importers(&analyzer).contains(&part));

        let updated = analyzer.update_all();
        let _ = updated.get_analyzed_files();
        updated.analyzer_store().delete_rust_facts_for_test("rust");
        let stale = updated.rust_files_without_facts().expect("live-blob probe");
        assert_eq!(stale.len(), 2, "both files lost their rows: {stale:?}");

        assert!(
            !updated.rust_usage_facts_ready(),
            "publication is not yet verified"
        );
        updated.warm_usage_facts();
        assert!(
            importers(&updated).contains(&part),
            "the query answers from rows the catch-up restored"
        );
        assert!(updated.rust_usage_facts_ready());
        assert!(updated.rust_usage_facts_warm());
        assert!(
            updated
                .rust_files_without_facts()
                .expect("live-blob probe")
                .is_empty(),
            "the catch-up set is empty afterwards"
        );
    }

    /// At or above the threshold the batch is handed to the background pool and
    /// the probe reports false until it drains. The barrier makes the false
    /// state observable without a timing assumption.
    #[test]
    fn an_above_threshold_catch_up_defers_and_reports_false_until_it_drains() {
        let (_temp, analyzer) = workspace_of(RUST_FACT_CATCH_UP_INLINE_LIMIT + 1);
        let part = ProjectFile::new(analyzer.project().root().to_path_buf(), "src/part0.rs");
        assert!(importers(&analyzer).contains(&part));

        let updated = analyzer.update_all();
        let _ = updated.get_analyzed_files();
        updated.analyzer_store().delete_rust_facts_for_test("rust");
        let stale = updated.rust_files_without_facts().expect("live-blob probe");
        assert_eq!(
            stale.len(),
            RUST_FACT_CATCH_UP_INLINE_LIMIT + 2,
            "the completed build must lose every module witness: {stale:?}"
        );
        assert!(
            !updated.rust_usage_facts_ready(),
            "publication is not yet verified"
        );

        let gate = updated.hold_rust_fact_catch_up_for_test();
        updated.ensure_rust_facts_caught_up();
        assert!(
            !updated.rust_usage_facts_ready(),
            "a deferred batch must report a wait"
        );
        assert!(!updated.rust_usage_facts_warm());

        gate.wait();
        let deadline = Instant::now() + Duration::from_secs(60);
        while !updated.rust_usage_facts_ready() {
            assert!(
                Instant::now() < deadline,
                "the deferred batch never drained"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(updated.rust_usage_facts_warm());
        assert!(
            updated
                .rust_files_without_facts()
                .expect("live-blob probe")
                .is_empty(),
            "the deferred batch persisted every stale file"
        );
        assert!(importers(&updated).contains(&part));
    }

    /// Parse pools persist per language and thread count, and every build of
    /// that language shares them (#3751). At parallelism 1 a deferred catch-up
    /// and another Rust build share one parse worker, and under the
    /// repository's `BIFROST_PARALLELISM=1`
    /// the dedicated build pool running the catch-up has one worker too. Had
    /// parsing moved onto that dedicated pool, the catch-up's producer would
    /// queue behind the catch-up that waits for it. The other build releases
    /// the catch-up from inside its own parse, so the two overlap on the one
    /// parse worker; both must finish.
    #[test]
    fn a_deferred_catch_up_persists_while_another_build_parses_at_parallelism_one() {
        use crate::analyzer::rust::RustAdapter;
        use crate::analyzer::{AnalyzerConfig, BuildProgressPhase, TreeSitterAnalyzer};
        use std::sync::atomic::{AtomicBool, Ordering};

        let config = AnalyzerConfig {
            parallelism: Some(1),
            ..AnalyzerConfig::default()
        };
        let (_temp, analyzer) = project_with_config(
            &workspace_files(RUST_FACT_CATCH_UP_INLINE_LIMIT + 1),
            config.clone(),
        );
        let updated = analyzer.update_all();
        let _ = updated.get_analyzed_files();
        updated.analyzer_store().delete_rust_facts_for_test("rust");

        let gate = updated.hold_rust_fact_catch_up_for_test();
        updated.ensure_rust_facts_caught_up();
        assert!(
            !updated.rust_usage_facts_ready(),
            "a deferred batch must report a wait"
        );

        // One file keeps the other build's live-OID planning inline: a
        // larger batch plans on the dedicated pool, whose worker the held
        // catch-up occupies until the gate opens.
        let other_temp = tempfile::tempdir().expect("tempdir");
        let other_root = other_temp.path().canonicalize().expect("canonical root");
        ProjectFile::new(other_root.clone(), "src/lib.rs")
            .write("pub struct App;\n")
            .expect("write Rust fixture");
        let released = AtomicBool::new(false);
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let other_build = std::thread::spawn(move || {
            let other = TreeSitterAnalyzer::new_with_config_and_progress(
                std::sync::Arc::new(TestProject::new(other_root, Language::Rust)),
                RustAdapter,
                config,
                move |event| {
                    if event.phase == BuildProgressPhase::Parse
                        && !released.swap(true, Ordering::SeqCst)
                    {
                        gate.wait();
                    }
                },
            );
            done_tx
                .send(other.get_analyzed_files().len())
                .expect("test thread waits for the other build");
        });

        let analyzed = match done_rx.recv_timeout(Duration::from_secs(60)) {
            Ok(analyzed) => analyzed,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => std::panic::resume_unwind(
                other_build
                    .join()
                    .expect_err("only a panic drops the sender unsent"),
            ),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                panic!("the other build must finish while the catch-up runs")
            }
        };
        other_build.join().expect("the other build finished");
        assert_eq!(analyzed, 1, "the other build indexed its one file");
        let deadline = Instant::now() + Duration::from_secs(60);
        while !updated.rust_usage_facts_ready() {
            assert!(
                Instant::now() < deadline,
                "the deferred batch never drained"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            updated
                .rust_files_without_facts()
                .expect("live-blob probe")
                .is_empty(),
            "the deferred batch persisted every stale file"
        );
    }

    /// The warm no longer builds anything: it is the same catch-up, and on a
    /// workspace analysis already persisted it finds nothing to do. It must
    /// still not drag the hierarchy index in behind it, which is what kept the
    /// warms separate (#1757, d8920a38). The reference contexts it used to be
    /// paired with no longer exist to be built: resolution is per site.
    #[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
    #[test]
    fn warming_the_usage_facts_warms_only_the_usage_facts() {
        let (_temp, analyzer) = workspace_of(1);
        assert!(!analyzer.rust_usage_facts_warm());

        analyzer.warm_usage_facts();

        assert!(analyzer.rust_usage_facts_warm());
    }

    /// A failed live-blob probe is not an empty catch-up set. Before #2325 the
    /// probe swallowed its store error and answered "no file needs catching
    /// up", so a damaged cache left every Rust usage answer quietly composed
    /// from stale facts and reported success.
    #[test]
    fn a_failed_live_blob_probe_reports_the_failure_instead_of_an_empty_catch_up_set() {
        let (_temp, analyzer) = workspace_of(1);
        analyzer.analyzer_store().drop_rust_modules_table_for_test();

        assert!(
            analyzer.rust_files_without_facts().is_err(),
            "a failed probe must not answer with an empty stale set"
        );

        let context = std::sync::Arc::new(crate::analyzer::AnalyzerQueryContext::default());
        analyzer.begin_query(&context);
        analyzer.warm_usage_facts();
        let error = context
            .store_error()
            .expect("a failed catch-up probe must reach the request boundary");
        analyzer.end_query(&context);
        assert!(
            error
                .to_string()
                .contains("rust fact catch-up live-blob probe"),
            "the recorded failure must name the probe: {error}"
        );
        assert!(!analyzer.rust_usage_facts_ready());
        assert!(!analyzer.rust_usage_facts_warm());
    }

    #[test]
    fn skipped_changed_content_does_not_become_ready_when_catch_up_finishes() {
        let (_temp, analyzer) = workspace_of(1);
        analyzer.analyzer_store().delete_rust_facts_for_test("rust");
        let file = ProjectFile::new(analyzer.project().root(), "src/part0.rs");
        file.write("pub fn changed_after_indexing() {}\n")
            .expect("change bytes without changing the live snapshot");
        let context = std::sync::Arc::new(crate::analyzer::AnalyzerQueryContext::default());
        analyzer.begin_query(&context);
        analyzer.warm_usage_facts();
        analyzer.end_query(&context);
        let error = context
            .store_error()
            .expect("unpublished content must be reported");
        assert!(
            error.to_string().contains("could not publish live files"),
            "{error}"
        );
        assert!(error.to_string().contains("part0.rs"), "{error}");
        assert!(!analyzer.rust_usage_facts_ready());
        assert!(!analyzer.rust_usage_facts_warm());
        assert!(analyzer.rust_files_without_facts().unwrap().contains(&file));
    }
}
