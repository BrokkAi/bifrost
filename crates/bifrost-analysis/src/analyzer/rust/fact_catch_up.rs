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

use std::sync::atomic::{AtomicUsize, Ordering};

use crate::analyzer::{IAnalyzer, PoolSafeMemo, ProjectFile, spawn_on_dedicated_build_pool};

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
    /// Files an above-threshold batch still owes rows for. The readiness probe
    /// is this reaching zero.
    outstanding: AtomicUsize,
    /// Test hook: a deferred batch waits here before it runs, so a test can
    /// observe the probe in its false state without a sleep. Follows the
    /// injection hooks the persistence path already carries
    /// (`should_inject_preparation_failure_for_test`).
    #[cfg(test)]
    gate: std::sync::Mutex<Option<std::sync::Arc<std::sync::Barrier>>>,
}

impl RustFactCatchUp {
    pub(super) fn new() -> Self {
        Self {
            settled: PoolSafeMemo::new(),
            outstanding: AtomicUsize::new(0),
            #[cfg(test)]
            gate: std::sync::Mutex::new(None),
        }
    }
}

impl RustAnalyzer {
    /// Ensure every live Rust file's blob carries fact rows before a query
    /// reads them. Runs at most once per analyzer generation.
    ///
    /// Called at the head of every cross-file usage walk. When the catch-up has
    /// settled -- the overwhelmingly common case, since analysis persists these
    /// rows itself -- this is one mutex probe.
    pub(super) fn ensure_rust_facts_caught_up(&self) {
        self.fact_catch_up.settled.get_or_build(
            || self.run_rust_fact_catch_up(),
            || self.run_rust_fact_catch_up(),
        );
    }

    /// Whether a query would wait for a catch-up batch. True when no batch is
    /// outstanding, including before any catch-up has run: there is no index to
    /// build under v2, so "not ready" only ever means "a batch is draining".
    ///
    /// This is what `get_active_workspace` reports as `usage_index_ready`.
    pub(crate) fn rust_usage_facts_ready(&self) -> bool {
        self.fact_catch_up.outstanding.load(Ordering::Acquire) == 0
    }

    /// Whether the catch-up has run for this generation and left nothing
    /// outstanding. The warm-ness question, as distinct from the wait question
    /// [`Self::rust_usage_facts_ready`] answers.
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
        let stale = self.rust_files_without_facts();
        if stale.is_empty() {
            return;
        }
        if stale.len() < RUST_FACT_CATCH_UP_INLINE_LIMIT {
            self.inner.persist_live_blobs(&stale);
            return;
        }
        self.fact_catch_up
            .outstanding
            .store(stale.len(), Ordering::Release);
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
            analyzer
                .fact_catch_up
                .outstanding
                .store(0, Ordering::Release);
        });
    }

    /// The live Rust files whose current blob carries no persisted facts.
    ///
    /// One indexed batch query against the store, never a parse: the candidate
    /// set is the analyzed file listing the walks already hold, mapped to oids
    /// through the live snapshot that every store-backed read uses.
    fn rust_files_without_facts(&self) -> Vec<ProjectFile> {
        let snapshot = self.live_path_snapshot();
        let files: Vec<(ProjectFile, git2::Oid)> = self
            .get_analyzed_files()
            .into_iter()
            .filter_map(|file| {
                let oid = snapshot.oid_for_path(&file)?;
                Some((file, oid))
            })
            .collect();
        let oids: Vec<git2::Oid> = files.iter().map(|(_, oid)| *oid).collect();
        let Ok(present) = self.analyzer_store().blobs_with_rust_facts("rust", &oids) else {
            return Vec::new();
        };
        files
            .into_iter()
            .filter(|(_, oid)| !present.contains(oid))
            .map(|(file, _)| file)
            .collect()
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
    use crate::analyzer::{Language, TestProject};
    use std::collections::BTreeSet;
    use std::time::{Duration, Instant};

    fn project(files: &[(String, String)]) -> (tempfile::TempDir, RustAnalyzer) {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        for (rel, body) in files {
            ProjectFile::new(root.clone(), rel)
                .write(body)
                .expect("write fixture file");
        }
        let analyzer = RustAnalyzer::from_project(TestProject::new(root, Language::Rust));
        // Force the analysis pass that persists the per-file fact rows.
        let _ = analyzer.get_analyzed_files();
        (temp, analyzer)
    }

    fn workspace_of(size: usize) -> (tempfile::TempDir, RustAnalyzer) {
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
        project(&files)
    }

    fn importers(analyzer: &RustAnalyzer) -> crate::hash::HashSet<ProjectFile> {
        let lib = ProjectFile::new(analyzer.project().root().to_path_buf(), "src/lib.rs");
        let target = analyzer
            .declarations(&lib)
            .into_iter()
            .find(|declaration| declaration.identifier() == "Widget")
            .expect("Widget declaration");
        analyzer.usage_importers(&analyzer.usage_binding_seeds(&BTreeSet::from([target])))
    }

    /// A file whose blob lost its fact rows is invisible to a store-backed
    /// query. Below the threshold the catch-up repairs it on the querying
    /// thread, and the probe never reports a wait, because there is none.
    ///
    /// Removing the `ensure_rust_facts_caught_up` call at the head of the walk
    /// leaves `part0` out of the answer, which is the fail-before for this
    /// guard.
    #[test]
    fn a_below_threshold_catch_up_runs_inline_and_never_reports_a_wait() {
        let (_temp, analyzer) = workspace_of(1);
        let part = ProjectFile::new(analyzer.project().root().to_path_buf(), "src/part0.rs");
        assert!(importers(&analyzer).contains(&part));

        analyzer.analyzer_store().delete_rust_facts_for_test("rust");
        let stale = analyzer.rust_files_without_facts();
        assert_eq!(stale.len(), 2, "both files lost their rows: {stale:?}");

        let updated = analyzer.update_all();
        assert!(
            updated.rust_usage_facts_ready(),
            "an inline catch-up must never report a wait"
        );
        assert!(
            importers(&updated).contains(&part),
            "the query answers from rows the catch-up restored"
        );
        assert!(updated.rust_usage_facts_ready());
        assert!(updated.rust_usage_facts_warm());
        assert!(
            updated.rust_files_without_facts().is_empty(),
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

        analyzer.analyzer_store().delete_rust_facts_for_test("rust");
        let updated = analyzer.update_all();
        assert!(
            updated.rust_usage_facts_ready(),
            "nothing is outstanding before the scan"
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
            updated.rust_files_without_facts().is_empty(),
            "the deferred batch persisted every stale file"
        );
        assert!(importers(&updated).contains(&part));
    }

    /// The warm no longer builds anything: it is the same catch-up, and on a
    /// workspace analysis already persisted it finds nothing to do. It must
    /// still not drag the hierarchy index or every reference context in behind
    /// it, which is what kept the two warms separate (#1757, d8920a38).
    #[test]
    fn warming_the_usage_facts_builds_neither_the_hierarchy_nor_the_reference_contexts() {
        let (_temp, analyzer) = workspace_of(1);
        let part = ProjectFile::new(analyzer.project().root().to_path_buf(), "src/part0.rs");
        assert!(!analyzer.rust_usage_facts_warm());

        analyzer.warm_usage_facts();

        assert!(analyzer.rust_usage_facts_warm());
        assert!(!analyzer.hierarchy_index_built_for_test());
        assert!(!analyzer.reference_context_built_for_test(&part));

        analyzer.warm_usage_reference_contexts();
        assert!(analyzer.reference_context_built_for_test(&part));
    }
}
