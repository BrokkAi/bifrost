//! Full-pipeline indexing profiler: throughput, peak RSS, and DB growth over a
//! complete index run.
//!
//! Builds the workspace analyzer for a repo, then runs the production `SemanticIndexer`
//! to completion while a background thread samples (every 2s) the phase, cumulative
//! indexed chunks and chunks/s, pending batches, current/peak RSS, and on-disk DB size
//! (`.db` + `.db-wal`). Unlike the narrower probes (`chunk_probe`, `embed_probe`,
//! `embed_seq_probe`) this exercises extract -> embed -> store end to end, so it is the
//! tool for whole-pipeline throughput and memory regressions. Honors
//! `BIFROST_EMBED_BACKEND` like production. Usage: `semantic_index_profile <repo-root>`.
#[cfg(not(feature = "nlp"))]
fn main() {
    eprintln!("semantic_index_profile requires the nlp feature");
    std::process::exit(1);
}

#[cfg(feature = "nlp")]
fn main() -> Result<(), String> {
    use std::path::PathBuf;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    };
    use std::time::{Duration, Instant};

    use brokk_bifrost::{
        AnalyzerConfig, FilesystemProject, Project, WorkspaceAnalyzer,
        nlp::indexer::SemanticIndexer, nlp::store::semantic_db_path,
        nlp::voyage::enable_embed_profile_logging,
    };

    fn rss_kb() -> u64 {
        std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|status| {
                status.lines().find_map(|line| {
                    line.strip_prefix("VmRSS:")?
                        .split_whitespace()
                        .next()?
                        .parse::<u64>()
                        .ok()
                })
            })
            .unwrap_or(0)
    }

    fn db_size_mib(root: &std::path::Path) -> f64 {
        let path = semantic_db_path(root);
        let main = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        let wal = std::fs::metadata(path.with_extension("db-wal"))
            .map(|m| m.len())
            .unwrap_or(0);
        (main + wal) as f64 / (1024.0 * 1024.0)
    }

    let root = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("../brokk"));
    enable_embed_profile_logging();
    let start = Instant::now();
    eprintln!("[profile] root={}", root.display());

    let project: Arc<dyn Project> =
        Arc::new(FilesystemProject::new(root.clone()).map_err(|err| err.to_string())?);
    let snapshot = Arc::new(WorkspaceAnalyzer::build(project, AnalyzerConfig::default()));
    let analyzed_files = snapshot.analyzer().analyzed_files().count();
    let build_secs = start.elapsed().as_secs_f64();
    eprintln!(
        "[profile] {build_secs:.1}s workspace built: {analyzed_files} analyzed files, rss_mib={:.0}",
        rss_kb() as f64 / 1024.0
    );

    let indexer = SemanticIndexer::start(root.clone(), snapshot.clone());
    let done = Arc::new(AtomicBool::new(false));
    let peak_rss = Arc::new(AtomicU64::new(0));

    let status_thread = {
        let (done, peak_rss) = (done.clone(), peak_rss.clone());
        let (indexer, snapshot) = (indexer.clone(), snapshot.clone());
        let root = root.clone();
        std::thread::spawn(move || {
            while !done.load(Ordering::Relaxed) {
                let status = indexer.status(&snapshot);
                let rss = rss_kb();
                peak_rss.fetch_max(rss, Ordering::Relaxed);
                let elapsed = start.elapsed().as_secs_f64();
                let rate = status.indexed_chunks as f64 / elapsed.max(1e-3);
                eprintln!(
                    "[profile] {elapsed:.0}s phase={} indexed_chunks={} ({rate:.0}/s) pending={} \
                     rss_mib={:.0} db_mib={:.0}",
                    status.phase,
                    status.indexed_chunks,
                    status.pending_batches,
                    rss as f64 / 1024.0,
                    db_size_mib(&root),
                );
                std::thread::sleep(Duration::from_secs(2));
            }
        })
    };

    // No fixed cap: a repo the size of intellij-community can run for a long time.
    let result = indexer.wait_ready(Duration::from_secs(24 * 3600));
    done.store(true, Ordering::Relaxed);
    let _ = status_thread.join();
    result?;

    let status = indexer.status(&snapshot);
    let total = start.elapsed().as_secs_f64();
    eprintln!(
        "[profile] DONE {total:.1}s phase={} indexed_chunks={} ({:.0} chunks/s) \
         peak_rss_mib={:.0} db_mib={:.1}",
        status.phase,
        status.indexed_chunks,
        status.indexed_chunks as f64 / total.max(1e-3),
        peak_rss.load(Ordering::Relaxed) as f64 / 1024.0,
        db_size_mib(&root),
    );
    indexer.close();
    Ok(())
}
