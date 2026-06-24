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
        atomic::{AtomicBool, Ordering},
    };
    use std::time::{Duration, Instant};

    use brokk_bifrost::{
        AnalyzerConfig, FilesystemProject, Project, WorkspaceAnalyzer,
        nlp::indexer::{DEFAULT_READY_TIMEOUT, SemanticIndexer},
        nlp::voyage::enable_embed_profile_logging,
    };

    fn rss_kb() -> Option<u64> {
        let status = std::fs::read_to_string("/proc/self/status").ok()?;
        status.lines().find_map(|line| {
            let rest = line.strip_prefix("VmRSS:")?;
            rest.split_whitespace().next()?.parse::<u64>().ok()
        })
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
    eprintln!(
        "[profile] {:.3}s workspace built rss_mib={:.1}",
        start.elapsed().as_secs_f64(),
        rss_kb().map(|kb| kb as f64 / 1024.0).unwrap_or(-1.0)
    );

    let indexer = SemanticIndexer::start(root.clone(), snapshot.clone());
    let done = Arc::new(AtomicBool::new(false));
    let status_done = done.clone();
    let status_indexer = indexer.clone();
    let status_snapshot = snapshot.clone();
    let status_start = start;
    let status_thread = std::thread::spawn(move || {
        while !status_done.load(Ordering::Relaxed) {
            let status = status_indexer.status(&status_snapshot);
            eprintln!(
                "[profile] {:.3}s phase={} indexed={} pending={} rss_mib={:.1}",
                status_start.elapsed().as_secs_f64(),
                status.phase,
                status.indexed_chunks,
                status.pending_batches,
                rss_kb().map(|kb| kb as f64 / 1024.0).unwrap_or(-1.0)
            );
            std::thread::sleep(Duration::from_secs(1));
        }
    });

    let result = indexer.wait_ready(DEFAULT_READY_TIMEOUT);
    done.store(true, Ordering::Relaxed);
    let _ = status_thread.join();
    result?;
    let status = indexer.status(&snapshot);
    eprintln!(
        "[profile] {:.3}s complete phase={} indexed={} pending={} rss_mib={:.1}",
        start.elapsed().as_secs_f64(),
        status.phase,
        status.indexed_chunks,
        status.pending_batches,
        rss_kb().map(|kb| kb as f64 / 1024.0).unwrap_or(-1.0)
    );
    indexer.close();
    Ok(())
}
