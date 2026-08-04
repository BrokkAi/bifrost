//! Per-file extraction timer: find the file whose `extract_file_chunks` spins.
//!
//! Builds the workspace analyzer for a repo, then runs `extract_file_chunks` over
//! every analyzed file, printing each file path BEFORE processing (flushed) so the
//! last line with no matching "done" is the culprit.
#[cfg(not(feature = "nlp"))]
fn main() {
    eprintln!("chunk_probe requires the nlp feature");
    std::process::exit(1);
}

#[cfg(feature = "nlp")]
fn main() -> Result<(), String> {
    use std::io::Write;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::Instant;

    use brokk_bifrost::{
        AnalyzerConfig, FilesystemProject, Project, WorkspaceAnalyzer, nlp::bm25::fts_text,
        nlp::chunker::extract_file_chunks,
    };

    let root = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .ok_or("usage: chunk_probe <repo-root>")?;
    let warn_ms: u128 = std::env::var("WARN_MS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(500);

    eprintln!("[probe] building workspace for {}", root.display());
    let project: Arc<dyn Project> =
        Arc::new(FilesystemProject::new(root.clone()).map_err(|e| e.to_string())?);
    let snapshot = WorkspaceAnalyzer::build(project, AnalyzerConfig::default());
    let analyzer = snapshot.analyzer();
    let files: Vec<_> = analyzer.analyzed_files().into_iter().collect();
    eprintln!(
        "[probe] {} analyzed files; timing extract_file_chunks each",
        files.len()
    );

    let stderr = std::io::stderr();
    for (i, file) in files.iter().enumerate() {
        // Print and flush BEFORE the call: a hang leaves this as the last line.
        {
            let mut h = stderr.lock();
            let _ = writeln!(h, "[probe] >>> {i} {}", file.rel_path().display());
            let _ = h.flush();
        }
        let t = Instant::now();
        let chunks = extract_file_chunks(analyzer, file);
        let ms = t.elapsed().as_millis();
        {
            let mut h = stderr.lock();
            let _ = writeln!(
                h,
                "[probe] extract-done {i} ({}ms, {} chunks)",
                ms,
                chunks.chunks.len()
            );
            let _ = h.flush();
        }
        if ms >= warn_ms {
            eprintln!(
                "[probe] SLOW-EXTRACT {ms}ms {} ({} chunks)",
                file.rel_path().display(),
                chunks.chunks.len()
            );
        }
        // Mirror raw-source BM25 tokenization performed after extraction.
        for c in &chunks.chunks {
            let ft = Instant::now();
            let _ = fts_text(&c.source_text);
            let fms = ft.elapsed().as_millis();
            if fms >= warn_ms {
                let mut h = stderr.lock();
                let _ = writeln!(
                    h,
                    "[probe] SLOW-FTS {fms}ms body bytes={} in {}",
                    c.source_text.len(),
                    file.rel_path().display()
                );
                let _ = h.flush();
            }
        }
    }
    eprintln!("[probe] done — no file hung");
    Ok(())
}
