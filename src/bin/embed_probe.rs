//! Embed-stage probe: find the component text whose `embed_passages` spins.
//!
//! Loads the production embedder, extracts every blob group's component texts
//! (exactly like the indexer), and embeds them group by group — printing the group
//! index and its largest text BEFORE the embed call (flushed), so a hang leaves the
//! culprit group as the last line. On a hang, rerun with BISECT=1 to embed the stuck
//! group one text at a time and name the exact text.
#[cfg(not(feature = "nlp"))]
fn main() {
    eprintln!("embed_probe requires the nlp feature");
    std::process::exit(1);
}

#[cfg(feature = "nlp")]
fn main() -> Result<(), String> {
    use std::io::Write;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::Instant;

    use brokk_bifrost::{
        AnalyzerConfig, FilesystemProject, Project, WorkspaceAnalyzer,
        nlp::engine::load_production_embedder, nlp::materialize::extract_group_texts,
    };

    let root = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .ok_or("usage: embed_probe <repo-root>")?;
    let warn_ms: u128 = std::env::var("WARN_MS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3000);

    eprintln!("[embed] loading production embedder");
    let embedder = load_production_embedder()?;

    eprintln!("[embed] building workspace for {}", root.display());
    let project: Arc<dyn Project> =
        Arc::new(FilesystemProject::new(root.clone()).map_err(|e| e.to_string())?);
    let snapshot = WorkspaceAnalyzer::build(project, AnalyzerConfig::default());
    let analyzer = snapshot.analyzer();
    let files: Vec<_> = analyzer.analyzed_files().into_iter().collect();
    eprintln!(
        "[embed] {} files; extracting + embedding in groups of 64",
        files.len()
    );

    let stderr = std::io::stderr();
    for (gi, group) in files.chunks(64).enumerate() {
        // extract_group_texts returns the distinct component texts for this file group,
        // mirroring the indexer's extract_group (chunk bodies + parent summaries).
        let texts = extract_group_texts(embedder.as_ref(), analyzer, group);
        if texts.is_empty() {
            continue;
        }
        let max_bytes = texts.iter().map(|t| t.len()).max().unwrap_or(0);
        {
            let mut h = stderr.lock();
            let _ = writeln!(
                h,
                "[embed] >>> group {gi} ({} texts, max_bytes={max_bytes})",
                texts.len()
            );
            let _ = h.flush();
        }
        let refs: Vec<&str> = texts.iter().map(|s| s.as_str()).collect();
        let t = Instant::now();
        if std::env::var("BISECT").is_ok() {
            for (ti, r) in refs.iter().enumerate() {
                let bt = Instant::now();
                let mut h = stderr.lock();
                let _ = writeln!(h, "[embed]     text {ti} bytes={}", r.len());
                let _ = h.flush();
                drop(h);
                embedder.embed_passages(&[r])?;
                let bms = bt.elapsed().as_millis();
                if bms >= warn_ms {
                    eprintln!(
                        "[embed] SLOW-TEXT {bms}ms group {gi} text {ti} bytes={}",
                        r.len()
                    );
                }
            }
        } else {
            embedder.embed_passages(&refs)?;
        }
        let ms = t.elapsed().as_millis();
        if ms >= warn_ms {
            eprintln!(
                "[embed] SLOW-GROUP {ms}ms group {gi} ({} texts, max_bytes={max_bytes})",
                texts.len()
            );
        }
    }
    eprintln!("[embed] done — no group hung");
    Ok(())
}
