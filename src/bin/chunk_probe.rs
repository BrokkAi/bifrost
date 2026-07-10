//! Per-file extraction timer: find the file whose `extract_file_chunks` spins.
//!
//! Builds the workspace analyzer for a repo, then runs `extract_file_chunks` over
//! every analyzed file, printing each file path BEFORE processing (flushed) so the
//! last line with no matching "done" is the culprit. Uses a cheap word-count token
//! estimate so a hang here implicates the analyzer layer, not the model tokenizer.
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

    // If BIFROST_PROBE_TOKENIZER points at a tokenizer.json, use the *real* BPE
    // tokenizer for count_tokens (reproduces the production hang). Otherwise fall
    // back to a cheap word count (analyzer-only test).
    let real_tok = std::env::var("BIFROST_PROBE_TOKENIZER").ok().map(|p| {
        tokenizers::Tokenizer::from_file(&p).unwrap_or_else(|e| panic!("load tokenizer {p}: {e}"))
    });

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

    // Cheap, bounded token estimate (whitespace words) unless a real tokenizer was
    // provided. If extraction hangs with the cheap one, the spin is in the analyzer;
    // if only with the real one, it's the BPE tokenizer.
    let count_tokens = |text: &str| match &real_tok {
        Some(tok) => tok.encode(text, false).map(|e| e.len()).unwrap_or(0),
        None => text.split_whitespace().count(),
    };

    let stderr = std::io::stderr();
    for (i, file) in files.iter().enumerate() {
        // Print and flush BEFORE the call: a hang leaves this as the last line.
        {
            let mut h = stderr.lock();
            let _ = writeln!(h, "[probe] >>> {i} {}", file.rel_path().display());
            let _ = h.flush();
        }
        let t = Instant::now();
        let chunks = extract_file_chunks(analyzer, file, &count_tokens);
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
        // Mirror extract_group's per-chunk work the probe otherwise skips:
        //   - count_tokens on the body (embed stage), and
        //   - fts_text on the body (BM25 subtoken tokenization).
        // Time each separately so a hang names both the file and the stage.
        for c in &chunks.chunks {
            if real_tok.is_some() {
                let bt = Instant::now();
                let toks = count_tokens(&c.text);
                let bms = bt.elapsed().as_millis();
                if bms >= warn_ms {
                    let mut h = stderr.lock();
                    let _ = writeln!(
                        h,
                        "[probe] SLOW-TOKENIZE {bms}ms body bytes={} tokens={toks} in {}",
                        c.text.len(),
                        file.rel_path().display()
                    );
                    let _ = h.flush();
                }
            }
            let ft = Instant::now();
            let _ = fts_text(&c.text);
            let fms = ft.elapsed().as_millis();
            if fms >= warn_ms {
                let mut h = stderr.lock();
                let _ = writeln!(
                    h,
                    "[probe] SLOW-FTS {fms}ms body bytes={} in {}",
                    c.text.len(),
                    file.rel_path().display()
                );
                let _ = h.flush();
            }
        }
    }
    eprintln!("[probe] done — no file hung");
    Ok(())
}
