//! Model-free semantic chunk-extraction profiler.
//!
//! Builds the production persisted workspace analyzer, then extracts the same
//! chunk texts as the semantic indexer without embedding or writing semantic
//! rows. Usage:
//!
//!     semantic_extraction_profile <repo-root> [max-files]
//!
//! Set `RAYON_NUM_THREADS` to control extraction concurrency. Files are sorted
//! by workspace-relative path before applying `max-files`, so separate process
//! runs use the same input.

#[cfg(not(feature = "nlp"))]
fn main() {
    eprintln!("semantic_extraction_profile requires the nlp feature");
    std::process::exit(1);
}

#[cfg(feature = "nlp")]
fn main() -> Result<(), String> {
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::Instant;

    use brokk_bifrost::{
        AnalyzerConfig, FilesystemProject, Project, WorkspaceAnalyzer,
        nlp::materialize::extract_group_texts,
    };

    const FILE_GROUP: usize = 64;

    let mut args = std::env::args_os().skip(1);
    let root = args
        .next()
        .map(PathBuf::from)
        .ok_or_else(|| "usage: semantic_extraction_profile <repo-root> [max-files]".to_string())?;
    let max_files = args
        .next()
        .map(|value| {
            value
                .to_str()
                .ok_or_else(|| "max-files must be UTF-8".to_string())?
                .parse::<usize>()
                .map_err(|err| format!("invalid max-files: {err}"))
        })
        .transpose()?;
    if args.next().is_some() {
        return Err("usage: semantic_extraction_profile <repo-root> [max-files]".to_string());
    }

    let started = Instant::now();
    let project: Arc<dyn Project> =
        Arc::new(FilesystemProject::new(root.clone()).map_err(|err| err.to_string())?);
    let workspace = WorkspaceAnalyzer::build(project, AnalyzerConfig::default());
    let build_seconds = started.elapsed().as_secs_f64();

    let mut files = workspace.analyzer().analyzed_files();
    files.sort_unstable_by(|left, right| left.rel_path().cmp(right.rel_path()));
    if let Some(max_files) = max_files {
        files.truncate(max_files);
    }
    let thread_count = rayon::current_num_threads();
    eprintln!(
        "[extract-profile] root={} files={} rayon_threads={} workspace_build_seconds={build_seconds:.3}",
        root.display(),
        files.len(),
        thread_count,
    );

    let extract_started = Instant::now();
    let mut texts = 0usize;
    let mut bytes = 0usize;
    for group in files.chunks(FILE_GROUP) {
        let extracted = extract_group_texts(workspace.analyzer(), group);
        texts += extracted.len();
        bytes += extracted.iter().map(String::len).sum::<usize>();
    }
    workspace.analyzer().release_streaming_readers();
    let extract_seconds = extract_started.elapsed().as_secs_f64();
    eprintln!(
        "[extract-profile] DONE files={} texts={} bytes={} rayon_threads={} extract_seconds={extract_seconds:.3} files_per_second={:.3}",
        files.len(),
        texts,
        bytes,
        thread_count,
        files.len() as f64 / extract_seconds.max(f64::EPSILON),
    );
    Ok(())
}
