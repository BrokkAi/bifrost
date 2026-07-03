use brokk_bifrost::{
    AnalyzerConfig, FilesystemProject, Language, WorkspaceAnalyzer,
    searchtools::{MostRelevantFilesParams, most_relevant_files},
};
use std::env;
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;

const DEFAULT_LIMIT: usize = 100;
const DEFAULT_RECENCY_HALF_LIFE: f64 = 250.0;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{err}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let _run_scope = brokk_bifrost::profiling::scope("cli.most_relevant_files");
    let mut args = env::args().skip(1);
    let mut root =
        env::current_dir().map_err(|err| format!("Failed to get current directory: {err}"))?;
    let mut seed_file_paths = Vec::new();
    let mut recency_half_life = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--root" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--root requires a path".to_string())?;
                root = value.into();
            }
            "--recency-half-life" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--recency-half-life requires a number or 'none'".to_string())?;
                recency_half_life = Some(parse_recency_half_life(&value)?);
            }
            "--help" | "-h" => {
                print_help();
                return Ok(());
            }
            other => seed_file_paths.push(other.to_string()),
        }
    }

    if seed_file_paths.is_empty() {
        print_help();
        return Err("At least one seed filename is required".to_string());
    }

    let project = {
        let _scope = brokk_bifrost::profiling::scope("cli.open_project");
        Arc::new(
            FilesystemProject::new(root)
                .map_err(|err| format!("Failed to open project root: {err}"))?,
        )
    };
    let workspace = {
        let _scope = brokk_bifrost::profiling::scope("cli.workspace_build");
        let seed_languages: std::collections::BTreeSet<_> = seed_file_paths
            .iter()
            .filter_map(|seed| {
                Path::new(seed)
                    .extension()
                    .and_then(|ext| ext.to_str())
                    .map(Language::from_extension)
                    .filter(|language| *language != Language::None)
            })
            .collect();
        if seed_languages.is_empty() {
            WorkspaceAnalyzer::build(project, AnalyzerConfig::default())
        } else {
            WorkspaceAnalyzer::build_for_languages(
                project,
                AnalyzerConfig::default(),
                &seed_languages,
            )
        }
    };
    let result = {
        let _scope = brokk_bifrost::profiling::scope("cli.rank");
        most_relevant_files(
            workspace.analyzer(),
            MostRelevantFilesParams {
                seed_file_paths,
                seed_weights: None,
                recency_half_life: recency_half_life.unwrap_or(Some(DEFAULT_RECENCY_HALF_LIFE)),
                limit: DEFAULT_LIMIT,
            },
        )
        .map_err(|err| format!("Failed to rank relevant files: {err}"))?
    };

    if !result.not_found.is_empty() {
        let not_found = result
            .not_found
            .iter()
            .map(|item| match &item.note {
                Some(note) => format!("{} ({note})", item.input),
                None => item.input.clone(),
            })
            .collect::<Vec<_>>()
            .join(", ");
        return Err(format!("Seed files not found: {}", not_found));
    }
    if !result.duplicates.is_empty() {
        return Err(format!(
            "Duplicate seed files: {}",
            result.duplicates.join(", ")
        ));
    }

    for file in result.files {
        println!("{file}");
    }

    Ok(())
}

fn parse_recency_half_life(value: &str) -> Result<Option<f64>, String> {
    if value.eq_ignore_ascii_case("none") {
        return Ok(None);
    }

    let parsed = value
        .parse::<f64>()
        .map_err(|err| format!("Invalid --recency-half-life value {value:?}: {err}"))?;
    if !parsed.is_finite() || parsed <= 0.0 {
        return Err(format!(
            "--recency-half-life must be finite and > 0, got {parsed}"
        ));
    }
    Ok(Some(parsed))
}

fn print_help() {
    println!(
        "Usage: most_relevant_files [--root PROJECT_ROOT] [--recency-half-life COMMITS|none] <seed-file>..."
    );
}
