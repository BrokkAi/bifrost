use brokk_analyzer::{
    AnalyzerConfig, FilesystemProject, WorkspaceAnalyzer,
    searchtools::{MostRelevantFilesParams, most_relevant_files},
};
use std::env;
use std::process::ExitCode;
use std::sync::Arc;

const DEFAULT_LIMIT: usize = 100;

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
    let _run_scope = brokk_analyzer::profiling::scope("cli.most_relevant_files");
    let mut args = env::args().skip(1);
    let mut root =
        env::current_dir().map_err(|err| format!("Failed to get current directory: {err}"))?;
    let mut seed_files = Vec::new();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--root" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--root requires a path".to_string())?;
                root = value.into();
            }
            "--help" | "-h" => {
                print_help();
                return Ok(());
            }
            other => seed_files.push(other.to_string()),
        }
    }

    if seed_files.is_empty() {
        print_help();
        return Err("At least one seed filename is required".to_string());
    }

    let project = {
        let _scope = brokk_analyzer::profiling::scope("cli.open_project");
        Arc::new(
            FilesystemProject::new(root)
                .map_err(|err| format!("Failed to open project root: {err}"))?,
        )
    };
    let workspace = {
        let _scope = brokk_analyzer::profiling::scope("cli.workspace_build");
        WorkspaceAnalyzer::build(project, AnalyzerConfig::default())
    };
    let result = {
        let _scope = brokk_analyzer::profiling::scope("cli.rank");
        most_relevant_files(
            workspace.analyzer(),
            MostRelevantFilesParams {
                seed_files,
                limit: DEFAULT_LIMIT,
            },
        )
    };

    if !result.not_found.is_empty() {
        return Err(format!(
            "Seed files not found: {}",
            result.not_found.join(", ")
        ));
    }

    for file in result.files {
        println!("{file}");
    }

    Ok(())
}

fn print_help() {
    println!("Usage: most_relevant_files [--root PROJECT_ROOT] <seed-file>...");
}
