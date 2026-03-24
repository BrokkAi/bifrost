use brokk_analyzer::{JavaAnalyzer, Language, TestProject, summarize_inputs};
use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

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
    let mut args = env::args().skip(1);
    let mut root =
        env::current_dir().map_err(|err| format!("Failed to get current directory: {err}"))?;
    let mut inputs = Vec::new();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--root" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--root requires a path".to_string())?;
                root = PathBuf::from(value);
            }
            "--help" | "-h" => {
                print_help();
                return Ok(());
            }
            _ => inputs.push(arg),
        }
    }

    if inputs.is_empty() {
        print_help();
        return Err("No files or symbols provided".to_string());
    }

    let root = root
        .canonicalize()
        .map_err(|err| format!("Failed to resolve project root {}: {err}", root.display()))?;
    let project = TestProject::new(root.clone(), Language::Java);
    let analyzer = JavaAnalyzer::from_project(project);
    let summaries = summarize_inputs(&analyzer, &root, &inputs)?;

    for (index, summary) in summaries.iter().enumerate() {
        if summaries.len() > 1 {
            println!("== {} ==", summary.label);
        }
        println!("{}", summary.text);
        if index + 1 < summaries.len() {
            println!();
        }
    }

    Ok(())
}

fn print_help() {
    println!("Usage: summarize [--root PROJECT_ROOT] <absolute-file-path-or-fqcn>...");
}
