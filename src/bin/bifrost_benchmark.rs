use brokk_bifrost::benchmark::{
    BenchmarkManifest, BenchmarkRunReport, BenchmarkScenario, ManifestLanguage, RunRequest,
    run_benchmark,
};
use chrono::Utc;
use std::env;
use std::path::{Path, PathBuf};
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
    let mut manifest_path = PathBuf::from("benchmark/targets.toml");

    let Some(command) = args.next() else {
        print_help();
        return Err("missing subcommand".to_string());
    };

    match command.as_str() {
        "validate" => {
            while let Some(arg) = args.next() {
                match arg.as_str() {
                    "--manifest" => {
                        let value = args
                            .next()
                            .ok_or_else(|| "--manifest requires a path".to_string())?;
                        manifest_path = value.into();
                    }
                    "--help" | "-h" => {
                        print_validate_help();
                        return Ok(());
                    }
                    other => return Err(format!("unknown validate argument: {other}")),
                }
            }
            validate_manifest(manifest_path)
        }
        "run" => {
            let mut selected_repo = None;
            let mut output_dir = None;
            let mut max_files = None;
            while let Some(arg) = args.next() {
                match arg.as_str() {
                    "--manifest" => {
                        let value = args
                            .next()
                            .ok_or_else(|| "--manifest requires a path".to_string())?;
                        manifest_path = value.into();
                    }
                    "--repo" => {
                        selected_repo = Some(
                            args.next()
                                .ok_or_else(|| "--repo requires a repo name".to_string())?,
                        );
                    }
                    "--output" => {
                        output_dir =
                            Some(PathBuf::from(args.next().ok_or_else(|| {
                                "--output requires a directory path".to_string()
                            })?));
                    }
                    "--max-files" => {
                        let value = args
                            .next()
                            .ok_or_else(|| "--max-files requires a positive integer".to_string())?;
                        let parsed = value.parse::<usize>().map_err(|_| {
                            format!("--max-files expects a positive integer, got `{value}`")
                        })?;
                        if parsed == 0 {
                            return Err("--max-files must be greater than zero".to_string());
                        }
                        max_files = Some(parsed);
                    }
                    "--help" | "-h" => {
                        print_run_help();
                        return Ok(());
                    }
                    other => return Err(format!("unknown run argument: {other}")),
                }
            }
            run_manifest(manifest_path, selected_repo, output_dir, max_files)
        }
        "--help" | "-h" => {
            print_help();
            Ok(())
        }
        other => Err(format!("unknown subcommand: {other}")),
    }
}

fn validate_manifest(path: PathBuf) -> Result<(), String> {
    let manifest = BenchmarkManifest::load_from_path(&path)
        .map_err(|err| format!("failed to load `{}`: {err}", path.display()))?;
    let covered_languages = manifest
        .covered_languages()
        .into_iter()
        .map(ManifestLanguage::label)
        .collect::<Vec<_>>()
        .join(", ");
    let covered_scenarios = manifest
        .covered_scenarios()
        .into_iter()
        .map(BenchmarkScenario::label)
        .collect::<Vec<_>>()
        .join(", ");

    println!("validated {} repos", manifest.repos.len());
    println!("manifest: {}", path.display());
    println!("covered languages: {covered_languages}");
    println!("covered scenarios: {covered_scenarios}");

    Ok(())
}

fn run_manifest(
    manifest_path: PathBuf,
    selected_repo: Option<String>,
    output_dir_override: Option<PathBuf>,
    max_files: Option<usize>,
) -> Result<(), String> {
    let manifest = BenchmarkManifest::load_from_path(&manifest_path)
        .map_err(|err| format!("failed to load `{}`: {err}", manifest_path.display()))?;
    let manifest_dir = manifest_root(&manifest_path)?;
    let repo_cache_dir = resolve_from_manifest_root(&manifest_dir, &manifest.repo_cache_dir);
    let output_dir = output_dir_override
        .map(|path| resolve_from_manifest_root(&manifest_dir, &path))
        .unwrap_or_else(|| resolve_from_manifest_root(&manifest_dir, &manifest.output_dir));
    std::fs::create_dir_all(&output_dir).map_err(|err| {
        format!(
            "failed to create output dir `{}`: {err}",
            output_dir.display()
        )
    })?;

    let report = run_benchmark(
        &manifest,
        &RunRequest {
            manifest_path: manifest_path.clone(),
            repo_cache_dir,
            selected_repo,
            max_files,
        },
    )?;
    let report_path = output_dir.join(format!("run-{}.json", Utc::now().format("%Y%m%dT%H%M%SZ")));
    write_report(&report, &report_path)?;
    print_run_summary(&report, &report_path);
    Ok(())
}

fn manifest_root(manifest_path: &Path) -> Result<PathBuf, String> {
    let absolute = if manifest_path.is_absolute() {
        manifest_path.to_path_buf()
    } else {
        env::current_dir()
            .map_err(|err| format!("failed to resolve current directory: {err}"))?
            .join(manifest_path)
    };
    absolute
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("manifest path has no parent: {}", manifest_path.display()))
}

fn resolve_from_manifest_root(manifest_root: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        manifest_root.join(path)
    }
}

fn write_report(report: &BenchmarkRunReport, report_path: &Path) -> Result<(), String> {
    let json = serde_json::to_string_pretty(report)
        .map_err(|err| format!("failed to serialize report: {err}"))?;
    std::fs::write(report_path, json)
        .map_err(|err| format!("failed to write report `{}`: {err}", report_path.display()))
}

fn print_run_summary(report: &BenchmarkRunReport, report_path: &Path) {
    if let Some(max_files) = report.max_files {
        println!("subset max_files={max_files}");
    }
    for repo in &report.repos {
        match repo.subset_max_files {
            Some(max_files) => println!(
                "repo {} subset={} workspace={}",
                repo.name,
                max_files,
                repo.workspace_path.display()
            ),
            None => println!("repo {}", repo.name),
        }
        for scenario in &repo.scenarios {
            let status = if scenario.success { "ok" } else { "failed" };
            match scenario.median_ms {
                Some(median) => {
                    println!(
                        "  {}: {status} median={median:.1} ms",
                        scenario.name.label()
                    );
                }
                None => {
                    println!("  {}: {status}", scenario.name.label());
                }
            }
            if let Some(message) = &scenario.failure_message {
                println!("    failure: {message}");
            }
        }
    }
    println!("wrote {}", report_path.display());
}

fn print_help() {
    println!("Usage: bifrost_benchmark <subcommand> [options]");
    println!("Subcommands:");
    println!("  validate [--manifest PATH]");
    println!("  run [--manifest PATH] [--repo NAME] [--output DIR] [--max-files N]");
}

fn print_validate_help() {
    println!("Usage: bifrost_benchmark validate [--manifest PATH]");
}

fn print_run_help() {
    println!(
        "Usage: bifrost_benchmark run [--manifest PATH] [--repo NAME] [--output DIR] [--max-files N]"
    );
}
