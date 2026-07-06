use brokk_bifrost::benchmark::{
    BenchmarkCompareReport, BenchmarkManifest, BenchmarkRunReport, BenchmarkScenario,
    ManifestLanguage, RunRequest, run_benchmark,
};
use chrono::Utc;
use serde::Serialize;
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
        "compare" => {
            let mut baseline_path = None;
            let mut candidate_path = None;
            let mut output_path = None;
            let mut strict = false;
            while let Some(arg) = args.next() {
                match arg.as_str() {
                    "--baseline" => {
                        baseline_path = Some(PathBuf::from(
                            args.next()
                                .ok_or_else(|| "--baseline requires a path".to_string())?,
                        ));
                    }
                    "--candidate" => {
                        candidate_path = Some(PathBuf::from(
                            args.next()
                                .ok_or_else(|| "--candidate requires a path".to_string())?,
                        ));
                    }
                    "--output" => {
                        output_path =
                            Some(PathBuf::from(args.next().ok_or_else(|| {
                                "--output requires a file path".to_string()
                            })?));
                    }
                    "--strict" => strict = true,
                    "--help" | "-h" => {
                        print_compare_help();
                        return Ok(());
                    }
                    other => return Err(format!("unknown compare argument: {other}")),
                }
            }
            compare_reports(
                baseline_path.ok_or_else(|| "--baseline is required".to_string())?,
                candidate_path.ok_or_else(|| "--candidate is required".to_string())?,
                output_path,
                strict,
            )
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
    if report.has_failures() {
        return Err(format!(
            "benchmark run recorded {} failed scenario(s); report: {}",
            report.failed_scenarios_count(),
            report_path.display()
        ));
    }
    Ok(())
}

fn compare_reports(
    baseline_path: PathBuf,
    candidate_path: PathBuf,
    output_path: Option<PathBuf>,
    strict: bool,
) -> Result<(), String> {
    let baseline = load_report(&baseline_path)?;
    let candidate = load_report(&candidate_path)?;
    let comparison = BenchmarkCompareReport::from_reports(&baseline, &candidate);

    if let Some(path) = output_path {
        write_json(&comparison, &path, "compare report")?;
        println!("wrote {}", path.display());
    }

    print_compare_summary(&comparison);

    if strict && comparison.has_actionable_regressions {
        return Err(format!(
            "benchmark compare recorded {} regression(s)",
            comparison.actionable_regression_count
        ));
    }

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
    write_json(report, report_path, "report")
}

fn write_json<T: Serialize>(value: &T, path: &Path, label: &str) -> Result<(), String> {
    let json = serde_json::to_string_pretty(value)
        .map_err(|err| format!("failed to serialize {label}: {err}"))?;
    std::fs::write(path, json)
        .map_err(|err| format!("failed to write {label} `{}`: {err}", path.display()))
}

fn load_report(path: &Path) -> Result<BenchmarkRunReport, String> {
    let json = std::fs::read_to_string(path)
        .map_err(|err| format!("failed to read report `{}`: {err}", path.display()))?;
    serde_json::from_str(&json)
        .map_err(|err| format!("failed to parse report `{}`: {err}", path.display()))
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

fn print_compare_summary(report: &BenchmarkCompareReport) {
    if report.has_regressions {
        println!("regressions detected: {}", report.regression_count);
    } else {
        println!("no regressions over threshold");
    }
    println!("compared {} scenarios", report.compared_scenarios_count);
    println!(
        "threshold: {:.1}% and {:.1} ms absolute floor",
        report.thresholds.relative_pct, report.thresholds.absolute_ms
    );
    if let Some(environment_variance) = &report.environment_variance {
        println!(
            "suspected environment variance: {}",
            environment_variance.detail
        );
    }
    if report.improvement_count > 0 {
        println!("improvements: {}", report.improvement_count);
    }
    if report.missing_candidate_count > 0 {
        println!(
            "missing candidate scenarios: {}",
            report.missing_candidate_count
        );
    }
    if report.new_candidate_count > 0 {
        println!("new candidate scenarios: {}", report.new_candidate_count);
    }

    for scenario in &report.scenarios {
        if matches!(
            scenario.outcome,
            brokk_bifrost::benchmark::ScenarioCompareOutcome::Unchanged
        ) {
            continue;
        }
        let detail = scenario.detail.as_deref().unwrap_or("state changed");
        match scenario.delta_ms {
            Some(delta_ms) => match scenario.delta_pct {
                Some(delta_pct) => println!(
                    "  {} {} {:?}: {:?} delta={delta_ms:.1} ms ({delta_pct:.1}%)",
                    scenario.repo_name,
                    scenario.scenario.label(),
                    scenario.transport,
                    scenario.outcome
                ),
                None => println!(
                    "  {} {} {:?}: {:?} delta={delta_ms:.1} ms",
                    scenario.repo_name,
                    scenario.scenario.label(),
                    scenario.transport,
                    scenario.outcome
                ),
            },
            None => println!(
                "  {} {} {:?}: {:?} ({detail})",
                scenario.repo_name,
                scenario.scenario.label(),
                scenario.transport,
                scenario.outcome
            ),
        }
    }
}

fn print_help() {
    println!("Usage: bifrost_benchmark <subcommand> [options]");
    println!("Subcommands:");
    println!("  validate [--manifest PATH]");
    println!("  run [--manifest PATH] [--repo NAME] [--output DIR] [--max-files N]");
    println!("  compare --baseline PATH --candidate PATH [--output PATH] [--strict]");
}

fn print_validate_help() {
    println!("Usage: bifrost_benchmark validate [--manifest PATH]");
}

fn print_run_help() {
    println!(
        "Usage: bifrost_benchmark run [--manifest PATH] [--repo NAME] [--output DIR] [--max-files N]"
    );
}

fn print_compare_help() {
    println!(
        "Usage: bifrost_benchmark compare --baseline PATH --candidate PATH [--output PATH] [--strict]"
    );
}
