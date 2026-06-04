use brokk_bifrost::benchmark::{BenchmarkManifest, BenchmarkScenario, ManifestLanguage};
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

fn print_help() {
    println!("Usage: bifrost_benchmark validate [--manifest PATH]");
    println!("Defaults: --manifest is benchmark/targets.toml");
}

fn print_validate_help() {
    println!("Usage: bifrost_benchmark validate [--manifest PATH]");
}
