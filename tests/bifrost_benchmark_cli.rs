use std::process::Command;

#[test]
fn validate_subcommand_reports_checked_in_manifest_coverage() {
    let output = Command::new(env!("CARGO_BIN_EXE_bifrost_benchmark"))
        .arg("validate")
        .output()
        .expect("run bifrost_benchmark validate");

    assert!(
        output.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("validated 10 repos"), "{stdout}");
    assert!(stdout.contains("covered languages:"), "{stdout}");
    assert!(stdout.contains("covered scenarios:"), "{stdout}");
    assert!(stdout.contains("scan_usages"), "{stdout}");
    assert!(stdout.contains("dead_code_smells"), "{stdout}");
}

#[test]
fn run_help_mentions_max_files_subset_option() {
    let output = Command::new(env!("CARGO_BIN_EXE_bifrost_benchmark"))
        .arg("run")
        .arg("--help")
        .output()
        .expect("run bifrost_benchmark run --help");

    assert!(
        output.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("--max-files"), "{stdout}");
}

#[test]
fn compare_help_mentions_baseline_candidate_and_strict() {
    let output = Command::new(env!("CARGO_BIN_EXE_bifrost_benchmark"))
        .arg("compare")
        .arg("--help")
        .output()
        .expect("run bifrost_benchmark compare --help");

    assert!(
        output.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("--baseline"), "{stdout}");
    assert!(stdout.contains("--candidate"), "{stdout}");
    assert!(stdout.contains("--strict"), "{stdout}");
}
