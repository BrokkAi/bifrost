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
}
