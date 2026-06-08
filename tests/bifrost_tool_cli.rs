use std::fs;
use std::path::PathBuf;
use std::process::Command;

use tempfile::TempDir;

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("testcode-java")
}

#[test]
fn tool_get_summaries_renders_text() {
    let output = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--root")
        .arg(fixture_root())
        .arg("--tool")
        .arg("get_summaries")
        .arg("--args")
        .arg(r#"{"targets":["A.java"]}"#)
        .output()
        .expect("run bifrost --tool get_summaries");

    assert!(
        output.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("A.java"), "{stdout}");
    assert!(stdout.contains("3..52: public class A"), "{stdout}");
}

#[test]
fn tool_no_line_numbers_suppresses_line_prefixes() {
    let output = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--root")
        .arg(fixture_root())
        .arg("--tool")
        .arg("get_summaries")
        .arg("--args")
        .arg(r#"{"targets":["A.java"]}"#)
        .arg("--no-line-numbers")
        .output()
        .expect("run bifrost --tool get_summaries --no-line-numbers");

    assert!(
        output.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("A.java"), "{stdout}");
    assert!(!stdout.contains("3..52: public class A"), "{stdout}");
    assert!(stdout.contains("public class A"), "{stdout}");
}

#[test]
fn tool_normalizes_absolute_paths_inside_workspace() {
    let output = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--root")
        .arg(fixture_root())
        .arg("--tool")
        .arg("get_file_contents")
        .arg("--args")
        .arg(format!(
            r#"{{"file_paths":["{}"]}}"#,
            fixture_root().join("A.java").display()
        ))
        .output()
        .expect("run bifrost --tool get_file_contents");

    assert!(
        output.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("\"path\": \"A.java\""), "{stdout}");
    assert!(stdout.contains("\"content\":"), "{stdout}");
}

#[test]
fn tool_rejects_absolute_paths_outside_workspace() {
    let outside = TempDir::new().expect("outside dir");
    let outside_file = outside.path().join("Outside.java");
    fs::write(&outside_file, "class Outside {}\n").expect("write outside file");

    let output = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--root")
        .arg(fixture_root())
        .arg("--tool")
        .arg("get_file_contents")
        .arg("--args")
        .arg(format!(
            r#"{{"file_paths":["{}"]}}"#,
            outside_file.display()
        ))
        .output()
        .expect("run bifrost --tool get_file_contents");

    assert!(!output.status.success(), "status should fail");
    let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
    assert!(stderr.contains("outside active workspace"), "{stderr}");
}

#[test]
fn tool_unknown_tool_is_reported() {
    let output = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--root")
        .arg(fixture_root())
        .arg("--tool")
        .arg("unknown_tool")
        .output()
        .expect("run bifrost --tool unknown_tool");

    assert!(!output.status.success(), "status should fail");
    let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
    assert!(stderr.contains("Unknown tool"), "{stderr}");
}

#[test]
fn tool_cannot_be_combined_with_server() {
    let output = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--root")
        .arg(fixture_root())
        .arg("--tool")
        .arg("get_summaries")
        .arg("--server")
        .arg("searchtools")
        .output()
        .expect("run invalid bifrost args");

    assert!(!output.status.success(), "status should fail");
    let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
    assert!(
        stderr.contains("--tool cannot be combined with --server"),
        "{stderr}"
    );
}

#[test]
fn help_mentions_tool_mode() {
    let output = Command::new(env!("CARGO_BIN_EXE_bifrost"))
        .arg("--help")
        .output()
        .expect("run bifrost --help");

    assert!(
        output.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("--tool TOOL_NAME"), "{stdout}");
    assert!(stdout.contains("--args"), "{stdout}");
}
