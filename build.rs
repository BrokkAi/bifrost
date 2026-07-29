use std::io::Write;
use std::process::Command;

fn git_output(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .filter(|value| !value.is_empty())
}

fn dirty_fingerprint() -> Option<String> {
    let diff = Command::new("git")
        .args([
            "diff",
            "--binary",
            "HEAD",
            "--",
            "src",
            "crates",
            "Cargo.toml",
            "Cargo.lock",
            "build.rs",
            "resources",
        ])
        .output()
        .ok()?;
    if !diff.status.success() || diff.stdout.is_empty() {
        return None;
    }
    let mut child = Command::new("git")
        .args(["hash-object", "--stdin"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .ok()?;
    child.stdin.take()?.write_all(&diff.stdout).ok()?;
    let output = child.wait_with_output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .filter(|hash| !hash.is_empty())
}

fn main() {
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=crates");
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-changed=Cargo.lock");
    println!("cargo:rerun-if-changed=resources");
    for git_path in ["HEAD", "index", "packed-refs"] {
        if let Some(path) = git_output(&["rev-parse", "--git-path", git_path]) {
            println!("cargo:rerun-if-changed={path}");
        }
    }
    if let Some(reference) = git_output(&["symbolic-ref", "-q", "HEAD"])
        && let Some(path) = git_output(&["rev-parse", "--git-path", &reference])
    {
        println!("cargo:rerun-if-changed={path}");
    }
    println!("cargo:rerun-if-env-changed=BIFROST_BUILD_IDENTITY_OVERRIDE");

    let identity = std::env::var("BIFROST_BUILD_IDENTITY_OVERRIDE").unwrap_or_else(|_| {
        let commit = git_output(&["rev-parse", "HEAD"]).unwrap_or_else(|| "unknown".to_string());
        if let Some(fingerprint) = dirty_fingerprint() {
            format!("{commit}-dirty.{fingerprint}")
        } else {
            commit
        }
    });
    println!("cargo:rustc-env=BIFROST_BUILD_IDENTITY={identity}");
}
