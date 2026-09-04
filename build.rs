use std::io::Write;
use std::path::Path;
use std::process::Command;

use serde::Deserialize;

fn git_output(args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(args)
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .filter(|value| !value.is_empty())
}

include!("src/build_identity_inputs.rs");

#[derive(Deserialize)]
struct CargoVcsInfo {
    git: CargoVcsGit,
}

#[derive(Deserialize)]
struct CargoVcsGit {
    sha1: String,
    dirty: bool,
}

fn cargo_vcs_identity(manifest_dir: &Path) -> Option<String> {
    let contents = std::fs::read(manifest_dir.join(".cargo_vcs_info.json")).ok()?;
    let info: CargoVcsInfo = serde_json::from_slice(&contents).ok()?;
    let sha = info.git.sha1;
    if sha.len() != 40 || !sha.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    if info.git.dirty {
        Some(format!("{sha}-dirty.cargo-vcs"))
    } else {
        Some(sha)
    }
}

fn dirty_fingerprint() -> Option<String> {
    let diff = Command::new("git")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(
            ["diff", "--binary", "HEAD", "--"]
                .iter()
                .chain(COMPILED_INPUTS.iter()),
        )
        .output()
        .ok()?;
    if !diff.status.success() || diff.stdout.is_empty() {
        return None;
    }
    let mut child = Command::new("git")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
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
    for input in COMPILED_INPUTS {
        println!("cargo:rerun-if-changed={input}");
    }
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
    println!("cargo:rerun-if-changed=.cargo_vcs_info.json");

    let identity = std::env::var("BIFROST_BUILD_IDENTITY_OVERRIDE").unwrap_or_else(|_| {
        // The last commit that touched a compiled input, not HEAD. A shallow
        // clone cannot see past its boundary and returns nothing here, which is
        // indistinguishable from "no such commit", so fall back to HEAD: naming
        // a commit that did not change the build is imprecise but never claims
        // two different binaries share an identity. Release builds do not rely
        // on that fallback -- the readiness preflight has full history and
        // passes the resolved value through BIFROST_BUILD_IDENTITY_OVERRIDE.
        let mut log_args = vec!["log", "-1", "--format=%H", "--"];
        log_args.extend_from_slice(COMPILED_INPUTS);
        let commit = git_output(&log_args).or_else(|| git_output(&["rev-parse", "HEAD"]));
        if let Some(commit) = commit {
            if let Some(fingerprint) = dirty_fingerprint() {
                format!("{commit}-dirty.{fingerprint}")
            } else {
                commit
            }
        } else {
            cargo_vcs_identity(Path::new(env!("CARGO_MANIFEST_DIR")))
                .unwrap_or_else(|| "unknown".to_string())
        }
    });
    println!("cargo:rustc-env=BIFROST_BUILD_IDENTITY={identity}");
}
