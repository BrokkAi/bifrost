use std::io::Write;
use std::path::Path;
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
    let source_dir = Path::new("vendor/tree-sitter-scala/src");
    let parser = source_dir.join("parser.c");
    let scanner = source_dir.join("scanner.c");
    let headers = [
        source_dir.join("tree_sitter/alloc.h"),
        source_dir.join("tree_sitter/array.h"),
        source_dir.join("tree_sitter/parser.h"),
    ];

    let mut build = cc::Build::new();
    build
        .std("c11")
        .include(source_dir)
        .flag_if_supported("-Wno-unused")
        .file(&parser)
        .file(&scanner);

    #[cfg(target_env = "msvc")]
    build.flag("-utf-8");

    // A downstream crate may also link the published tree-sitter-scala crate.
    // Keep every native symbol private so link order cannot substitute that
    // parser (or its scanner) for Bifrost's pinned snapshot.
    for (upstream, private) in [
        ("tree_sitter_scala", "brokk_bifrost_tree_sitter_scala"),
        (
            "tree_sitter_scala_external_scanner_create",
            "brokk_bifrost_tree_sitter_scala_external_scanner_create",
        ),
        (
            "tree_sitter_scala_external_scanner_destroy",
            "brokk_bifrost_tree_sitter_scala_external_scanner_destroy",
        ),
        (
            "tree_sitter_scala_external_scanner_scan",
            "brokk_bifrost_tree_sitter_scala_external_scanner_scan",
        ),
        (
            "tree_sitter_scala_external_scanner_serialize",
            "brokk_bifrost_tree_sitter_scala_external_scanner_serialize",
        ),
        (
            "tree_sitter_scala_external_scanner_deserialize",
            "brokk_bifrost_tree_sitter_scala_external_scanner_deserialize",
        ),
        ("token_name", "brokk_bifrost_tree_sitter_scala_token_name"),
    ] {
        build.define(upstream, Some(private));
    }

    build.compile("brokk-bifrost-tree-sitter-scala");

    for path in [parser, scanner].into_iter().chain(headers) {
        println!("cargo:rerun-if-changed={}", path.display());
    }
    println!("cargo:rerun-if-changed=src");
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
