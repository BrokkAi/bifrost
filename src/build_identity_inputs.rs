/// Every tracked path that can change the produced binary.
///
/// This is the definition of "what the build is", and four things read it:
/// the rerun triggers and the compile-time identity in `build.rs` (which
/// `include!`s this file), and the runtime identity check in
/// `src/benchmark/runner.rs` (`current_bifrost_commit_at`). The build
/// identity names the last commit that touched one of these paths, not
/// `HEAD`: a commit touching nothing compiled must not produce a different
/// identity, both because the release metadata cycle depends on it (a
/// checksum correction must not perturb the build) and because the runtime
/// check would otherwise reject a binary that is byte-identical to what a
/// rebuild would produce. The compile-time and runtime derivations must stay
/// identical, which is why the list lives in this one file.
///
/// Adding to this list is safe; removing from it is not. A path that affects
/// the binary but is absent here yields an identity that fails to change when
/// the binary does.
const COMPILED_INPUTS: &[&str] = &[
    "src",
    "crates",
    "resources",
    "Cargo.toml",
    "Cargo.lock",
    "build.rs",
    // The pinned channel and the codegen flags both change the emitted binary
    // and were absent from the rerun and fingerprint sets before this list
    // existed.
    "rust-toolchain.toml",
    ".cargo/config.toml",
];

enum CompiledInputsFingerprint {
    DiffCommandUnavailable,
    NoUsableDiff,
    HashCommandUnavailable,
    HashOutput(Vec<u8>),
}

// Keep the command outcomes separate so each caller can preserve its fallback
// behavior for unavailable Git operations.
fn compiled_inputs_fingerprint_at(
    repo_root: &std::path::Path,
) -> CompiledInputsFingerprint {
    let diff = match std::process::Command::new("git")
        .args(
            ["diff", "--binary", "HEAD", "--"]
                .iter()
                .copied()
                .chain(COMPILED_INPUTS.iter().copied()),
        )
        .current_dir(repo_root)
        .output()
    {
        Ok(diff) => diff,
        Err(_) => return CompiledInputsFingerprint::DiffCommandUnavailable,
    };
    if !diff.status.success() || diff.stdout.is_empty() {
        return CompiledInputsFingerprint::NoUsableDiff;
    }

    let mut hasher = match std::process::Command::new("git")
        .args(["hash-object", "--stdin"])
        .current_dir(repo_root)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
    {
        Ok(hasher) => hasher,
        Err(_) => return CompiledInputsFingerprint::HashCommandUnavailable,
    };
    let Some(mut stdin) = hasher.stdin.take() else {
        return CompiledInputsFingerprint::HashCommandUnavailable;
    };
    if std::io::Write::write_all(&mut stdin, &diff.stdout).is_err() {
        return CompiledInputsFingerprint::HashCommandUnavailable;
    }
    drop(stdin);

    let hash = match hasher.wait_with_output() {
        Ok(hash) if hash.status.success() => hash,
        _ => return CompiledInputsFingerprint::HashCommandUnavailable,
    };
    CompiledInputsFingerprint::HashOutput(hash.stdout)
}
