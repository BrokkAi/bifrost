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
