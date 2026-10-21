#![allow(dead_code)]

//! Scratch cache roots for tests that would otherwise open the developer's
//! real repository cache database.
//!
//! A persisted workspace resolves its store through
//! `gitblob::cache_db_path`, which walks up to the *primary* repository root.
//! A test rooted at `<checkout>/tests/fixtures/<name>` therefore opens the
//! store under `<checkout>/.bifrost/cache`: the one database every other
//! Bifrost build on the machine also writes. On 2026-08-04 a sibling worktree
//! migrated that file one schema version ahead and 35 otherwise unrelated
//! tests failed with `DatabaseTooFarAhead` (issue #1588). Tests took all of
//! the coupling of the shared cache and none of its reuse benefit.
//!
//! Two seams remove the coupling, both by moving the cache the workspace
//! resolves rather than by teaching individual tests about caches:
//!
//! * [`FixtureCorpus`] materializes a checked-in fixture outside the
//!   repository, so `cache_db_path` resolves inside the copy. It suits an
//!   in-process test, where `BIFROST_CACHE_DIR` is not available: the
//!   environment is process-global, so setting it would funnel every
//!   concurrently running test in the binary onto one SQLite file and would
//!   break the tests that assert default resolution.
//! * [`ScratchCacheDir`] sets `BIFROST_CACHE_DIR` on one spawned `Command`.
//!   That override is per-process by construction, which is exactly what a
//!   spawned binary needs and what an in-process test cannot have.
//!
//! Both assert that the workspace owns its cache. An ambient
//! `BIFROST_CACHE_ROOT` may relocate it into a private repository namespace,
//! but a checked-in fixture must not borrow its containing checkout's namespace
//! and an ambient exact-directory override must not funnel unrelated roots
//! into one database.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;

use brokk_bifrost_analysis::gitblob::{
    CACHE_DIR_ENV, CACHE_ROOT_ENV, cache_db_path, discover, primary_repo_root,
};
use tempfile::TempDir;

/// A checked-in fixture corpus, materialized outside the repository.
///
/// The copy owns its cache: by default it lives beside the workspace; an
/// ambient BIFROST_CACHE_ROOT instead gives it a private repository namespace.
pub struct FixtureCorpus {
    _temp: TempDir,
    root: PathBuf,
}

impl FixtureCorpus {
    /// Copy the fixture directory `source` to a scratch workspace root.
    pub fn copied_from(source: &Path) -> Self {
        let temp = TempDir::new().expect("create fixture corpus temp dir");
        let root = temp
            .path()
            .canonicalize()
            .expect("canonicalize fixture corpus root");
        copy_dir_recursively(source, &root).unwrap_or_else(|err| {
            panic!(
                "failed to copy fixture corpus {} to {}: {err}",
                source.display(),
                root.display()
            )
        });
        assert_cache_is_scratch(&root);
        Self { _temp: temp, root }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
}

/// A cache directory for one spawned Bifrost process.
pub struct ScratchCacheDir {
    temp: TempDir,
}

impl ScratchCacheDir {
    pub fn new() -> Self {
        Self {
            temp: TempDir::new().expect("create scratch cache temp dir"),
        }
    }

    pub fn path(&self) -> &Path {
        self.temp.path()
    }

    /// A `Command` for `program` whose cache is this directory.
    ///
    /// A child that inherits the ambient environment resolves the cache from
    /// its workspace root exactly as an in-process build does, so every
    /// spawned process pointed at a path inside the checkout needs one of
    /// these (issue #1588).
    pub fn command(&self, program: impl AsRef<OsStr>) -> Command {
        let mut command = Command::new(program);
        self.bind(&mut command);
        command
    }

    /// Point an already-built `Command` at this directory.
    pub fn bind(&self, command: &mut Command) {
        assert_cache_is_scratch(self.temp.path());
        command.env(CACHE_DIR_ENV, self.temp.path());
    }
}

impl Default for ScratchCacheDir {
    fn default() -> Self {
        Self::new()
    }
}

/// Fail unless `scratch_root` owns its resolved cache directory.
///
/// This is the regression guard for issue #1588, re-evaluated by every test
/// that takes a scratch root rather than recorded once somewhere it can rot.
/// It also catches an ambient `BIFROST_CACHE_DIR`, which would silently defeat
/// the isolation by pointing every root at one shared database.
pub(crate) fn cache_is_scratch(scratch_root: &Path) -> bool {
    let resolved = cache_db_path(scratch_root);
    if resolved.starts_with(scratch_root) {
        return true;
    }
    let Some(cache_root) = std::env::var_os(CACHE_ROOT_ENV).filter(|value| !value.is_empty())
    else {
        return false;
    };
    if std::env::var_os(CACHE_DIR_ENV).is_some_and(|value| !value.is_empty()) {
        return false;
    }
    // A checked-in fixture must not borrow its containing checkout's namespace.
    let canonical_root = scratch_root
        .canonicalize()
        .unwrap_or_else(|_| scratch_root.to_path_buf());
    if discover(scratch_root)
        .as_ref()
        .and_then(primary_repo_root)
        .is_some_and(|primary| primary != canonical_root)
    {
        return false;
    }
    // The resolver gives each primary root one child of CACHE_ROOT. Accept
    // that private namespace, never the machine root itself as a shared cache.
    resolved.parent().and_then(Path::parent) == Some(Path::new(&cache_root))
}

pub(crate) fn assert_cache_is_scratch(scratch_root: &Path) {
    let resolved = cache_db_path(scratch_root);
    assert!(
        cache_is_scratch(scratch_root),
        "a test workspace must own its cache: {} resolved to {}. \
         The cache must live inside the scratch workspace or its private \
         {CACHE_ROOT_ENV} namespace. A containing checkout's cache and a shared \
         ambient {CACHE_DIR_ENV} are unsafe for tests (issue #1588).",
        scratch_root.display(),
        resolved.display(),
    );
}

pub fn copy_dir_recursively(source: &Path, destination: &Path) -> std::io::Result<()> {
    let mut pending = vec![(source.to_path_buf(), destination.to_path_buf())];
    while let Some((source, destination)) = pending.pop() {
        std::fs::create_dir_all(&destination)?;
        for entry in std::fs::read_dir(&source)? {
            let entry = entry?;
            let target = destination.join(entry.file_name());
            if entry.file_type()?.is_dir() {
                pending.push((entry.path(), target));
            } else {
                std::fs::copy(entry.path(), target)?;
            }
        }
    }
    Ok(())
}
