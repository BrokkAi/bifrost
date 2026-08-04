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
//! Both assert that the cache they hand out really is outside the checkout, so
//! a change that quietly re-binds the repository database fails the tests that
//! rely on it instead of corrupting them.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;

use brokk_bifrost_analysis::gitblob::{CACHE_DIR_ENV, cache_db_path};
use tempfile::TempDir;

/// A checked-in fixture corpus, materialized outside the repository.
///
/// The copy is a workspace root in its own right, so every derived artifact
/// (the persisted cache above all) lands beside it and is removed with it.
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

/// Fail unless the cache `scratch_root` resolves to lives inside it.
///
/// This is the regression guard for issue #1588, re-evaluated by every test
/// that takes a scratch root rather than recorded once somewhere it can rot.
/// It also catches an ambient `BIFROST_CACHE_DIR`, which would silently defeat
/// the isolation by pointing every root at one shared database.
fn assert_cache_is_scratch(scratch_root: &Path) {
    let resolved = cache_db_path(scratch_root);
    assert!(
        resolved.starts_with(scratch_root),
        "a test workspace must own its cache: {} resolved to {}. \
         A scratch root inside a Git checkout resolves to that checkout's shared \
         `.bifrost/cache` database, and an ambient {CACHE_DIR_ENV} redirects every \
         root to one database; neither is safe for tests (issue #1588).",
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
