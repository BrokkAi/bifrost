//! Shared git blob-OID plumbing for content-addressed caches.
//!
//! Files are hashed from the bytes visible in the working tree, using Git's
//! blob hashing, so analyzer cache keys line up with the exact byte stream used
//! for tree-sitter ranges and LSP positions. On LF checkouts this matches the
//! index OID for clean files; on CRLF checkouts it intentionally differs.

use std::collections::{HashMap, HashSet};
use std::fs::Metadata;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;

use git2::{
    AttrCheckFlags, AttrValue, ErrorCode, IndexEntry, ObjectType, Oid, Repository, Status,
    StatusOptions,
};
use growable_bloom_filter::GrowableBloom;

use crate::analyzer::canonical_hash::{hash_domain_bytes, lower_hex_string};

pub type Result<T> = std::result::Result<T, String>;

/// Workspace-local directory holding Bifrost's tracked project configuration.
pub const PROJECT_DIR_NAME: &str = ".bifrost";

/// Generated state beneath [`PROJECT_DIR_NAME`].
pub const CACHE_SUBDIR_NAME: &str = "cache";
pub const CACHE_DIR_ENV: &str = "BIFROST_CACHE_DIR";
pub const CACHE_ROOT_ENV: &str = "BIFROST_CACHE_ROOT";

/// Directory name Bifrost owns inside a machine-local cache location.
const MACHINE_CACHE_APP_NAME: &str = "bifrost";

/// Subdirectory of the machine-local cache root that holds one database per
/// set of workspace roots (see [`multiroot_persistence_dir`]).
const MULTIROOT_SUBDIR_NAME: &str = "multiroot";

/// Discover the repository containing `root`, if any.
pub fn discover(root: &Path) -> Option<Repository> {
    Repository::discover(root)
        .ok()
        .filter(|repo| !repo.is_bare())
}

/// The repository's default branch reference, or `HEAD` when the checkout
/// does not advertise one through `refs/remotes/origin/HEAD`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefaultBranchRef {
    pub ref_name: String,
    pub display_name: String,
    pub fallback: bool,
}

/// Resolve the default branch without consulting a network host.
///
/// A remote's symbolic `origin/HEAD` is the only local Git record that
/// identifies its default branch unambiguously. Checkouts that do not carry
/// that record fall back to their current `HEAD` and report the fallback so
/// callers can describe the reduced evidence honestly.
pub fn resolve_default_branch_ref(repo: &Repository) -> DefaultBranchRef {
    if let Ok(head_ref) = repo.find_reference("refs/remotes/origin/HEAD")
        && let Some(target) = head_ref.symbolic_target()
    {
        let display_name = target.rsplit('/').next().unwrap_or(target).to_string();
        return DefaultBranchRef {
            ref_name: target.to_string(),
            display_name,
            fallback: false,
        };
    }
    DefaultBranchRef {
        ref_name: "HEAD".to_string(),
        display_name: "HEAD (default branch unavailable)".to_string(),
        fallback: true,
    }
}

/// Whether `root` resolves to a Git object database, a bare repository
/// included.
///
/// This deliberately does not go through [`discover`], which filters bare
/// repositories out because the analyses built on it walk a checkout. Reading
/// an immutable revision needs no checkout: the blobs come out of the object
/// database, which a bare repository has, and `git clone --bare` is a normal
/// way to hand a tool history without a worktree. The cache location agrees --
/// [`cache_dir_path`] falls back to the given root, so a bare repository's
/// cache lands beside its object database, which is where the location
/// contract puts every other repository's cache too.
pub fn has_object_database(root: &Path) -> bool {
    Repository::discover(root).is_ok()
}

/// Resolve the primary repository root. Linked worktrees collapse to the
/// checkout that owns the common object database.
pub fn primary_repo_root(repo: &Repository) -> Option<PathBuf> {
    let root = if repo.is_bare() {
        None
    } else if repo.is_worktree() {
        repo.commondir().parent().map(Path::to_path_buf)
    } else {
        repo.workdir().map(Path::to_path_buf)
    };
    root.map(|root| root.canonicalize().unwrap_or(root))
}

/// Resolve the generated cache directory under `.bifrost/cache` at the primary
/// repo root. Non-git roots fall back to the provided workspace root.
///
/// This is the single cache-location contract, and every entry point resolves
/// through it: CLI, LSP, and MCP sessions bound through client roots or Codex
/// sandbox metadata alike. The cache belongs at the primary root because it is
/// keyed by blob object ID and is therefore valid for every linked worktree of
/// that checkout, and because it sits beside the object database the analyzer
/// must already be able to read. Do not re-derive it per bound root: a private
/// per-worktree database splits the cache in two (a CLI and an MCP session on
/// the same checkout stop seeing each other's work) and costs a full extra copy
/// of the corpus. Scoping a session's *results* to its bound root is the job of
/// reconciliation against that worktree's current oids, not of the file's
/// location. `BIFROST_CACHE_ROOT` keeps that sharing contract while relocating
/// each primary repository to a stable child of one machine-local root.
/// `BIFROST_CACHE_DIR` deliberately overrides both locations with one exact
/// directory, at the cost of per-root divergence and cross-repository writer
/// contention; version-keyed naming applies inside either override too.
///
pub fn cache_dir_path(workspace_root: &Path) -> PathBuf {
    cache_dir_path_with_overrides(
        workspace_root,
        std::env::var_os(CACHE_DIR_ENV).filter(|value| !value.is_empty()),
        std::env::var_os(CACHE_ROOT_ENV).filter(|value| !value.is_empty()),
    )
}

fn cache_dir_path_with_overrides(
    workspace_root: &Path,
    cache_dir: Option<std::ffi::OsString>,
    cache_root: Option<std::ffi::OsString>,
) -> PathBuf {
    if let Some(cache_dir) = cache_dir {
        return PathBuf::from(cache_dir);
    }
    let primary_root = discover(workspace_root)
        .as_ref()
        .and_then(primary_repo_root)
        .unwrap_or_else(|| workspace_root.to_path_buf());
    if let Some(cache_root) = cache_root {
        let canonical_primary = primary_root.canonicalize().unwrap_or(primary_root);
        return PathBuf::from(cache_root).join(cache_repository_key(&canonical_primary));
    }
    primary_root.join(PROJECT_DIR_NAME).join(CACHE_SUBDIR_NAME)
}

/// Resolve the unified cache database path through [`cache_dir_path`].
///
/// The file name carries the schema version this build reads
/// (`crate::cache_db::cache_db_file_name`), so checkouts at different versions
/// share the directory without sharing a file (issue #1589).
pub fn cache_db_path(workspace_root: &Path) -> PathBuf {
    cache_dir_path(workspace_root).join(crate::cache_db::cache_db_file_name())
}

#[cfg(test)]
fn cache_db_path_with_overrides(
    workspace_root: &Path,
    cache_dir: Option<std::ffi::OsString>,
    cache_root: Option<std::ffi::OsString>,
) -> PathBuf {
    cache_dir_path_with_overrides(workspace_root, cache_dir, cache_root)
        .join(crate::cache_db::cache_db_file_name())
}

fn cache_repository_key(primary_root: &Path) -> String {
    let digest = hash_domain_bytes(
        b"bifrost-cache-primary-root-v1",
        &platform_path_bytes(primary_root),
    );
    format!(
        "{}-{}",
        readable_path_name(primary_root),
        &lower_hex_string(&digest)[..16]
    )
}

/// The last path component, reduced to characters every supported filesystem
/// accepts in a directory name. Cache keys carry it so a human listing the
/// cache can tell the entries apart; the digest beside it, not this name, is
/// what makes an entry unique.
fn readable_path_name(path: &Path) -> String {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(|name| {
            name.chars()
                .map(|character| {
                    if character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.') {
                        character
                    } else {
                        '_'
                    }
                })
                .collect::<String>()
        })
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "workspace".to_string())
}

/// Machine-local cache root for state that no single repository owns.
///
/// `BIFROST_CACHE_ROOT` wins when it is set and non-empty, exactly as it does
/// in [`cache_dir_path`], so one environment variable still relocates every
/// Bifrost cache on the machine. Otherwise this is the platform's conventional
/// per-user cache directory. No platform-directory crate is in this workspace,
/// and these environment variables are the platform contract on each system, so
/// resolve them directly, the way the MCP installer resolves its own
/// directories (`src/mcp_install.rs`).
///
/// A host with no resolvable home directory -- a stripped container, a service
/// account with no `%LOCALAPPDATA%` -- gets `None`. Its caller reports that
/// instead of inventing a location the next process would not find again.
fn machine_cache_root() -> Option<PathBuf> {
    machine_cache_root_with_overrides(
        std::env::var_os(CACHE_ROOT_ENV).filter(|value| !value.is_empty()),
    )
}

fn machine_cache_root_with_overrides(cache_root: Option<std::ffi::OsString>) -> Option<PathBuf> {
    match cache_root {
        Some(cache_root) => Some(PathBuf::from(cache_root)),
        None => platform_cache_root(),
    }
}

#[cfg(windows)]
fn platform_cache_root() -> Option<PathBuf> {
    std::env::var_os("LOCALAPPDATA")
        .filter(|value| !value.is_empty())
        .map(|local_app_data| {
            PathBuf::from(local_app_data)
                .join(MACHINE_CACHE_APP_NAME)
                .join(CACHE_SUBDIR_NAME)
        })
}

#[cfg(target_os = "macos")]
fn platform_cache_root() -> Option<PathBuf> {
    home_dir().map(|home| {
        home.join("Library")
            .join("Caches")
            .join(MACHINE_CACHE_APP_NAME)
    })
}

#[cfg(all(unix, not(target_os = "macos")))]
fn platform_cache_root() -> Option<PathBuf> {
    match std::env::var_os("XDG_CACHE_HOME").filter(|value| !value.is_empty()) {
        Some(xdg_cache_home) => Some(PathBuf::from(xdg_cache_home).join(MACHINE_CACHE_APP_NAME)),
        None => home_dir().map(|home| home.join(".cache").join(MACHINE_CACHE_APP_NAME)),
    }
}

#[cfg(not(any(unix, windows)))]
fn platform_cache_root() -> Option<PathBuf> {
    None
}

#[cfg(unix)]
fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

/// Persistence root for a workspace assembled from several repositories.
///
/// Such a workspace owns no repository of its own to hold a cache, and writing
/// into any one member would make that member's database depend on which other
/// folders happened to be open beside it. The database therefore lives at a
/// machine-local location named by the root set itself, so the same folders --
/// opened in any order, by any session -- find the same database and reuse the
/// parse work already in it.
///
/// The name is the first root's directory name, for a human reading the cache,
/// plus a digest over every canonical root path. Distinct root sets get
/// distinct directories; ordering does not matter, because the roots are
/// sorted before hashing. `None` means this machine has no resolvable cache
/// root (see [`machine_cache_root`]).
///
/// This resolves a path and creates nothing. The directory appears when a
/// store opens beneath it, at the location the [`cache_dir_path`] funnel picks
/// for this root -- which is `<dir>/.bifrost/cache` for a non-git directory,
/// and an override's own location when one is set.
pub fn multiroot_persistence_dir(roots: &[PathBuf]) -> Option<PathBuf> {
    multiroot_persistence_dir_under(machine_cache_root(), roots)
}

/// [`multiroot_persistence_dir`] with the machine cache root supplied directly.
///
/// A host that places its own caches, and a test that must not depend on the
/// developer's environment or mutate the process's, passes the root instead of
/// setting `BIFROST_CACHE_ROOT`.
pub fn multiroot_persistence_dir_with_overrides(
    roots: &[PathBuf],
    cache_root: Option<std::ffi::OsString>,
) -> Option<PathBuf> {
    multiroot_persistence_dir_under(machine_cache_root_with_overrides(cache_root), roots)
}

fn multiroot_persistence_dir_under(
    cache_root: Option<PathBuf>,
    roots: &[PathBuf],
) -> Option<PathBuf> {
    debug_assert!(
        !roots.is_empty(),
        "a multi-root workspace has at least one root"
    );
    Some(
        cache_root?
            .join(MULTIROOT_SUBDIR_NAME)
            .join(multiroot_key(roots)),
    )
}

fn multiroot_key(roots: &[PathBuf]) -> String {
    let mut roots = roots
        .iter()
        .map(|root| root.canonicalize().unwrap_or_else(|_| root.clone()))
        .collect::<Vec<_>>();
    roots.sort();
    roots.dedup();
    let mut bytes = Vec::new();
    for root in &roots {
        // Length-prefix each path so that no two different root sets can
        // flatten to the same byte stream.
        let path_bytes = platform_path_bytes(root);
        bytes.extend_from_slice(&(path_bytes.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&path_bytes);
    }
    let digest = hash_domain_bytes(b"bifrost-multiroot-roots-v1", &bytes);
    let readable = match roots.first() {
        Some(root) => readable_path_name(root),
        None => "workspace".to_string(),
    };
    format!("{readable}-{}", &lower_hex_string(&digest)[..16])
}

/// Stable machine-local identity of one bound workspace root.
///
/// A cache database is shared by linked worktrees, so workspace-derived rows
/// need the bound root in their identity even though blob-derived rows do not.
/// Hash the canonical platform path bytes rather than storing an absolute path
/// or requiring it to be Unicode.
pub fn workspace_cache_identity(workspace_root: &Path) -> String {
    let canonical = workspace_root
        .canonicalize()
        .unwrap_or_else(|_| workspace_root.to_path_buf());
    lower_hex_string(&hash_domain_bytes(
        b"bifrost-cache-workspace-root-v1",
        &platform_path_bytes(&canonical),
    ))
}

#[cfg(unix)]
fn platform_path_bytes(path: &Path) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt as _;

    path.as_os_str().as_bytes().to_vec()
}

#[cfg(windows)]
fn platform_path_bytes(path: &Path) -> Vec<u8> {
    use std::os::windows::ffi::OsStrExt as _;

    path.as_os_str()
        .encode_wide()
        .flat_map(u16::to_le_bytes)
        .collect()
}

#[cfg(not(any(unix, windows)))]
fn platform_path_bytes(path: &Path) -> Vec<u8> {
    path.to_string_lossy().as_bytes().to_vec()
}

/// Working-tree blob OID (hex) for each of `rel_paths`.
pub fn working_tree_oids(
    repo: &Repository,
    rel_paths: &[String],
) -> Result<HashMap<String, String>> {
    Ok(working_tree_oid_values(repo, rel_paths)?
        .into_iter()
        .map(|(path, oid)| (path, oid.to_string()))
        .collect())
}

/// Resolve many working-tree paths with one Git index and dirty-tree scan.
///
/// Clean tracked files use the index OID without reading their bytes when Git
/// records byte-identical worktree content. Dirty, transformed, and untracked
/// files use the bytes visible to the analyzer. Missing files are absent from
/// the result. This startup path replaces repeated point resolution, which
/// read every clean source file in large Java workspaces.
pub fn working_tree_oid_values(
    repo: &Repository,
    rel_paths: &[String],
) -> Result<HashMap<String, Oid>> {
    let started = std::time::Instant::now();
    let workdir = workdir(repo)?;
    let mut index = repo.index().map_err(|e| e.to_string())?;
    // A long-lived Bifrost process can observe an external Git command.
    index.read(true).map_err(|e| e.to_string())?;
    let dirty = dirty_worktree_paths(repo, None)?;
    let index_oids: HashMap<String, Oid> = index
        .iter()
        .map(|entry| Ok((index_path_to_string(&entry)?, entry.id)))
        .collect::<Result<_>>()?;
    let blob_sizes = canonical_blob_sizes(
        repo,
        rel_paths
            .iter()
            .filter(|rel| !dirty.contains(*rel))
            .filter_map(|rel| index_oids.get(rel).copied()),
    );
    resolve_working_tree_oid_values(
        repo,
        workdir,
        rel_paths,
        &dirty,
        &index_oids,
        &blob_sizes,
        started,
    )
}

/// One-scan working-tree identity snapshot: index OIDs with their cached
/// stat data for tracked paths, and the set of dirty (modified, staged, or
/// untracked) paths.
///
/// Callers resolve individual paths against it and hash only the files whose
/// working bytes Git did not record. Building the snapshot reads no file
/// contents, so an unreadable file outside the caller's file set (for example
/// another process's live database under `.bifrost/cache`) cannot fail the
/// scan. Serving an index OID re-checks the file's current stat against the
/// index entry, the same way Git detects worktree edits, so a snapshot taken
/// at startup stays valid for later full-refresh sweeps.
pub struct WorkingTreeIdentity {
    tracked: HashMap<String, TrackedIdentity>,
    dirty: HashSet<String>,
    verified_clean_paths: Mutex<HashSet<String>>,
    /// Paths a long-lived caller explicitly reported as changed after this
    /// identity was captured. Their current bytes must be hashed even when an
    /// editor or checkout preserved the size and mtime recorded in the index.
    invalidated_paths: Mutex<HashSet<String>>,
}

/// A working-tree OID paired with the filesystem observation used to resolve
/// it. Callers can retain the metadata without taking a second stat pass and
/// decide whether the observation is still current at their boundary.
pub struct WorkingTreeResolution {
    pub oid: Oid,
    pub metadata: Metadata,
}

struct TrackedIdentity {
    oid: Oid,
    file_size: u32,
    mtime_seconds: i32,
    mtime_nanoseconds: u32,
}

impl WorkingTreeIdentity {
    /// Stop serving this snapshot's index identity for explicitly changed paths.
    ///
    /// Invalidations last for the lifetime of this repository-wide snapshot.
    /// A later resolution hashes the visible bytes for these paths; replacing
    /// the snapshot after a full refresh makes the current Git index eligible
    /// again. Unnamed paths retain the clean-index fast path.
    pub fn invalidate_paths(&self, rel_paths: impl IntoIterator<Item = String>) {
        self.invalidated_paths
            .lock()
            .expect("working-tree identity invalidation mutex poisoned")
            .extend(rel_paths);
    }

    /// Index OID for `rel` when the file at `abs_path` still carries the
    /// bytes Git recorded: the path was clean at scan time and its current
    /// size and mtime match the index entry's cached stat. Dirty, untracked,
    /// ignored, and since-edited paths return `None`; their identity is the
    /// hash of the visible working bytes.
    pub fn clean_index_oid(&self, repo: &Repository, rel: &str, abs_path: &Path) -> Option<Oid> {
        let (tracked, file_size) = self.stat_clean_entry(rel, abs_path)?;

        if self
            .verified_clean_paths
            .lock()
            .expect("working-tree identity verification mutex poisoned")
            .contains(rel)
        {
            return Some(tracked.oid);
        }

        // Git can keep a transformed worktree clean while the index OID still
        // names the canonical blob. Hash those bytes instead of serving the
        // canonical OID. A line-ending conversion changes the worktree size,
        // while other filters need the attribute guard below.
        if canonical_blob_size(repo, tracked.oid) != Some(file_size.len())
            || has_content_transform(repo, Path::new(rel))
        {
            return None;
        }
        self.verified_clean_paths
            .lock()
            .expect("working-tree identity verification mutex poisoned")
            .insert(rel.to_string());
        Some(tracked.oid)
    }

    /// The index OID this scan recorded for `rel` when the path was clean at
    /// scan time and the file at `abs_path` still carries the size and mtime
    /// the index entry cached.
    ///
    /// This is [`Self::clean_index_oid`] without its per-path content-transform
    /// verdict, so the caller owes that verdict itself. Take this form only when
    /// answering transforms for a whole path set at once is the point: the
    /// semantic identity walk batches them through one `git check-attr` process
    /// because libgit2 answered Firefox's paths one at a time in 55.3 s of CPU
    /// (issue #1904). Every other caller wants `clean_index_oid`.
    pub fn stat_clean_index_oid(&self, rel: &str, abs_path: &Path) -> Option<Oid> {
        self.stat_clean_entry(rel, abs_path)
            .map(|(tracked, _)| tracked.oid)
    }

    /// Resolve a batch of paths while retaining the metadata observed for
    /// each returned OID. Clean tracked paths use one batched object-database
    /// size lookup instead of opening the ODB once per path. A path is omitted
    /// when its bytes were not stable for the duration of its resolution;
    /// callers can then fall back to point resolution.
    pub fn resolve_with_metadata(
        &self,
        repo: &Repository,
        rel_paths: &[String],
    ) -> Result<HashMap<String, WorkingTreeResolution>> {
        let workdir = workdir(repo)?;
        let clean_candidates: HashMap<String, (Oid, Metadata)> = rel_paths
            .iter()
            .filter_map(|rel| {
                let abs_path = workdir.join(rel);
                let (tracked, metadata) = self.stat_clean_entry(rel, &abs_path)?;
                Some((rel.clone(), (tracked.oid, metadata)))
            })
            .collect();
        let blob_sizes = canonical_blob_sizes(repo, clean_candidates.values().map(|(oid, _)| *oid));
        let mut resolved = HashMap::with_capacity(rel_paths.len());
        for rel in rel_paths {
            let abs_path = workdir.join(rel);
            let Some(metadata_before) = clean_candidates
                .get(rel)
                .map(|(_, metadata)| metadata.clone())
                .or_else(|| std::fs::metadata(&abs_path).ok())
            else {
                continue;
            };
            if !metadata_before.is_file() {
                continue;
            }

            let clean_oid = clean_candidates.get(rel).and_then(|(oid, _)| {
                let verified = self
                    .verified_clean_paths
                    .lock()
                    .expect("working-tree identity verification mutex poisoned")
                    .contains(rel);
                let same_size =
                    blob_sizes.get(oid).copied().flatten() == Some(metadata_before.len());
                let untransformed = !has_content_transform(repo, Path::new(rel));
                (verified || (same_size && untransformed)).then_some(*oid)
            });
            let oid = if let Some(oid) = clean_oid {
                self.verified_clean_paths
                    .lock()
                    .expect("working-tree identity verification mutex poisoned")
                    .insert(rel.clone());
                oid
            } else {
                hash_working_file(workdir, rel)?
            };
            let Some(metadata_after) = std::fs::metadata(&abs_path).ok() else {
                continue;
            };
            if !metadata_same(&metadata_before, &metadata_after) {
                continue;
            }
            resolved.insert(
                rel.clone(),
                WorkingTreeResolution {
                    oid,
                    metadata: metadata_after,
                },
            );
        }
        Ok(resolved)
    }

    /// The tracked entry for `rel` and the current file size, when the scan saw
    /// the path clean and the file still carries the recorded stat. One
    /// `metadata` call serves both callers above.
    fn stat_clean_entry(&self, rel: &str, abs_path: &Path) -> Option<(&TrackedIdentity, Metadata)> {
        if self
            .invalidated_paths
            .lock()
            .expect("working-tree identity invalidation mutex poisoned")
            .contains(rel)
        {
            return None;
        }
        if self.dirty.contains(rel) {
            return None;
        }
        let tracked = self.tracked.get(rel)?;
        let metadata = std::fs::metadata(abs_path).ok()?;
        if !metadata.is_file() || metadata.len() != u64::from(tracked.file_size) {
            return None;
        }
        let modified = metadata
            .modified()
            .ok()?
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?;
        if modified.as_secs() != u64::try_from(tracked.mtime_seconds).ok()? {
            return None;
        }
        // Index entries on some filesystems and Git versions truncate the
        // nanosecond field to zero; only a recorded value can disagree.
        if tracked.mtime_nanoseconds != 0 && modified.subsec_nanos() != tracked.mtime_nanoseconds {
            return None;
        }
        Some((tracked, metadata))
    }
}

fn metadata_same(left: &Metadata, right: &Metadata) -> bool {
    if left.len() != right.len() || left.modified().ok() != right.modified().ok() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        left.dev() == right.dev()
            && left.ino() == right.ino()
            && left.mode() == right.mode()
            && left.uid() == right.uid()
            && left.gid() == right.gid()
    }
    #[cfg(not(unix))]
    {
        true
    }
}

/// Take one repository-wide identity scan. Language analyzers share this
/// result instead of repeating Git index and dirty-tree work at startup.
pub fn working_tree_identity(repo: &Repository) -> Result<WorkingTreeIdentity> {
    let started = std::time::Instant::now();
    let mut index = repo.index().map_err(|e| e.to_string())?;
    index.read(true).map_err(|e| e.to_string())?;
    let dirty = dirty_worktree_paths(repo, None)?;
    // Keep the startup scan to index and dirty-tree data. Canonical blob sizes
    // and attributes are checked only when an analyzer requests that path.
    // This avoids object-database work for unrelated languages and files.
    let entries: Vec<IndexEntry> = index.iter().collect();
    let mut tracked = HashMap::with_capacity(entries.len());
    for entry in entries {
        let rel = index_path_to_string(&entry)?;
        tracked.insert(
            rel,
            TrackedIdentity {
                oid: entry.id,
                file_size: entry.file_size,
                mtime_seconds: entry.mtime.seconds(),
                mtime_nanoseconds: entry.mtime.nanoseconds(),
            },
        );
    }
    if crate::profiling::enabled() {
        crate::profiling::note(format!(
            "git_identity_scan index={} dirty={} blob_headers=0 elapsed_ms={:.1}",
            tracked.len(),
            dirty.len(),
            started.elapsed().as_secs_f64() * 1000.0,
        ));
    }
    Ok(WorkingTreeIdentity {
        tracked,
        dirty,
        verified_clean_paths: Mutex::new(HashSet::new()),
        invalidated_paths: Mutex::new(HashSet::new()),
    })
}

/// Return whether Git may change the bytes visible in the worktree for `path`.
///
/// Text/eol conversion is handled by comparing the index stat size with the
/// canonical blob size in [`WorkingTreeIdentity::clean_index_oid`]. These
/// attributes cover custom filters and other byte transforms whose output can
/// have the same size as the canonical blob.
fn has_content_transform(repo: &Repository, path: &Path) -> bool {
    for name in ["filter", "ident", "working-tree-encoding"] {
        let value = match repo.get_attr_bytes(path, name, AttrCheckFlags::FILE_THEN_INDEX) {
            Ok(value) => value,
            // An attribute lookup failure prevents proof of byte identity.
            // Hash the visible bytes instead of trusting the index OID.
            Err(_) => return true,
        };
        if !matches!(
            AttrValue::from_bytes(value),
            AttrValue::False | AttrValue::Unspecified
        ) {
            return true;
        }
    }
    false
}

/// Read canonical blob sizes once per unique index OID.
///
/// A missing object or an unavailable object database returns `None`. Callers
/// treat that result as transformed and hash visible worktree bytes.
fn canonical_blob_sizes(
    repo: &Repository,
    oids: impl Iterator<Item = Oid>,
) -> HashMap<Oid, Option<u64>> {
    let mut object_db = None;
    let mut sizes = HashMap::new();
    for oid in oids {
        if sizes.contains_key(&oid) {
            continue;
        }
        if object_db.is_none() {
            object_db = repo.odb().ok();
        }
        let size = object_db.as_ref().and_then(|odb| {
            odb.read_header(oid)
                .ok()
                .and_then(|(size, kind)| (kind == ObjectType::Blob).then_some(size as u64))
        });
        sizes.insert(oid, size);
    }
    sizes
}

fn canonical_blob_size(repo: &Repository, oid: Oid) -> Option<u64> {
    canonical_blob_sizes(repo, std::iter::once(oid))
        .get(&oid)
        .copied()
        .flatten()
}

/// Resolve every existing tracked and untracked path in one repository snapshot.
///
/// The Git index supplies clean tracked paths without reading their bytes. The
/// worktree diff supplies only changed, deleted, and untracked paths that need
/// filesystem checks. Callers that need the blob identity should use
/// [`all_working_tree_oid_values`]; this path-only form avoids hashing dirty
/// files when a caller only needs the active file set.
pub fn all_working_tree_paths(repo: &Repository) -> Result<HashSet<String>> {
    working_tree_paths(repo, None)
}

/// The Git pathspec that selects `canonical_root` inside `canonical_workdir`,
/// or `None` when both name the same directory.
///
/// Git spells pathspecs and index paths with `/` on every platform, so the
/// workdir-relative path is converted from the host separator. The trailing
/// `/` keeps the value usable as a prefix test against those index paths.
/// A root outside the working directory yields `None`, which asks for the
/// whole repository.
pub fn subtree_pathspec(canonical_workdir: &Path, canonical_root: &Path) -> Option<String> {
    let rel = canonical_root.strip_prefix(canonical_workdir).ok()?;
    if rel.as_os_str().is_empty() {
        return None;
    }
    let mut pathspec = crate::path_utils::normalize_pattern(&rel.to_string_lossy());
    pathspec.push('/');
    Some(pathspec)
}

/// [`all_working_tree_paths`] narrowed to the subtree that `subtree` selects.
///
/// An ancestor repository can own a workspace root. Scanning the whole
/// repository then costs the ancestor's size on every call, which a
/// filesystem-event-driven caller pays per event. `subtree` is a
/// [`subtree_pathspec`] value and prunes both the index iteration and Git's
/// worktree scan to the workspace.
pub fn working_tree_paths_under(repo: &Repository, subtree: &str) -> Result<HashSet<String>> {
    working_tree_paths(repo, Some(subtree))
}

fn working_tree_paths(repo: &Repository, subtree: Option<&str>) -> Result<HashSet<String>> {
    let workdir = workdir(repo)?;
    let mut index = repo.index().map_err(|e| e.to_string())?;
    index.read(true).map_err(|e| e.to_string())?;
    let dirty = dirty_worktree_paths(repo, subtree)?;
    let mut paths = HashSet::with_capacity(index.len() + dirty.len());

    for entry in index.iter() {
        let rel = index_path_to_string(&entry)?;
        if subtree.is_some_and(|prefix| !rel.starts_with(prefix)) {
            continue;
        }
        if !dirty.contains(&rel) || workdir.join(&rel).is_file() {
            paths.insert(rel);
        }
    }
    for rel in dirty {
        if index.get_path(Path::new(&rel), 0).is_none() && workdir.join(&rel).is_file() {
            paths.insert(rel);
        }
    }
    Ok(paths)
}

fn resolve_working_tree_oid_values(
    repo: &Repository,
    workdir: &Path,
    rel_paths: &[String],
    dirty: &HashSet<String>,
    index_oids: &HashMap<String, Oid>,
    blob_sizes: &HashMap<Oid, Option<u64>>,
    started: std::time::Instant,
) -> Result<HashMap<String, Oid>> {
    let mut out = HashMap::with_capacity(rel_paths.len());
    let mut hashed = 0usize;
    for rel in rel_paths {
        let path = Path::new(rel);
        let index_oid = index_oids.get(rel).copied();
        let use_worktree = if dirty.contains(rel) || index_oid.is_none() {
            true
        } else {
            let size_differs = match index_oid.and_then(|oid| blob_sizes.get(&oid).copied()) {
                Some(Some(blob_size)) => std::fs::metadata(workdir.join(path))
                    .map(|metadata| metadata.len() != blob_size)
                    .unwrap_or(true),
                // A missing index object cannot prove byte identity. Hash the
                // visible bytes instead of serving a potentially stale OID.
                Some(None) | None => true,
            };
            if size_differs {
                true
            } else {
                has_content_transform(repo, path)
            }
        };
        let oid = if use_worktree {
            match hash_working_file(workdir, rel) {
                Ok(oid) => oid,
                Err(_) if !workdir.join(path).is_file() => continue,
                Err(error) => return Err(error),
            }
        } else {
            index_oid.expect("clean tracked path has an index OID")
        };
        hashed += usize::from(use_worktree);
        out.insert(rel.clone(), oid);
    }
    if crate::profiling::enabled() {
        crate::profiling::note(format!(
            "git_identity files={} index={} hashed={} elapsed_ms={:.1}",
            rel_paths.len(),
            out.len().saturating_sub(hashed),
            hashed,
            started.elapsed().as_secs_f64() * 1000.0,
        ));
    }
    Ok(out)
}

/// Like [`working_tree_oids`] but kept as the explicit incremental-update API.
pub fn working_tree_oids_targeted(
    repo: &Repository,
    rel_paths: &[String],
) -> Result<HashMap<String, String>> {
    working_tree_oids(repo, rel_paths)
}

/// Resolve every path in the index to the blob OID for its current working-tree
/// bytes.
pub fn working_tree_oids_full(repo: &Repository) -> Result<HashMap<String, String>> {
    let index = repo.index().map_err(|e| e.to_string())?;
    let rel_paths = index
        .iter()
        .map(|entry| index_path_to_string(&entry))
        .collect::<Result<Vec<_>>>()?;
    working_tree_oids(repo, &rel_paths)
}

/// Resolve one path to the OID of its current working-tree bytes. Returns
/// `Ok(None)` for a missing file.
pub fn working_tree_oid_for_path(repo: &Repository, rel_path: &Path) -> Result<Option<Oid>> {
    let workdir = workdir(repo)?;
    let index = repo.index().map_err(|e| e.to_string())?;
    let Some(rel) = rel_path.to_str() else {
        return Err(format!("non-UTF-8 git path: {}", rel_path.display()));
    };
    if !workdir.join(rel_path).is_file() {
        return Ok(None);
    }
    Ok(Some(resolve_path_oid(workdir, &index, rel)?))
}

/// Whether a path's working-tree content differs from the index entry.
pub fn is_path_dirty(repo: &Repository, rel_path: &Path) -> Result<bool> {
    let workdir = workdir(repo)?;
    let index = repo.index().map_err(|e| e.to_string())?;
    let Some(entry) = index.get_path(rel_path, 0) else {
        return Ok(workdir.join(rel_path).is_file());
    };
    Ok(!entry_stat_matches(&workdir.join(rel_path), &entry))
}

/// Read a blob's bytes by OID.
pub fn read_blob(repo: &Repository, oid_hex: &str) -> Result<Vec<u8>> {
    let oid = Oid::from_str(oid_hex).map_err(|e| e.to_string())?;
    let blob = repo.find_blob(oid).map_err(|e| e.to_string())?;
    Ok(blob.content().to_vec())
}

/// Target false-positive rate for the GC reachability filter. There are no
/// false negatives, so GC never drops a reachable blob.
const GC_BLOOM_FP_RATE: f64 = 0.05;
const GC_BLOOM_EST_OIDS: usize = 1 << 19;

/// Whether Git may lazily fetch missing objects from a promisor remote over a
/// network transport.
///
/// Object enumeration is not a local operation in that repository shape:
/// commands such as `rev-list --objects --all` may transparently fetch every
/// absent historical object. Callers that cannot bound or cancel that work
/// must decline it before spawning Git. Local-path promisors remain eligible
/// because their object transfer is filesystem-bound like an ordinary local
/// clone.
pub fn has_network_promisor_remote(repo: &Repository) -> Result<bool> {
    let config = repo.config().map_err(|error| error.to_string())?;
    let mut remote_names: HashSet<String> = repo
        .remotes()
        .map_err(|error| error.to_string())?
        .iter()
        .flatten()
        .map(str::to_owned)
        .collect();
    // A partially configured or hand-edited clone can retain the extension
    // marker even if its remote no longer appears in `Repository::remotes`.
    // Keep that state conservative rather than accidentally permitting a walk.
    if let Ok(remote) = config.get_string("extensions.partialclone") {
        remote_names.insert(remote);
    }
    for remote in remote_names {
        let key = format!("remote.{remote}.promisor");
        let promisor = match config.get_bool(&key) {
            Ok(promisor) => promisor,
            Err(error) if error.code() == ErrorCode::NotFound => false,
            Err(error) => return Err(format!("reading `{key}`: {error}")),
        };
        if promisor && !remote_url_is_local(&config, &remote) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Whether a Git remote URL names a path handled by the local filesystem.
/// Plain relative paths, absolute paths, tilde paths and `file:` URLs are
/// local. Scheme URLs and scp-style `host:path` spellings are network-backed.
/// A missing URL stays conservative.
fn remote_url_is_local(config: &git2::Config, remote: &str) -> bool {
    let Ok(url) = config.get_string(&format!("remote.{remote}.url")) else {
        return false;
    };
    if url
        .get(..5)
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("file:"))
        || Path::new(&url).is_absolute()
        || url.starts_with('~')
    {
        return true;
    }
    !url.contains("://") && !url.contains(':')
}

/// A Bloom filter of every OID reachable from any ref or linked worktree HEAD,
/// built by streaming `git rev-list --objects --all <worktree-heads...>`.
pub fn reachable_bloom(repo: &Repository) -> Result<GrowableBloom> {
    if has_network_promisor_remote(repo)? {
        return Err(
            "refusing to enumerate reachable objects from a network-backed promisor clone"
                .to_string(),
        );
    }
    let workdir = workdir(repo)?;
    let mut args = vec![
        "rev-list".to_string(),
        "--objects".to_string(),
        "--all".to_string(),
    ];
    args.extend(worktree_heads(repo)?);
    let mut child = background_git(workdir)
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("git rev-list failed to spawn: {e}"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "git rev-list produced no stdout".to_string())?;

    let mut bloom = GrowableBloom::new(GC_BLOOM_FP_RATE, GC_BLOOM_EST_OIDS);
    for line in BufReader::new(stdout).lines() {
        let line = line.map_err(|e| format!("reading git rev-list output: {e}"))?;
        let oid = line.split(' ').next().unwrap_or("");
        if oid.len() >= 40 {
            bloom.insert(oid);
        }
    }
    let status = child
        .wait()
        .map_err(|e| format!("git rev-list wait failed: {e}"))?;
    if !status.success() {
        return Err("git rev-list --objects --all failed".to_string());
    }
    Ok(bloom)
}

/// Commit OIDs checked out by every linked worktree, including detached HEADs
/// that are not otherwise reachable from refs.
pub fn worktree_heads(repo: &Repository) -> Result<Vec<String>> {
    let text = worktree_porcelain(repo)?;
    let mut heads = Vec::new();
    let mut seen = HashSet::new();
    for line in text.lines() {
        if let Some(head) = line.strip_prefix("HEAD ")
            && let Ok(oid) = Oid::from_str(head)
            && !oid.is_zero()
            && seen.insert(head.to_string())
        {
            heads.push(head.to_string());
        }
    }
    Ok(heads)
}

/// Roots of every linked worktree of this repo, including the main worktree.
pub fn worktree_roots(repo: &Repository) -> Result<Vec<PathBuf>> {
    let text = worktree_porcelain(repo)?;
    let mut roots = Vec::new();
    for line in text.lines() {
        if let Some(path) = line.strip_prefix("worktree ") {
            roots.push(PathBuf::from(path));
        }
    }
    Ok(roots)
}

fn worktree_porcelain(repo: &Repository) -> Result<String> {
    let workdir = workdir(repo)?;
    let output = background_git(workdir)
        .args(["worktree", "list", "--porcelain"])
        .output()
        .map_err(|e| format!("git worktree list failed to spawn: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "git worktree list failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Blob OIDs (hex) of dirty/untracked files in `root`'s working tree.
pub fn uncommitted_oids(root: &Path) -> Result<HashSet<String>> {
    let Some(repo) = discover(root) else {
        return Ok(HashSet::new());
    };
    let workdir = workdir(&repo)?.to_path_buf();
    let mut out = HashSet::new();
    for rel in dirty_paths(&repo)? {
        if let Ok(oid) = hash_working_file(&workdir, &rel) {
            out.insert(oid.to_string());
        }
    }
    Ok(out)
}

/// Blob OIDs (hex) for every existing tracked file and every untracked file in
/// `root`'s working tree.
///
/// GC must retain the bytes analyzers actually parsed, even when Git considers
/// those bytes clean after line-ending conversion. Missing tracked files and
/// files that cannot be hashed are skipped because they cannot back an active
/// working-tree analysis.
pub fn existing_working_tree_oids(root: &Path) -> Result<HashSet<String>> {
    let Some(repo) = discover(root) else {
        return Ok(HashSet::new());
    };
    let workdir = workdir(&repo)?.to_path_buf();
    let index = repo.index().map_err(|e| e.to_string())?;
    let mut tracked_paths = HashSet::with_capacity(index.len());
    let mut out = HashSet::with_capacity(index.len());

    for entry in index.iter() {
        let Ok(rel) = index_path_to_string(&entry) else {
            continue;
        };
        tracked_paths.insert(rel.clone());
        if workdir.join(&rel).is_file()
            && let Ok(oid) = hash_working_file(&workdir, &rel)
        {
            out.insert(oid.to_string());
        }
    }

    for rel in dirty_paths(&repo)? {
        if !tracked_paths.contains(&rel)
            && workdir.join(&rel).is_file()
            && let Ok(oid) = hash_working_file(&workdir, &rel)
        {
            out.insert(oid.to_string());
        }
    }
    Ok(out)
}

fn workdir(repo: &Repository) -> Result<&Path> {
    repo.workdir()
        .ok_or_else(|| "repository has no working directory".to_string())
}

/// A git subprocess in `workdir` that takes no optional locks.
///
/// Bifrost is a background analyzer of someone else's repository. A plain
/// `git status` opportunistically takes `.git/index.lock` to write a
/// refreshed index stat cache, and that lock races the user's own git
/// commands: their `git commit` (or a test harness's libgit2 index write)
/// fails with "the index is locked" for work Bifrost was doing behind their
/// back. `GIT_OPTIONAL_LOCKS=0` is git's documented contract for exactly
/// this kind of tooling -- the command completes without performing any
/// optional sub-operation that requires a lock. Every git spawn goes through
/// here so no future call site can reintroduce the race.
fn background_git(workdir: &Path) -> Command {
    let mut command = Command::new("git");
    command.current_dir(workdir).env("GIT_OPTIONAL_LOCKS", "0");
    command
}

fn resolve_path_oid(workdir: &Path, index: &git2::Index, rel: &str) -> Result<Oid> {
    let path = Path::new(rel);
    match index.get_path(path, 0) {
        Some(entry) => resolve_index_entry_oid(workdir, &entry),
        None => hash_working_file(workdir, rel),
    }
}

pub fn resolve_index_entry_oid(workdir: &Path, entry: &IndexEntry) -> Result<Oid> {
    let rel = index_path_to_string(entry)?;
    hash_working_file(workdir, &rel)
}

pub fn index_path_to_string(entry: &IndexEntry) -> Result<String> {
    String::from_utf8(entry.path.clone()).map_err(|err| format!("non-UTF-8 git index path: {err}"))
}

pub(crate) fn entry_stat_matches(path: &Path, entry: &IndexEntry) -> bool {
    let Ok(metadata) = std::fs::metadata(path) else {
        return false;
    };
    metadata.is_file() && metadata_matches_index(&metadata, entry)
}

#[cfg(unix)]
fn metadata_matches_index(metadata: &Metadata, entry: &IndexEntry) -> bool {
    use std::os::unix::fs::MetadataExt;

    metadata.dev() as u32 == entry.dev
        && metadata.ino() as u32 == entry.ino
        && metadata.mode() == entry.mode
        && metadata.uid() == entry.uid
        && metadata.gid() == entry.gid
        && metadata.size() as u32 == entry.file_size
        && metadata.mtime() as i32 == entry.mtime.seconds()
        && metadata.mtime_nsec() as u32 == entry.mtime.nanoseconds()
}

#[cfg(not(unix))]
fn metadata_matches_index(metadata: &Metadata, entry: &IndexEntry) -> bool {
    use std::time::UNIX_EPOCH;

    let Ok(modified) = metadata.modified() else {
        return false;
    };
    let Ok(duration) = modified.duration_since(UNIX_EPOCH) else {
        return false;
    };
    metadata.len() as u32 == entry.file_size
        && duration.as_secs() as i32 == entry.mtime.seconds()
        && duration.subsec_nanos() == entry.mtime.nanoseconds()
}

fn dirty_paths(repo: &Repository) -> Result<HashSet<String>> {
    let mut opts = StatusOptions::new();
    opts.include_untracked(true)
        .recurse_untracked_dirs(true)
        .include_unmodified(false)
        .exclude_submodules(true);
    let statuses = repo.statuses(Some(&mut opts)).map_err(|e| e.to_string())?;
    let mut dirty = HashSet::new();
    let changed = dirty_flags();
    for entry in statuses.iter() {
        if entry.status().intersects(changed)
            && let Some(path) = entry.path()
        {
            dirty.insert(path.to_string());
        }
    }
    Ok(dirty)
}

fn dirty_worktree_paths(repo: &Repository, subtree: Option<&str>) -> Result<HashSet<String>> {
    let _scope = crate::profiling::scope("gitblob::dirty_worktree_paths");
    let workdir = workdir(repo)?;
    // libgit2's recursive index-to-worktree diff can rescan very large trees
    // one entry at a time. Native Git uses its optimized index and filesystem
    // checks for the same dirty overlay. This matters for repositories such as
    // Firefox, where the libgit2 scan exceeded the MCP request budget.
    let mut command = background_git(workdir);
    command.args(["status", "--porcelain=v1", "-z", "--untracked-files=all"]);
    if let Some(subtree) = subtree {
        // Porcelain paths stay relative to the working directory root, so the
        // pathspec changes only which part of the tree Git walks. `:(literal)`
        // keeps a directory name containing `*`, `?`, `[`, or a leading `:`
        // from being read as pathspec magic.
        command.arg("--").arg(format!(":(literal){subtree}"));
    }
    let output = command
        .output()
        .map_err(|error| format!("git status failed to spawn: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "git status failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let mut dirty = HashSet::new();
    let mut fields = output.stdout.split(|byte| *byte == 0);
    while let Some(field) = fields.next() {
        if field.is_empty() {
            continue;
        }
        // Porcelain v1 records two status bytes, one space, then the path.
        // With -z, rename and copy records contain the second path as the next
        // NUL-delimited field. Keep both paths so deletions and additions are
        // removed or overlaid correctly by callers.
        if field.len() < 4 {
            continue;
        }
        let status = &field[..2];
        let path = &field[3..];
        if status != b"  " && status != b"!!" {
            dirty.insert(String::from_utf8_lossy(path).into_owned());
            if (status.contains(&b'R') || status.contains(&b'C'))
                && let Some(previous) = fields.next().filter(|previous| !previous.is_empty())
            {
                dirty.insert(String::from_utf8_lossy(previous).into_owned());
            }
        }
    }
    Ok(dirty)
}

fn dirty_flags() -> Status {
    Status::WT_MODIFIED
        | Status::WT_NEW
        | Status::WT_TYPECHANGE
        | Status::WT_RENAMED
        | Status::INDEX_MODIFIED
        | Status::INDEX_NEW
        | Status::INDEX_TYPECHANGE
        | Status::INDEX_RENAMED
}

fn hash_working_file(workdir: &Path, rel: &str) -> Result<Oid> {
    #[cfg(test)]
    HASH_WORKING_FILE_CALLS.with(|calls| calls.set(calls.get() + 1));
    Oid::hash_file(ObjectType::Blob, workdir.join(rel)).map_err(|e| e.to_string())
}

#[cfg(test)]
thread_local! {
    static HASH_WORKING_FILE_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Throwaway repositories for tests, not published API. The analyzer store,
/// workspace and tree-sitter unit tests in `brokk-bifrost-analysis` build these
/// fixtures too, and a `cfg(test)` module is invisible across a crate boundary,
/// so dependents reach it by enabling this crate's `test-support` feature. Same
/// gate as the `*_for_test` entry points in [`crate::cache_gc`].
#[cfg(any(test, feature = "test-support"))]
pub mod test_repo {
    use git2::{IndexAddOption, IndexTime, Oid, Repository, Signature};
    use std::path::Path;
    use std::time::UNIX_EPOCH;

    pub fn init_repo(dir: &Path) -> Repository {
        let repo = Repository::init(dir).unwrap();
        {
            let mut config = repo.config().unwrap();
            config.set_str("user.email", "t@example.com").unwrap();
            config.set_str("user.name", "T").unwrap();
        }
        repo
    }

    fn commit_index(repo: &Repository, message: &str) -> Oid {
        let mut index = repo.index().unwrap();
        let tree_id = index.write_tree().unwrap();
        let tree = repo.find_tree(tree_id).unwrap();
        let sig = Signature::now("T", "t@example.com").unwrap();
        let parent = repo.head().ok().and_then(|head| head.peel_to_commit().ok());
        match parent {
            Some(parent) => repo
                .commit(Some("HEAD"), &sig, &sig, message, &tree, &[&parent])
                .unwrap(),
            None => repo
                .commit(Some("HEAD"), &sig, &sig, message, &tree, &[])
                .unwrap(),
        }
    }

    pub fn commit_all(repo: &Repository, message: &str) -> Oid {
        let mut index = repo.index().unwrap();
        index
            .add_all(["*"].iter(), IndexAddOption::DEFAULT, None)
            .unwrap();
        index.write().unwrap();
        drop(index);
        commit_index(repo, message)
    }

    pub fn commit_paths(repo: &Repository, paths: &[&str], message: &str) -> Oid {
        let mut index = repo.index().unwrap();
        for path in paths {
            index.add_path(Path::new(path)).unwrap();
        }
        index.write().unwrap();
        drop(index);
        commit_index(repo, message)
    }

    /// Refresh the index stat for a worktree file while preserving its OID.
    pub fn refresh_index_stat_preserving_oid(repo: &Repository, path: &str) -> Oid {
        let workdir = repo.workdir().expect("test repository workdir");
        let metadata = std::fs::metadata(workdir.join(path)).unwrap();
        let modified = metadata
            .modified()
            .unwrap()
            .duration_since(UNIX_EPOCH)
            .unwrap();
        let mut index = repo.index().unwrap();
        let mut entry = index
            .get_path(Path::new(path), 0)
            .expect("source index entry");
        let oid = entry.id;
        entry.file_size = u32::try_from(metadata.len()).unwrap();
        let index_time = IndexTime::new(
            i32::try_from(modified.as_secs()).unwrap(),
            modified.subsec_nanos(),
        );
        entry.mtime = index_time;
        entry.ctime = index_time;
        index.add(&entry).unwrap();
        index.write().unwrap();
        oid
    }
}

#[cfg(test)]
mod tests {
    use super::test_repo::{
        commit_all, commit_paths, init_repo, refresh_index_stat_preserving_oid,
    };
    use super::*;

    fn reset_hash_calls() {
        HASH_WORKING_FILE_CALLS.with(|calls| calls.set(0));
    }

    fn hash_calls() -> usize {
        HASH_WORKING_FILE_CALLS.with(std::cell::Cell::get)
    }

    fn set_promisor_url(repo: &Repository, url: &str) {
        if repo.find_remote("origin").is_ok() {
            repo.remote_set_url("origin", url).unwrap();
        } else {
            repo.remote("origin", url).unwrap();
        }
        repo.config()
            .unwrap()
            .set_bool("remote.origin.promisor", true)
            .unwrap();
    }

    #[test]
    fn cache_root_keeps_linked_worktrees_together_and_repositories_apart() {
        let temp = tempfile::TempDir::new().unwrap();
        let first_root = temp.path().join("first").join("shared-name");
        let second_root = temp.path().join("second").join("shared-name");
        std::fs::create_dir_all(&first_root).unwrap();
        std::fs::create_dir_all(&second_root).unwrap();
        let first = init_repo(&first_root);
        let _second = init_repo(&second_root);
        std::fs::write(first_root.join("a.txt"), "first\n").unwrap();
        commit_all(&first, "init");
        let linked_root = temp.path().join("linked");
        let _linked = first.worktree("linked", &linked_root, None).unwrap();
        let cache_root = temp.path().join("local-cache");

        let first_cache = cache_db_path_with_overrides(
            &first_root,
            None,
            Some(cache_root.as_os_str().to_owned()),
        );
        let linked_cache = cache_db_path_with_overrides(
            &linked_root,
            None,
            Some(cache_root.as_os_str().to_owned()),
        );
        let second_cache = cache_db_path_with_overrides(
            &second_root,
            None,
            Some(cache_root.as_os_str().to_owned()),
        );

        assert_eq!(first_cache, linked_cache);
        assert_ne!(first_cache, second_cache);
        assert_eq!(
            cache_dir_path_with_overrides(
                &first_root,
                None,
                Some(cache_root.as_os_str().to_owned()),
            ),
            first_cache.parent().unwrap()
        );
        assert_eq!(
            first_cache.parent().and_then(Path::parent),
            Some(cache_root.as_path())
        );
        assert!(
            first_cache
                .parent()
                .unwrap()
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("shared-name-")
        );
    }

    #[test]
    fn multiroot_persistence_dir_is_order_insensitive() {
        let temp = tempfile::TempDir::new().unwrap();
        let cache_root = temp.path().join("machine-cache");
        let first = temp.path().join("service-a");
        let second = temp.path().join("service-b");
        std::fs::create_dir_all(&first).unwrap();
        std::fs::create_dir_all(&second).unwrap();

        let forward = multiroot_persistence_dir_with_overrides(
            &[first.clone(), second.clone()],
            Some(cache_root.as_os_str().to_owned()),
        )
        .unwrap();
        let reversed = multiroot_persistence_dir_with_overrides(
            &[second.clone(), first.clone()],
            Some(cache_root.as_os_str().to_owned()),
        )
        .unwrap();
        let repeated = multiroot_persistence_dir_with_overrides(
            &[second, first.clone(), first],
            Some(cache_root.as_os_str().to_owned()),
        )
        .unwrap();

        assert_eq!(forward, reversed);
        assert_eq!(
            forward, repeated,
            "a repeated root names the same workspace"
        );
        assert_eq!(
            forward.parent(),
            Some(cache_root.join("multiroot").as_path())
        );
        assert!(
            forward
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("service-a-"),
            "the first root should name the directory: {}",
            forward.display()
        );
        assert!(
            !forward.exists(),
            "resolving a persistence directory must not create it"
        );
    }

    #[test]
    fn distinct_root_sets_get_distinct_dirs() {
        let temp = tempfile::TempDir::new().unwrap();
        let cache_root = temp.path().join("machine-cache");
        let first = temp.path().join("service-a");
        let second = temp.path().join("service-b");
        let third = temp.path().join("service-c");
        for root in [&first, &second, &third] {
            std::fs::create_dir_all(root).unwrap();
        }
        let dir_for = |roots: &[PathBuf]| {
            multiroot_persistence_dir_with_overrides(roots, Some(cache_root.as_os_str().to_owned()))
                .unwrap()
        };

        let pair = dir_for(&[first.clone(), second.clone()]);
        let other_pair = dir_for(&[first.clone(), third.clone()]);
        let triple = dir_for(&[first.clone(), second.clone(), third]);
        let single = dir_for(&[first]);

        assert_ne!(pair, other_pair);
        assert_ne!(pair, triple, "a superset is a different workspace");
        assert_ne!(pair, single);
        assert_ne!(second, other_pair);
    }

    #[test]
    fn cache_root_override_relocates_the_dir() {
        let temp = tempfile::TempDir::new().unwrap();
        let first = temp.path().join("service-a");
        let second = temp.path().join("service-b");
        std::fs::create_dir_all(&first).unwrap();
        std::fs::create_dir_all(&second).unwrap();
        let roots = [first, second];
        let one = temp.path().join("cache-one");
        let other = temp.path().join("cache-other");

        let under_one =
            multiroot_persistence_dir_with_overrides(&roots, Some(one.as_os_str().to_owned()))
                .unwrap();
        let under_other =
            multiroot_persistence_dir_with_overrides(&roots, Some(other.as_os_str().to_owned()))
                .unwrap();

        assert!(under_one.starts_with(&one));
        assert!(under_other.starts_with(&other));
        assert_eq!(
            under_one.strip_prefix(&one),
            under_other.strip_prefix(&other),
            "the same roots keep the same name under either cache root"
        );
        assert_eq!(
            machine_cache_root_with_overrides(Some(one.as_os_str().to_owned())),
            Some(one)
        );
    }

    #[test]
    fn exact_cache_directory_override_wins_over_cache_root() {
        let temp = tempfile::TempDir::new().unwrap();
        let workspace = temp.path().join("workspace");
        std::fs::create_dir(&workspace).unwrap();
        let exact = temp.path().join("exact");
        let root = temp.path().join("root");

        assert_eq!(
            cache_db_path_with_overrides(
                &workspace,
                Some(exact.as_os_str().to_owned()),
                Some(root.as_os_str().to_owned()),
            ),
            exact.join(crate::cache_db::cache_db_file_name())
        );
        assert_eq!(
            cache_dir_path_with_overrides(
                &workspace,
                Some(exact.as_os_str().to_owned()),
                Some(root.as_os_str().to_owned()),
            ),
            exact
        );
    }

    #[test]
    fn promisor_remote_detection_distinguishes_local_paths_from_network_transports() {
        let temp = tempfile::TempDir::new().unwrap();
        let repo = init_repo(temp.path());

        for url in [
            "https://example.invalid/repo.git",
            "ssh://example.invalid/repo.git",
            "git@example.invalid:repo.git",
        ] {
            set_promisor_url(&repo, url);
            assert!(
                has_network_promisor_remote(&repo).unwrap(),
                "{url} is network-backed"
            );
        }
        for url in [
            "file:///tmp/source.git",
            "../source.git",
            "source.git",
            "~/source.git",
        ] {
            set_promisor_url(&repo, url);
            assert!(
                !has_network_promisor_remote(&repo).unwrap(),
                "{url} is a local-path remote"
            );
        }

        let absolute = temp.path().join("source.git");
        set_promisor_url(&repo, absolute.to_str().expect("UTF-8 temporary path"));
        assert!(
            !has_network_promisor_remote(&repo).unwrap(),
            "an absolute local promisor path must remain eligible"
        );

        repo.config()
            .unwrap()
            .set_bool("remote.origin.promisor", false)
            .unwrap();
        repo.remote_set_url("origin", "https://example.invalid/repo.git")
            .unwrap();
        assert!(!has_network_promisor_remote(&repo).unwrap());
    }

    #[test]
    fn reachable_bloom_refuses_network_promisor_enumeration_before_spawning_git() {
        let temp = tempfile::TempDir::new().unwrap();
        let repo = init_repo(temp.path());
        set_promisor_url(&repo, "https://example.invalid/repo.git");

        let error = reachable_bloom(&repo).expect_err("network promisor walk must be refused");
        assert!(error.contains("refusing to enumerate"), "{error}");
    }

    #[test]
    fn clean_file_oid_matches_git_hash_object() {
        let temp = tempfile::TempDir::new().unwrap();
        let repo = init_repo(temp.path());
        std::fs::write(temp.path().join("a.txt"), "hello\n").unwrap();
        commit_all(&repo, "init");

        reset_hash_calls();
        let oids = working_tree_oids(&repo, &["a.txt".to_string()]).unwrap();
        assert_eq!(
            oids["a.txt"],
            Oid::hash_object(ObjectType::Blob, b"hello\n")
                .unwrap()
                .to_string()
        );
        assert_eq!(
            hash_calls(),
            0,
            "clean tracked content must use its index OID"
        );
    }

    #[test]
    fn all_working_tree_paths_use_index_and_dirty_overlay() {
        let temp = tempfile::TempDir::new().unwrap();
        let repo = init_repo(temp.path());
        std::fs::write(temp.path().join("tracked.rs"), "fn tracked() {}\n").unwrap();
        commit_all(&repo, "init");
        std::fs::write(temp.path().join("dirty.rs"), "fn dirty() {}\n").unwrap();

        let paths = all_working_tree_paths(&repo).unwrap();
        assert!(paths.contains("tracked.rs"), "{paths:?}");
        assert!(paths.contains("dirty.rs"), "{paths:?}");

        std::fs::remove_file(temp.path().join("tracked.rs")).unwrap();
        let paths = all_working_tree_paths(&repo).unwrap();
        assert!(!paths.contains("tracked.rs"), "{paths:?}");
        assert!(paths.contains("dirty.rs"), "{paths:?}");
    }

    #[test]
    fn subtree_pathspec_selects_the_workdir_relative_directory() {
        let workdir = Path::new("/repo");
        assert_eq!(subtree_pathspec(workdir, workdir), None);
        assert_eq!(
            subtree_pathspec(workdir, Path::new("/repo/packages/app")).as_deref(),
            Some("packages/app/")
        );
        assert_eq!(subtree_pathspec(workdir, Path::new("/elsewhere")), None);
    }

    #[cfg(windows)]
    #[test]
    fn subtree_pathspec_spells_windows_roots_with_forward_slashes() {
        assert_eq!(
            subtree_pathspec(Path::new(r"C:\repo"), Path::new(r"C:\repo\packages\app")).as_deref(),
            Some("packages/app/")
        );
    }

    #[test]
    fn working_tree_paths_under_returns_only_the_subtree() {
        let temp = tempfile::TempDir::new().unwrap();
        let repo = init_repo(temp.path());
        for rel in ["sub/tracked.rs", "outside/tracked.rs"] {
            let path = temp.path().join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, "fn tracked() {}\n").unwrap();
        }
        commit_all(&repo, "init");
        for rel in ["sub/untracked.rs", "outside/untracked.rs"] {
            std::fs::write(temp.path().join(rel), "fn untracked() {}\n").unwrap();
        }

        let paths = working_tree_paths_under(&repo, "sub/").unwrap();
        assert_eq!(
            paths,
            HashSet::from(["sub/tracked.rs".to_string(), "sub/untracked.rs".to_string()])
        );
        assert!(all_working_tree_paths(&repo).unwrap().is_superset(&paths));
    }

    #[test]
    fn clean_eol_transformed_file_oid_matches_visible_bytes() {
        let temp = tempfile::TempDir::new().unwrap();
        let repo = init_repo(temp.path());
        let source_path = temp.path().join("a.cs");
        std::fs::write(&source_path, "class A {}\n").unwrap();
        commit_all(&repo, "source");

        std::fs::write(temp.path().join(".gitattributes"), "*.cs text eol=crlf\n").unwrap();
        commit_paths(&repo, &[".gitattributes"], "attributes");
        std::fs::write(&source_path, "class A {}\r\n").unwrap();

        // Match the index stat Git records after a transformed checkout while
        // retaining the canonical LF blob OID.
        let index_oid = refresh_index_stat_preserving_oid(&repo, "a.cs");
        let visible_oid = Oid::hash_object(ObjectType::Blob, b"class A {}\r\n").unwrap();
        assert_ne!(visible_oid, index_oid, "LF and CRLF OIDs must differ");

        reset_hash_calls();
        let resolved = working_tree_oids(&repo, &["a.cs".to_string()]).unwrap();
        let visible_oid_hex = visible_oid.to_string();
        let index_oid_hex = index_oid.to_string();
        assert_eq!(resolved.get("a.cs"), Some(&visible_oid_hex));
        assert_ne!(resolved.get("a.cs"), Some(&index_oid_hex));
        assert_eq!(hash_calls(), 1);
    }

    #[test]
    fn equal_size_filter_attribute_hashes_working_tree_bytes() {
        let temp = tempfile::TempDir::new().unwrap();
        let repo = init_repo(temp.path());
        let source_path = temp.path().join("a.txt");
        std::fs::write(&source_path, "hello\n").unwrap();
        commit_all(&repo, "source");

        // The explicit filter has equal-size output in this fixture. The
        // attribute guard must still avoid trusting the index OID.
        std::fs::write(temp.path().join(".gitattributes"), "*.txt filter=opaque\n").unwrap();
        commit_paths(&repo, &[".gitattributes"], "attributes");

        let index_oid = repo
            .index()
            .unwrap()
            .get_path(Path::new("a.txt"), 0)
            .expect("source index entry")
            .id;
        let visible_oid = Oid::hash_object(ObjectType::Blob, b"hello\n").unwrap();
        assert_eq!(visible_oid, index_oid);

        reset_hash_calls();
        let resolved = working_tree_oids(&repo, &["a.txt".to_string()]).unwrap();
        assert_eq!(resolved.get("a.txt"), Some(&visible_oid.to_string()));
        assert_eq!(hash_calls(), 1);
    }

    #[test]
    fn dirty_file_oid_reflects_working_tree() {
        let temp = tempfile::TempDir::new().unwrap();
        let repo = init_repo(temp.path());
        std::fs::write(temp.path().join("a.txt"), "hello\n").unwrap();
        commit_all(&repo, "init");
        std::fs::write(temp.path().join("a.txt"), "changed\n").unwrap();

        reset_hash_calls();
        let oids = working_tree_oids(&repo, &["a.txt".to_string()]).unwrap();
        assert_eq!(
            oids["a.txt"],
            Oid::hash_object(ObjectType::Blob, b"changed\n")
                .unwrap()
                .to_string()
        );
        assert_eq!(hash_calls(), 1);

        let uncommitted = uncommitted_oids(temp.path()).unwrap();
        assert!(uncommitted.contains(&oids["a.txt"]));
    }

    #[test]
    fn targeted_matches_bulk_for_clean_dirty_and_untracked() {
        let temp = tempfile::TempDir::new().unwrap();
        let repo = init_repo(temp.path());
        std::fs::write(temp.path().join("clean.txt"), "clean\n").unwrap();
        std::fs::write(temp.path().join("dirty.txt"), "committed\n").unwrap();
        commit_all(&repo, "init");
        std::fs::write(temp.path().join("dirty.txt"), "working\n").unwrap();
        std::fs::write(temp.path().join("new.txt"), "fresh\n").unwrap();

        let paths = vec![
            "clean.txt".to_string(),
            "dirty.txt".to_string(),
            "new.txt".to_string(),
        ];
        let bulk = working_tree_oids(&repo, &paths).unwrap();
        let targeted = working_tree_oids_targeted(&repo, &paths).unwrap();
        assert_eq!(bulk, targeted);
        assert_eq!(
            targeted["clean.txt"],
            Oid::hash_object(ObjectType::Blob, b"clean\n")
                .unwrap()
                .to_string()
        );
        assert_eq!(
            targeted["dirty.txt"],
            Oid::hash_object(ObjectType::Blob, b"working\n")
                .unwrap()
                .to_string()
        );
    }

    #[test]
    fn batched_identity_pairs_current_metadata_with_clean_dirty_and_untracked_oids() {
        let temp = tempfile::TempDir::new().unwrap();
        let repo = init_repo(temp.path());
        std::fs::write(temp.path().join("clean.txt"), "clean\n").unwrap();
        std::fs::write(temp.path().join("dirty.txt"), "committed\n").unwrap();
        commit_all(&repo, "init");
        std::fs::write(temp.path().join("dirty.txt"), "working\n").unwrap();
        std::fs::write(temp.path().join("new.txt"), "fresh\n").unwrap();

        let identity = working_tree_identity(&repo).unwrap();
        reset_hash_calls();
        let resolved = identity
            .resolve_with_metadata(
                &repo,
                &[
                    "clean.txt".to_string(),
                    "dirty.txt".to_string(),
                    "new.txt".to_string(),
                ],
            )
            .unwrap();

        for (path, bytes) in [
            ("clean.txt", b"clean\n".as_slice()),
            ("dirty.txt", b"working\n".as_slice()),
            ("new.txt", b"fresh\n".as_slice()),
        ] {
            let resolution = &resolved[path];
            assert_eq!(
                resolution.oid,
                Oid::hash_object(ObjectType::Blob, bytes).unwrap()
            );
            assert_eq!(resolution.metadata.len(), bytes.len() as u64);
            assert!(metadata_same(
                &resolution.metadata,
                &std::fs::metadata(temp.path().join(path)).unwrap()
            ));
        }
        assert_eq!(
            hash_calls(),
            2,
            "only dirty and untracked files should read visible bytes"
        );
    }

    #[test]
    fn invalidating_one_path_retains_other_clean_index_identities() {
        let temp = tempfile::TempDir::new().unwrap();
        let repo = init_repo(temp.path());
        std::fs::write(temp.path().join("changed.txt"), "before!\n").unwrap();
        std::fs::write(temp.path().join("untouched.txt"), "stable\n").unwrap();
        commit_all(&repo, "init");

        let identity = working_tree_identity(&repo).unwrap();
        identity.invalidate_paths(["changed.txt".to_string()]);
        reset_hash_calls();
        let resolved = identity
            .resolve_with_metadata(
                &repo,
                &["changed.txt".to_string(), "untouched.txt".to_string()],
            )
            .unwrap();

        assert_eq!(
            resolved["changed.txt"].oid,
            Oid::hash_object(ObjectType::Blob, b"before!\n").unwrap()
        );
        assert_eq!(
            resolved["untouched.txt"].oid,
            Oid::hash_object(ObjectType::Blob, b"stable\n").unwrap()
        );
        assert_eq!(
            hash_calls(),
            1,
            "only the explicitly invalidated path should leave the index fast path"
        );
    }

    #[test]
    fn gc_oids_include_existing_tracked_and_untracked_bytes() {
        let temp = tempfile::TempDir::new().unwrap();
        let repo = init_repo(temp.path());
        std::fs::write(temp.path().join("clean.txt"), "clean\n").unwrap();
        std::fs::write(temp.path().join("changed.txt"), "committed\n").unwrap();
        std::fs::write(temp.path().join("deleted.txt"), "deleted\n").unwrap();
        commit_all(&repo, "init");

        std::fs::write(temp.path().join("changed.txt"), "working\r\n").unwrap();
        std::fs::remove_file(temp.path().join("deleted.txt")).unwrap();
        std::fs::write(temp.path().join("untracked.txt"), "untracked\n").unwrap();

        let oids = existing_working_tree_oids(temp.path()).unwrap();
        for bytes in [
            b"clean\n".as_slice(),
            b"working\r\n".as_slice(),
            b"untracked\n".as_slice(),
        ] {
            let oid = Oid::hash_object(ObjectType::Blob, bytes)
                .unwrap()
                .to_string();
            assert!(oids.contains(&oid), "missing working-tree OID {oid}");
        }
        let deleted_oid = Oid::hash_object(ObjectType::Blob, b"deleted\n")
            .unwrap()
            .to_string();
        assert!(!oids.contains(&deleted_oid));
    }
}
