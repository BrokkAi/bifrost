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
use std::time::Duration;

use git2::{AttrCheckFlags, AttrValue, ErrorCode, IndexEntry, ObjectType, Oid, Repository};
use growable_bloom_filter::GrowableBloom;

use crate::analyzer::canonical_hash::{hash_domain_bytes, lower_hex_string};
use crate::path_normalization::NormalizePath;

/// A parse product's content-derived identity. SQLite row IDs are not identities.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BlobKey {
    pub oid: Oid,
    pub lang: String,
    pub variant: ParseVariant,
}

impl BlobKey {
    /// Identify a parse that does not depend on a selected configuration.
    pub fn unvaried(oid: Oid, lang: impl Into<String>) -> Self {
        Self {
            oid,
            lang: lang.into(),
            variant: ParseVariant::Empty,
        }
    }
}

/// The configuration-dependent component of a blob's parse identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ParseVariant {
    Empty,
    Digest([u8; 32]),
}

impl ParseVariant {
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Empty => &[],
            Self::Digest(digest) => digest,
        }
    }
}

impl rusqlite::types::ToSql for ParseVariant {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        Ok(self.as_bytes().into())
    }
}

impl rusqlite::types::FromSql for ParseVariant {
    fn column_result(value: rusqlite::types::ValueRef<'_>) -> rusqlite::types::FromSqlResult<Self> {
        let bytes = value.as_blob()?;
        if bytes.is_empty() {
            Ok(Self::Empty)
        } else {
            bytes.try_into().map(Self::Digest).map_err(|_| {
                rusqlite::types::FromSqlError::Other("invalid parse variant length".into())
            })
        }
    }
}

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
        let display_name = target
            .strip_prefix("refs/remotes/origin/")
            .unwrap_or(target)
            .to_string();
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

/// The machine-local cache root for callers outside this module.
///
/// This is the public form of [`machine_cache_root`], including the
/// `BIFROST_CACHE_ROOT` override. It resolves a location and creates nothing.
pub fn machine_cache_dir() -> Option<PathBuf> {
    machine_cache_root()
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
    #[cfg(test)]
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
    #[cfg(test)]
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

#[cfg(test)]
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
/// filesystem checks. Initialized submodules contribute their own local index
/// and dirty paths, prefixed relative to this repository. No child is fetched
/// or initialized. Callers that need the blob identity should use
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

/// Open only an already materialized gitlink; never initialize or fetch it.
fn materialized_submodule(repo: &Repository, rel: &str) -> Result<Option<Repository>> {
    let relative = Path::new(rel);
    if !relative
        .components()
        .all(|part| matches!(part, std::path::Component::Normal(_)))
    {
        return Err(format!("invalid submodule path: {rel}"));
    }
    let parent = workdir(repo)?
        .canonicalize()
        .map_err(|error| error.to_string())?;
    let path = parent.join(relative);
    // An uninitialized gitlink has no child Git metadata. Opening the parent
    // through repository discovery would incorrectly treat it as a child.
    if !path
        .join(".git")
        .try_exists()
        .map_err(|error| error.to_string())?
    {
        return Ok(None);
    }
    let canonical = path.canonicalize().map_err(|error| error.to_string())?;
    if canonical != path || !canonical.starts_with(&parent) || canonical == parent {
        return Err(format!(
            "submodule path escapes its parent or uses a symlink: {rel}"
        ));
    }
    let submodule = repo
        .find_submodule(rel)
        .map_err(|error| error.to_string())?;
    let child = submodule.open().map_err(|error| error.to_string())?;
    let child_root = workdir(&child)?
        .canonicalize()
        .map_err(|error| error.to_string())?;
    if child_root != canonical {
        return Err(format!(
            "submodule working directory does not match gitlink: {rel}"
        ));
    }
    Ok(Some(child))
}

fn contained_child_file(workdir: &Path, rel: &Path) -> Result<bool> {
    let path = workdir.join(rel);
    if !path.is_file() {
        return Ok(false);
    }
    let canonical = path.canonicalize().map_err(|error| error.to_string())?;
    if !canonical.starts_with(workdir) {
        return Err(format!(
            "submodule source escapes its working directory: {}",
            rel.display()
        ));
    }
    Ok(true)
}

fn working_tree_paths(repo: &Repository, subtree: Option<&str>) -> Result<HashSet<String>> {
    let mut paths = HashSet::new();
    // Strict descendant workdirs make traversal acyclic. The stack and full
    // listing belong to this query only, not to a retained workspace index.
    let mut pending = vec![(
        repo.path().to_path_buf(),
        String::new(),
        subtree.map(str::to_owned),
    )];
    while let Some((gitdir, prefix, scope)) = pending.pop() {
        let current = Repository::open(gitdir).map_err(|error| error.to_string())?;
        let workdir = workdir(&current)?
            .canonicalize()
            .map_err(|error| error.to_string())?;
        let mut index = current.index().map_err(|error| error.to_string())?;
        index.read(true).map_err(|error| error.to_string())?;
        let dirty = dirty_worktree_paths(&current, scope.as_deref())?;
        let mut visited_gitlinks = HashSet::new();
        for entry in index.iter() {
            let rel = index_path_to_string(&entry)?;
            if entry.mode == 0o160000 {
                // Conflict stages may contain the same gitlink several times.
                if !visited_gitlinks.insert(rel.clone()) {
                    continue;
                }
                let child_prefix = format!("{rel}/");
                let child_scope = match scope.as_deref() {
                    Some(scope) if scope.starts_with(&child_prefix) => {
                        Some(scope[child_prefix.len()..].to_owned())
                    }
                    Some(scope) if !child_prefix.starts_with(scope) => continue,
                    _ => None,
                };
                if let Some(child) = materialized_submodule(&current, &rel)? {
                    pending.push((
                        child.path().to_path_buf(),
                        format!("{prefix}{child_prefix}"),
                        child_scope,
                    ));
                }
                continue;
            }
            if scope
                .as_deref()
                .is_some_and(|scope| !rel.starts_with(scope))
            {
                continue;
            }
            if (!dirty.contains(&rel) || workdir.join(&rel).is_file())
                && (prefix.is_empty() || contained_child_file(&workdir, Path::new(&rel))?)
            {
                paths.insert(format!("{prefix}{rel}"));
            }
        }
        for rel in dirty {
            if index.get_path(Path::new(&rel), 0).is_none()
                && workdir.join(&rel).is_file()
                && (prefix.is_empty() || contained_child_file(&workdir, Path::new(&rel))?)
            {
                paths.insert(format!("{prefix}{rel}"));
            }
        }
    }
    Ok(paths)
}

/// Whether one working-directory path belongs to the listing
/// [`all_working_tree_paths`] builds, decided for that path alone.
///
/// The listing holds tracked paths whose file exists and untracked files Git
/// does not ignore, so a path is listed when it is a file and either the index
/// tracks it or no ignore rule matches it. A file watcher uses this to update
/// a cached listing for one created, removed or renamed path without walking
/// the worktree.
pub fn working_tree_path_is_listed(repo: &Repository, rel_path: &Path) -> Result<bool> {
    if !rel_path
        .components()
        .all(|part| matches!(part, std::path::Component::Normal(_)))
    {
        return Ok(false);
    }
    let mut current = Repository::open(repo.path()).map_err(|error| error.to_string())?;
    let mut relative = rel_path.to_path_buf();
    let mut in_child = false;
    loop {
        let workdir = workdir(&current)?
            .canonicalize()
            .map_err(|error| error.to_string())?;
        let normalized_workdir = workdir.to_path_buf().normalize();
        let mut index = current.index().map_err(|error| error.to_string())?;
        index.read(true).map_err(|error| error.to_string())?;
        // A gitlink can only be an ancestor of this path. Point membership
        // probes those index entries instead of scanning the whole index.
        let gitlink = relative
            .ancestors()
            .filter(|path| !path.as_os_str().is_empty())
            .find_map(|path| {
                (0..=3)
                    .filter_map(|stage| index.get_path(path, stage))
                    .find(|entry| entry.mode == 0o160000)
            })
            .map(|entry| index_path_to_string(&entry))
            .transpose()?;
        if let Some(gitlink) = gitlink {
            let Some(child) = materialized_submodule(&current, &gitlink)? else {
                return Ok(false);
            };
            relative = relative
                .strip_prefix(&gitlink)
                .expect("gitlink prefix matched")
                .to_path_buf();
            current = child;
            in_child = true;
            continue;
        }
        if !workdir.join(&relative).is_file() {
            return Ok(false);
        }
        if in_child && !contained_child_file(&workdir, &relative)? {
            return Ok(false);
        }
        if index.get_path(&relative, 0).is_some() {
            return Ok(true);
        }
        // Native Git does not enumerate the contents of an untracked nested
        // repository. A point update must not admit them either.
        if let Some(owner) = workdir.join(&relative).parent().and_then(discover) {
            let owner_workdir = owner
                .workdir()
                .map(Path::canonicalize)
                .transpose()
                .map_err(|error| error.to_string())?
                .map(NormalizePath::normalize);
            if owner_workdir.as_deref() != Some(normalized_workdir.as_path()) {
                return Ok(false);
            }
        }
        return current
            .is_path_ignored(&relative)
            .map(|ignored| !ignored)
            .map_err(|error| error.to_string());
    }
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

/// Blob OIDs (hex) for every existing tracked file and every untracked file in
/// `root`'s working tree.
///
/// GC must retain the bytes analyzers actually parsed, even when Git considers
/// those bytes clean after line-ending conversion. Missing files are skipped.
/// An unreadable worktree or file does not prove that its
/// cached bytes are dead, so errors abort collection instead of omitting them.
pub fn existing_working_tree_oids(root: &Path) -> Result<HashSet<String>> {
    // Git retains prunable registrations for worktrees whose directories were
    // removed. They cannot own current working files; an existing directory
    // whose repository cannot be opened is a different, uncertain case.
    if !root.try_exists().map_err(|error| error.to_string())? {
        return Ok(HashSet::new());
    }
    let repo = Repository::open(root)
        .map_err(|error| format!("opening GC worktree {}: {error}", root.display()))?;
    let workdir = workdir(&repo)?;
    let mut out = HashSet::new();
    for rel in all_working_tree_paths(&repo)? {
        let path = workdir.join(&rel);
        let metadata = match std::fs::metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(format!("inspecting GC file {}: {error}", path.display())),
        };
        if metadata.is_file() {
            let oid = hash_working_file(workdir, &rel)
                .map_err(|error| format!("hashing GC file {}: {error}", path.display()))?;
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
/// this helper, or explicitly supplies that environment to the shared bounded
/// process runner, so no call site can reintroduce the race.
fn background_git(workdir: &Path) -> Command {
    let mut command = Command::new("git");
    command.current_dir(workdir).env("GIT_OPTIONAL_LOCKS", "0");
    command
}

pub fn resolve_index_entry_oid(workdir: &Path, entry: &IndexEntry) -> Result<Oid> {
    let rel = index_path_to_string(entry)?;
    hash_working_file(workdir, &rel)
}

pub fn index_path_to_string(entry: &IndexEntry) -> Result<String> {
    String::from_utf8(entry.path.clone()).map_err(|err| format!("non-UTF-8 git index path: {err}"))
}

fn dirty_worktree_paths(repo: &Repository, subtree: Option<&str>) -> Result<HashSet<String>> {
    let _scope = crate::profiling::scope("gitblob::dirty_worktree_paths");
    let workdir = workdir(repo)?;
    // libgit2's recursive index-to-worktree diff can rescan very large trees
    // one entry at a time. Native Git uses its optimized index and filesystem
    // checks for the same dirty overlay. This matters for repositories such as
    // Firefox, where the libgit2 scan exceeded the MCP request budget.
    let mut args: Vec<std::ffi::OsString> =
        ["status", "--porcelain=v1", "-z", "--untracked-files=all"]
            .into_iter()
            .map(Into::into)
            .collect();
    if let Some(subtree) = subtree {
        // Porcelain paths stay relative to the working directory root, so the
        // pathspec changes only which part of the tree Git walks. `:(literal)`
        // keeps a directory name containing `*`, `?`, `[`, or a leading `:`
        // from being read as pathspec magic.
        args.push("--".into());
        args.push(format!(":(literal){subtree}").into());
    }
    // A regular file read can block in a worktree's filesystem provider. GC
    // joins its worker on workspace shutdown, so an unbounded status child
    // previously prevented the workspace from closing. The shared runner
    // terminates and reaps the child and its descendants on timeout. Preserve
    // the complete porcelain stream; no output is silently truncated.
    let output = crate::process::run_bounded_process(
        &crate::process::BoundedProcessRequest {
            program: "git".into(),
            args,
            env: vec![("GIT_OPTIONAL_LOCKS".into(), "0".into())],
            clear_env: false,
            cwd: workdir.to_path_buf(),
            stdin: None,
            timeout: Duration::from_secs(30),
            stdout_limit: usize::MAX,
            stderr_limit: usize::MAX,
            description: format!("git status in {}", workdir.display()),
        },
        || false,
    )?;
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

fn hash_working_file(workdir: &Path, rel: &str) -> Result<Oid> {
    #[cfg(test)]
    HASH_WORKING_FILE_CALLS.with(|calls| calls.set(calls.get() + 1));
    working_tree_file_oid(&workdir.join(rel))
}

/// Hash one working-tree file as a Git blob without resolving it through an index.
pub fn working_tree_file_oid(path: &Path) -> Result<Oid> {
    Oid::hash_file(ObjectType::Blob, path).map_err(|e| e.to_string())
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
    use git2::{IndexTime, Oid, Repository, Signature};
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

    pub fn commit_all(repo: &Repository, message: &str) -> Oid {
        let signature = Signature::now("T", "t@example.com").unwrap();
        crate::test_git_support::commit_all(repo, message, &signature)
    }

    pub fn commit_paths(repo: &Repository, paths: &[&str], message: &str) -> Oid {
        let signature = Signature::now("T", "t@example.com").unwrap();
        crate::test_git_support::commit_paths(repo, paths, message, &signature)
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
    use super::test_repo::{commit_all, commit_paths, init_repo};
    use super::*;
    use brokk_bifrost_test_macros::hardwon;

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
    #[hardwon("#1469: local promisor transports must not be mistaken for network remotes")]
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
    #[hardwon("#1469: blobless partial-clone reachability could trigger an unbounded remote fetch")]
    fn reachable_bloom_refuses_network_promisor_enumeration_before_spawning_git() {
        let temp = tempfile::TempDir::new().unwrap();
        let repo = init_repo(temp.path());
        set_promisor_url(&repo, "https://example.invalid/repo.git");

        let error = reachable_bloom(&repo).expect_err("network promisor walk must be refused");
        assert!(error.contains("refusing to enumerate"), "{error}");
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

    fn initialized_child(parent: &Repository, rel: &str) -> Repository {
        let root = parent.workdir().unwrap();
        let child = init_repo(&root.join(rel));
        std::fs::write(
            child.workdir().unwrap().join("tracked.py"),
            "def tracked(): return 1\n",
        )
        .unwrap();
        let oid = commit_all(&child, "child");
        register_gitlink(parent, rel, oid);
        child
    }

    fn register_gitlink(parent: &Repository, rel: &str, oid: Oid) {
        let root = parent.workdir().unwrap();
        let modules = root.join(".gitmodules");
        let mut text = if modules.exists() {
            std::fs::read_to_string(&modules).unwrap()
        } else {
            String::new()
        };
        text.push_str(&format!(
            "[submodule \"{rel}\"]\n\tpath = {rel}\n\turl = https://example.invalid/child.git\n"
        ));
        std::fs::write(modules, text).unwrap();
        let mut index = parent.index().unwrap();
        index
            .add(&IndexEntry {
                ctime: git2::IndexTime::new(0, 0),
                mtime: git2::IndexTime::new(0, 0),
                dev: 0,
                ino: 0,
                mode: 0o160000,
                uid: 0,
                gid: 0,
                file_size: 0,
                id: oid,
                flags: 0,
                flags_extended: 0,
                path: rel.as_bytes().to_vec(),
            })
            .unwrap();
        index.write().unwrap();
        drop(index);
        commit_paths(parent, &[".gitmodules"], "register child");
    }

    #[test]
    #[hardwon(
        "#3772: initialized Git submodule sources were omitted from parent workspace analysis"
    )]
    fn materialized_submodules_preserve_nested_source_scope_and_identity() {
        let temp = tempfile::tempdir().unwrap();
        let parent = init_repo(temp.path());
        std::fs::write(temp.path().join("parent.py"), "def parent(): return 1\n").unwrap();
        commit_all(&parent, "parent");
        let child = initialized_child(&parent, "vendor/child");
        let nested = initialized_child(&child, "nested");
        let nested_root = nested.workdir().unwrap();
        std::fs::write(nested_root.join(".gitignore"), "ignored.py\ntracked.py\n").unwrap();
        std::fs::write(nested_root.join("ignored.py"), "ignored").unwrap();
        std::fs::write(nested_root.join("new.py"), "def new(): return 2\n").unwrap();
        let changed = b"def tracked(): return 42\n";
        std::fs::write(nested_root.join("tracked.py"), changed).unwrap();

        let paths = all_working_tree_paths(&parent).unwrap();
        for path in [
            "parent.py",
            "vendor/child/tracked.py",
            "vendor/child/nested/tracked.py",
            "vendor/child/nested/new.py",
        ] {
            assert!(paths.contains(path), "{paths:?}");
            assert!(
                working_tree_path_is_listed(&parent, Path::new(path)).unwrap(),
                "point membership rejected listed path {path:?}: {paths:?}"
            );
        }
        for path in [
            "vendor/child",
            "vendor/child/nested",
            "vendor/child/nested/ignored.py",
            "vendor/child/.git/config",
        ] {
            assert!(!paths.contains(path), "{paths:?}");
            assert!(!working_tree_path_is_listed(&parent, Path::new(path)).unwrap());
        }
        let scoped = working_tree_paths_under(&parent, "vendor/child/nested/").unwrap();
        assert_eq!(
            scoped,
            paths
                .iter()
                .filter(|path| path.starts_with("vendor/child/nested/"))
                .cloned()
                .collect()
        );
        assert!(
            !working_tree_paths_under(&parent, "vendor/childish/")
                .unwrap()
                .contains("vendor/child/tracked.py")
        );
        let oid = Oid::hash_object(ObjectType::Blob, changed)
            .unwrap()
            .to_string();
        let rel = "vendor/child/nested/tracked.py".to_string();
        let resolved = working_tree_identity(&parent)
            .unwrap()
            .resolve_with_metadata(&parent, std::slice::from_ref(&rel))
            .unwrap();
        assert_eq!(resolved[&rel].oid.to_string(), oid);
        assert!(
            existing_working_tree_oids(temp.path())
                .unwrap()
                .contains(&oid)
        );
        assert!(parent.find_blob(Oid::from_str(&oid).unwrap()).is_err());
        std::fs::remove_file(nested_root.join("tracked.py")).unwrap();
        assert!(
            !all_working_tree_paths(&parent)
                .unwrap()
                .contains("vendor/child/nested/tracked.py")
        );
        assert!(
            !working_tree_path_is_listed(&parent, Path::new("vendor/child/nested/tracked.py"))
                .unwrap()
        );
    }

    #[test]
    #[hardwon("#3772: uninitialized gitlinks must not be fetched or treated as discovered source")]
    fn materialized_submodules_skip_uninitialized_and_unregistered_repositories() {
        let temp = tempfile::tempdir().unwrap();
        let parent = init_repo(temp.path());
        std::fs::write(temp.path().join("parent.py"), "parent").unwrap();
        commit_all(&parent, "parent");
        let child = initialized_child(&parent, "child");
        let oid = child.head().unwrap().target().unwrap();
        register_gitlink(&parent, "missing", oid);
        let unrelated = init_repo(&temp.path().join("unregistered"));
        std::fs::write(
            unrelated.workdir().unwrap().join("private.py"),
            "unregistered",
        )
        .unwrap();
        commit_all(&unrelated, "unregistered");
        let paths = all_working_tree_paths(&parent).unwrap();
        assert!(paths.contains("child/tracked.py"), "{paths:?}");
        assert!(!paths.contains("missing"), "{paths:?}");
        assert!(!paths.contains("unregistered/private.py"), "{paths:?}");
        assert!(
            !working_tree_path_is_listed(&parent, Path::new("unregistered/private.py")).unwrap()
        );
        assert!(!working_tree_path_is_listed(&parent, Path::new("missing/tracked.py")).unwrap());
    }

    #[test]
    #[hardwon("#3772: conflicted gitlink stages duplicated or desynchronized submodule membership")]
    fn materialized_submodule_conflict_keeps_point_membership_in_sync() {
        let temp = tempfile::tempdir().unwrap();
        let parent = init_repo(temp.path());
        initialized_child(&parent, "child");
        let mut index = parent.index().unwrap();
        let mut entry = index.get_path(Path::new("child"), 0).unwrap();
        index.remove_path(Path::new("child")).unwrap();
        for stage in 1..=3 {
            entry.flags = (entry.flags & !0x3000) | (stage << 12);
            index.add(&entry).unwrap();
        }
        index.write().unwrap();
        assert!(index.has_conflicts());
        assert!(index.get_path(Path::new("child"), 0).is_none());
        let paths = all_working_tree_paths(&parent).unwrap();
        assert!(paths.contains("child/tracked.py"), "{paths:?}");
        assert!(working_tree_path_is_listed(&parent, Path::new("child/tracked.py")).unwrap());
    }

    #[test]
    #[hardwon("#3772: initialized submodule source discovery failed for gitfile checkouts")]
    fn materialized_submodules_support_gitfile_checkouts() {
        let temp = tempfile::tempdir().unwrap();
        let parent = init_repo(temp.path());
        let child = initialized_child(&parent, "child");
        let child_root = child.workdir().unwrap().to_path_buf();
        child
            .config()
            .unwrap()
            .set_str("core.worktree", child_root.to_str().unwrap())
            .unwrap();
        let gitdir = parent.path().join("modules/child");
        std::fs::create_dir_all(gitdir.parent().unwrap()).unwrap();
        drop(child);
        std::fs::rename(child_root.join(".git"), &gitdir).unwrap();
        std::fs::write(
            child_root.join(".git"),
            format!("gitdir: {}\n", gitdir.display()),
        )
        .unwrap();
        let paths = all_working_tree_paths(&parent).unwrap();
        assert!(paths.contains("child/tracked.py"), "{paths:?}");
        assert!(!paths.contains("child/.git"), "{paths:?}");
        assert!(working_tree_path_is_listed(&parent, Path::new("child/tracked.py")).unwrap());
        let project = crate::analyzer::project::FilesystemProject::new(temp.path()).unwrap();
        use crate::analyzer::project::Project;
        assert!(
            project
                .analyzable_files(crate::analyzer::Language::Python)
                .unwrap()
                .iter()
                .any(|file| file.rel_path() == Path::new("child/tracked.py"))
        );
    }

    #[cfg(unix)]
    #[test]
    #[hardwon("#3772: submodule discovery must not admit symlink paths outside its parent root")]
    fn materialized_submodules_reject_source_and_directory_symlink_escapes() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let parent = init_repo(temp.path());
        let child = initialized_child(&parent, "child");
        std::fs::write(outside.path().join("private.py"), "private").unwrap();
        symlink(
            outside.path().join("private.py"),
            child.workdir().unwrap().join("escape.py"),
        )
        .unwrap();
        assert!(
            all_working_tree_paths(&parent)
                .unwrap_err()
                .contains("escapes")
        );
        assert!(
            working_tree_path_is_listed(&parent, Path::new("child/escape.py"))
                .unwrap_err()
                .contains("escapes")
        );
        std::fs::remove_file(child.workdir().unwrap().join("escape.py")).unwrap();
        let external = init_repo(outside.path());
        commit_all(&external, "external");
        register_gitlink(
            &parent,
            "linked",
            external.head().unwrap().target().unwrap(),
        );
        symlink(outside.path(), temp.path().join("linked")).unwrap();
        // Native Git may reject the replaced gitlink during status before
        // the explicit containment check. Either path must fail closed.
        assert!(all_working_tree_paths(&parent).is_err());
        assert!(
            working_tree_path_is_listed(&parent, Path::new("linked/private.py"))
                .unwrap_err()
                .contains("symlink")
        );
    }

    #[test]
    #[hardwon("#2742: subtree enumeration must use workdir-relative pathspecs without siblings")]
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
    #[hardwon(
        "#2742: Windows subtree pathspecs must spell the root-relative path with forward slashes"
    )]
    fn subtree_pathspec_spells_windows_roots_with_forward_slashes() {
        assert_eq!(
            subtree_pathspec(Path::new(r"C:\repo"), Path::new(r"C:\repo\packages\app")).as_deref(),
            Some("packages/app/")
        );
    }

    #[test]
    #[hardwon(
        "#2742: subtree queries scanned ancestor repositories instead of the requested workspace scope"
    )]
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
    #[hardwon(
        "#2542: file identity batching read stale metadata and needlessly hashed clean files"
    )]
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
    #[hardwon("#1679: announced edits stayed invisible because Git file identities were stale")]
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

    /// GC keeps an analyzer row while its blob is in `live_bloom`, which joins
    /// `reachable_bloom` with `existing_working_tree_oids` for every
    /// registered worktree. Each set must hold every blob a row can name.
    #[test]
    fn gc_liveness_covers_history_empty_files_and_removed_worktrees() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path().join("main");
        std::fs::create_dir_all(&root).unwrap();
        let repo = init_repo(&root);
        // An ordinary clone: a network remote without `remote.origin.promisor`.
        // Git treats a remote as a promisor only when that key is true or
        // `extensions.partialclone` names it.
        repo.remote("origin", "https://example.invalid/repo.git")
            .unwrap();
        assert!(!has_network_promisor_remote(&repo).unwrap());

        std::fs::write(root.join("a.rs"), "fn first() {}\n").unwrap();
        std::fs::write(root.join("__init__.py"), "").unwrap();
        let first = commit_all(&repo, "first");
        std::fs::write(root.join("a.rs"), "fn second() {}\n").unwrap();
        commit_all(&repo, "second");
        std::fs::write(root.join("untracked.py"), "").unwrap();

        // A linked worktree whose directory was deleted without
        // `git worktree prune` stays registered.
        let linked = temp.path().join("linked");
        repo.worktree("linked", &linked, None).unwrap();
        std::fs::remove_dir_all(&linked).unwrap();
        assert_eq!(worktree_roots(&repo).unwrap().len(), 2);
        assert_eq!(existing_working_tree_oids(&linked).unwrap(), HashSet::new());

        // A blob reachable only from history, read from the first commit's tree.
        let history_blob = repo
            .find_commit(first)
            .unwrap()
            .tree()
            .unwrap()
            .get_name("a.rs")
            .expect("a.rs in the first commit")
            .id();
        assert_eq!(
            history_blob,
            Oid::hash_object(ObjectType::Blob, b"fn first() {}\n").unwrap()
        );
        let bloom = reachable_bloom(&repo).unwrap();
        assert!(bloom.contains(history_blob.to_string().as_str()));

        // Empty files share Git's well-known empty blob OID.
        let empty_blob = "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391";
        assert!(
            existing_working_tree_oids(&root)
                .unwrap()
                .contains(empty_blob)
        );
        std::fs::remove_file(root.join("__init__.py")).unwrap();
        assert!(
            existing_working_tree_oids(&root)
                .unwrap()
                .contains(empty_blob),
            "an untracked empty file alone keeps the empty blob live"
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
}

/// Cache-identity tests on real repositories. The oracles are git2's own
/// `Oid::hash_object` over the bytes on disk, `Repository::status_file`, and
/// the committed blob's byte length; none of them reuse the code under test.
#[cfg(test)]
mod working_tree_identity_tests {
    use super::test_repo::{commit_all, init_repo};
    use super::*;
    use brokk_bifrost_test_macros::hardwon;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    /// A fixed time well before any index file written during a test, so no
    /// index entry is ever racily clean.
    fn mtime(step: u64) -> SystemTime {
        UNIX_EPOCH + Duration::new(1_700_000_000 + step, 123_456_789)
    }

    fn set_mtime(path: &Path, step: u64) {
        std::fs::OpenOptions::new()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(mtime(step))
            .unwrap();
    }

    /// Write `bytes` with mode 0644 (independent of the umask) and a chosen
    /// mtime. Equal file system timestamps are otherwise common for writes
    /// made within one kernel tick.
    pub(super) fn write_file(path: &Path, bytes: &[u8], step: u64) {
        std::fs::write(path, bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        set_mtime(path, step);
    }

    pub(super) fn blob_oid(bytes: &[u8]) -> Oid {
        Oid::hash_object(ObjectType::Blob, bytes).unwrap()
    }

    fn index_oid(repo: &Repository, rel: &str) -> Oid {
        repo.index()
            .unwrap()
            .get_path(Path::new(rel), 0)
            .expect("tracked path")
            .id
    }

    #[test]
    fn stat_clean_identity_serves_the_index_oid_until_the_stat_changes() {
        let temp = tempfile::TempDir::new().unwrap();
        let repo = init_repo(temp.path());
        let file = temp.path().join("a.rs");
        let committed: &[u8] = b"fn a() {}\n";
        write_file(&file, committed, 0);
        write_file(&temp.path().join("other.rs"), b"fn o() {}\n", 0);
        commit_all(&repo, "init");
        let identity = working_tree_identity(&repo).unwrap();
        let both = |rel: &str| {
            let abs = temp.path().join(rel);
            (
                identity.clean_index_oid(&repo, rel, &abs),
                identity.stat_clean_index_oid(rel, &abs),
            )
        };
        // The production path, `resolve_with_metadata`, answers from the same
        // snapshot and the same verified-clean memo.
        let resolve = |rel: &str| {
            identity
                .resolve_with_metadata(&repo, &[rel.to_string()])
                .unwrap()[rel]
                .oid
        };
        let modified = |rel: &str| {
            repo.status_file(Path::new(rel))
                .unwrap()
                .contains(git2::Status::WT_MODIFIED)
        };
        let committed_oid = blob_oid(committed);

        assert_eq!(both("a.rs"), (Some(committed_oid), Some(committed_oid)));
        // Served again from the verified-clean memo.
        assert_eq!(both("a.rs"), (Some(committed_oid), Some(committed_oid)));

        // A different size alone stops the fast path, even with the recorded
        // mtime and a path already in the verified-clean memo.
        let longer: &[u8] = b"fn a() { 1; }\n";
        write_file(&file, longer, 0);
        assert!(modified("a.rs"));
        assert_eq!(both("a.rs"), (None, None));
        assert_eq!(resolve("a.rs"), blob_oid(longer));

        // A different size or a different mtime stops the fast path.
        write_file(&file, b"fn a() { 1; }\n", 1);
        assert_eq!(both("a.rs"), (None, None));
        write_file(&file, b"fn z() {}\n", 2);
        assert_eq!(both("a.rs"), (None, None));

        // Restoring the bytes and mtime restores the identity.
        write_file(&file, committed, 0);
        assert_eq!(both("a.rs"), (Some(committed_oid), Some(committed_oid)));
        assert_eq!(resolve("a.rs"), committed_oid);

        // A same-size edit that keeps the whole-second mtime but changes the
        // recorded nanoseconds stops the fast path too. The nanosecond value
        // is a multiple of 100 ns so that NTFS can store it. Skip this step
        // where the file system or the index dropped the nanoseconds, because
        // then no stat difference exists.
        let same_size: &[u8] = b"fn y() {}\n";
        assert_eq!(same_size.len(), committed.len());
        std::fs::write(&file, same_size).unwrap();
        let nanos_mtime = UNIX_EPOCH + Duration::new(1_700_000_000, 987_654_300);
        std::fs::OpenOptions::new()
            .write(true)
            .open(&file)
            .unwrap()
            .set_modified(nanos_mtime)
            .unwrap();
        let stored = std::fs::metadata(&file).unwrap().modified().unwrap();
        let index_nanos = repo
            .index()
            .unwrap()
            .get_path(Path::new("a.rs"), 0)
            .expect("tracked path")
            .mtime
            .nanoseconds();
        if stored == nanos_mtime && index_nanos != 0 && index_nanos != 987_654_300 {
            assert!(modified("a.rs"));
            assert_eq!(both("a.rs"), (None, None));
            assert_eq!(resolve("a.rs"), blob_oid(same_size));
        } else {
            eprintln!(
                "skipping the nanosecond step: stored mtime {stored:?}, index nanoseconds {index_nanos}"
            );
        }

        // Racy case: a same-size edit that restores the mtime is invisible to
        // the stat check, so the snapshot still serves the old OID. The
        // caller-supplied invalidation is the remedy and applies per path.
        write_file(&file, b"fn z() {}\n", 0);
        assert_eq!(both("a.rs"), (Some(committed_oid), Some(committed_oid)));
        identity.invalidate_paths(["a.rs".to_string()]);
        assert_eq!(both("a.rs"), (None, None));
        assert_eq!(
            both("other.rs"),
            (
                Some(blob_oid(b"fn o() {}\n")),
                Some(blob_oid(b"fn o() {}\n"))
            )
        );

        // Missing and untracked paths have no index identity.
        write_file(&temp.path().join("new.rs"), b"fn n() {}\n", 0);
        assert_eq!(both("new.rs"), (None, None));
        assert_eq!(both("ghost.rs"), (None, None));
    }

    #[test]
    fn paths_dirty_at_scan_time_have_no_index_identity() {
        let temp = tempfile::TempDir::new().unwrap();
        let repo = init_repo(temp.path());
        let file = temp.path().join("a.rs");
        write_file(&file, b"fn a() {}\n", 0);
        commit_all(&repo, "init");

        write_file(&file, b"fn z() {}\n", 1);
        let identity = working_tree_identity(&repo).unwrap();
        // The edit is reverted after the scan, so the stat matches the index
        // again; the scan still saw the path dirty and refuses its OID.
        write_file(&file, b"fn a() {}\n", 0);
        assert_eq!(identity.clean_index_oid(&repo, "a.rs", &file), None);
        assert_eq!(identity.stat_clean_index_oid("a.rs", &file), None);
    }

    #[test]
    fn transformed_or_unverifiable_clean_entries_only_serve_the_stat_form() {
        let temp = tempfile::TempDir::new().unwrap();
        let repo = init_repo(temp.path());
        write_file(&temp.path().join("eol.cs"), b"class A {}\n", 0);
        write_file(&temp.path().join("filtered.txt"), b"hello\n", 0);
        write_file(&temp.path().join("plain.txt"), b"plain\n", 0);
        write_file(&temp.path().join("missing.rs"), b"fn m() {}\n", 0);
        commit_all(&repo, "init");
        write_file(
            &temp.path().join(".gitattributes"),
            b"*.cs text eol=crlf\nfiltered.txt filter=opaque\n",
            0,
        );
        commit_all(&repo, "attributes");

        // The CRLF checkout keeps the canonical LF blob in the index but a
        // longer file on disk. Git records that file's stat in the index.
        write_file(&temp.path().join("eol.cs"), b"class A {}\r\n", 1);
        let eol_oid = super::test_repo::refresh_index_stat_preserving_oid(&repo, "eol.cs");
        assert_eq!(eol_oid, blob_oid(b"class A {}\n"));

        // Delete the loose object behind missing.rs, so the index names an
        // object the database no longer holds while the stat still matches.
        let absent = index_oid(&repo, "missing.rs");
        let hex = absent.to_string();
        std::fs::remove_file(repo.path().join("objects").join(&hex[..2]).join(&hex[2..])).unwrap();
        let repo = Repository::open(temp.path()).unwrap();

        let identity = working_tree_identity(&repo).unwrap();
        let abs = |rel: &str| temp.path().join(rel);

        // Transformed or unverifiable: the checked form declines (the caller
        // must hash the visible bytes), the stat form still names the index OID.
        for (rel, index) in [
            ("eol.cs", eol_oid),
            ("filtered.txt", blob_oid(b"hello\n")),
            ("missing.rs", absent),
        ] {
            assert_eq!(
                identity.clean_index_oid(&repo, rel, &abs(rel)),
                None,
                "{rel}"
            );
            assert_eq!(
                identity.stat_clean_index_oid(rel, &abs(rel)),
                Some(index),
                "{rel}"
            );
        }
        assert_eq!(
            identity.clean_index_oid(&repo, "plain.txt", &abs("plain.txt")),
            Some(blob_oid(b"plain\n"))
        );
    }

    /// Each attribute lets a clean checkout show bytes that differ from the
    /// canonical blob the index names. Git keeps the path clean because the
    /// index stat matches, so only the attribute (or, for eol, the size)
    /// tells the production path to hash the visible bytes.
    #[test]
    #[hardwon(
        "#1742: CRLF and same-size filtered checkouts got the index OID, not the visible bytes"
    )]
    fn transformed_clean_entries_resolve_to_the_visible_bytes() {
        let temp = tempfile::TempDir::new().unwrap();
        let repo = init_repo(temp.path());
        // The fixture rewrites each file in place and then records its size
        // and mtime in the index, as a transforming checkout would. It cannot
        // record the real ctime, so tell `git status` not to compare it; a
        // ctime mismatch would make Git rehash and report the path dirty.
        repo.config()
            .unwrap()
            .set_bool("core.trustctime", false)
            .unwrap();
        let ident_committed = format!("$Id: {} $\n", "0".repeat(40)).into_bytes();
        // Checkout replaces any expanded `$Id: ... $` with the blob's own OID.
        let ident_visible = format!("$Id: {} $\n", blob_oid(&ident_committed)).into_bytes();
        // (path, committed bytes, bytes a transforming checkout writes)
        let cases: Vec<(&str, Vec<u8>, Vec<u8>)> = vec![
            (
                "eol.cs",
                b"class A {}\n".to_vec(),
                b"class A {}\r\n".to_vec(),
            ),
            // A filter driver whose smudge output keeps the length.
            ("filtered.txt", b"hello\n".to_vec(), b"HELLO\n".to_vec()),
            ("ident.txt", ident_committed, ident_visible),
            // "text\n" in EBCDIC code page 037: one byte per character.
            (
                "encoded.txt",
                b"text\n".to_vec(),
                vec![0xA3, 0x85, 0xA7, 0xA3, 0x25],
            ),
        ];
        for (rel, committed, _) in &cases {
            write_file(&temp.path().join(rel), committed, 0);
        }
        commit_all(&repo, "init");
        write_file(
            &temp.path().join(".gitattributes"),
            b"*.cs text eol=crlf\nfiltered.txt filter=opaque\nident.txt ident\n\
              encoded.txt working-tree-encoding=IBM037\n",
            0,
        );
        super::test_repo::commit_paths(&repo, &[".gitattributes"], "attributes");
        for (rel, committed, visible) in &cases {
            assert_ne!(blob_oid(visible), blob_oid(committed), "{rel}");
            write_file(&temp.path().join(rel), visible, 1);
            let index = super::test_repo::refresh_index_stat_preserving_oid(&repo, rel);
            assert_eq!(index, blob_oid(committed), "{rel}");
        }

        let identity = working_tree_identity(&repo).unwrap();
        let rels: Vec<String> = cases.iter().map(|(rel, _, _)| rel.to_string()).collect();
        let resolved = identity.resolve_with_metadata(&repo, &rels).unwrap();
        for (rel, committed, visible) in &cases {
            let abs = temp.path().join(rel);
            // The scan saw the path clean with a matching stat, so the index
            // fast path was available to every resolver below.
            assert_eq!(
                identity.stat_clean_index_oid(rel, &abs),
                Some(blob_oid(committed)),
                "{rel}"
            );
            assert_eq!(resolved[*rel].oid, blob_oid(visible), "{rel}");
            assert_eq!(identity.clean_index_oid(&repo, rel, &abs), None, "{rel}");
        }
    }

    #[test]
    fn canonical_blob_size_is_the_stored_byte_length_of_blobs_only() {
        let temp = tempfile::TempDir::new().unwrap();
        let repo = init_repo(temp.path());
        let bytes = b"line one\nline two\r\n\0binary tail";
        let blob = repo.blob(bytes).unwrap();
        let empty = repo.blob(b"").unwrap();
        write_file(&temp.path().join("a.rs"), b"fn a() {}\n", 0);
        let commit = commit_all(&repo, "init");
        let tree = repo.find_commit(commit).unwrap().tree_id();

        assert_eq!(canonical_blob_size(&repo, blob), Some(bytes.len() as u64));
        assert_eq!(canonical_blob_size(&repo, empty), Some(0));
        // Present, but not a blob.
        assert_eq!(canonical_blob_size(&repo, tree), None);
        assert_eq!(canonical_blob_size(&repo, commit), None);
        // Absent from the object database.
        assert_eq!(canonical_blob_size(&repo, blob_oid(b"never stored")), None);
    }

    #[test]
    fn index_entry_oid_is_the_hash_of_the_visible_bytes_not_the_recorded_id() {
        let temp = tempfile::TempDir::new().unwrap();
        let repo = init_repo(temp.path());
        let file = temp.path().join("a.rs");
        write_file(&file, b"fn a() {}\n", 0);
        commit_all(&repo, "init");
        let entry = repo
            .index()
            .unwrap()
            .get_path(Path::new("a.rs"), 0)
            .unwrap();
        assert_eq!(
            resolve_index_entry_oid(temp.path(), &entry).unwrap(),
            entry.id
        );

        write_file(&file, b"fn changed() {}\n", 1);
        let resolved = resolve_index_entry_oid(temp.path(), &entry).unwrap();
        assert_eq!(resolved, blob_oid(b"fn changed() {}\n"));
        assert_ne!(resolved, entry.id);

        // A deleted file is an error, not a stale OID.
        std::fs::remove_file(&file).unwrap();
        assert!(resolve_index_entry_oid(temp.path(), &entry).is_err());

        // An index path that is not UTF-8 cannot name a file for the caller.
        let mut bad = entry;
        bad.path = vec![0xff, 0xfe];
        assert!(
            resolve_index_entry_oid(temp.path(), &bad)
                .unwrap_err()
                .contains("non-UTF-8")
        );
    }

    #[test]
    fn read_blob_returns_stored_bytes_and_rejects_non_blobs() {
        let temp = tempfile::TempDir::new().unwrap();
        let repo = init_repo(temp.path());
        write_file(&temp.path().join("a.rs"), b"fn a() {}\n", 0);
        let commit = commit_all(&repo, "init");
        let tree = repo.find_commit(commit).unwrap().tree_id();
        let stored = repo.blob(b"\xff\0not utf8\r\n").unwrap();

        assert_eq!(
            read_blob(&repo, &stored.to_string()).unwrap(),
            b"\xff\0not utf8\r\n"
        );
        assert!(read_blob(&repo, "not a hex oid").is_err());
        assert!(read_blob(&repo, &blob_oid(b"never stored").to_string()).is_err());
        assert!(read_blob(&repo, &tree.to_string()).is_err());
    }

    #[test]
    fn default_branch_ref_follows_origin_head_and_otherwise_falls_back_to_head() {
        let temp = tempfile::TempDir::new().unwrap();
        let repo = init_repo(temp.path());
        write_file(&temp.path().join("a.rs"), b"fn a() {}\n", 0);
        let commit = commit_all(&repo, "init");

        assert_eq!(
            resolve_default_branch_ref(&repo),
            DefaultBranchRef {
                ref_name: "HEAD".to_string(),
                display_name: "HEAD (default branch unavailable)".to_string(),
                fallback: true,
            }
        );

        repo.reference("refs/remotes/origin/main", commit, true, "main")
            .unwrap();
        // A non-symbolic origin/HEAD does not identify a branch.
        repo.reference("refs/remotes/origin/HEAD", commit, true, "detached")
            .unwrap();
        assert!(resolve_default_branch_ref(&repo).fallback);

        repo.reference_symbolic(
            "refs/remotes/origin/HEAD",
            "refs/remotes/origin/main",
            true,
            "origin/HEAD",
        )
        .unwrap();
        assert_eq!(
            resolve_default_branch_ref(&repo),
            DefaultBranchRef {
                ref_name: "refs/remotes/origin/main".to_string(),
                display_name: "main".to_string(),
                fallback: false,
            }
        );
    }

    #[test]
    #[hardwon("f288e4d7d2e6: a default branch with slashes showed only its last segment")]
    fn default_branch_display_name_keeps_slashes_in_branch_names() {
        let temp = tempfile::TempDir::new().unwrap();
        let repo = init_repo(temp.path());
        write_file(&temp.path().join("a.rs"), b"fn a() {}\n", 0);
        let commit = commit_all(&repo, "init");
        repo.reference("refs/remotes/origin/release/1.0", commit, true, "branch")
            .unwrap();
        repo.reference_symbolic(
            "refs/remotes/origin/HEAD",
            "refs/remotes/origin/release/1.0",
            true,
            "origin/HEAD",
        )
        .unwrap();
        let resolved = resolve_default_branch_ref(&repo);
        assert_eq!(resolved.ref_name, "refs/remotes/origin/release/1.0");
        assert_eq!(resolved.display_name, "release/1.0");
    }

    #[test]
    fn object_database_exists_for_checkouts_and_bare_repositories_only() {
        let temp = tempfile::TempDir::new().unwrap();

        // Discovery searches parent directories, so a plain directory has an
        // object database exactly when git finds one above it (a TMPDIR inside
        // a checkout). Ask git rather than assume the temp root is outside one.
        let plain = temp.path().join("plain");
        std::fs::create_dir(&plain).unwrap();
        let git_finds_one = std::process::Command::new("git")
            .arg("-C")
            .arg(&plain)
            .args(["rev-parse", "--git-dir"])
            .output()
            .unwrap()
            .status
            .success();
        assert_eq!(has_object_database(&plain), git_finds_one);

        let checkout = temp.path().join("checkout");
        std::fs::create_dir(&checkout).unwrap();
        init_repo(&checkout);
        std::fs::create_dir(checkout.join("sub")).unwrap();
        assert!(has_object_database(&checkout));
        assert!(has_object_database(&checkout.join("sub")));
        assert!(discover(&checkout).is_some());

        // A bare repository has objects but no checkout, so `discover`
        // filters it out while `has_object_database` accepts it.
        let bare = temp.path().join("bare.git");
        Repository::init_bare(&bare).unwrap();
        assert!(has_object_database(&bare));
        assert!(discover(&bare).is_none());
    }
}
