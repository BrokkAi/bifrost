//! Bounded process-local content digests for immutable-looking local files.
use crate::analyzer::canonical_hash::CanonicalHasher;
use crate::retention_budget::{BudgetRegion, RetainedBytes, RetentionBudget};
use std::fs::{File, Metadata};
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Regular-file identity from metadata. Unix reports device, inode, size, mtime
/// and ctime. Other platforms report size, the modification time and, where the
/// platform records it, the creation time in the ctime slot; stable std exposes
/// no device or inode there, so both are zero. Timestamps are only as fine as
/// the filesystem keeps them: FAT's 2 s modification granularity can hide a
/// same-size rewrite within that window, an accepted limit shared with IntelliJ.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FileIdentity {
    device: u64,
    inode: u64,
    size: u64,
    mtime_ns: i128,
    ctime_ns: i128,
}

/// Read the identity of a regular file. `None` means the path is not a regular
/// file or its modification time could not be read; callers treat that as a
/// change, never as a match.
pub fn file_identity(metadata: &Metadata) -> Option<FileIdentity> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        metadata.is_file().then(|| FileIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
            size: metadata.size(),
            mtime_ns: i128::from(metadata.mtime()) * 1_000_000_000
                + i128::from(metadata.mtime_nsec()),
            ctime_ns: i128::from(metadata.ctime()) * 1_000_000_000
                + i128::from(metadata.ctime_nsec()),
        })
    }
    #[cfg(not(unix))]
    {
        fn nanos_since_epoch(time: SystemTime) -> i128 {
            match time.duration_since(UNIX_EPOCH) {
                Ok(after) => after.as_nanos() as i128,
                Err(before) => -(before.duration().as_nanos() as i128),
            }
        }
        if !metadata.is_file() {
            return None;
        }
        Some(FileIdentity {
            device: 0,
            inode: 0,
            size: metadata.len(),
            mtime_ns: nanos_since_epoch(metadata.modified().ok()?),
            // A platform without creation times leaves the slot equal on both
            // sides of a comparison, so size and mtime decide.
            ctime_ns: metadata.created().map_or(0, nanos_since_epoch),
        })
    }
}

/// Read an identity for consumers that accept metadata-level change detection
/// on any filesystem and platform, including FUSE, overlayfs, network mounts
/// and Windows. A content change that leaves every identity field equal goes
/// unnoticed. `Ok(None)` means no identity could be read; treat it as changed. IntelliJ CE uses this model for JDK modules (records size and
/// mtime in `JrtHandler.java:49-103`, reopens jars when size or mtime changes
/// in `ZipHandler.java:15-23, 44-58`, and compares timestamp and length during
/// refresh in `RefreshWorker.java:751-761`), without a trusted-filesystem
/// branch. The shared content-digest cache retains its trusted-filesystem
/// allowlist for every other consumer. Use this reader as the deliberate
/// opt-in alternative when metadata-level detection is acceptable.
pub fn metadata_change_identity(path: &Path) -> std::io::Result<Option<FileIdentity>> {
    Ok(file_identity(&std::fs::metadata(path)?))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn filesystem_stats(path: &Path) -> std::io::Result<libc::statfs> {
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    let mut stats = std::mem::MaybeUninit::uninit();
    // SAFETY: path is NUL terminated and stats is writable statfs storage.
    if unsafe { libc::statfs(path.as_ptr(), stats.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: successful statfs initialized the storage.
    Ok(unsafe { stats.assume_init() })
}

#[cfg(target_os = "linux")]
pub(crate) fn filesystem_type(path: &Path) -> std::io::Result<u64> {
    Ok(filesystem_stats(path)?.f_type as u64 & 0xffff_ffff)
}

/// Positive allowlist; unknown filesystems and failed inspection are untrusted.
/// Consumers deliberately accepting metadata-level change detection on any
/// filesystem can use [`metadata_change_identity`] instead.
pub fn on_trusted_local_file_system(path: &Path) -> bool {
    #[cfg(target_os = "linux")]
    {
        // ext2/3/4, XFS, Btrfs, tmpfs, ZFS, F2FS.
        // Overlay backing mounts may be remote; inspecting them is future work.
        matches!(
            filesystem_type(path),
            Ok(0xef53 | 0x5846_5342 | 0x9123_683e | 0x0102_1994 | 0x2fc1_2fc1 | 0xf2f5_2010)
        )
    }
    #[cfg(target_os = "macos")]
    {
        let Ok(stats) = filesystem_stats(path) else {
            return false;
        };
        // SAFETY: statfs supplies a NUL-terminated filesystem name.
        let name = unsafe { std::ffi::CStr::from_ptr(stats.f_fstypename.as_ptr()) };
        matches!(name.to_bytes(), b"apfs" | b"hfs")
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = path;
        false
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Key {
    domain: &'static [u8],
    root: PathBuf,
    member_count: usize,
    listing_digest: [u8; 32],
}

fn identities(root: &Path, members: &[PathBuf]) -> Option<Vec<(String, FileIdentity)>> {
    let mut result = Vec::with_capacity(members.len());
    for member in members {
        // Only normal relative paths can be certified under this root.
        if member
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
        {
            return None;
        }
        let path = root.join(member);
        // A member may cross a mount boundary even when the root is local.
        if !on_trusted_local_file_system(&path) {
            return None;
        }
        let metadata = std::fs::metadata(&path).ok()?;
        result.push((member.to_str()?.to_owned(), file_identity(&metadata)?));
    }
    Some(result)
}

fn racy_clean(members: &[(String, FileIdentity)], now: SystemTime) -> bool {
    let Ok(now) = now.duration_since(UNIX_EPOCH) else {
        return false;
    };
    let now = now.as_nanos() as i128;
    members.iter().all(|(_, identity)| {
        [identity.mtime_ns, identity.ctime_ns]
            .into_iter()
            .all(|timestamp| now - timestamp > 2_000_000_000)
    })
}

/// One opened member, in the caller's original order.
pub struct MemberFile<'a> {
    pub relative_path: &'a Path,
    pub file: &'a mut File,
    pub size: u64,
}

fn key(domain: &'static [u8], root: &Path, members: &[(String, FileIdentity)]) -> Key {
    let mut hash = CanonicalHasher::new(b"bifrost-content-digest-listing:v1");
    for (path, identity) in members {
        hash.value(path.as_bytes());
        hash.value(&identity.device.to_be_bytes());
        hash.value(&identity.inode.to_be_bytes());
        hash.value(&identity.size.to_be_bytes());
        hash.value(&identity.mtime_ns.to_be_bytes());
        hash.value(&identity.ctime_ns.to_be_bytes());
    }
    Key {
        domain,
        root: root.to_owned(),
        member_count: members.len(),
        listing_digest: hash.finish(),
    }
}

/// At most 128 entries, each retaining one root path, a static domain reference,
/// a member count, a 32-byte listing hash and a 32-byte digest (plus cache overhead).
/// Member listings and file bytes are never retained across calls.
#[derive(Clone)]
pub struct ContentDigestCache {
    entries: BudgetRegion<Key, [u8; 32]>,
}

impl RetainedBytes for Key {
    fn retained_bytes(&self) -> usize {
        // The region retains key copies for lookup and registration.
        2 * (std::mem::size_of::<Self>() + self.root.retained_bytes())
    }
}

impl ContentDigestCache {
    /// Create a budget-charged cache. Clone this cache to share its region;
    /// separate calls create separate regions charged to the same budget.
    pub fn new(budget: &RetentionBudget) -> Self {
        Self {
            entries: budget.region("core.content-digests", Some(128)),
        }
    }

    /// Stream one opened member at a time, unless trusted identities hit.
    ///
    /// The digest must be a function of the domain, the member paths in the
    /// given order and their bytes, because a hit returns it without running
    /// the algorithm. The domain names the algorithm, including its ordering
    /// rules. `init` is a plain function of the member count, so the initial
    /// state cannot carry other inputs; `member` and `finish` may count calls
    /// but must not mix anything else into the digest.
    ///
    /// Where the platform supplies file identity, a member whose identity
    /// changes while it is read is an error, and so is a member listing that
    /// differs between the start and the end of the read: the bytes hashed may
    /// never have existed together. Detection has limits: there is no identity
    /// on Windows, a listing exists only on trusted file systems and outside
    /// the racy window, and a
    /// same-size rewrite within one timestamp tick keeps its identity. Such
    /// reads are never cached, so the returned digest can still describe bytes
    /// that never existed together. A caller that binds content must re-check
    /// it where the bytes are used, as capture does against a pinned digest.
    pub fn digest<S>(
        &self,
        domain: &'static [u8],
        root: &Path,
        members: &[PathBuf],
        init: fn(usize) -> S,
        mut member: impl FnMut(&mut S, MemberFile<'_>) -> std::io::Result<()>,
        finish: impl FnOnce(S) -> [u8; 32],
    ) -> std::io::Result<[u8; 32]> {
        let start = SystemTime::now();
        let canonical = root.canonicalize()?;
        let before = (root == canonical && on_trusted_local_file_system(root))
            .then(|| identities(root, members))
            .flatten()
            .filter(|listing| racy_clean(listing, start));
        let cache_key = before.as_ref().map(|listing| key(domain, root, listing));
        if let Some(key) = &cache_key
            && let Some(digest) = self.entries.get(key)
        {
            return Ok(*digest);
        }
        let mut state = init(members.len());
        for (index, path) in members.iter().enumerate() {
            let mut file = File::open(root.join(path))?;
            let metadata = file.metadata()?;
            let identity = file_identity(&metadata);
            // The listing names the file each path held at the start; a handle
            // that opened another file means the read crossed a change.
            if before
                .as_ref()
                .is_some_and(|listing| identity.as_ref() != Some(&listing[index].1))
            {
                return Err(std::io::Error::other(format!(
                    "{} changed before it was read",
                    root.join(path).display()
                )));
            }
            member(
                &mut state,
                MemberFile {
                    relative_path: path,
                    file: &mut file,
                    size: metadata.len(),
                },
            )?;
            if file_identity(&file.metadata()?) != identity {
                return Err(std::io::Error::other(format!(
                    "{} changed while it was read",
                    root.join(path).display()
                )));
            }
        }
        let digest = finish(state);
        let after = before.as_ref().map(|_| identities(root, members));
        if after
            .as_ref()
            .is_some_and(|after| after.as_ref() != before.as_ref())
        {
            return Err(std::io::Error::other(format!(
                "members of {} changed while they were read",
                root.display()
            )));
        }
        if before.is_some()
            && root.canonicalize()? == canonical
            && after.flatten().as_ref() == before.as_ref()
        {
            drop(
                self.entries
                    .insert(cache_key.expect("a listing gives a key"), digest),
            );
        }
        Ok(digest)
    }
}

#[cfg(test)]
mod metadata_identity_tests {
    use super::metadata_change_identity;
    use std::fs;

    #[test]
    fn metadata_identity_tracks_file_changes() -> std::io::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("jdk-module.jar");
        fs::write(&path, b"initial")?;
        let initial = metadata_change_identity(&path)?;
        assert_eq!(initial, metadata_change_identity(&path)?);

        assert!(initial.is_some());

        // Same size, different bytes and a later mtime: the identity changes on
        // every platform, including Windows, where only size and times exist.
        fs::write(&path, b"changed")?;
        let modified = fs::metadata(&path)?.modified()?;
        fs::File::options()
            .write(true)
            .open(&path)?
            .set_modified(modified + std::time::Duration::from_secs(10))?;
        let changed = metadata_change_identity(&path)?;
        assert!(changed.is_some());
        assert_ne!(initial, changed);
        assert_eq!(changed, metadata_change_identity(&path)?);
        Ok(())
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::fs::{self, FileTimes};
    use std::time::Duration;

    #[test]
    fn identity_cache_invalidation_and_trust() -> std::io::Result<()> {
        let dir = tempfile::tempdir()?;
        let trusted = on_trusted_local_file_system(dir.path());
        let cache = ContentDigestCache::new(&RetentionBudget::new(1_000_000));
        let a = PathBuf::from("a");
        let b = PathBuf::from("b");
        fs::write(dir.path().join(&a), b"old")?;
        fs::write(dir.path().join(&b), b"two")?;
        let calls = Cell::new(0);
        let compute = |_: &mut (), _: MemberFile<'_>| Ok(());
        let digest = |domain, members: &[PathBuf]| {
            cache.digest(
                domain,
                dir.path(),
                members,
                |_| (),
                compute,
                |_| {
                    calls.set(calls.get() + 1);
                    [42; 32]
                },
            )
        };
        // Newly created files are racy even if their mtime is manually aged:
        // ctime must age too.
        let old = SystemTime::now() - Duration::from_secs(10);
        fs::File::open(dir.path().join(&a))?.set_times(FileTimes::new().set_modified(old))?;
        digest(b"one", std::slice::from_ref(&a))?;
        digest(b"one", std::slice::from_ref(&a))?;
        assert_eq!(calls.get(), 2);
        std::thread::sleep(Duration::from_millis(2100));
        digest(b"one", std::slice::from_ref(&a))?;
        digest(b"one", std::slice::from_ref(&a))?;
        if !trusted {
            assert_eq!(calls.get(), 4);
            return Ok(());
        }
        assert_eq!(calls.get(), 3);
        digest(b"two", std::slice::from_ref(&a))?;
        assert_eq!(calls.get(), 4);
        digest(b"one", &[a.clone(), b.clone()])?;
        assert_eq!(calls.get(), 5);
        digest(b"one", &[b.clone(), a.clone()])?;
        assert_eq!(calls.get(), 6, "caller order changes the key");
        digest(b"one", std::slice::from_ref(&b))?;
        assert_eq!(calls.get(), 7, "removing a member changes identity");
        let renamed = PathBuf::from("renamed");
        fs::rename(dir.path().join(&b), dir.path().join(&renamed))?;
        digest(b"one", std::slice::from_ref(&renamed))?;
        assert_eq!(calls.get(), 8);
        fs::write(dir.path().join(&a), b"new")?;
        fs::File::open(dir.path().join(&a))?.set_times(FileTimes::new().set_modified(old))?;
        digest(b"one", std::slice::from_ref(&a))?;
        assert_eq!(
            calls.get(),
            9,
            "ctime catches equal-size rewrite with restored mtime"
        );
        std::os::unix::fs::symlink(&a, dir.path().join("link"))?;
        for _ in 0..2 {
            digest(b"one", &[PathBuf::from("link")])?;
        }
        assert_eq!(calls.get(), 11);
        for _ in 0..2 {
            assert!(
                cache
                    .digest(
                        b"error",
                        dir.path(),
                        std::slice::from_ref(&a),
                        |_| (),
                        |_, _| Err(std::io::Error::other("compute failed")),
                        |_| [0; 32]
                    )
                    .is_err()
            );
        }
        digest(b"error", &[a])?;
        assert_eq!(calls.get(), 12);
        Ok(())
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#9559: path swaps must not change the bytes read by compute"
    )]
    fn swapped_intermediate_and_root_symlinks() -> std::io::Result<()> {
        use std::io::Read;
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir()?;
        let root = dir.path().canonicalize()?;
        for (name, bytes) in [("first", b"old"), ("second", b"new")] {
            fs::create_dir(root.join(name))?;
            fs::write(root.join(name).join("a"), bytes)?;
        }
        symlink("first", root.join("link"))?;
        std::thread::sleep(Duration::from_millis(2100));
        let cache = ContentDigestCache::new(&RetentionBudget::new(1_000_000));
        let members = [PathBuf::from("link/a")];
        // The handle keeps reading the file it opened, but the path now names
        // another file, so the read is refused rather than returned.
        let swapped = cache.digest(
            b"swap",
            &root,
            &members,
            |_| (),
            |_, opened| {
                fs::remove_file(root.join("link"))?;
                symlink("second", root.join("link"))?;
                let mut bytes = Vec::new();
                opened.file.read_to_end(&mut bytes)?;
                assert_eq!(bytes, b"old");
                Ok(())
            },
            |_| [1; 32],
        );
        // Only a trusted file system has the listing that exposes the swap;
        // elsewhere the read is an uncached best effort.
        if on_trusted_local_file_system(&root) {
            assert!(swapped.is_err(), "{swapped:?}");
        } else {
            assert_eq!(swapped?, [1; 32]);
        }
        assert_eq!(
            cache.digest(
                b"swap",
                &root,
                &members,
                |_| (),
                |_, opened| {
                    let mut bytes = Vec::new();
                    opened.file.read_to_end(&mut bytes)?;
                    assert_eq!(bytes, b"new");
                    Ok(())
                },
                |_| [2; 32]
            )?,
            [2; 32]
        );
        let linked_root = root.join("link");
        for _ in 0..2 {
            cache.digest(
                b"root",
                &linked_root,
                &[PathBuf::from("a")],
                |_| (),
                |_, _| Ok(()),
                |_| [3; 32],
            )?;
        }
        Ok(())
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#9559: fresh files cannot age into eligibility during compute"
    )]
    fn racy_before_long_compute() -> std::io::Result<()> {
        let dir = tempfile::tempdir()?;
        fs::write(dir.path().join("a"), b"fresh")?;
        let cache = ContentDigestCache::new(&RetentionBudget::new(1_000_000));
        let root = dir.path().canonicalize()?;
        let members = [PathBuf::from("a")];
        cache.digest(
            b"racy",
            &root,
            &members,
            |_| (),
            |_, _| {
                std::thread::sleep(Duration::from_millis(2100));
                Ok(())
            },
            |_| [1; 32],
        )?;
        assert_eq!(
            cache.digest(b"racy", &root, &members, |_| (), |_, _| Ok(()), |_| [2; 32])?,
            [2; 32]
        );
        Ok(())
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#9559: a member rewritten while it was read still produced a digest of bytes that never existed together"
    )]
    fn a_member_changed_during_its_read_is_an_error() -> std::io::Result<()> {
        let dir = tempfile::tempdir()?;
        let root = dir.path().canonicalize()?;
        fs::write(root.join("a"), b"before")?;
        let cache = ContentDigestCache::new(&RetentionBudget::new(1_000_000));
        let result = cache.digest(
            b"rewrite",
            &root,
            &[PathBuf::from("a")],
            |_| (),
            |_, _| {
                // Rewrite in place: same inode, new size and change time.
                fs::write(root.join("a"), b"after, and longer")?;
                Ok(())
            },
            |_| [7; 32],
        );
        assert!(result.is_err(), "{result:?}");
        Ok(())
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#9559: sorted cache keys reused an order-sensitive digest"
    )]
    fn caller_order_and_zero_budget() -> std::io::Result<()> {
        let dir = tempfile::tempdir()?;
        let root = dir.path().canonicalize()?;
        fs::write(root.join("a"), b"a")?;
        fs::write(root.join("b"), b"b")?;
        std::thread::sleep(Duration::from_millis(2100));
        let members = [PathBuf::from("a"), PathBuf::from("b")];
        for limit in [0, 1_000_000] {
            let budget = RetentionBudget::new(limit);
            let cache = ContentDigestCache::new(&budget);
            let calls = Cell::new(0);
            for paths in [members.clone(), [members[1].clone(), members[0].clone()]] {
                let expected = if paths[0] == Path::new("a") { 1 } else { 2 };
                let digest = cache.digest(
                    b"order",
                    &root,
                    &paths,
                    |_| Vec::new(),
                    |state, member| {
                        calls.set(calls.get() + 1);
                        state.push(member.relative_path.to_owned());
                        Ok(())
                    },
                    |state| {
                        if state[0] == Path::new("a") {
                            [1; 32]
                        } else {
                            [2; 32]
                        }
                    },
                )?;
                assert_eq!(digest, [expected; 32]);
            }
            assert_eq!(calls.get(), 4);
            if limit == 0 {
                for _ in 0..2 {
                    cache.digest(
                        b"order",
                        &root,
                        &members,
                        |_| (),
                        |_, _| {
                            calls.set(calls.get() + 1);
                            Ok(())
                        },
                        |_| [1; 32],
                    )?;
                }
                assert_eq!(calls.get(), 8);
                assert_eq!(budget.accounted_bytes(), 0);
            }
            let shared = cache.clone();
            assert_eq!(cache.entries.namespace(), shared.entries.namespace());
        }
        Ok(())
    }

    #[test]
    fn racy_boundary_and_clock_skew() {
        let identity = FileIdentity {
            device: 1,
            inode: 1,
            size: 0,
            mtime_ns: 0,
            ctime_ns: 0,
        };
        let mut members = vec![("a".to_owned(), identity)];
        assert!(!racy_clean(&members, UNIX_EPOCH + Duration::from_secs(2)));
        assert!(racy_clean(
            &members,
            UNIX_EPOCH + Duration::from_nanos(2_000_000_001)
        ));
        members[0].1.ctime_ns = 10_000_000_000;
        assert!(!racy_clean(&members, UNIX_EPOCH + Duration::from_secs(3)));
    }
}
