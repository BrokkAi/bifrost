//! Owner-budgeted exact file digests shared by external-artifact samplers.
use brokk_bifrost_core::content_digest::{
    FileIdentity, metadata_change_identity, open_file_identity, open_regular_file,
};
use brokk_bifrost_core::retention_budget::{BudgetRegion, RetainedBytes, RetentionBudget};
use std::fs::{File, Metadata};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Clone, PartialEq, Eq, Hash)]
struct Key(PathBuf, FileIdentity);
impl RetainedBytes for Key {
    fn retained_bytes(&self) -> usize {
        std::mem::size_of::<Self>() + self.0.capacity()
    }
}

/// Eviction only changes the cost of obtaining an answer.
pub struct ArtifactDigestMemo {
    entries: BudgetRegion<Key, [u8; 32]>,
    bytes_hashed: AtomicU64,
}
impl ArtifactDigestMemo {
    pub fn new(budget: &RetentionBudget) -> Self {
        Self {
            entries: budget.region("artifact-content-digests", None),
            bytes_hashed: AtomicU64::new(0),
        }
    }
    /// Cumulative artifact bytes streamed by this owner, including declined files.
    pub fn bytes_hashed(&self) -> u64 {
        self.bytes_hashed.load(Ordering::Relaxed)
    }
}

// ext2/3/4 may have old one-second inodes; XFS, Btrfs and OpenZFS encode
// nanoseconds. Use the conservative one-second bound for all four types.
// https://kernel.org/doc/html/latest/filesystems/ext4/inodes.html
// https://www.kernel.org/pub/linux/docs/man-pages/book/man-pages-6.06.pdf (inode(7))
// https://github.com/openzfs/zfs/blob/master/include/os/linux/zfs/sys/zfs_znode_impl.h (ZFS_TIME_ENCODE)
// Linux coarse timestamps tick once per jiffy; also include the running
// kernel's CLOCK_REALTIME_COARSE resolution rather than assuming CONFIG_HZ.
// https://www.kernel.org/doc/html/latest/filesystems/multigrain-ts.html
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn granularity(filesystem: u64) -> Option<i128> {
    matches!(
        filesystem,
        0xef53 | 0x5846_5342 | 0x9123_683e | 0x2fc1_2fc1 | 0x4846_5300
    )
    .then_some(1_000_000_000)
}

#[cfg(target_os = "linux")]
fn filesystem_type(path: &Path) -> Option<u64> {
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut stats = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: valid NUL-terminated path and writable output storage.
    if unsafe { libc::statfs(path.as_ptr(), stats.as_mut_ptr()) } != 0 {
        return None;
    }
    // SAFETY: successful statfs initialized stats.
    Some(unsafe { stats.assume_init() }.f_type as u64 & 0xffff_ffff)
}
#[cfg(target_os = "macos")]
fn filesystem_type(path: &Path) -> Option<u64> {
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut stats = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: valid NUL-terminated path and writable output storage.
    if unsafe { libc::statfs(path.as_ptr(), stats.as_mut_ptr()) } != 0 {
        return None;
    }
    // SAFETY: successful statfs initialized stats and its terminated type name.
    let stats = unsafe { stats.assume_init() };
    let name = unsafe { std::ffi::CStr::from_ptr(stats.f_fstypename.as_ptr()) };
    // HFS Plus stores seconds; APFS has no verified bound in this classifier.
    // https://developer.apple.com/library/archive/technotes/tn/tn1150.html
    (name.to_bytes() == b"hfs").then_some(0x4846_5300)
}
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn filesystem_type(_path: &Path) -> Option<u64> {
    None
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn old_enough(filesystem: Option<u64>, metadata: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Some(margin) = filesystem.and_then(granularity) else {
        return false;
    };
    #[cfg(target_os = "linux")]
    let margin = {
        let mut resolution = std::mem::MaybeUninit::<libc::timespec>::uninit();
        // SAFETY: writable timespec output storage.
        if unsafe { libc::clock_getres(libc::CLOCK_REALTIME_COARSE, resolution.as_mut_ptr()) } != 0
        {
            return false;
        }
        // SAFETY: successful clock_getres initialized resolution.
        let resolution = unsafe { resolution.assume_init() };
        margin.max(i128::from(resolution.tv_sec) * 1_000_000_000 + i128::from(resolution.tv_nsec))
    };
    // A freshly written file supplies a filesystem-issued bound. Never compare
    // server timestamps to SystemTime::now(). Different devices cannot certify
    // each other's clocks. Failure or a different-device TMPDIR means rehash.
    let Ok(mut marker) = tempfile::tempfile() else {
        return false;
    };
    use std::io::Write;
    if marker.write_all(b"digest-clock").is_err() {
        return false;
    }
    let Ok(clock) = marker.metadata() else {
        return false;
    };
    if clock.dev() != metadata.dev() {
        return false;
    }
    let bound = i128::from(clock.mtime()) * 1_000_000_000 + i128::from(clock.mtime_nsec());
    [
        i128::from(metadata.mtime()) * 1_000_000_000 + i128::from(metadata.mtime_nsec()),
        i128::from(metadata.ctime()) * 1_000_000_000 + i128::from(metadata.ctime_nsec()),
    ]
    .into_iter()
    .all(|time| bound - time > margin)
}
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn old_enough(_filesystem: Option<u64>, _metadata: &Metadata) -> bool {
    // No verified filesystem granularity classifier on these platforms yet.
    // In particular Windows std metadata does not provide change-time identity.
    false
}

/// Digest the exact buffer consumed by an artifact decoder. Callers on platforms
/// without a file change identity can read once and pass this same buffer to
/// their decoder, without relying on path or metadata equality. This path never
/// consults or populates the file digest memo.
pub fn digest_bytes(bytes: &[u8]) -> [u8; 32] {
    brokk_bifrost_core::analyzer::canonical_hash::sha256_bytes(bytes)
}

/// Hash an opened regular file, checking both the handle and current path on
/// either a hit or a miss. Unsupported identities are never memoized.
pub fn digest_file(
    memo: Option<&ArtifactDigestMemo>,
    path: &Path,
    hash: impl FnOnce(&mut File, u64) -> std::io::Result<[u8; 32]>,
) -> std::io::Result<[u8; 32]> {
    digest_on_filesystem(memo, path, filesystem_type(path), hash)
}

/// Independently verify file contents without consulting or admitting a memo
/// entry. Keep owner hash accounting and the same opened-file race checks.
pub fn rehash_file(
    memo: Option<&ArtifactDigestMemo>,
    path: &Path,
    hash: impl FnOnce(&mut File, u64) -> std::io::Result<[u8; 32]>,
) -> std::io::Result<[u8; 32]> {
    // No filesystem eligibility proof: always hash, never admit.
    digest_on_filesystem(memo, path, None, hash)
}

fn digest_on_filesystem(
    memo: Option<&ArtifactDigestMemo>,
    path: &Path,
    filesystem: Option<u64>,
    hash: impl FnOnce(&mut File, u64) -> std::io::Result<[u8; 32]>,
) -> std::io::Result<[u8; 32]> {
    let original_path = path;
    let path = path.canonicalize()?;
    let mut file = open_regular_file(&path)?;
    let metadata = file.metadata()?;
    // The identity comes from the opened handle, as on Windows.
    let before = Some(open_file_identity(&file)?);
    let key = before.clone().map(|identity| Key(path.clone(), identity));
    let eligible = memo.is_some() && old_enough(filesystem, &metadata);
    let cached = if eligible {
        key.as_ref()
            .and_then(|key| memo.and_then(|memo| memo.entries.get(key)))
    } else {
        None
    };
    let missed = cached.is_none();
    let digest = if let Some(cached) = cached {
        *cached
    } else {
        if let Some(memo) = memo {
            memo.bytes_hashed
                .fetch_add(metadata.len(), Ordering::Relaxed);
        }
        hash(&mut file, metadata.len())?
    };
    if before != metadata_change_identity(original_path)?
        || before != Some(open_file_identity(&file)?)
        || before != metadata_change_identity(&path)?
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "artifact changed while hashing",
        ));
    }
    if eligible
        && missed
        && let (Some(memo), Some(key)) = (memo, key)
    {
        memo.entries.insert(key, digest);
    }
    Ok(digest)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use brokk_bifrost_core::content_digest::file_identity;
    use sha2::{Digest, Sha256};
    use std::io::Read;
    fn hash(file: &mut File, _: u64) -> std::io::Result<[u8; 32]> {
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        Ok(Sha256::digest(&bytes).into())
    }

    #[brokk_bifrost_test_macros::hardwon(
        "#12745: every generation rehashed all dependency artifacts"
    )]
    #[test]
    fn content_memo_race_warm_and_eviction_boundary() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("dependency.jar");
        std::fs::write(&path, b"first").unwrap();
        let memo = ArtifactDigestMemo::new(&RetentionBudget::for_test_capacity(8 << 20));
        let first = digest_file(Some(&memo), &path, hash).unwrap();
        std::fs::write(&path, b"other").unwrap();
        let second = digest_file(Some(&memo), &path, hash).unwrap();
        assert_ne!(first, second);
        assert_eq!(memo.bytes_hashed(), 10);
        assert_eq!(digest_file(Some(&memo), &path, hash).unwrap(), second);
        assert_eq!(memo.bytes_hashed(), 15, "racy files must rehash");
        std::thread::sleep(std::time::Duration::from_millis(1100));
        let supported = old_enough(filesystem_type(&path), &std::fs::metadata(&path).unwrap());

        assert_eq!(digest_file(Some(&memo), &path, hash).unwrap(), second);
        let warm = memo.bytes_hashed();
        assert_eq!(digest_file(Some(&memo), &path, hash).unwrap(), second);
        assert_eq!(memo.bytes_hashed(), warm + if supported { 0 } else { 5 });
        std::fs::write(root.path().join("Unrelated.java"), b"class Unrelated {}").unwrap();
        assert_eq!(digest_file(Some(&memo), &path, hash).unwrap(), second);
        assert_eq!(
            memo.bytes_hashed(),
            warm + if supported { 0 } else { 10 },
            "unrelated edit hashes zero artifact bytes on admitted filesystems"
        );
        let evicted = ArtifactDigestMemo::new(&RetentionBudget::for_test_capacity(1));
        assert_eq!(digest_file(Some(&evicted), &path, hash).unwrap(), second);
        assert_eq!(digest_file(Some(&evicted), &path, hash).unwrap(), second);
        assert_eq!(evicted.bytes_hashed(), 10);
        std::fs::write(&path, b"other").unwrap();
        assert_eq!(
            digest_file(Some(&memo), &path, hash).unwrap(),
            second,
            "identical rewrite preserves content identity"
        );
    }

    #[test]
    fn unknown_filesystem_never_admits() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("dependency.jar");
        std::fs::write(&path, b"bytes").unwrap();
        let memo = ArtifactDigestMemo::new(&RetentionBudget::for_test_capacity(8 << 20));
        assert_eq!(granularity(0), None);
        let a = digest_on_filesystem(Some(&memo), &path, Some(0), hash).unwrap();
        let b = digest_on_filesystem(Some(&memo), &path, Some(0), hash).unwrap();
        assert_eq!(a, b);
        assert_eq!(memo.bytes_hashed(), 10);
        let key = Key(
            path.canonicalize().unwrap(),
            file_identity(&path).unwrap().unwrap(),
        );
        assert!(memo.entries.get(&key).is_none());
    }
}
