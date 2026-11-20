//! Bounded process-local content digests for immutable-looking local files.
use crate::analyzer::canonical_hash::CanonicalHasher;
use crate::retention_budget::{BudgetRegion, RetainedBytes, RetentionBudget};
use std::fs::File;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Stat exposes timestamp precision, not the filesystem update granularity.
/// Without a reported granularity, use the coarsest supported one (FAT: 2 s).
pub const FILE_TIMESTAMP_GRANULARITY: Duration = Duration::from_secs(2);

/// Windows returns `FILE_BASIC_INFO.ChangeTime == 0` when a filesystem or
/// server cannot report a change time. Converted to Unix nanoseconds that is
/// 1601-01-01, not zero.
const ABSENT_WINDOWS_CHANGE_TIME_NS: i128 = -116_444_736_000_000_000 * 100;

/// Open a regular file without blocking on Unix special files, including a
/// FIFO installed between the metadata check and open.
pub fn open_regular_file(path: &Path) -> std::io::Result<File> {
    let reject = || std::io::Error::new(std::io::ErrorKind::InvalidInput, "not a regular file");
    if !std::fs::metadata(path)?.is_file() {
        return Err(reject());
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(reject());
    }
    Ok(file)
}

/// Stat identity for a file or directory. Unix records device, inode, size,
/// mtime and ctime. Windows records volume serial, file index, size,
/// LastWriteTime and ChangeTime. Timestamps are nanoseconds since the Unix epoch,
/// at the precision kept by the filesystem.
///
/// Other platforms report size, the modification time and, where the platform
/// records it, the creation time in the ctime slot; device and inode are zero
/// there.
///
/// Timestamps are only as fine as the filesystem keeps them: FAT's 2 s
/// modification granularity can hide a same-size rewrite within that window,
/// an accepted limit shared with IntelliJ.
/// Directory timestamps can also miss transient ignore/config candidates. On
/// ZFS (statfs 0x2fc12fc1), kernel 7.0.0-42-generic, directory ctime stayed equal
/// in 46,817/50,000 stat-create-stat trials; full identity stayed equal in
/// 45,288/50,000 create-delete trials (#13309). Ignore-input receipts therefore
/// require a second agreeing listing when a pre-known proxy is racy. Two agreeing
/// observations are strong evidence, not proof: a writer that repeats the same
/// create-read-delete of the exact ignore/config filename, aligned with both
/// reads while absent at all four candidate stat points, can still certify.
/// That repeating, read-aligned writer is an accepted limit (#13309); the
/// confirmation is bounded to two listings, with no retry loop.
///
/// See "Where data lives" in `.agents/docs/architecture-and-analyzer-store.md`
/// for permitted uses.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FileIdentity {
    device: u64,
    pub(crate) inode: u64,
    size: u64,
    pub(crate) mtime_ns: i128,
    pub(crate) ctime_ns: i128,
}

impl FileIdentity {
    /// File object identity, excluding size and timestamps. Unix uses the
    /// device/inode pair; Windows uses volume serial/file index. Other
    /// platforms do not provide an object witness here. A zero index means the
    /// filesystem supplied none (some Windows volumes and network shares), so
    /// it is not an identity: two such files would otherwise compare equal.
    pub fn object_identity(&self) -> Option<(u64, u64)> {
        (cfg!(any(unix, windows)) && self.inode != 0).then_some((self.device, self.inode))
    }

    /// The device (Unix) or volume serial (Windows) holding the file. Unlike
    /// object_identity it stays available when the filesystem supplies no file
    /// index, so a move to another volume remains detectable.
    pub fn volume(&self) -> Option<u64> {
        cfg!(any(unix, windows)).then_some(self.device)
    }

    /// Whether either timestamp is at or after the caller's race cutoff,
    /// expressed in nanoseconds since the Unix epoch.
    pub fn racy(&self, cutoff: i128) -> bool {
        self.mtime_ns >= cutoff || self.ctime_ns >= cutoff
    }

    /// Whether this identity can hide a rewrite in the observation's timestamp
    /// tick. Use the time recorded before observing the digest's inputs, never
    /// the time of a later lookup, which would age a racy entry into trust.
    pub fn racy_at(&self, observed_at: SystemTime, granularity: Duration) -> bool {
        observed_at
            .duration_since(UNIX_EPOCH)
            .map_or(true, |observed| {
                self.racy(observed.as_nanos() as i128 - granularity.as_nanos() as i128)
            })
    }

    /// Stable binding for metadata-verified external inputs.
    pub fn digest(&self) -> [u8; 32] {
        let mut hash = CanonicalHasher::new(b"bifrost-file-metadata-binding-v1");
        hash.value(&self.device.to_be_bytes());
        hash.value(&self.inode.to_be_bytes());
        hash.value(&self.size.to_be_bytes());
        hash.value(&self.mtime_ns.to_be_bytes());
        hash.value(&self.ctime_ns.to_be_bytes());
        hash.finish()
    }
}

#[cfg(not(windows))]
fn metadata_identity(metadata: &std::fs::Metadata) -> std::io::Result<FileIdentity> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(FileIdentity {
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
        Ok(FileIdentity {
            device: 0,
            inode: 0,
            size: metadata.len(),
            mtime_ns: nanos_since_epoch(metadata.modified()?),
            ctime_ns: metadata.created().map_or(0, nanos_since_epoch),
        })
    }
}

#[cfg(windows)]
fn open_stat_file(path: &Path) -> std::io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS;
    // Backup semantics permits opening directories, and the default open
    // follows symlinks just like std::fs::metadata.
    File::options()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
}

/// Read an existing path's identity, including directories, following symlinks.
/// Missing directory entries return `Ok(None)`; errors reading an existing
/// entry's target (including dangling symlinks) are propagated.
pub fn stat_identity(path: &Path) -> std::io::Result<Option<FileIdentity>> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(link) if link.is_symlink() => std::fs::metadata(path)?,
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    #[cfg(not(windows))]
    {
        metadata_identity(&metadata).map(Some)
    }
    #[cfg(windows)]
    {
        // The metadata probe distinguishes an absent entry from an unreadable
        // symlink target; identity fields all come from the opened handle.
        let _ = metadata;
        open_stat_file(path)
            .and_then(|file| open_file_identity(&file))
            .map(Some)
    }
}

/// Read a regular file's identity, following symlinks. Non-regular files return
/// `Ok(None)`; errors, including missing paths, are propagated.
pub fn file_identity(path: &Path) -> std::io::Result<Option<FileIdentity>> {
    #[cfg(windows)]
    {
        let file = open_stat_file(path)?;
        if !file.metadata()?.is_file() {
            return Ok(None);
        }
        open_file_identity(&file).map(Some)
    }
    #[cfg(not(windows))]
    {
        let metadata = std::fs::metadata(path)?;
        if !metadata.is_file() {
            return Ok(None);
        }
        metadata_identity(&metadata).map(Some)
    }
}

/// Read the identity of an already open file or directory from its handle.
pub fn open_file_identity(file: &File) -> std::io::Result<FileIdentity> {
    #[cfg(not(windows))]
    {
        metadata_identity(&file.metadata()?)
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, FILE_BASIC_INFO, FileBasicInfo, GetFileInformationByHandle,
            GetFileInformationByHandleEx,
        };
        // SAFETY: these FFI output structures consist only of integer fields,
        // for which zero is a valid initial value.
        let mut basic: FILE_BASIC_INFO = unsafe { std::mem::zeroed() };
        // SAFETY: BY_HANDLE_FILE_INFORMATION also admits all-zero initialization.
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: both calls fill their documented output structures; file
        // keeps the borrowed handle alive throughout the calls.
        if unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle(),
                FileBasicInfo,
                (&mut basic as *mut FILE_BASIC_INFO).cast(),
                std::mem::size_of::<FILE_BASIC_INFO>() as u32,
            )
        } == 0
            // SAFETY: info is writable output storage and file owns the handle.
            || unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0
        {
            return Err(std::io::Error::last_os_error());
        }
        // ChangeTime catches ordinary mtime-preserving saves. SetFileTime
        // cannot restore it, though SetFileInformationByHandle(FileBasicInfo)
        // can deliberately restore every timestamp.
        const UNIX_EPOCH_FILETIME: i128 = 116_444_736_000_000_000;
        Ok(FileIdentity {
            device: u64::from(info.dwVolumeSerialNumber),
            inode: (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
            size: (u64::from(info.nFileSizeHigh) << 32) | u64::from(info.nFileSizeLow),
            mtime_ns: (i128::from(basic.LastWriteTime) - UNIX_EPOCH_FILETIME) * 100,
            ctime_ns: (i128::from(basic.ChangeTime) - UNIX_EPOCH_FILETIME) * 100,
        })
    }
}

/// Read a change-time identity suitable for guarding separately reopened artifact
/// decoders. A missing file index or change time cannot prove that the decoder
/// observed the sampled contents, so those return `Ok(None)` and callers must
/// refuse reuse. The identity is read from the opened handle.
pub fn artifact_change_identity(path: &Path) -> std::io::Result<Option<FileIdentity>> {
    let identity = open_file_identity(&open_regular_file(path)?)?;
    Ok(artifact_identity_is_strong(&identity).then_some(identity))
}

fn artifact_identity_is_strong(identity: &FileIdentity) -> bool {
    identity.inode != 0
        && identity.ctime_ns != 0
        && identity.ctime_ns != ABSENT_WINDOWS_CHANGE_TIME_NS
}

/// Read an identity for consumers that accept metadata-level change detection
/// on any filesystem and platform, including FUSE, overlayfs, network mounts
/// and Windows. A content change that leaves every identity field equal goes
/// unnoticed. `Ok(None)` means a non-regular file; treat it as changed.
/// IntelliJ CE uses this model for JDK modules (records size and
/// mtime in `JrtHandler.java:49-103`, reopens jars when size or mtime changes
/// in `ZipHandler.java:15-23, 44-58`, and compares timestamp and length during
/// refresh in `RefreshWorker.java:751-761`), without a trusted-filesystem
/// branch. The shared content-digest cache retains its trusted-filesystem
/// allowlist for every other consumer.
///
/// See "Where data lives" in `.agents/docs/architecture-and-analyzer-store.md`
/// for permitted uses.
pub fn metadata_change_identity(path: &Path) -> std::io::Result<Option<FileIdentity>> {
    file_identity(path)
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
        result.push((member.to_str()?.to_owned(), file_identity(&path).ok()??));
    }
    Some(result)
}

fn racy_clean(members: &[(String, FileIdentity)], observed_at: SystemTime) -> bool {
    members
        .iter()
        .all(|(_, identity)| !identity.racy_at(observed_at, FILE_TIMESTAMP_GRANULARITY))
}

/// One opened member, in the caller's original order.
pub struct MemberFile<'a> {
    pub relative_path: &'a Path,
    pub file: &'a mut File,
    pub size: u64,
}

/// Identifies a member whose metadata observation or admission failed.
#[derive(Debug)]
pub struct DigestMemberError {
    pub path: PathBuf,
    source: std::io::Error,
}

impl std::fmt::Display for DigestMemberError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.path.display(), self.source)
    }
}

impl std::error::Error for DigestMemberError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
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
/// a member count, a 32-byte listing hash, a 32-byte digest and its observation time (plus cache overhead).
/// Member listings and file bytes are never retained across calls.
#[derive(Clone)]
pub struct ContentDigestCache {
    entries: BudgetRegion<Key, DigestEntry>,
    verifications: BudgetRegion<Key, VerificationSuccess>,
    verification_locks: std::sync::Arc<
        std::sync::Mutex<std::collections::HashMap<Key, std::sync::Arc<std::sync::Mutex<()>>>>,
    >,
}

#[derive(Clone)]
struct DigestEntry {
    digest: [u8; 32],
    observed_at: SystemTime,
}

impl RetainedBytes for DigestEntry {
    fn retained_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
    }
}

struct Flight<'a> {
    locks:
        &'a std::sync::Mutex<std::collections::HashMap<Key, std::sync::Arc<std::sync::Mutex<()>>>>,
    key: Key,
    lock: std::sync::Arc<std::sync::Mutex<()>>,
}
impl Drop for Flight<'_> {
    fn drop(&mut self) {
        let mut locks = self.locks.lock().expect("verification map poisoned");
        // Keep the entry while other callers are waiting on this lock.
        if std::sync::Arc::strong_count(&self.lock) == 2 {
            locks.remove(&self.key);
        }
    }
}

#[derive(Clone)]
struct VerificationSuccess;

impl RetainedBytes for VerificationSuccess {
    fn retained_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
    }
}

fn trusted_observation(
    root: &Path,
    canonical: &Path,
    members: &[PathBuf],
    start: SystemTime,
) -> Option<Vec<(String, FileIdentity)>> {
    (root == canonical && on_trusted_local_file_system(root))
        .then(|| identities(root, members))
        .flatten()
        .filter(|listing| racy_clean(listing, start))
}

impl RetainedBytes for Key {
    fn retained_bytes(&self) -> usize {
        // The region's Arc-backed key is shared by lookup and registration.
        std::mem::size_of::<Self>() + crate::allocation_size::allocation_size(self.root.capacity())
    }
}

impl ContentDigestCache {
    /// Create a budget-charged cache. Clone this cache to share its region;
    /// separate calls create separate regions charged to the same budget.
    pub fn new(budget: &RetentionBudget) -> Self {
        Self {
            entries: budget.region("core.content-digests", Some(128)),
            verifications: budget.region("core.content-verifications", None),
            verification_locks: std::sync::Arc::new(std::sync::Mutex::new(
                std::collections::HashMap::new(),
            )),
        }
    }

    /// Verify immutable, owner-bound content without a filesystem observation.
    /// The binding must include a process-unique owner and every validity input.
    /// Only success is retained in the same budgeted region as file verification.
    pub fn verify_immutable_once<T, E>(
        &self,
        binding: [u8; 32],
        verify: impl FnOnce() -> Result<T, E>,
    ) -> Result<Option<T>, E> {
        let cache_key = Key {
            domain: b"verified-immutable-content-v1",
            root: PathBuf::new(),
            member_count: 0,
            listing_digest: binding,
        };
        self.with_key_lock(cache_key.clone(), || {
            if self.verifications.get(&cache_key).is_some() {
                return Ok(None);
            }
            let result = verify()?;
            drop(self.verifications.insert(cache_key, VerificationSuccess));
            Ok(Some(result))
        })
    }

    fn with_key_lock<T>(&self, cache_key: Key, operation: impl FnOnce() -> T) -> T {
        let flight = self.flight(cache_key);
        let _guard = flight
            .lock
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        operation()
    }

    fn flight(&self, cache_key: Key) -> Flight<'_> {
        {
            let mut locks = self
                .verification_locks
                .lock()
                .expect("verification map poisoned");
            Flight {
                locks: &self.verification_locks,
                key: cache_key.clone(),
                lock: locks.entry(cache_key.clone()).or_default().clone(),
            }
        }
    }

    /// Cache an immutable JDK selection on every filesystem by canonical home,
    /// ordered member names and the same FileIdentity used by observe_jdk,
    /// observed once at selection. Only identities older than the two-second
    /// timestamp window at observation can authorize reuse. Fresh identities
    /// can hide same-size rewrites within one timestamp tick, so their digests
    /// are returned without retention. Misses check opened handles and re-observe the
    /// root and members after hashing; a changed read fails without caching.
    /// Uncontended hits observe metadata once. After a contended flight wait,
    /// re-observe once before accepting a hit because the selection may have
    /// changed during the wait. A change fails without retrying.
    #[allow(clippy::too_many_arguments)] // Cancellation supplements the digest algorithm callbacks.
    pub fn digest_by_metadata<S>(
        &self,
        domain: &'static [u8],
        root: &Path,
        members: &[PathBuf],
        cancellation: Option<&crate::cancellation::CancellationToken>,
        validate_size: impl Fn(usize, u64) -> std::io::Result<()>,
        init: fn(usize) -> S,
        member: impl FnMut(&mut S, MemberFile<'_>) -> std::io::Result<()>,
        finish: impl FnOnce(S) -> [u8; 32],
    ) -> std::io::Result<[u8; 32]> {
        self.digest_by_metadata_at(
            domain,
            root,
            members,
            cancellation,
            validate_size,
            init,
            member,
            finish,
            SystemTime::now(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn digest_by_metadata_at<S>(
        &self,
        domain: &'static [u8],
        root: &Path,
        members: &[PathBuf],
        cancellation: Option<&crate::cancellation::CancellationToken>,
        validate_size: impl Fn(usize, u64) -> std::io::Result<()>,
        init: fn(usize) -> S,
        mut member: impl FnMut(&mut S, MemberFile<'_>) -> std::io::Result<()>,
        finish: impl FnOnce(S) -> [u8; 32],
        observed_at: SystemTime,
    ) -> std::io::Result<[u8; 32]> {
        // Take the cutoff before observing any member, never after a long read
        // or flight wait that could make a racy observation appear old.
        let canonical = root.canonicalize()?;
        let observe_listing = || -> std::io::Result<([u8; 32], Vec<FileIdentity>)> {
            let mut identities = Vec::with_capacity(members.len());
            let mut listing = CanonicalHasher::new(b"bifrost-jdk-metadata-listing:v1");
            for (index, path) in members.iter().enumerate() {
                let observation = || -> std::io::Result<FileIdentity> {
                    let identity =
                        metadata_change_identity(&canonical.join(path))?.ok_or_else(|| {
                            std::io::Error::other(format!(
                                "no regular-file metadata identity for {}",
                                canonical.join(path).display()
                            ))
                        })?;
                    validate_size(index, identity.size)?;
                    Ok(identity)
                };
                let identity = observation().map_err(|source| {
                    std::io::Error::new(
                        source.kind(),
                        DigestMemberError {
                            path: canonical.join(path),
                            source,
                        },
                    )
                })?;
                listing.value(path.as_os_str().as_encoded_bytes());
                listing.value(&identity.digest());
                identities.push(identity);
            }
            Ok((listing.finish(), identities))
        };
        let (listing_digest, identities) = observe_listing()?;
        let reusable_at = |time| {
            identities
                .iter()
                .all(|identity| !identity.racy_at(time, FILE_TIMESTAMP_GRANULARITY))
        };
        let cache_key = Key {
            domain,
            root: canonical.clone(),
            member_count: members.len(),
            listing_digest,
        };
        let unchanged = || -> std::io::Result<bool> {
            Ok(root.canonicalize()?.as_path() == canonical.as_path()
                && observe_listing()?.0 == cache_key.listing_digest)
        };
        let changed_error = || {
            std::io::Error::other(format!(
                "members of {} changed while they were read",
                root.display()
            ))
        };
        let flight = self.flight(cache_key.clone());
        let mut waited = false;
        let _guard = loop {
            if cancellation.is_some_and(|token| token.is_cancelled()) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "JDK digest wait cancelled",
                ));
            }
            match flight.lock.try_lock() {
                Ok(guard) => break guard,
                Err(std::sync::TryLockError::Poisoned(error)) => break error.into_inner(),
                Err(std::sync::TryLockError::WouldBlock) => {
                    waited = true;
                    // Existing verification flights have only a mutex, with no
                    // completion signal. Keep their blocking behavior unchanged.
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
            }
        };
        if cancellation.is_some_and(|token| token.is_cancelled()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "JDK digest wait cancelled",
            ));
        }
        if waited && !unchanged()? {
            return Err(changed_error());
        }
        {
            if let Some(entry) = self.entries.get(&cache_key)
                && reusable_at(entry.observed_at)
            {
                return Ok(entry.digest);
            }
            let mut stable = true;
            let mut opened_listing = CanonicalHasher::new(b"bifrost-jdk-metadata-listing:v1");
            let mut state = init(members.len());
            for path in members {
                let mut file = File::open(canonical.join(path))?;
                let metadata = file.metadata()?;
                let identity = metadata
                    .is_file()
                    .then(|| open_file_identity(&file))
                    .transpose()?;
                opened_listing.value(path.as_os_str().as_encoded_bytes());
                if let Some(identity) = &identity {
                    opened_listing.value(&identity.digest());
                } else {
                    stable = false;
                }
                member(
                    &mut state,
                    MemberFile {
                        relative_path: path,
                        file: &mut file,
                        size: metadata.len(),
                    },
                )?;
                let after = file.metadata()?;
                stable &= after
                    .is_file()
                    .then(|| open_file_identity(&file))
                    .transpose()?
                    == identity;
            }
            let digest = finish(state);
            stable &= opened_listing.finish() == cache_key.listing_digest;
            stable &= unchanged()?;
            if !stable {
                return Err(changed_error());
            }
            if reusable_at(observed_at) {
                drop(self.entries.insert(
                    cache_key,
                    DigestEntry {
                        digest,
                        observed_at,
                    },
                ));
            }
            Ok(digest)
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
    /// never have existed together. Detection has limits: a listing exists
    /// only on trusted file systems and outside the racy window, and a
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
        let before = trusted_observation(root, &canonical, members, start);
        let cache_key = before.as_ref().map(|listing| key(domain, root, listing));
        if let Some(key) = &cache_key
            && let Some(digest) = self.entries.get(key)
        {
            return Ok(digest.digest);
        }
        let mut state = init(members.len());
        for (index, path) in members.iter().enumerate() {
            let mut file = File::open(root.join(path))?;
            let metadata = file.metadata()?;
            let identity = metadata
                .is_file()
                .then(|| open_file_identity(&file))
                .transpose()?;
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
            // Keep size and identity from the same observation; the earlier
            // file-kind probe may precede a concurrent resize.
            member(
                &mut state,
                MemberFile {
                    relative_path: path,
                    file: &mut file,
                    size: identity
                        .as_ref()
                        .map_or(metadata.len(), |identity| identity.size),
                },
            )?;
            if file
                .metadata()?
                .is_file()
                .then(|| open_file_identity(&file))
                .transpose()?
                != identity
            {
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
            drop(self.entries.insert(
                cache_key.expect("a listing gives a key"),
                DigestEntry {
                    digest,
                    observed_at: start,
                },
            ));
        }
        Ok(digest)
    }
}

#[cfg(test)]
mod metadata_identity_tests {
    use super::{artifact_change_identity, metadata_change_identity};
    use std::fs;

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#14002: Windows reported every regular artifact's change identity as weak"
    )]
    fn artifact_change_identity_accepts_a_regular_file() -> std::io::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("artifact.jar");
        fs::write(&path, b"artifact")?;
        assert!(artifact_change_identity(&path)?.is_some());
        Ok(())
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#14002: Windows mapped an absent ChangeTime to a nonzero 1601 epoch"
    )]
    fn artifact_identity_rejects_an_absent_windows_change_time() {
        let identity = super::FileIdentity {
            device: 1,
            inode: 1,
            size: 1,
            mtime_ns: 1,
            ctime_ns: super::ABSENT_WINDOWS_CHANGE_TIME_NS,
        };
        assert!(!super::artifact_identity_is_strong(&identity));
    }

    #[cfg(windows)]
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#12975: a same-size Windows rewrite with restored mtime kept the artifact identity"
    )]
    fn artifact_change_identity_catches_a_windows_rewrite_with_restored_mtime()
    -> std::io::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("artifact.jar");
        fs::write(&path, b"first")?;
        let before = artifact_change_identity(&path)?.expect("a regular file has an identity");
        let modified = fs::metadata(&path)?.modified()?;
        std::thread::sleep(std::time::Duration::from_millis(1100));
        fs::write(&path, b"other")?;
        fs::File::options()
            .write(true)
            .open(&path)?
            .set_times(fs::FileTimes::new().set_modified(modified))?;
        let rewritten = fs::metadata(&path)?;
        assert_eq!(rewritten.len(), 5);
        assert_eq!(rewritten.modified()?, modified);
        let after = artifact_change_identity(&path)?.expect("a regular file has an identity");
        assert_ne!(before, after);
        Ok(())
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#12097: unchanged JDK files on overlay and FUSE were hashed again on every selection"
    )]
    fn metadata_digest_reuses_old_files_and_invalidates() -> std::io::Result<()> {
        use super::{ContentDigestCache, MemberFile};
        use crate::retention_budget::RetentionBudget;
        use std::{cell::Cell, path::PathBuf, time::Duration};
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("java.base.jmod");
        fs::write(&path, b"initial")?;
        let cache = ContentDigestCache::new(&RetentionBudget::for_test_capacity(1_000_000));
        let calls = Cell::new(0);
        let observed_at = std::time::SystemTime::now() + Duration::from_secs(60);
        let digest = |members: &[PathBuf]| {
            cache.digest_by_metadata_at(
                b"jdk-test",
                dir.path(),
                members,
                None,
                |_, _| Ok(()),
                |_| (),
                |_, _: MemberFile<'_>| Ok(()),
                |_| {
                    calls.set(calls.get() + 1);
                    [calls.get(); 32]
                },
                observed_at,
            )
        };
        let members = [PathBuf::from("java.base.jmod")];
        assert_eq!(digest(&members)?, [1; 32]);
        assert_eq!(digest(&members)?, [1; 32]);
        // A cached identity must still satisfy this selection's admitted sizes.
        let refused = cache.digest_by_metadata_at(
            b"jdk-test",
            dir.path(),
            &members,
            None,
            |_, size| {
                if size != 1 {
                    return Err(std::io::Error::other("preflight size changed"));
                }
                Ok(())
            },
            |_| (),
            |_, _| panic!("cached digest must not hash"),
            |_| [99; 32],
            observed_at,
        );
        assert!(refused.is_err(), "cache hit must check admitted sizes");
        let missing = cache
            .digest_by_metadata_at(
                b"jdk-test",
                dir.path(),
                &[members[0].clone(), PathBuf::from("missing.jmod")],
                None,
                |_, _| Ok(()),
                |_| (),
                |_, _| panic!("observation must fail first"),
                |_| [99; 32],
                observed_at,
            )
            .expect_err("second member is absent");
        let member = missing
            .get_ref()
            .unwrap()
            .downcast_ref::<super::DigestMemberError>()
            .unwrap();
        assert_eq!(member.path, dir.path().canonicalize()?.join("missing.jmod"));

        let modified = fs::metadata(&path)?.modified()?;
        fs::File::options()
            .write(true)
            .open(&path)?
            .set_modified(modified + Duration::from_secs(10))?;
        assert_eq!(digest(&members)?, [2; 32]);
        fs::write(&path, b"different size")?;
        assert_eq!(digest(&members)?, [3; 32]);
        assert_eq!(digest(&[])?, [4; 32]);
        assert_eq!(digest(&members)?, [3; 32]);
        #[cfg(unix)]
        {
            // Archive installation can replace an inode while restoring size
            // and mtime. The digest and observation must agree it changed.
            let before = metadata_change_identity(&path)?;
            let modified = fs::metadata(&path)?.modified()?;
            let replacement = dir.path().join("replacement");
            fs::write(&replacement, b"replaced bytes")?;
            fs::File::options()
                .write(true)
                .open(&replacement)?
                .set_modified(modified)?;
            fs::rename(&replacement, &path)?;
            assert_eq!(fs::metadata(&path)?.len(), 14);
            assert_eq!(fs::metadata(&path)?.modified()?, modified);
            assert_ne!(metadata_change_identity(&path)?, before);
            assert_eq!(digest(&members)?, [5; 32]);
            assert_eq!(digest(&members)?, [5; 32]);
        }
        Ok(())
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#12097: a replacement read was cached under the earlier member identity"
    )]
    fn metadata_digest_rejects_a_changed_read() -> std::io::Result<()> {
        use super::ContentDigestCache;
        use crate::retention_budget::RetentionBudget;
        use std::{io::Read, path::PathBuf};
        let dir = tempfile::tempdir()?;
        let first = dir.path().join("a");
        let second = dir.path().join("b");
        fs::write(&first, b"first")?;
        fs::write(&second, b"original")?;
        let budget = RetentionBudget::for_test_capacity(1_000_000);
        let cache = ContentDigestCache::new(&budget);
        let members = [PathBuf::from("a"), PathBuf::from("b")];
        let raced = cache.digest_by_metadata(
            b"replacement-race",
            dir.path(),
            &members,
            None,
            |_, _| Ok(()),
            |_| Vec::new(),
            |bytes, opened| {
                if opened.relative_path == members[0] {
                    // The callback runs after all key identities were read,
                    // but before the second member is opened and hashed.
                    fs::write(&second, b"replacement, longer")?;
                }
                opened.file.read_to_end(bytes)?;
                Ok(())
            },
            |bytes| {
                assert_eq!(bytes, b"firstreplacement, longer");
                [1; 32]
            },
        );
        assert!(
            raced.is_err(),
            "changed bytes must not become a pin: {raced:?}"
        );
        assert_eq!(
            budget.accounted_bytes(),
            0,
            "changed read must not be retained"
        );
        let mut reads = 0;
        assert_eq!(
            cache.digest_by_metadata(
                b"replacement-race",
                dir.path(),
                &members,
                None,
                |_, _| Ok(()),
                |_| (),
                |_, _| {
                    reads += 1;
                    Ok(())
                },
                |_| [2; 32],
            )?,
            [2; 32]
        );
        assert_eq!(reads, 2, "the next call recomputes");
        assert_eq!(
            cache.digest_by_metadata(
                b"replacement-race",
                dir.path(),
                &members,
                None,
                |_, _| Ok(()),
                |_| (),
                |_, _| Ok(()),
                |_| [3; 32],
            )?,
            [3; 32]
        );
        Ok(())
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#12097: a cancelled digest waiter blocked until the first hasher finished"
    )]
    fn metadata_digest_wait_is_cancellable() -> std::io::Result<()> {
        use super::ContentDigestCache;
        use crate::{cancellation::CancellationToken, retention_budget::RetentionBudget};
        use std::{
            path::PathBuf,
            sync::mpsc,
            time::{Duration, Instant},
        };
        let dir = tempfile::tempdir()?;
        fs::write(dir.path().join("a"), b"module")?;
        let cache = ContentDigestCache::new(&RetentionBudget::for_test_capacity(1_000_000));
        let members = [PathBuf::from("a")];
        let token = CancellationToken::new();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        std::thread::scope(|scope| {
            let cache = &cache;
            let root = dir.path();
            let members = &members;
            let first = scope.spawn(move || {
                cache.digest_by_metadata(
                    b"cancel-wait",
                    root,
                    members,
                    None,
                    |_, _| Ok(()),
                    |_| (),
                    |_, _| {
                        entered_tx.send(()).expect("signal first hasher");
                        release_rx.recv().expect("release first hasher");
                        Ok(())
                    },
                    |_| [42; 32],
                )
            });
            entered_rx
                .recv_timeout(Duration::from_secs(10))
                .expect("first hasher started");
            let cancellation = &token;
            let waiter = scope.spawn(move || {
                let result = cache.digest_by_metadata(
                    b"cancel-wait",
                    root,
                    members,
                    Some(cancellation),
                    |_, _| Ok(()),
                    |_| (),
                    |_, _| panic!("waiter must not hash"),
                    |_| [99; 32],
                );
                done_tx.send(result).expect("return waiter outcome");
            });
            let start = Instant::now();
            let waiting = loop {
                if cache
                    .verification_locks
                    .lock()
                    .expect("flight map")
                    .values()
                    .any(|lock| std::sync::Arc::strong_count(lock) == 3)
                {
                    break true;
                }
                if start.elapsed() > Duration::from_secs(10) {
                    break false;
                }
                std::thread::sleep(Duration::from_millis(1));
            };
            token.cancel();
            let cancelled = done_rx.recv_timeout(Duration::from_secs(2));
            // Always release before asserting, so a failing test cannot hang
            // the scoped threads by leaving the first hasher blocked.
            release_tx.send(()).expect("release first hasher");
            assert_eq!(first.join().expect("first hasher panicked")?, [42; 32]);
            waiter.join().expect("waiter panicked");
            assert!(waiting, "waiter did not join the existing flight");
            let error = cancelled
                .expect("cancelled waiter must finish before first hasher")
                .expect_err("cancelled waiter must not return a digest");
            assert_eq!(error.kind(), std::io::ErrorKind::Interrupted);
            Ok::<(), std::io::Error>(())
        })?;
        assert!(
            cache
                .verification_locks
                .lock()
                .expect("flight map")
                .is_empty()
        );
        assert_eq!(
            cache.digest_by_metadata(
                b"cancel-wait",
                dir.path(),
                &members,
                None,
                |_, _| Ok(()),
                |_| (),
                |_, _| Ok(()),
                |_| [42; 32],
            )?,
            [42; 32]
        );
        Ok(())
    }

    #[test]
    fn metadata_identity_tracks_file_changes() -> std::io::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("jdk-module.jar");
        fs::write(&path, b"initial")?;
        let initial = metadata_change_identity(&path)?;
        assert_eq!(initial, metadata_change_identity(&path)?);

        assert!(initial.is_some());

        // Same size, different bytes and a later mtime: the identity changes on
        // every platform, including Windows.
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
        let cache = ContentDigestCache::new(&RetentionBudget::for_test_capacity(1_000_000));
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
        let cache = ContentDigestCache::new(&RetentionBudget::for_test_capacity(1_000_000));
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
        let cache = ContentDigestCache::new(&RetentionBudget::for_test_capacity(1_000_000));
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
        let cache = ContentDigestCache::new(&RetentionBudget::for_test_capacity(1_000_000));
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
            let budget = RetentionBudget::for_test_capacity(limit);
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
