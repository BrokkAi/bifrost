//! Process-local stat receipts for the inputs applied by one listing.
use super::{IgnoreObservationError, IgnoreObservationOperation};
use crate::process::{BoundedProcessRequest, run_bounded_process};
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime};

#[derive(Debug, Clone, PartialEq, Eq)]
struct Identity {
    device: u64,
    inode: u64,
    size: u64,
    modified_ns: i128,
    changed_ns: i128,
}

impl Identity {
    fn racy(&self, cutoff: i128) -> bool {
        if self.changed_ns >= cutoff {
            return true;
        }
        self.modified_ns >= cutoff
    }
}

fn identity(path: &Path) -> io::Result<Option<Identity>> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(link) if link.is_symlink() => std::fs::metadata(path)?,
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(Some(Identity {
            changed_ns: i128::from(metadata.ctime()) * 1_000_000_000
                + i128::from(metadata.ctime_nsec()),
            device: metadata.dev(),
            inode: metadata.ino(),
            size: metadata.len(),
            modified_ns: i128::from(metadata.mtime()) * 1_000_000_000
                + i128::from(metadata.mtime_nsec()),
        }))
    }
    #[cfg(windows)]
    {
        use std::os::windows::{fs::OpenOptionsExt, io::AsRawHandle};
        use windows_sys::Win32::Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, FILE_BASIC_INFO, FILE_FLAG_BACKUP_SEMANTICS, FileBasicInfo,
            GetFileInformationByHandle, GetFileInformationByHandleEx,
        };
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(path)?;
        let mut basic: FILE_BASIC_INFO = unsafe { std::mem::zeroed() };
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        // Both calls fill their documented output structures; file keeps the
        // borrowed handle alive throughout the calls.
        if unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle(),
                FileBasicInfo,
                (&mut basic as *mut FILE_BASIC_INFO).cast(),
                std::mem::size_of::<FILE_BASIC_INFO>() as u32,
            )
        } == 0
            || unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0
        {
            return Err(io::Error::last_os_error());
        }
        // ChangeTime includes metadata/content changes, unlike LastWriteTime.
        // SetFileTime cannot set it; SetFileInformationByHandle(FileBasicInfo)
        // CAN set it. This detects ordinary mtime-preserving saves, not a tool
        // deliberately restoring every timestamp. See Microsoft's FILE_BASIC_INFO
        // and SetFileInformationByHandle documentation.
        Ok(Some(Identity {
            device: u64::from(info.dwVolumeSerialNumber),
            inode: (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
            size: metadata.len(),
            modified_ns: (i128::from(basic.LastWriteTime) - 116_444_736_000_000_000) * 100,
            changed_ns: (i128::from(basic.ChangeTime) - 116_444_736_000_000_000) * 100,
        }))
    }
}

#[derive(Debug, Default)]
pub(crate) struct IgnoreInputs {
    inputs: Vec<(PathBuf, Option<Identity>)>,
    discovered_proxies: BTreeSet<PathBuf>,
    // Only pre-known inputs have directory identities sampled before the walk.
    // Keys retain the requested proxy, values its nearest existing ancestor.
    pre_known_proxies: BTreeMap<PathBuf, (PathBuf, Identity)>,
    racy_pre_known_proxy: bool,
}

pub(crate) type InputReceipt = Result<Arc<IgnoreInputs>, IgnoreObservationError>;

impl IgnoreInputs {
    pub(crate) fn record(&mut self, path: PathBuf) -> io::Result<()> {
        let state = identity(&path)?;
        if let Some(parent) = path.parent() {
            self.discovered_proxies.insert(parent.to_path_buf());
        }
        self.inputs.push((path, state));
        Ok(())
    }

    fn record_pre_known(&mut self, path: PathBuf) -> io::Result<()> {
        let state = identity(&path)?;
        // Without a usable file identity retain the directory proxy. A symlink
        // anywhere in the path can be redirected while the reader runs and
        // restored before finish without changing the final file's identity,
        // so only a symlink-free path skips the proxy.
        //
        // Accepted limit: if the input's parent directory is renamed away,
        // replaced by a directory holding different rules while the reader
        // runs, and then renamed back before finish, the file keeps its
        // identity and path, so this certifies. Two stats cannot see that,
        // and the only signal is the parent's ctime, which for ~/.gitconfig
        // is HOME and moves on every unrelated file change there. The previous
        // parent-only rule had the same gap one directory level higher.
        let parent_proxy = state
            .as_ref()
            .is_none_or(|state| state.inode == 0 || state.changed_ns == 0)
            || std::fs::canonicalize(&path).map_or(true, |canonical| {
                !crate::path_normalization::is_canonical_spelling(&path, &canonical)
            });
        for component in path.ancestors() {
            if std::fs::symlink_metadata(component).is_ok_and(|metadata| metadata.is_symlink())
                && let Some(parent) = component.parent()
            {
                self.record_proxy(parent)?;
            }
        }
        if parent_proxy && let Some(parent) = path.parent() {
            self.record_proxy(parent)?;
        }
        self.inputs.push((path, state));
        Ok(())
    }

    fn record_proxy(&mut self, directory: &Path) -> io::Result<()> {
        if !self.pre_known_proxies.contains_key(directory) {
            let sampled = SystemTime::now();
            let proxy = existing_proxy(directory)?;
            self.racy_pre_known_proxy |= proxy.1.racy(racy_cutoff(sampled)?);
            self.pre_known_proxies
                .insert(directory.to_path_buf(), proxy);
        }
        Ok(())
    }

    pub(crate) fn needs_confirmation(&self) -> bool {
        self.racy_pre_known_proxy
    }

    pub(crate) fn same_inputs(&self, other: &Self) -> bool {
        // Parallel discovery order is not part of the receipt. Each receipt's
        // valid() has already checked every duplicate observation individually.
        self.inputs
            .iter()
            .map(|(path, state)| (path, state))
            .collect::<BTreeMap<_, _>>()
            == other
                .inputs
                .iter()
                .map(|(path, state)| (path, state))
                .collect::<BTreeMap<_, _>>()
    }

    pub(crate) fn valid(&self) -> io::Result<bool> {
        for (path, before) in &self.inputs {
            if &identity(path)? != before {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub(crate) fn finish(self, started: SystemTime) -> io::Result<Arc<Self>> {
        // Like Git's racy-index timestamp rule, an input newer than the
        // enumeration cannot certify what that enumeration read. Two seconds
        // also cover coarse filesystem timestamp granularity (e.g. FAT).
        let cutoff = racy_cutoff(started)?;
        for (path, state) in &self.inputs {
            if state.as_ref().is_some_and(|state| state.racy(cutoff)) {
                return Err(io::Error::other(format!(
                    "racy ignore input timestamp: {}",
                    path.display()
                )));
            }
        }
        for (directory, before) in &self.pre_known_proxies {
            if &existing_proxy(directory)? != before {
                return Err(io::Error::other(format!(
                    "ignore input directory changed during capture: {}",
                    directory.display()
                )));
            }
        }
        // Recent pre-known proxies need a second agreeing listing before reuse.
        // See the timestamp limitation and ZFS measurement beside FileIdentity
        // in content_digest.rs. valid() also re-stats absent candidates, so a
        // candidate that remains present cannot hide behind its proxy's mtime.
        // A file deleted after enumeration but before its first stat appears
        // absent twice. Its parent's mtime still exposes that race. Check only
        // during capture: unrelated directory churn after capture must never
        // invalidate the receipt. Churn inside this window costs at most one
        // extra re-list. Missing parent directories use their nearest existing
        // ancestor, whose mtime exposes creation/deletion of that directory.
        for directory in &self.discovered_proxies {
            let (candidate, state) = existing_proxy(directory)?;
            if state.racy(cutoff) {
                return Err(io::Error::other(format!(
                    "racy ignore input directory timestamp: {}",
                    candidate.display()
                )));
            }
        }
        // Includes absent candidates: creation/deletion during capture must
        // not be certified by the first stat alone.
        if !self.valid()? {
            return Err(io::Error::other(
                "ignore inputs changed during receipt capture",
            ));
        }
        Ok(Arc::new(self))
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            + self.pre_known_proxies.len() * std::mem::size_of::<(PathBuf, (PathBuf, Identity))>()
            + self.discovered_proxies.len() * std::mem::size_of::<PathBuf>()
            + self.inputs.capacity() * std::mem::size_of::<(PathBuf, Option<Identity>)>()
            + self
                .inputs
                .iter()
                .map(|(path, _)| path.capacity())
                .chain(self.discovered_proxies.iter().map(PathBuf::capacity))
                .chain(
                    self.pre_known_proxies
                        .iter()
                        .map(|(path, (ancestor, _))| path.capacity() + ancestor.capacity()),
                )
                .sum::<usize>()
    }
}

fn racy_cutoff(sampled: SystemTime) -> io::Result<i128> {
    Ok(sampled
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_nanos() as i128
        - 2_000_000_000)
}

// Use the same lookup both before and after the walk, including missing parents.
fn existing_proxy(mut candidate: &Path) -> io::Result<(PathBuf, Identity)> {
    loop {
        if let Some(state) = identity(candidate)? {
            #[cfg(test)]
            let state = COARSE_PROXY.with(|slot| {
                let mut state = state;
                if let Some((path, modified, changed)) = slot.borrow().as_ref()
                    && candidate == path
                {
                    state.modified_ns = *modified;
                    state.changed_ns = *changed;
                }
                state
            });
            return Ok((candidate.to_path_buf(), state));
        }
        candidate = candidate
            .parent()
            .ok_or_else(|| io::Error::other("ignore input has no existing parent directory"))?;
    }
}

// Model a filesystem tick deterministically, without relying on the host's
// timestamp granularity. Only directory proxy timestamps are projected; every
// candidate still uses the single real identity reader above.
#[cfg(test)]
thread_local! {
    static COARSE_PROXY: std::cell::RefCell<Option<(PathBuf, i128, i128)>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(crate) struct CoarseProxyGuard;

#[cfg(test)]
impl Drop for CoarseProxyGuard {
    fn drop(&mut self) {
        COARSE_PROXY.with(|slot| *slot.borrow_mut() = None);
    }
}

#[cfg(test)]
pub(crate) fn coarse_proxy_for_test(path: &Path) -> CoarseProxyGuard {
    let state = identity(path).unwrap().expect("fixture proxy exists");
    COARSE_PROXY.with(|slot| {
        assert!(slot.borrow().is_none(), "nested coarse proxy fixture");
        *slot.borrow_mut() = Some((path.to_path_buf(), state.modified_ns, state.changed_ns));
    });
    CoarseProxyGuard
}

pub(crate) fn unavailable(root: &Path, cause: impl Into<String>) -> IgnoreObservationError {
    IgnoreObservationError::new(
        root,
        IgnoreObservationOperation::Listing,
        io::Error::other(cause.into()),
    )
}

pub(crate) fn git(
    root: &Path,
    args: &[&str],
) -> Result<crate::process::BoundedProcessOutput, String> {
    run_bounded_process(
        &BoundedProcessRequest {
            program: "git".into(),
            args: args.iter().map(Into::into).collect(),
            env: vec![("GIT_OPTIONAL_LOCKS".into(), "0".into())],
            clear_env: false,
            cwd: root.to_path_buf(),
            stdin: None,
            timeout: Duration::from_secs(30),
            stdout_limit: usize::MAX,
            stderr_limit: usize::MAX,
            description: format!("git ignore inputs in {}", root.display()),
        },
        || false,
    )
}

pub(crate) fn supports_matching(root: &Path) -> bool {
    static SUPPORTED: OnceLock<bool> = OnceLock::new();
    *SUPPORTED.get_or_init(|| {
        let Ok(output) = git(root, &["--version"]) else {
            return false;
        };
        let version = String::from_utf8_lossy(&output.stdout);
        let mut parts = version
            .trim()
            .strip_prefix("git version ")
            .unwrap_or("")
            .split('.');
        let major = parts.next().and_then(|s| s.parse::<u32>().ok());
        let minor = parts.next().and_then(|s| s.parse::<u32>().ok());
        // --ignored=matching was introduced in Git 2.16:
        // https://github.com/git/git/blob/master/Documentation/RelNotes/2.16.0.adoc
        output.status.success() && major.zip(minor).is_some_and(|v| v >= (2, 16))
    })
}

fn home() -> io::Result<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .ok_or_else(|| io::Error::other("cannot resolve Git home directory"))
}

fn xdg() -> io::Result<PathBuf> {
    Ok(std::env::var_os("XDG_CONFIG_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or(home()?.join(".config")))
}

fn config_candidates(inputs: &mut IgnoreInputs, root: &Path) -> io::Result<()> {
    // Watch absent config candidates too: setting an initially unset key or
    // adding a higher-precedence definition must invalidate the receipt.
    match std::env::var_os("GIT_CONFIG_GLOBAL") {
        Some(path) => inputs.record_pre_known(PathBuf::from(path))?,
        None => {
            inputs.record_pre_known(home()?.join(".gitconfig"))?;
            inputs.record_pre_known(xdg()?.join("git/config"))?;
        }
    }
    if let Some(repo) = crate::gitblob::discover(root) {
        inputs.record_pre_known(repo.path().join("config"))?;
        inputs.record_pre_known(repo.commondir().join("config"))?;
        inputs.record_pre_known(repo.path().join("config.worktree"))?;
    }
    Ok(())
}

fn system_config(inputs: &mut IgnoreInputs, root: &Path) -> io::Result<()> {
    // Git itself reports its compiled system path, including nonexistent files:
    // https://git-scm.com/docs/git-var#Documentation/git-var.txt-GITCONFIGSYSTEM
    // Older Git without this variable cannot certify this input; never guess.
    if std::env::var_os("GIT_CONFIG_NOSYSTEM").is_some_and(|value| {
        !matches!(
            value.to_string_lossy().to_ascii_lowercase().as_str(),
            "" | "0" | "false" | "no" | "off"
        )
    }) {
        return Ok(());
    }
    let path = match std::env::var_os("GIT_CONFIG_SYSTEM") {
        Some(path) => PathBuf::from(path),
        None => {
            let output = git(root, &["var", "GIT_CONFIG_SYSTEM"]).map_err(io::Error::other)?;
            if !output.status.success() {
                return Err(io::Error::other("Git cannot report its system config path"));
            }
            let path = output.stdout.strip_suffix(b"\n").unwrap_or(&output.stdout);
            if path.is_empty() || path.contains(&b'\n') {
                return Err(io::Error::other("ambiguous Git system config path"));
            }
            crate::gitblob::bytes_to_path(path)
        }
    };
    inputs.record_pre_known(root.join(path))
}

pub(crate) fn git_pre_inputs(root: &Path) -> io::Result<IgnoreInputs> {
    let mut inputs = IgnoreInputs::default();
    let repo = crate::gitblob::discover(root)
        .ok_or_else(|| io::Error::other("Git repository disappeared"))?;
    let config_root = repo
        .workdir()
        .ok_or_else(|| io::Error::other("repository has no workdir"))?;
    inputs.record_pre_known(repo.commondir().join("info/exclude"))?;
    config_candidates(&mut inputs, root)?;
    system_config(&mut inputs, config_root)?;
    let config = git(
        config_root,
        &["config", "--null", "--show-origin", "--list"],
    )
    .map_err(io::Error::other)?;
    if !config.status.success() {
        return Err(io::Error::other("Git config input enumeration failed"));
    }
    let mut fields = config.stdout.split(|b| *b == 0);
    while let Some(origin) = fields.next().filter(|field| !field.is_empty()) {
        let entry = fields
            .next()
            .ok_or_else(|| io::Error::other("missing config entry"))?;
        // onbranch/hasconfig conditions depend on inputs beyond rule-file
        // stats. Do not certify that scope with an unconditional receipt.
        if entry.starts_with(b"includeif.") {
            return Err(io::Error::other(
                "conditional Git config input scope unavailable",
            ));
        }
        if let Some(path) = origin.strip_prefix(b"file:") {
            inputs.record_pre_known(config_root.join(crate::gitblob::bytes_to_path(path)))?;
        }
    }
    // Git expands ~ and %(prefix) for include path VALUES. Relative
    // includes are anchored at the config that declares them, not cwd.
    // Record inactive/missing include candidates too: their creation may
    // change a later config read. --list above records every loaded origin.
    let includes = git(
        config_root,
        &[
            "config",
            "--null",
            "--show-origin",
            "--path",
            "--get-regexp",
            r"^(include|includeif\..*)\.path$",
        ],
    )
    .map_err(io::Error::other)?;
    if includes.status.success() {
        let mut fields = includes.stdout.split(|b| *b == 0);
        while let Some(origin) = fields.next().filter(|field| !field.is_empty()) {
            let origin = origin
                .strip_prefix(b"file:")
                .ok_or_else(|| io::Error::other("non-file include origin"))?;
            let entry = fields
                .next()
                .ok_or_else(|| io::Error::other("missing include entry"))?;
            let value = entry
                .splitn(2, |byte| *byte == b'\n')
                .nth(1)
                .ok_or_else(|| io::Error::other("missing include path"))?;
            let origin = config_root.join(crate::gitblob::bytes_to_path(origin));
            inputs.record_pre_known(
                origin
                    .parent()
                    .expect("config file has a parent")
                    .join(crate::gitblob::bytes_to_path(value)),
            )?;
        }
    } else if includes.status.code() != Some(1) {
        return Err(io::Error::other("Git include input enumeration failed"));
    }
    let output = git(
        config_root,
        &[
            "config",
            "--null",
            "--show-origin",
            "--path",
            "--get",
            "core.excludesFile",
        ],
    )
    .map_err(io::Error::other)?;
    if output.status.code() == Some(1) && output.stdout.is_empty() {
        inputs.record_pre_known(xdg()?.join("git/ignore"))?;
    } else if output.status.success() {
        // -z makes both origin and value raw NUL-delimited paths.
        let mut fields = output.stdout.split(|b| *b == 0);
        let origin = fields
            .next()
            .and_then(|s| s.strip_prefix(b"file:"))
            .ok_or_else(|| io::Error::other("non-file core.excludesFile origin"))?;
        let value = fields
            .next()
            .ok_or_else(|| io::Error::other("missing core.excludesFile path"))?;
        inputs.record_pre_known(config_root.join(crate::gitblob::bytes_to_path(origin)))?;
        inputs.record_pre_known(config_root.join(crate::gitblob::bytes_to_path(value)))?;
    } else {
        return Err(io::Error::other(format!(
            "git config failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(inputs)
}

pub(crate) fn git_receipt(
    root: &Path,
    inputs: Result<IgnoreInputs, String>,
    directories: Result<BTreeSet<PathBuf>, String>,
    started: SystemTime,
) -> InputReceipt {
    inputs
        .map_err(io::Error::other)
        .and_then(|mut inputs| {
            for directory in directories.map_err(io::Error::other)? {
                inputs.record(directory.join(".gitignore"))?;
                inputs.record(directory.join(".bifrostignore"))?;
            }
            inputs.finish(started)
        })
        .map_err(|error| {
            IgnoreObservationError::new(root, IgnoreObservationOperation::Listing, error)
        })
}

// ignore 0.4.27 (Cargo.lock) applies .gitignore, optional .ignore,
// repository info/exclude and gitignore::gitconfig_excludes_path().
// Its global resolver reads HOME/.gitconfig and XDG_CONFIG_HOME/git/config,
// not the repository's core.excludesFile setting.
pub(crate) fn walk_globals(root: &Path, inputs: &mut IgnoreInputs) -> io::Result<()> {
    config_candidates(inputs, root)?;
    inputs.record_pre_known(home()?.join(".gitconfig"))?;
    inputs.record_pre_known(xdg()?.join("git/config"))?;
    if let Some(path) = ignore::gitignore::gitconfig_excludes_path() {
        inputs.record_pre_known(path)?;
    } else {
        return Err(io::Error::other("ignore crate global input unavailable"));
    }
    for directory in root.ancestors() {
        inputs.record_pre_known(directory.join(".gitignore"))?;
        inputs.record_pre_known(directory.join(".ignore"))?;
        inputs.record_pre_known(directory.join(".git/info/exclude"))?;
    }
    Ok(())
}
