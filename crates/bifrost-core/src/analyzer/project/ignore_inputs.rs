//! Process-local stat receipts for the inputs applied by one listing.
use crate::content_digest::{FileIdentity, stat_identity};
use crate::path_normalization::NormalizePath;
use crate::process::{BoundedProcessRequest, run_bounded_process};
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime};

#[derive(Debug, Clone, PartialEq, Eq)]
struct RepositorySelection {
    git_dir: PathBuf,
    common_dir: PathBuf,
    workdir: PathBuf,
}

impl RepositorySelection {
    fn capture(repo: &git2::Repository) -> io::Result<Self> {
        Ok(Self {
            git_dir: repo.path().to_path_buf().normalize(),
            common_dir: repo.commondir().to_path_buf().normalize(),
            workdir: repo
                .workdir()
                .ok_or_else(|| io::Error::other("repository has no workdir"))?
                .to_path_buf()
                .normalize(),
        })
    }

    #[cfg(feature = "test-support")]
    fn bytes(&self) -> usize {
        self.git_dir.capacity() + self.common_dir.capacity() + self.workdir.capacity()
    }
}

// Captured by the listing's own index reader, never by a second enumeration.
#[derive(Debug)]
pub(crate) struct IndexReceipt {
    selection: RepositorySelection,
    path: PathBuf,
    // Once published, this is a certifiable anchor for the membership digest.
    state: Mutex<Option<FileIdentity>>,
    digest: [u8; 32],
}

fn index_digest(index: &git2::Index) -> [u8; 32] {
    use crate::analyzer::canonical_hash::CanonicalHasher;
    let mut hash = CanonicalHasher::new(b"workspace-index-membership-v1");
    for entry in index.iter() {
        hash.value(&entry.path);
        hash.value(&entry.mode.to_le_bytes());
        // Stage and assume-unchanged; extended flags hold skip-worktree
        // and intent-to-add. The extended-presence bit is encoding only.
        hash.value(&(entry.flags & 0xb000).to_le_bytes());
        hash.value(&(entry.flags_extended & 0x6000).to_le_bytes());
    }
    hash.finish()
}

fn check_index_environment() -> io::Result<()> {
    if ["GIT_DIR", "GIT_INDEX_FILE"]
        .iter()
        .any(|key| std::env::var_os(key).is_some())
    {
        return Err(structural("Git index environment override"));
    }
    Ok(())
}

pub(crate) fn read_listing_index(
    repo: &git2::Repository,
) -> Result<(git2::Index, io::Result<IndexReceipt>), git2::Error> {
    let mut index = repo.index()?;
    let path = index.path().map(Path::to_path_buf);
    let before = path.as_deref().map(index_identity).transpose();
    index.read(true)?;
    let receipt = (|| {
        check_index_environment()?;
        let path = path.ok_or_else(|| structural("index path unavailable"))?;
        let before = before.map_err(structural)?.flatten();
        let digest = index_digest(&index);
        if index_identity(&path).map_err(structural)? != before {
            return Err(io::Error::other("index changed during listing read"));
        }
        Ok(IndexReceipt {
            selection: RepositorySelection::capture(repo)?,
            path,
            state: Mutex::new(before),
            digest,
        })
    })();
    Ok((index, receipt))
}

impl IndexReceipt {
    pub(super) fn for_repository(self, repo: &git2::Repository) -> io::Result<Self> {
        // The listing reader reopens the gitdir. Its workdir/common-dir must
        // still describe the outer collector's pathspec and rendering root.
        if self.selection != RepositorySelection::capture(repo)? {
            return Err(io::Error::other(
                "repository selection changed between listing discovery and index capture",
            ));
        }
        Ok(self)
    }

    fn valid(&self) -> io::Result<bool> {
        check_index_environment()?;
        let mut before = self.state.lock().expect("index receipt mutex poisoned");
        let current = index_identity(&self.path).map_err(structural)?;
        if current == *before {
            return Ok(true);
        }
        let observed_at = SystemTime::now();
        let repo = git2::Repository::open(&self.selection.git_dir).map_err(structural)?;
        let (_, observed) = read_listing_index(&repo).map_err(structural)?;
        let observed = observed?;
        if observed.selection != self.selection
            || observed.path != self.path
            || observed.digest != self.digest
        {
            return Ok(false);
        }
        if *observed.state.lock().expect("index receipt mutex poisoned") != current {
            return Err(io::Error::other("index changed during receipt validation"));
        }
        // Equal membership can be used now because it was just reread. A
        // recent stat cannot anchor later fast-path acceptance: a same-tick
        // rewrite might preserve it. Retain the old anchor until a fresh read
        // observes a certifiable stat, rather than aging an unread digest.
        let cutoff = racy_cutoff(observed_at)?;
        if current.as_ref().is_none_or(|state| !state.racy(cutoff)) {
            *before = current;
        }
        Ok(true)
    }
}

fn index_identity(path: &Path) -> io::Result<Option<FileIdentity>> {
    let state = stat_identity(path)?;
    #[cfg(test)]
    let state = COARSE_INDEX.with(|slot| {
        state.map(|mut state| {
            if let Some((projected_path, modified, changed)) = slot.borrow().as_ref()
                && path == projected_path
            {
                state.mtime_ns = *modified;
                state.ctime_ns = *changed;
            }
            state
        })
    });
    Ok(state)
}

// Simulate the documented coarse-filesystem contract for a single index,
// preserving its real inode, size and contents. This does not assert that the
// host filesystem empirically aliases timestamps for regular-file rewrites.
#[cfg(test)]
thread_local! {
    static COARSE_INDEX: std::cell::RefCell<Option<(PathBuf, i128, i128)>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(crate) struct CoarseIndexGuard;

#[cfg(test)]
impl Drop for CoarseIndexGuard {
    fn drop(&mut self) {
        COARSE_INDEX.with(|slot| *slot.borrow_mut() = None);
    }
}

#[cfg(test)]
pub(crate) fn coarse_index_for_test(path: &Path) -> CoarseIndexGuard {
    let state = stat_identity(path).unwrap().expect("fixture index exists");
    COARSE_INDEX.with(|slot| {
        assert!(slot.borrow().is_none(), "nested coarse index fixture");
        *slot.borrow_mut() = Some((path.to_path_buf(), state.mtime_ns, state.ctime_ns));
    });
    CoarseIndexGuard
}

#[derive(Debug, Default)]
pub(crate) struct IgnoreInputs {
    inputs: Vec<(PathBuf, Option<FileIdentity>)>,
    index: Option<IndexReceipt>,
    selection: Option<RepositorySelection>,
    // Gitfile values are opaque: libgit2 canonicalizes aliases they contain.
    // Retain the requested root so warm reuse can re-establish selection.
    gitfile_discovery_root: Option<PathBuf>,
    discovered_proxies: BTreeSet<PathBuf>,
    // Only pre-known inputs have directory identities sampled before the walk.
    // Keys retain the requested proxy, values its nearest existing ancestor.
    pre_known_proxies: BTreeMap<PathBuf, (PathBuf, FileIdentity)>,
    racy_pre_known_proxy: bool,
    // `gitdir:` matches the repository realpath; `gitdir:./` also uses the
    // config origin's realpath. Retain duplicate observations to detect races.
    realpath_witnesses: Vec<(PathBuf, PathBuf)>,
}

// A missing reuse certificate does not mean listing or matcher acquisition failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InputReceiptCause {
    Transient,
    Structural,
}

#[derive(Debug)]
struct StructuralInputError(io::Error);
impl std::fmt::Display for StructuralInputError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
}
impl std::error::Error for StructuralInputError {}

fn structural(cause: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::other(StructuralInputError(io::Error::other(cause)))
}

#[derive(Debug, Clone)]
pub struct InputReceiptUnavailable {
    pub path: PathBuf,
    pub cause: Arc<io::Error>,
    pub(crate) kind: InputReceiptCause,
}

impl InputReceiptUnavailable {
    pub(crate) fn new(root: &Path, cause: io::Error) -> Self {
        let kind = if cause
            .get_ref()
            .is_some_and(|cause| cause.is::<StructuralInputError>())
        {
            InputReceiptCause::Structural
        } else {
            InputReceiptCause::Transient
        };
        Self {
            path: root.to_path_buf(),
            cause: Arc::new(cause),
            kind,
        }
    }
}

impl std::fmt::Display for InputReceiptUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ignore-input receipt for {}: {}",
            self.path.display(),
            self.cause
        )
    }
}

pub(crate) type InputReceipt = Result<Arc<IgnoreInputs>, InputReceiptUnavailable>;

impl IgnoreInputs {
    pub(crate) fn record(&mut self, path: PathBuf) -> io::Result<()> {
        // The Git listing canonicalizes its worktree, which leaves a verbatim
        // prefix on Windows. ProjectFile roots are normalized, so store the
        // same spelling or an explicit update cannot match this input.
        let path = path.normalize();
        let state = stat_identity(&path)?;
        if let Some(parent) = path.parent() {
            self.discovered_proxies.insert(parent.to_path_buf());
        }
        self.inputs.push((path, state));
        Ok(())
    }

    fn record_pre_known(&mut self, path: PathBuf) -> io::Result<()> {
        let state = stat_identity(&path)?;
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
            .is_none_or(|state| state.inode == 0 || state.ctime_ns == 0)
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

    fn record_realpath(&mut self, path: PathBuf) -> io::Result<()> {
        let canonical = normalized_realpath(&path)?;
        self.realpath_witnesses.push((path, canonical));
        Ok(())
    }

    /// Explicit updates to a recorded input invalidate the receipt even when
    /// the filesystem's stat identity has not moved yet.
    pub(crate) fn names_changed_input(
        &self,
        changed: &BTreeSet<crate::analyzer::ProjectFile>,
    ) -> bool {
        let paths = changed
            .iter()
            .map(|file| file.abs_path())
            .collect::<BTreeSet<_>>();
        self.inputs.iter().any(|(path, _)| paths.contains(path))
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
        self.selection == other.selection
            && self.gitfile_discovery_root == other.gitfile_discovery_root
            && self.realpath_witnesses.iter().collect::<BTreeSet<_>>()
                == other.realpath_witnesses.iter().collect::<BTreeSet<_>>()
            && self
                .inputs
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
            if &stat_identity(path)? != before {
                return Ok(false);
            }
        }
        for (path, expected) in &self.realpath_witnesses {
            if normalized_realpath(path).ok().as_ref() != Some(expected) {
                return Ok(false);
            }
        }
        if let Some(root) = &self.gitfile_discovery_root {
            // A regular .git file can contain a directory alias whose
            // retarget leaves the file and every old canonical input intact.
            // Only gitfile selections pay one warm libgit2 rediscovery; do it
            // before the index's unchanged-stat fast path can certify reuse.
            let current = RepositorySelection::capture(&discover_receipt_repository(root)?)?;
            if self.selection.as_ref() != Some(&current) {
                return Ok(false);
            }
        }
        match &self.index {
            Some(index) => index.valid(),
            None => Ok(true),
        }
    }

    #[cfg(all(test, unix))]
    pub(super) fn assert_recorded_file_identities_unchanged(&self) {
        for (path, state) in &self.inputs {
            assert_eq!(&stat_identity(path).unwrap(), state, "{}", path.display());
        }
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
        if let Some(index) = &self.index
            && index
                .state
                .lock()
                .expect("index receipt mutex poisoned")
                .as_ref()
                .is_some_and(|state| state.racy(cutoff))
        {
            return Err(io::Error::other(format!(
                "racy index timestamp: {}",
                index.path.display()
            )));
        }
        for (directory, before) in &self.pre_known_proxies {
            let after = existing_proxy(directory)?;
            if &after != before {
                return Err(io::Error::other(format!(
                    "ignore input directory changed during capture: {} (before {before:?}, after {after:?})",
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
            + self.pre_known_proxies.len()
                * std::mem::size_of::<(PathBuf, (PathBuf, FileIdentity))>()
            + self.discovered_proxies.len() * std::mem::size_of::<PathBuf>()
            + self.inputs.capacity() * std::mem::size_of::<(PathBuf, Option<FileIdentity>)>()
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
            + self
                .index
                .as_ref()
                .map_or(0, |index| index.path.capacity() + index.selection.bytes())
            + self
                .selection
                .as_ref()
                .map_or(0, RepositorySelection::bytes)
            + self
                .gitfile_discovery_root
                .as_ref()
                .map_or(0, PathBuf::capacity)
            + self.realpath_witnesses.capacity() * std::mem::size_of::<(PathBuf, PathBuf)>()
            + self
                .realpath_witnesses
                .iter()
                .map(|(path, expected)| path.capacity() + expected.capacity())
                .sum::<usize>()
    }
}

fn normalized_realpath(path: &Path) -> io::Result<PathBuf> {
    std::fs::canonicalize(path).map(NormalizePath::normalize)
}

fn racy_cutoff(sampled: SystemTime) -> io::Result<i128> {
    Ok(sampled
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_nanos() as i128
        - 2_000_000_000)
}

// Use the same lookup both before and after the walk, including missing parents.
fn existing_proxy(mut candidate: &Path) -> io::Result<(PathBuf, FileIdentity)> {
    loop {
        if let Some(state) = stat_identity(candidate)? {
            #[cfg(test)]
            let state = COARSE_PROXY.with(|slot| {
                // Model one filesystem tick: the proxy's complete sampled
                // identity did not move. Projecting only the timestamps missed
                // an NTFS directory size change when an entry moves the $I30
                // index out of its resident record.
                slot.borrow()
                    .as_ref()
                    .and_then(|(path, state)| {
                        (candidate == path.as_path()).then(|| (*state).clone())
                    })
                    .unwrap_or(state)
            });
            return Ok((candidate.to_path_buf(), state));
        }
        candidate = candidate
            .parent()
            .ok_or_else(|| io::Error::other("ignore input has no existing parent directory"))?;
    }
}

// Model a filesystem tick deterministically, without relying on the host's
// timestamp granularity. The whole directory proxy identity is projected;
// every candidate still uses the single real identity reader above.
#[cfg(test)]
thread_local! {
    static COARSE_PROXY: std::cell::RefCell<Option<(PathBuf, FileIdentity)>> = const { std::cell::RefCell::new(None) };
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
    let state = stat_identity(path).unwrap().expect("fixture proxy exists");
    COARSE_PROXY.with(|slot| {
        assert!(slot.borrow().is_none(), "nested coarse proxy fixture");
        *slot.borrow_mut() = Some((path.to_path_buf(), state));
    });
    CoarseProxyGuard
}

pub(crate) fn unavailable(root: &Path, cause: impl Into<String>) -> InputReceiptUnavailable {
    InputReceiptUnavailable::new(root, io::Error::other(cause.into()))
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
    Ok(xdg_for(&home()?))
}

fn xdg_for(home: &Path) -> PathBuf {
    std::env::var_os("XDG_CONFIG_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".config"))
}

fn config_candidates(inputs: &mut IgnoreInputs, repo: &git2::Repository) -> io::Result<()> {
    // Watch absent config candidates too: setting an initially unset key or
    // adding a higher-precedence definition must invalidate the receipt.
    match std::env::var_os("GIT_CONFIG_GLOBAL") {
        Some(path) => inputs.record_pre_known(PathBuf::from(path))?,
        None => {
            inputs.record_pre_known(home()?.join(".gitconfig"))?;
            inputs.record_pre_known(xdg()?.join("git/config"))?;
        }
    }
    inputs.record_pre_known(repo.path().join("config"))?;
    inputs.record_pre_known(repo.commondir().join("config"))?;
    inputs.record_pre_known(repo.path().join("config.worktree"))?;
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
                let message = format!(
                    "Git cannot report its system config path: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                );
                return Err(if output.status.code() == Some(128) {
                    structural(message)
                } else {
                    io::Error::other(message)
                });
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

/// `(origin, "key\nvalue")` pairs from `git config --null --show-origin --list`.
fn config_list(config_root: &Path) -> io::Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let config = git(
        config_root,
        &["config", "--null", "--show-origin", "--list"],
    )
    .map_err(io::Error::other)?;
    if !config.status.success() {
        let message = format!(
            "Git config input enumeration failed: {}",
            String::from_utf8_lossy(&config.stderr).trim()
        );
        return Err(if config.status.code() == Some(128) {
            structural(message)
        } else {
            io::Error::other(message)
        });
    }
    let mut entries = Vec::new();
    let mut fields = config.stdout.split(|b| *b == 0);
    while let Some(origin) = fields.next().filter(|field| !field.is_empty()) {
        let entry = fields
            .next()
            .ok_or_else(|| io::Error::other("missing config entry"))?;
        entries.push((origin.to_vec(), entry.to_vec()));
    }
    Ok(entries)
}

/// The condition text of an `includeif.<condition>.path` entry. Git lowercases
/// the section and variable but keeps the subsection verbatim.
fn includeif_condition(entry: &[u8]) -> Option<&[u8]> {
    let key = entry.split(|byte| *byte == b'\n').next()?;
    let rest = key.strip_prefix(b"includeif.")?;
    let split = rest.iter().rposition(|byte| *byte == b'.')?;
    (&rest[split + 1..] == b"path").then_some(&rest[..split])
}

fn record_includeif_inputs(
    inputs: &mut IgnoreInputs,
    config_root: &Path,
    config: &[(Vec<u8>, Vec<u8>)],
) -> io::Result<(bool, bool)> {
    let mut saw_gitdir = false;
    let mut saw_onbranch = false;
    for (origin, entry) in config {
        // Git evaluated every condition when it produced the list and the
        // include candidates are recorded whether or not they were active. A
        // condition's truth value can still change while every recorded file
        // stays the same, so certify only the kinds whose inputs are witnessed
        // here. Prefixes are case-sensitive, as in Git.
        let Some(condition) = includeif_condition(entry) else {
            continue;
        };
        if let Some(pattern) = condition
            .strip_prefix(b"gitdir:")
            .or_else(|| condition.strip_prefix(b"gitdir/i:"))
        {
            saw_gitdir = true;
            if pattern.first() == Some(&b'.')
                && pattern
                    .get(1)
                    .is_some_and(|separator| std::path::is_separator(char::from(*separator)))
            {
                // Git anchors ./ at the canonical config origin, even when
                // a symlink retarget preserves the config's file identity.
                let origin = origin
                    .strip_prefix(b"file:")
                    .ok_or_else(|| structural("non-file relative gitdir condition origin"))?;
                let path = config_root.join(crate::gitblob::bytes_to_path(origin));
                inputs.record_pre_known(path.clone())?;
                inputs.record_realpath(path)?;
            }
        } else if condition.starts_with(b"onbranch:") {
            saw_onbranch = true;
        } else {
            // The condition persists until the configuration changes, so the
            // cause is structural, not a race.
            return Err(structural(format!(
                "conditional Git config input scope unavailable: {:?}",
                String::from_utf8_lossy(condition)
            )));
        }
    }
    Ok((saw_gitdir, saw_onbranch))
}

fn reject_reference_symlink(path: &Path) -> io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_symlink() => Err(structural(format!(
            "onbranch filesystem-symlink reference: {}",
            path.display()
        ))),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(structural(error)),
    }
}

fn record_onbranch_inputs(inputs: &mut IgnoreInputs, repo: &git2::Repository) -> io::Result<()> {
    let head_path = repo.path().join("HEAD");
    // Git can interpret a filesystem link's spelling as a virtual ref name,
    // even when different spellings have the same canonical file and OID.
    // Refuse this unsupported representation before following even a dangling
    // link. Ordinary files keep witnesses for future file-to-link transitions.
    reject_reference_symlink(&head_path)?;
    inputs.record_pre_known(head_path.clone())?;
    inputs.record_realpath(head_path.clone())?;
    // Bind the representation check to the followed observations as well: a
    // symlink introduced after the first check must not become our witness.
    reject_reference_symlink(&head_path)?;
    let head = repo.find_reference("HEAD").map_err(structural)?;
    if head.symbolic_target_bytes().is_none() {
        return Ok(()); // Detached HEAD never matches onbranch.
    }
    let target = head
        .symbolic_target()
        .ok_or_else(|| structural("non-UTF-8 onbranch HEAD target"))?;
    if !target.starts_with("refs/heads/") || !git2::Reference::is_valid_name(target) {
        return Err(structural("unsupported onbranch HEAD reference namespace"));
    }
    // Branch refs are common-directory owned, including in linked worktrees.
    // Record the loose file even for packed/unborn branches: its creation or
    // conversion from an OID to another symbolic ref can change onbranch.
    let target_path = repo.commondir().join(target);
    reject_reference_symlink(&target_path)?;
    inputs.record_pre_known(target_path.clone())?;
    if target_path.try_exists()? {
        inputs.record_realpath(target_path.clone())?;
    } else {
        // Resolving an absent loose ref consults packed-refs, including for
        // unborn branches. A later malformed packed file changes Git's error
        // behavior; witness its content identity or absence as well.
        let packed = repo.commondir().join("packed-refs");
        inputs.record_pre_known(packed.clone())?;
        if packed.try_exists()? {
            inputs.record_realpath(packed)?;
        }
    }
    reject_reference_symlink(&target_path)?;
    match repo.find_reference(target) {
        Ok(reference) if reference.symbolic_target_bytes().is_some() => {
            Err(structural("onbranch HEAD has multiple symbolic references"))
        }
        Ok(_) => Ok(()),
        Err(error) if error.code() == git2::ErrorCode::NotFound => Ok(()),
        Err(error) => Err(structural(error)),
    }
}

fn discover_receipt_repository(root: &Path) -> io::Result<git2::Repository> {
    // Locating a repository and opening it fail for different reasons. A
    // repository that cannot be found is a capture race. Once found, a
    // repository that cannot be opened stays unusable until its configuration
    // is repaired: libgit2 reports an unreadable active include as an OS
    // "locked" error, not ErrorClass::Config.
    let git_dir = git2::Repository::discover_path(root, std::iter::empty::<&std::ffi::OsStr>())
        .map_err(|_| io::Error::other("Git repository disappeared"))?;
    match git2::Repository::open(&git_dir) {
        Ok(repo) if !repo.is_bare() => Ok(repo),
        Ok(_) => Err(io::Error::other("Git repository disappeared")),
        Err(error) if error.code() == git2::ErrorCode::NotFound => {
            Err(io::Error::other("Git repository disappeared"))
        }
        Err(error) => Err(structural(format!(
            "Git repository could not be opened: {error}"
        ))),
    }
}

pub(crate) fn git_pre_inputs(root: &Path) -> io::Result<IgnoreInputs> {
    let mut inputs = IgnoreInputs::default();
    // Keep the requested spelling: canonicalizing it first would lose a root
    // alias whose retarget changes the selected subtree within one repository.
    inputs.record_realpath(root.to_path_buf())?;
    let repo = discover_receipt_repository(root)?;
    let selection = RepositorySelection::capture(&repo)?;
    #[cfg(test)]
    super::AFTER_GIT_INPUT_REPOSITORY_DISCOVERY.with(|hook| {
        if let Some(hook) = hook.borrow_mut().take() {
            hook();
        }
    });
    let workspace_root = root.canonicalize()?.normalize();
    let repository_root = selection.workdir.canonicalize()?.normalize();
    if !workspace_root.starts_with(&repository_root) {
        return Err(io::Error::other(
            "repository selection changed during input capture",
        ));
    }
    // Sample selectors before refreshing libgit2 authority. Missing .git
    // candidates also witness creation of a nearer repository in a subtree.
    // Existing .git directories get only a canonical path witness, never a
    // directory identity whose index.lock churn would invalidate warm reuse.
    for directory in workspace_root.ancestors() {
        let selector = directory.join(".git");
        if !selector.is_dir() {
            inputs.record_pre_known(selector.clone())?;
            if selector.try_exists()? {
                inputs.gitfile_discovery_root = Some(root.to_path_buf());
            }
        }
        if selector.try_exists()? {
            inputs.record_realpath(selector)?;
        }
        if directory == repository_root {
            break;
        }
    }
    // commondir redirects shared refs/config; gitdir is a linked worktree's
    // backlink and can change the workdir while the private index stays put.
    for name in ["commondir", "gitdir"] {
        let selector = selection.git_dir.join(name);
        inputs.record_pre_known(selector.clone())?;
        if selector.try_exists()? {
            inputs.record_realpath(selector)?;
        }
    }
    config_candidates(&mut inputs, &repo)?;
    // Rediscover from the requested root, preserving nearest/nested discovery.
    // A later selector stat is not evidence for the first discovery. One
    // bounded consistency check refuses that mismatch instead of retrying.
    let repo = discover_receipt_repository(root)?;
    if RepositorySelection::capture(&repo)? != selection {
        return Err(io::Error::other(
            "repository selection changed during input capture",
        ));
    }
    inputs.selection = Some(selection);
    let config_root = repo
        .workdir()
        .ok_or_else(|| io::Error::other("repository has no workdir"))?;
    // These candidates are known before Git status reads them. Use the same
    // work-tree boundary as its directory census, including absent rules.
    for directory in workspace_root.ancestors() {
        inputs.record_pre_known(directory.join(".gitignore"))?;
        if directory == repository_root {
            break;
        }
    }
    inputs.record_pre_known(repo.commondir().join("info/exclude"))?;
    system_config(&mut inputs, config_root)?;
    let mut config = config_list(config_root)?;
    #[cfg(test)]
    super::AFTER_GIT_CONFIG_LIST.with(|hook| {
        if let Some(hook) = hook.borrow_mut().take() {
            hook();
        }
    });
    let (mut saw_gitdir, saw_onbranch) =
        record_includeif_inputs(&mut inputs, config_root, &config)?;
    if saw_onbranch {
        if repo.path().join("reftable").is_dir() || repo.commondir().join("reftable").is_dir() {
            return Err(structural(
                "onbranch conditional Git config with reftable ref storage",
            ));
        }
        // The worktree HEAD decides. Sample it before Git reads it again, so a
        // switch during capture cannot match the first listing's answer, and
        // re-classify in case the post-sample branch activates nested rules.
        // When no onbranch condition exists HEAD stays unrecorded and a branch
        // switch keeps the receipt valid.
        record_onbranch_inputs(&mut inputs, &repo)?;
        config = config_list(config_root)?;
        let (saw_gitdir_after, _) = record_includeif_inputs(&mut inputs, config_root, &config)?;
        saw_gitdir |= saw_gitdir_after;
    }
    if saw_gitdir {
        // The tested directory is Git's realpath of the repository directory.
        // A retargeted symlinked ancestor or a replaced directory changes it.
        inputs.record_realpath(repo.path().to_path_buf())?;
    }
    for (origin, _) in &config {
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
            let candidate = origin
                .parent()
                .expect("config file has a parent")
                .join(crate::gitblob::bytes_to_path(value));
            // Unreadable or non-file include targets (matched or not) persist
            // until repaired, so any non-NotFound open/read error is structural.
            match crate::content_digest::open_regular_file(&candidate).and_then(|mut file| {
                use std::io::Read;
                file.read(&mut [0u8; 1])
            }) {
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(structural(format!(
                        "unreadable Git config include {}: {error}",
                        candidate.display()
                    )));
                }
            }
            inputs.record_pre_known(candidate)?;
        }
    } else if includes.status.code() != Some(1) {
        let message = format!(
            "Git include input enumeration failed: {}",
            String::from_utf8_lossy(&includes.stderr).trim()
        );
        return Err(if includes.status.code() == Some(128) {
            structural(message)
        } else {
            io::Error::other(message)
        });
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
        let message = format!(
            "git config failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
        return Err(if output.status.code() == Some(128) {
            structural(message)
        } else {
            io::Error::other(message)
        });
    }
    // The condition closure must describe the origins sampled above. A
    // relative condition can activate nested conditions between enumeration
    // and sampling, even when hardlinked config files keep their identities.
    // Verify once rather than adopting an unsampled closure or retrying. This
    // bounded Git read is only for fresh gitdir captures, never warm valid().
    if saw_gitdir && config_list(config_root)? != config {
        return Err(io::Error::other("Git config inputs changed during capture"));
    }
    Ok(inputs)
}

pub(crate) fn git_receipt(
    root: &Path,
    inputs: io::Result<IgnoreInputs>,
    directories: Result<BTreeSet<PathBuf>, String>,
    started: SystemTime,
    index: io::Result<IndexReceipt>,
) -> InputReceipt {
    // Report the census and index causes before the pre-input result, so a
    // structural census or index failure is not hidden behind a transient
    // config failure. Each error keeps the cause set where it was produced.
    let build = || -> io::Result<Arc<IgnoreInputs>> {
        let directories = directories.map_err(structural)?;
        let index = index?;
        let mut inputs = inputs?;
        // The listing reader and the input producer discover independently.
        // Their complete selections must agree before this index can anchor
        // reuse, even when each owner's own observations were stable.
        if inputs.selection.as_ref() != Some(&index.selection) {
            return Err(io::Error::other(
                "repository selection changed between input and index capture",
            ));
        }
        inputs.index = Some(index);
        let workspace_root = root.canonicalize()?;
        for directory in directories {
            // The workspace-to-repository chain was sampled before status.
            // Do not reclassify those pre-known inputs as discovered: their
            // proxies use the unchanged confirmation rule instead.
            if !workspace_root.starts_with(&directory) {
                inputs.record(directory.join(".gitignore"))?;
            }
            // Unlike Git rules, analysis-only rules never apply above the
            // selected workspace, even inside a containing repository.
            if directory.starts_with(&workspace_root) {
                inputs.record(directory.join(".bifrostignore"))?;
            }
        }
        inputs.finish(started)
    };
    build().map_err(|error| InputReceiptUnavailable::new(root, error))
}

// ignore 0.4.27 (Cargo.lock) applies .gitignore, optional .ignore,
// repository info/exclude and gitignore::gitconfig_excludes_path().
// Its global resolver reads std::env::home_dir()/.gitconfig and
// XDG_CONFIG_HOME/git/config, not the repository's core.excludesFile setting.
// home_dir() is HOME on Unix but USERPROFILE on Windows, so record the files
// that resolver reads rather than the Git path's home() candidate.
pub(crate) fn walk_globals(root: &Path, inputs: &mut IgnoreInputs) -> io::Result<()> {
    inputs.record_pre_known(walk_home()?.join(".gitconfig"))?;
    inputs.record_pre_known(walk_xdg()?.join("git/config"))?;
    if let Some(path) = ignore::gitignore::gitconfig_excludes_path() {
        inputs.record_pre_known(path)?;
    } else {
        return Err(io::Error::other("ignore crate global input unavailable"));
    }
    // workspace_walk_builder disables parent layers and .ignore files. The
    // root rule is pre-known because it can change before the walk starts;
    // descendant rules are captured by the walk's directory observations.
    inputs.record_pre_known(root.join(".gitignore"))?;
    inputs.record_pre_known(root.join(".git/info/exclude"))?;
    Ok(())
}

// `ignore` resolves its global config and default excludes file from
// std::env::home_dir(). Use the same source here so the receipt covers what
// the walk reads; on Windows that is USERPROFILE, not HOME.
fn walk_home() -> io::Result<PathBuf> {
    std::env::home_dir().ok_or_else(|| io::Error::other("cannot resolve Git home directory"))
}

fn walk_xdg() -> io::Result<PathBuf> {
    Ok(xdg_for(&walk_home()?))
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;
    use crate::analyzer::ProjectFile;
    use brokk_bifrost_test_macros::hardwon;
    use std::collections::BTreeSet;

    #[test]
    #[hardwon("#14349: a verbatim recorded input did not match its normalized ProjectFile")]
    fn recorded_rule_input_matches_project_file_path_identity() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let path = root.join(".bifrostignore");
        std::fs::write(&path, "").unwrap();
        let mut inputs = IgnoreInputs::default();
        inputs.record(path).unwrap();
        assert!(
            inputs.names_changed_input(&BTreeSet::from([ProjectFile::new(root, ".bifrostignore")]))
        );
    }
}
