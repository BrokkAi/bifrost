//! Preparation owns all processes; updates and readers verify file and environment inputs.
use brokk_bifrost_core::{
    analyzer::{
        canonical_hash::CanonicalHasher, external_selection::*, outer_request::OuterRequest,
    },
    cancellation::CancellationToken,
    process::{BoundedProcessRequest, run_bounded_process},
};
use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

pub const RUST_TOOLCHAIN_CODE_DOMAIN: &[u8] = b"bifrost-rust-toolchain-observation:v1";
pub const RUST_TOOLCHAIN_ANSWER_CODEC: &[u8] = b"bifrost-rust-toolchain-answer:v1";
const POLICY: &[u8] = b"PATH:first-executable-must-be-absolute,canonical,outside-workspace:path-rustc,preparation-only-proxy-probe,live-stat-pins,strong-compiler-identity;-vV;--print,sysroot;inherit-env;RUSTUP_AUTO_INSTALL=0;timeout=10s;stdout=65536;stderr=65536";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Unavailable {
    WorkspaceToolchainPath,
    SelectorRead,
    InvalidSelector,
    NoRustc,
    NoRustup,
    CompilerRejected,
    InvalidOutput,
    ProcessFailure,
    Cancelled,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToolchainIdentity {
    pub release: String,
    pub channel: String,
    pub commit: String,
    pub host: String,
    pub target: Option<String>,
    pub sysroot: PathBuf,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ToolchainOutcome {
    Observed(ToolchainIdentity),
    Unavailable(Unavailable),
}
impl ToolchainOutcome {
    /// Binding requires the verified compiler release, channel and commit.
    pub fn matches_verified_release(
        &self,
        receipt: &brokk_bifrost_semantic::analyzer::semantic_model::VerifiedSysrootReceipt,
    ) -> bool {
        use brokk_bifrost_semantic::analyzer::semantic_model::RustToolchainChannel;
        let expected = &receipt.provenance.toolchain;
        let channel = match expected.channel {
            RustToolchainChannel::Stable => "stable",
            RustToolchainChannel::Beta => "beta",
            RustToolchainChannel::Nightly => "nightly",
        };
        matches!(self, Self::Observed(identity) if identity.release == expected.release
            && identity.channel == channel && !expected.commit.is_empty()
            && identity.commit == expected.commit)
    }
}
#[derive(Clone, Debug)]
pub struct PreparedToolchain {
    pub outcome: ToolchainOutcome,
    pub selector_digest: [u8; 32],
    pub answer_digest: [u8; 32],
    pub reusable: bool,
    pins: CompilerPins,
}
#[derive(Clone, Debug, Default)]
struct CompilerPins {
    compiler: Option<PathBuf>,
    toolchain_entry: Option<PathBuf>,
    selection_path: Option<PathBuf>,
}
#[derive(Clone)]
struct ToolchainState {
    publication: u64,
    // Update fast-path hint only; receipt validity is checked against live inputs.
    update_selector_digest: Option<[u8; 32]>,
    prepared: Option<Arc<PreparedToolchain>>,
}
pub struct ToolchainAuthority {
    root: PathBuf,
    project: Arc<dyn brokk_bifrost_core::analyzer::project::Project>,
    state: Mutex<ToolchainState>,
    #[cfg(test)]
    selector_paths: Option<std::ffi::OsString>,
    #[cfg(test)]
    selector_home: Option<PathBuf>,
}
impl Clone for ToolchainAuthority {
    fn clone(&self) -> Self {
        Self {
            root: self.root.clone(),
            project: self.project.clone(),
            state: Mutex::new(self.state.lock().expect("toolchain lock").clone()),
            #[cfg(test)]
            selector_paths: self.selector_paths.clone(),
            #[cfg(test)]
            selector_home: self.selector_home.clone(),
        }
    }
}
impl ToolchainAuthority {
    pub fn new(project: Arc<dyn brokk_bifrost_core::analyzer::project::Project>) -> Self {
        let root = project.root().to_owned();
        let update_selector_digest =
            selected_selectors(project.as_ref(), &CancellationToken::default())
                .ok()
                .map(|inputs| inputs.digest);
        Self {
            root,
            project,
            state: Mutex::new(ToolchainState {
                publication: 0,
                update_selector_digest,
                prepared: None,
            }),
            #[cfg(test)]
            selector_paths: None,
            #[cfg(test)]
            selector_home: None,
        }
    }
    pub fn clone_for_project(
        &self,
        project: Arc<dyn brokk_bifrost_core::analyzer::project::Project>,
    ) -> Self {
        let root = project.root().to_owned();
        let update_selector_digest =
            selected_selectors(project.as_ref(), &CancellationToken::default())
                .ok()
                .map(|inputs| inputs.digest);
        let prepared = if self.root == root {
            self.state.lock().expect("toolchain lock").prepared.clone()
        } else {
            None
        };
        Self {
            root,
            project,
            state: Mutex::new(ToolchainState {
                publication: 0,
                update_selector_digest,
                prepared,
            }),
            #[cfg(test)]
            selector_paths: self.selector_paths.clone(),
            #[cfg(test)]
            selector_home: self.selector_home.clone(),
        }
    }
    fn selector_inputs(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<SelectorInputs, SelectionRefused> {
        let paths = std::env::var_os("PATH");
        #[cfg(test)]
        let paths = self.selector_paths.clone().or(paths);
        let home = rustup_home(&self.root);
        #[cfg(test)]
        let home = self.selector_home.clone().or(home);
        selected_selectors_in_context(self.project.as_ref(), cancellation, paths, home)
    }
    pub fn prepared(&self) -> Option<Arc<PreparedToolchain>> {
        self.prepared_with_cancellation(&CancellationToken::default())
    }
    fn prepared_with_cancellation(
        &self,
        cancellation: &CancellationToken,
    ) -> Option<Arc<PreparedToolchain>> {
        let prepared = self
            .state
            .lock()
            .expect("toolchain lock")
            .prepared
            .clone()?;
        let inputs = self.selector_inputs(cancellation).ok()?;
        let digest = pinned_digest(inputs.digest, &prepared.pins).ok()?;
        (prepared.selector_digest == digest).then_some(prepared)
    }
    pub fn selectors_unchanged(&self) -> bool {
        let state = self.state.lock().expect("toolchain lock").clone();
        let Ok(inputs) = self.selector_inputs(&CancellationToken::default()) else {
            return false;
        };
        state.update_selector_digest == Some(inputs.digest)
            && state.prepared.as_ref().is_none_or(|prepared| {
                pinned_digest(inputs.digest, &prepared.pins).ok() == Some(prepared.selector_digest)
            })
    }
    /// Called only by dependency preparation and refresh, never by answer().
    pub fn refresh(&self, cancellation: &CancellationToken) {
        self.refresh_using(cancellation, |compiler| {
            observe(compiler, &self.root, cancellation)
        });
    }
    #[cfg(test)]
    fn refresh_with(&self, observe: impl FnOnce() -> ToolchainOutcome) {
        self.refresh_using(&CancellationToken::default(), |_| observe());
    }
    fn refresh_using(
        &self,
        cancellation: &CancellationToken,
        observe: impl FnOnce(&Path) -> ToolchainOutcome,
    ) {
        let initial_publication = self.state.lock().expect("toolchain lock").publication;
        let Ok(before) = self.selector_inputs(cancellation) else {
            return;
        };
        let mut pins = CompilerPins::default();
        let resolution = resolve_recorded_compiler(
            &self.root,
            before.compiler.clone(),
            cancellation,
            before.refusal.clone(),
            before.home.as_deref(),
            &mut pins,
        );
        pins.compiler = resolution.as_ref().ok().cloned();
        let Ok(digest) = pinned_digest(before.digest, &pins) else {
            return;
        };
        let mut candidate = None;
        match resolution {
            Ok(compiler) => self.prepare(&mut candidate, digest, None, || observe(&compiler)),
            Err(cause) => self.prepare(&mut candidate, digest, Some(cause), || {
                unreachable!("refusal cannot observe")
            }),
        }
        let candidate = candidate.as_mut().expect("prepare supplies a receipt");
        Arc::get_mut(candidate)
            .expect("unpublished receipt is unique")
            .pins = pins;
        let Ok(after) = self.selector_inputs(cancellation) else {
            return;
        };
        if pinned_digest(after.digest, &candidate.pins).ok() != Some(digest) {
            return;
        }
        // Optimistic publication: metadata reads never hold the state lock.
        loop {
            let current = self.state.lock().expect("toolchain lock").clone();
            let Ok(live) = self.selector_inputs(cancellation) else {
                return;
            };
            if pinned_digest(live.digest, &candidate.pins).ok() != Some(digest) {
                return;
            }
            let current_is_live = current.prepared.as_ref().is_some_and(|receipt| {
                pinned_digest(live.digest, &receipt.pins).ok() == Some(receipt.selector_digest)
            });
            let mut state = self.state.lock().expect("toolchain lock");
            if state.publication != current.publication {
                continue;
            }
            if current.publication != initial_publication && current_is_live {
                return;
            }
            state.update_selector_digest = Some(live.digest);
            state.prepared = Some(candidate.clone());
            state.publication = state
                .publication
                .checked_add(1)
                .expect("toolchain publication exhausted");
            return;
        }
    }

    fn prepare(
        &self,
        slot: &mut Option<Arc<PreparedToolchain>>,
        digest: [u8; 32],
        refusal: Option<Unavailable>,
        observe: impl FnOnce() -> ToolchainOutcome,
    ) {
        let outcome = match refusal {
            Some(cause) => ToolchainOutcome::Unavailable(cause),
            None => observe(),
        };
        let reusable = matches!(
            &outcome,
            ToolchainOutcome::Observed(_)
                | ToolchainOutcome::Unavailable(Unavailable::WorkspaceToolchainPath)
        );
        let mut hash = CanonicalHasher::new(RUST_TOOLCHAIN_ANSWER_CODEC);
        // Typed records are memory-only; this digest is not an opaque database value.
        match &outcome {
            ToolchainOutcome::Observed(identity) => {
                hash.value(b"observed");
                for value in [
                    &identity.release,
                    &identity.channel,
                    &identity.commit,
                    &identity.host,
                ] {
                    hash.value(value.as_bytes());
                }
                hash.value(identity.sysroot.as_os_str().as_encoded_bytes());
                match &identity.target {
                    Some(target) => {
                        hash.value(b"target");
                        hash.value(target.as_bytes());
                    }
                    None => hash.value(b"no-target"),
                }
            }
            ToolchainOutcome::Unavailable(cause) => {
                hash.value(b"unavailable");
                hash.value(&[match cause {
                    Unavailable::WorkspaceToolchainPath => 0,
                    Unavailable::SelectorRead => 1,
                    Unavailable::InvalidSelector => 2,
                    Unavailable::NoRustc => 3,
                    Unavailable::CompilerRejected => 4,
                    Unavailable::InvalidOutput => 5,
                    Unavailable::ProcessFailure => 6,
                    Unavailable::Cancelled => 7,
                    Unavailable::NoRustup => 8,
                }]);
            }
        }
        *slot = Some(Arc::new(PreparedToolchain {
            outcome,
            selector_digest: digest,
            answer_digest: hash.finish(),
            reusable,
            pins: CompilerPins::default(),
        }));
    }
}
impl ExternalSelectionAuthority for ToolchainAuthority {
    fn questions(&self) -> Vec<ExternalSelectionQuestion> {
        let mut hash = CanonicalHasher::new(RUST_TOOLCHAIN_CODE_DOMAIN);
        hash.value(self.root.as_os_str().as_encoded_bytes());
        hash.value(POLICY);
        vec![ExternalSelectionQuestion {
            kind: ExternalSelectionQuestionKind::RustToolchain,
            digest: hash.finish(),
            uncertified: false,
        }]
    }
    fn answer(
        &self,
        request: &OuterRequest,
        question: &ExternalSelectionQuestion,
        _: &SelectionRetry,
        cancellation: &CancellationToken,
    ) -> Result<Arc<VerifiedSelection>, SelectionRefused> {
        if cancellation.is_cancelled() {
            return Err(SelectionRefused::Cancelled);
        }
        if self.questions().first() != Some(question) {
            return Err(SelectionRefused::Stale);
        }
        request.external_selection(self.project.as_ref(), question.digest, || {
            let view_stamp = self.project.view_stamp();
            let prepared = self
                .prepared_with_cancellation(cancellation)
                .ok_or(SelectionRefused::Stale)?;
            if self.project.view_stamp() != view_stamp {
                return Err(SelectionRefused::Stale);
            }
            Ok(VerifiedSelection {
                question_digest: question.digest,
                answer_digest: prepared.answer_digest,
                certified: prepared.reusable && view_stamp.is_some(),
                view_stamp,
                complete: prepared.reusable,
                records: prepared,
            })
        })
    }
}
// Read the selected view and disk together: compiler observations can describe
// only views whose selector bytes and absences agree with the process's disk.
struct SelectorInputs {
    digest: [u8; 32],
    refusal: Option<Unavailable>,
    compiler: Result<PathBuf, Unavailable>,
    home: Option<PathBuf>,
}
fn selected_selectors(
    project: &dyn brokk_bifrost_core::analyzer::project::Project,
    cancellation: &CancellationToken,
) -> Result<SelectorInputs, SelectionRefused> {
    selected_selectors_in_context(
        project,
        cancellation,
        std::env::var_os("PATH"),
        rustup_home(project.root()),
    )
}
fn selected_selectors_in_context(
    project: &dyn brokk_bifrost_core::analyzer::project::Project,
    cancellation: &CancellationToken,
    paths: Option<std::ffi::OsString>,
    home: Option<PathBuf>,
) -> Result<SelectorInputs, SelectionRefused> {
    let mut consistent = true;
    let inputs = selectors_from(
        project.root(),
        std::env::var_os("RUSTUP_TOOLCHAIN"),
        home.clone(),
        |path| {
            let disk = std::fs::read(path);
            let Some(file) = project.file_by_abs_path_allow_missing(path) else {
                return disk;
            };
            let selected = project
                .read_file_snapshot(&file)
                .map(|snapshot| snapshot.bytes().to_vec());
            let agrees = match (&selected, &disk) {
                (Ok(selected), Ok(disk)) => selected == disk,
                (Err(selected), Err(disk)) => selected.kind() == disk.kind(),
                _ => false,
            };
            consistent &= agrees;
            selected
        },
    );
    if !consistent {
        return Err(SelectionRefused::Stale);
    }
    if cancellation.is_cancelled() {
        return Err(SelectionRefused::Cancelled);
    }
    let (digest, refusal) = inputs;
    let mut hash = CanonicalHasher::new(RUST_TOOLCHAIN_CODE_DOMAIN);
    hash.value(&digest);
    let compiler = rustc_in_paths(project.root(), paths)
        .and_then(|path| vetted_compiler_path(project.root(), &path));
    match &compiler {
        Ok(path) => {
            hash.value(path.as_os_str().as_encoded_bytes());
            hash_compiler_identity(path, &mut hash).map_err(|_| SelectionRefused::Stale)?;
        }
        Err(cause) => hash.value(format!("path-compiler-refused:{cause:?}").as_bytes()),
    }
    Ok(SelectorInputs {
        digest: hash.finish(),
        refusal,
        compiler,
        home,
    })
}

#[cfg(test)]
fn selectors_with_override(
    root: &Path,
    toolchain_override: Option<std::ffi::OsString>,
) -> ([u8; 32], Option<Unavailable>) {
    selectors_from(root, toolchain_override, rustup_home(root), |path| {
        std::fs::read(path)
    })
}
fn rustup_home(root: &Path) -> Option<PathBuf> {
    let home = std::env::var_os("RUSTUP_HOME")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME")
                .or_else(|| std::env::var_os("USERPROFILE"))
                .map(|h| PathBuf::from(h).join(".rustup"))
        });
    home.map(|home| {
        if home.is_absolute() {
            home
        } else {
            root.join(home)
        }
    })
}
fn pinned_digest(base: [u8; 32], pins: &CompilerPins) -> std::io::Result<[u8; 32]> {
    if pins.compiler.is_none() && pins.toolchain_entry.is_none() && pins.selection_path.is_none() {
        return Ok(base);
    }
    let mut hash = CanonicalHasher::new(RUST_TOOLCHAIN_CODE_DOMAIN);
    hash.value(&base);
    if let Some(path) = &pins.selection_path {
        let selected = path.canonicalize()?;
        if pins
            .compiler
            .as_ref()
            .is_some_and(|compiler| *compiler != selected)
        {
            return Err(std::io::Error::other("selected compiler link changed"));
        }
        hash.value(path.as_os_str().as_encoded_bytes());
        hash.value(selected.as_os_str().as_encoded_bytes());
    }
    if let Some(path) = &pins.compiler {
        hash.value(path.as_os_str().as_encoded_bytes());
        hash_compiler_identity(path, &mut hash)?;
    }
    if let Some(path) = &pins.toolchain_entry {
        hash.value(path.as_os_str().as_encoded_bytes());
        match std::fs::symlink_metadata(path) {
            Ok(metadata) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    for value in [
                        metadata.dev(),
                        metadata.ino(),
                        metadata.len(),
                        metadata.mtime() as u64,
                        metadata.mtime_nsec() as u64,
                        metadata.ctime() as u64,
                        metadata.ctime_nsec() as u64,
                    ] {
                        hash.value(&value.to_be_bytes());
                    }
                }
                #[cfg(not(unix))]
                {
                    hash.value(&metadata.len().to_be_bytes());
                    hash.value(
                        format!("{:?}:{:?}", metadata.modified()?, metadata.created().ok())
                            .as_bytes(),
                    );
                }
                hash.value(path.canonicalize()?.as_os_str().as_encoded_bytes());
                if metadata.file_type().is_symlink() {
                    hash.value(std::fs::read_link(path)?.as_os_str().as_encoded_bytes());
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                hash.value(b"absent-toolchain-entry")
            }
            Err(error) => return Err(error),
        }
    }
    Ok(hash.finish())
}
fn selectors_from(
    root: &Path,
    toolchain_override: Option<std::ffi::OsString>,
    home: Option<PathBuf>,
    mut read: impl FnMut(&Path) -> std::io::Result<Vec<u8>>,
) -> ([u8; 32], Option<Unavailable>) {
    let mut hash = CanonicalHasher::new(RUST_TOOLCHAIN_CODE_DOMAIN);
    let mut refusal = None;
    let mut files = Vec::new();
    for ancestor in root.ancestors() {
        let mut selected = None;
        for name in ["rust-toolchain", "rust-toolchain.toml"] {
            let path = ancestor.join(name);
            hash.value(path.as_os_str().as_encoded_bytes());
            match read(&path) {
                Ok(bytes) => {
                    hash.value(b"present");
                    hash.value(&bytes);
                    if selected.is_none() {
                        selected = Some(selector_validity(&bytes, name));
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => hash.value(b"absent"),
                Err(_) => {
                    hash.value(b"unreadable");
                    selected.get_or_insert(Some(Unavailable::SelectorRead));
                }
            }
        }
        files.push((ancestor, selected));
    }
    for name in [
        "PATH",
        "RUSTUP_TOOLCHAIN",
        "RUSTUP_HOME",
        "HOME",
        "USERPROFILE",
        "CARGO_BUILD_TARGET",
    ] {
        hash.value(name.as_bytes());
        match std::env::var_os(name) {
            Some(value) => {
                hash.value(b"present");
                hash.value(value.as_encoded_bytes());
            }
            None => hash.value(b"absent"),
        }
    }
    let mut settings = None;
    if let Some(home) = home {
        let home = if home.is_absolute() {
            home
        } else {
            root.join(home)
        };
        match read(&home.join("settings.toml")) {
            Ok(bytes) => {
                hash.value(&bytes);
                settings = match std::str::from_utf8(&bytes)
                    .ok()
                    .and_then(|s| s.parse::<toml::Value>().ok())
                {
                    Some(value) => Some(value),
                    None => {
                        refusal = Some(Unavailable::InvalidSelector);
                        None
                    }
                };
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => hash.value(b"absent"),
            Err(_) => refusal = Some(Unavailable::SelectorRead),
        }
    }
    if toolchain_override.is_some() {
        refusal = None;
    } else if refusal.is_none() {
        let overrides = settings
            .as_ref()
            .and_then(|s| s.get("overrides"))
            .and_then(toml::Value::as_table);
        for (ancestor, file) in files {
            // rustup walks toward the root; a directory override wins a tie.
            let canonical = ancestor
                .canonicalize()
                .unwrap_or_else(|_| ancestor.to_owned());
            if overrides.is_some_and(|o| o.contains_key(&canonical.to_string_lossy().to_string())) {
                break;
            }
            if let Some(result) = file {
                refusal = result;
                break;
            }
        }
    }
    if let Ok(path) = rustc_path(root) {
        hash.value(path.as_os_str().as_encoded_bytes());
    } else if refusal.is_none() {
        refusal = Some(Unavailable::NoRustc);
    }
    (hash.finish(), refusal)
}
fn selector_validity(bytes: &[u8], name: &str) -> Option<Unavailable> {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return Some(Unavailable::InvalidSelector);
    };
    match text.parse::<toml::Value>() {
        Ok(value) => {
            let Some(toolchain) = value.get("toolchain").and_then(toml::Value::as_table) else {
                return Some(Unavailable::InvalidSelector);
            };
            if toolchain.contains_key("path") {
                return Some(Unavailable::WorkspaceToolchainPath);
            }
            if toolchain.is_empty() {
                return Some(Unavailable::InvalidSelector);
            }
            None
        }
        Err(_)
            if name == "rust-toolchain"
                && text.trim().is_ascii()
                && !text.trim().is_empty()
                && text.split_whitespace().count() == 1
                && !text.trim().contains(['/', '\\']) =>
        {
            None
        }
        Err(_) => Some(Unavailable::InvalidSelector),
    }
}
fn rustc_path(root: &Path) -> Result<PathBuf, Unavailable> {
    rustc_in_paths(root, std::env::var_os("PATH"))
}
fn rustc_in_paths(root: &Path, paths: Option<std::ffi::OsString>) -> Result<PathBuf, Unavailable> {
    executable_in_paths(
        root,
        if cfg!(windows) { "rustc.exe" } else { "rustc" },
        paths,
    )
}
fn executable_in_paths(
    root: &Path,
    name: &str,
    paths: Option<std::ffi::OsString>,
) -> Result<PathBuf, Unavailable> {
    let canonical_root = root.canonicalize().map_err(|_| Unavailable::NoRustc)?;
    for entry in paths
        .into_iter()
        .flat_map(|paths| std::env::split_paths(&paths).collect::<Vec<_>>())
    {
        // Locate the executable before applying trust policy. Skipping an unsafe
        // match would describe a different compiler from the one PATH selects.
        let directory = if entry.is_absolute() {
            entry.clone()
        } else {
            root.join(&entry)
        };
        let path = directory.join(name);
        let metadata = match path.metadata() {
            Ok(metadata) => metadata,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                ) =>
            {
                continue;
            }
            Err(_) => return Err(Unavailable::NoRustc),
        };
        if !metadata.is_file() {
            continue;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o111 == 0 {
                continue;
            }
        }
        if !entry.is_absolute() {
            return Err(Unavailable::WorkspaceToolchainPath);
        }
        let directory = directory.canonicalize().map_err(|_| Unavailable::NoRustc)?;
        if directory.starts_with(&canonical_root) {
            return Err(Unavailable::WorkspaceToolchainPath);
        }
        vetted_compiler_path(&canonical_root, &path)?;
        return Ok(directory.join(name));
    }
    Err(Unavailable::NoRustc)
}

fn vetted_compiler_path(root: &Path, path: &Path) -> Result<PathBuf, Unavailable> {
    if !path.is_absolute() {
        return Err(Unavailable::NoRustc);
    }
    let root = root.canonicalize().map_err(|_| Unavailable::NoRustc)?;
    let path = path.canonicalize().map_err(|_| Unavailable::NoRustc)?;
    if path.starts_with(root) {
        return Err(Unavailable::WorkspaceToolchainPath);
    }
    let metadata = path.metadata().map_err(|_| Unavailable::NoRustc)?;
    if !metadata.is_file() {
        return Err(Unavailable::NoRustc);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o111 == 0 {
            return Err(Unavailable::NoRustc);
        }
    }
    Ok(path)
}
fn same_executable(first: &Path, second: &Path) -> std::io::Result<bool> {
    if first.canonicalize()? == second.canonicalize()? {
        return Ok(true);
    }
    let first_metadata = first.metadata()?;
    let second_metadata = second.metadata()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if first_metadata.dev() == second_metadata.dev()
            && first_metadata.ino() == second_metadata.ino()
        {
            return Ok(true);
        }
    }
    if first_metadata.len() != second_metadata.len() {
        return Ok(false);
    }
    Ok(std::fs::read(first)? == std::fs::read(second)?)
}
fn hash_compiler_identity(path: &Path, hash: &mut CanonicalHasher) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        let identity = brokk_bifrost_core::content_digest::metadata_change_identity(path)?
            .ok_or_else(|| std::io::Error::other("compiler is not a regular file"))?;
        // Memory-only identity, including every field of the shared strong stat record.
        hash.value(format!("{identity:?}").as_bytes());
    }
    #[cfg(not(unix))]
    {
        hash.value(&brokk_bifrost_core::analyzer::canonical_hash::sha256_bytes(
            &std::fs::read(path)?,
        ));
    }
    Ok(())
}
#[cfg(all(test, unix))]
fn resolve_compiler(
    root: &Path,
    paths: Option<std::ffi::OsString>,
    cancellation: &CancellationToken,
) -> Result<PathBuf, Unavailable> {
    resolve_selected_compiler(root, paths, cancellation, None)
}
#[cfg(all(test, unix))]
fn resolve_selected_compiler(
    root: &Path,
    paths: Option<std::ffi::OsString>,
    cancellation: &CancellationToken,
    rustup_refusal: Option<Unavailable>,
) -> Result<PathBuf, Unavailable> {
    let compiler = rustc_in_paths(root, paths).and_then(|path| vetted_compiler_path(root, &path));
    resolve_recorded_compiler(
        root,
        compiler,
        cancellation,
        rustup_refusal,
        rustup_home(root).as_deref(),
        &mut CompilerPins::default(),
    )
}
fn resolve_recorded_compiler(
    root: &Path,
    compiler: Result<PathBuf, Unavailable>,
    cancellation: &CancellationToken,
    rustup_refusal: Option<Unavailable>,
    home: Option<&Path>,
    pins: &mut CompilerPins,
) -> Result<PathBuf, Unavailable> {
    let compiler = compiler?;
    let sibling = compiler
        .parent()
        .expect("absolute compiler has parent")
        .join(if cfg!(windows) {
            "rustup.exe"
        } else {
            "rustup"
        });
    let known_proxy = match vetted_compiler_path(root, &sibling) {
        Ok(sibling) => {
            same_executable(&compiler, &sibling).map_err(|_| Unavailable::ProcessFailure)?
        }
        Err(_) => false,
    };
    if known_proxy && let Some(cause) = &rustup_refusal {
        return Err(cause.clone());
    }
    // rustup 1.29.1 Process::name honors this before dispatching argv[0].
    // `which` is metadata-only; never probe an unknown proxy with compiler flags.
    let mut request = compiler_request(root, compiler.as_os_str().to_owned(), &["which", "rustc"]);
    request
        .env
        .push(("RUSTUP_FORCE_ARG0".into(), "rustup".into()));
    let output = run_bounded_process(&request, || cancellation.is_cancelled()).map_err(|_| {
        if cancellation.is_cancelled() {
            Unavailable::Cancelled
        } else {
            Unavailable::ProcessFailure
        }
    })?;
    if output.status.success() {
        let path = String::from_utf8(output.stdout).map_err(|_| Unavailable::InvalidOutput)?;
        if !output.stderr.is_empty() || path.lines().count() != 1 || path.trim().is_empty() {
            return Err(Unavailable::InvalidOutput);
        }
        pins.selection_path = Some(PathBuf::from(path.trim()));
        if let Some(home) = home {
            let toolchains = home.join("toolchains");
            if let Ok(relative) = Path::new(path.trim()).strip_prefix(&toolchains)
                && let Some(std::path::Component::Normal(name)) = relative.components().next()
            { pins.toolchain_entry = Some(toolchains.join(name)); }
        }
        if let Some(cause) = rustup_refusal { return Err(cause); }
        vetted_compiler_path(root, Path::new(path.trim()))
    } else if !known_proxy && output.status.code() == Some(1) && output.stdout.is_empty()
        && String::from_utf8(output.stderr).is_ok_and(|stderr| stderr.trim() == "error: multiple input filenames provided (first two filenames are `which` and `rustc`)")
    {
        Ok(compiler)
    } else {
        Err(Unavailable::CompilerRejected)
    }
}
fn compiler_request(
    root: &Path,
    program: std::ffi::OsString,
    args: &[&str],
) -> BoundedProcessRequest {
    BoundedProcessRequest {
        program,
        args: args.iter().map(|arg| (*arg).into()).collect(),
        env: vec![("RUSTUP_AUTO_INSTALL".into(), "0".into())],
        clear_env: false,
        cwd: root.to_path_buf(),
        stdin: None,
        timeout: Duration::from_secs(10),
        stdout_limit: 65536,
        stderr_limit: 65536,
        description: "Rust toolchain observation".into(),
    }
}
fn compiler_output(
    request: &BoundedProcessRequest,
    cancellation: &CancellationToken,
) -> Result<String, Unavailable> {
    let output = run_bounded_process(request, || cancellation.is_cancelled()).map_err(|_| {
        if cancellation.is_cancelled() {
            Unavailable::Cancelled
        } else {
            Unavailable::ProcessFailure
        }
    })?;
    if !output.status.success() {
        return Err(Unavailable::CompilerRejected);
    }
    String::from_utf8(output.stdout).map_err(|_| Unavailable::InvalidOutput)
}
fn observe(compiler: &Path, root: &Path, cancellation: &CancellationToken) -> ToolchainOutcome {
    let run = |args: &[&str]| {
        let program = compiler.as_os_str().to_owned();
        compiler_output(&compiler_request(root, program, args), cancellation)
    };
    let result = (|| {
        let version = run(&["-vV"])?;
        let sysroot = run(&["--print", "sysroot"])?;
        let field = |key: &str| {
            version
                .lines()
                .find_map(|line| line.strip_prefix(key))
                .map(str::to_owned)
                .ok_or(Unavailable::InvalidOutput)
        };
        let release = field("release: ")?;
        let channel = if release.contains("nightly") {
            "nightly"
        } else if release.contains("beta") {
            "beta"
        } else {
            "stable"
        }
        .into();
        // -vV certifies the compiler host, not a Cargo build target.
        Ok(ToolchainIdentity {
            release,
            channel,
            commit: field("commit-hash: ")?,
            host: field("host: ")?,
            target: None,
            sysroot: PathBuf::from(sysroot.trim()),
        })
    })();
    match result {
        Ok(identity) => ToolchainOutcome::Observed(identity),
        Err(cause) => ToolchainOutcome::Unavailable(cause),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_authority(root: PathBuf) -> ToolchainAuthority {
        ToolchainAuthority::new(Arc::new(
            brokk_bifrost_core::analyzer::project::FilesystemProject::new(root).unwrap(),
        ))
    }
    #[cfg(unix)]
    #[test]
    fn rustup_resolution_refuses_workspace_compiler_and_observes_external() {
        use std::os::unix::fs::PermissionsExt;
        let workspace = tempfile::tempdir().unwrap();
        let trusted = tempfile::tempdir().unwrap();
        let marker = workspace.path().join("executed");
        let fake = workspace.path().join("rustc");
        std::fs::write(&fake, "#!/bin/sh\nprintf unsafe > executed\n").unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        let rustup = trusted.path().join("rustup");
        let selected = trusted.path().join("selected");
        // Read an output path as data, without embedding temporary paths as shell syntax.
        std::fs::write(&rustup, "#!/bin/sh\n[ \"$1\" = which ] && [ \"$2\" = rustc ] || exit 1\nexec /bin/cat \"${0%/*}/selected\"\n").unwrap();
        std::fs::set_permissions(&rustup, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::os::unix::fs::symlink(&rustup, trusted.path().join("rustc")).unwrap();
        std::fs::write(&selected, fake.to_str().unwrap()).unwrap();
        let paths = std::env::join_paths([trusted.path()]).unwrap();
        let cancellation = CancellationToken::default();
        assert_eq!(
            resolve_compiler(workspace.path(), Some(paths.clone()), &cancellation),
            Err(Unavailable::WorkspaceToolchainPath)
        );
        assert!(!marker.exists());
        let proxy = trusted.path().join("rustc");
        std::fs::remove_file(&proxy).unwrap();
        std::fs::hard_link(&rustup, &proxy).unwrap();
        assert_eq!(
            resolve_compiler(workspace.path(), Some(paths.clone()), &cancellation),
            Err(Unavailable::WorkspaceToolchainPath)
        );
        std::fs::remove_file(&proxy).unwrap();
        std::fs::copy(&rustup, &proxy).unwrap();
        assert_eq!(
            resolve_compiler(workspace.path(), Some(paths.clone()), &cancellation),
            Err(Unavailable::WorkspaceToolchainPath)
        );
        assert!(!marker.exists());
        let safe = trusted.path().join("rustc-real");
        std::fs::write(&safe, "#!/bin/sh\nif [ \"$1\" = -vV ]; then\nprintf 'release: 1.100.0\\ncommit-hash: safe\\nhost: test-host\\n'\nelse\nprintf /safe/sysroot\nfi\n").unwrap();
        std::fs::set_permissions(&safe, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(&selected, safe.to_str().unwrap()).unwrap();
        let compiler = resolve_compiler(workspace.path(), Some(paths), &cancellation).unwrap();
        assert_eq!(compiler, safe.canonicalize().unwrap());
        assert!(
            matches!(observe(&compiler, workspace.path(), &cancellation), ToolchainOutcome::Observed(identity) if identity.commit == "safe")
        );
        assert!(!marker.exists());
    }

    #[cfg(unix)]
    #[test]
    fn isolated_proxy_is_probed_and_standalone_ignores_rustup_selectors() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let workspace = tempfile::tempdir().unwrap();
        let external = tempfile::tempdir().unwrap();
        let path_dir = tempfile::tempdir().unwrap();
        let proxy = external.path().join("proxy-only");
        let target = workspace.path().join("rustc");
        std::fs::write(&target, "#!/bin/sh\nprintf unsafe > executed\n").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(&proxy, "#!/bin/sh\n[ \"$RUSTUP_FORCE_ARG0\" = rustup ] && [ \"$RUSTUP_AUTO_INSTALL\" = 0 ] && [ \"$1\" = which ] && [ \"$2\" = rustc ] || exit 2\nexec /bin/cat \"${0%/*}/selected\"\n").unwrap();
        std::fs::set_permissions(&proxy, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(external.path().join("selected"), target.to_str().unwrap()).unwrap();
        symlink(&proxy, path_dir.path().join("rustc")).unwrap();
        let paths = std::env::join_paths([path_dir.path()]).unwrap();
        let cancellation = CancellationToken::default();
        assert_eq!(
            resolve_compiler(workspace.path(), Some(paths.clone()), &cancellation),
            Err(Unavailable::WorkspaceToolchainPath)
        );
        assert!(!workspace.path().join("executed").exists());
        std::fs::write(
            workspace.path().join("rust-toolchain.toml"),
            "[toolchain]\npath = '/untrusted'\n",
        )
        .unwrap();
        let mut authority = test_authority(workspace.path().to_owned());
        authority.selector_paths = Some(paths);
        authority.refresh(&cancellation);
        assert_eq!(
            authority.prepared().unwrap().outcome,
            ToolchainOutcome::Unavailable(Unavailable::WorkspaceToolchainPath)
        );
        let standalone = external.path().join("standalone");
        std::fs::write(&standalone, "#!/bin/sh\nif [ \"$1\" = which ]; then\nprintf '%s\\n' 'error: multiple input filenames provided (first two filenames are `which` and `rustc`)' >&2\nexit 1\nfi\nif [ \"$1\" = -vV ]; then\nprintf 'release: 1.100.0\\ncommit-hash: independent\\nhost: test-host\\n'\nelse\nprintf /safe/sysroot\nfi\n").unwrap();
        std::fs::set_permissions(&standalone, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::remove_file(path_dir.path().join("rustc")).unwrap();
        symlink(&standalone, path_dir.path().join("rustc")).unwrap();
        authority.refresh(&cancellation);
        assert!(
            matches!(authority.prepared().unwrap().outcome, ToolchainOutcome::Observed(ref identity) if identity.commit == "independent")
        );
        assert!(!workspace.path().join("executed").exists());
    }

    #[cfg(unix)]
    #[test]
    fn independent_path_compiler_precedes_rustup() {
        use std::os::unix::fs::PermissionsExt;
        let workspace = tempfile::tempdir().unwrap();
        let compiler_dir = tempfile::tempdir().unwrap();
        let rustup_dir = tempfile::tempdir().unwrap();
        let compiler = compiler_dir.path().join("rustc");
        std::fs::write(&compiler, "#!/bin/sh\nif [ \"$1\" = which ]; then\nprintf '%s\\n' 'error: multiple input filenames provided (first two filenames are `which` and `rustc`)' >&2\nexit 1\nfi\nif [ \"$1\" = -vV ]; then\nprintf 'release: 1.100.0\\ncommit-hash: independent\\nhost: test-host\\n'\nelse\nprintf /safe/sysroot\nfi\n").unwrap();
        std::fs::set_permissions(&compiler, std::fs::Permissions::from_mode(0o755)).unwrap();
        let rustup = rustup_dir.path().join("rustup");
        std::fs::write(
            &rustup,
            "#!/bin/sh\nprintf called > rustup-called\nexit 1\n",
        )
        .unwrap();
        std::fs::set_permissions(&rustup, std::fs::Permissions::from_mode(0o755)).unwrap();
        let paths = std::env::join_paths([compiler_dir.path(), rustup_dir.path()]).unwrap();
        let cancellation = CancellationToken::default();
        let resolved = resolve_compiler(workspace.path(), Some(paths), &cancellation).unwrap();
        assert_eq!(resolved, compiler.canonicalize().unwrap());
        assert!(
            matches!(observe(&resolved, workspace.path(), &cancellation), ToolchainOutcome::Observed(identity) if identity.commit == "independent")
        );
        assert!(!workspace.path().join("rustup-called").exists());
    }

    #[cfg(unix)]
    #[test]
    fn compiler_replacement_at_same_path_refuses_receipt() {
        use std::os::unix::fs::PermissionsExt;
        let workspace = tempfile::tempdir().unwrap();
        let external = tempfile::tempdir().unwrap();
        let compiler = external.path().join("rustc");
        std::fs::write(&compiler, "#!/bin/sh\nif [ \"$1\" = which ]; then\nprintf '%s\\n' 'error: multiple input filenames provided (first two filenames are `which` and `rustc`)' >&2\nexit 1\nfi\nexit 0\n").unwrap();
        std::fs::set_permissions(&compiler, std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut authority = test_authority(workspace.path().to_owned());
        authority.selector_paths = Some(std::env::join_paths([external.path()]).unwrap());
        authority.refresh_with(|| {
            ToolchainOutcome::Observed(ToolchainIdentity {
                release: "1.100.0".into(),
                channel: "stable".into(),
                commit: "old".into(),
                host: "test-host".into(),
                target: None,
                sysroot: workspace.path().to_owned(),
            })
        });
        let question = authority.questions().remove(0);
        let answer = || {
            authority.answer(
                &OuterRequest::new(),
                &question,
                &SelectionRetry::default(),
                &CancellationToken::default(),
            )
        };
        assert!(answer().unwrap().certified);
        let replacement = external.path().join("replacement");
        std::fs::write(&replacement, "#!/bin/sh\nif [ \"$1\" = which ]; then\nprintf '%s\\n' 'error: multiple input filenames provided (first two filenames are `which` and `rustc`)' >&2\nexit 1\nfi\nexit 0\n").unwrap();
        std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::rename(replacement, &compiler).unwrap();
        assert!(matches!(answer(), Err(SelectionRefused::Stale)));
    }

    #[test]
    fn observation_leaves_state_unlocked_and_concurrent_publication_wins() {
        let workspace = tempfile::tempdir().unwrap();
        let authority = test_authority(workspace.path().to_owned());
        authority.refresh_with(|| ToolchainOutcome::Unavailable(Unavailable::CompilerRejected));
        let mut concurrent = None;
        authority.refresh_with(|| {
            assert!(authority.state.try_lock().is_ok());
            let question = authority.questions().remove(0);
            assert!(
                authority
                    .answer(
                        &OuterRequest::new(),
                        &question,
                        &SelectionRetry::default(),
                        &CancellationToken::default()
                    )
                    .is_ok()
            );
            authority.refresh_with(|| ToolchainOutcome::Unavailable(Unavailable::InvalidOutput));
            concurrent = authority.prepared();
            ToolchainOutcome::Unavailable(Unavailable::CompilerRejected)
        });
        assert!(Arc::ptr_eq(
            &authority.prepared().unwrap(),
            &concurrent.unwrap()
        ));
    }

    #[cfg(unix)]
    #[test]
    fn live_checks_run_no_process_and_detect_settings_and_relinks() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let workspace = tempfile::tempdir().unwrap();
        let external = tempfile::tempdir().unwrap();
        let home = external.path().join("home");
        let toolchains = home.join("toolchains");
        std::fs::create_dir_all(&toolchains).unwrap();
        let settings = home.join("settings.toml");
        std::fs::write(&settings, "").unwrap();
        let entry = toolchains.join("chosen");
        let first = external.path().join("first");
        let second = external.path().join("second");
        for target in [&first, &second] {
            std::fs::create_dir_all(target.join("bin")).unwrap();
            let compiler = target.join("bin/rustc");
            std::fs::write(&compiler, "#!/bin/sh\nprintf ran > compiler-ran\nif [ \"$1\" = -vV ]; then\nprintf 'release: 1.100.0\\ncommit-hash: prepared\\nhost: test-host\\n'\nelse\nprintf /safe/sysroot\nfi\n").unwrap();
            std::fs::set_permissions(compiler, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        symlink(&first, &entry).unwrap();
        let rustup = external.path().join("rustup");
        std::fs::write(
            &rustup,
            "#!/bin/sh\nprintf ran > probe-ran\nexec /bin/cat \"${0%/*}/selected\"\n",
        )
        .unwrap();
        std::fs::set_permissions(&rustup, std::fs::Permissions::from_mode(0o755)).unwrap();
        symlink(&rustup, external.path().join("rustc")).unwrap();
        std::fs::write(
            external.path().join("selected"),
            entry.join("bin/rustc").to_str().unwrap(),
        )
        .unwrap();
        let mut authority = test_authority(workspace.path().to_owned());
        authority.selector_paths = Some(std::env::join_paths([external.path()]).unwrap());
        authority.selector_home = Some(home);
        assert!(!workspace.path().join("probe-ran").exists());
        authority.refresh(&CancellationToken::default());
        assert_eq!(
            authority.prepared().unwrap().pins.toolchain_entry,
            Some(entry.clone())
        );
        std::fs::remove_file(workspace.path().join("probe-ran")).unwrap();
        std::fs::remove_file(workspace.path().join("compiler-ran")).unwrap();
        let question = authority.questions().remove(0);
        let answer = || {
            authority.answer(
                &OuterRequest::new(),
                &question,
                &SelectionRetry::default(),
                &CancellationToken::default(),
            )
        };
        assert!(authority.selectors_unchanged());
        assert!(answer().unwrap().certified);
        let clone = authority.clone_for_project(authority.project.clone());
        assert!(clone.prepared().is_some());
        std::fs::write(&settings, "[overrides]\n").unwrap();
        assert!(matches!(answer(), Err(SelectionRefused::Stale)));
        std::fs::write(&settings, "").unwrap();
        assert!(answer().unwrap().certified);
        std::fs::remove_file(&entry).unwrap();
        symlink(&second, &entry).unwrap();
        assert!(matches!(answer(), Err(SelectionRefused::Stale)));
        assert!(!authority.selectors_unchanged());
        assert!(!workspace.path().join("probe-ran").exists());
        assert!(!workspace.path().join("compiler-ran").exists());
    }

    #[test]
    fn stale_refresh_preserves_newer_live_publication() {
        let workspace = tempfile::tempdir().unwrap();
        let authority = test_authority(workspace.path().to_owned());
        let observed = |commit: &str| {
            ToolchainOutcome::Observed(ToolchainIdentity {
                release: "1.100.0".into(),
                channel: "stable".into(),
                commit: commit.into(),
                host: "test-host".into(),
                target: None,
                sysroot: workspace.path().to_owned(),
            })
        };
        let mut newer = None;
        authority.refresh_with(|| {
            std::fs::write(
                workspace.path().join("rust-toolchain.toml"),
                "[toolchain]\nchannel = 'stable'\n",
            )
            .unwrap();
            authority.refresh_with(|| observed("newer"));
            newer = authority.prepared();
            observed("older")
        });
        let current = authority.prepared().unwrap();
        assert!(Arc::ptr_eq(&current, &newer.unwrap()));
        let question = authority.questions().remove(0);
        assert!(
            authority
                .answer(
                    &OuterRequest::new(),
                    &question,
                    &SelectionRetry::default(),
                    &CancellationToken::default()
                )
                .unwrap()
                .certified
        );
        assert_eq!(current.outcome, observed("newer"));
    }

    #[test]
    fn request_keeps_selection_across_preparation_refresh() {
        let root = tempfile::tempdir().unwrap();
        let authority = test_authority(root.path().to_owned());
        let mut state = authority.state.lock().unwrap();
        let digest = state.update_selector_digest.unwrap();
        authority.prepare(&mut state.prepared, digest, None, || {
            ToolchainOutcome::Unavailable(Unavailable::CompilerRejected)
        });
        drop(state);
        let request = OuterRequest::new();
        let question = authority.questions().remove(0);
        let cancellation = CancellationToken::default();
        let first = authority
            .answer(
                &request,
                &question,
                &SelectionRetry::default(),
                &cancellation,
            )
            .unwrap();
        let mut state = authority.state.lock().unwrap();
        let digest = state.update_selector_digest.unwrap();
        authority.prepare(&mut state.prepared, digest, None, || {
            ToolchainOutcome::Unavailable(Unavailable::InvalidOutput)
        });
        drop(state);
        let second = authority
            .answer(
                &request,
                &question,
                &SelectionRetry::default(),
                &cancellation,
            )
            .unwrap();
        assert!(Arc::ptr_eq(&first, &second));
        let next = authority
            .answer(
                &OuterRequest::new(),
                &question,
                &SelectionRetry::default(),
                &cancellation,
            )
            .unwrap();
        assert_ne!(first.answer_digest, next.answer_digest);
    }

    #[test]
    fn selector_change_refuses_prepared_receipt() {
        let root = tempfile::tempdir().unwrap();
        let authority = test_authority(root.path().to_owned());
        // Explicit preparation seam avoids compiler execution and Cargo's selector environment.
        authority.refresh_with(|| {
            ToolchainOutcome::Observed(ToolchainIdentity {
                release: "1.100.0".into(),
                channel: "stable".into(),
                commit: "first".into(),
                host: "test-host".into(),
                target: None,
                sysroot: root.path().to_owned(),
            })
        });
        let request = OuterRequest::new();
        let question = authority.questions().remove(0);
        let cancellation = CancellationToken::default();
        let first = authority
            .answer(
                &request,
                &question,
                &SelectionRetry::default(),
                &cancellation,
            )
            .unwrap();
        assert!(first.certified);
        std::fs::write(
            root.path().join("rust-toolchain.toml"),
            "[toolchain]\nchannel = 'beta'\n",
        )
        .unwrap();
        let settled = authority
            .answer(
                &request,
                &question,
                &SelectionRetry::default(),
                &cancellation,
            )
            .unwrap();
        assert!(Arc::ptr_eq(&first, &settled));
        assert!(matches!(
            authority.answer(
                &OuterRequest::new(),
                &question,
                &SelectionRetry::default(),
                &CancellationToken::default()
            ),
            Err(SelectionRefused::Stale)
        ));
        authority.refresh_with(|| ToolchainOutcome::Unavailable(Unavailable::CompilerRejected));
        assert!(
            authority
                .answer(
                    &OuterRequest::new(),
                    &question,
                    &SelectionRetry::default(),
                    &CancellationToken::default()
                )
                .is_ok()
        );
    }

    #[test]
    fn selectors_changing_during_observation_discard_receipt() {
        let root = tempfile::tempdir().unwrap();
        let authority = test_authority(root.path().to_owned());
        let observed = || {
            ToolchainOutcome::Observed(ToolchainIdentity {
                release: "1.100.0".into(),
                channel: "stable".into(),
                commit: "first".into(),
                host: "test-host".into(),
                target: None,
                sysroot: root.path().to_owned(),
            })
        };
        authority.refresh_with(observed);
        assert!(authority.prepared().is_some());
        authority.refresh_with(|| {
            std::fs::write(
                root.path().join("rust-toolchain.toml"),
                "[toolchain]\nchannel = 'beta'\n",
            )
            .unwrap();
            observed()
        });
        assert!(authority.state.lock().unwrap().prepared.is_some());
        assert!(authority.prepared().is_none());
        let question = authority.questions().remove(0);
        assert!(matches!(
            authority.answer(
                &OuterRequest::new(),
                &question,
                &SelectionRetry::default(),
                &CancellationToken::default()
            ),
            Err(SelectionRefused::Stale)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn path_search_skips_nonexecutable_rustc() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let first = root.path().join("first");
        let second = root.path().join("second");
        for (dir, mode) in [(&first, 0o644), (&second, 0o755)] {
            std::fs::create_dir(dir).unwrap();
            let file = dir.join("rustc");
            std::fs::write(&file, "compiler").unwrap();
            std::fs::set_permissions(file, std::fs::Permissions::from_mode(mode)).unwrap();
        }
        let workspace = tempfile::tempdir().unwrap();
        let paths = std::env::join_paths([first, second.clone()]).unwrap();
        assert_eq!(
            rustc_in_paths(workspace.path(), Some(paths)),
            Ok(second.canonicalize().unwrap().join("rustc"))
        );
    }

    #[test]
    fn changed_overlay_selector_refuses_disk_observation() {
        use brokk_bifrost_core::analyzer::project::OverlayProject;
        let temp = tempfile::tempdir().unwrap();
        let content = "[toolchain]\nchannel = 'stable'\n";
        std::fs::write(temp.path().join("rust-toolchain.toml"), content).unwrap();
        let authority = test_authority(temp.path().to_owned());
        // The analyzer canonicalizes its root, so key the overlay and the
        // observed sysroot by that root. A raw temp path differs where `/var`
        // is a symlink to `/private/var` (macOS), and the overlay would miss.
        let root = authority.project.root().to_path_buf();
        let path = root.join("rust-toolchain.toml");
        authority.refresh_with(|| {
            ToolchainOutcome::Observed(ToolchainIdentity {
                release: "1.100.0".into(),
                channel: "stable".into(),
                commit: "test".into(),
                host: "test-host".into(),
                target: None,
                sysroot: root.clone(),
            })
        });
        let overlay = Arc::new(OverlayProject::new(authority.project.clone()));
        assert!(overlay.set(path.clone(), content.into()));
        let updated = authority.clone_for_project(overlay.clone());
        let question = updated.questions().remove(0);
        let answer = || {
            updated.answer(
                &OuterRequest::new(),
                &question,
                &SelectionRetry::default(),
                &CancellationToken::default(),
            )
        };
        assert!(answer().unwrap().certified);
        assert!(overlay.set(path, "[toolchain]\nchannel = 'beta'\n".into()));
        assert!(matches!(answer(), Err(SelectionRefused::Stale)));
    }

    #[cfg(unix)]
    #[test]
    fn workspace_compiler_is_never_executed() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let root = tempfile::tempdir().unwrap();
        let real = tempfile::tempdir().unwrap();
        let bin = root.path().join("bin");
        std::fs::create_dir(&bin).unwrap();
        let links = real.path().join("links");
        std::fs::create_dir(&links).unwrap();
        for name in ["rustc", "rustup"] {
            for dir in [root.path(), bin.as_path()] {
                let fake = dir.join(name);
                std::fs::write(&fake, "#!/bin/sh\nprintf unsafe > executed\n").unwrap();
                std::fs::set_permissions(fake, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
            let safe = real.path().join(name);
            std::fs::write(&safe, "#!/bin/sh\nprintf later > later-executed\n").unwrap();
            std::fs::set_permissions(&safe, std::fs::Permissions::from_mode(0o755)).unwrap();
            symlink(bin.join(name), links.join(name)).unwrap();
            for first in [
                Path::new(""),
                Path::new("."),
                Path::new("bin"),
                bin.as_path(),
                links.as_path(),
            ] {
                let paths = std::env::join_paths([first, real.path()]).unwrap();
                assert_eq!(
                    executable_in_paths(root.path(), name, Some(paths)),
                    Err(Unavailable::WorkspaceToolchainPath)
                );
            }
        }
        let paths = std::env::join_paths([bin.as_path(), real.path()]).unwrap();
        let mut authority = test_authority(root.path().to_owned());
        authority.selector_paths = Some(paths);
        authority.refresh(&CancellationToken::default());
        assert_eq!(
            authority.prepared().unwrap().outcome,
            ToolchainOutcome::Unavailable(Unavailable::WorkspaceToolchainPath)
        );
        assert!(!root.path().join("executed").exists());
        assert!(!root.path().join("later-executed").exists());
    }

    #[test]
    fn local_compiler_and_ancestor_selector_refresh() {
        let root = tempfile::tempdir().unwrap();
        let workspace = root.path().join("workspace");
        std::fs::create_dir(&workspace).unwrap();
        let authority = test_authority(workspace);
        let cancellation = CancellationToken::default();
        authority.refresh(&cancellation);
        let first = authority.prepared().unwrap();
        match &first.outcome {
            ToolchainOutcome::Unavailable(Unavailable::NoRustc) => {
                eprintln!("skip: {:?}", first.outcome);
                return;
            }
            ToolchainOutcome::Observed(identity) => {
                assert!(!identity.release.is_empty());
                assert!(!identity.channel.is_empty());
                assert!(!identity.host.is_empty());
                eprintln!("{identity:?}");
            }
            other => panic!("local compiler observation failed: {other:?}"),
        }
        authority.refresh(&cancellation);
        assert!(!Arc::ptr_eq(&first, &authority.prepared().unwrap()));
    }

    #[test]
    fn unchanged_selectors_refresh_compiler() {
        let root = tempfile::tempdir().unwrap();
        let authority = test_authority(root.path().to_owned());
        let identity = |commit: &str| {
            ToolchainOutcome::Observed(ToolchainIdentity {
                release: "1.100.0-nightly".into(),
                channel: "nightly".into(),
                commit: commit.into(),
                host: "test-host".into(),
                target: None,
                sysroot: root.path().to_owned(),
            })
        };
        authority.refresh_with(|| identity("first"));
        let first = authority.prepared().unwrap();
        authority.refresh_with(|| identity("second"));
        let second = authority.prepared().unwrap();
        assert_eq!(first.selector_digest, second.selector_digest);
        assert_eq!(second.outcome, identity("second"));
        assert_ne!(first.answer_digest, second.answer_digest);
        use brokk_bifrost_semantic::analyzer::semantic_model::*;
        let mut receipt = VerifiedSysrootReceipt {
            path: "core.json".into(),
            provenance: RustSysrootProvenance {
                toolchain: RustToolchainIdentity {
                    release: "1.100.0-nightly".into(),
                    channel: RustToolchainChannel::Nightly,
                    date: "2026-11-14".into(),
                    commit: "first".into(),
                },
                component: RustdocComponent::RustDocsJsonPreview,
                target: "test-host".into(),
                archive_sha256: "test".into(),
                archive_member: "core.json".into(),
            },
        };
        assert!(first.outcome.matches_verified_release(&receipt));
        assert!(!second.outcome.matches_verified_release(&receipt));
        receipt.provenance.toolchain.commit.clear();
        assert!(!first.outcome.matches_verified_release(&receipt));
    }

    #[test]
    fn nearer_selector_ignores_invalid_ancestor() {
        let root = tempfile::tempdir().unwrap();
        let workspace = root.path().join("workspace");
        std::fs::create_dir(&workspace).unwrap();
        std::fs::write(root.path().join("rust-toolchain.toml"), "invalid [").unwrap();
        std::fs::write(workspace.join("rust-toolchain"), "stable").unwrap();
        let (digest, refusal) = selectors_with_override(&workspace, None);
        let authority = test_authority(workspace);
        let mut slot = None;
        authority.prepare(&mut slot, digest, refusal, || {
            ToolchainOutcome::Unavailable(Unavailable::CompilerRejected)
        });
        assert_eq!(
            slot.unwrap().outcome,
            ToolchainOutcome::Unavailable(Unavailable::CompilerRejected)
        );
    }

    #[test]
    fn workspace_path_refuses_before_spawn() {
        for name in ["rust-toolchain", "rust-toolchain.toml"] {
            let root = tempfile::tempdir().unwrap();
            let bytes = b"[toolchain]\npath = '/untrusted/compiler'\n";
            std::fs::write(root.path().join(name), bytes).unwrap();
            let authority = test_authority(root.path().to_owned());
            let mut slot = None;
            authority.prepare(
                &mut slot,
                [0; 32],
                selectors_with_override(root.path(), None).1,
                || panic!("path selector must refuse before spawning"),
            );
            assert_eq!(
                slot.unwrap().outcome,
                ToolchainOutcome::Unavailable(Unavailable::WorkspaceToolchainPath)
            );
        }
    }

    #[test]
    fn uninstalled_named_channel_is_unavailable_without_installing() {
        let root = tempfile::tempdir().unwrap();
        let Ok(rustup) = executable_in_paths(
            root.path(),
            if cfg!(windows) {
                "rustup.exe"
            } else {
                "rustup"
            },
            std::env::var_os("PATH"),
        ) else {
            eprintln!(
                "skip: rustup unavailable on PATH ({:?})",
                Unavailable::NoRustup
            );
            return;
        };
        // Cargo supplies its own RUSTUP_TOOLCHAIN and compiler PATH to tests.
        // An explicit rustup run selects the missing name without global env mutation.
        let request = compiler_request(
            root.path(),
            rustup.into_os_string(),
            &["run", "nightly-1900-01-01", "rustc", "-vV"],
        );
        assert_eq!(
            request.env,
            vec![("RUSTUP_AUTO_INSTALL".into(), "0".into())]
        );
        assert_eq!(
            compiler_output(&request, &CancellationToken::default()),
            Err(Unavailable::CompilerRejected)
        );
    }
}
