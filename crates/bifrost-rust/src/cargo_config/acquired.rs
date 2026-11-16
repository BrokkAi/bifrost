//! Recorded discovery inputs for Cargo configuration. No configuration text or
//! physical home path belongs in this record. The acquisition boundary owns
//! filesystem reads; pure consumers receive this immutable value.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;

use super::{RustCargoConfigSourceEffect, RustStdlibBuildMode};

/// The acquired-input family's own identity lever. Derived dependency evidence
/// and feature projections bind this digest, not an unversioned mutable head.
pub const ACQUIRED_CARGO_CONFIG_DOMAIN: &[u8] = b"bifrost.acquired-cargo-config.v2";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RustCargoConfigReadState {
    Absent,
    File {
        sha256: [u8; 32],
        bytes: u64,
    },
    Environment {
        value_sha256: Option<[u8; 32]>,
        working_directory_sha256: Option<[u8; 32]>,
    },
    Unavailable {
        reason: RustCargoConfigReadFailure,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RustCargoConfigReadFailure {
    Unreadable,
    Malformed,
    OutsideInclude,
    CyclicInclude,
    SourceFilesLimit,
    TotalBytesLimit,
    FileBytesLimit,
    MissingRequiredInclude,
    Unclassifiable,
    UnknownHome,
    ChangedDuringAcquisition,
}

/// A structural label (for example Cargo-home/config/include[0]), never a
/// configured include value, absolute home path, or environment value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RustCargoConfigRead {
    pub label: String,
    pub state: RustCargoConfigReadState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RustCargoLocalInputRef {
    pub oid: git2::Oid,
    /// None identifies a legacy input whose presence was not established.
    pub present: Option<bool>,
}

/// An ordered local layer used to reconstruct local patch/paths semantics from
/// existing selected snapshots. External source overrides stay unresolved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RustCargoLocalLayerRef {
    pub path: PathBuf,
    pub base: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RustCargoConfigOwnerFacts {
    pub workspace: PathBuf,
    pub targets: Vec<String>,
    pub target_configured: bool,
    pub target_defining: Vec<PathBuf>,
    /// Unsupported target values are represented without retaining private paths.
    pub target_unsupported: bool,
    pub build_mode: RustStdlibBuildMode,
    pub cfg_atoms: BTreeSet<String>,
    pub host_cfg_atoms: BTreeSet<String>,
    pub has_extern_flags: bool,
    pub source_effect: RustCargoConfigSourceEffect,
    pub complete: bool,
    pub external_source_unresolved: bool,
    pub local_layers: Vec<RustCargoLocalLayerRef>,
}

/// One request-owned capture, persisted as one acquired-input set. Parsed TOML
/// does not survive acquisition. A generation may own these typed input facts
/// under its required-state retention charge; this is not a warm external cache.
#[derive(Clone, PartialEq, Eq)]
pub struct RustCargoAcquiredConfigView {
    /// The full host triple (vendor and environment included) that host-only
    /// Cargo selection, such as `[target.<triple>.build-dependencies]`, was
    /// evaluated against (#12604). The view is the single owner of this fact:
    /// the host-dependency predicate reads it here and `digest()` hashes it, so
    /// a gnu and a musl binary cannot share a view identity and then disagree
    /// on the answer. The `cfg` atoms alone carry neither vendor nor
    /// environment.
    ///
    /// Assumption: build-dependencies belong to the machine that builds the
    /// analyzed project. Recording Bifrost's own host triple assumes that
    /// machine is the one running Bifrost.
    pub host_triple: String,
    pub owners: BTreeMap<PathBuf, RustCargoConfigOwnerFacts>,
    pub local_inputs: BTreeMap<PathBuf, RustCargoLocalInputRef>,
    pub reads: Vec<RustCargoConfigRead>,
    pub complete: bool,
}

impl Default for RustCargoAcquiredConfigView {
    /// View-building code records the compile-time host triple here; consumers
    /// read it back from the view.
    fn default() -> Self {
        Self {
            host_triple: super::host_target_triple().to_owned(),
            owners: BTreeMap::new(),
            local_inputs: BTreeMap::new(),
            reads: Vec::new(),
            complete: false,
        }
    }
}

impl std::fmt::Debug for RustCargoAcquiredConfigView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RustCargoAcquiredConfigView")
            .field("host_triple", &self.host_triple)
            .field("owners", &self.owners.len())
            .field("local_inputs", &self.local_inputs.len())
            .field("reads", &self.reads.len())
            .field("complete", &self.complete)
            .finish_non_exhaustive()
    }
}

impl RustCargoAcquiredConfigView {
    pub fn owner(&self, directory: &std::path::Path) -> Option<&RustCargoConfigOwnerFacts> {
        self.owners.get(directory).or_else(|| {
            self.owners
                .values()
                .find(|facts| facts.workspace == directory)
        })
    }

    /// The interpreted facts of every owner, in one encoding shared by
    /// [`Self::digest`] and [`Self::effective_digest`].
    fn hash_owners(&self, hash: &mut CanonicalHasher) {
        for (owner, facts) in &self.owners {
            hash.field("owner", owner.as_os_str().as_encoded_bytes());
            hash.field("workspace", facts.workspace.as_os_str().as_encoded_bytes());
            hash.field("target.configured", &[u8::from(facts.target_configured)]);
            for level in &facts.target_defining {
                hash.field("target.defining", level.as_os_str().as_encoded_bytes());
            }
            hash.field("target.unsupported", &[u8::from(facts.target_unsupported)]);
            for target in &facts.targets {
                hash.field("target", target.as_bytes());
            }
            hash.field("build.mode", build_mode_label(facts.build_mode).as_bytes());
            for atom in &facts.cfg_atoms {
                hash.field("cfg", atom.as_bytes());
            }
            for atom in &facts.host_cfg_atoms {
                hash.field("host.cfg", atom.as_bytes());
            }
            hash.field("extern.flags", &[u8::from(facts.has_extern_flags)]);
            hash.field(
                "source.effect",
                source_effect_label(facts.source_effect).as_bytes(),
            );
            hash.field("owner.complete", &[u8::from(facts.complete)]);
            hash.field(
                "external.sources",
                &[u8::from(facts.external_source_unresolved)],
            );
            for layer in &facts.local_layers {
                hash.field("layer.path", layer.path.as_os_str().as_encoded_bytes());
                hash.field("layer.base", layer.base.as_os_str().as_encoded_bytes());
            }
        }
    }

    /// What this acquisition means to its consumers: completeness and each
    /// owner's interpreted facts (targets, cfg atoms, build mode, extern flags,
    /// source effect, local layer paths). Unlike [`Self::digest`] it omits the
    /// local input OIDs and the read receipts, so an edit that leaves the
    /// interpretation unchanged, such as a comment, keeps it. The warm update
    /// path rebuilds only when this changes.
    pub fn effective_digest(&self) -> [u8; 32] {
        let mut hash = CanonicalHasher::new(b"bifrost.acquired-cargo-config-effect.v1");
        hash.field("complete", &[u8::from(self.complete)]);
        self.hash_owners(&mut hash);
        hash.finish()
    }

    pub fn digest(&self) -> [u8; 32] {
        let mut hash = CanonicalHasher::new(ACQUIRED_CARGO_CONFIG_DOMAIN);
        hash.field("complete", &[u8::from(self.complete)]);
        hash.field("host.triple", self.host_triple.as_bytes());
        for (path, input) in &self.local_inputs {
            hash.field("local.path", path.as_os_str().as_encoded_bytes());
            hash.field("local.oid", input.oid.as_bytes());
            hash.field(
                "local.present",
                &[match input.present {
                    None => 2,
                    Some(false) => 0,
                    Some(true) => 1,
                }],
            );
        }
        // Structural acquisition order is canonicalized independently of SQL row order.
        let mut reads = self.reads.iter().collect::<Vec<_>>();
        reads.sort_by(|a, b| a.label.cmp(&b.label));
        for read in reads {
            hash.field("read.label", read.label.as_bytes());
            match &read.state {
                RustCargoConfigReadState::Absent => hash.field("read.state", b"absent"),
                RustCargoConfigReadState::File { sha256, bytes } => {
                    hash.field("read.state", b"file");
                    hash.field("read.content", sha256);
                    hash.field("read.bytes", &bytes.to_le_bytes());
                }
                RustCargoConfigReadState::Environment {
                    value_sha256,
                    working_directory_sha256,
                } => {
                    hash.field("read.state", b"environment");
                    hash.field(
                        "read.environment.present",
                        &[u8::from(value_sha256.is_some())],
                    );
                    if let Some(digest) = value_sha256 {
                        hash.field("read.environment", digest);
                    }
                    if let Some(digest) = working_directory_sha256 {
                        hash.field("read.environment.working-directory", digest);
                    }
                }
                RustCargoConfigReadState::Unavailable { reason } => {
                    hash.field("read.unavailable", reason.label().as_bytes())
                }
            }
        }
        self.hash_owners(&mut hash);
        hash.finish()
    }
}

pub fn build_mode_label(mode: RustStdlibBuildMode) -> &'static str {
    match mode {
        RustStdlibBuildMode::Prebuilt => "prebuilt",
        RustStdlibBuildMode::BuildStd => "build_std",
        RustStdlibBuildMode::Unknown => "unknown",
    }
}

pub fn source_effect_label(effect: RustCargoConfigSourceEffect) -> &'static str {
    match effect {
        RustCargoConfigSourceEffect::Preserves => "preserves",
        RustCargoConfigSourceEffect::Changes => "changes",
        RustCargoConfigSourceEffect::Unknown => "unknown",
    }
}

impl RustCargoConfigReadFailure {
    pub fn label(self) -> &'static str {
        match self {
            Self::Unreadable => "unreadable",
            Self::Malformed => "malformed",
            Self::OutsideInclude => "outside_include",
            Self::CyclicInclude => "cyclic_include",
            Self::SourceFilesLimit => "max_source_files_per_artifact",
            Self::TotalBytesLimit => "max_total_artifact_bytes",
            Self::FileBytesLimit => "max_artifact_bytes",
            Self::MissingRequiredInclude => "missing_required_include",
            Self::Unclassifiable => "unclassifiable",
            Self::UnknownHome => "unknown_home",
            Self::ChangedDuringAcquisition => "changed_during_acquisition",
        }
    }
}

impl super::RustCargoConfiguration {
    /// Capture the interpreted facts before discarding parsed external TOML.
    /// The boundary supplies ordered local references, never external text.
    pub fn acquired_owner_facts(
        &self,
        directory: &std::path::Path,
        workspace: PathBuf,
        local_layers: Vec<RustCargoLocalLayerRef>,
    ) -> RustCargoConfigOwnerFacts {
        let (mut targets, defining) = self.configured_build_targets(directory);
        let unsupported = targets
            .iter()
            .any(|target| cfg_expr::targets::get_builtin_target_by_triple(target).is_none());
        if unsupported {
            targets.clear();
        }
        let complete = self.acquisition_is_complete(directory);
        RustCargoConfigOwnerFacts {
            workspace,
            targets,
            target_configured: !defining.is_empty(),
            target_defining: defining.into_iter().map(PathBuf::from).collect(),
            target_unsupported: unsupported,
            build_mode: self.stdlib_build_mode(directory),
            cfg_atoms: if complete {
                self.cfg_atoms(directory)
            } else {
                super::uncertain_cfg_atoms()
            },
            host_cfg_atoms: if complete {
                self.host_cfg_atoms(directory)
            } else {
                super::uncertain_cfg_atoms()
            },
            has_extern_flags: !complete || self.has_extern_flags(directory),
            source_effect: self.source_effect(directory),
            complete,
            external_source_unresolved: self.levels(directory).iter().any(|(_, document)| {
                !document.workspace_paths
                    && document.source_effect() != RustCargoConfigSourceEffect::Preserves
            }),
            local_layers,
        }
    }

    /// Reconstruct the reader without filesystem or environment access. Every
    /// recorded local reference must match a supplied immutable snapshot,
    /// including explicit absence. A partial/mismatched record cannot certify
    /// prebuilt stdlib mode or dependency source identity.
    pub fn from_acquired_view<'a>(
        view: &RustCargoAcquiredConfigView,
        snapshots: impl IntoIterator<Item = (&'a std::path::Path, git2::Oid, Option<bool>, &'a [u8])>,
    ) -> Self {
        let mut selected = BTreeMap::new();
        let mut valid = true;
        for (path, oid, present, bytes) in snapshots {
            if selected
                .insert(path.to_path_buf(), (oid, present, bytes))
                .is_some()
            {
                valid = false;
            }
        }
        for (path, input) in &view.local_inputs {
            valid &= selected.get(path).is_some_and(|(oid, present, bytes)| {
                *oid == input.oid
                    && *present == input.present
                    && present.is_some()
                    && git2::Oid::hash_object(git2::ObjectType::Blob, bytes).ok() == Some(*oid)
            });
        }
        let mut layers = BTreeMap::new();
        for (owner, facts) in &view.owners {
            let mut documents = Vec::new();
            for layer in &facts.local_layers {
                let document = view
                    .local_inputs
                    .get(&layer.path)
                    .filter(|input| input.present == Some(true))
                    .and_then(|_| selected.get(&layer.path))
                    .and_then(|(_, _, bytes)| {
                        super::RustCargoConfigDocument::from_source_bytes(bytes).ok()
                    });
                match document {
                    Some(document) => documents.push((layer.base.clone(), document)),
                    None => valid = false,
                }
            }
            layers.insert(owner.clone(), documents);
        }
        let mut recorded = view.clone();
        if !valid || !recorded.complete {
            recorded.complete = false;
            for facts in recorded.owners.values_mut() {
                facts.complete = false;
                facts.source_effect = RustCargoConfigSourceEffect::Unknown;
                facts.build_mode = RustStdlibBuildMode::Unknown;
                facts.cfg_atoms = super::uncertain_cfg_atoms();
                facts.host_cfg_atoms = super::uncertain_cfg_atoms();
                facts.has_extern_flags = true;
            }
        }
        Self {
            recorded: Some(recorded),
            recorded_layers: layers,
            ..Self::default()
        }
    }
}

impl super::RustCargoConfiguration {
    pub fn unknown_acquired() -> Self {
        Self::from_acquired_view(&RustCargoAcquiredConfigView::default(), std::iter::empty())
    }
}
