//! Filesystem admission for Cargo's files-only configuration view (#12398).
//! Pure evidence and reconciliation consume the returned record instead of
//! reopening these paths. No external configuration text survives in the record.

use brokk_bifrost_core::path_normalization::NormalizePath;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::analyzer::semantic_model::{DependencyPackLimits, ExternalDiscoveryRead};
use brokk_bifrost_analysis::analyzer::dependency_support::report_external_discovery_read;
use brokk_bifrost_core::analyzer::canonical_hash::sha256_bytes;
use brokk_bifrost_core::analyzer::model::ProjectFile;
use brokk_bifrost_core::analyzer::project::{Project, ProjectSourceSnapshot};
use brokk_bifrost_rust::cargo_config::acquired::{
    RustCargoAcquiredConfigView, RustCargoConfigRead, RustCargoConfigReadFailure as Failure,
    RustCargoConfigReadState as State, RustCargoLocalInputRef, RustCargoLocalLayerRef,
};
use brokk_bifrost_rust::cargo_config::{RustCargoConfigDocument, RustCargoConfiguration};

pub(crate) struct CargoConfigurationAcquisition {
    pub view: RustCargoAcquiredConfigView,
    pub configuration: RustCargoConfiguration,
    pub external_reads: Vec<ExternalDiscoveryRead>,
    /// Existing local snapshot retention owns these bytes, including includes.
    /// External bytes are never placed here.
    pub local: BTreeMap<PathBuf, (ProjectSourceSnapshot, bool)>,
}

struct Admission<'a> {
    project: &'a dyn Project,
    limits: &'a DependencyPackLimits,
    bytes: u64,
    files: usize,
    external_reads: Vec<ExternalDiscoveryRead>,
    supplied: BTreeMap<PathBuf, ProjectSourceSnapshot>,
    cache: BTreeMap<PathBuf, Result<Option<RustCargoConfigDocument>, Failure>>,
    view: RustCargoAcquiredConfigView,
    local: BTreeMap<PathBuf, (ProjectSourceSnapshot, bool)>,
}

impl Admission<'_> {
    fn external(&mut self, read: ExternalDiscoveryRead) {
        report_external_discovery_read(read.clone());
        self.external_reads.push(read);
    }
    fn failure(&mut self, label: &str, reason: Failure) {
        brokk_bifrost_analysis::analyzer::dependency_support::refuse_external_discovery_reads();
        self.view.complete = false;
        self.view.reads.push(RustCargoConfigRead {
            label: label.into(),
            state: State::Unavailable { reason },
        });
    }

    fn read(
        &mut self,
        path: &Path,
        label: &str,
    ) -> Result<Option<RustCargoConfigDocument>, Failure> {
        // The existing dependency discovery file and total artifact-byte budgets
        // govern config layers/includes too (DependencyPackLimits); no new cap.
        if self.files >= self.limits.max_source_files_per_artifact {
            self.failure(label, Failure::SourceFilesLimit);
            return Err(Failure::SourceFilesLimit);
        }
        self.files += 1;
        if let Some(cached) = self.cache.get(path) {
            return cached.clone();
        }
        let total_remaining = self
            .limits
            .max_total_artifact_bytes
            .saturating_sub(self.bytes);
        let remaining = total_remaining.min(self.limits.producer.max_artifact_bytes);
        let byte_limit = if remaining == total_remaining {
            Failure::TotalBytesLimit
        } else {
            Failure::FileBytesLimit
        };
        let result = if let Ok(relative) = path.strip_prefix(self.project.root()) {
            let canonical_root = std::fs::canonicalize(self.project.root())
                .unwrap_or_else(|_| self.project.root().into());
            // The lexical strip_prefix above already establishes containment.
            // Canonicalization resolves a symlinked root and, on Windows,
            // returns a verbatim (`\\?\`) spelling. An absent candidate has no
            // canonical target, so comparing its lexical spelling against the
            // canonical root would report every absent `.cargo/config` as an
            // escape. Only a successful canonicalization can prove an escape.
            let canonical = std::fs::canonicalize(path);
            if canonical
                .as_ref()
                .is_ok_and(|physical| !physical.starts_with(&canonical_root))
            {
                self.failure(label, Failure::OutsideInclude);
                return Err(Failure::OutsideInclude);
            }
            if let Some(snapshot) = self.supplied.get(relative).cloned() {
                if snapshot.source().len() as u64 > remaining {
                    Err(byte_limit)
                } else {
                    let bytes = snapshot.source().as_bytes().to_vec();
                    if git2::Oid::hash_object(git2::ObjectType::Blob, &bytes).ok()
                        != Some(snapshot.oid())
                    {
                        Err(Failure::Malformed)
                    } else {
                        self.local.insert(relative.to_path_buf(), (snapshot, true));
                        Ok(Some(bytes))
                    }
                }
            } else {
                // Read the already-contained canonical path, avoiding a second
                // traversal through a symlink that can change after admission.
                let physical = canonical
                    .as_ref()
                    .ok()
                    .and_then(|physical| physical.strip_prefix(&canonical_root).ok())
                    .unwrap_or(relative);
                let file = ProjectFile::new(self.project.root(), physical);
                self.project
                    .has_exact_directory_entry(&file)
                    .or_else(|error| {
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                        ) {
                            Ok(false)
                        } else {
                            Err(error)
                        }
                    })
                    .map_err(|_| Failure::Unreadable)
                    .and_then(|exists| {
                        if !exists {
                            self.local.insert(
                                relative.to_path_buf(),
                                (ProjectSourceSnapshot::disk(String::new()), false),
                            );
                            Ok(None)
                        } else {
                            self.project
                                .read_source_snapshot_limited(
                                    &file,
                                    usize::try_from(remaining).unwrap_or(usize::MAX),
                                )
                                .map_err(|_| Failure::Unreadable)
                                .and_then(|snapshot| snapshot.ok_or(byte_limit))
                                .and_then(|snapshot| {
                                    let bytes = snapshot.source().as_bytes().to_vec();
                                    if git2::Oid::hash_object(git2::ObjectType::Blob, &bytes).ok()
                                        != Some(snapshot.oid())
                                    {
                                        return Err(Failure::Malformed);
                                    }
                                    self.local.insert(relative.to_path_buf(), (snapshot, true));
                                    Ok(Some(bytes))
                                })
                        }
                    })
            }
        } else {
            match std::fs::File::open(path) {
                Ok(file) => {
                    let mut bytes = Vec::new();
                    file.take(remaining.saturating_add(1))
                        .read_to_end(&mut bytes)
                        .map_err(|_| Failure::Unreadable)
                        .and_then(|_| {
                            if bytes.len() as u64 > remaining {
                                Err(byte_limit)
                            } else {
                                self.external(ExternalDiscoveryRead::file(path, &bytes));
                                Ok(Some(bytes))
                            }
                        })
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    self.external(ExternalDiscoveryRead::AbsentFile {
                        absolute_path: path.into(),
                    });
                    Ok(None)
                }
                Err(_) => Err(Failure::Unreadable),
            }
        };
        let document = match result {
            Ok(Some(bytes)) => {
                self.bytes = self.bytes.saturating_add(bytes.len() as u64);
                self.view.reads.push(RustCargoConfigRead {
                    label: label.into(),
                    state: State::File {
                        sha256: sha256_bytes(&bytes),
                        bytes: bytes.len() as u64,
                    },
                });
                RustCargoConfigDocument::from_source_bytes(&bytes)
                    .map(Some)
                    .map_err(|_| Failure::Malformed)
            }
            Ok(None) => {
                self.view.reads.push(RustCargoConfigRead {
                    label: label.into(),
                    state: State::Absent,
                });
                Ok(None)
            }
            Err(reason) => Err(reason),
        };
        if let Err(reason) = document {
            self.failure(label, reason);
        }
        self.cache.insert(path.into(), document.clone());
        document
    }

    /// Iterative postorder keeps hostile include nesting off the Rust call stack.
    /// Each frame owns flat documents; the reader also flattens nested layers.
    fn layer(
        &mut self,
        path: PathBuf,
        label: String,
        domain: &Path,
    ) -> Option<(RustCargoConfigDocument, Vec<RustCargoLocalLayerRef>)> {
        struct Frame {
            path: PathBuf,
            label: String,
            document: RustCargoConfigDocument,
            specs: Vec<brokk_bifrost_rust::cargo_config::RustCargoConfigInclude>,
            children: Vec<Option<(PathBuf, RustCargoConfigDocument)>>,
            local: Vec<RustCargoLocalLayerRef>,
        }
        let workspace_domain = std::fs::canonicalize(self.project.root())
            .unwrap_or_else(|_| self.project.root().into());
        let first = self.read(&path, &label).ok()??;
        let specs = match first.include_specs() {
            Ok(specs) => specs,
            Err(_) => {
                self.failure(&label, Failure::Unclassifiable);
                return None;
            }
        };
        let mut active =
            BTreeSet::from([std::fs::canonicalize(&path).unwrap_or_else(|_| path.clone())]);
        let mut frames = vec![Frame {
            path,
            label,
            document: first,
            specs,
            children: Vec::new(),
            local: Vec::new(),
        }];
        loop {
            let frame = frames.last_mut()?;
            if frame.children.len() == frame.specs.len() {
                let Frame {
                    path,
                    label,
                    document,
                    children,
                    mut local,
                    ..
                } = frames.pop()?;
                let resolved = match document.with_included_documents(children) {
                    Ok(document) => document,
                    Err(_) => {
                        self.failure(&label, Failure::MissingRequiredInclude);
                        return None;
                    }
                };
                active.remove(&std::fs::canonicalize(&path).unwrap_or_else(|_| path.clone()));
                let base = if let Ok(relative) = path.strip_prefix(self.project.root()) {
                    // Cargo's config-relative paths use two levels above
                    // the defining file, including arbitrary config filenames:
                    // https://doc.rust-lang.org/cargo/reference/config.html#config-relative-paths
                    let base = relative
                        .parent()
                        .and_then(Path::parent)
                        .unwrap_or(Path::new(""));
                    local.push(RustCargoLocalLayerRef {
                        path: relative.into(),
                        base: base.into(),
                    });
                    base.to_path_buf()
                } else {
                    PathBuf::new()
                };
                if let Some(parent) = frames.last_mut() {
                    parent.children.push(Some((base, resolved)));
                    parent.local.extend(local);
                } else {
                    return Some((resolved, local));
                }
                continue;
            }
            let index = frame.children.len();
            let spec = &frame.specs[index];
            let next = frame
                .path
                .parent()
                .unwrap_or(Path::new("/"))
                .join(&spec.path)
                .normalize();
            let label = format!("{}/include[{index}]", frame.label);
            // Canonicalize BEFORE content acquisition, even for absolute includes.
            // Missing optional includes must still have a contained parent.
            let canonical = std::fs::canonicalize(&next);
            let contained = canonical
                .as_ref()
                .is_ok_and(|path| path.starts_with(domain) || path.starts_with(&workspace_domain))
                || (canonical
                    .as_ref()
                    .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
                    && next
                        .parent()
                        .and_then(|parent| std::fs::canonicalize(parent).ok())
                        .is_some_and(|parent| {
                            parent.starts_with(domain) || parent.starts_with(&workspace_domain)
                        }));
            if !contained {
                self.failure(&label, Failure::OutsideInclude);
                return None;
            }
            let key = canonical.unwrap_or_else(|_| next.clone());
            if active.contains(&key) {
                self.failure(&label, Failure::CyclicInclude);
                return None;
            }
            match self.read(&next, &label) {
                Ok(None) if spec.optional => frame.children.push(None),
                Ok(Some(document)) => {
                    let specs = match document.include_specs() {
                        Ok(specs) => specs,
                        Err(_) => {
                            self.failure(&label, Failure::Unclassifiable);
                            return None;
                        }
                    };
                    active.insert(key);
                    frames.push(Frame {
                        path: next,
                        label,
                        document,
                        specs,
                        children: Vec::new(),
                        local: Vec::new(),
                    });
                }
                Ok(None) => {
                    self.failure(&label, Failure::MissingRequiredInclude);
                    return None;
                }
                Err(_) => return None,
            }
        }
    }
}

/// `home` is the fixed Cargo-home location acquired by the caller, with its
/// HOME/CARGO_HOME read receipts. Tests inject it without changing process env.
/// A missing home identity is incomplete, rather than presumed empty.
pub(crate) fn acquire_with_home(
    project: &dyn Project,
    selected: &[(ProjectFile, ProjectSourceSnapshot)],
    limits: &DependencyPackLimits,
    home: Option<&Path>,
    environment_reads: Vec<RustCargoConfigRead>,
) -> CargoConfigurationAcquisition {
    let mut admission = Admission {
        project,
        limits,
        bytes: 0,
        files: 0,
        external_reads: Vec::new(),
        supplied: selected
            .iter()
            .map(|(file, snapshot)| (file.rel_path().to_path_buf(), snapshot.clone()))
            .collect(),
        cache: BTreeMap::new(),
        view: RustCargoAcquiredConfigView {
            host_triple: brokk_bifrost_rust::cargo_config::host_target_triple().to_owned(),
            complete: true,
            reads: environment_reads,
            ..Default::default()
        },
        local: BTreeMap::new(),
    };
    let root = project.root();
    let domain = std::fs::canonicalize(root).unwrap_or_else(|_| root.into());
    let mut base = Vec::new();
    let mut locals = BTreeMap::new();
    let mut refs = BTreeMap::<PathBuf, Vec<RustCargoLocalLayerRef>>::new();
    let mut locations = Vec::new();
    // Cargo resolves a relative CARGO_HOME against its invocation directory.
    // Resolve without requiring the home to exist, so absence remains observable.
    let home = home.and_then(|path| std::path::absolute(path).ok());
    if let Some(home) = home.as_deref() {
        locations.push((
            home.to_path_buf(),
            "cargo-home".to_owned(),
            std::fs::canonicalize(home).unwrap_or_else(|_| home.into()),
        ));
    } else {
        admission.failure("cargo-home", Failure::UnknownHome);
    }
    for (index, ancestor) in root
        .ancestors()
        .skip(1)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .enumerate()
    {
        locations.push((
            ancestor.join(".cargo"),
            format!("ancestor[{index}]"),
            domain.clone(),
        ));
    }
    let mut owners = BTreeSet::from([PathBuf::new()]);
    for (file, _) in selected {
        if file
            .rel_path()
            .file_name()
            .is_some_and(|name| name == "Cargo.toml")
        {
            owners.insert(
                file.rel_path()
                    .parent()
                    .unwrap_or(Path::new(""))
                    .to_path_buf(),
            );
        }
    }
    let directories = owners
        .iter()
        .flat_map(|owner| owner.ancestors().map(Path::to_path_buf))
        .collect::<BTreeSet<_>>();
    for directory in &directories {
        locations.push((
            root.join(directory).join(".cargo"),
            format!("workspace/{}", directory.display()),
            domain.clone(),
        ));
    }
    // Cargo-home can coincide with a searched `.cargo` location: do not apply
    // its arrays twice. The directory hierarchy wins its more-specific position.
    let mut used = BTreeSet::new();
    locations.reverse();
    locations.retain(|(path, _, _)| used.insert(path.clone()));
    locations.reverse();
    for (location, label, include_domain) in locations {
        let legacy = location.join("config");
        let modern = location.join("config.toml");
        // An existing legacy file masks the modern file entirely, including
        // malformed content. Its recorded presence already binds that choice.
        let old = admission.read(&legacy, &format!("{label}/config"));
        let chosen = match old {
            Ok(Some(_)) => Some(legacy),
            Ok(None) => admission
                .read(&modern, &format!("{label}/config.toml"))
                .ok()
                .flatten()
                .map(|_| modern),
            Err(_) => None,
        };
        let Some(path) = chosen else {
            continue;
        };
        let Some((document, local_refs)) =
            admission.layer(path.clone(), format!("{label}/selected"), &include_domain)
        else {
            continue;
        };
        if let Ok(relative) = path.strip_prefix(root) {
            let directory = relative
                .parent()
                .and_then(Path::parent)
                .unwrap_or(Path::new(""));
            refs.insert(directory.into(), local_refs);
            locals.insert(relative.into(), document);
        } else {
            base.push((PathBuf::from(label), document));
        }
    }
    if !admission
        .external_reads
        .iter()
        .all(ExternalDiscoveryRead::still_matches)
    {
        admission.failure("external-revalidation", Failure::ChangedDuringAcquisition);
    }
    let configuration = RustCargoConfiguration::from_files(locals)
        .with_base_layers(base)
        .with_acquisition_complete(admission.view.complete);
    // Owners with the same deepest local layer have the same interpretation.
    // Evaluate that prefix once: a large workspace must not re-walk a shared
    // include tree for every member. Only typed facts are cloned per owner.
    let mut prefixes = BTreeMap::new();
    for owner in owners {
        let prefix = owner
            .ancestors()
            .find(|directory| refs.contains_key(*directory))
            .unwrap_or(Path::new(""))
            .to_path_buf();
        let facts = prefixes.entry(prefix.clone()).or_insert_with(|| {
            let local_layers = prefix
                .ancestors()
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .flat_map(|directory| refs.get(directory).into_iter().flatten().cloned())
                .collect();
            configuration.acquired_owner_facts(&prefix, prefix.clone(), local_layers)
        });
        let mut facts = facts.clone();
        facts.workspace = owner.clone();
        admission.view.owners.insert(owner, facts);
    }
    admission.view.local_inputs = admission
        .local
        .iter()
        .map(|(path, (snapshot, present))| {
            (
                path.clone(),
                RustCargoLocalInputRef {
                    oid: snapshot.oid(),
                    present: Some(*present),
                },
            )
        })
        .collect();
    // Discard parsed external documents at this boundary. Every downstream
    // consumer, including global stdlib selection, sees this ONE recorded view.
    let configuration = RustCargoConfiguration::from_acquired_view(
        &admission.view,
        admission.local.iter().map(|(path, (source, present))| {
            (
                path.as_path(),
                source.oid(),
                Some(*present),
                source.source().as_bytes(),
            )
        }),
    );
    CargoConfigurationAcquisition {
        view: admission.view,
        configuration,
        local: admission.local,
        external_reads: admission.external_reads,
    }
}

pub(crate) fn acquire(
    project: &dyn Project,
    selected: &[(ProjectFile, ProjectSourceSnapshot)],
    limits: &DependencyPackLimits,
) -> CargoConfigurationAcquisition {
    acquire_from_environment(
        project,
        selected,
        limits,
        if cfg!(windows) { "USERPROFILE" } else { "HOME" },
    )
}

fn acquire_from_environment(
    project: &dyn Project,
    selected: &[(ProjectFile, ProjectSourceSnapshot)],
    limits: &DependencyPackLimits,
    home_name: &'static str,
) -> CargoConfigurationAcquisition {
    let mut reads = Vec::new();
    let cargo_home = std::env::var_os("CARGO_HOME");
    let home = std::env::var_os(home_name);
    // Cargo treats an empty CARGO_HOME as unset. Keep the original value in
    // the receipt so a later nonempty override invalidates this selection.
    let explicit = cargo_home.as_ref().filter(|value| !value.is_empty());
    let location = explicit.map(PathBuf::from).or_else(|| {
        home.as_ref()
            .filter(|value| !value.is_empty())
            .map(|home| PathBuf::from(home).join(".cargo"))
    });
    let relative_home = location.as_ref().is_some_and(|path| path.is_relative());
    let working_directory = relative_home
        .then(std::env::current_dir)
        .and_then(Result::ok);
    let mut external_environment = Vec::new();
    for (name, value) in [("CARGO_HOME", &cargo_home), (home_name, &home)] {
        let selected_home = if explicit.is_some() {
            name == "CARGO_HOME"
        } else {
            name == home_name
        };
        let directory = selected_home.then(|| working_directory.clone()).flatten();
        let receipt = ExternalDiscoveryRead::Environment {
            name: name.into(),
            value: value.clone(),
            working_directory: directory.clone(),
        };
        report_external_discovery_read(receipt.clone());
        external_environment.push(receipt);
        reads.push(RustCargoConfigRead {
            label: format!("environment/{name}"),
            state: State::Environment {
                value_sha256: value
                    .as_ref()
                    .map(|value| sha256_bytes(value.as_encoded_bytes())),
                working_directory_sha256: directory
                    .as_ref()
                    .map(|directory| sha256_bytes(directory.as_os_str().as_encoded_bytes())),
            },
        });
    }
    let location = location.and_then(|path| {
        if path.is_absolute() {
            Some(path)
        } else {
            working_directory
                .as_ref()
                .map(|directory| directory.join(path))
        }
    });
    let mut acquired = acquire_with_home(project, selected, limits, location.as_deref(), reads);
    if !external_environment
        .iter()
        .all(ExternalDiscoveryRead::still_matches)
    {
        brokk_bifrost_analysis::analyzer::dependency_support::refuse_external_discovery_reads();
        acquired.view.complete = false;
        for facts in acquired.view.owners.values_mut() {
            facts.complete = false;
        }
        acquired.configuration = acquired.configuration.with_acquisition_complete(false);
    }
    acquired.external_reads.extend(external_environment);
    acquired
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_core::analyzer::Language;
    use brokk_bifrost_core::analyzer::project::TestProject;
    use brokk_bifrost_rust::cargo_config::{RustCargoConfigSourceEffect, RustStdlibBuildMode};
    use brokk_bifrost_test_macros::hardwon;

    fn put(root: &Path, path: &str, source: &str) {
        let path = root.join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, source).unwrap();
    }
    fn fixture() -> (tempfile::TempDir, TestProject, PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("workspace");
        std::fs::create_dir_all(&root).unwrap();
        put(
            &root,
            "Cargo.toml",
            "[package]\nname='example'\nversion='0.1.0'\n",
        );
        let home = temp.path().join("cargo-home");
        std::fs::create_dir_all(&home).unwrap();
        (temp, TestProject::new(root, Language::Rust), home)
    }
    fn capture(project: &dyn Project, home: &Path) -> CargoConfigurationAcquisition {
        let file = ProjectFile::new(project.root(), "Cargo.toml");
        let selected = vec![(file.clone(), project.read_source_snapshot(&file).unwrap())];
        acquire_with_home(
            project,
            &selected,
            &DependencyPackLimits::default(),
            Some(home),
            Vec::new(),
        )
    }
    fn replay(capture: &CargoConfigurationAcquisition) -> RustCargoConfiguration {
        RustCargoConfiguration::from_acquired_view(
            &capture.view,
            capture.local.iter().map(|(path, (source, present))| {
                (
                    path.as_path(),
                    source.oid(),
                    Some(*present),
                    source.source().as_bytes(),
                )
            }),
        )
    }

    #[test]
    fn no_config_is_complete_and_recorded_absences_replay() {
        let (_temp, project, home) = fixture();
        let acquired = capture(&project, &home);
        assert!(acquired.view.complete);
        assert_eq!(
            acquired.configuration.source_effect(Path::new("")),
            RustCargoConfigSourceEffect::Preserves
        );
        assert_eq!(
            replay(&acquired).stdlib_build_mode(Path::new("")),
            RustStdlibBuildMode::Prebuilt
        );
        let mut missing = acquired.view.clone();
        missing.local_inputs.values_mut().next().unwrap().present = None;
        assert_eq!(
            RustCargoConfiguration::from_acquired_view(
                &missing,
                acquired.local.iter().map(|(path, (source, present))| (
                    path.as_path(),
                    source.oid(),
                    Some(*present),
                    source.source().as_bytes()
                ))
            )
            .stdlib_build_mode(Path::new("")),
            RustStdlibBuildMode::Unknown
        );
    }
    #[cfg(unix)]
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#12649: an absent Cargo config under a symlinked temp root was reported outside the workspace"
    )]
    fn symlinked_workspace_root_records_absent_layers_and_reads_the_selected_config() {
        let temp = tempfile::tempdir().unwrap();
        let physical = temp.path().join("physical");
        let workspace = physical.join("workspace");
        std::fs::create_dir_all(&workspace).unwrap();
        put(
            &workspace,
            "Cargo.toml",
            "[package]\nname='example'\nversion='0.1.0'\n",
        );
        put(
            &workspace,
            ".cargo/config.toml",
            "[build]\ntarget='aarch64-unknown-linux-gnu'\n",
        );
        let home = temp.path().join("cargo-home");
        std::fs::create_dir_all(&home).unwrap();
        let linked = temp.path().join("linked");
        std::os::unix::fs::symlink(&physical, &linked).unwrap();
        let project = TestProject::new(linked.join("workspace"), Language::Rust);
        let acquired = capture(&project, &home);
        assert!(acquired.view.complete);
        assert_eq!(
            acquired
                .configuration
                .configured_build_targets(Path::new(""))
                .0,
            vec!["aarch64-unknown-linux-gnu"]
        );
        assert_eq!(
            acquired
                .local
                .get(Path::new(".cargo/config"))
                .map(|(_, present)| *present),
            Some(false)
        );
        assert_eq!(
            acquired
                .local
                .get(Path::new(".cargo/config.toml"))
                .map(|(_, present)| *present),
            Some(true)
        );
        assert_eq!(
            replay(&acquired).stdlib_build_mode(Path::new("")),
            RustStdlibBuildMode::Prebuilt
        );
    }

    /// An absent `.cargo/config` has no canonical target. A workspace root
    /// whose lexical spelling differs from its canonical spelling (a symlink
    /// here, a Windows verbatim `\\?\` prefix in production) must still record
    /// the absence instead of reporting an escape that makes every Cargo fact
    /// incomplete.
    #[cfg(unix)]
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#12753: an absent Cargo config under a non-canonical root was reported outside the include"
    )]
    fn non_canonical_workspace_root_records_absent_config_as_absent() {
        let temp = tempfile::tempdir().unwrap();
        let real = temp.path().join("real");
        std::fs::create_dir_all(&real).unwrap();
        put(
            &real,
            "Cargo.toml",
            "[package]\nname='example'\nversion='0.1.0'\n",
        );
        let linked = temp.path().join("linked");
        std::os::unix::fs::symlink(&real, &linked).unwrap();
        let project = TestProject::new(linked, Language::Rust);
        let home = temp.path().join("cargo-home");
        std::fs::create_dir_all(&home).unwrap();

        let acquired = capture(&project, &home);

        assert!(acquired.view.complete, "{:?}", acquired.view.reads);
        assert_eq!(
            acquired
                .local
                .get(Path::new(".cargo/config"))
                .map(|(_, present)| *present),
            Some(false),
            "an absent config must still be recorded: {:?}",
            acquired.view.reads
        );
        assert!(
            !acquired.view.reads.iter().any(|read| matches!(
                read.state,
                State::Unavailable {
                    reason: Failure::OutsideInclude
                }
            )),
            "an absent config is not an escape: {:?}",
            acquired.view.reads
        );
    }

    #[test]
    fn ancestor_and_home_layers_are_in_the_record_without_text_or_home_paths() {
        let (temp, project, home) = fixture();
        put(
            temp.path(),
            ".cargo/config.toml",
            "[build]\ntarget='aarch64-unknown-linux-gnu'\n",
        );
        put(
            &home,
            "config.toml",
            "[http]\nproxy='SECRET_TOKEN_12398'\n[unstable]\nbuild-std=['std']\n",
        );
        let acquired = capture(&project, &home);
        assert_eq!(
            acquired
                .configuration
                .configured_build_targets(Path::new(""))
                .0,
            vec!["aarch64-unknown-linux-gnu"]
        );
        assert_eq!(
            replay(&acquired).stdlib_build_mode(Path::new("")),
            RustStdlibBuildMode::BuildStd
        );
        assert!(
            acquired
                .view
                .reads
                .iter()
                .any(|read| read.label.starts_with("ancestor[")
                    && matches!(read.state, State::File { .. }))
        );
        let text = format!("{:?}", acquired.view);
        assert!(!text.contains("SECRET_TOKEN_12398"));
        assert!(!text.contains(home.to_str().unwrap()));
        assert!(acquired.local.keys().all(|path| !path.is_absolute()));
        assert!(
            acquired
                .local
                .values()
                .all(|(snapshot, _)| !snapshot.source().contains("SECRET_TOKEN_12398"))
        );
    }
    #[test]
    fn included_sources_and_rustflags_survive_pure_replay() {
        let (_temp, project, home) = fixture();
        put(
            project.root(),
            ".cargo/config.toml",
            "include='overrides.toml'\n",
        );
        put(
            project.root(),
            ".cargo/overrides.toml",
            "[source.crates-io]\nreplace-with='private'\n[build]\nrustflags=['--cfg','included_flag','--extern=extra']\n",
        );
        let acquired = capture(&project, &home);
        let reader = replay(&acquired);
        assert_eq!(
            reader.source_effect(Path::new("")),
            RustCargoConfigSourceEffect::Changes
        );
        assert!(reader.cfg_atoms(Path::new("")).contains("included_flag"));
        assert!(reader.has_extern_flags(Path::new("")));
        assert!(
            acquired
                .view
                .local_inputs
                .contains_key(Path::new(".cargo/overrides.toml"))
        );
    }
    #[test]
    fn outside_include_is_not_read_and_withdraws_prebuilt_mode() {
        let (temp, project, home) = fixture();
        put(
            temp.path(),
            "outside.toml",
            "[unstable]\nbuild-std=['std']\n",
        );
        put(
            project.root(),
            ".cargo/config.toml",
            "include='../../outside.toml'\n",
        );
        let acquired = capture(&project, &home);
        assert!(!acquired.view.complete);
        assert_eq!(
            replay(&acquired).stdlib_build_mode(Path::new("")),
            RustStdlibBuildMode::Unknown
        );
        assert!(!acquired.view.reads.iter().any(
            |read| read.label.contains("include[") && matches!(read.state, State::File { .. })
        ));
    }
    #[cfg(unix)]
    #[test]
    fn symlink_include_escape_is_not_read() {
        let (temp, project, home) = fixture();
        put(
            temp.path(),
            "outside.toml",
            "[unstable]\nbuild-std=['std']\n",
        );
        put(
            project.root(),
            ".cargo/config.toml",
            "include='link.toml'\n",
        );
        std::os::unix::fs::symlink(
            temp.path().join("outside.toml"),
            project.root().join(".cargo/link.toml"),
        )
        .unwrap();
        let acquired = capture(&project, &home);
        assert!(!acquired.view.complete);
        assert!(!acquired.local.contains_key(Path::new(".cargo/link.toml")));
    }
    #[test]
    fn unreadable_home_never_becomes_prebuilt_and_cycle_is_bounded() {
        let (_temp, project, home) = fixture();
        std::fs::create_dir(home.join("config")).unwrap();
        let acquired = capture(&project, &home);
        assert_eq!(
            acquired.configuration.stdlib_build_mode(Path::new("")),
            RustStdlibBuildMode::Unknown
        );
        std::fs::remove_dir(home.join("config")).unwrap();
        put(
            project.root(),
            ".cargo/config.toml",
            "include='config.toml'\n",
        );
        let acquired = capture(&project, &home);
        assert!(!acquired.view.complete);
        assert!(acquired.view.reads.iter().any(|read| matches!(
            read.state,
            State::Unavailable {
                reason: Failure::CyclicInclude
            }
        )));
    }
    #[test]
    fn same_revision_home_edit_changes_input_digest_and_pure_snapshot_stays_frozen() {
        let (_temp, project, home) = fixture();
        let before = capture(&project, &home);
        put(&home, "config.toml", "[unstable]\nbuild-std=['std']\n");
        let after = capture(&project, &home);
        assert_ne!(before.view.digest(), after.view.digest());
        assert_eq!(
            replay(&before).stdlib_build_mode(Path::new("")),
            RustStdlibBuildMode::Prebuilt
        );
        assert_eq!(
            replay(&after).stdlib_build_mode(Path::new("")),
            RustStdlibBuildMode::BuildStd
        );
    }
    #[test]
    fn existing_acquisition_budgets_report_named_causes_and_unknown_mode() {
        let (_temp, project, home) = fixture();
        let file = ProjectFile::new(project.root(), "Cargo.toml");
        let selected = vec![(file.clone(), project.read_source_snapshot(&file).unwrap())];
        let file_limit = DependencyPackLimits {
            max_source_files_per_artifact: 0,
            ..Default::default()
        };
        let captured = acquire_with_home(&project, &selected, &file_limit, Some(&home), Vec::new());
        assert_eq!(
            captured.configuration.stdlib_build_mode(Path::new("")),
            RustStdlibBuildMode::Unknown
        );
        assert!(captured.view.reads.iter().any(|read| matches!(
            read.state,
            State::Unavailable {
                reason: Failure::SourceFilesLimit
            }
        )));
        assert_eq!(
            Failure::SourceFilesLimit.label(),
            "max_source_files_per_artifact"
        );
        put(&home, "config.toml", "[unstable]\nbuild-std=['std']\n");
        let byte_limit = DependencyPackLimits {
            max_total_artifact_bytes: 1,
            ..Default::default()
        };
        let captured = acquire_with_home(&project, &selected, &byte_limit, Some(&home), Vec::new());
        assert_eq!(
            captured.configuration.stdlib_build_mode(Path::new("")),
            RustStdlibBuildMode::Unknown
        );
        assert!(captured.view.reads.iter().any(|read| matches!(
            read.state,
            State::Unavailable {
                reason: Failure::TotalBytesLimit
            }
        )));
        assert_eq!(Failure::TotalBytesLimit.label(), "max_total_artifact_bytes");
    }
    #[test]
    fn same_revision_home_edit_refreshes_store_reader_and_withdraws_feature_projections() {
        use brokk_bifrost_analysis::analyzer::store::{
            AnalyzerStore, WorkspaceConfigurationInput, WorkspaceId,
        };
        let (_temp, project, home) = fixture();
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let generation = store
            .ensure_language_epoch_value("rust", "12398-acquired-config")
            .unwrap();
        let workspace = WorkspaceId("c".repeat(64));
        let sync = |acquired: CargoConfigurationAcquisition| {
            let mut inputs = acquired
                .local
                .into_iter()
                .map(|(path, (source, present))| {
                    let path = path.to_string_lossy().into_owned();
                    if present {
                        WorkspaceConfigurationInput::new(path, source.source().as_bytes().into())
                    } else {
                        WorkspaceConfigurationInput::absent(path)
                    }
                })
                .collect::<Vec<_>>();
            inputs.push(WorkspaceConfigurationInput::new(
                "Cargo.toml".into(),
                std::fs::read(project.root().join("Cargo.toml"))
                    .unwrap()
                    .into(),
            ));
            inputs.sort_by(|left, right| left.relative_path().cmp(right.relative_path()));
            WorkspaceConfigurationInput::attach_rust_cargo_acquisition(&mut inputs, acquired.view);
            store
                .sync_workspace_inputs_for_workspace(
                    &workspace,
                    "rust",
                    generation,
                    &[],
                    &[],
                    &[],
                    &[],
                    &[],
                    &[],
                    &inputs,
                    &[],
                    &[],
                )
                .unwrap()
        };
        let before = sync(capture(&project, &home));
        assert_eq!(
            store
                .selected_rust_cargo_configuration(&before)
                .unwrap()
                .stdlib_build_mode(Path::new("")),
            RustStdlibBuildMode::Prebuilt
        );
        let snapshot = before.clone();
        store.conn.execute_fixture(move |conn| -> brokk_bifrost_analysis::analyzer::store::Result<()> {
            conn.execute("INSERT INTO rust_crate_reconciliations VALUES(?1,?2,?3,?4)",rusqlite::params![snapshot.workspace_id.as_str(),snapshot.generation.get(),snapshot.revision,[1u8;32].as_slice()])?;
            conn.execute("INSERT INTO rust_feature_discoveries VALUES(?1,?2,?3,?4)",rusqlite::params![snapshot.workspace_id.as_str(),snapshot.generation.get(),[2u8;32].as_slice(),snapshot.revision])?;
            conn.execute("INSERT INTO rust_feature_projections VALUES(?1,?2,?3,?4,?5,1,NULL,'Cargo.toml','')",rusqlite::params![snapshot.workspace_id.as_str(),snapshot.generation.get(),[2u8;32].as_slice(),[3u8;32].as_slice(),[4u8;32].as_slice()])?;
            Ok(())
        }).unwrap();
        put(&home, "config.toml", "[unstable]\nbuild-std=['std']\n");
        let after = sync(capture(&project, &home));
        assert_eq!(
            before.revision, after.revision,
            "repository inputs did not change"
        );
        assert_eq!(
            store
                .selected_rust_cargo_configuration(&after)
                .unwrap()
                .stdlib_build_mode(Path::new("")),
            RustStdlibBuildMode::BuildStd
        );
        let conn = store.read_conn().unwrap();
        let certificates: i64 = conn
            .query_row(
                "SELECT count(*) FROM rust_crate_reconciliations",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let projections: i64 = conn
            .query_row("SELECT count(*) FROM rust_feature_projections", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!((certificates, projections), (0, 0));
        let selected:i64=conn.query_row("SELECT count(*) FROM dependency_evidence_selections AS selection JOIN dependency_evidence_sets AS inputs USING(set_id) WHERE inputs.input_digest LIKE 'bifrost.acquired-cargo-config.v2:%'",[],|row|row.get(0)).unwrap();
        assert_eq!(selected, 0, "the one acquired input set remains unselected");
    }
    #[test]
    fn acquired_target_only_view_preserves_pure_exact_lock_association() {
        use brokk_bifrost_analysis::analyzer::store::StoreLanguageSupport;
        let (_temp, project, home) = fixture();
        put(
            project.root(),
            "Cargo.toml",
            "[package]\nname='example'\nversion='0.1.0'\n[dependencies]\ndep='1.0.0'\n",
        );
        put(
            project.root(),
            "Cargo.lock",
            &format!(
                "version=3\n[[package]]\nname='example'\nversion='0.1.0'\ndependencies=['dep']\n[[package]]\nname='dep'\nversion='1.0.0'\nsource='registry+https://github.com/rust-lang/crates.io-index'\nchecksum='{}'\n",
                "a".repeat(64)
            ),
        );
        for config in [None, Some("[build]\ntarget='aarch64-unknown-linux-gnu'\n")] {
            if let Some(source) = config {
                put(project.root(), ".cargo/config.toml", source);
            }
            let acquired = capture(&project, &home);
            let mut selected = acquired
                .local
                .iter()
                .map(|(path, (source, present))| {
                    (
                        ProjectFile::new(project.root(), path),
                        source.clone(),
                        Some(*present),
                    )
                })
                .collect::<Vec<_>>();
            for path in ["Cargo.toml", "Cargo.lock"] {
                let file = ProjectFile::new(project.root(), path);
                selected.push((
                    file.clone(),
                    project.read_source_snapshot(&file).unwrap(),
                    Some(true),
                ));
            }
            let rows = super::super::RustSupport
                .selected_dependency_file_evidence_with_rust_config(
                    project.root(),
                    &selected,
                    Some(&acquired.view),
                    &Default::default(),
                );
            assert!(
                rows.rows.iter().any(|row| row.package == "dep"
                    && row
                        .conditions
                        .iter()
                        .any(|condition| condition.kind == "cargo.lock_association"
                            && condition.value == "exact")),
                "{rows:?}"
            );
        }
    }

    #[test]
    fn legacy_file_masks_malformed_modern_and_malformed_cfg_is_unknown() {
        let (_temp, project, home) = fixture();
        put(
            project.root(),
            ".cargo/config",
            "[build]\ntarget='x86_64-unknown-linux-gnu'\n",
        );
        put(project.root(), ".cargo/config.toml", "malformed=[");
        let acquired = capture(&project, &home);
        assert!(acquired.view.complete);
        assert_eq!(
            replay(&acquired).stdlib_build_mode(Path::new("")),
            RustStdlibBuildMode::Prebuilt
        );
        assert!(!acquired.local.contains_key(Path::new(".cargo/config.toml")));
        std::fs::remove_file(project.root().join(".cargo/config")).unwrap();
        put(
            project.root(),
            ".cargo/config.toml",
            "[build]\nrustflags=['--cfg']\n",
        );
        let acquired = capture(&project, &home);
        assert_eq!(
            replay(&acquired).stdlib_build_mode(Path::new("")),
            RustStdlibBuildMode::Unknown
        );
        assert!(
            replay(&acquired)
                .cfg_atoms(Path::new(""))
                .contains("bifrost_incomplete_features")
        );
    }
    #[test]
    fn overlay_build_std_uses_its_own_record_and_reclaims_it_with_the_lease() {
        use brokk_bifrost_analysis::analyzer::store::{
            AnalyzerStore, WorkspaceConfigurationInput, WorkspaceId, WorkspaceSnapshots,
        };
        use brokk_bifrost_core::analyzer::project::OverlayProject;
        use std::sync::Arc;
        let (_temp, project, home) = fixture();
        let store = Arc::new(AnalyzerStore::open_ephemeral().unwrap());
        let generation = store
            .ensure_language_epoch_value("rust", "12398-overlay-config")
            .unwrap();
        let mut inputs = vec![WorkspaceConfigurationInput::new(
            "Cargo.toml".into(),
            std::fs::read(project.root().join("Cargo.toml"))
                .unwrap()
                .into(),
        )];
        let baseline = capture(&project, &home);
        inputs.extend(baseline.local.into_iter().map(|(path, (source, present))| {
            let path = brokk_bifrost_core::path_utils::workspace_relative_slash_path(&path);
            if present {
                WorkspaceConfigurationInput::new(path, source.source().as_bytes().into())
            } else {
                WorkspaceConfigurationInput::absent(path)
            }
        }));
        WorkspaceConfigurationInput::attach_rust_cargo_acquisition(&mut inputs, baseline.view);
        let snapshot = store
            .sync_workspace_inputs_for_workspace(
                &WorkspaceId("d".repeat(64)),
                "rust",
                generation,
                &[],
                &[],
                &[],
                &[],
                &[],
                &[],
                &inputs,
                &[],
                &[],
            )
            .unwrap();
        let project = Arc::new(project);
        let overlay = OverlayProject::new(project.clone());
        assert!(overlay.set(
            project.root().join(".cargo/config.toml"),
            "[unstable]\nbuild-std=['std']\n".into()
        ));
        let snapshots = WorkspaceSnapshots::from_iter([("rust".to_owned(), snapshot.clone())]);
        let publication =
            brokk_bifrost_analysis::analyzer::store::dependency_file_evidence::publish_overlay(
                &store,
                &snapshots,
                &overlay,
                Language::Rust,
            )
            .unwrap()
            .unwrap();
        let mode = publication
            .acquired_rust_configuration()
            .unwrap()
            .unwrap()
            .stdlib_build_mode(Path::new(""));
        assert_ne!(
            mode,
            RustStdlibBuildMode::Prebuilt,
            "rebuilding std cannot certify a prebuilt artifact, even if external home input is unclassifiable"
        );
        assert_eq!(
            store
                .selected_rust_cargo_configuration(&snapshot)
                .unwrap()
                .stdlib_build_mode(Path::new("")),
            RustStdlibBuildMode::Prebuilt,
            "a sibling's disk selection stays immutable"
        );
        assert!(!publication.cargo_external_reads().is_empty());
        let counts = || {
            let conn = store.read_conn().unwrap();
            conn.query_row("SELECT count(*) FROM dependency_evidence_sets WHERE input_digest LIKE 'bifrost.acquired-cargo-config.v2:%'",[],|row|row.get::<_,i64>(0)).unwrap()
        };
        assert_eq!(counts(), 2);
        drop(publication);
        assert_eq!(
            counts(),
            1,
            "the unselected input set is reclaimed with its request lease"
        );
        store
            .delete_workspace_projection(&snapshot.workspace_id)
            .unwrap();
        assert_eq!(
            counts(),
            0,
            "workspace deletion reclaims its remaining input set"
        );
    }
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#12922: native Windows separators hid the selected Cargo layer from the point reader"
    )]
    fn pure_point_reader_keeps_absent_legacy_absent_and_reads_the_modern_patch() {
        use brokk_bifrost_analysis::analyzer::store::{
            AnalyzerStore, WorkspaceConfigurationInput, WorkspaceId,
        };
        let (_temp, project, home) = fixture();
        put(
            project.root(),
            ".cargo/config.toml",
            "[patch.crates-io]\nlog={path='vendor/log'}\n",
        );
        let acquired = capture(&project, &home);
        assert!(acquired.view.complete, "{:?}", acquired.view);
        let mut inputs = acquired
            .local
            .into_iter()
            .map(|(path, (source, present))| {
                // Configuration inputs are keyed by slash-separated workspace
                // paths. `PathBuf::to_string_lossy` uses native Windows
                // separators, which would hide the layer from the point reader.
                let path = brokk_bifrost_core::path_utils::workspace_relative_slash_path(&path);
                if present {
                    WorkspaceConfigurationInput::new(path, source.source().as_bytes().into())
                } else {
                    WorkspaceConfigurationInput::absent(path)
                }
            })
            .collect::<Vec<_>>();
        inputs.push(WorkspaceConfigurationInput::new(
            "Cargo.toml".into(),
            std::fs::read(project.root().join("Cargo.toml"))
                .unwrap()
                .into(),
        ));
        WorkspaceConfigurationInput::attach_rust_cargo_acquisition(&mut inputs, acquired.view);
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let generation = store
            .ensure_language_epoch_value("rust", "12398-point-reader")
            .unwrap();
        let snapshot = store
            .sync_workspace_inputs_for_workspace(
                &WorkspaceId("e".repeat(64)),
                "rust",
                generation,
                &[],
                &[],
                &[],
                &[],
                &[],
                &[],
                &inputs,
                &[],
                &[],
            )
            .unwrap();
        let conn = store.read_conn().unwrap();
        let reader = AnalyzerStore::rust_selected_cargo_configuration_at_paths(
            &conn,
            &snapshot,
            &[".cargo/config".into(), ".cargo/config.toml".into()],
        )
        .unwrap()
        .unwrap();
        assert!(reader.acquisition_is_complete(Path::new("")));
        assert!(
            !reader.preserves_registry_package(Path::new(""), "log"),
            "the absent legacy placeholder must not mask the modern patch"
        );
    }
    #[test]
    fn windows_userprofile_default_is_complete_and_tracks_freshness() {
        const CHILD: &str = "BIFROST_12398_USERPROFILE_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let (_temp, project, home) = fixture();
            for explicit in [None, Some("")] {
                put(
                    &home,
                    ".cargo/config.toml",
                    "[build]\ntarget='aarch64-unknown-linux-gnu'\nrustflags=['--cfg','profile_flag']\n",
                );
                let mut command = std::process::Command::new(std::env::current_exe().unwrap());
                command.args(["--exact", "analyzer::rust::cargo_configuration_acquisition::tests::windows_userprofile_default_is_complete_and_tracks_freshness", "--nocapture"])
                    .env(CHILD, project.root()).env("USERPROFILE", &home).env_remove("HOME");
                if let Some(value) = explicit {
                    command.env("CARGO_HOME", value);
                } else {
                    command.env_remove("CARGO_HOME");
                }
                let output = command.output().unwrap();
                assert!(
                    output.status.success(),
                    "stdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            return;
        }
        let project = TestProject::new(
            PathBuf::from(std::env::var_os(CHILD).unwrap()),
            Language::Rust,
        );
        let manifest = ProjectFile::new(project.root(), "Cargo.toml");
        let selected = vec![(
            manifest.clone(),
            project.read_source_snapshot(&manifest).unwrap(),
        )];
        // Exercise the exact Windows environment branch on every test host.
        let capture = || {
            acquire_from_environment(
                &project,
                &selected,
                &DependencyPackLimits::default(),
                "USERPROFILE",
            )
        };
        let first = capture();
        assert!(first.view.complete);
        assert_eq!(
            first
                .configuration
                .configured_build_targets(Path::new(""))
                .0,
            vec!["aarch64-unknown-linux-gnu"]
        );
        assert_eq!(
            first.configuration.stdlib_build_mode(Path::new("")),
            RustStdlibBuildMode::Prebuilt
        );
        assert!(first.external_reads.iter().any(|read| matches!(read, ExternalDiscoveryRead::Environment { name, value: Some(_), .. } if name.as_ref() == "USERPROFILE")));
        assert!(
            first
                .external_reads
                .iter()
                .all(ExternalDiscoveryRead::still_matches)
        );
        assert_eq!(first.view.digest(), capture().view.digest());
        let home = PathBuf::from(std::env::var_os("USERPROFILE").unwrap());
        put(
            &home,
            ".cargo/config.toml",
            "[unstable]\nbuild-std=['std']\n",
        );
        assert!(
            !first
                .external_reads
                .iter()
                .all(ExternalDiscoveryRead::still_matches)
        );
        let changed = capture();
        assert_ne!(first.view.digest(), changed.view.digest());
        assert_eq!(
            changed.configuration.stdlib_build_mode(Path::new("")),
            RustStdlibBuildMode::BuildStd
        );
    }

    #[test]
    fn relative_cargo_home_tracks_cwd_and_refreshes_the_warm_analyzer() {
        use brokk_bifrost_analysis::analyzer::IAnalyzer;
        use std::sync::Arc;
        const CHILD: &str = "BIFROST_12398_CARGO_HOME_CWD_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let (temp, project, _) = fixture();
            put(project.root(), "src/lib.rs", "pub fn example() {}\n");
            for (context, target) in [
                ("first", "x86_64-unknown-linux-gnu"),
                ("second", "aarch64-unknown-linux-gnu"),
            ] {
                put(
                    &temp.path().join(context),
                    "cargo-home/config.toml",
                    &format!("[build]\ntarget='{target}'\n"),
                );
            }
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "analyzer::rust::cargo_configuration_acquisition::tests::relative_cargo_home_tracks_cwd_and_refreshes_the_warm_analyzer", "--nocapture"])
                .env(CHILD, project.root())
                .env("BIFROST_12398_CARGO_HOME_SECOND_CWD", temp.path().join("second"))
                .env("CARGO_HOME", "cargo-home")
                .current_dir(temp.path().join("first"))
                .output().unwrap();
            assert!(
                output.status.success(),
                "stdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        // Cwd is process-global: mutate it only inside this one-test subprocess.
        let project = TestProject::new(
            PathBuf::from(std::env::var_os(CHILD).unwrap()),
            Language::Rust,
        );
        let file = ProjectFile::new(project.root(), "Cargo.toml");
        let selected = vec![(file.clone(), project.read_source_snapshot(&file).unwrap())];
        let first = acquire(&project, &selected, &DependencyPackLimits::default());
        let before = super::super::RustAnalyzer::new(Arc::new(project.clone()));
        let read = |analyzer: &super::super::RustAnalyzer| {
            let snapshots = analyzer.inner.selected_workspace_snapshots();
            analyzer
                .inner
                .analyzer_store()
                .selected_rust_cargo_configuration(&snapshots["rust"])
                .unwrap()
                .configured_build_targets(Path::new(""))
                .0
        };
        assert_eq!(read(&before), vec!["x86_64-unknown-linux-gnu"]);
        let environment = first.external_reads.iter().find(|read| matches!(read, ExternalDiscoveryRead::Environment { name, working_directory: Some(_), .. } if name.as_ref() == "CARGO_HOME")).unwrap();
        assert!(environment.still_matches());
        std::env::set_current_dir(std::env::var_os("BIFROST_12398_CARGO_HOME_SECOND_CWD").unwrap())
            .unwrap();
        assert!(!environment.still_matches());
        let second = acquire(&project, &selected, &DependencyPackLimits::default());
        assert!(first.view.complete && second.view.complete);
        assert_ne!(first.view.digest(), second.view.digest());
        let home_read = |view: &RustCargoAcquiredConfigView| {
            view.reads
                .iter()
                .find(|read| read.label == "environment/CARGO_HOME")
                .unwrap()
                .state
                .clone()
        };
        assert_ne!(home_read(&first.view), home_read(&second.view));
        let listing = project.all_files_with_omissions().unwrap();
        let after = before.update_with_listing(&BTreeSet::new(), Some(&listing));
        let fresh = super::super::RustAnalyzer::new(Arc::new(project));
        assert_eq!(read(&after), vec!["aarch64-unknown-linux-gnu"]);
        assert_eq!(read(&after), read(&fresh));
    }

    #[test]
    fn relative_cargo_home_acquires_the_same_target_and_flags_as_absolute_home() {
        let (_temp, project, home) = fixture();
        put(
            &home,
            "config.toml",
            "[build]\ntarget='aarch64-unknown-linux-gnu'\nrustflags=['--cfg','home_flag']\n",
        );
        let cwd = std::env::current_dir().unwrap();
        let common = cwd
            .components()
            .zip(home.components())
            .take_while(|(left, right)| left == right)
            .count();
        assert!(
            common > 0,
            "test home and working directory share a filesystem root"
        );
        let mut relative = PathBuf::new();
        for _ in cwd.components().skip(common) {
            relative.push("..");
        }
        for component in home.components().skip(common) {
            relative.push(component.as_os_str());
        }
        assert!(relative.is_relative());
        let absolute = capture(&project, &home);
        let relative = capture(&project, &relative);
        assert!(relative.view.complete);
        assert_eq!(relative.view.digest(), absolute.view.digest());
        assert_eq!(
            relative
                .configuration
                .configured_build_targets(Path::new(""))
                .0,
            vec!["aarch64-unknown-linux-gnu"]
        );
        assert_eq!(
            relative.configuration.stdlib_build_mode(Path::new("")),
            RustStdlibBuildMode::Prebuilt
        );
    }

    #[test]
    fn optional_include_creation_edit_and_removal_refresh_the_warm_analyzer() {
        use brokk_bifrost_analysis::analyzer::IAnalyzer;
        use std::sync::Arc;
        let (_temp, project, _home) = fixture();
        put(project.root(), "src/lib.rs", "pub fn example() {}\n");
        put(
            project.root(),
            ".cargo/config.toml",
            "include=[{path='../settings/flags.toml',optional=true}]\n",
        );
        std::fs::create_dir_all(project.root().join("settings")).unwrap();
        let mut warm = super::super::RustAnalyzer::new(Arc::new(project.clone()));
        assert!(warm.inner.configuration_acquisition_inputs_complete());
        let read = |analyzer: &super::super::RustAnalyzer| {
            let snapshots = analyzer.inner.selected_workspace_snapshots();
            analyzer
                .inner
                .analyzer_store()
                .selected_rust_cargo_configuration(&snapshots["rust"])
                .unwrap()
                .configured_build_targets(Path::new(""))
                .0
        };
        assert!(read(&warm).is_empty());
        let included = ProjectFile::new(project.root(), "settings/flags.toml");
        for target in [
            Some("aarch64-unknown-linux-gnu"),
            Some("x86_64-unknown-linux-gnu"),
            None,
        ] {
            if let Some(target) = target {
                put(
                    project.root(),
                    "settings/flags.toml",
                    &format!("[build]\ntarget='{target}'\n"),
                );
            } else {
                std::fs::remove_file(included.abs_path()).unwrap();
            }
            warm = warm.update(&BTreeSet::from([included.clone()]));
            let fresh = super::super::RustAnalyzer::new(Arc::new(project.clone()));
            assert_eq!(
                read(&warm),
                target.into_iter().map(str::to_owned).collect::<Vec<_>>()
            );
            assert_eq!(read(&warm), read(&fresh));
        }
    }

    #[test]
    fn repairing_a_missing_include_refreshes_an_empty_warm_update() {
        use brokk_bifrost_analysis::analyzer::IAnalyzer;
        use std::sync::Arc;
        let (_temp, project, _home) = fixture();
        put(project.root(), "src/lib.rs", "pub fn example() {}\n");
        put(
            project.root(),
            ".cargo/config.toml",
            "include='later.toml'\n",
        );
        let before = super::super::RustAnalyzer::new(Arc::new(project.clone()));
        assert!(!before.inner.configuration_acquisition_inputs_complete());
        let read = |analyzer: &super::super::RustAnalyzer| {
            let snapshots = analyzer.inner.selected_workspace_snapshots();
            analyzer
                .inner
                .analyzer_store()
                .selected_rust_cargo_configuration(&snapshots["rust"])
                .unwrap()
                .configured_build_targets(Path::new(""))
                .0
        };
        assert!(read(&before).is_empty());
        put(
            project.root(),
            ".cargo/later.toml",
            "[build]\ntarget='aarch64-unknown-linux-gnu'\n",
        );
        let listing = project.all_files_with_omissions().unwrap();
        let after = before.update_with_listing(&BTreeSet::new(), Some(&listing));
        let fresh = super::super::RustAnalyzer::new(Arc::new(project));
        assert_eq!(read(&after), vec!["aarch64-unknown-linux-gnu"]);
        assert_eq!(read(&after), read(&fresh));
    }
    #[test]
    fn same_revision_external_ancestor_edit_refreshes_the_rust_analyzer() {
        use brokk_bifrost_analysis::analyzer::IAnalyzer;
        use std::sync::Arc;
        let (temp, project, _home) = fixture();
        put(project.root(), "src/lib.rs", "pub fn example() {}\n");
        put(
            temp.path(),
            ".cargo/config.toml",
            "[build]\ntarget='x86_64-unknown-linux-gnu'\n",
        );
        let before = super::super::RustAnalyzer::new(Arc::new(project.clone()));
        let read = |analyzer: &super::super::RustAnalyzer| {
            let snapshots = analyzer.inner.selected_workspace_snapshots();
            let snapshot = snapshots["rust"].clone();
            let targets = analyzer
                .inner
                .analyzer_store()
                .selected_rust_cargo_configuration(&snapshot)
                .unwrap()
                .configured_build_targets(Path::new(""))
                .0;
            (snapshot, targets)
        };
        let (old_snapshot, old_targets) = read(&before);
        assert_eq!(old_targets, vec!["x86_64-unknown-linux-gnu"]);
        put(
            temp.path(),
            ".cargo/config.toml",
            "[build]\ntarget='aarch64-unknown-linux-gnu'\n",
        );
        let listing = project.all_files_with_omissions().unwrap();
        let after = before.update_with_listing(&BTreeSet::new(), Some(&listing));
        let (new_snapshot, new_targets) = read(&after);
        assert_eq!(
            old_snapshot.revision, new_snapshot.revision,
            "an external-only edit keeps the repository revision"
        );
        assert_eq!(new_targets, vec!["aarch64-unknown-linux-gnu"]);
        let fresh = super::super::RustAnalyzer::new(Arc::new(project));
        assert_eq!(new_targets, read(&fresh).1);
    }

    /// A warm update rebuilds on a configuration edit only when the acquired
    /// configuration's meaning changes. A comment, an alias or an `[http]` entry
    /// keeps the interpreted facts, so nothing rebuilds and the acquisition
    /// stays complete and equal to a fresh one. A new build target, and a source
    /// replacement (a source-effect change), rebuild and still match a fresh one.
    #[test]
    #[hardwon(
        "#12654: any changed Cargo configuration input rebuilt the whole workspace before its acquired meaning was compared"
    )]
    fn configuration_edits_rebuild_only_when_their_acquired_meaning_changes() {
        use brokk_bifrost_analysis::analyzer::IAnalyzer;
        use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::full_update_count_for_test;
        use std::sync::Arc;
        let (_temp, project, _home) = fixture();
        put(project.root(), "src/lib.rs", "pub fn example() {}\n");
        put(
            project.root(),
            ".cargo/config.toml",
            "[build]\ntarget='x86_64-unknown-linux-gnu'\n",
        );
        let root = project.root().to_path_buf();
        let config = ProjectFile::new(project.root(), ".cargo/config.toml");
        let read = |analyzer: &super::super::RustAnalyzer| {
            let snapshots = analyzer.inner.selected_workspace_snapshots();
            let configuration = analyzer
                .inner
                .analyzer_store()
                .selected_rust_cargo_configuration(&snapshots["rust"])
                .unwrap();
            let directory = Path::new("");
            (
                configuration.acquisition_is_complete(directory),
                configuration.source_effect(directory),
                configuration.configured_build_targets(directory).0,
                configuration.has_extern_rustflags(directory),
            )
        };
        let mut warm = super::super::RustAnalyzer::new(Arc::new(project.clone()));
        for (edited, rebuilds) in [
            (
                "# a comment\n[build]\ntarget='x86_64-unknown-linux-gnu'\n",
                false,
            ),
            (
                "[build]\ntarget='x86_64-unknown-linux-gnu'\n[alias]\nb='build'\n[http]\ntimeout=30\n",
                false,
            ),
            ("[build]\ntarget='aarch64-unknown-linux-gnu'\n", true),
            (
                "[build]\ntarget='aarch64-unknown-linux-gnu'\n[source.crates-io]\nreplace-with='vendored'\n[source.vendored]\ndirectory='vendor'\n",
                true,
            ),
        ] {
            put(project.root(), ".cargo/config.toml", edited);
            let before = full_update_count_for_test(&root);
            warm = warm.update(&BTreeSet::from([config.clone()]));
            assert_eq!(
                full_update_count_for_test(&root) - before,
                usize::from(rebuilds),
                "{edited}"
            );
            let fresh = super::super::RustAnalyzer::new(Arc::new(project.clone()));
            assert_eq!(read(&warm), read(&fresh), "{edited}");
            assert!(read(&warm).0, "the acquisition stays complete: {edited}");
        }
    }

    /// A retained `include`d file is neither a native configuration input nor a
    /// package-identity input, so a warm update has no in-place republication
    /// for it: even a comment-only edit rebuilds, and the result matches a
    /// fresh analyzer.
    #[test]
    #[hardwon(
        "#12654: an edited retained Cargo include must not continue incrementally without being republished"
    )]
    fn an_edited_retained_include_rebuilds_like_a_fresh_analyzer() {
        use brokk_bifrost_analysis::analyzer::IAnalyzer;
        use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::full_update_count_for_test;
        use std::sync::Arc;
        let (_temp, project, _home) = fixture();
        put(project.root(), "src/lib.rs", "pub fn example() {}\n");
        put(
            project.root(),
            ".cargo/config.toml",
            "include='settings/flags.toml'\n",
        );
        put(
            project.root(),
            ".cargo/settings/flags.toml",
            "[build]\ntarget='x86_64-unknown-linux-gnu'\n",
        );
        let root = project.root().to_path_buf();
        let included = ProjectFile::new(project.root(), ".cargo/settings/flags.toml");
        let read = |analyzer: &super::super::RustAnalyzer| {
            let snapshots = analyzer.inner.selected_workspace_snapshots();
            let configuration = analyzer
                .inner
                .analyzer_store()
                .selected_rust_cargo_configuration(&snapshots["rust"])
                .unwrap();
            (
                configuration.acquisition_is_complete(Path::new("")),
                configuration.configured_build_targets(Path::new("")).0,
            )
        };
        let mut warm = super::super::RustAnalyzer::new(Arc::new(project.clone()));
        put(
            project.root(),
            ".cargo/settings/flags.toml",
            "# a comment\n[build]\ntarget='x86_64-unknown-linux-gnu'\n",
        );
        let before = full_update_count_for_test(&root);
        warm = warm.update(&BTreeSet::from([included]));
        assert_eq!(full_update_count_for_test(&root) - before, 1);
        let fresh = super::super::RustAnalyzer::new(Arc::new(project.clone()));
        assert_eq!(read(&warm), read(&fresh));
        assert!(read(&warm).0);
    }
}
