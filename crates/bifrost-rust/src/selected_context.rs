//! Immutable Rust mount context for native-resolution operations.
//!
//! Cargo and source bytes are consumed before operation construction. The
//! builder below accepts content-addressed facts backed by private exact
//! manifest bytes plus an exact selected path inventory, so module and include
//! reachability cannot consult the live filesystem. Dirty manifests use the
//! same input shape with an OID computed from their transient bytes.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::path::{Component, Path, PathBuf};

use brokk_bifrost_core::analyzer::resolution_facts::{
    FileResolutionFacts, ResolutionIdentifierRole, ResolutionNameId, ResolutionNamespace,
    ResolutionRootImportAnchor, ResolutionScopeId, ResolutionSiteId,
};
use brokk_bifrost_core::analyzer::rust_facts::{
    RustCfgCondition, RustImportTargetFact, RustIncludeHostBindingFact, RustModuleRouteFacts,
    RustUsageFacts, RustVisibility,
};
use brokk_bifrost_core::analyzer::source_facts::SourceDeclarationId;
use brokk_bifrost_core::analyzer::symbol_path::strip_raw_identifier_prefix;
use brokk_bifrost_core::hash::HashMap as CargoHashMap;
use git2::{ObjectType, Oid};

use crate::cargo_manifest::RustCargoManifestDocument;
use crate::cargo_routes::{
    AUTO_TARGET_MAX_DEPTH, RustCargoTargetKind, auto_cargo_target_kind,
    cargo_dependency_directory_with, normalize_crate_name,
};

mod crate_inventory;
pub use crate_inventory::{RustCrateDependency, RustCrateTarget, rust_crate_targets};

pub const RUST_CARGO_MANIFEST_FACT_VERSION: u16 = 7;

/// One cooperatively bounded unit while compiling selected Rust topology.
///
/// The language crate names the kind of work without owning a consumer budget.
/// Callers map these events onto the operation-local budget and cancellation
/// session that owns the complete request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RustSelectedContextWork {
    /// Profile-independent index construction. Callers use this event to poll
    /// cancellation, but it does not consume the established profile-overlay
    /// scope budget.
    PreparationNode,
    ScopeNode,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RustSelectedBuildOutcome<T> {
    Ready(T),
    Stopped,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RustCargoManifestFacts {
    pub version: u16,
    pub is_workspace: bool,
    pub workspace_members: Box<[PathBuf]>,
    /// Workspace-relative directory patterns this workspace never claims.
    /// Cargo accepts glob patterns here, so each entry is matched by path
    /// component rather than compared for equality.
    pub workspace_excludes: Box<[PathBuf]>,
    pub workspace_package_edition: Option<RustCargoEdition>,
    pub package: Option<RustCargoPackageFact>,
    pub dependencies: Box<[RustCargoDependencyFact]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RustCargoPackageFact {
    pub package_name: String,
    pub library_name: String,
    pub library_path: PathBuf,
    pub automatic_targets: RustCargoAutomaticTargetFacts,
    pub explicit_targets: Box<[RustCargoTargetFact]>,
    pub build_script: Option<PathBuf>,
    pub has_custom_target_configuration: bool,
    pub edition: RustCargoPackageEdition,
    pub workspace_path: Option<PathBuf>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RustCargoAutomaticTargetFacts {
    pub library_explicit: bool,
    pub library: Option<bool>,
    pub binaries: Option<bool>,
    pub examples: Option<bool>,
    pub tests: Option<bool>,
    pub benches: Option<bool>,
    pub has_explicit_target: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RustCargoTargetFact {
    pub kind: RustCallerTargetKind,
    pub candidate_paths: Box<[PathBuf]>,
    pub test_profile_enabled: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RustCargoEdition {
    Rust2015,
    Rust2018,
    Rust2021,
    Rust2024,
}

impl RustCargoEdition {
    fn uses_uniform_paths(self) -> bool {
        self != Self::Rust2015
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RustCargoPackageEdition {
    Explicit(RustCargoEdition),
    Workspace,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RustCargoDependencyFact {
    pub manifest_name: String,
    pub exposed_name: String,
    pub package_name: String,
    pub relative_path: Option<PathBuf>,
    pub kind: RustCargoDependencyKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RustCargoDependencyKind {
    Normal,
    Development,
    Build,
}

impl RustCargoManifestFacts {
    /// Parse versioned facts from manifest bytes without using a mount path.
    pub fn from_source(source: &str) -> Result<Self, String> {
        let document = RustCargoManifestDocument::from_source(source)
            .map_err(|error| format!("invalid Cargo manifest facts: {error}"))?;
        Self::from_document(&document)
    }

    /// Derive operation-local facts from one already parsed Cargo document.
    pub(crate) fn from_document(manifest: &RustCargoManifestDocument) -> Result<Self, String> {
        let is_workspace = manifest.get("workspace").is_some();
        let workspace_members = manifest
            .get("workspace")
            .and_then(|workspace| workspace.get("members"))
            .and_then(toml::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(toml::Value::as_str)
            .map(PathBuf::from)
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let workspace_excludes = manifest
            .get("workspace")
            .and_then(|workspace| workspace.get("exclude"))
            .and_then(toml::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(toml::Value::as_str)
            .map(PathBuf::from)
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let workspace_package_edition = match manifest
            .get("workspace")
            .and_then(|workspace| workspace.get("package"))
            .and_then(|package| package.get("edition"))
        {
            None => None,
            Some(toml::Value::String(edition)) => Some(parse_cargo_edition(edition)?),
            Some(_) => return Err("invalid Cargo workspace package edition fact".to_string()),
        };
        let package = if let Some(package_name) = manifest.package_name() {
            let package = manifest
                .get("package")
                .expect("a Cargo package name requires a package table");
            let fact = (|| -> Result<RustCargoPackageFact, String> {
                let library = manifest.get("lib");
                let has_explicit_target = cargo_manifest_has_explicit_target(manifest);
                let mut target_configuration_complete = true;
                let automatic_targets = RustCargoAutomaticTargetFacts {
                    library_explicit: library.is_some(),
                    library: cargo_package_boolean(
                        package,
                        "autolib",
                        &mut target_configuration_complete,
                    ),
                    binaries: cargo_package_boolean(
                        package,
                        "autobins",
                        &mut target_configuration_complete,
                    ),
                    examples: cargo_package_boolean(
                        package,
                        "autoexamples",
                        &mut target_configuration_complete,
                    ),
                    tests: cargo_package_boolean(
                        package,
                        "autotests",
                        &mut target_configuration_complete,
                    ),
                    benches: cargo_package_boolean(
                        package,
                        "autobenches",
                        &mut target_configuration_complete,
                    ),
                    has_explicit_target,
                };
                let library_name = manifest
                    .library_name()
                    .map(normalize_crate_name)
                    .unwrap_or_else(|| normalize_crate_name(package_name));
                let library_path = manifest
                    .library_path()
                    .unwrap_or_else(|_| {
                        target_configuration_complete = false;
                        Path::new("src/lib.rs")
                    })
                    .to_path_buf();
                let edition = match package.get("edition") {
                    None => Ok(RustCargoPackageEdition::Explicit(
                        RustCargoEdition::Rust2015,
                    )),
                    Some(toml::Value::String(edition)) => {
                        parse_cargo_edition(edition).map(RustCargoPackageEdition::Explicit)
                    }
                    Some(toml::Value::Table(edition))
                        if edition.get("workspace").and_then(toml::Value::as_bool)
                            == Some(true) =>
                    {
                        Ok(RustCargoPackageEdition::Workspace)
                    }
                    Some(_) => Err("invalid Cargo package edition fact".to_string()),
                }?;
                if library.is_some_and(|library| library.as_table().is_none()) {
                    target_configuration_complete = false;
                }
                let explicit_targets = cargo_explicit_target_facts(
                    manifest,
                    package_name,
                    &mut target_configuration_complete,
                );
                let build_script =
                    cargo_build_script_fact(package, &mut target_configuration_complete);
                Ok(RustCargoPackageFact {
                    package_name: package_name.to_string(),
                    library_name,
                    library_path,
                    automatic_targets,
                    explicit_targets: explicit_targets.into_boxed_slice(),
                    build_script,
                    has_custom_target_configuration: !target_configuration_complete,
                    edition,
                    workspace_path: package
                        .get("workspace")
                        .and_then(toml::Value::as_str)
                        .map(PathBuf::from),
                })
            })()?;
            Some(fact)
        } else {
            None
        };
        let mut dependencies = Vec::new();
        for (table_name, kind) in [
            ("dependencies", RustCargoDependencyKind::Normal),
            ("dev-dependencies", RustCargoDependencyKind::Development),
            ("build-dependencies", RustCargoDependencyKind::Build),
        ] {
            let Some(table) = manifest.get(table_name).and_then(toml::Value::as_table) else {
                continue;
            };
            for (exposed_name, value) in table {
                let package_name = value
                    .as_table()
                    .and_then(|dependency| dependency.get("package"))
                    .and_then(toml::Value::as_str)
                    .unwrap_or(exposed_name);
                let relative_path = value
                    .as_table()
                    .and_then(|dependency| dependency.get("path"))
                    .and_then(toml::Value::as_str)
                    .map(PathBuf::from);
                dependencies.push(RustCargoDependencyFact {
                    manifest_name: exposed_name.clone(),
                    exposed_name: normalize_crate_name(exposed_name),
                    package_name: package_name.to_string(),
                    relative_path,
                    kind,
                });
            }
        }
        dependencies.sort_by(|left, right| {
            left.exposed_name
                .cmp(&right.exposed_name)
                .then_with(|| left.kind.cmp(&right.kind))
        });
        Ok(Self {
            version: RUST_CARGO_MANIFEST_FACT_VERSION,
            is_workspace,
            workspace_members,
            workspace_excludes,
            workspace_package_edition,
            package,
            dependencies: dependencies.into_boxed_slice(),
        })
    }
}

fn cargo_package_boolean(
    package: &toml::Value,
    key: &str,
    target_configuration_complete: &mut bool,
) -> Option<bool> {
    match package.get(key) {
        Some(toml::Value::Boolean(value)) => Some(*value),
        Some(_) => {
            *target_configuration_complete = false;
            None
        }
        None => None,
    }
}

fn cargo_manifest_has_explicit_target(manifest: &RustCargoManifestDocument) -> bool {
    manifest.get("lib").is_some()
        || ["bin", "example", "test", "bench"].into_iter().any(|name| {
            manifest
                .get(name)
                .and_then(toml::Value::as_array)
                .is_some_and(|targets| !targets.is_empty())
        })
}

fn cargo_explicit_target_facts(
    manifest: &RustCargoManifestDocument,
    package_name: &str,
    target_configuration_complete: &mut bool,
) -> Vec<RustCargoTargetFact> {
    let mut facts = Vec::new();
    for (table_name, kind) in [
        ("bin", RustCallerTargetKind::Binary),
        ("example", RustCallerTargetKind::Example),
        ("test", RustCallerTargetKind::Test),
        ("bench", RustCallerTargetKind::Bench),
    ] {
        let Some(value) = manifest.get(table_name) else {
            continue;
        };
        let Some(targets) = value.as_array() else {
            *target_configuration_complete = false;
            continue;
        };
        for target in targets {
            let Some(target) = target.as_table() else {
                *target_configuration_complete = false;
                continue;
            };
            let candidate_paths = match target.get("path") {
                Some(toml::Value::String(path)) => vec![PathBuf::from(path)],
                Some(_) => {
                    *target_configuration_complete = false;
                    Vec::new()
                }
                None => match target.get("name") {
                    Some(toml::Value::String(name)) => {
                        inferred_cargo_target_paths(table_name, name, package_name)
                    }
                    Some(_) | None => {
                        *target_configuration_complete = false;
                        Vec::new()
                    }
                },
            };
            if candidate_paths.is_empty() {
                *target_configuration_complete = false;
                continue;
            }
            let test_profile_enabled = if kind == RustCallerTargetKind::Binary {
                match target.get("test") {
                    Some(toml::Value::Boolean(enabled)) => *enabled,
                    Some(_) => {
                        *target_configuration_complete = false;
                        true
                    }
                    None => true,
                }
            } else {
                true
            };
            facts.push(RustCargoTargetFact {
                kind,
                candidate_paths: candidate_paths.into_boxed_slice(),
                test_profile_enabled,
            });
        }
    }
    facts
}

fn inferred_cargo_target_paths(table_name: &str, name: &str, package_name: &str) -> Vec<PathBuf> {
    if !matches!(
        Path::new(name).components().collect::<Vec<_>>().as_slice(),
        [Component::Normal(_)]
    ) {
        return Vec::new();
    }
    match table_name {
        "bin" => {
            let mut paths = Vec::new();
            if normalize_crate_name(name) == normalize_crate_name(package_name) {
                paths.push(PathBuf::from("src/main.rs"));
            }
            paths.push(Path::new("src/bin").join(name).with_extension("rs"));
            paths.push(Path::new("src/bin").join(name).join("main.rs"));
            paths
        }
        "example" => vec![
            Path::new("examples").join(name).with_extension("rs"),
            Path::new("examples").join(name).join("main.rs"),
        ],
        "test" => vec![
            Path::new("tests").join(name).with_extension("rs"),
            Path::new("tests").join(name).join("main.rs"),
        ],
        "bench" => vec![
            Path::new("benches").join(name).with_extension("rs"),
            Path::new("benches").join(name).join("main.rs"),
        ],
        _ => unreachable!("explicit Cargo target tables are enumerated above"),
    }
}

fn cargo_build_script_fact(
    package: &toml::Value,
    target_configuration_complete: &mut bool,
) -> Option<PathBuf> {
    match package.get("build") {
        Some(toml::Value::String(path)) => Some(PathBuf::from(path)),
        Some(toml::Value::Boolean(false)) => None,
        Some(toml::Value::Boolean(true)) | None => Some(PathBuf::from("build.rs")),
        Some(_) => {
            *target_configuration_complete = false;
            None
        }
    }
}

fn parse_cargo_edition(edition: &str) -> Result<RustCargoEdition, String> {
    match edition {
        "2015" => Ok(RustCargoEdition::Rust2015),
        "2018" => Ok(RustCargoEdition::Rust2018),
        "2021" => Ok(RustCargoEdition::Rust2021),
        "2024" => Ok(RustCargoEdition::Rust2024),
        _ => Err(format!("unsupported Cargo package edition: {edition}")),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RustSelectedManifestMount {
    pub relative_path: PathBuf,
    pub content_oid: Oid,
    pub facts: RustCargoManifestFacts,
    document: RustCargoManifestDocument,
}

impl RustSelectedManifestMount {
    pub fn from_source(relative_path: impl Into<PathBuf>, source: &str) -> Result<Self, String> {
        Self::from_source_bytes(relative_path, source.as_bytes().to_vec().into_boxed_slice())
    }

    /// Construct a selected manifest from its exact UTF-8 source bytes.
    ///
    /// The bytes are retained privately so a store writer can persist the
    /// content that produced the facts, while consumers continue to receive
    /// the existing typed facts surface. The content OID is always computed
    /// from the retained bytes rather than accepted from a caller.
    pub fn from_source_bytes(
        relative_path: impl Into<PathBuf>,
        source_bytes: Box<[u8]>,
    ) -> Result<Self, String> {
        let document = RustCargoManifestDocument::from_source_bytes(source_bytes)?;
        Self::from_document(relative_path, document)
    }

    /// Rehydrate a selected manifest from bytes stored under a content OID.
    ///
    /// This verifies the cache's content-addressed boundary before parsing;
    /// normalized SQL facts must never be used to reconstruct unavailable
    /// source bytes.
    pub fn from_retained_source(
        relative_path: impl Into<PathBuf>,
        content_oid: Oid,
        source_bytes: Box<[u8]>,
    ) -> Result<Self, String> {
        let document = RustCargoManifestDocument::from_retained_source(content_oid, source_bytes)?;
        Self::from_document(relative_path, document)
    }

    fn from_document(
        relative_path: impl Into<PathBuf>,
        document: RustCargoManifestDocument,
    ) -> Result<Self, String> {
        let content_oid = document.content_oid();
        Ok(Self {
            relative_path: relative_path.into(),
            content_oid,
            facts: RustCargoManifestFacts::from_document(&document)?,
            document,
        })
    }

    /// Exact UTF-8 bytes used to compute `content_oid` and parse `facts`.
    pub fn source_bytes(&self) -> &[u8] {
        self.document.source_bytes()
    }

    /// The parsed Cargo document that produced this mount's facts.
    pub fn document(&self) -> &RustCargoManifestDocument {
        &self.document
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RustSelectedSourceMount {
    pub relative_path: PathBuf,
    pub content_oid: Oid,
    pub facts: RustUsageFacts,
    pub resolution_facts: FileResolutionFacts,
}

/// Content-owned Rust topology inputs reconstructed from selected store rows.
///
/// Common root-path authority is deliberately absent: selected operations
/// read those exact mounted halves from the sealed resolution interior.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RustSelectedTopologySourceMount {
    pub relative_path: PathBuf,
    pub content_oid: Oid,
    pub facts: RustUsageFacts,
}

/// Immutable, canonical Rust topology inputs shared by one or more profiles.
///
/// The source mounts are converted to the legacy source shape and their
/// profile-independent module/include route indexes are compiled once. Profile
/// builders borrow those stable indexes instead of rebuilding source topology
/// for every Cargo target. The default resolution facts are intentionally
/// empty: the topology builder only needs imports and Rust usage facts, while
/// common root authorities remain operation-owned.
pub struct RustSelectedTopologyInput {
    sources: BTreeMap<PathBuf, RustSelectedSourceMount>,
    manifests: BTreeMap<PathBuf, RustSelectedManifestMount>,
    manifests_by_directory: BTreeMap<PathBuf, PathBuf>,
    source_topologies: BTreeMap<PathBuf, RustSelectedPreparedSource>,
    content_identity: Box<[u8]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RustSelectedPreparedActivation {
    condition: RustCfgCondition,
    gap_start: Option<usize>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RustSelectedPreparedRoute {
    scope: usize,
    declaration_start: usize,
    declaration_end: usize,
    candidates_for_root: Box<[PathBuf]>,
    candidates_for_file: Box<[PathBuf]>,
    activation: Box<[RustSelectedPreparedActivation]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RustSelectedPreparedInclude {
    target: Option<PathBuf>,
    scope: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RustSelectedPreparedImport {
    route: (Box<[String]>, ResolutionRootImportAnchor),
    profile_work: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RustSelectedPreparedSource {
    scope_segments: Box<[Box<[String]>]>,
    scope_activations: Box<[Box<[RustSelectedPreparedActivation]>]>,
    scope_is_inline: Box<[bool]>,
    scopes_by_body: ScopesByBody,
    module_activations: Box<[Box<[RustSelectedPreparedActivation]>]>,
    module_declaring_segments: Box<[Option<Box<[String]>>]>,
    module_declaring_work: Box<[usize]>,
    module_visibilities: Box<[RustVisibility]>,
    module_scope_index_work: usize,
    routes: Box<[RustSelectedPreparedRoute]>,
    includes: Box<[RustSelectedPreparedInclude]>,
    imports: Box<[RustSelectedPreparedImport]>,
}

type ScopesByBody = HashMap<(usize, usize), Vec<(usize, Box<[String]>)>>;

impl RustSelectedTopologyInput {
    pub fn source_count(&self) -> usize {
        self.sources.len()
    }

    pub fn manifest_count(&self) -> usize {
        self.manifests.len()
    }

    pub fn manifest_directory_count(&self) -> usize {
        self.manifests_by_directory.len()
    }

    pub fn source_paths(&self) -> impl Iterator<Item = &Path> {
        self.sources.keys().map(PathBuf::as_path)
    }

    pub fn source_facts(&self, path: &Path) -> Option<&RustUsageFacts> {
        self.sources.get(path).map(|source| &source.facts)
    }
}

/// Prepare canonical Rust topology inputs for one or more profiles.
pub fn prepare_rust_selected_topology_input(
    source_mounts: impl IntoIterator<Item = RustSelectedTopologySourceMount>,
    manifest_mounts: impl IntoIterator<Item = RustSelectedManifestMount>,
) -> Result<RustSelectedTopologyInput, String> {
    let RustSelectedBuildOutcome::Ready(input) =
        prepare_rust_selected_topology_input_with_progress(
            source_mounts,
            manifest_mounts,
            &mut |_| true,
        )?
    else {
        unreachable!("an always-live selected Rust topology input cannot stop")
    };
    Ok(input)
}

pub fn prepare_rust_selected_topology_input_with_progress(
    source_mounts: impl IntoIterator<Item = RustSelectedTopologySourceMount>,
    manifest_mounts: impl IntoIterator<Item = RustSelectedManifestMount>,
    progress: &mut impl FnMut(RustSelectedContextWork) -> bool,
) -> Result<RustSelectedBuildOutcome<RustSelectedTopologyInput>, String> {
    let RustSelectedBuildOutcome::Ready(sources) = unique_mounts(
        source_mounts
            .into_iter()
            .map(|mount| RustSelectedSourceMount {
                relative_path: mount.relative_path,
                content_oid: mount.content_oid,
                facts: mount.facts,
                resolution_facts: FileResolutionFacts::default(),
            }),
        |mount| &mount.relative_path,
        "source",
        progress,
    )?
    else {
        return Ok(RustSelectedBuildOutcome::Stopped);
    };
    let RustSelectedBuildOutcome::Ready(manifests) = unique_mounts(
        manifest_mounts,
        |mount| &mount.relative_path,
        "manifest",
        progress,
    )?
    else {
        return Ok(RustSelectedBuildOutcome::Stopped);
    };
    for manifest in manifests.values() {
        if !progress(RustSelectedContextWork::ScopeNode) {
            return Ok(RustSelectedBuildOutcome::Stopped);
        }
        if manifest.facts.version != RUST_CARGO_MANIFEST_FACT_VERSION {
            return Err(format!(
                "unsupported Rust Cargo manifest fact version at {:?}: {}",
                manifest.relative_path, manifest.facts.version
            ));
        }
    }
    let mut manifests_by_directory = BTreeMap::new();
    for path in manifests.keys() {
        if !progress(RustSelectedContextWork::ScopeNode) {
            return Ok(RustSelectedBuildOutcome::Stopped);
        }
        manifests_by_directory.insert(
            path.parent().unwrap_or(Path::new("")).to_path_buf(),
            path.clone(),
        );
    }
    let RustSelectedBuildOutcome::Ready(content_identity) =
        selected_content_identity_bytes(&sources, &manifests, progress)?
    else {
        return Ok(RustSelectedBuildOutcome::Stopped);
    };
    let RustSelectedBuildOutcome::Ready(source_topologies) =
        prepare_rust_selected_source_topologies(&sources, progress)?
    else {
        return Ok(RustSelectedBuildOutcome::Stopped);
    };
    Ok(RustSelectedBuildOutcome::Ready(RustSelectedTopologyInput {
        sources,
        manifests,
        manifests_by_directory,
        source_topologies,
        content_identity,
    }))
}

fn selected_content_identity_bytes(
    sources: &BTreeMap<PathBuf, RustSelectedSourceMount>,
    manifests: &BTreeMap<PathBuf, RustSelectedManifestMount>,
    progress: &mut impl FnMut(RustSelectedContextWork) -> bool,
) -> Result<RustSelectedBuildOutcome<Box<[u8]>>, String> {
    let mut bytes = Vec::new();
    for (path, mount) in sources {
        if !progress(RustSelectedContextWork::ScopeNode) {
            return Ok(RustSelectedBuildOutcome::Stopped);
        }
        append_path_identity(&mut bytes, path)?;
        bytes.extend_from_slice(mount.content_oid.as_bytes());
    }
    for (path, mount) in manifests {
        if !progress(RustSelectedContextWork::ScopeNode) {
            return Ok(RustSelectedBuildOutcome::Stopped);
        }
        append_path_identity(&mut bytes, path)?;
        bytes.extend_from_slice(mount.content_oid.as_bytes());
    }
    Ok(RustSelectedBuildOutcome::Ready(bytes.into_boxed_slice()))
}

fn prepare_rust_selected_source_topologies(
    sources: &BTreeMap<PathBuf, RustSelectedSourceMount>,
    progress: &mut impl FnMut(RustSelectedContextWork) -> bool,
) -> Result<RustSelectedBuildOutcome<BTreeMap<PathBuf, RustSelectedPreparedSource>>, String> {
    let mut source_topologies = BTreeMap::new();
    for (path, source) in sources {
        let RustSelectedBuildOutcome::Ready(topology) =
            prepare_rust_selected_source_topology(source, progress)?
        else {
            return Ok(RustSelectedBuildOutcome::Stopped);
        };
        source_topologies.insert(path.clone(), topology);
    }
    Ok(RustSelectedBuildOutcome::Ready(source_topologies))
}

fn prepare_rust_selected_source_topology(
    source: &RustSelectedSourceMount,
    progress: &mut impl FnMut(RustSelectedContextWork) -> bool,
) -> Result<RustSelectedBuildOutcome<RustSelectedPreparedSource>, String> {
    let facts = &source.facts.module_routes;
    let progress =
        &mut |_work: RustSelectedContextWork| progress(RustSelectedContextWork::PreparationNode);
    let mut scope_segments: Vec<Box<[String]>> = Vec::with_capacity(facts.scopes.len());
    for (index, scope) in facts.scopes.iter().enumerate() {
        if !progress(RustSelectedContextWork::ScopeNode) {
            return Ok(RustSelectedBuildOutcome::Stopped);
        }
        let mut segments = Vec::new();
        if let Some(parent) = scope.parent {
            assert!(parent < index, "Rust module scopes are pre-order");
            facts
                .scopes
                .get(parent)
                .expect("Rust module scope parent exists");
            for segment in &scope_segments[parent] {
                if !progress(RustSelectedContextWork::ScopeNode) {
                    return Ok(RustSelectedBuildOutcome::Stopped);
                }
                segments.push(segment.clone());
            }
        }
        if !scope.module_name.is_empty() {
            segments.push(scope.module_name.clone());
        }
        scope_segments.push(segments.into_boxed_slice());
    }

    let mut inline_modules_by_body = HashMap::new();
    for module in source
        .facts
        .modules
        .iter()
        .filter(|module| module.is_inline)
    {
        if !progress(RustSelectedContextWork::ScopeNode) {
            return Ok(RustSelectedBuildOutcome::Stopped);
        }
        inline_modules_by_body
            .entry((module.start_byte, module.end_byte))
            .or_insert(module);
    }
    let mut route_scopes_by_declaration = HashMap::new();
    for (index, route) in facts.routes.iter().enumerate() {
        if !progress(RustSelectedContextWork::ScopeNode) {
            return Ok(RustSelectedBuildOutcome::Stopped);
        }
        route_scopes_by_declaration
            .entry((route.declaration_start, route.declaration_end))
            .or_insert((index, route.scope));
    }
    let mut scope_indices_by_body = HashMap::new();
    for (index, scope) in facts.scopes.iter().enumerate() {
        if !progress(RustSelectedContextWork::ScopeNode) {
            return Ok(RustSelectedBuildOutcome::Stopped);
        }
        scope_indices_by_body
            .entry((scope.body_start, scope.body_end))
            .or_insert(index);
    }
    let mut scope_module_conditions = Vec::with_capacity(facts.scopes.len());
    let mut scope_is_inline = Vec::with_capacity(facts.scopes.len());
    for scope in &facts.scopes {
        if !progress(RustSelectedContextWork::ScopeNode) {
            return Ok(RustSelectedBuildOutcome::Stopped);
        }
        let module = inline_modules_by_body.get(&(scope.body_start, scope.body_end));
        scope_is_inline.push(module.is_some());
        scope_module_conditions.push(
            module
                .map(|module| RustSelectedPreparedActivation {
                    condition: module.cfg_condition.clone(),
                    gap_start: Some(module.start_byte),
                })
                .unwrap_or(RustSelectedPreparedActivation {
                    condition: RustCfgCondition::Always,
                    gap_start: None,
                }),
        );
    }

    let mut scope_activations: Vec<Box<[RustSelectedPreparedActivation]>> =
        Vec::with_capacity(facts.scopes.len());
    for (index, scope) in facts.scopes.iter().enumerate() {
        let mut chain = Vec::new();
        if let Some(parent) = scope.parent {
            assert!(parent < index, "Rust module scopes are pre-order");
            for activation in &scope_activations[parent] {
                if !progress(RustSelectedContextWork::ScopeNode) {
                    return Ok(RustSelectedBuildOutcome::Stopped);
                }
                chain.push(activation.clone());
            }
        }
        if !progress(RustSelectedContextWork::ScopeNode) {
            return Ok(RustSelectedBuildOutcome::Stopped);
        }
        chain.push(scope_module_conditions[index].clone());
        scope_activations.push(chain.into_boxed_slice());
    }

    let mut scopes_by_body = HashMap::new();
    for (index, scope) in facts.scopes.iter().enumerate() {
        if !progress(RustSelectedContextWork::ScopeNode) {
            return Ok(RustSelectedBuildOutcome::Stopped);
        }
        let mut segments = Vec::new();
        for segment in &scope_segments[index] {
            if !progress(RustSelectedContextWork::ScopeNode) {
                return Ok(RustSelectedBuildOutcome::Stopped);
            }
            segments.push(segment.clone());
        }
        scopes_by_body
            .entry((scope.body_start, scope.body_end))
            .or_insert_with(Vec::new)
            .push((index, segments.into_boxed_slice()));
    }

    let mut module_activations = Vec::with_capacity(source.facts.modules.len());
    let mut module_declaring_segments = Vec::with_capacity(source.facts.modules.len());
    let mut module_declaring_work = Vec::with_capacity(source.facts.modules.len());
    for module in &source.facts.modules {
        if !progress(RustSelectedContextWork::ScopeNode) {
            return Ok(RustSelectedBuildOutcome::Stopped);
        }
        let scope = if module.is_inline {
            scope_indices_by_body
                .get(&(module.start_byte, module.end_byte))
                .copied()
        } else {
            route_scopes_by_declaration
                .get(&(module.start_byte, module.end_byte))
                .map(|(_, scope)| *scope)
        };
        let mut activation = vec![RustSelectedPreparedActivation {
            condition: module.cfg_condition.clone(),
            gap_start: Some(module.start_byte),
        }];
        let declaring_scope = if module.is_inline {
            scope.map(|scope| facts.scopes[scope].parent.unwrap_or(scope))
        } else {
            scope
        };
        assert!(
            module.module_name.is_empty() || declaring_scope.is_some(),
            "every non-root Rust module has one structured declaring scope: {module:?}"
        );
        if let Some(scope) = scope {
            for inherited in &scope_activations[scope] {
                if !progress(RustSelectedContextWork::ScopeNode) {
                    return Ok(RustSelectedBuildOutcome::Stopped);
                }
                activation.push(inherited.clone());
            }
        }
        module_activations.push(activation.into_boxed_slice());
        let declaring_segments = if let Some(scope) = declaring_scope {
            let mut declaring_segments = Vec::new();
            for segment in &scope_segments[scope] {
                if !progress(RustSelectedContextWork::ScopeNode) {
                    return Ok(RustSelectedBuildOutcome::Stopped);
                }
                declaring_segments.push(segment.clone());
            }
            Some(declaring_segments.into_boxed_slice())
        } else {
            None
        };
        module_declaring_segments.push(declaring_segments);
        module_declaring_work
            .push(declaring_scope.map_or(0, |scope| scope_activations[scope].len()));
    }

    let mut routes = Vec::with_capacity(facts.routes.len());
    for (route_index, route) in facts.routes.iter().enumerate() {
        if !progress(RustSelectedContextWork::ScopeNode) {
            return Ok(RustSelectedBuildOutcome::Stopped);
        }
        assert!(
            route.scope < facts.scopes.len(),
            "Rust module route has no structured scope: {route:?}"
        );
        let mut activation = vec![RustSelectedPreparedActivation {
            condition: route.cfg_condition.clone(),
            gap_start: Some(route.declaration_start),
        }];
        for inherited in &scope_activations[route.scope] {
            if !progress(RustSelectedContextWork::ScopeNode) {
                return Ok(RustSelectedBuildOutcome::Stopped);
            }
            activation.push(inherited.clone());
        }
        let RustSelectedBuildOutcome::Ready(candidates_for_root) =
            module_candidates(source.relative_path.as_path(), facts, true, route, progress)
        else {
            return Ok(RustSelectedBuildOutcome::Stopped);
        };
        let RustSelectedBuildOutcome::Ready(candidates_for_file) = module_candidates(
            source.relative_path.as_path(),
            facts,
            false,
            route,
            progress,
        ) else {
            return Ok(RustSelectedBuildOutcome::Stopped);
        };
        assert_eq!(route_index, routes.len());
        routes.push(RustSelectedPreparedRoute {
            scope: route.scope,
            declaration_start: route.declaration_start,
            declaration_end: route.declaration_end,
            candidates_for_root: candidates_for_root.into_boxed_slice(),
            candidates_for_file: candidates_for_file.into_boxed_slice(),
            activation: activation.into_boxed_slice(),
        });
    }

    let mut includes = Vec::with_capacity(source.facts.include_edges.len());
    for edge in &source.facts.include_edges {
        if !progress(RustSelectedContextWork::ScopeNode) {
            return Ok(RustSelectedBuildOutcome::Stopped);
        }
        let target = normalize_selected_path(
            source.relative_path.parent().unwrap_or(Path::new("")),
            Path::new(&edge.relative_path),
        );
        let RustSelectedBuildOutcome::Ready(scope) =
            selected_inline_scope_at_byte_with_progress(facts, edge.include_start, progress)
        else {
            return Ok(RustSelectedBuildOutcome::Stopped);
        };
        includes.push(RustSelectedPreparedInclude { target, scope });
    }

    let mut imports = Vec::with_capacity(source.facts.import_targets.len());
    for target in &source.facts.import_targets {
        let mut profile_work = 0_usize;
        let RustSelectedBuildOutcome::Ready(route) =
            selected_import_route_segments_with_progress(target, &mut |work| {
                profile_work = profile_work
                    .checked_add(1)
                    .expect("selected Rust import preparation work fits usize");
                progress(work)
            })
        else {
            return Ok(RustSelectedBuildOutcome::Stopped);
        };
        imports.push(RustSelectedPreparedImport {
            route,
            profile_work,
        });
    }

    let mut module_visibilities = Vec::with_capacity(source.facts.modules.len());
    for module in &source.facts.modules {
        if !progress(RustSelectedContextWork::ScopeNode) {
            return Ok(RustSelectedBuildOutcome::Stopped);
        }
        let visibility = if module.is_inline {
            scope_indices_by_body
                .get(&(module.start_byte, module.end_byte))
                .map(|scope_index| facts.scopes[*scope_index].visibility.clone())
                .unwrap_or(RustVisibility::Private)
        } else {
            route_scopes_by_declaration
                .get(&(module.start_byte, module.end_byte))
                .map(|(route_index, _)| facts.routes[*route_index].visibility.clone())
                .unwrap_or(RustVisibility::Private)
        };
        module_visibilities.push(visibility);
    }
    let module_scope_index_work = facts.scopes.iter().fold(0_usize, |work, scope| {
        let ancestry_work = scope.parent.map_or(0, |parent| {
            1_usize
                .checked_add(scope_segments[parent].len())
                .expect("selected Rust scope-index ancestry work fits usize")
        });
        work.checked_add(1)
            .and_then(|work| work.checked_add(ancestry_work))
            .and_then(|work| work.checked_add(usize::from(!scope.module_name.is_empty())))
            .expect("selected Rust module scope-index work fits usize")
    });

    Ok(RustSelectedBuildOutcome::Ready(
        RustSelectedPreparedSource {
            scope_segments: scope_segments.into_boxed_slice(),
            scope_activations: scope_activations.into_boxed_slice(),
            scope_is_inline: scope_is_inline.into_boxed_slice(),
            scopes_by_body,
            module_activations: module_activations.into_boxed_slice(),
            module_declaring_segments: module_declaring_segments.into_boxed_slice(),
            module_declaring_work: module_declaring_work.into_boxed_slice(),
            module_visibilities: module_visibilities.into_boxed_slice(),
            module_scope_index_work,
            routes: routes.into_boxed_slice(),
            includes: includes.into_boxed_slice(),
            imports: imports.into_boxed_slice(),
        },
    ))
}

fn selected_prepared_scope_activation_with_progress(
    conditions: &[RustSelectedPreparedActivation],
    profile: &RustCallerTargetProfile,
    file: &Path,
    gaps: &mut BTreeSet<RustSelectedContextGap>,
    progress: &mut impl FnMut(RustSelectedContextWork) -> bool,
) -> RustSelectedBuildOutcome<RustSelectedActivation> {
    if !(0..conditions.len()).all(|_| progress(RustSelectedContextWork::ScopeNode)) {
        return RustSelectedBuildOutcome::Stopped;
    }
    let mut activation = RustSelectedActivation::Active;
    for condition in conditions {
        let current = profile.activation(&condition.condition);
        if current == RustSelectedActivation::Unknown
            && let Some(start_byte) = condition.gap_start
        {
            gaps.insert(RustSelectedContextGap::UnknownActivation {
                file: file.to_path_buf(),
                start_byte,
            });
        }
        activation = combine_selected_activation(activation, current);
        if activation == RustSelectedActivation::Inactive {
            return RustSelectedBuildOutcome::Ready(activation);
        }
    }
    RustSelectedBuildOutcome::Ready(activation)
}

fn selected_prepared_module_activation_with_progress(
    conditions: &[RustSelectedPreparedActivation],
    profile: &RustCallerTargetProfile,
    file: &Path,
    gaps: &mut BTreeSet<RustSelectedContextGap>,
    progress: &mut impl FnMut(RustSelectedContextWork) -> bool,
) -> RustSelectedBuildOutcome<RustSelectedActivation> {
    let Some((own, inherited)) = conditions.split_first() else {
        return RustSelectedBuildOutcome::Ready(RustSelectedActivation::Active);
    };
    let own_activation = profile.activation(&own.condition);
    if own_activation == RustSelectedActivation::Unknown {
        gaps.insert(RustSelectedContextGap::UnknownActivation {
            file: file.to_path_buf(),
            start_byte: own
                .gap_start
                .expect("a Rust module activation has its declaration start"),
        });
    }
    let RustSelectedBuildOutcome::Ready(inherited_activation) =
        selected_prepared_scope_activation_with_progress(inherited, profile, file, gaps, progress)
    else {
        return RustSelectedBuildOutcome::Stopped;
    };
    RustSelectedBuildOutcome::Ready(combine_selected_activation(
        own_activation,
        inherited_activation,
    ))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RustCallerTargetKind {
    Library,
    Binary,
    Example,
    Test,
    Bench,
    Build,
    /// A Rust source file that no Cargo target owns. The file is its own
    /// single-file crate root: it has no dependency crates, and every route
    /// that leaves the file is a detached-profile gap.
    Detached,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RustCallerTargetProfile {
    pub manifest_path: PathBuf,
    pub target_kind: RustCallerTargetKind,
    /// Exact target root relative to the caller manifest directory.
    pub target_root: PathBuf,
    pub target_triple: String,
    pub cfg_atoms: BTreeSet<String>,
    pub features: BTreeSet<String>,
    /// Cargo target routing (including dev dependencies), distinct from the
    /// selected default cfg(test), which is enabled for every workspace member.
    pub test: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RustSelectedActivation {
    Active,
    Inactive,
    Unknown,
}

pub enum RustSelectedLibraryContextOutcome {
    Ready(Box<RustSelectedContext>),
    Unavailable,
}

impl RustCallerTargetProfile {
    pub fn activation(&self, condition: &RustCfgCondition) -> RustSelectedActivation {
        crate::cfg::activation(self, condition)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RustSelectedWorkspaceProfiles {
    pub profiles: Box<[RustCallerTargetProfile]>,
    pub target_inventory_complete: bool,
}

/// Enumerate every supported Cargo target from retained manifest facts.
///
/// The selected source inventory is exact, so explicit, inferred, and
/// auto-discovered target roots can be selected without consulting the live
/// filesystem. Unsupported target shapes remain an explicit completeness
/// boundary.
pub fn rust_selected_workspace_profiles(
    source_mounts: &[RustSelectedTopologySourceMount],
    manifest_mounts: &[RustSelectedManifestMount],
) -> Result<RustSelectedWorkspaceProfiles, String> {
    let RustSelectedBuildOutcome::Ready(profiles) = rust_selected_workspace_profiles_with_progress(
        source_mounts,
        manifest_mounts,
        &mut |_| true,
    )?
    else {
        unreachable!("an always-live selected workspace profile build cannot stop")
    };
    Ok(profiles)
}

pub fn rust_selected_workspace_profiles_with_progress(
    source_mounts: &[RustSelectedTopologySourceMount],
    manifest_mounts: &[RustSelectedManifestMount],
    progress: &mut impl FnMut(RustSelectedContextWork) -> bool,
) -> Result<RustSelectedBuildOutcome<RustSelectedWorkspaceProfiles>, String> {
    let RustSelectedBuildOutcome::Ready(input) =
        prepare_rust_selected_topology_input_with_progress(
            source_mounts.iter().cloned(),
            manifest_mounts.iter().cloned(),
            progress,
        )?
    else {
        return Ok(RustSelectedBuildOutcome::Stopped);
    };
    rust_selected_workspace_profiles_from_prepared_with_progress(&input, progress)
}

pub fn rust_selected_workspace_profiles_from_prepared(
    input: &RustSelectedTopologyInput,
) -> Result<RustSelectedWorkspaceProfiles, String> {
    let RustSelectedBuildOutcome::Ready(profiles) =
        rust_selected_workspace_profiles_from_prepared_with_progress(input, &mut |_| true)?
    else {
        unreachable!("an always-live selected Rust workspace profile build cannot stop")
    };
    Ok(profiles)
}

pub fn rust_selected_workspace_profiles_from_prepared_with_progress(
    input: &RustSelectedTopologyInput,
    progress: &mut impl FnMut(RustSelectedContextWork) -> bool,
) -> Result<RustSelectedBuildOutcome<RustSelectedWorkspaceProfiles>, String> {
    let mut source_paths = BTreeSet::new();
    let mut sources_by_target_directory = HashMap::<&Path, Vec<&RustSelectedSourceMount>>::new();
    let mut target_inventory_complete = true;
    for source in input.sources.values() {
        if !progress(RustSelectedContextWork::ScopeNode) {
            return Ok(RustSelectedBuildOutcome::Stopped);
        }
        source_paths.insert(source.relative_path.as_path());
        let mut directory = source.relative_path.parent();
        for _ in 0..AUTO_TARGET_MAX_DEPTH {
            if !progress(RustSelectedContextWork::ScopeNode) {
                return Ok(RustSelectedBuildOutcome::Stopped);
            }
            let Some(candidate) = directory else {
                break;
            };
            sources_by_target_directory
                .entry(candidate)
                .or_default()
                .push(source);
            directory = candidate.parent();
        }
    }

    let mut profiles = Vec::new();
    for manifest in input.manifests.values() {
        if !progress(RustSelectedContextWork::ScopeNode) {
            return Ok(RustSelectedBuildOutcome::Stopped);
        }
        let Some(package) = &manifest.facts.package else {
            continue;
        };
        let directory = manifest.relative_path.parent().unwrap_or(Path::new(""));
        let RustSelectedBuildOutcome::Ready(edition) =
            effective_cargo_edition(&manifest.relative_path, &input.manifests, progress)?
        else {
            return Ok(RustSelectedBuildOutcome::Stopped);
        };
        let automatic = &package.automatic_targets;
        if cargo_library_target_enabled(package) {
            add_selected_target_profiles(
                &mut profiles,
                &mut target_inventory_complete,
                &source_paths,
                &manifest.relative_path,
                RustCallerTargetKind::Library,
                &package.library_path,
                true,
            );
        }
        if package.has_custom_target_configuration {
            target_inventory_complete = false;
        }
        for target in &package.explicit_targets {
            for candidate in &target.candidate_paths {
                if !progress(RustSelectedContextWork::ScopeNode) {
                    return Ok(RustSelectedBuildOutcome::Stopped);
                }
                add_selected_target_profiles(
                    &mut profiles,
                    &mut target_inventory_complete,
                    &source_paths,
                    &manifest.relative_path,
                    target.kind,
                    candidate,
                    target.test_profile_enabled,
                );
            }
        }
        if let Some(build_script) = package.build_script.as_deref() {
            add_selected_target_profiles(
                &mut profiles,
                &mut target_inventory_complete,
                &source_paths,
                &manifest.relative_path,
                RustCallerTargetKind::Build,
                build_script,
                false,
            );
        }
        let auto_bins = cargo_automatic_target_enabled(
            automatic.binaries,
            edition,
            automatic.has_explicit_target,
        );
        let auto_examples = cargo_automatic_target_enabled(
            automatic.examples,
            edition,
            automatic.has_explicit_target,
        );
        let auto_tests =
            cargo_automatic_target_enabled(automatic.tests, edition, automatic.has_explicit_target);
        let auto_benches = cargo_automatic_target_enabled(
            automatic.benches,
            edition,
            automatic.has_explicit_target,
        );
        for source in sources_by_target_directory
            .get(directory)
            .into_iter()
            .flatten()
        {
            if !progress(RustSelectedContextWork::ScopeNode) {
                return Ok(RustSelectedBuildOutcome::Stopped);
            }
            let target_root = source
                .relative_path
                .strip_prefix(directory)
                .expect("target-directory grouping keeps sources below the directory");
            let kind = auto_cargo_target_kind(
                target_root,
                auto_bins,
                auto_examples,
                auto_tests,
                auto_benches,
            );
            let Some(kind) = kind else {
                continue;
            };
            let kind = match kind {
                RustCargoTargetKind::Library => unreachable!(
                    "Cargo's automatic non-library target classifier cannot return a library"
                ),
                RustCargoTargetKind::Binary => RustCallerTargetKind::Binary,
                RustCargoTargetKind::Example => RustCallerTargetKind::Example,
                RustCargoTargetKind::Test => RustCallerTargetKind::Test,
                RustCargoTargetKind::Bench => RustCallerTargetKind::Bench,
                RustCargoTargetKind::Build => {
                    unreachable!("Cargo's automatic target classifier cannot return a build script")
                }
            };
            add_default_workspace_profiles(
                &mut profiles,
                &manifest.relative_path,
                kind,
                target_root.to_path_buf(),
                true,
            );
        }
    }
    profiles.sort_by(|left, right| {
        left.manifest_path
            .cmp(&right.manifest_path)
            .then_with(|| left.target_kind.cmp(&right.target_kind))
            .then_with(|| left.target_root.cmp(&right.target_root))
            .then_with(|| left.test.cmp(&right.test))
    });
    profiles.dedup();
    Ok(RustSelectedBuildOutcome::Ready(
        RustSelectedWorkspaceProfiles {
            profiles: profiles.into_boxed_slice(),
            target_inventory_complete,
        },
    ))
}

/// Cargo's legacy rule: in edition 2015, declaring any target at all turns off
/// automatic discovery of that kind. It covers binaries, examples, tests and
/// benches, and not the library, which is why the library has its own rule
/// below.
fn cargo_automatic_target_enabled(
    configured: Option<bool>,
    edition: RustCargoEdition,
    has_explicit_target: bool,
) -> bool {
    configured.unwrap_or(edition != RustCargoEdition::Rust2015 || !has_explicit_target)
}

/// A package's library is `src/lib.rs` in every edition, whatever else the
/// manifest declares, unless `[lib]` names another path or `autolib = false`.
///
/// Measured against Cargo 1.96 rather than read from the documentation: a
/// package with `edition = "2015"`, an explicit `[[bin]] path = "src/cli.rs"`,
/// and both `src/lib.rs` and `src/main.rs` present reports targets
/// `[legacy: lib (lib.rs), legacy-cli: bin (cli.rs)]` under
/// `cargo metadata --no-deps`. The implicit `main.rs` binary is dropped by the
/// legacy rule; the library is not. Under 2021 all three appear.
///
/// Routing the library through [`cargo_automatic_target_enabled`] therefore
/// left every 2015 package that declares a binary with no library target at
/// all. Its `src/lib.rs` became a `detached` topology, and a detached crate key
/// is one `narrow_forward_scope_to_crates` declines to narrow, so those
/// requests resolved against the whole selection.
fn cargo_library_target_enabled(package: &RustCargoPackageFact) -> bool {
    package.automatic_targets.library_explicit || package.automatic_targets.library.unwrap_or(true)
}

fn add_selected_target_profiles(
    profiles: &mut Vec<RustCallerTargetProfile>,
    target_inventory_complete: &mut bool,
    source_paths: &BTreeSet<&Path>,
    manifest_path: &Path,
    kind: RustCallerTargetKind,
    candidate: &Path,
    test_profile_enabled: bool,
) {
    let directory = manifest_path.parent().unwrap_or(Path::new(""));
    let Some(target_root) = normalize_selected_path(directory, candidate) else {
        *target_inventory_complete = false;
        return;
    };
    let Ok(profile_target_root) = target_root.strip_prefix(directory) else {
        *target_inventory_complete = false;
        return;
    };
    if source_paths.contains(target_root.as_path()) {
        add_default_workspace_profiles(
            profiles,
            manifest_path,
            kind,
            profile_target_root.to_path_buf(),
            test_profile_enabled,
        );
    }
}

fn add_default_workspace_profiles(
    profiles: &mut Vec<RustCallerTargetProfile>,
    manifest_path: &Path,
    kind: RustCallerTargetKind,
    target_root: PathBuf,
    test_profile_enabled: bool,
) {
    let test_profiles: &[bool] = match kind {
        RustCallerTargetKind::Library => &[false, true],
        RustCallerTargetKind::Binary | RustCallerTargetKind::Example => {
            if test_profile_enabled {
                &[false, true]
            } else {
                &[false]
            }
        }
        RustCallerTargetKind::Test | RustCallerTargetKind::Bench => &[true],
        RustCallerTargetKind::Build | RustCallerTargetKind::Detached => &[false],
    };
    for &test in test_profiles {
        profiles.push(default_workspace_profile(
            manifest_path,
            kind,
            target_root.clone(),
            test,
        ));
    }
}

fn default_workspace_profile(
    manifest_path: &Path,
    target_kind: RustCallerTargetKind,
    target_root: PathBuf,
    test: bool,
) -> RustCallerTargetProfile {
    RustCallerTargetProfile {
        manifest_path: manifest_path.to_path_buf(),
        target_kind,
        target_root,
        target_triple: "selected-workspace-unspecified".to_string(),
        cfg_atoms: crate::cfg::default_cfg_atoms(),
        features: BTreeSet::new(),
        test,
    }
}

pub fn build_rust_selected_library_context_for_caller(
    source_mounts: &[RustSelectedTopologySourceMount],
    manifest_mounts: &[RustSelectedManifestMount],
    caller: &Path,
) -> Result<RustSelectedLibraryContextOutcome, String> {
    let RustSelectedBuildOutcome::Ready(outcome) =
        build_rust_selected_library_context_for_caller_with_progress(
            source_mounts,
            manifest_mounts,
            caller,
            |_| true,
        )?
    else {
        unreachable!("an always-live selected Rust caller build cannot stop")
    };
    Ok(outcome)
}

pub fn build_rust_selected_library_context_for_caller_with_progress(
    source_mounts: &[RustSelectedTopologySourceMount],
    manifest_mounts: &[RustSelectedManifestMount],
    caller: &Path,
    mut progress: impl FnMut(RustSelectedContextWork) -> bool,
) -> Result<RustSelectedBuildOutcome<RustSelectedLibraryContextOutcome>, String> {
    let RustSelectedBuildOutcome::Ready(manifests) = unique_mounts(
        manifest_mounts.iter().cloned(),
        |mount| &mount.relative_path,
        "manifest",
        &mut progress,
    )?
    else {
        return Ok(RustSelectedBuildOutcome::Stopped);
    };
    let mut candidates = Vec::new();
    for manifest in manifests.values() {
        if !progress(RustSelectedContextWork::ScopeNode) {
            return Ok(RustSelectedBuildOutcome::Stopped);
        }
        if let Some(package) = manifest.facts.package.as_ref() {
            if !cargo_library_target_enabled(package) {
                continue;
            }
            let directory = manifest.relative_path.parent().unwrap_or(Path::new(""));
            if caller.starts_with(directory) {
                candidates.push((
                    directory.components().count(),
                    manifest.relative_path.clone(),
                    package.library_path.clone(),
                ));
            }
        }
    }
    candidates.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| left.1.cmp(&right.1)));
    let Some((depth, manifest_path, target_root)) = candidates.first().cloned() else {
        return build_rust_detached_caller_context_with_progress(
            source_mounts,
            manifest_mounts,
            &manifests,
            caller,
            &mut progress,
        );
    };
    if candidates
        .get(1)
        .is_some_and(|candidate| candidate.0 == depth)
    {
        return Ok(RustSelectedBuildOutcome::Ready(
            RustSelectedLibraryContextOutcome::Unavailable,
        ));
    }
    let caller_root = normalize_selected_path(
        manifest_path.parent().unwrap_or(Path::new("")),
        &target_root,
    )
    .ok_or_else(|| "caller library root escapes selected inventory".to_string())?;
    let profile = RustCallerTargetProfile {
        manifest_path,
        target_kind: RustCallerTargetKind::Library,
        target_root,
        target_triple: "selected-library-unspecified".to_string(),
        cfg_atoms: crate::cfg::default_cfg_atoms(),
        features: BTreeSet::new(),
        test: false,
    };
    let RustSelectedBuildOutcome::Ready(context) =
        build_rust_selected_topology_context_with_progress(
            source_mounts.iter().cloned(),
            manifest_mounts.iter().cloned(),
            profile,
            &mut progress,
        )?
    else {
        return Ok(RustSelectedBuildOutcome::Stopped);
    };
    let mut owns_caller = false;
    for membership in &context.target_memberships {
        if !progress(RustSelectedContextWork::ScopeNode) {
            return Ok(RustSelectedBuildOutcome::Stopped);
        }
        if membership.crate_root == caller_root && membership.file == caller {
            owns_caller = true;
            break;
        }
    }
    if !owns_caller {
        return build_rust_detached_caller_context_with_progress(
            source_mounts,
            manifest_mounts,
            &manifests,
            caller,
            &mut progress,
        );
    }
    Ok(RustSelectedBuildOutcome::Ready(
        RustSelectedLibraryContextOutcome::Ready(Box::new(context)),
    ))
}

/// Build the selected context for a detached Rust file: a source file that no
/// Cargo target owns, either because no manifest encloses it or because no
/// target of the enclosing package reaches it.
///
/// The file is its own single-file crate root. It has no dependency crates, and
/// every route that leaves it is recorded as a detached-profile gap, so callers
/// report the file's own contents exactly and report everything outside it as
/// incomplete rather than as absent.
fn build_rust_detached_caller_context_with_progress(
    source_mounts: &[RustSelectedTopologySourceMount],
    manifest_mounts: &[RustSelectedManifestMount],
    manifests: &BTreeMap<PathBuf, RustSelectedManifestMount>,
    caller: &Path,
    progress: &mut impl FnMut(RustSelectedContextWork) -> bool,
) -> Result<RustSelectedBuildOutcome<RustSelectedLibraryContextOutcome>, String> {
    if !source_mounts
        .iter()
        .any(|mount| mount.relative_path == caller)
    {
        return Ok(RustSelectedBuildOutcome::Ready(
            RustSelectedLibraryContextOutcome::Unavailable,
        ));
    }
    let mut enclosing: Option<(usize, &Path)> = None;
    for path in manifests.keys() {
        if !progress(RustSelectedContextWork::ScopeNode) {
            return Ok(RustSelectedBuildOutcome::Stopped);
        }
        let directory = path.parent().unwrap_or(Path::new(""));
        if !caller.starts_with(directory) {
            continue;
        }
        let depth = directory.components().count();
        if enclosing.is_none_or(|(selected, _)| depth > selected) {
            enclosing = Some((depth, path.as_path()));
        }
    }
    let profile = detached_profile_for_source(enclosing.map(|(_, path)| path), caller)?;
    let RustSelectedBuildOutcome::Ready(context) =
        build_rust_selected_topology_context_with_progress(
            source_mounts.iter().cloned(),
            manifest_mounts.iter().cloned(),
            profile,
            progress,
        )?
    else {
        return Ok(RustSelectedBuildOutcome::Stopped);
    };
    Ok(RustSelectedBuildOutcome::Ready(
        RustSelectedLibraryContextOutcome::Ready(Box::new(context)),
    ))
}

/// The `Detached` profile of one source no Cargo target reaches: the file is
/// its own single-file crate root, rooted at the nearest enclosing manifest
/// when there is one and at the workspace root when there is none.
fn detached_profile_for_source(
    enclosing_manifest: Option<&Path>,
    source: &Path,
) -> Result<RustCallerTargetProfile, String> {
    let (manifest_path, target_root) = match enclosing_manifest {
        Some(path) => {
            let directory = path.parent().unwrap_or(Path::new(""));
            let target_root = source.strip_prefix(directory).map_err(|error| {
                format!("detached Rust source escapes its enclosing manifest: {error}")
            })?;
            (path.to_path_buf(), target_root.to_path_buf())
        }
        None => (PathBuf::new(), source.to_path_buf()),
    };
    Ok(RustCallerTargetProfile {
        manifest_path,
        target_kind: RustCallerTargetKind::Detached,
        target_root,
        target_triple: "selected-detached-unspecified".to_string(),
        cfg_atoms: crate::cfg::default_cfg_atoms(),
        features: BTreeSet::new(),
        test: true,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RustSelectedModuleEdge {
    pub crate_root: PathBuf,
    pub declaring_file: PathBuf,
    pub target_file: PathBuf,
    /// Canonical source declaration which introduced this module edge. The
    /// file root has no edge; module continuation joins this identity before
    /// consulting the selected module path.
    pub declaration: Option<SourceDeclarationId>,
    pub declaring_module_segments: Box<[String]>,
    pub module_segments: Box<[String]>,
    pub visibility: RustVisibility,
    pub imports_macros: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct RustSelectedDependencyEdge {
    pub source_crate_root: PathBuf,
    pub exposed_name: String,
    pub target_crate_root: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RustSelectedModuleActivation {
    pub file: PathBuf,
    pub module_name: String,
    pub start_byte: usize,
    pub end_byte: usize,
    pub activation: RustSelectedActivation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RustSelectedRootRouteKind {
    Module,
    ExternCrate,
    NamedUse,
    GlobUse,
    LocalNamedUse,
    LocalGlobUse,
    NamedReexport,
    GlobReexport,
    ExportedMacro,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct RustSelectedRootRoute {
    pub file: PathBuf,
    /// Selected structured module path at which this route is declared.
    pub owner_module_segments: Box<[String]>,
    /// Common-resolution attachment scope for routes that participate in a
    /// selected import half. Macro-generated unsupported scopes remain absent.
    pub owner_resolution_scope: Option<ResolutionScopeId>,
    pub route: String,
    pub route_segments: Option<Box<[String]>>,
    /// Structural anchor at which this route starts. The marker is semantic:
    /// it must remain distinct from an otherwise identical bare route when
    /// selected topology chooses a destination.
    pub anchor: ResolutionRootImportAnchor,
    pub local_name: Option<String>,
    pub target_name: Option<String>,
    pub kind: RustSelectedRootRouteKind,
    pub visibility: RustVisibility,
    /// Canonical declaration for a synthetic selected module route. Import,
    /// macro, and other non-module routes have no module declaration.
    pub declaration: Option<SourceDeclarationId>,
    /// Source import ordinal for real import routes. Synthetic module and
    /// exported-macro routes have no corresponding import declaration.
    pub source_import_ordinal: Option<usize>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct RustSelectedRootBridge {
    pub source_file: PathBuf,
    pub source_import_site: ResolutionSiteId,
    /// Exact source import declaration, independent of its terminal export name.
    pub source_import_ordinal: usize,
    pub source_root_scope: ResolutionScopeId,
    pub anchor: ResolutionRootImportAnchor,
    pub target_file: PathBuf,
    pub target_root_scope: ResolutionScopeId,
    pub route: Box<[String]>,
    pub source_name: String,
    pub target_name: String,
    pub namespace: ResolutionNamespace,
    /// Exact source declaration authority for the terminal target.  This is
    /// optional only for the legacy topology test constructors; production
    /// selected Rust routes must carry it before a restricted target is
    /// admitted.
    pub declaration_authority: Option<RustSelectedDeclarationAuthority>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct RustSelectedRootImportAuthority {
    pub source_file: PathBuf,
    pub source_module_segments: Box<[String]>,
    pub source_root_scope: ResolutionScopeId,
    pub route: Box<[String]>,
    /// Structural anchor retained from the source import.
    pub anchor: ResolutionRootImportAnchor,
    pub source_name: String,
    pub target_name: String,
    pub namespace: ResolutionNamespace,
    /// Source import ordinal for a real import authority. Positioned root
    /// references are demand authorities, not import declarations.
    pub source_import_ordinal: Option<usize>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct RustSelectedRootExportAuthority {
    pub target_file: PathBuf,
    pub target_module_segments: Box<[String]>,
    pub target_root_scope: ResolutionScopeId,
    pub name: String,
    pub namespace: ResolutionNamespace,
    /// Exact source declaration authority for this terminal.  The root token
    /// is shared by scope and namespace and is never an identity join. `None`
    /// is unavailable authority and must be rejected by the operation; it is
    /// never an unrestricted/public fallback.
    pub declaration_authority: Option<RustSelectedDeclarationAuthority>,
}

/// Source-owned authority for one selected Rust declaration.  The operation
/// obtains this record through `resolution_semantic_sites.source_site`, then
/// `source_native_declaration_bridges.declaration_id`, and finally the Rust
/// declaration-property row.  Names and parser-unit keys are deliberately not
/// part of this identity contract.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RustSelectedDeclarationAuthority {
    pub source_site: ResolutionSiteId,
    pub declaration: SourceDeclarationId,
    pub crate_root: PathBuf,
    pub declaring_module_segments: Box<[String]>,
    pub visibility: RustVisibility,
}

impl Ord for RustSelectedDeclarationAuthority {
    fn cmp(&self, other: &Self) -> Ordering {
        self.source_site
            .cmp(&other.source_site)
            .then_with(|| self.declaration.get().cmp(&other.declaration.get()))
            .then_with(|| self.crate_root.cmp(&other.crate_root))
            .then_with(|| {
                self.declaring_module_segments
                    .cmp(&other.declaring_module_segments)
            })
            .then_with(|| self.visibility.cmp(&other.visibility))
    }
}

impl PartialOrd for RustSelectedDeclarationAuthority {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl RustSelectedDeclarationAuthority {
    pub fn reaches(
        &self,
        requester_crate_root: &Path,
        requester_module_segments: &[String],
    ) -> bool {
        rust_declaration_visibility_reaches(
            &self.visibility,
            self.crate_root == requester_crate_root,
            requester_module_segments,
            &self.declaring_module_segments,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct RustSelectedRootBridgeTopology {
    pub source_file: PathBuf,
    pub source_root_scope: ResolutionScopeId,
    pub target_file: PathBuf,
    pub target_root_scope: ResolutionScopeId,
    pub route: Box<[String]>,
    /// Structural anchor retained through bridge identity.
    pub anchor: ResolutionRootImportAnchor,
    pub source_name: String,
    pub target_name: String,
    pub namespace: ResolutionNamespace,
    /// Source import ordinal retained through topology deduplication.
    pub source_import_ordinal: Option<usize>,
    /// `None` is an operationally unavailable endpoint, never an allow-all
    /// result. The selected operation rejects such a bridge before composing
    /// a root descriptor.
    pub declaration_authority: Option<RustSelectedDeclarationAuthority>,
}

/// A selected bridge before the eager candidate-union projection forgets
/// which requester placement and source import justified it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct RustSelectedRootBridgeExposure {
    pub requester: RustSelectedTargetMembership,
    pub source_import: RustSelectedRootImportAuthority,
    pub bridge: RustSelectedRootBridgeTopology,
}

/// Structured file-local module path for one persisted module scope.
pub fn rust_selected_module_scope_segments(
    facts: &RustModuleRouteFacts,
    scope: usize,
) -> Box<[String]> {
    let mut segments = Vec::new();
    let mut current = Some(scope);
    while let Some(index) = current {
        assert!(index < facts.scopes.len(), "Rust module route has no scope");
        let scope_fact = &facts.scopes[index];
        if !scope_fact.module_name.is_empty() {
            segments.push(scope_fact.module_name.clone());
        }
        current = scope_fact.parent;
    }
    segments.reverse();
    segments.into_boxed_slice()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RustSelectedMacroVisibility {
    pub file: PathBuf,
    pub declaration: SourceDeclarationId,
    pub name: String,
    pub visible_after: usize,
    pub scope_start: usize,
    pub scope_end: usize,
    pub exported: bool,
}

/// Select a textual macro through the selected file-backed module ancestry.
/// Each parent lookup occurs at its module declaration, not at the end of the
/// parent file. Multiple placements must agree on the canonical definition.
pub fn rust_selected_textual_macro<'facts>(
    context: &RustSelectedContext,
    file: &Path,
    position: usize,
    name: &str,
    source: impl Fn(&Path) -> Option<&'facts RustUsageFacts>,
    imports_macros: impl Fn(&Path, SourceDeclarationId) -> bool,
    keep_going: &dyn Fn() -> bool,
) -> RustSelectedBuildOutcome<Option<(PathBuf, SourceDeclarationId)>> {
    type Query = (PathBuf, usize);
    type Definition = (PathBuf, SourceDeclarationId);
    type Rank = (usize, std::cmp::Reverse<usize>);
    enum Frame {
        Visit(Query),
        Finish {
            query: Query,
            local: Vec<(Rank, Definition)>,
            imported: Vec<(Rank, Query)>,
            parents: Vec<Query>,
        },
    }
    let initial = (file.to_path_buf(), position);
    let mut pending = vec![Frame::Visit(initial.clone())];
    let mut active = BTreeSet::new();
    let mut answers = BTreeMap::<Query, Option<Definition>>::new();
    while let Some(frame) = pending.pop() {
        if !keep_going() {
            return RustSelectedBuildOutcome::Stopped;
        }
        match frame {
            Frame::Visit(query) => {
                if answers.contains_key(&query) {
                    continue;
                }
                if !active.insert(query.clone()) {
                    answers.insert(query, None);
                    continue;
                }
                let (file, position) = &query;
                let Some(facts) = source(file) else {
                    answers.insert(query.clone(), None);
                    active.remove(&query);
                    continue;
                };
                let mut local = Vec::new();
                for definition in &context.macro_visibility {
                    if !keep_going() {
                        return RustSelectedBuildOutcome::Stopped;
                    }
                    if definition.file == *file
                        && definition.name == name
                        && definition.visible_after <= *position
                        && definition.scope_start <= *position
                        && (*position < definition.scope_end
                            || facts.module_routes.scopes.first().is_some_and(|root| {
                                *position == root.body_end
                                    && definition.scope_start == root.body_start
                                    && definition.scope_end == root.body_end
                            }))
                    {
                        local.push((
                            (
                                definition.scope_end - definition.scope_start,
                                std::cmp::Reverse(definition.visible_after),
                            ),
                            (file.clone(), definition.declaration),
                        ));
                    }
                }
                let mut imported = Vec::new();
                let mut parents = Vec::new();
                for edge in &context.module_edges {
                    if !keep_going() {
                        return RustSelectedBuildOutcome::Stopped;
                    }
                    if edge.target_file == *file && edge.declaring_file != *file {
                        let Some(parent) = source(&edge.declaring_file) else {
                            continue;
                        };
                        let route = parent
                            .module_routes
                            .routes
                            .iter()
                            .find(|route| Some(route.declaration) == edge.declaration)
                            .expect("file-backed module edge has a source route");
                        parents.push((edge.declaring_file.clone(), route.declaration_start));
                    }
                    if edge.declaring_file != *file
                        || !edge
                            .declaration
                            .is_some_and(|declaration| imports_macros(file, declaration))
                    {
                        continue;
                    }
                    let (owner, visible_after, target_position) = if edge.target_file == *file {
                        let scope = facts
                            .module_routes
                            .scopes
                            .iter()
                            .find(|scope| scope.declaration == edge.declaration)
                            .expect("inline module edge has a source scope");
                        let owner = &facts.module_routes.scopes
                            [scope.parent.expect("inline module has a parent")];
                        (owner, scope.body_end, scope.body_end.saturating_sub(1))
                    } else {
                        let route = facts
                            .module_routes
                            .routes
                            .iter()
                            .find(|route| Some(route.declaration) == edge.declaration)
                            .expect("file-backed module edge has a source route");
                        let Some(target) = source(&edge.target_file) else {
                            continue;
                        };
                        let Some(root) = target.module_routes.scopes.first() else {
                            continue;
                        };
                        (
                            &facts.module_routes.scopes[route.scope],
                            route.declaration_end,
                            root.body_end,
                        )
                    };
                    if visible_after <= *position
                        && owner.body_start <= *position
                        && (*position < owner.body_end
                            || facts.module_routes.scopes.first().is_some_and(|root| {
                                *position == root.body_end
                                    && owner.body_start == root.body_start
                                    && owner.body_end == root.body_end
                            }))
                    {
                        imported.push((
                            (
                                owner.body_end - owner.body_start,
                                std::cmp::Reverse(visible_after),
                            ),
                            (edge.target_file.clone(), target_position),
                        ));
                    }
                }
                for splice in &context.include_splices {
                    if !keep_going() {
                        return RustSelectedBuildOutcome::Stopped;
                    }
                    if splice.included_file == *file {
                        parents.push((splice.host_file.clone(), splice.include_start));
                    }
                    if splice.host_file != *file || splice.include_start >= *position {
                        continue;
                    }
                    let owner = facts
                        .module_routes
                        .scopes
                        .iter()
                        .filter(|scope| {
                            scope.body_start <= splice.include_start
                                && splice.include_start < scope.body_end
                        })
                        .min_by_key(|scope| scope.body_end - scope.body_start)
                        .expect("include is inside its host module");
                    if owner.body_start <= *position
                        && (*position < owner.body_end
                            || facts.module_routes.scopes.first().is_some_and(|root| {
                                *position == root.body_end
                                    && owner.body_start == root.body_start
                                    && owner.body_end == root.body_end
                            }))
                        && let Some(root) = source(&splice.included_file)
                            .and_then(|facts| facts.module_routes.scopes.first())
                    {
                        imported.push((
                            (
                                owner.body_end - owner.body_start,
                                std::cmp::Reverse(splice.include_start),
                            ),
                            (splice.included_file.clone(), root.body_end),
                        ));
                    }
                }
                let dependencies = imported
                    .iter()
                    .map(|(_, query)| query.clone())
                    .chain(parents.iter().cloned())
                    .collect::<Vec<_>>();
                pending.push(Frame::Finish {
                    query,
                    local,
                    imported,
                    parents,
                });
                pending.extend(dependencies.into_iter().map(Frame::Visit));
            }
            Frame::Finish {
                query,
                mut local,
                imported,
                parents,
            } => {
                for (rank, dependency) in imported {
                    if let Some(Some(definition)) = answers.get(&dependency) {
                        local.push((rank, definition.clone()));
                    }
                }
                local.sort();
                let selected = if let Some((rank, definition)) = local.first() {
                    local
                        .iter()
                        .take_while(|(other, _)| other == rank)
                        .all(|(_, candidate)| candidate == definition)
                        .then(|| definition.clone())
                } else {
                    let candidates = parents
                        .iter()
                        .map(|parent| answers.get(parent).cloned().flatten())
                        .collect::<BTreeSet<_>>();
                    (candidates.len() == 1)
                        .then(|| candidates.into_iter().next().flatten())
                        .flatten()
                };
                active.remove(&query);
                answers.insert(query, selected);
            }
        }
    }
    RustSelectedBuildOutcome::Ready(answers.remove(&initial).flatten())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RustSelectedIncludeSplice {
    pub host_file: PathBuf,
    pub included_file: PathBuf,
    pub host_module: String,
    pub include_start: usize,
    pub host_bindings: Box<[RustIncludeHostBindingFact]>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct RustSelectedTargetMembership {
    pub crate_root: PathBuf,
    pub file: PathBuf,
    pub edition: RustCargoEdition,
    pub module_segments: Box<[String]>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RustSelectedContextGap {
    ExternalDependency {
        source_crate_root: PathBuf,
        exposed_name: String,
    },
    UnknownActivation {
        file: PathBuf,
        start_byte: usize,
    },
    UnsupportedMacroGeneratedModule {
        file: PathBuf,
        start_byte: usize,
    },
    CyclicModuleRoute {
        file: PathBuf,
        start_byte: usize,
    },
    CyclicInclude {
        file: PathBuf,
        include_start: usize,
    },
    InvalidMountedPath {
        path: PathBuf,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RustSelectedContext {
    pub profile: RustCallerTargetProfile,
    pub identity: Oid,
    pub target_roots: BTreeSet<PathBuf>,
    /// Actual module placements at each selected file's content root. Inline
    /// memberships extend one of these roots with file-local module segments.
    pub file_root_memberships: BTreeSet<RustSelectedTargetMembership>,
    pub target_memberships: BTreeSet<RustSelectedTargetMembership>,
    pub reachable_files: BTreeSet<PathBuf>,
    pub dependency_edges: Box<[RustSelectedDependencyEdge]>,
    pub module_edges: Box<[RustSelectedModuleEdge]>,
    pub module_activations: Box<[RustSelectedModuleActivation]>,
    pub root_routes: Box<[RustSelectedRootRoute]>,
    pub root_bridges: Box<[RustSelectedRootBridge]>,
    pub macro_visibility: Box<[RustSelectedMacroVisibility]>,
    pub include_splices: Box<[RustSelectedIncludeSplice]>,
    pub gaps: BTreeSet<RustSelectedContextGap>,
}

pub fn build_rust_selected_context(
    source_mounts: impl IntoIterator<Item = RustSelectedSourceMount>,
    manifest_mounts: impl IntoIterator<Item = RustSelectedManifestMount>,
    profile: RustCallerTargetProfile,
) -> Result<RustSelectedContext, String> {
    let RustSelectedBuildOutcome::Ready(mut build) = build_rust_selected_context_with_progress(
        source_mounts,
        manifest_mounts,
        profile,
        &mut |_| true,
    )?
    else {
        unreachable!("an always-live selected Rust context build cannot stop")
    };
    let dependency_edges = build
        .context
        .dependency_edges
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    build.context.root_bridges = selected_root_bridges(
        &build.sources,
        &build.context.file_root_memberships,
        &build.context.target_memberships,
        &dependency_edges,
        &build.context.module_edges,
        &build.context.root_routes,
    );
    Ok(build.context)
}

struct RustSelectedContextBuild {
    context: RustSelectedContext,
    sources: BTreeMap<PathBuf, RustSelectedSourceMount>,
}

fn build_rust_selected_context_with_progress(
    source_mounts: impl IntoIterator<Item = RustSelectedSourceMount>,
    manifest_mounts: impl IntoIterator<Item = RustSelectedManifestMount>,
    profile: RustCallerTargetProfile,
    progress: &mut impl FnMut(RustSelectedContextWork) -> bool,
) -> Result<RustSelectedBuildOutcome<RustSelectedContextBuild>, String> {
    let RustSelectedBuildOutcome::Ready(sources) = unique_mounts(
        source_mounts,
        |mount| &mount.relative_path,
        "source",
        progress,
    )?
    else {
        return Ok(RustSelectedBuildOutcome::Stopped);
    };
    let RustSelectedBuildOutcome::Ready(manifests) = unique_mounts(
        manifest_mounts,
        |mount| &mount.relative_path,
        "manifest",
        progress,
    )?
    else {
        return Ok(RustSelectedBuildOutcome::Stopped);
    };
    for manifest in manifests.values() {
        if !progress(RustSelectedContextWork::ScopeNode) {
            return Ok(RustSelectedBuildOutcome::Stopped);
        }
        if manifest.facts.version != RUST_CARGO_MANIFEST_FACT_VERSION {
            return Err(format!(
                "unsupported Rust Cargo manifest fact version at {:?}: {}",
                manifest.relative_path, manifest.facts.version
            ));
        }
    }
    if !manifests.contains_key(&profile.manifest_path) {
        return Err(format!(
            "caller manifest is absent from selected inventory: {:?}",
            profile.manifest_path
        ));
    }
    let RustSelectedBuildOutcome::Ready(content_identity) =
        selected_content_identity_bytes(&sources, &manifests, progress)?
    else {
        return Ok(RustSelectedBuildOutcome::Stopped);
    };
    let mut manifests_by_directory = BTreeMap::new();
    for path in manifests.keys() {
        if !progress(RustSelectedContextWork::ScopeNode) {
            return Ok(RustSelectedBuildOutcome::Stopped);
        }
        manifests_by_directory.insert(
            path.parent().unwrap_or(Path::new("")).to_path_buf(),
            path.clone(),
        );
    }
    let RustSelectedBuildOutcome::Ready(source_topologies) =
        prepare_rust_selected_source_topologies(&sources, progress)?
    else {
        return Ok(RustSelectedBuildOutcome::Stopped);
    };
    let RustSelectedBuildOutcome::Ready(context) =
        build_rust_selected_context_from_maps_with_progress(
            &sources,
            &manifests,
            &manifests_by_directory,
            profile,
            progress,
            &source_topologies,
            &content_identity,
        )?
    else {
        return Ok(RustSelectedBuildOutcome::Stopped);
    };
    Ok(RustSelectedBuildOutcome::Ready(RustSelectedContextBuild {
        context,
        sources,
    }))
}

fn build_rust_selected_context_from_maps_with_progress(
    sources: &BTreeMap<PathBuf, RustSelectedSourceMount>,
    manifests: &BTreeMap<PathBuf, RustSelectedManifestMount>,
    manifests_by_directory: &BTreeMap<PathBuf, PathBuf>,
    profile: RustCallerTargetProfile,
    progress: &mut impl FnMut(RustSelectedContextWork) -> bool,
    source_topologies: &BTreeMap<PathBuf, RustSelectedPreparedSource>,
    content_identity: &[u8],
) -> Result<RustSelectedBuildOutcome<RustSelectedContext>, String> {
    let RustSelectedBuildOutcome::Ready(identity) =
        selected_context_identity(content_identity, &profile, progress)?
    else {
        return Ok(RustSelectedBuildOutcome::Stopped);
    };
    let mut gaps = BTreeSet::new();
    let mut roots = BTreeSet::new();
    let mut pending_roots = VecDeque::new();
    let mut dependency_edges = BTreeSet::new();
    let mut external_dependencies: BTreeMap<PathBuf, BTreeSet<String>> = BTreeMap::new();
    let cargo_manifests = manifests
        .values()
        .map(|manifest| {
            (
                manifest
                    .relative_path
                    .parent()
                    .unwrap_or(Path::new(""))
                    .to_path_buf(),
                manifest.document.clone(),
            )
        })
        .collect::<CargoHashMap<_, _>>();
    let caller_directory = profile.manifest_path.parent().unwrap_or(Path::new(""));
    let caller_root = normalize_selected_path(caller_directory, &profile.target_root)
        .ok_or_else(|| "caller target root escapes selected inventory".to_string())?;
    let mut detached_editions = BTreeMap::new();
    if profile.target_kind == RustCallerTargetKind::Detached {
        assert!(
            sources.contains_key(&caller_root),
            "a detached selected Rust caller root is a mounted source: {caller_root:?}"
        );
        let RustSelectedBuildOutcome::Ready(edition) =
            detached_caller_edition(&profile.manifest_path, manifests, progress)?
        else {
            return Ok(RustSelectedBuildOutcome::Stopped);
        };
        roots.insert(caller_root.clone());
        detached_editions.insert(caller_root.clone(), edition);
    } else if sources.contains_key(&caller_root) {
        let RustSelectedBuildOutcome::Ready(edition) =
            effective_cargo_edition(&profile.manifest_path, manifests, progress)?
        else {
            return Ok(RustSelectedBuildOutcome::Stopped);
        };
        roots.insert(caller_root.clone());
        pending_roots.push_back((profile.manifest_path.clone(), caller_root.clone(), edition));
        let package = manifests[&profile.manifest_path]
            .facts
            .package
            .as_ref()
            .expect("a selected Cargo target has package facts");
        if let Some(library_root) = same_package_library_root(&profile, package, sources)? {
            roots.insert(library_root.clone());
            dependency_edges.insert(RustSelectedDependencyEdge {
                source_crate_root: caller_root.clone(),
                exposed_name: package.library_name.clone(),
                target_crate_root: library_root.clone(),
            });
            pending_roots.push_back((profile.manifest_path.clone(), library_root, edition));
        }
    }

    let mut visited_manifests = BTreeSet::new();
    let mut crate_editions = detached_editions;
    while let Some((manifest_path, source_crate_root, source_edition)) = pending_roots.pop_front() {
        if !progress(RustSelectedContextWork::ScopeNode) {
            return Ok(RustSelectedBuildOutcome::Stopped);
        }
        if !visited_manifests.insert((manifest_path.clone(), source_crate_root.clone())) {
            continue;
        }
        let manifest = &manifests[&manifest_path];
        let directory = manifest_path.parent().unwrap_or(Path::new(""));
        for dependency in &manifest.facts.dependencies {
            if !progress(RustSelectedContextWork::ScopeNode) {
                return Ok(RustSelectedBuildOutcome::Stopped);
            }
            let available = if source_crate_root == caller_root {
                dependency_available(dependency.kind, profile.target_kind, profile.test)
            } else {
                dependency.kind == RustCargoDependencyKind::Normal
            };
            if !available {
                continue;
            }
            let table_name = match dependency.kind {
                RustCargoDependencyKind::Normal => "dependencies",
                RustCargoDependencyKind::Development => "dev-dependencies",
                RustCargoDependencyKind::Build => "build-dependencies",
            };
            let raw_dependency = manifest
                .document
                .get(table_name)
                .and_then(toml::Value::as_table)
                .and_then(|dependencies| dependencies.get(&dependency.manifest_name))
                .expect("every selected Cargo dependency fact retains its source value");
            let Some(dependency_directory) = cargo_dependency_directory_with(
                Path::new(""),
                directory,
                &manifest.document,
                &dependency.manifest_name,
                raw_dependency,
                &cargo_manifests,
                &mut normalize_selected_path,
            ) else {
                if let Some(relative_path) = dependency.relative_path.as_deref()
                    && normalize_selected_path(directory, relative_path).is_none()
                {
                    gaps.insert(RustSelectedContextGap::InvalidMountedPath {
                        path: relative_path.to_path_buf(),
                    });
                } else {
                    external_dependencies
                        .entry(source_crate_root.clone())
                        .or_default()
                        .insert(dependency.exposed_name.clone());
                }
                continue;
            };
            let Some(dependency_manifest_path) = manifests_by_directory.get(&dependency_directory)
            else {
                external_dependencies
                    .entry(source_crate_root.clone())
                    .or_default()
                    .insert(dependency.exposed_name.clone());
                continue;
            };
            let dependency_manifest = &manifests[dependency_manifest_path];
            let Some(package) = dependency_manifest.facts.package.as_ref() else {
                external_dependencies
                    .entry(source_crate_root.clone())
                    .or_default()
                    .insert(dependency.exposed_name.clone());
                continue;
            };
            let RustSelectedBuildOutcome::Ready(dependency_edition) =
                effective_cargo_edition(&dependency_manifest.relative_path, manifests, progress)?
            else {
                return Ok(RustSelectedBuildOutcome::Stopped);
            };
            if !cargo_library_target_enabled(package) {
                external_dependencies
                    .entry(source_crate_root.clone())
                    .or_default()
                    .insert(dependency.exposed_name.clone());
                continue;
            }
            if package.package_name != dependency.package_name {
                external_dependencies
                    .entry(source_crate_root.clone())
                    .or_default()
                    .insert(dependency.exposed_name.clone());
                continue;
            }
            let Some(root) = normalize_selected_path(&dependency_directory, &package.library_path)
            else {
                gaps.insert(RustSelectedContextGap::InvalidMountedPath {
                    path: package.library_path.clone(),
                });
                continue;
            };
            if sources.contains_key(&root) {
                roots.insert(root.clone());
                dependency_edges.insert(RustSelectedDependencyEdge {
                    source_crate_root: source_crate_root.clone(),
                    exposed_name: dependency.exposed_name.clone(),
                    target_crate_root: root.clone(),
                });
                pending_roots.push_back((
                    dependency_manifest.relative_path.clone(),
                    root,
                    dependency_edition,
                ));
            } else {
                external_dependencies
                    .entry(source_crate_root.clone())
                    .or_default()
                    .insert(dependency.exposed_name.clone());
            }
        }
        crate_editions.insert(source_crate_root, source_edition);
    }

    let mut reachable_files = BTreeSet::new();
    let mut target_memberships = BTreeSet::new();
    let mut file_root_memberships = BTreeSet::new();
    let mut module_edges = Vec::new();
    let mut include_splices = Vec::new();
    let mut pending_files: VecDeque<(_, _, _, _, Vec<PathBuf>, Vec<PathBuf>)> = VecDeque::new();
    for root in &roots {
        if !progress(RustSelectedContextWork::ScopeNode) {
            return Ok(RustSelectedBuildOutcome::Stopped);
        }
        pending_files.push_back((
            root.clone(),
            root.clone(),
            crate_editions[root],
            Vec::<String>::new(),
            vec![root.clone()],
            vec![root.clone()],
        ));
    }
    while let Some((
        crate_root,
        file,
        edition,
        module_segments,
        module_ancestry,
        include_ancestry,
    )) = pending_files.pop_front()
    {
        if !progress(RustSelectedContextWork::ScopeNode) {
            return Ok(RustSelectedBuildOutcome::Stopped);
        }
        let membership = RustSelectedTargetMembership {
            crate_root: crate_root.clone(),
            file: file.clone(),
            edition,
            module_segments: module_segments.clone().into_boxed_slice(),
        };
        if !target_memberships.insert(membership.clone()) {
            continue;
        }
        file_root_memberships.insert(membership);
        reachable_files.insert(file.clone());
        let source_facts = &sources[&file].facts;
        let facts = &source_facts.module_routes;
        for scope_index in 1..facts.scopes.len() {
            if !progress(RustSelectedContextWork::ScopeNode) {
                return Ok(RustSelectedBuildOutcome::Stopped);
            }
            let scope = &facts.scopes[scope_index];
            if !source_topologies[file.as_path()].scope_is_inline[scope_index] {
                continue;
            }
            let scope_activation = selected_prepared_scope_activation_with_progress(
                &source_topologies[file.as_path()].scope_activations[scope_index],
                &profile,
                &file,
                &mut gaps,
                progress,
            );
            let RustSelectedBuildOutcome::Ready(RustSelectedActivation::Active) = scope_activation
            else {
                continue;
            };
            if !(0..source_topologies[file.as_path()].scope_activations[scope_index].len())
                .all(|_| progress(RustSelectedContextWork::ScopeNode))
            {
                return Ok(RustSelectedBuildOutcome::Stopped);
            }
            let scope_segments =
                source_topologies[file.as_path()].scope_segments[scope_index].to_vec();
            let mut module_path = module_segments.clone();
            module_path.extend(scope_segments.iter().cloned());
            target_memberships.insert(RustSelectedTargetMembership {
                crate_root: crate_root.clone(),
                file: file.clone(),
                edition,
                module_segments: module_path.clone().into_boxed_slice(),
            });
            let mut declaring_module_path = module_segments.clone();
            if let Some((_, parent)) = scope_segments.split_last() {
                declaring_module_path.extend(parent.iter().cloned());
            }
            module_edges.push(RustSelectedModuleEdge {
                crate_root: crate_root.clone(),
                declaring_file: file.clone(),
                target_file: file.clone(),
                declaration: scope.declaration,
                declaring_module_segments: declaring_module_path.into_boxed_slice(),
                module_segments: module_path.into_boxed_slice(),
                visibility: scope.visibility.clone(),
                imports_macros: scope.imports_macros,
            });
        }
        let RustSelectedBuildOutcome::Ready(routes) = resolved_module_routes_from_prepared(
            &file,
            facts,
            &source_topologies[file.as_path()],
            &profile,
            &mut gaps,
            progress,
        ) else {
            return Ok(RustSelectedBuildOutcome::Stopped);
        };
        for (route_index, route) in routes {
            if !(0..facts.scopes.len()).all(|_| progress(RustSelectedContextWork::ScopeNode)) {
                return Ok(RustSelectedBuildOutcome::Stopped);
            }
            let candidates = if file == crate_root {
                source_topologies[file.as_path()].routes[route_index]
                    .candidates_for_root
                    .as_ref()
            } else {
                source_topologies[file.as_path()].routes[route_index]
                    .candidates_for_file
                    .as_ref()
            };
            for target in candidates {
                if !progress(RustSelectedContextWork::ScopeNode) {
                    return Ok(RustSelectedBuildOutcome::Stopped);
                }
                if !sources.contains_key(target) {
                    continue;
                }
                let mut target_module_segments = module_segments.clone();
                if !(0..source_topologies[file.as_path()].scope_activations[route.scope].len())
                    .all(|_| progress(RustSelectedContextWork::ScopeNode))
                {
                    return Ok(RustSelectedBuildOutcome::Stopped);
                }
                let inline_module_segments =
                    &source_topologies[file.as_path()].scope_segments[route.scope];
                target_module_segments.extend(inline_module_segments.iter().cloned());
                target_module_segments.push(route.module_name.clone());
                let mut declaring_module_segments = module_segments.clone();
                declaring_module_segments.extend(inline_module_segments.iter().cloned());
                module_edges.push(RustSelectedModuleEdge {
                    crate_root: crate_root.clone(),
                    declaring_file: file.clone(),
                    target_file: target.clone(),
                    declaration: Some(route.declaration),
                    declaring_module_segments: declaring_module_segments.into_boxed_slice(),
                    module_segments: target_module_segments.clone().into_boxed_slice(),
                    visibility: route.visibility.clone(),
                    imports_macros: route.imports_macros,
                });
                if module_ancestry.contains(target) {
                    gaps.insert(RustSelectedContextGap::CyclicModuleRoute {
                        file: file.clone(),
                        start_byte: route.declaration_start,
                    });
                    continue;
                }
                let mut target_ancestry = module_ancestry.clone();
                target_ancestry.push(target.clone());
                pending_files.push_back((
                    crate_root.clone(),
                    target.clone(),
                    edition,
                    target_module_segments,
                    target_ancestry,
                    vec![target.clone()],
                ));
            }
        }
        for (include_index, edge) in source_facts.include_edges.iter().enumerate() {
            if !progress(RustSelectedContextWork::ScopeNode) {
                return Ok(RustSelectedBuildOutcome::Stopped);
            }
            let scope = source_topologies[file.as_path()].includes[include_index].scope;
            let activation_outcome = selected_prepared_scope_activation_with_progress(
                &source_topologies[file.as_path()].scope_activations[scope],
                &profile,
                &file,
                &mut gaps,
                progress,
            );
            let RustSelectedBuildOutcome::Ready(activation) = activation_outcome else {
                return Ok(RustSelectedBuildOutcome::Stopped);
            };
            if activation != RustSelectedActivation::Active {
                continue;
            }
            let target = source_topologies[file.as_path()].includes[include_index]
                .target
                .as_ref();
            let Some(target) = target else {
                gaps.insert(RustSelectedContextGap::InvalidMountedPath {
                    path: PathBuf::from(&edge.relative_path),
                });
                continue;
            };
            if !sources.contains_key(target) {
                // The missing expansion can introduce any binding in the host
                // scope, so an empty route inventory cannot prove absence.
                gaps.insert(RustSelectedContextGap::UnsupportedMacroGeneratedModule {
                    file: file.clone(),
                    start_byte: edge.include_start,
                });
                continue;
            }
            if !(0..source_topologies[file.as_path()].scope_activations[scope].len())
                .all(|_| progress(RustSelectedContextWork::ScopeNode))
            {
                return Ok(RustSelectedBuildOutcome::Stopped);
            }
            let scope_segments = &source_topologies[file.as_path()].scope_segments[scope];
            if include_ancestry.contains(target) {
                gaps.insert(RustSelectedContextGap::CyclicInclude {
                    file: file.clone(),
                    include_start: edge.include_start,
                });
                continue;
            }
            include_splices.push(RustSelectedIncludeSplice {
                host_file: file.clone(),
                included_file: target.clone(),
                host_module: module_segments
                    .iter()
                    .cloned()
                    .chain(scope_segments.iter().cloned())
                    .collect::<Vec<_>>()
                    .join("."),
                include_start: edge.include_start,
                host_bindings: edge.host_bindings.clone().into_boxed_slice(),
            });
            let mut target_module_segments = module_segments.clone();
            target_module_segments.extend(scope_segments.iter().cloned());
            let target_membership = RustSelectedTargetMembership {
                crate_root: crate_root.clone(),
                file: target.clone(),
                edition,
                module_segments: target_module_segments.into_boxed_slice(),
            };
            if !target_memberships.contains(&target_membership) {
                let mut target_ancestry = include_ancestry.clone();
                target_ancestry.push(target.clone());
                let mut target_module_ancestry = module_ancestry.clone();
                target_module_ancestry.push(target.clone());
                pending_files.push_back((
                    crate_root.clone(),
                    target.to_path_buf(),
                    edition,
                    target_membership.module_segments.into_vec(),
                    target_module_ancestry,
                    target_ancestry,
                ));
            }
        }
    }

    // The route reducers below only ask for memberships owned by the current
    // file. Keep the BTreeSet as the canonical public inventory, but index its
    // already-sorted entries by file so each reducer does not rescan every
    // membership for every reachable file.
    let mut file_root_memberships_by_file: HashMap<&Path, Vec<&RustSelectedTargetMembership>> =
        HashMap::new();
    for membership in &file_root_memberships {
        if !progress(RustSelectedContextWork::ScopeNode) {
            return Ok(RustSelectedBuildOutcome::Stopped);
        }
        file_root_memberships_by_file
            .entry(membership.file.as_path())
            .or_default()
            .push(membership);
    }

    let mut module_activations = Vec::new();
    let mut root_routes = Vec::new();
    let mut macro_visibility = Vec::new();
    for file in &reachable_files {
        if !progress(RustSelectedContextWork::ScopeNode) {
            return Ok(RustSelectedBuildOutcome::Stopped);
        }
        let source_mount = &sources[file];
        let facts = &source_mount.facts;
        if !(0..source_topologies[file.as_path()].module_scope_index_work)
            .all(|_| progress(RustSelectedContextWork::ScopeNode))
        {
            return Ok(RustSelectedBuildOutcome::Stopped);
        }
        let module_scopes_by_body = &source_topologies[file.as_path()].scopes_by_body;
        for (module_index, module) in facts.modules.iter().enumerate() {
            if !progress(RustSelectedContextWork::ScopeNode) {
                return Ok(RustSelectedBuildOutcome::Stopped);
            }
            let activation_outcome = selected_prepared_module_activation_with_progress(
                &source_topologies[file.as_path()].module_activations[module_index],
                &profile,
                file,
                &mut gaps,
                progress,
            );
            let RustSelectedBuildOutcome::Ready(activation) = activation_outcome else {
                return Ok(RustSelectedBuildOutcome::Stopped);
            };
            if activation == RustSelectedActivation::Unknown {
                gaps.insert(RustSelectedContextGap::UnknownActivation {
                    file: file.clone(),
                    start_byte: module.start_byte,
                });
            }
            module_activations.push(RustSelectedModuleActivation {
                file: file.clone(),
                module_name: module.module_name.clone(),
                start_byte: module.start_byte,
                end_byte: module.end_byte,
                activation,
            });
            if activation != RustSelectedActivation::Inactive && !module.module_name.is_empty() {
                let visibility =
                    &source_topologies[file.as_path()].module_visibilities[module_index];
                if !(0..source_topologies[file.as_path()].module_declaring_work[module_index])
                    .all(|_| progress(RustSelectedContextWork::ScopeNode))
                {
                    return Ok(RustSelectedBuildOutcome::Stopped);
                }
                let declaring_module_segments = source_topologies[file.as_path()]
                    .module_declaring_segments[module_index]
                    .as_deref()
                    .expect("every active non-root Rust module has one structured declaring scope");
                let local_module_name = module
                    .module_name
                    .rsplit('.')
                    .next()
                    .expect("a non-root Rust module has a local name")
                    .to_string();
                if let Some(file_memberships) = file_root_memberships_by_file.get(file.as_path()) {
                    for membership in file_memberships {
                        let mut owner_module_segments = Vec::new();
                        for segment in &membership.module_segments {
                            if !progress(RustSelectedContextWork::ScopeNode) {
                                return Ok(RustSelectedBuildOutcome::Stopped);
                            }
                            owner_module_segments.push(segment.clone());
                        }
                        for segment in declaring_module_segments {
                            if !progress(RustSelectedContextWork::ScopeNode) {
                                return Ok(RustSelectedBuildOutcome::Stopped);
                            }
                            owner_module_segments.push(segment.clone());
                        }
                        root_routes.push(RustSelectedRootRoute {
                            file: file.clone(),
                            owner_module_segments: owner_module_segments.into_boxed_slice(),
                            owner_resolution_scope: None,
                            route: local_module_name.clone(),
                            route_segments: None,
                            source_import_ordinal: None,
                            anchor: ResolutionRootImportAnchor::Lexical,
                            local_name: Some(local_module_name.clone()),
                            target_name: Some(local_module_name.clone()),
                            kind: RustSelectedRootRouteKind::Module,
                            visibility: visibility.clone(),
                            declaration: if module.is_inline {
                                module_scopes_by_body
                                    .get(&(module.start_byte, module.end_byte))
                                    .and_then(|scopes| {
                                        assert!(
                                            scopes.len() <= 1,
                                            "one inline Rust module body has one selected scope"
                                        );
                                        scopes.first().and_then(|(scope_index, _)| {
                                            facts.module_routes.scopes[*scope_index].declaration
                                        })
                                    })
                            } else {
                                facts
                                    .module_routes
                                    .routes
                                    .iter()
                                    .find(|route| {
                                        route.declaration_start == module.start_byte
                                            && route.declaration_end == module.end_byte
                                    })
                                    .map(|route| route.declaration)
                            },
                        });
                    }
                }
            }
        }
        for (import_index, import) in facts.import_targets.iter().enumerate() {
            if !progress(RustSelectedContextWork::ScopeNode) {
                return Ok(RustSelectedBuildOutcome::Stopped);
            }
            match profile.activation(&import.cfg_condition) {
                RustSelectedActivation::Inactive => continue,
                RustSelectedActivation::Unknown => {
                    gaps.insert(RustSelectedContextGap::UnknownActivation {
                        file: file.clone(),
                        start_byte: import.owner_start,
                    });
                    continue;
                }
                RustSelectedActivation::Active => {}
            }
            // An import no `mod` encloses is owned by the file's own root
            // module scope, and must not be joined to it by bytes: the two
            // projections measure a file-scope extent differently.
            // `RustImportContextFact` defines the file-root owner extent as
            // the complete canonical source bytes, while the root module
            // scope's body is the parse root occurrence, and tree-sitter
            // starts `source_file` at the first token. In a file that opens
            // with a blank line the two differ by the leading trivia, the byte
            // join found nothing, and every module-level `use` in that file
            // was dropped -- with its root route, its bridge, and every
            // reference that arrives through it, forward and reverse alike.
            // An inline module owner is the same interned body occurrence on
            // both sides, so those still join exactly.
            let owner = if import.owner_module.is_empty() {
                Some((0, &source_topologies[file.as_path()].scope_segments[0]))
            } else {
                let owner_scopes = module_scopes_by_body
                    .get(&(import.owner_start, import.owner_end))
                    .map(Vec::as_slice)
                    .unwrap_or(&[]);
                assert!(
                    owner_scopes.len() <= 1,
                    "one Rust module-level import has at most one structured owner scope: import={import:?}, scopes={owner_scopes:?}"
                );
                owner_scopes
                    .first()
                    .map(|(index, segments)| (*index, segments))
            };
            let Some((owner_scope_index, local_owner_segments)) = owner else {
                continue;
            };
            let owner_resolution_scope = if import.local_extent.is_some() {
                import.native_scope
            } else {
                facts.module_routes.scopes[owner_scope_index].resolution_scope
            };
            let Some(owner_resolution_scope) = owner_resolution_scope else {
                continue;
            };
            let reexport = !matches!(
                import.visibility,
                RustVisibility::Private | RustVisibility::SelfModule
            );
            let prepared_import = &source_topologies[file.as_path()].imports[import_index];
            if !(0..prepared_import.profile_work)
                .all(|_| progress(RustSelectedContextWork::ScopeNode))
            {
                return Ok(RustSelectedBuildOutcome::Stopped);
            }
            let (route_segments, anchor) = &prepared_import.route;
            if let Some(file_memberships) = file_root_memberships_by_file.get(file.as_path()) {
                for root in file_memberships {
                    let mut owner_module_segments = Vec::new();
                    for segment in &root.module_segments {
                        if !progress(RustSelectedContextWork::ScopeNode) {
                            return Ok(RustSelectedBuildOutcome::Stopped);
                        }
                        owner_module_segments.push(segment.clone());
                    }
                    for segment in local_owner_segments.iter() {
                        if !progress(RustSelectedContextWork::ScopeNode) {
                            return Ok(RustSelectedBuildOutcome::Stopped);
                        }
                        owner_module_segments.push(segment.clone());
                    }
                    root_routes.push(RustSelectedRootRoute {
                        file: file.clone(),
                        owner_module_segments: owner_module_segments.into_boxed_slice(),
                        owner_resolution_scope: Some(owner_resolution_scope),
                        route: import.module_path.join("::"),
                        route_segments: Some(route_segments.clone()),
                        source_import_ordinal: Some(import_index),
                        anchor: *anchor,
                        local_name: import.bound_name.clone(),
                        target_name: import.imported_name.clone(),
                        kind: if import.is_extern_crate {
                            RustSelectedRootRouteKind::ExternCrate
                        } else if Some(owner_resolution_scope)
                            != facts.module_routes.scopes[owner_scope_index].resolution_scope
                        {
                            if import.is_glob {
                                RustSelectedRootRouteKind::LocalGlobUse
                            } else {
                                RustSelectedRootRouteKind::LocalNamedUse
                            }
                        } else {
                            match (import.is_glob, reexport) {
                                (false, false) => RustSelectedRootRouteKind::NamedUse,
                                (true, false) => RustSelectedRootRouteKind::GlobUse,
                                (false, true) => RustSelectedRootRouteKind::NamedReexport,
                                (true, true) => RustSelectedRootRouteKind::GlobReexport,
                            }
                        },
                        visibility: import.visibility.clone(),
                        declaration: None,
                    });
                }
            }
        }
        for definition in &facts.module_routes.item_macros {
            if !progress(RustSelectedContextWork::ScopeNode) {
                return Ok(RustSelectedBuildOutcome::Stopped);
            }
            macro_visibility.push(RustSelectedMacroVisibility {
                file: file.clone(),
                declaration: definition.declaration,
                name: definition.name.clone(),
                visible_after: definition.visible_after,
                scope_start: definition.scope_start,
                scope_end: definition.scope_end,
                exported: definition.exported,
            });
            if definition.exported {
                root_routes.push(RustSelectedRootRoute {
                    file: file.clone(),
                    owner_module_segments: Box::new([]),
                    owner_resolution_scope: Some(ResolutionScopeId::new(0)),
                    route: definition.name.clone(),
                    route_segments: None,
                    source_import_ordinal: None,
                    anchor: ResolutionRootImportAnchor::Lexical,
                    local_name: Some(definition.name.clone()),
                    target_name: Some(definition.name.clone()),
                    kind: RustSelectedRootRouteKind::ExportedMacro,
                    visibility: RustVisibility::Public,
                    declaration: Some(definition.declaration),
                });
            }
        }
    }
    module_edges.sort_by(|left, right| {
        left.crate_root
            .cmp(&right.crate_root)
            .then_with(|| left.declaring_file.cmp(&right.declaring_file))
            .then_with(|| left.target_file.cmp(&right.target_file))
            .then_with(|| left.declaration.cmp(&right.declaration))
    });
    module_activations.sort_by(|left, right| {
        left.file
            .cmp(&right.file)
            .then_with(|| left.start_byte.cmp(&right.start_byte))
    });
    // Root extern aliases enter the crate's extern prelude. Included roots
    // also share aliases declared in their host module, regardless of the
    // physical file that supplied the declaration.
    let extern_routes = root_routes
        .iter()
        .filter(|route| route.kind == RustSelectedRootRouteKind::ExternCrate)
        .cloned()
        .collect::<Vec<_>>();
    for route in extern_routes {
        let owners = target_memberships
            .iter()
            .filter(|membership| {
                membership.file == route.file
                    && membership.module_segments == route.owner_module_segments
            })
            .collect::<Vec<_>>();
        for target in &target_memberships {
            if !progress(RustSelectedContextWork::ScopeNode) {
                return Ok(RustSelectedBuildOutcome::Stopped);
            }
            if owners.iter().any(|owner| {
                owner.crate_root == target.crate_root
                    && (owner.module_segments.is_empty()
                        || owner.module_segments == target.module_segments)
            }) && (target.file != route.file
                || target.module_segments != route.owner_module_segments)
            {
                let mut alias = route.clone();
                alias.file = target.file.clone();
                alias.owner_module_segments = target.module_segments.clone();
                alias.owner_resolution_scope = None;
                alias.source_import_ordinal = None;
                root_routes.push(alias);
            }
        }
    }
    root_routes.sort_by(|left, right| {
        left.file
            .cmp(&right.file)
            .then_with(|| left.owner_module_segments.cmp(&right.owner_module_segments))
            .then_with(|| left.route.cmp(&right.route))
            .then_with(|| left.anchor.cmp(&right.anchor))
            .then_with(|| left.kind.cmp(&right.kind))
            .then_with(|| left.source_import_ordinal.cmp(&right.source_import_ordinal))
    });
    // Every Rust crate reaches the standard library through the implicit
    // extern prelude. Bifrost never mounts its source, so treat the three
    // standard crate names as declared-but-unindexed for every selected crate
    // root alongside the registry and git dependencies collected above.
    for crate_root in crate_editions.keys() {
        for exposed_name in ["alloc", "core", "std"] {
            external_dependencies
                .entry(crate_root.clone())
                .or_default()
                .insert(exposed_name.to_string());
        }
    }
    // A root route names its first segment inside one file and module. Only the
    // memberships that own that exact file and module say which crate declared
    // the name, so index the canonical membership inventory once and keep the
    // boundary scan linear in memberships plus routes.
    let mut crate_roots_by_file_module: HashMap<(&Path, &[String]), Vec<&Path>> = HashMap::new();
    for membership in &target_memberships {
        if !progress(RustSelectedContextWork::ScopeNode) {
            return Ok(RustSelectedBuildOutcome::Stopped);
        }
        crate_roots_by_file_module
            .entry((membership.file.as_path(), &membership.module_segments))
            .or_default()
            .push(membership.crate_root.as_path());
    }
    for route in &root_routes {
        if !progress(RustSelectedContextWork::ScopeNode) {
            return Ok(RustSelectedBuildOutcome::Stopped);
        }
        let external_name = match route.kind {
            RustSelectedRootRouteKind::ExternCrate => route.target_name.as_deref(),
            RustSelectedRootRouteKind::NamedUse
            | RustSelectedRootRouteKind::GlobUse
            | RustSelectedRootRouteKind::LocalNamedUse
            | RustSelectedRootRouteKind::LocalGlobUse
            | RustSelectedRootRouteKind::NamedReexport
            | RustSelectedRootRouteKind::GlobReexport => route
                .route_segments
                .as_deref()
                .and_then(|segments| segments.first())
                .map(String::as_str),
            RustSelectedRootRouteKind::Module | RustSelectedRootRouteKind::ExportedMacro => None,
        };
        let Some(external_name) = external_name else {
            continue;
        };
        let Some(crate_roots) =
            crate_roots_by_file_module.get(&(route.file.as_path(), &*route.owner_module_segments))
        else {
            continue;
        };
        for crate_root in crate_roots {
            if external_dependencies
                .get(*crate_root)
                .is_some_and(|exposed_names| exposed_names.contains(external_name))
            {
                gaps.insert(RustSelectedContextGap::ExternalDependency {
                    source_crate_root: crate_root.to_path_buf(),
                    exposed_name: external_name.to_string(),
                });
            }
        }
    }
    macro_visibility.sort_by(|left, right| {
        left.file
            .cmp(&right.file)
            .then_with(|| left.visible_after.cmp(&right.visible_after))
    });
    include_splices.sort_by(|left, right| {
        left.host_file
            .cmp(&right.host_file)
            .then_with(|| left.include_start.cmp(&right.include_start))
    });
    let context = RustSelectedContext {
        profile,
        identity,
        target_roots: roots,
        file_root_memberships,
        target_memberships,
        reachable_files,
        dependency_edges: dependency_edges
            .into_iter()
            .collect::<Vec<_>>()
            .into_boxed_slice(),
        module_edges: module_edges.into_boxed_slice(),
        module_activations: module_activations.into_boxed_slice(),
        root_routes: root_routes.into_boxed_slice(),
        root_bridges: Box::new([]),
        macro_visibility: macro_visibility.into_boxed_slice(),
        include_splices: include_splices.into_boxed_slice(),
        gaps,
    };
    Ok(RustSelectedBuildOutcome::Ready(context))
}

/// Build every selected Rust topology fact that does not depend on common
/// root-path rows.
///
/// A selected operation compiles `root_bridges` afterward from its exact
/// mounted import/export path halves. Keeping that authority out of this input
/// prevents operation-time reconstruction of `FileResolutionFacts`.
pub fn build_rust_selected_topology_context(
    source_mounts: impl IntoIterator<Item = RustSelectedTopologySourceMount>,
    manifest_mounts: impl IntoIterator<Item = RustSelectedManifestMount>,
    profile: RustCallerTargetProfile,
) -> Result<RustSelectedContext, String> {
    let RustSelectedBuildOutcome::Ready(context) =
        build_rust_selected_topology_context_with_progress(
            source_mounts,
            manifest_mounts,
            profile,
            &mut |_| true,
        )?
    else {
        unreachable!("an always-live selected Rust topology build cannot stop")
    };
    Ok(context)
}

pub fn build_rust_selected_topology_context_with_progress(
    source_mounts: impl IntoIterator<Item = RustSelectedTopologySourceMount>,
    manifest_mounts: impl IntoIterator<Item = RustSelectedManifestMount>,
    profile: RustCallerTargetProfile,
    progress: &mut impl FnMut(RustSelectedContextWork) -> bool,
) -> Result<RustSelectedBuildOutcome<RustSelectedContext>, String> {
    let RustSelectedBuildOutcome::Ready(input) =
        prepare_rust_selected_topology_input_with_progress(
            source_mounts,
            manifest_mounts,
            progress,
        )?
    else {
        return Ok(RustSelectedBuildOutcome::Stopped);
    };
    build_rust_selected_topology_context_from_prepared_with_progress(&input, profile, progress)
}

pub fn build_rust_selected_topology_context_from_prepared(
    input: &RustSelectedTopologyInput,
    profile: RustCallerTargetProfile,
) -> Result<RustSelectedContext, String> {
    let RustSelectedBuildOutcome::Ready(context) =
        build_rust_selected_topology_context_from_prepared_with_progress(
            input,
            profile,
            &mut |_| true,
        )?
    else {
        unreachable!("an always-live selected Rust topology build cannot stop")
    };
    Ok(context)
}

pub fn build_rust_selected_topology_context_from_prepared_with_progress(
    input: &RustSelectedTopologyInput,
    profile: RustCallerTargetProfile,
    progress: &mut impl FnMut(RustSelectedContextWork) -> bool,
) -> Result<RustSelectedBuildOutcome<RustSelectedContext>, String> {
    let outcome = build_rust_selected_context_from_maps_with_progress(
        &input.sources,
        &input.manifests,
        &input.manifests_by_directory,
        profile,
        progress,
        &input.source_topologies,
        &input.content_identity,
    )?;
    let RustSelectedBuildOutcome::Ready(context) = outcome else {
        return Ok(RustSelectedBuildOutcome::Stopped);
    };
    assert!(
        context.root_bridges.is_empty(),
        "topology-only Rust inputs cannot synthesize common root bridges"
    );
    Ok(RustSelectedBuildOutcome::Ready(context))
}

/// Resolve exact selected named-import authorities through the immutable Cargo
/// and module topology. The caller derives both authority sets from mounted
/// common paths, so this function never reconstructs their local coordinates.
pub fn compile_rust_selected_root_bridge_topology(
    context: &RustSelectedContext,
    imports: impl IntoIterator<Item = RustSelectedRootImportAuthority>,
    exports: impl IntoIterator<Item = RustSelectedRootExportAuthority>,
) -> Box<[RustSelectedRootBridgeTopology]> {
    let RustSelectedBuildOutcome::Ready(bridges) =
        compile_rust_selected_root_bridge_topology_with_progress(
            context,
            imports,
            exports,
            &mut |_| true,
        )
    else {
        unreachable!("an always-live selected Rust bridge build cannot stop")
    };
    bridges
}

pub fn compile_rust_selected_root_bridge_topology_with_progress(
    context: &RustSelectedContext,
    imports: impl IntoIterator<Item = RustSelectedRootImportAuthority>,
    exports: impl IntoIterator<Item = RustSelectedRootExportAuthority>,
    progress: &mut impl FnMut(RustSelectedContextWork) -> bool,
) -> RustSelectedBuildOutcome<Box<[RustSelectedRootBridgeTopology]>> {
    let mut selected_imports = BTreeSet::new();
    for import in imports {
        if !progress(RustSelectedContextWork::ScopeNode) {
            return RustSelectedBuildOutcome::Stopped;
        }
        selected_imports.insert(import);
    }
    let mut selected_exports = BTreeSet::new();
    for export in exports {
        if !progress(RustSelectedContextWork::ScopeNode) {
            return RustSelectedBuildOutcome::Stopped;
        }
        selected_exports.insert(export);
    }
    let mut bridges = BTreeSet::new();
    let topology = RustSelectedTopologyAuthority {
        context,
        imports: &selected_imports,
        exports: &selected_exports,
    };
    for import in &selected_imports {
        if !progress(RustSelectedContextWork::ScopeNode) {
            return RustSelectedBuildOutcome::Stopped;
        }
        for membership in &context.target_memberships {
            if !progress(RustSelectedContextWork::ScopeNode) {
                return RustSelectedBuildOutcome::Stopped;
            }
            if membership.file != import.source_file
                || membership.module_segments != import.source_module_segments
            {
                continue;
            }
            let mut route = Vec::new();
            for segment in &import.route {
                if !progress(RustSelectedContextWork::ScopeNode) {
                    return RustSelectedBuildOutcome::Stopped;
                }
                route.push(segment.as_str());
            }
            let RustSelectedBuildOutcome::Ready(import_targets) = selected_topology_import_targets(
                topology.context,
                membership,
                topology.imports,
                topology.exports,
                &route,
                import.anchor,
                progress,
            ) else {
                return RustSelectedBuildOutcome::Stopped;
            };
            for target in import_targets {
                if !progress(RustSelectedContextWork::ScopeNode) {
                    return RustSelectedBuildOutcome::Stopped;
                }
                let RustSelectedBuildOutcome::Ready(targets) = selected_topology_export_targets(
                    topology,
                    membership,
                    std::slice::from_ref(&target),
                    &import.target_name,
                    import.namespace,
                    progress,
                ) else {
                    return RustSelectedBuildOutcome::Stopped;
                };
                for target in targets {
                    if !progress(RustSelectedContextWork::ScopeNode) {
                        return RustSelectedBuildOutcome::Stopped;
                    }
                    bridges.insert(RustSelectedRootBridgeTopology {
                        source_file: import.source_file.clone(),
                        source_root_scope: import.source_root_scope,
                        target_file: target.target_file,
                        target_root_scope: target.target_root_scope,
                        route: import.route.clone(),
                        source_import_ordinal: import.source_import_ordinal,
                        anchor: import.anchor,
                        source_name: import.source_name.clone(),
                        target_name: target.name,
                        namespace: import.namespace,
                        declaration_authority: target.declaration_authority.clone(),
                    });
                }
            }
        }
    }
    RustSelectedBuildOutcome::Ready(bridges.into_iter().collect::<Vec<_>>().into_boxed_slice())
}

/// Compile selected root bridges from an indexed topology. Workspace and
/// bounded caller operations share this implementation: progress charges the
/// actual indexed traversal rather than repeated full relation scans. The
/// legacy compiler remains a differential oracle for canonical bridge output.
/// The canonical macro-export route proves public exposure at the crate root;
/// the declaration and physical target file retain their original identity.
fn macro_crate_root_exposure(
    export: &RustSelectedRootExportAuthority,
) -> RustSelectedRootExportAuthority {
    assert_eq!(export.namespace, ResolutionNamespace::Macro);
    let mut exposed = export.clone();
    exposed.target_module_segments = Box::new([]);
    let authority = exposed
        .declaration_authority
        .as_mut()
        .expect("macro export exposure has canonical declaration authority");
    authority.declaring_module_segments = Box::new([]);
    authority.visibility = RustVisibility::Public;
    exposed
}

#[derive(Clone, Copy)]
struct RustSelectedTopologyAuthority<'a> {
    context: &'a RustSelectedContext,
    imports: &'a BTreeSet<RustSelectedRootImportAuthority>,
    exports: &'a BTreeSet<RustSelectedRootExportAuthority>,
}

fn selected_topology_export_targets(
    topology: RustSelectedTopologyAuthority<'_>,
    requester: &RustSelectedTargetMembership,
    initial_targets: &[RustSelectedImportTarget],
    target_name: &str,
    namespace: ResolutionNamespace,
    progress: &mut impl FnMut(RustSelectedContextWork) -> bool,
) -> RustSelectedBuildOutcome<BTreeSet<RustSelectedRootExportAuthority>> {
    let mut selected = BTreeSet::new();
    let mut pending = VecDeque::new();
    for target in initial_targets {
        if !progress(RustSelectedContextWork::ScopeNode) {
            return RustSelectedBuildOutcome::Stopped;
        }
        let RustSelectedBuildOutcome::Ready(visible) =
            selected_module_route_is_visible_with_progress(
                &topology.context.module_edges,
                &target.crate_root,
                &requester.crate_root,
                &requester.module_segments,
                &target.module_segments,
                progress,
            )
        else {
            return RustSelectedBuildOutcome::Stopped;
        };
        if visible {
            pending.push_back((requester.clone(), target.clone(), target_name.to_string()));
        }
    }
    let mut visited = BTreeSet::new();
    while let Some((requester, target, requested_name)) = pending.pop_front() {
        if !progress(RustSelectedContextWork::ScopeNode) {
            return RustSelectedBuildOutcome::Stopped;
        }
        if namespace == ResolutionNamespace::Macro && target.module_segments.is_empty() {
            for export in topology.exports {
                if !progress(RustSelectedContextWork::ScopeNode) {
                    return RustSelectedBuildOutcome::Stopped;
                }
                if export.namespace != namespace || export.name != requested_name {
                    continue;
                }
                let Some(authority) = &export.declaration_authority else {
                    continue;
                };
                if authority.crate_root != target.crate_root {
                    continue;
                }
                for route in &topology.context.root_routes {
                    if !progress(RustSelectedContextWork::ScopeNode) {
                        return RustSelectedBuildOutcome::Stopped;
                    }
                    if route.kind == RustSelectedRootRouteKind::ExportedMacro
                        && route.file == export.target_file
                        && route.declaration == Some(authority.declaration)
                    {
                        selected.insert(macro_crate_root_exposure(export));
                    }
                }
            }
        }
        for target_membership in &topology.context.target_memberships {
            if !progress(RustSelectedContextWork::ScopeNode) {
                return RustSelectedBuildOutcome::Stopped;
            }
            if target_membership.crate_root != target.crate_root
                || target_membership.module_segments != target.module_segments
            {
                continue;
            }
            if !visited.insert((
                requester.crate_root.clone(),
                requester.module_segments.clone(),
                target_membership.crate_root.clone(),
                target_membership.module_segments.clone(),
                target_membership.file.clone(),
                requested_name.clone(),
                namespace,
            )) {
                continue;
            }
            for direct in topology.exports.iter().filter(|export| {
                export.target_file == target_membership.file
                    && export.target_module_segments == target_membership.module_segments
                    && export.name == requested_name
                    && export.namespace == namespace
                    && export
                        .declaration_authority
                        .as_ref()
                        .is_some_and(|authority| {
                            authority.reaches(&requester.crate_root, &requester.module_segments)
                        })
            }) {
                selected.insert(direct.clone());
            }
            for route in &topology.context.root_routes {
                if !progress(RustSelectedContextWork::ScopeNode) {
                    return RustSelectedBuildOutcome::Stopped;
                }
                if route.file != target_membership.file
                    || route.owner_module_segments != target_membership.module_segments
                    || !rust_module_visibility_reaches(
                        &route.visibility,
                        requester.crate_root == target_membership.crate_root,
                        &requester.module_segments,
                        &target_membership.module_segments,
                    )
                {
                    continue;
                }
                let forwarded_name = match route.kind {
                    RustSelectedRootRouteKind::NamedReexport
                        if route.local_name.as_deref() == Some(requested_name.as_str()) =>
                    {
                        route.target_name.as_deref()
                    }
                    RustSelectedRootRouteKind::GlobReexport => Some(requested_name.as_str()),
                    _ => None,
                };
                let (Some(route_segments), Some(forwarded_name)) =
                    (route.route_segments.as_deref(), forwarded_name)
                else {
                    continue;
                };
                let mut route_names = Vec::new();
                for segment in route_segments {
                    if !progress(RustSelectedContextWork::ScopeNode) {
                        return RustSelectedBuildOutcome::Stopped;
                    }
                    route_names.push(segment.as_str());
                }
                let RustSelectedBuildOutcome::Ready(forwarded_targets) =
                    selected_topology_import_targets(
                        topology.context,
                        target_membership,
                        topology.imports,
                        topology.exports,
                        &route_names,
                        route.anchor,
                        progress,
                    )
                else {
                    return RustSelectedBuildOutcome::Stopped;
                };
                for forwarded_target in forwarded_targets {
                    if !progress(RustSelectedContextWork::ScopeNode) {
                        return RustSelectedBuildOutcome::Stopped;
                    }
                    let RustSelectedBuildOutcome::Ready(visible) =
                        selected_module_route_is_visible_with_progress(
                            &topology.context.module_edges,
                            &forwarded_target.crate_root,
                            &target_membership.crate_root,
                            &target_membership.module_segments,
                            &forwarded_target.module_segments,
                            progress,
                        )
                    else {
                        return RustSelectedBuildOutcome::Stopped;
                    };
                    if visible {
                        pending.push_back((
                            target_membership.clone(),
                            forwarded_target,
                            forwarded_name.to_string(),
                        ));
                    }
                }
            }
        }
    }
    RustSelectedBuildOutcome::Ready(selected)
}

/// Compile the continuation of a bare Rust Type-prefix after the native
/// resolver has selected its exact source declaration.
///
/// The first module edge is joined by `(declaring_file, declaration)`, never
/// by its displayed module name.  Only after that identity join does the
/// ordinary selected topology resolver interpret `route` relative to the
/// selected module.  A type declaration with no matching module edge therefore
/// produces no module continuation, allowing the caller to preserve its
/// separate type/member path rather than silently selecting a same-named
/// module.
#[allow(clippy::too_many_arguments)]
pub fn compile_rust_selected_module_prefix_continuation_with_progress(
    context: &RustSelectedContext,
    requester: &RustSelectedTargetMembership,
    imports: &BTreeSet<RustSelectedRootImportAuthority>,
    exports: &BTreeSet<RustSelectedRootExportAuthority>,
    declaring_file: &Path,
    declaration: SourceDeclarationId,
    route: &[String],
    anchor: ResolutionRootImportAnchor,
    target_name: &str,
    namespace: ResolutionNamespace,
    progress: &mut impl FnMut(RustSelectedContextWork) -> bool,
) -> RustSelectedBuildOutcome<BTreeSet<RustSelectedRootExportAuthority>> {
    let mut exact_module_targets = BTreeSet::new();
    for edge in &context.module_edges {
        if !progress(RustSelectedContextWork::ScopeNode) {
            return RustSelectedBuildOutcome::Stopped;
        }
        if edge.declaring_file != declaring_file || edge.declaration != Some(declaration) {
            continue;
        }
        if !rust_module_visibility_reaches(
            &edge.visibility,
            edge.crate_root == requester.crate_root,
            &requester.module_segments,
            &edge.declaring_module_segments,
        ) {
            continue;
        }
        let Some(target_membership) = context.target_memberships.iter().find(|membership| {
            membership.crate_root == edge.crate_root
                && membership.file == edge.target_file
                && membership.module_segments == edge.module_segments
        }) else {
            continue;
        };
        exact_module_targets.insert(RustSelectedImportTarget {
            crate_root: target_membership.crate_root.clone(),
            module_segments: target_membership.module_segments.clone(),
        });
    }
    if exact_module_targets.is_empty() {
        return RustSelectedBuildOutcome::Ready(BTreeSet::new());
    }

    let route_names = route.iter().map(String::as_str).collect::<Vec<_>>();
    let mut continuation_targets = Vec::new();
    for target in exact_module_targets {
        if !progress(RustSelectedContextWork::ScopeNode) {
            return RustSelectedBuildOutcome::Stopped;
        }
        let Some(target_membership) = context.target_memberships.iter().find(|membership| {
            membership.crate_root == target.crate_root
                && membership.module_segments == target.module_segments
        }) else {
            continue;
        };
        if route_names.is_empty() {
            continuation_targets.push(target);
            continue;
        }
        let RustSelectedBuildOutcome::Ready(targets) = selected_topology_import_targets(
            context,
            target_membership,
            imports,
            exports,
            &route_names,
            anchor,
            progress,
        ) else {
            return RustSelectedBuildOutcome::Stopped;
        };
        continuation_targets.extend(targets);
    }
    selected_topology_export_targets(
        RustSelectedTopologyAuthority {
            context,
            imports,
            exports,
        },
        requester,
        &continuation_targets,
        target_name,
        namespace,
        progress,
    )
}

fn selected_topology_import_targets(
    context: &RustSelectedContext,
    source: &RustSelectedTargetMembership,
    imports: &BTreeSet<RustSelectedRootImportAuthority>,
    exports: &BTreeSet<RustSelectedRootExportAuthority>,
    route: &[&str],
    anchor: ResolutionRootImportAnchor,
    progress: &mut impl FnMut(RustSelectedContextWork) -> bool,
) -> RustSelectedBuildOutcome<Vec<RustSelectedImportTarget>> {
    if !progress(RustSelectedContextWork::ScopeNode) {
        return RustSelectedBuildOutcome::Stopped;
    }
    if anchor == ResolutionRootImportAnchor::Absolute {
        for _ in route {
            if !progress(RustSelectedContextWork::ScopeNode) {
                return RustSelectedBuildOutcome::Stopped;
            }
        }
        if !source.edition.uses_uniform_paths() {
            let module_segments = route
                .iter()
                .map(|segment| (*segment).to_string())
                .collect::<Vec<_>>()
                .into_boxed_slice();
            return RustSelectedBuildOutcome::Ready(vec![RustSelectedImportTarget {
                crate_root: source.crate_root.clone(),
                module_segments,
            }]);
        }
    }
    let Some(first) = route.first().copied() else {
        return RustSelectedBuildOutcome::Ready(Vec::new());
    };
    if matches!(first, "crate" | "self" | "super") {
        for _ in route {
            if !progress(RustSelectedContextWork::ScopeNode) {
                return RustSelectedBuildOutcome::Stopped;
            }
        }
        return RustSelectedBuildOutcome::Ready(
            resolve_same_crate_module(&source.module_segments, route)
                .map(|module_segments| {
                    vec![RustSelectedImportTarget {
                        crate_root: source.crate_root.clone(),
                        module_segments,
                    }]
                })
                .unwrap_or_default(),
        );
    }
    let mut extern_crate_names = BTreeSet::new();
    for root_route in &context.root_routes {
        if !progress(RustSelectedContextWork::ScopeNode) {
            return RustSelectedBuildOutcome::Stopped;
        }
        if root_route.file == source.file
            && root_route.owner_module_segments == source.module_segments
            && root_route.kind == RustSelectedRootRouteKind::ExternCrate
            && root_route.local_name.as_deref() == Some(first)
            && let Some(target_name) = root_route.target_name.as_deref()
        {
            extern_crate_names.insert(target_name);
        }
    }
    let dependency_name = if extern_crate_names.len() == 1 {
        extern_crate_names.first().copied()
    } else if extern_crate_names.is_empty() && source.edition.uses_uniform_paths() {
        Some(first)
    } else {
        None
    };
    let mut dependencies = Vec::new();
    if let Some(dependency_name) = dependency_name {
        for dependency in &context.dependency_edges {
            if !progress(RustSelectedContextWork::ScopeNode) {
                return RustSelectedBuildOutcome::Stopped;
            }
            if dependency.source_crate_root == source.crate_root
                && dependency.exposed_name == dependency_name
            {
                let mut module_segments = Vec::new();
                for segment in &route[1..] {
                    if !progress(RustSelectedContextWork::ScopeNode) {
                        return RustSelectedBuildOutcome::Stopped;
                    }
                    module_segments.push((*segment).to_string());
                }
                dependencies.push(RustSelectedImportTarget {
                    crate_root: dependency.target_crate_root.clone(),
                    module_segments: module_segments.into_boxed_slice(),
                });
            }
        }
    }
    let binding_file = if source.edition.uses_uniform_paths() {
        &source.file
    } else {
        let mut root_file = None;
        for membership in &context.target_memberships {
            if !progress(RustSelectedContextWork::ScopeNode) {
                return RustSelectedBuildOutcome::Stopped;
            }
            if membership.crate_root == source.crate_root && membership.module_segments.is_empty() {
                root_file = Some(&membership.file);
                break;
            }
        }
        let Some(root_file) = root_file else {
            return RustSelectedBuildOutcome::Ready(Vec::new());
        };
        root_file
    };
    let binding_module_segments = if source.edition.uses_uniform_paths() {
        source.module_segments.as_ref()
    } else {
        &[]
    };
    let local_type_binding = exports.iter().any(|export| {
        export.target_file == *binding_file
            && export.target_module_segments.as_ref() == binding_module_segments
            && export.name == first
            && export.namespace == ResolutionNamespace::Type
    }) || {
        let mut found = false;
        for import in imports {
            if !progress(RustSelectedContextWork::ScopeNode) {
                return RustSelectedBuildOutcome::Stopped;
            }
            if import.source_file == *binding_file
                && import.source_module_segments.as_ref() == binding_module_segments
                && import.source_name == first
                && import.namespace == ResolutionNamespace::Type
            {
                found = true;
                break;
            }
        }
        found
    } || context.root_routes.iter().any(|route| {
        route.file == *binding_file
            && route.owner_module_segments.as_ref() == binding_module_segments
            && route.kind == RustSelectedRootRouteKind::Module
            && route.local_name.as_deref() == Some(first)
    });
    let mut module_segments = if source.edition.uses_uniform_paths() {
        source.module_segments.to_vec()
    } else {
        Vec::new()
    };
    for segment in route {
        if !progress(RustSelectedContextWork::ScopeNode) {
            return RustSelectedBuildOutcome::Stopped;
        }
        module_segments.push((*segment).to_string());
    }
    if local_type_binding && anchor != ResolutionRootImportAnchor::Absolute {
        let mut selected = false;
        for membership in &context.target_memberships {
            if !progress(RustSelectedContextWork::ScopeNode) {
                return RustSelectedBuildOutcome::Stopped;
            }
            if membership.crate_root == source.crate_root
                && membership.module_segments.as_ref() == module_segments
            {
                selected = true;
                break;
            }
        }
        if selected {
            return RustSelectedBuildOutcome::Ready(vec![RustSelectedImportTarget {
                crate_root: source.crate_root.clone(),
                module_segments: module_segments.into_boxed_slice(),
            }]);
        }
        return RustSelectedBuildOutcome::Ready(Vec::new());
    }
    if anchor == ResolutionRootImportAnchor::Absolute {
        assert!(
            source.edition.uses_uniform_paths(),
            "Rust 2015 leading-absolute routes return at the crate root"
        );
        RustSelectedBuildOutcome::Ready(dependencies)
    } else if source.edition.uses_uniform_paths() || !dependencies.is_empty() {
        RustSelectedBuildOutcome::Ready(dependencies)
    } else {
        RustSelectedBuildOutcome::Ready(Vec::new())
    }
}

/// The edition a detached Rust file is read under.
///
/// A detached file belongs to no Cargo target, so no package edition applies to
/// it directly. The nearest enclosing manifest still states the edition the
/// surrounding sources are written in, so use that when the manifest declares a
/// package edition or a workspace package edition. With no enclosing manifest,
/// use the current default edition, which is what rust-analyzer reads a
/// detached file under.
fn detached_caller_edition(
    manifest_path: &Path,
    manifests: &BTreeMap<PathBuf, RustSelectedManifestMount>,
    progress: &mut impl FnMut(RustSelectedContextWork) -> bool,
) -> Result<RustSelectedBuildOutcome<RustCargoEdition>, String> {
    let Some(manifest) = manifests.get(manifest_path) else {
        return Ok(RustSelectedBuildOutcome::Ready(DETACHED_DEFAULT_EDITION));
    };
    if manifest.facts.package.is_some() {
        return effective_cargo_edition(manifest_path, manifests, progress);
    }
    Ok(RustSelectedBuildOutcome::Ready(
        manifest
            .facts
            .workspace_package_edition
            .unwrap_or(DETACHED_DEFAULT_EDITION),
    ))
}

/// The edition a detached Rust file is read under when no manifest encloses it.
const DETACHED_DEFAULT_EDITION: RustCargoEdition = RustCargoEdition::Rust2024;

fn effective_cargo_edition(
    manifest_path: &Path,
    manifests: &BTreeMap<PathBuf, RustSelectedManifestMount>,
    progress: &mut impl FnMut(RustSelectedContextWork) -> bool,
) -> Result<RustSelectedBuildOutcome<RustCargoEdition>, String> {
    if !progress(RustSelectedContextWork::ScopeNode) {
        return Ok(RustSelectedBuildOutcome::Stopped);
    }
    let manifest = &manifests[manifest_path];
    let package = manifest
        .facts
        .package
        .as_ref()
        .ok_or_else(|| format!("selected target manifest has no package: {manifest_path:?}"))?;
    match package.edition {
        RustCargoPackageEdition::Explicit(edition) => {
            return Ok(RustSelectedBuildOutcome::Ready(edition));
        }
        RustCargoPackageEdition::Workspace => {}
    }
    let package_directory = manifest_path.parent().unwrap_or(Path::new(""));
    let workspace = if let Some(workspace_path) = package.workspace_path.as_deref() {
        let directory = normalize_selected_path(package_directory, workspace_path)
            .ok_or_else(|| "Cargo package workspace path escapes selected inventory".to_string())?;
        let path = directory.join("Cargo.toml");
        manifests.get(&path)
    } else {
        let mut selected = None;
        for (path, candidate) in manifests {
            if !progress(RustSelectedContextWork::ScopeNode) {
                return Ok(RustSelectedBuildOutcome::Stopped);
            }
            let workspace_directory = path.parent().unwrap_or(Path::new(""));
            let contains_package = candidate.facts.is_workspace
                && cargo_workspace_claims_package(
                    workspace_directory,
                    &candidate.facts,
                    package_directory,
                );
            if contains_package {
                let depth = path.components().count();
                if selected.is_none_or(|(selected_depth, _)| depth > selected_depth) {
                    selected = Some((depth, candidate));
                }
            }
        }
        selected.map(|(_, manifest)| manifest)
    }
    .ok_or_else(|| {
        format!("workspace-inherited Cargo edition has no selected workspace: {manifest_path:?}")
    })?;
    workspace
        .facts
        .workspace_package_edition
        .ok_or_else(|| format!("workspace-inherited Cargo edition is absent: {manifest_path:?}"))
        .map(RustSelectedBuildOutcome::Ready)
}

/// Whether one `[workspace]` manifest claims the package in `package_directory`.
///
/// A workspace claims every package under its directory except the ones its
/// `exclude` patterns name. Cargo treats an excluded directory as outside the
/// workspace entirely, so it inherits nothing from `[workspace.package]` and
/// is not a member. Bifrost's own root manifest excludes `.claude/worktrees/*`
/// precisely because those checkouts hold whole copies of the repository whose
/// manifests must not be claimed by the surrounding workspace.
fn cargo_workspace_claims_package(
    workspace_directory: &Path,
    facts: &RustCargoManifestFacts,
    package_directory: &Path,
) -> bool {
    if !package_directory.starts_with(workspace_directory) {
        return false;
    }
    let Ok(relative) = package_directory.strip_prefix(workspace_directory) else {
        return false;
    };
    !facts
        .workspace_excludes
        .iter()
        .any(|pattern| cargo_path_pattern_covers(pattern, relative))
}

/// Whether one Cargo path pattern names `path` or one of its ancestors.
///
/// Cargo matches these entries as globs against workspace-relative directory
/// paths. Matching walks `Path` components so the same pattern behaves the
/// same on Windows and Unix, and an excluded directory also excludes every
/// package nested inside it.
fn cargo_path_pattern_covers(pattern: &Path, path: &Path) -> bool {
    let mut pattern_components = pattern.components();
    let mut path_components = path.components();
    loop {
        let Some(expected) = pattern_components.next() else {
            // The pattern named an ancestor directory of this path.
            return true;
        };
        let Some(actual) = path_components.next() else {
            return false;
        };
        let (Component::Normal(expected), Component::Normal(actual)) = (expected, actual) else {
            if expected != actual {
                return false;
            }
            continue;
        };
        let (Some(expected), Some(actual)) = (expected.to_str(), actual.to_str()) else {
            return false;
        };
        if !cargo_name_pattern_matches(expected, actual) {
            return false;
        }
    }
}

/// Whether one Cargo glob component matches one path component.
///
/// `*` stands for any run of characters inside a single component and `?` for
/// exactly one. The walk is iterative with one backtrack point, so a pattern
/// cannot recurse on deeply repeated wildcards.
fn cargo_name_pattern_matches(pattern: &str, name: &str) -> bool {
    let pattern = pattern.as_bytes();
    let name = name.as_bytes();
    let mut pattern_index = 0_usize;
    let mut name_index = 0_usize;
    let mut star: Option<(usize, usize)> = None;
    while name_index < name.len() {
        match pattern.get(pattern_index) {
            Some(b'*') => {
                star = Some((pattern_index, name_index));
                pattern_index += 1;
            }
            Some(b'?') => {
                pattern_index += 1;
                name_index += 1;
            }
            Some(&expected) if expected == name[name_index] => {
                pattern_index += 1;
                name_index += 1;
            }
            _ => match star {
                Some((star_pattern, star_name)) => {
                    pattern_index = star_pattern + 1;
                    name_index = star_name + 1;
                    star = Some((star_pattern, name_index));
                }
                None => return false,
            },
        }
    }
    pattern[pattern_index..].iter().all(|byte| *byte == b'*')
}

fn selected_root_bridges(
    sources: &BTreeMap<PathBuf, RustSelectedSourceMount>,
    file_root_memberships: &BTreeSet<RustSelectedTargetMembership>,
    memberships: &BTreeSet<RustSelectedTargetMembership>,
    dependency_edges: &BTreeSet<RustSelectedDependencyEdge>,
    module_edges: &[RustSelectedModuleEdge],
    root_routes: &[RustSelectedRootRoute],
) -> Box<[RustSelectedRootBridge]> {
    let mut bridges = BTreeSet::new();
    let resolver = RustSelectedRouteResolver {
        sources,
        file_root_memberships,
        memberships,
        dependency_edges,
        module_edges,
        root_routes,
    };
    for route in root_routes.iter().filter(|route| {
        matches!(
            route.kind,
            RustSelectedRootRouteKind::NamedUse
                | RustSelectedRootRouteKind::GlobUse
                | RustSelectedRootRouteKind::LocalNamedUse
                | RustSelectedRootRouteKind::LocalGlobUse
        )
    }) {
        let Some(source) = sources.get(&route.file) else {
            continue;
        };
        for (import_site, route_names) in selected_structured_imports(source, route) {
            for membership in memberships.iter().filter(|membership| {
                membership.file == route.file
                    && membership.module_segments == route.owner_module_segments
            }) {
                let route_name_refs = route_names.iter().map(String::as_str).collect::<Vec<_>>();
                let targets = selected_import_targets(
                    source,
                    membership,
                    sources,
                    memberships,
                    dependency_edges,
                    root_routes,
                    &route_name_refs,
                );
                for demand in source
                    .resolution_facts
                    .root_import_demands
                    .iter()
                    .filter(|demand| demand.import_site == import_site)
                {
                    let demand_name = resolution_name(&source.resolution_facts, demand.name);
                    let (source_name, target_name) = match route.kind {
                        RustSelectedRootRouteKind::NamedUse
                        | RustSelectedRootRouteKind::LocalNamedUse
                            if route.local_name.as_deref() == Some(demand_name) =>
                        {
                            let Some(target_name) = route.target_name.as_deref() else {
                                continue;
                            };
                            (demand_name, target_name)
                        }
                        RustSelectedRootRouteKind::GlobUse
                        | RustSelectedRootRouteKind::LocalGlobUse => (demand_name, demand_name),
                        _ => continue,
                    };
                    let exports = resolver.export_targets(
                        membership,
                        &targets,
                        target_name,
                        demand.namespace,
                    );
                    for export in exports {
                        bridges.insert(RustSelectedRootBridge {
                            source_file: route.file.clone(),
                            source_import_site: import_site,
                            source_import_ordinal: route
                                .source_import_ordinal
                                .expect("a selected import bridge has an import declaration"),
                            source_root_scope: route
                                .owner_resolution_scope
                                .expect("a structured import has a source scope"),
                            anchor: route.anchor,
                            target_file: export.file,
                            target_root_scope: export.root_scope,
                            route: route_names.clone(),
                            source_name: source_name.to_string(),
                            target_name: export.name,
                            namespace: demand.namespace,
                            declaration_authority: None,
                        });
                    }
                }
            }
        }
    }
    bridges.into_iter().collect::<Vec<_>>().into_boxed_slice()
}

fn selected_import_route_segments_with_progress(
    target: &RustImportTargetFact,
    progress: &mut impl FnMut(RustSelectedContextWork) -> bool,
) -> RustSelectedBuildOutcome<(Box<[String]>, ResolutionRootImportAnchor)> {
    if !progress(RustSelectedContextWork::ScopeNode) {
        return RustSelectedBuildOutcome::Stopped;
    }
    let mut route = Vec::with_capacity(target.module_path.len());
    for segment in &target.module_path {
        if !progress(RustSelectedContextWork::ScopeNode) {
            return RustSelectedBuildOutcome::Stopped;
        }
        route.push(strip_raw_identifier_prefix(segment).to_string());
    }
    let anchor = if target.leading_absolute {
        ResolutionRootImportAnchor::Absolute
    } else {
        ResolutionRootImportAnchor::Lexical
    };
    RustSelectedBuildOutcome::Ready((route.into_boxed_slice(), anchor))
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct RustSelectedImportTarget {
    crate_root: PathBuf,
    module_segments: Box<[String]>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct RustSelectedExportTarget {
    file: PathBuf,
    root_scope: ResolutionScopeId,
    name: String,
}

struct RustSelectedRouteResolver<'a> {
    sources: &'a BTreeMap<PathBuf, RustSelectedSourceMount>,
    file_root_memberships: &'a BTreeSet<RustSelectedTargetMembership>,
    memberships: &'a BTreeSet<RustSelectedTargetMembership>,
    dependency_edges: &'a BTreeSet<RustSelectedDependencyEdge>,
    module_edges: &'a [RustSelectedModuleEdge],
    root_routes: &'a [RustSelectedRootRoute],
}

fn selected_structured_imports(
    source: &RustSelectedSourceMount,
    route: &RustSelectedRootRoute,
) -> Vec<(ResolutionSiteId, Box<[String]>)> {
    source
        .resolution_facts
        .root_imports
        .iter()
        .filter_map(|import| {
            if Some(import.root_scope) != route.owner_resolution_scope {
                return None;
            }
            let mut segments = source
                .resolution_facts
                .root_import_segments
                .iter()
                .filter(|segment| segment.import_site == import.site)
                .collect::<Vec<_>>();
            segments.sort_unstable_by_key(|segment| segment.position);
            if segments.is_empty() {
                return None;
            }
            let route_names = segments
                .iter()
                .map(|segment| resolution_name(&source.resolution_facts, segment.name).to_string())
                .collect::<Vec<_>>();
            (route_names.join("::") == route.route)
                .then(|| (import.site, route_names.into_boxed_slice()))
        })
        .collect()
}

impl RustSelectedRouteResolver<'_> {
    fn export_targets(
        &self,
        requester: &RustSelectedTargetMembership,
        initial_targets: &[RustSelectedImportTarget],
        target_name: &str,
        namespace: ResolutionNamespace,
    ) -> BTreeSet<RustSelectedExportTarget> {
        let mut exports = BTreeSet::new();
        let mut pending = VecDeque::new();
        for target in initial_targets {
            if selected_module_route_is_visible(
                self.module_edges,
                &target.crate_root,
                &requester.crate_root,
                &requester.module_segments,
                &target.module_segments,
            ) {
                pending.push_back((requester.clone(), target.clone(), target_name.to_string()));
            }
        }

        let mut visited = BTreeSet::new();
        while let Some((requester, target, requested_name)) = pending.pop_front() {
            for target_membership in self.memberships.iter().filter(|membership| {
                membership.crate_root == target.crate_root
                    && membership.module_segments == target.module_segments
            }) {
                if !visited.insert((
                    requester.crate_root.clone(),
                    requester.module_segments.clone(),
                    target_membership.crate_root.clone(),
                    target_membership.module_segments.clone(),
                    target_membership.file.clone(),
                    requested_name.clone(),
                    namespace,
                )) {
                    continue;
                }
                let target_source = &self.sources[&target_membership.file];
                for export in target_source
                    .resolution_facts
                    .root_exports
                    .iter()
                    .filter(|export| export.namespace == namespace)
                {
                    let Some(local_module_segments) = selected_resolution_scope_segments(
                        &target_source.facts.module_routes,
                        export.root_scope,
                    ) else {
                        continue;
                    };
                    if !selected_export_attaches_to_membership(
                        self.file_root_memberships,
                        target_membership,
                        &local_module_segments,
                    ) {
                        continue;
                    }
                    let identifier = target_source
                        .resolution_facts
                        .identifiers
                        .iter()
                        .find(|identifier| {
                            identifier.site == export.declaration
                                && identifier.role == ResolutionIdentifierRole::Declaration
                        })
                        .expect("selected Rust root export names one declaration identifier");
                    assert!(
                        identifier.namespace == namespace
                            || target_source
                                .resolution_facts
                                .additional_definition_namespaces
                                .iter()
                                .any(|additional| {
                                    additional.declaration == export.declaration
                                        && additional.namespace == namespace
                                }),
                        "selected Rust root export namespace must be primary or additional: export={export:?}, identifier={identifier:?}"
                    );
                    let exported_name =
                        resolution_name(&target_source.resolution_facts, identifier.name);
                    if exported_name == requested_name {
                        exports.insert(RustSelectedExportTarget {
                            file: target_membership.file.clone(),
                            root_scope: export.root_scope,
                            name: exported_name.to_string(),
                        });
                    }
                }

                for route in self.root_routes.iter().filter(|route| {
                    route.file == target_membership.file
                        && route.owner_module_segments == target_membership.module_segments
                        && route.kind == RustSelectedRootRouteKind::NamedReexport
                        && route.local_name.as_deref() == Some(requested_name.as_str())
                        && rust_module_visibility_reaches(
                            &route.visibility,
                            requester.crate_root == target_membership.crate_root,
                            &requester.module_segments,
                            &target_membership.module_segments,
                        )
                }) {
                    let Some(forwarded_name) = route.target_name.as_deref() else {
                        continue;
                    };
                    for (import_site, route_names) in
                        selected_structured_imports(target_source, route)
                    {
                        if !target_source
                            .resolution_facts
                            .root_import_demands
                            .iter()
                            .any(|demand| {
                                demand.import_site == import_site
                                    && demand.namespace == namespace
                                    && resolution_name(&target_source.resolution_facts, demand.name)
                                        == requested_name
                            })
                        {
                            continue;
                        }
                        let route_name_refs =
                            route_names.iter().map(String::as_str).collect::<Vec<_>>();
                        for forwarded_target in selected_import_targets(
                            target_source,
                            target_membership,
                            self.sources,
                            self.memberships,
                            self.dependency_edges,
                            self.root_routes,
                            &route_name_refs,
                        ) {
                            if selected_module_route_is_visible(
                                self.module_edges,
                                &forwarded_target.crate_root,
                                &target_membership.crate_root,
                                &target_membership.module_segments,
                                &forwarded_target.module_segments,
                            ) {
                                pending.push_back((
                                    target_membership.clone(),
                                    forwarded_target,
                                    forwarded_name.to_string(),
                                ));
                            }
                        }
                    }
                }

                for route in self.root_routes.iter().filter(|route| {
                    route.file == target_membership.file
                        && route.owner_module_segments == target_membership.module_segments
                        && route.kind == RustSelectedRootRouteKind::GlobReexport
                        && rust_module_visibility_reaches(
                            &route.visibility,
                            requester.crate_root == target_membership.crate_root,
                            &requester.module_segments,
                            &target_membership.module_segments,
                        )
                }) {
                    let Some(route_segments) = route.route_segments.as_deref() else {
                        continue;
                    };
                    let route_name_refs = route_segments
                        .iter()
                        .map(String::as_str)
                        .collect::<Vec<_>>();
                    for forwarded_target in selected_import_targets(
                        target_source,
                        target_membership,
                        self.sources,
                        self.memberships,
                        self.dependency_edges,
                        self.root_routes,
                        &route_name_refs,
                    ) {
                        if selected_module_route_is_visible(
                            self.module_edges,
                            &forwarded_target.crate_root,
                            &target_membership.crate_root,
                            &target_membership.module_segments,
                            &forwarded_target.module_segments,
                        ) {
                            pending.push_back((
                                target_membership.clone(),
                                forwarded_target,
                                requested_name.clone(),
                            ));
                        }
                    }
                }
            }
        }
        exports
    }
}

fn selected_import_targets(
    source_mount: &RustSelectedSourceMount,
    source: &RustSelectedTargetMembership,
    sources: &BTreeMap<PathBuf, RustSelectedSourceMount>,
    memberships: &BTreeSet<RustSelectedTargetMembership>,
    dependency_edges: &BTreeSet<RustSelectedDependencyEdge>,
    root_routes: &[RustSelectedRootRoute],
    route: &[&str],
) -> Vec<RustSelectedImportTarget> {
    let Some(first) = route.first().copied() else {
        return Vec::new();
    };
    if matches!(first, "crate" | "self" | "super") {
        return resolve_same_crate_module(&source.module_segments, route)
            .map(|module_segments| {
                vec![RustSelectedImportTarget {
                    crate_root: source.crate_root.clone(),
                    module_segments,
                }]
            })
            .unwrap_or_default();
    }
    let extern_crate_names = root_routes
        .iter()
        .filter(|root_route| {
            root_route.file == source.file
                && root_route.owner_module_segments == source.module_segments
                && root_route.kind == RustSelectedRootRouteKind::ExternCrate
                && root_route.local_name.as_deref() == Some(first)
        })
        .filter_map(|root_route| root_route.target_name.as_deref())
        .collect::<BTreeSet<_>>();
    let dependency_name = if extern_crate_names.len() == 1 {
        extern_crate_names.first().copied()
    } else if extern_crate_names.is_empty() && source.edition.uses_uniform_paths() {
        Some(first)
    } else {
        None
    };
    let dependencies = dependency_name
        .into_iter()
        .flat_map(|dependency_name| {
            dependency_edges.iter().filter(move |dependency| {
                dependency.source_crate_root == source.crate_root
                    && dependency.exposed_name == dependency_name
            })
        })
        .map(|dependency| RustSelectedImportTarget {
            crate_root: dependency.target_crate_root.clone(),
            module_segments: route[1..]
                .iter()
                .map(|segment| (*segment).to_string())
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        })
        .collect::<Vec<_>>();
    let mut module_segments = if source.edition.uses_uniform_paths() {
        source.module_segments.to_vec()
    } else {
        Vec::new()
    };
    module_segments.extend(route.iter().map(|segment| (*segment).to_string()));
    let binding_mount = if source.edition.uses_uniform_paths() {
        source_mount
    } else {
        let Some(root) = memberships.iter().find(|membership| {
            membership.crate_root == source.crate_root && membership.module_segments.is_empty()
        }) else {
            return Vec::new();
        };
        &sources[&root.file]
    };
    if rust_root_has_type_binding(&binding_mount.resolution_facts, first) {
        if memberships.iter().any(|membership| {
            membership.crate_root == source.crate_root
                && membership.module_segments.as_ref() == module_segments
        }) {
            return vec![RustSelectedImportTarget {
                crate_root: source.crate_root.clone(),
                module_segments: module_segments.into_boxed_slice(),
            }];
        }
        return Vec::new();
    }
    if source.edition.uses_uniform_paths() || !dependencies.is_empty() {
        dependencies
    } else {
        Vec::new()
    }
}

fn rust_root_has_type_binding(facts: &FileResolutionFacts, spelling: &str) -> bool {
    facts.identifiers.iter().any(|identifier| {
        identifier.role == ResolutionIdentifierRole::Declaration
            && identifier.namespace == ResolutionNamespace::Type
            && facts.sites[identifier.site.index()].scope == ResolutionScopeId::new(0)
            && resolution_name(facts, identifier.name) == spelling
    }) || facts.root_import_demands.iter().any(|demand| {
        demand.namespace == ResolutionNamespace::Type
            && resolution_name(facts, demand.name) == spelling
    })
}

fn resolve_same_crate_module(source_module: &[String], route: &[&str]) -> Option<Box<[String]>> {
    let mut module_segments = match route.first().copied()? {
        "crate" => Vec::new(),
        "self" | "super" => source_module.to_vec(),
        _ => return None,
    };
    let mut position = 0;
    while route
        .get(position)
        .is_some_and(|segment| matches!(*segment, "self" | "super"))
    {
        if route[position] == "super" {
            module_segments.pop()?;
        }
        position += 1;
    }
    if route[0] == "crate" {
        position = 1;
    }
    module_segments.extend(
        route[position..]
            .iter()
            .map(|segment| (*segment).to_string()),
    );
    Some(module_segments.into_boxed_slice())
}

fn selected_module_route_is_visible(
    module_edges: &[RustSelectedModuleEdge],
    target_crate_root: &Path,
    source_crate_root: &Path,
    source_module: &[String],
    target_module: &[String],
) -> bool {
    (1..=target_module.len()).all(|length| {
        module_edges.iter().any(|edge| {
            edge.crate_root == target_crate_root
                && edge.module_segments.as_ref() == &target_module[..length]
                && rust_module_visibility_reaches(
                    &edge.visibility,
                    target_crate_root == source_crate_root,
                    source_module,
                    &edge.declaring_module_segments,
                )
        })
    })
}

fn selected_module_route_is_visible_with_progress(
    module_edges: &[RustSelectedModuleEdge],
    target_crate_root: &Path,
    source_crate_root: &Path,
    source_module: &[String],
    target_module: &[String],
    progress: &mut impl FnMut(RustSelectedContextWork) -> bool,
) -> RustSelectedBuildOutcome<bool> {
    for length in 1..=target_module.len() {
        let mut visible = false;
        for edge in module_edges {
            if !progress(RustSelectedContextWork::ScopeNode) {
                return RustSelectedBuildOutcome::Stopped;
            }
            if edge.crate_root == target_crate_root
                && edge.module_segments.as_ref() == &target_module[..length]
                && rust_module_visibility_reaches(
                    &edge.visibility,
                    target_crate_root == source_crate_root,
                    source_module,
                    &edge.declaring_module_segments,
                )
            {
                visible = true;
                break;
            }
        }
        if !visible {
            return RustSelectedBuildOutcome::Ready(false);
        }
    }
    RustSelectedBuildOutcome::Ready(true)
}

fn rust_module_visibility_reaches(
    visibility: &RustVisibility,
    same_crate: bool,
    source_module: &[String],
    declaring_module: &[String],
) -> bool {
    if *visibility == RustVisibility::Public {
        return true;
    }
    if !same_crate {
        return false;
    }
    let scope = match visibility {
        RustVisibility::Public | RustVisibility::Crate => return true,
        RustVisibility::Private | RustVisibility::SelfModule => declaring_module,
        RustVisibility::SuperModule => declaring_module
            .split_last()
            .map_or(declaring_module, |(_, parent)| parent),
        RustVisibility::InPath(path) => {
            let Some(scope) = resolve_visibility_scope(declaring_module, path) else {
                return false;
            };
            return source_module.starts_with(&scope);
        }
    };
    source_module.starts_with(scope)
}

/// Apply terminal Rust item visibility after module-route visibility has been
/// checked.  A public module path does not make a private terminal item
/// public, and restricted item visibility never crosses a crate boundary.
pub fn rust_declaration_visibility_reaches(
    visibility: &RustVisibility,
    same_crate: bool,
    requester_module: &[String],
    declaring_module: &[String],
) -> bool {
    if *visibility == RustVisibility::Public {
        return true;
    }
    if !same_crate {
        return false;
    }
    let scope = match visibility {
        RustVisibility::Public | RustVisibility::Crate => return true,
        RustVisibility::Private | RustVisibility::SelfModule => declaring_module,
        RustVisibility::SuperModule => declaring_module
            .split_last()
            .map_or(declaring_module, |(_, parent)| parent),
        RustVisibility::InPath(path) => {
            let Some(scope) = resolve_visibility_scope(declaring_module, path) else {
                return false;
            };
            return requester_module.starts_with(&scope);
        }
    };
    requester_module.starts_with(scope)
}

fn resolve_visibility_scope(declaring_module: &[String], path: &[String]) -> Option<Box<[String]>> {
    let first = path.first()?;
    let mut scope = match first.as_str() {
        "crate" => Vec::new(),
        "self" | "super" => declaring_module.to_vec(),
        _ => return Some(path.to_vec().into_boxed_slice()),
    };
    let mut position = 0;
    while path
        .get(position)
        .is_some_and(|segment| matches!(segment.as_str(), "self" | "super"))
    {
        if path[position] == "super" {
            scope.pop()?;
        }
        position += 1;
    }
    if first == "crate" {
        position = 1;
    }
    scope.extend(path[position..].iter().cloned());
    Some(scope.into_boxed_slice())
}

fn resolution_name(facts: &FileResolutionFacts, name: ResolutionNameId) -> &str {
    facts
        .names
        .get(name.index())
        .filter(|fact| fact.id == name)
        .map(|fact| fact.spelling.as_str())
        .expect("Rust selected root route names an unknown resolution spelling")
}

fn selected_resolution_scope_segments(
    facts: &RustModuleRouteFacts,
    resolution_scope: ResolutionScopeId,
) -> Option<Box<[String]>> {
    facts
        .scopes
        .iter()
        .position(|scope| scope.resolution_scope == Some(resolution_scope))
        .map(|scope| rust_selected_module_scope_segments(facts, scope))
}

fn selected_export_attaches_to_membership(
    file_root_memberships: &BTreeSet<RustSelectedTargetMembership>,
    target: &RustSelectedTargetMembership,
    local_module_segments: &[String],
) -> bool {
    file_root_memberships.iter().any(|root| {
        root.crate_root == target.crate_root
            && root.file == target.file
            && root.edition == target.edition
            && target.module_segments.len()
                == root.module_segments.len() + local_module_segments.len()
            && target.module_segments.starts_with(&root.module_segments)
            && &target.module_segments[root.module_segments.len()..] == local_module_segments
    })
}

fn unique_mounts<T>(
    mounts: impl IntoIterator<Item = T>,
    path_of: impl Fn(&T) -> &PathBuf,
    label: &str,
    progress: &mut impl FnMut(RustSelectedContextWork) -> bool,
) -> Result<RustSelectedBuildOutcome<BTreeMap<PathBuf, T>>, String> {
    let mut by_path = BTreeMap::new();
    for mount in mounts {
        if !progress(RustSelectedContextWork::ScopeNode) {
            return Ok(RustSelectedBuildOutcome::Stopped);
        }
        let path = path_of(&mount).clone();
        if path.is_absolute()
            || normalize_selected_path(Path::new(""), &path).as_ref() != Some(&path)
        {
            return Err(format!("{label} mount path is not normalized: {path:?}"));
        }
        if by_path.insert(path.clone(), mount).is_some() {
            return Err(format!("duplicate selected {label} mount: {path:?}"));
        }
    }
    Ok(RustSelectedBuildOutcome::Ready(by_path))
}

fn same_package_library_root(
    profile: &RustCallerTargetProfile,
    package: &RustCargoPackageFact,
    sources: &BTreeMap<PathBuf, RustSelectedSourceMount>,
) -> Result<Option<PathBuf>, String> {
    if matches!(
        profile.target_kind,
        RustCallerTargetKind::Library
            | RustCallerTargetKind::Build
            | RustCallerTargetKind::Detached
    ) || !cargo_library_target_enabled(package)
    {
        return Ok(None);
    }
    let directory = profile.manifest_path.parent().unwrap_or(Path::new(""));
    let root = normalize_selected_path(directory, &package.library_path)
        .ok_or_else(|| "caller package library root escapes inventory".to_string())?;
    Ok(sources.contains_key(&root).then_some(root))
}

fn dependency_available(
    kind: RustCargoDependencyKind,
    target: RustCallerTargetKind,
    test: bool,
) -> bool {
    // A detached file belongs to no Cargo target, so no manifest dependency
    // table applies to it.
    if target == RustCallerTargetKind::Detached {
        return false;
    }
    match kind {
        RustCargoDependencyKind::Normal => target != RustCallerTargetKind::Build,
        RustCargoDependencyKind::Development => {
            test || matches!(
                target,
                RustCallerTargetKind::Example
                    | RustCallerTargetKind::Test
                    | RustCallerTargetKind::Bench
            )
        }
        RustCargoDependencyKind::Build => target == RustCallerTargetKind::Build,
    }
}

fn selected_context_identity(
    content_identity: &[u8],
    profile: &RustCallerTargetProfile,
    progress: &mut impl FnMut(RustSelectedContextWork) -> bool,
) -> Result<RustSelectedBuildOutcome<Oid>, String> {
    if !progress(RustSelectedContextWork::ScopeNode) {
        return Ok(RustSelectedBuildOutcome::Stopped);
    }
    let mut bytes = Vec::new();
    append_path_identity(&mut bytes, &profile.manifest_path)?;
    bytes.push(profile.target_kind as u8);
    append_path_identity(&mut bytes, &profile.target_root)?;
    append_identity_text(&mut bytes, &profile.target_triple);
    for atom in &profile.cfg_atoms {
        if !progress(RustSelectedContextWork::ScopeNode) {
            return Ok(RustSelectedBuildOutcome::Stopped);
        }
        append_identity_text(&mut bytes, atom);
    }
    bytes.push(0xff);
    for feature in &profile.features {
        if !progress(RustSelectedContextWork::ScopeNode) {
            return Ok(RustSelectedBuildOutcome::Stopped);
        }
        append_identity_text(&mut bytes, feature);
    }
    bytes.push(u8::from(profile.test));
    bytes.extend_from_slice(content_identity);
    Oid::hash_object(ObjectType::Blob, &bytes)
        .map(RustSelectedBuildOutcome::Ready)
        .map_err(|error| error.to_string())
}

fn append_path_identity(bytes: &mut Vec<u8>, path: &Path) -> Result<(), String> {
    for component in path.components() {
        let Component::Normal(component) = component else {
            return Err(format!(
                "selected identity path is not normalized: {path:?}"
            ));
        };
        let component = component
            .to_str()
            .ok_or_else(|| format!("selected identity path is not UTF-8: {path:?}"))?;
        append_identity_text(bytes, component);
    }
    bytes.push(0xfe);
    Ok(())
}

fn append_identity_text(bytes: &mut Vec<u8>, value: &str) {
    let length = u64::try_from(value.len()).expect("selected identity text length fits u64");
    bytes.extend_from_slice(&length.to_le_bytes());
    bytes.extend_from_slice(value.as_bytes());
}

fn resolved_module_routes_from_prepared<'a>(
    file: &Path,
    route_facts: &'a RustModuleRouteFacts,
    prepared: &'a RustSelectedPreparedSource,
    profile: &RustCallerTargetProfile,
    gaps: &mut BTreeSet<RustSelectedContextGap>,
    progress: &mut impl FnMut(RustSelectedContextWork) -> bool,
) -> RustSelectedBuildOutcome<
    Vec<(
        usize,
        &'a brokk_bifrost_core::analyzer::rust_facts::RustModuleRouteFact,
    )>,
> {
    let mut routes = Vec::new();
    for (route_index, prepared_route) in prepared.routes.iter().enumerate() {
        if !progress(RustSelectedContextWork::ScopeNode) {
            return RustSelectedBuildOutcome::Stopped;
        }
        let route = &route_facts.routes[route_index];
        assert_eq!(
            route.declaration_start, prepared_route.declaration_start,
            "prepared Rust module route changed"
        );
        assert_eq!(
            route.declaration_end, prepared_route.declaration_end,
            "prepared Rust module route changed"
        );
        if !route.gates.is_empty() {
            gaps.insert(RustSelectedContextGap::UnsupportedMacroGeneratedModule {
                file: file.to_path_buf(),
                start_byte: route.declaration_start,
            });
            continue;
        }
        let (own, inherited) = prepared_route
            .activation
            .split_first()
            .expect("prepared Rust route has an own activation condition");
        match profile.activation(&own.condition) {
            RustSelectedActivation::Inactive => continue,
            RustSelectedActivation::Unknown => {
                gaps.insert(RustSelectedContextGap::UnknownActivation {
                    file: file.to_path_buf(),
                    start_byte: own
                        .gap_start
                        .expect("a Rust route activation has its declaration start"),
                });
            }
            RustSelectedActivation::Active => {}
        }
        let RustSelectedBuildOutcome::Ready(inherited_activation) =
            selected_prepared_scope_activation_with_progress(
                inherited, profile, file, gaps, progress,
            )
        else {
            return RustSelectedBuildOutcome::Stopped;
        };
        if inherited_activation != RustSelectedActivation::Inactive {
            routes.push((route_index, route));
        }
    }
    RustSelectedBuildOutcome::Ready(routes)
}

fn selected_inline_scope_at_byte_with_progress(
    route_facts: &RustModuleRouteFacts,
    byte: usize,
    progress: &mut impl FnMut(RustSelectedContextWork) -> bool,
) -> RustSelectedBuildOutcome<usize> {
    let mut selected = 0;
    for (index, scope) in route_facts.scopes.iter().enumerate() {
        if !progress(RustSelectedContextWork::ScopeNode) {
            return RustSelectedBuildOutcome::Stopped;
        }
        if scope.body_start <= byte
            && byte < scope.body_end
            && route_facts.scopes[selected].body_start <= scope.body_start
        {
            selected = index;
        }
    }
    RustSelectedBuildOutcome::Ready(selected)
}

fn combine_selected_activation(
    left: RustSelectedActivation,
    right: RustSelectedActivation,
) -> RustSelectedActivation {
    match (left, right) {
        (RustSelectedActivation::Inactive, _) | (_, RustSelectedActivation::Inactive) => {
            RustSelectedActivation::Inactive
        }
        (RustSelectedActivation::Unknown, _) | (_, RustSelectedActivation::Unknown) => {
            RustSelectedActivation::Unknown
        }
        (RustSelectedActivation::Active, RustSelectedActivation::Active) => {
            RustSelectedActivation::Active
        }
    }
}

fn module_candidates(
    file: &Path,
    facts: &RustModuleRouteFacts,
    is_crate_root: bool,
    route: &brokk_bifrost_core::analyzer::rust_facts::RustModuleRouteFact,
    progress: &mut impl FnMut(RustSelectedContextWork) -> bool,
) -> RustSelectedBuildOutcome<Vec<PathBuf>> {
    let parent = file.parent().unwrap_or(Path::new(""));
    let stem = file
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or_default();
    let base = if is_crate_root || stem == "mod" {
        parent.to_path_buf()
    } else {
        parent.join(stem)
    };
    #[derive(Clone)]
    struct ScopeDirectories {
        module: Option<PathBuf>,
        attribute: Option<PathBuf>,
    }
    let mut scopes = Vec::with_capacity(facts.scopes.len());
    for scope in &facts.scopes {
        if !progress(RustSelectedContextWork::ScopeNode) {
            return RustSelectedBuildOutcome::Stopped;
        }
        let directories = match scope.parent {
            None => ScopeDirectories {
                module: Some(base.clone()),
                attribute: Some(parent.to_path_buf()),
            },
            Some(parent_index) => {
                assert!(
                    parent_index < scopes.len(),
                    "Rust module scopes are pre-order"
                );
                let enclosing: &ScopeDirectories = &scopes[parent_index];
                let directory = match scope.path_attribute.as_deref() {
                    Some(attribute) => enclosing
                        .attribute
                        .as_deref()
                        .and_then(|base| normalize_selected_path(base, Path::new(attribute))),
                    None => enclosing
                        .module
                        .as_ref()
                        .map(|base| base.join(&scope.module_name)),
                };
                ScopeDirectories {
                    module: directory.clone(),
                    attribute: directory,
                }
            }
        };
        scopes.push(directories);
    }
    assert!(route.scope < scopes.len(), "Rust module route has no scope");
    let scope = &scopes[route.scope];
    if let Some(attribute) = route.path_attribute.as_deref() {
        return RustSelectedBuildOutcome::Ready(
            scope
                .attribute
                .as_deref()
                .and_then(|base| normalize_selected_path(base, Path::new(attribute)))
                .into_iter()
                .collect(),
        );
    }
    let Some(scoped_base) = scope.module.as_ref() else {
        return RustSelectedBuildOutcome::Ready(Vec::new());
    };
    RustSelectedBuildOutcome::Ready(
        [
            scoped_base.join(&route.module_name).with_extension("rs"),
            scoped_base.join(&route.module_name).join("mod.rs"),
        ]
        .into_iter()
        .filter_map(|path| normalize_selected_path(Path::new(""), &path))
        .collect(),
    )
}

fn normalize_selected_path(base: &Path, path: &Path) -> Option<PathBuf> {
    if path.is_absolute() {
        return None;
    }
    let mut normalized = base.to_path_buf();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop().then_some(())?;
            }
            Component::Normal(component) => normalized.push(component),
            Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    Some(normalized)
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use super::*;
    use crate::declarations::parse_rust_file;
    use crate::resolution_spike_fixture::M6A_RUST_WORKSPACE_FILES;

    fn test_public_declaration_authority() -> RustSelectedDeclarationAuthority {
        RustSelectedDeclarationAuthority {
            source_site: ResolutionSiteId::new(0),
            declaration: SourceDeclarationId::new(0),
            crate_root: PathBuf::new(),
            declaring_module_segments: Box::new([]),
            visibility: RustVisibility::Public,
        }
    }

    #[test]
    fn declaration_visibility_uses_exact_declaring_module_and_crate() {
        let declaring = ["outer".to_string(), "inner".to_string()];
        let descendant = ["outer".to_string(), "inner".to_string(), "leaf".to_string()];
        let sibling = ["outer".to_string(), "other".to_string()];
        let parent = ["outer".to_string()];
        let outside = ["other".to_string()];
        let foreign = ["outer".to_string(), "inner".to_string(), "leaf".to_string()];

        assert!(rust_declaration_visibility_reaches(
            &RustVisibility::Private,
            true,
            &declaring,
            &declaring,
        ));
        assert!(rust_declaration_visibility_reaches(
            &RustVisibility::Private,
            true,
            &descendant,
            &declaring,
        ));
        assert!(!rust_declaration_visibility_reaches(
            &RustVisibility::Private,
            true,
            &sibling,
            &declaring,
        ));
        assert!(rust_declaration_visibility_reaches(
            &RustVisibility::Crate,
            true,
            &sibling,
            &declaring,
        ));
        assert!(rust_declaration_visibility_reaches(
            &RustVisibility::SuperModule,
            true,
            &parent,
            &declaring,
        ));
        assert!(!rust_declaration_visibility_reaches(
            &RustVisibility::SuperModule,
            true,
            &outside,
            &declaring,
        ));
        assert!(rust_declaration_visibility_reaches(
            &RustVisibility::InPath(vec!["crate".into(), "outer".into()]),
            true,
            &descendant,
            &declaring,
        ));
        assert!(!rust_declaration_visibility_reaches(
            &RustVisibility::Private,
            false,
            &foreign,
            &declaring,
        ));
    }

    fn fixture_inputs() -> (Vec<RustSelectedSourceMount>, Vec<RustSelectedManifestMount>) {
        inputs_from_files(M6A_RUST_WORKSPACE_FILES)
    }

    fn inputs_from_files(
        files: &[(&str, &str)],
    ) -> (Vec<RustSelectedSourceMount>, Vec<RustSelectedManifestMount>) {
        // Absolute on every OS, as ProjectFile requires; nothing reads it.
        let root = std::env::temp_dir().join("selected-context-does-not-touch-disk");
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("configure Rust parser");
        let mut sources = Vec::new();
        let mut manifests = Vec::new();
        for (path, source) in files {
            if path.ends_with("Cargo.toml") {
                manifests.push(
                    RustSelectedManifestMount::from_source(*path, source)
                        .expect("parse selected manifest facts"),
                );
                continue;
            }
            let tree = parser
                .parse(source, None)
                .expect("parse selected Rust source");
            let file =
                brokk_bifrost_core::analyzer::ProjectFile::new(root.clone(), PathBuf::from(path));
            let parsed = parse_rust_file(&file, source, &tree);
            sources.push(RustSelectedSourceMount {
                relative_path: PathBuf::from(path),
                content_oid: Oid::hash_object(ObjectType::Blob, source.as_bytes())
                    .expect("hash selected source"),
                facts: parsed.rust_usage_facts,
                resolution_facts: parsed.resolution_facts,
            });
        }
        (sources, manifests)
    }

    fn rust_files_below(root: &Path, relative: &Path, files: &mut Vec<PathBuf>) {
        let mut pending = vec![root.join(relative)];
        while let Some(path) = pending.pop() {
            let Ok(metadata) = path.symlink_metadata() else {
                continue;
            };
            if metadata.is_file() {
                if path.extension().is_some_and(|extension| extension == "rs") {
                    files.push(
                        path.strip_prefix(root)
                            .expect("operator corpus stays below the workspace root")
                            .to_path_buf(),
                    );
                }
                continue;
            }
            if !metadata.is_dir() {
                continue;
            }
            let mut children = std::fs::read_dir(&path)
                .expect("read operator corpus directory")
                .map(|entry| entry.expect("read operator corpus entry").path())
                .collect::<Vec<_>>();
            children.sort();
            pending.extend(children.into_iter().rev());
        }
    }

    fn current_bifrost_package_inputs()
    -> (Vec<RustSelectedSourceMount>, Vec<RustSelectedManifestMount>) {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .expect("canonical Bifrost workspace root");
        let manifest_source =
            std::fs::read_to_string(root.join("Cargo.toml")).expect("read Bifrost root manifest");
        let manifest = RustSelectedManifestMount::from_source("Cargo.toml", &manifest_source)
            .expect("parse Bifrost root manifest");
        let mut paths = Vec::new();
        for directory in ["src", "tests", "test-support", "examples", "benches"] {
            rust_files_below(&root, Path::new(directory), &mut paths);
        }
        if root.join("build.rs").is_file() {
            paths.push(PathBuf::from("build.rs"));
        }
        // These are analyzer input samples read as data by tests, not sources
        // compiled into one of the package's Cargo targets.
        paths.retain(|path| !path.starts_with(Path::new("tests/fixtures")));
        paths.sort();
        paths.dedup();

        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("configure Rust parser");
        let sources = paths
            .into_iter()
            .map(|relative_path| {
                let source = std::fs::read_to_string(root.join(&relative_path))
                    .unwrap_or_else(|error| panic!("read {relative_path:?}: {error}"));
                let tree = parser
                    .parse(&source, None)
                    .unwrap_or_else(|| panic!("parse {relative_path:?}"));
                let file = brokk_bifrost_core::analyzer::ProjectFile::new(
                    root.clone(),
                    relative_path.clone(),
                );
                let parsed = parse_rust_file(&file, &source, &tree);
                RustSelectedSourceMount {
                    relative_path,
                    content_oid: Oid::hash_object(ObjectType::Blob, source.as_bytes())
                        .expect("hash Bifrost source"),
                    facts: parsed.rust_usage_facts,
                    resolution_facts: parsed.resolution_facts,
                }
            })
            .collect();
        (sources, vec![manifest])
    }

    fn profile(left: bool, test: bool) -> RustCallerTargetProfile {
        RustCallerTargetProfile {
            manifest_path: PathBuf::from("app/Cargo.toml"),
            target_kind: RustCallerTargetKind::Binary,
            target_root: PathBuf::from("src/main.rs"),
            target_triple: "x86_64-unknown-linux-gnu".to_string(),
            cfg_atoms: BTreeSet::from(["target_os = \"linux\"".to_string()]),
            features: left.then(|| "left".to_string()).into_iter().collect(),
            test,
        }
    }

    fn same_crate_inputs() -> (Vec<RustSelectedSourceMount>, Vec<RustSelectedManifestMount>) {
        const FILES: &[(&str, &str)] = &[
            (
                "Cargo.toml",
                "[workspace]\nmembers = [\"app\"]\n[workspace.package]\nedition = \"2024\"\n",
            ),
            (
                "app/Cargo.toml",
                "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition.workspace = true\n",
            ),
            ("app/src/lib.rs", "pub(crate) mod parent;\nmod outsider;\n"),
            ("app/src/parent.rs", "pub(super) mod child;\n"),
            (
                "app/src/parent/child.rs",
                "pub struct Item { pub value: () }\n",
            ),
            (
                "app/src/outsider.rs",
                concat!(
                    "pub(self) mod own;\n",
                    "use crate::parent::child::Item as CrateItem;\n",
                    "use super::parent::child::Item as SuperItem;\n",
                    "use self::own::Own as SelfItem;\n",
                    "pub(self) use self::own::Own as SelfPublicItem;\n",
                    "use own::Own as RelativeItem;\n",
                ),
            ),
            (
                "app/src/outsider/own.rs",
                "pub struct Own { pub value: () }\n",
            ),
        ];
        inputs_from_files(FILES)
    }

    fn topology_sources(
        sources: Vec<RustSelectedSourceMount>,
    ) -> Vec<RustSelectedTopologySourceMount> {
        sources
            .into_iter()
            .map(|source| RustSelectedTopologySourceMount {
                relative_path: source.relative_path,
                content_oid: source.content_oid,
                facts: source.facts,
            })
            .collect()
    }

    #[test]
    fn canonical_import_segments_survive_prior_local_and_later_alias_or_glob() {
        const FILES: &[(&str, &str)] = &[
            (
                "app/Cargo.toml",
                "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            ),
            (
                "app/src/lib.rs",
                "mod local;\nmod later;\nfn local_scope() { use crate::local::Only; }\nuse crate::later::{Target as Alias, *};\n",
            ),
            ("app/src/local.rs", "pub struct Only;\n"),
            ("app/src/later.rs", "pub struct Target;\n"),
        ];
        let (sources, manifests) = inputs_from_files(FILES);
        let targets = &sources[0].facts.import_targets;
        let local_index = targets
            .iter()
            .position(|target| target.imported_name.as_deref() == Some("Only"))
            .expect("local import fact");
        let alias_index = targets
            .iter()
            .position(|target| target.bound_name.as_deref() == Some("Alias"))
            .expect("aliased import fact");
        let glob_index = targets
            .iter()
            .position(|target| target.is_glob)
            .expect("glob import fact");
        assert!(local_index < alias_index);
        assert!(local_index < glob_index);

        let mut progress = |_| true;
        assert_eq!(
            selected_import_route_segments_with_progress(&targets[alias_index], &mut progress),
            RustSelectedBuildOutcome::Ready((
                vec!["crate".to_string(), "later".to_string()].into_boxed_slice(),
                ResolutionRootImportAnchor::Lexical,
            ))
        );
        assert_eq!(
            selected_import_route_segments_with_progress(&targets[glob_index], &mut progress),
            RustSelectedBuildOutcome::Ready((
                vec!["crate".to_string(), "later".to_string()].into_boxed_slice(),
                ResolutionRootImportAnchor::Lexical,
            ))
        );

        let context = build_rust_selected_context(sources, manifests, same_crate_profile())
            .expect("build selected context from canonical import facts");
        assert!(context.root_routes.iter().any(|route| {
            route.local_name.as_deref() == Some("Alias") && route.route == "crate::later"
        }));
        assert!(context.root_routes.iter().any(|route| {
            route.kind == RustSelectedRootRouteKind::GlobUse && route.route == "crate::later"
        }));
    }

    #[test]
    fn textual_macro_inheritance_uses_module_declaration_order() {
        for (root, expected) in [
            (
                "macro_rules! inherited { ($t:ty) => {}; }\nmod child;\n",
                true,
            ),
            (
                "mod child;\nmacro_rules! inherited { ($t:ty) => {}; }\n",
                false,
            ),
        ] {
            let (sources, manifests) = inputs_from_files(&[
                (
                    "app/Cargo.toml",
                    "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
                ),
                ("app/src/lib.rs", root),
                ("app/src/child.rs", "inherited!(usize);\n"),
            ]);
            let context =
                build_rust_selected_context(sources.clone(), manifests, same_crate_profile())
                    .unwrap();
            let result = rust_selected_textual_macro(
                &context,
                Path::new("app/src/child.rs"),
                0,
                "inherited",
                |path| {
                    sources
                        .iter()
                        .find(|source| source.relative_path == path)
                        .map(|source| &source.facts)
                },
                |_, _| false,
                &|| true,
            );
            let RustSelectedBuildOutcome::Ready(result) = result else {
                panic!("unbounded lookup stops");
            };
            assert_eq!(result.is_some(), expected);
            if let Some((file, declaration)) = result {
                assert_eq!(file, Path::new("app/src/lib.rs"));
                assert_eq!(
                    declaration,
                    sources
                        .iter()
                        .find(|source| source.relative_path == file)
                        .unwrap()
                        .facts
                        .module_routes
                        .item_macros[0]
                        .declaration
                );
            }
        }
    }

    fn same_crate_profile() -> RustCallerTargetProfile {
        RustCallerTargetProfile {
            manifest_path: PathBuf::from("app/Cargo.toml"),
            target_kind: RustCallerTargetKind::Library,
            target_root: PathBuf::from("src/lib.rs"),
            target_triple: "x86_64-unknown-linux-gnu".to_string(),
            cfg_atoms: BTreeSet::new(),
            features: BTreeSet::new(),
            test: false,
        }
    }

    #[test]
    fn workspace_inherited_edition_accepts_nonvirtual_workspace_root() {
        const FILES: &[(&str, &str)] = &[
            (
                "Cargo.toml",
                "[workspace]\nmembers = []\n\n[workspace.package]\nedition = \"2024\"\n\n[package]\nname = \"root\"\nversion = \"0.1.0\"\nedition.workspace = true\n",
            ),
            ("src/lib.rs", "pub fn root() {}\n"),
        ];
        let (sources, manifests) = inputs_from_files(FILES);
        let mut profile = same_crate_profile();
        profile.manifest_path = PathBuf::from("Cargo.toml");
        profile.target_root = PathBuf::from("src/lib.rs");
        let context = build_rust_selected_context(sources, manifests, profile)
            .expect("resolve an edition inherited by a nonvirtual workspace root");

        assert!(context.target_memberships.iter().any(|membership| {
            membership.crate_root == Path::new("src/lib.rs")
                && membership.edition == RustCargoEdition::Rust2024
        }));
    }

    #[test]
    fn detached_cfg_defaults_prove_refute_and_preserve_unknown_atoms() {
        let profile = detached_profile_for_source(None, Path::new("scratch.rs")).unwrap();
        for (predicate, expected) in [
            ("test", RustSelectedActivation::Active),
            ("not(test)", RustSelectedActivation::Inactive),
            ("feature = \"x\"", RustSelectedActivation::Unknown),
            ("custom_atom", RustSelectedActivation::Unknown),
            (
                "all(test, debug_assertions)",
                RustSelectedActivation::Active,
            ),
            (
                "any(not(test), not(debug_assertions))",
                RustSelectedActivation::Inactive,
            ),
            (
                "all(not(test), custom_atom)",
                RustSelectedActivation::Unknown,
            ),
            ("any(test, custom_atom)", RustSelectedActivation::Unknown),
        ] {
            let source = format!("#[cfg({predicate})] fn gated() {{}}");
            let mut parser = tree_sitter::Parser::new();
            parser
                .set_language(&tree_sitter_rust::LANGUAGE.into())
                .unwrap();
            let tree = parser.parse(&source, None).unwrap();
            let item = crate::syntax::unwrap_attributes(tree.root_node().named_child(0).unwrap());
            let condition = crate::lexical_scope::rust_cfg_condition(item, &source);
            assert_eq!(
                profile.activation(&condition),
                expected,
                "{predicate}: {condition:?}"
            );
        }
    }

    #[test]
    fn detached_cfg_target_values_follow_the_compiled_host() {
        use brokk_bifrost_core::analyzer::rust_facts::RustCfgInstruction;
        let profile = detached_profile_for_source(None, Path::new("scratch.rs")).unwrap();
        for (key, value) in [
            ("target_os", std::env::consts::OS),
            ("target_arch", std::env::consts::ARCH),
            ("target_family", std::env::consts::FAMILY),
        ] {
            let condition = RustCfgCondition::Expression(
                vec![RustCfgInstruction::KeyValue {
                    key: key.to_string(),
                    value: value.to_string(),
                }]
                .into_boxed_slice(),
            );
            assert_eq!(
                profile.activation(&condition),
                RustSelectedActivation::Active
            );
            let condition = RustCfgCondition::Expression(
                vec![RustCfgInstruction::KeyValue {
                    key: key.to_string(),
                    value: "nonexistent-target-value".to_string(),
                }]
                .into_boxed_slice(),
            );
            assert_eq!(
                profile.activation(&condition),
                RustSelectedActivation::Inactive
            );
        }
        assert_eq!(
            profile.activation(&RustCfgCondition::Atom("unix".into())),
            if cfg!(unix) {
                RustSelectedActivation::Active
            } else {
                RustSelectedActivation::Inactive
            }
        );
        assert_eq!(
            profile.activation(&RustCfgCondition::Atom("windows".into())),
            if cfg!(windows) {
                RustSelectedActivation::Active
            } else {
                RustSelectedActivation::Inactive
            }
        );
    }

    #[test]
    fn default_target_profiles_keep_unconfigured_cfg_atoms_unknown() {
        let normal = same_crate_profile();
        assert_eq!(
            normal.activation(&RustCfgCondition::Atom("test".to_string())),
            RustSelectedActivation::Active,
        );
        assert_eq!(
            normal.activation(&RustCfgCondition::NotAtom("test".to_string())),
            RustSelectedActivation::Inactive,
        );
        for condition in [
            RustCfgCondition::Atom("feature = \"left\"".to_string()),
            RustCfgCondition::NotAtom("feature = \"left\"".to_string()),
            RustCfgCondition::Atom("all(unix, feature = \"left\")".to_string()),
            RustCfgCondition::Atom("any(test, feature = \"left\")".to_string()),
        ] {
            assert_eq!(
                normal.activation(&condition),
                RustSelectedActivation::Unknown,
                "unconfigured condition {condition:?}",
            );
        }
    }

    #[test]
    fn library_caller_profile_is_derived_only_for_an_unconditional_nearest_package() {
        let (sources, manifests) = same_crate_inputs();
        let mut topology_sources = topology_sources(sources);
        let outcome = build_rust_selected_library_context_for_caller(
            &topology_sources,
            &manifests,
            Path::new("app/src/parent.rs"),
        )
        .expect("derive selected library caller context");
        let RustSelectedLibraryContextOutcome::Ready(context) = outcome else {
            panic!("an unconditional library member must have a selected caller context")
        };
        assert!(context.target_memberships.iter().any(|membership| {
            membership.crate_root == Path::new("app/src/lib.rs")
                && membership.file == Path::new("app/src/parent.rs")
        }));

        topology_sources[0].facts.modules[0].cfg_condition =
            RustCfgCondition::Atom("feature = \"unknown\"".to_string());
        let RustSelectedLibraryContextOutcome::Ready(context) =
            build_rust_selected_library_context_for_caller(
                &topology_sources,
                &manifests,
                Path::new("app/src/parent.rs"),
            )
            .expect("retain a cfg-dependent selected library caller context")
        else {
            panic!("an unknown module activation remains a possible library route")
        };
        assert!(context.gaps.iter().any(|gap| matches!(
            gap,
            RustSelectedContextGap::UnknownActivation { file, .. }
                if file == Path::new("app/src/lib.rs")
        )));
        assert!(matches!(
            build_rust_selected_library_context_for_caller(
                &topology_sources,
                &manifests,
                Path::new("app/src/bin/tool.rs"),
            )
            .expect("reject a non-library caller"),
            RustSelectedLibraryContextOutcome::Unavailable
        ));
    }

    #[test]
    fn a_manifest_less_rust_file_resolves_as_a_detached_crate_root() {
        const FILES: &[(&str, &str)] = &[
            ("loose/app.rs", "mod helper;\npub struct Item;\n"),
            ("loose/helper.rs", "pub struct Helper;\n"),
        ];
        let (sources, manifests) = inputs_from_files(FILES);
        let topology = topology_sources(sources);
        let outcome = build_rust_selected_library_context_for_caller(
            &topology,
            &manifests,
            Path::new("loose/app.rs"),
        )
        .expect("derive a detached selected caller context");
        let RustSelectedLibraryContextOutcome::Ready(context) = outcome else {
            panic!("a Rust file no manifest encloses is its own detached crate root")
        };
        assert_eq!(
            context.target_roots,
            BTreeSet::from([PathBuf::from("loose/app.rs")])
        );
        assert_eq!(
            context.reachable_files,
            BTreeSet::from([
                PathBuf::from("loose/app.rs"),
                PathBuf::from("loose/helper.rs")
            ])
        );
        assert!(context.dependency_edges.is_empty());
        for file in ["loose/app.rs", "loose/helper.rs"] {
            assert!(
                context.target_memberships.iter().any(|membership| {
                    membership.crate_root == Path::new("loose/app.rs")
                        && membership.file == Path::new(file)
                        && membership.edition == DETACHED_DEFAULT_EDITION
                }),
                "{file} is a module of the detached root: {:?}",
                context.target_memberships
            );
        }
        assert!(context.gaps.is_empty(), "{:?}", context.gaps);
    }

    #[test]
    fn a_package_source_no_target_reaches_resolves_as_a_detached_crate_root() {
        const FILES: &[(&str, &str)] = &[
            (
                "Cargo.toml",
                "[workspace]\nmembers = [\"app\"]\n[workspace.package]\nedition = \"2021\"\n",
            ),
            (
                "app/Cargo.toml",
                "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition.workspace = true\n",
            ),
            ("app/src/lib.rs", "pub struct Root;\n"),
            ("app/src/orphan.rs", "pub struct Orphan;\n"),
        ];
        let (sources, manifests) = inputs_from_files(FILES);
        let topology = topology_sources(sources);
        let outcome = build_rust_selected_library_context_for_caller(
            &topology,
            &manifests,
            Path::new("app/src/orphan.rs"),
        )
        .expect("derive a detached selected caller context");
        let RustSelectedLibraryContextOutcome::Ready(context) = outcome else {
            panic!("a package source that no Cargo target reaches is a detached crate root")
        };
        assert_eq!(
            context.target_roots,
            BTreeSet::from([PathBuf::from("app/src/orphan.rs")])
        );
        assert!(context.target_memberships.iter().any(|membership| {
            membership.crate_root == Path::new("app/src/orphan.rs")
                && membership.file == Path::new("app/src/orphan.rs")
                && membership.edition == RustCargoEdition::Rust2021
        }));
        assert!(context.dependency_edges.is_empty());
        assert!(
            !context
                .reachable_files
                .contains(Path::new("app/src/lib.rs"))
        );
    }

    #[test]
    fn excluded_directories_leave_the_enclosing_cargo_workspace() {
        let manifest = RustSelectedManifestMount::from_source(
            "Cargo.toml",
            concat!(
                "[workspace]\n",
                "members = [\"crates/app\"]\n",
                "exclude = [\".claude/worktrees/*\", \"vendor/*\"]\n",
                "[workspace.package]\n",
                "edition = \"2024\"\n",
            ),
        )
        .expect("parse workspace manifest facts");
        let workspace = Path::new("");
        for claimed in ["crates/app", "crates/app/nested", "tools"] {
            assert!(
                cargo_workspace_claims_package(workspace, &manifest.facts, Path::new(claimed)),
                "{claimed}"
            );
        }
        for excluded in [
            "vendor/app",
            "vendor/app/nested",
            ".claude/worktrees/lane",
            ".claude/worktrees/lane/crates/app",
        ] {
            assert!(
                !cargo_workspace_claims_package(workspace, &manifest.facts, Path::new(excluded)),
                "{excluded}"
            );
        }
    }

    #[test]
    fn an_excluded_package_cannot_inherit_the_enclosing_workspace_edition() {
        const FILES: &[(&str, &str)] = &[
            (
                "Cargo.toml",
                concat!(
                    "[workspace]\n",
                    "members = [\"crates/app\"]\n",
                    "exclude = [\"vendor/*\"]\n",
                    "[workspace.package]\n",
                    "edition = \"2024\"\n",
                ),
            ),
            (
                "vendor/app/Cargo.toml",
                "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition.workspace = true\n",
            ),
            ("vendor/app/src/lib.rs", "pub fn vendored() {}\n"),
        ];
        let (sources, manifests) = inputs_from_files(FILES);
        let error = rust_selected_workspace_profiles(&topology_sources(sources), &manifests)
            .expect_err("an excluded package has no workspace to inherit from");
        assert!(
            error.contains("has no selected workspace") && error.contains("vendor/app/Cargo.toml"),
            "{error}"
        );
    }

    #[test]
    fn duplicate_package_names_stay_in_their_own_workspace_scope() {
        const FILES: &[(&str, &str)] = &[
            (
                "Cargo.toml",
                concat!(
                    "[workspace]\n",
                    "members = [\"crates/app\"]\n",
                    "exclude = [\"vendor/*\"]\n",
                    "[workspace.package]\n",
                    "edition = \"2024\"\n",
                ),
            ),
            (
                "crates/app/Cargo.toml",
                "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition.workspace = true\n",
            ),
            ("crates/app/src/lib.rs", "pub fn member() {}\n"),
            (
                "vendor/app/Cargo.toml",
                "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2015\"\n",
            ),
            ("vendor/app/src/lib.rs", "pub fn vendored() {}\n"),
        ];
        let (sources, manifests) = inputs_from_files(FILES);
        let inventory =
            rust_selected_workspace_profiles(&topology_sources(sources.clone()), &manifests)
                .expect("enumerate workspace profiles");
        assert!(inventory.target_inventory_complete);

        for (manifest_path, root, edition) in [
            (
                "crates/app/Cargo.toml",
                "crates/app/src/lib.rs",
                RustCargoEdition::Rust2024,
            ),
            (
                "vendor/app/Cargo.toml",
                "vendor/app/src/lib.rs",
                RustCargoEdition::Rust2015,
            ),
        ] {
            let profile = inventory
                .profiles
                .iter()
                .find(|profile| {
                    profile.manifest_path == Path::new(manifest_path)
                        && profile.target_kind == RustCallerTargetKind::Library
                        && !profile.test
                })
                .unwrap_or_else(|| panic!("library profile for {manifest_path}"));
            let context =
                build_rust_selected_context(sources.clone(), manifests.clone(), profile.clone())
                    .unwrap_or_else(|error| {
                        panic!("build selected context for {manifest_path}: {error}")
                    });
            let files = context
                .target_memberships
                .iter()
                .map(|membership| membership.file.as_path())
                .collect::<BTreeSet<_>>();
            assert_eq!(files, [Path::new(root)].into());
            // Two packages named `app` are two crates. The member inherits the
            // workspace edition; the excluded copy keeps its own and is never
            // merged into the member's crate.
            assert!(
                context
                    .target_memberships
                    .iter()
                    .all(|membership| membership.edition == edition),
                "{manifest_path}: {:?}",
                context.target_memberships
            );
        }
    }

    #[test]
    fn selected_workspace_profiles_cover_default_cargo_target_layouts() {
        const FILES: &[(&str, &str)] = &[
            (
                "Cargo.toml",
                "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            ),
            ("src/lib.rs", "pub fn library() {}\n"),
            ("src/main.rs", "fn main() {}\n"),
            ("src/bin/tool.rs", "fn main() {}\n"),
            ("examples/demo.rs", "fn main() {}\n"),
            ("tests/service.rs", "#[test]\nfn service() {}\n"),
            ("benches/throughput.rs", "fn throughput() {}\n"),
            ("build.rs", "fn main() {}\n"),
        ];
        let (sources, manifests) = inputs_from_files(FILES);
        let inventory = rust_selected_workspace_profiles(&topology_sources(sources), &manifests)
            .expect("enumerate default Cargo targets");

        assert!(inventory.target_inventory_complete);
        let targets = inventory
            .profiles
            .iter()
            .map(|profile| {
                (
                    profile.target_kind,
                    profile.target_root.as_path(),
                    profile.test,
                )
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(
            targets,
            BTreeSet::from([
                (
                    RustCallerTargetKind::Library,
                    Path::new("src/lib.rs"),
                    false
                ),
                (RustCallerTargetKind::Library, Path::new("src/lib.rs"), true),
                (
                    RustCallerTargetKind::Binary,
                    Path::new("src/main.rs"),
                    false
                ),
                (RustCallerTargetKind::Binary, Path::new("src/main.rs"), true),
                (
                    RustCallerTargetKind::Binary,
                    Path::new("src/bin/tool.rs"),
                    false
                ),
                (
                    RustCallerTargetKind::Binary,
                    Path::new("src/bin/tool.rs"),
                    true
                ),
                (
                    RustCallerTargetKind::Example,
                    Path::new("examples/demo.rs"),
                    false
                ),
                (
                    RustCallerTargetKind::Example,
                    Path::new("examples/demo.rs"),
                    true
                ),
                (
                    RustCallerTargetKind::Test,
                    Path::new("tests/service.rs"),
                    true
                ),
                (
                    RustCallerTargetKind::Bench,
                    Path::new("benches/throughput.rs"),
                    true
                ),
                (RustCallerTargetKind::Build, Path::new("build.rs"), false),
            ])
        );

        let (sources, manifests) = inputs_from_files(&[
            (
                "Cargo.toml",
                concat!(
                    "[package]\n",
                    "name = \"app\"\n",
                    "version = \"0.1.0\"\n",
                    "edition = \"2024\"\n",
                    "autobins = false\n",
                    "autoexamples = false\n",
                    "autotests = false\n",
                    "autobenches = false\n",
                    "build = false\n",
                    "\n",
                    "[[test]]\n",
                    "name = \"service\"\n",
                ),
            ),
            ("src/lib.rs", "pub fn library() {}\n"),
            ("src/main.rs", "fn main() {}\n"),
            ("examples/demo.rs", "fn main() {}\n"),
            ("tests/service.rs", "#[test]\nfn service() {}\n"),
            ("benches/throughput.rs", "fn throughput() {}\n"),
            ("build.rs", "fn main() {}\n"),
        ]);
        let inventory = rust_selected_workspace_profiles(&topology_sources(sources), &manifests)
            .expect("honor disabled automatic targets and build scripts");
        assert!(inventory.target_inventory_complete);
        assert_eq!(inventory.profiles.len(), 3);
        assert_eq!(
            inventory
                .profiles
                .iter()
                .map(|profile| (
                    profile.target_kind,
                    profile.target_root.as_path(),
                    profile.test,
                ))
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                (
                    RustCallerTargetKind::Library,
                    Path::new("src/lib.rs"),
                    false,
                ),
                (RustCallerTargetKind::Library, Path::new("src/lib.rs"), true),
                (
                    RustCallerTargetKind::Test,
                    Path::new("tests/service.rs"),
                    true,
                ),
            ])
        );

        let explicit = RustSelectedManifestMount::from_source(
            "Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2024\"\n[[bin]]\nname = \"tool\"\npath = \"src/tool.rs\"\n",
        )
        .expect("parse explicit binary target");
        assert!(
            !explicit
                .facts
                .package
                .expect("package facts")
                .has_custom_target_configuration
        );

        let disabled = RustSelectedManifestMount::from_source(
            "Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\nautolib = false\n",
        )
        .expect("parse disabled automatic library target");
        let disabled_package = disabled.facts.package.as_ref().expect("package facts");
        assert!(!cargo_library_target_enabled(disabled_package));

        // Cargo profiles decide target_os from the compiled host, so the
        // fixture names the host OS to stay active on every CI platform.
        let host_lib = format!(
            "#[cfg(target_os = \"{}\")]\nmod host;\n",
            std::env::consts::OS
        );
        let (sources, manifests) = inputs_from_files(&[
            FILES[0],
            ("src/lib.rs", host_lib.as_str()),
            ("src/host.rs", "pub fn platform() {}\n"),
        ]);
        let inventory =
            rust_selected_workspace_profiles(&topology_sources(sources.clone()), &manifests)
                .expect("retain an unknown target-cfg route boundary");
        assert!(inventory.target_inventory_complete);
        let profile = inventory
            .profiles
            .iter()
            .find(|profile| profile.target_kind == RustCallerTargetKind::Library && !profile.test)
            .expect("normal library profile");
        let context = build_rust_selected_context(sources, manifests, profile.clone())
            .expect("build context with an unknown target-cfg route");
        assert!(
            !context
                .gaps
                .iter()
                .any(|gap| matches!(gap, RustSelectedContextGap::UnknownActivation { .. })),
            "host target_os is decided for Cargo profiles"
        );
        assert!(
            context
                .target_memberships
                .iter()
                .any(|membership| { membership.file == Path::new("src/host.rs") })
        );
    }

    #[test]
    fn selected_workspace_profiles_cover_bifrost_shaped_manifest_and_every_source() {
        const FILES: &[(&str, &str)] = &[
            (
                "Cargo.toml",
                concat!(
                    "[package]\n",
                    "name = \"app\"\n",
                    "version = \"0.1.0\"\n",
                    "edition = \"2024\"\n",
                    "build = \"tools/build.rs\"\n",
                    "\n",
                    "[features]\n",
                    "default = []\n",
                    "optional-api = []\n",
                    "\n",
                    "[lib]\n",
                    "name = \"app_core\"\n",
                    "crate-type = [\"rlib\", \"cdylib\"]\n",
                    "\n",
                    "[[bin]]\n",
                    "name = \"manual\"\n",
                    "path = \"tools/manual.rs\"\n",
                    "test = false\n",
                    "\n",
                    "[[example]]\n",
                    "name = \"listed\"\n",
                    "\n",
                    "[[test]]\n",
                    "name = \"listed\"\n",
                    "\n",
                    "[[bench]]\n",
                    "name = \"listed\"\n",
                ),
            ),
            ("src/lib.rs", "pub fn library() {}\n"),
            ("src/bin/automatic.rs", "fn main() {}\n"),
            ("tools/manual.rs", "fn main() {}\n"),
            ("tools/build.rs", "fn main() {}\n"),
            ("examples/listed/main.rs", "fn main() {}\n"),
            ("examples/automatic/main.rs", "fn main() {}\n"),
            ("tests/listed/main.rs", "#[test]\nfn listed() {}\n"),
            ("tests/automatic/main.rs", "#[test]\nfn automatic() {}\n"),
            ("benches/listed/main.rs", "fn listed() {}\n"),
            ("benches/automatic/main.rs", "fn automatic() {}\n"),
        ];
        let (sources, manifests) = inputs_from_files(FILES);
        let inventory =
            rust_selected_workspace_profiles(&topology_sources(sources.clone()), &manifests)
                .expect("enumerate a Bifrost-shaped Cargo manifest");

        assert!(inventory.target_inventory_complete);
        let targets = inventory
            .profiles
            .iter()
            .map(|profile| {
                (
                    profile.target_kind,
                    profile.target_root.as_path(),
                    profile.test,
                )
            })
            .collect::<BTreeSet<_>>();
        for expected in [
            (
                RustCallerTargetKind::Library,
                Path::new("src/lib.rs"),
                false,
            ),
            (RustCallerTargetKind::Library, Path::new("src/lib.rs"), true),
            (
                RustCallerTargetKind::Binary,
                Path::new("tools/manual.rs"),
                false,
            ),
            (
                RustCallerTargetKind::Binary,
                Path::new("src/bin/automatic.rs"),
                true,
            ),
            (
                RustCallerTargetKind::Example,
                Path::new("examples/listed/main.rs"),
                false,
            ),
            (
                RustCallerTargetKind::Example,
                Path::new("examples/automatic/main.rs"),
                true,
            ),
            (
                RustCallerTargetKind::Test,
                Path::new("tests/listed/main.rs"),
                true,
            ),
            (
                RustCallerTargetKind::Test,
                Path::new("tests/automatic/main.rs"),
                true,
            ),
            (
                RustCallerTargetKind::Bench,
                Path::new("benches/listed/main.rs"),
                true,
            ),
            (
                RustCallerTargetKind::Bench,
                Path::new("benches/automatic/main.rs"),
                true,
            ),
            (
                RustCallerTargetKind::Build,
                Path::new("tools/build.rs"),
                false,
            ),
        ] {
            assert!(
                targets.contains(&expected),
                "missing target profile {expected:?}"
            );
        }
        assert!(
            !targets.contains(&(
                RustCallerTargetKind::Binary,
                Path::new("tools/manual.rs"),
                true,
            )),
            "an explicit binary with test = false has no test profile"
        );

        let mut owned_sources = BTreeSet::new();
        for profile in &inventory.profiles {
            let context =
                build_rust_selected_context(sources.clone(), manifests.clone(), profile.clone())
                    .expect("build an enumerated selected Cargo profile");
            owned_sources.extend(
                context
                    .target_memberships
                    .iter()
                    .map(|membership| membership.file.clone()),
            );
        }
        let all_sources = sources
            .iter()
            .map(|source| source.relative_path.clone())
            .collect::<BTreeSet<_>>();
        assert_eq!(owned_sources, all_sources);
    }

    #[test]
    #[ignore = "operator-only real Bifrost target inventory proof"]
    fn current_bifrost_package_target_inventory_matches_cargo_and_owns_every_source() {
        let (sources, manifests) = current_bifrost_package_inputs();
        let prepared = prepare_rust_selected_topology_input(
            topology_sources(sources.clone()),
            manifests.clone(),
        )
        .expect("prepare the current Bifrost package topology");
        let inventory = rust_selected_workspace_profiles_from_prepared(&prepared)
            .expect("enumerate the current Bifrost package targets");
        assert!(inventory.target_inventory_complete);

        let roots_by_kind = inventory
            .profiles
            .iter()
            .map(|profile| (profile.target_kind, profile.target_root.clone()))
            .collect::<BTreeSet<_>>();
        let binary_count = roots_by_kind
            .iter()
            .filter(|(kind, _)| *kind == RustCallerTargetKind::Binary)
            .count();
        let integration_test_count = roots_by_kind
            .iter()
            .filter(|(kind, _)| *kind == RustCallerTargetKind::Test)
            .count();
        let test_profile_count = inventory
            .profiles
            .iter()
            .filter(|profile| profile.test)
            .count();
        assert_eq!(binary_count, 7, "current Cargo metadata binary targets");
        assert_eq!(
            integration_test_count, 24,
            "current Cargo metadata integration-test targets",
        );
        assert!(inventory.profiles.iter().any(|profile| {
            profile.target_kind == RustCallerTargetKind::Library && profile.test
        }));

        let mut owned_sources = BTreeSet::new();
        for profile in &inventory.profiles {
            let context =
                build_rust_selected_topology_context_from_prepared(&prepared, profile.clone())
                    .unwrap_or_else(|error| panic!("build {profile:?}: {error}"));
            owned_sources.extend(
                context
                    .target_memberships
                    .iter()
                    .map(|membership| membership.file.clone()),
            );
        }
        let all_sources = sources
            .iter()
            .map(|source| source.relative_path.clone())
            .collect::<BTreeSet<_>>();
        let unowned_sources = all_sources
            .difference(&owned_sources)
            .cloned()
            .collect::<Vec<_>>();
        eprintln!(
            "current Bifrost selected target inventory: complete={}, binaries={binary_count}, integration_tests={integration_test_count}, test_profiles={test_profile_count}, unowned_sources={unowned_sources:?}",
            inventory.target_inventory_complete,
        );
        assert!(unowned_sources.is_empty());
    }

    /// Corrected 2026-09-22 (measured against Cargo 1.96, not read from the
    /// documentation): a package with `edition = "2015"`, an explicit
    /// `[[bin]] path = "src/cli.rs"` and both `src/lib.rs` and `src/main.rs`
    /// present reports `[legacy: lib (lib.rs), legacy-cli: bin (cli.rs)]` under
    /// `cargo metadata --no-deps`. The legacy 2015 rule drops the implicit
    /// binary and leaves the library, so an inherited 2015 edition with a
    /// manual target keeps the implicit library everywhere, and this test now
    /// pins that. It previously pinned the opposite.
    #[test]
    fn inherited_rust_2015_explicit_target_keeps_implicit_library_everywhere() {
        let (sources, manifests) = inputs_from_files(&[
            (
                "Cargo.toml",
                concat!(
                    "[workspace]\n",
                    "members = [\"app\", \"member\"]\n",
                    "\n",
                    "[workspace.package]\n",
                    "edition = \"2015\"\n",
                ),
            ),
            (
                "app/Cargo.toml",
                concat!(
                    "[package]\n",
                    "name = \"app\"\n",
                    "version = \"0.1.0\"\n",
                    "edition.workspace = true\n",
                    "\n",
                    "[lib]\n",
                    "\n",
                    "[dependencies]\n",
                    "member = { path = \"../member\" }\n",
                ),
            ),
            (
                "member/Cargo.toml",
                concat!(
                    "[package]\n",
                    "name = \"member\"\n",
                    "version = \"0.1.0\"\n",
                    "edition.workspace = true\n",
                    "\n",
                    "[[bin]]\n",
                    "name = \"member-tool\"\n",
                    "path = \"src/main.rs\"\n",
                ),
            ),
            ("app/src/lib.rs", "pub fn app() {}\n"),
            ("member/src/lib.rs", "pub fn member_library() {}\n"),
            ("member/src/main.rs", "fn main() {}\n"),
        ]);
        let topology_sources = topology_sources(sources.clone());
        let inventory = rust_selected_workspace_profiles(&topology_sources, &manifests)
            .expect("resolve the inherited Rust 2015 edition");
        assert!(inventory.target_inventory_complete);
        assert!(inventory.profiles.iter().any(|profile| {
            profile.manifest_path == Path::new("member/Cargo.toml")
                && profile.target_kind == RustCallerTargetKind::Binary
        }));
        assert!(
            inventory.profiles.iter().any(|profile| {
                profile.manifest_path == Path::new("member/Cargo.toml")
                    && profile.target_kind == RustCallerTargetKind::Library
            }),
            "the member's src/lib.rs is its library whatever else the manifest declares"
        );

        let app_profile = inventory
            .profiles
            .iter()
            .find(|profile| {
                profile.manifest_path == Path::new("app/Cargo.toml")
                    && profile.target_kind == RustCallerTargetKind::Library
                    && !profile.test
            })
            .expect("the explicitly declared app library profile");
        let app_context =
            build_rust_selected_context(sources, manifests.clone(), app_profile.clone())
                .expect("build the app profile");
        assert!(
            !app_context.dependency_edges.is_empty(),
            "the member's implicit library is a path dependency target of app"
        );

        // `member/src/lib.rs` is the member package's library root, so a caller
        // context selected on it is that library's, not a detached crate root's.
        let RustSelectedLibraryContextOutcome::Ready(member_context) =
            build_rust_selected_library_context_for_caller(
                &topology_sources,
                &manifests,
                Path::new("member/src/lib.rs"),
            )
            .expect("select a caller library context")
        else {
            panic!("the member library root selects its own library context")
        };
        assert_eq!(
            member_context.target_roots,
            BTreeSet::from([PathBuf::from("member/src/lib.rs")])
        );
        assert!(member_context.dependency_edges.is_empty());
    }

    #[test]
    fn selected_workspace_profiles_preserve_cargo_paths_across_nested_manifests() {
        const FILES: &[(&str, &str)] = &[
            (
                "Cargo.toml",
                "[package]\nname = \"outer\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            ),
            ("src/lib.rs", "pub fn outer() {}\n"),
            (
                "examples/member/Cargo.toml",
                "[package]\nname = \"member\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            ),
            ("examples/member/src/lib.rs", "pub fn member() {}\n"),
            ("examples/member/main.rs", "fn main() {}\n"),
        ];
        let (sources, manifests) = inputs_from_files(FILES);
        let inventory = rust_selected_workspace_profiles(&topology_sources(sources), &manifests)
            .expect("enumerate Cargo path targets across a nested manifest");

        assert!(inventory.target_inventory_complete);
        assert_eq!(
            inventory
                .profiles
                .iter()
                .map(|profile| (
                    profile.manifest_path.as_path(),
                    profile.target_kind,
                    profile.target_root.as_path(),
                    profile.test,
                ))
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                (
                    Path::new("Cargo.toml"),
                    RustCallerTargetKind::Example,
                    Path::new("examples/member/main.rs"),
                    false,
                ),
                (
                    Path::new("Cargo.toml"),
                    RustCallerTargetKind::Example,
                    Path::new("examples/member/main.rs"),
                    true,
                ),
                (
                    Path::new("Cargo.toml"),
                    RustCallerTargetKind::Library,
                    Path::new("src/lib.rs"),
                    false,
                ),
                (
                    Path::new("Cargo.toml"),
                    RustCallerTargetKind::Library,
                    Path::new("src/lib.rs"),
                    true,
                ),
                (
                    Path::new("examples/member/Cargo.toml"),
                    RustCallerTargetKind::Library,
                    Path::new("src/lib.rs"),
                    false,
                ),
                (
                    Path::new("examples/member/Cargo.toml"),
                    RustCallerTargetKind::Library,
                    Path::new("src/lib.rs"),
                    true,
                ),
            ]),
        );
    }

    #[test]
    fn selected_workspace_profiles_normalize_library_paths_and_retain_escape_gaps() {
        let (sources, manifests) = inputs_from_files(&[
            (
                "Cargo.toml",
                "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2024\"\n[lib]\npath = \"./src/../src/lib.rs\"\n",
            ),
            ("src/lib.rs", "pub fn library() {}\n"),
        ]);
        let inventory = rust_selected_workspace_profiles(&topology_sources(sources), &manifests)
            .expect("normalize a contained library target path");
        assert!(inventory.target_inventory_complete);
        assert_eq!(inventory.profiles.len(), 2);
        assert!(
            inventory
                .profiles
                .iter()
                .all(|profile| profile.target_root == Path::new("src/lib.rs"))
        );

        let (sources, manifests) = inputs_from_files(&[
            (
                "app/Cargo.toml",
                "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2024\"\n[lib]\npath = \"../shared/src/lib.rs\"\n",
            ),
            ("shared/src/lib.rs", "pub fn shared() {}\n"),
        ]);
        let inventory = rust_selected_workspace_profiles(&topology_sources(sources), &manifests)
            .expect("retain an escaping library target boundary");
        assert!(!inventory.target_inventory_complete);
        assert!(inventory.profiles.is_empty());
    }

    #[test]
    fn module_route_cycles_close_with_a_structured_gap() {
        const FILES: &[(&str, &str)] = &[
            (
                "Cargo.toml",
                "[package]\nname = \"cycle\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            ),
            ("src/lib.rs", "#[path = \"a.rs\"] pub mod a;\n"),
            ("src/a.rs", "#[path = \"b.rs\"] pub mod b;\n"),
            ("src/b.rs", "#[path = \"a.rs\"] pub mod a_again;\n"),
        ];
        let (sources, manifests) = inputs_from_files(FILES);
        let mut profile = same_crate_profile();
        profile.manifest_path = PathBuf::from("Cargo.toml");
        let context = build_rust_selected_context(sources, manifests, profile)
            .expect("close a cyclic path-routed module graph");

        assert_eq!(
            context.reachable_files,
            BTreeSet::from([
                PathBuf::from("src/a.rs"),
                PathBuf::from("src/b.rs"),
                PathBuf::from("src/lib.rs"),
            ])
        );
        assert!(context.gaps.iter().any(|gap| {
            matches!(
                gap,
                RustSelectedContextGap::CyclicModuleRoute {
                    file,
                    start_byte: _
                } if file == Path::new("src/b.rs")
            )
        }));
        assert_eq!(context.target_memberships.len(), 3);
    }

    #[test]
    fn external_module_nested_in_inline_scope_preserves_qualified_route() {
        const FILES: &[(&str, &str)] = &[
            (
                "Cargo.toml",
                "[package]\nname = \"inline-external\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            ),
            (
                "src/lib.rs",
                "mod inline { pub mod leaf; }\nuse crate::inline::leaf::target as imported;\n",
            ),
            ("src/inline/leaf.rs", "pub fn target() {}\n"),
        ];
        let (sources, manifests) = inputs_from_files(FILES);
        let mut profile = same_crate_profile();
        profile.manifest_path = PathBuf::from("Cargo.toml");
        let context = build_rust_selected_context(sources, manifests, profile)
            .expect("build an external module nested in an inline scope");

        assert!(context.target_memberships.iter().any(|membership| {
            membership.file == Path::new("src/inline/leaf.rs")
                && membership.module_segments.as_ref() == ["inline", "leaf"]
        }));
        assert!(context.module_edges.iter().any(|edge| {
            edge.target_file == Path::new("src/inline/leaf.rs")
                && edge.declaring_module_segments.as_ref() == ["inline"]
                && edge.module_segments.as_ref() == ["inline", "leaf"]
        }));
        assert!(context.root_bridges.iter().any(|bridge| {
            bridge.source_name == "imported"
                && bridge.target_file == Path::new("src/inline/leaf.rs")
                && bridge.route.as_ref() == ["crate", "inline", "leaf"]
                && bridge.target_name == "target"
        }));
    }

    #[test]
    fn inline_module_visibility_is_structured_and_parent_cfg_excludes_descendants() {
        const FILES: &[(&str, &str)] = &[
            (
                "Cargo.toml",
                "[package]\nname = \"inline-gates\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            ),
            (
                "src/lib.rs",
                "#[cfg(not(test))] pub mod inactive { pub mod leaf; }\npub(super) mod restricted { pub mod child; }\nmod consumer;\n",
            ),
            ("src/inactive/leaf.rs", "pub fn target() {}\n"),
            ("src/restricted/child.rs", "pub fn target() {}\n"),
            (
                "src/consumer.rs",
                "use crate::restricted::child::target as restricted_target;\n",
            ),
        ];
        let (sources, manifests) = inputs_from_files(FILES);
        let mut profile = same_crate_profile();
        profile.manifest_path = PathBuf::from("Cargo.toml");
        let context = build_rust_selected_context(sources, manifests, profile)
            .expect("build inline visibility and cfg context");

        assert!(
            context
                .reachable_files
                .contains(Path::new("src/restricted/child.rs"))
        );
        assert!(
            !context
                .reachable_files
                .contains(Path::new("src/inactive/leaf.rs"))
        );
        assert!(context.module_edges.iter().any(|edge| {
            edge.module_segments.as_ref() == ["restricted"]
                && edge.visibility == RustVisibility::SuperModule
        }));
        assert!(context.module_edges.iter().any(|edge| {
            edge.module_segments.as_ref() == ["restricted", "child"]
                && edge.visibility == RustVisibility::Public
        }));
        assert!(context.root_routes.iter().any(|route| {
            route.kind == RustSelectedRootRouteKind::Module
                && route.route == "restricted"
                && route.visibility == RustVisibility::SuperModule
        }));
        assert!(context.module_activations.iter().any(|activation| {
            activation.module_name == "inactive"
                && activation.activation == RustSelectedActivation::Inactive
        }));
        assert!(context.module_activations.iter().any(|activation| {
            activation.module_name == "inactive.leaf"
                && activation.activation == RustSelectedActivation::Inactive
        }));
        assert!(
            !context
                .target_memberships
                .iter()
                .any(|membership| membership.module_segments.as_ref() == ["inactive", "leaf"])
        );
    }

    #[test]
    fn a_declared_include_macro_does_not_mount_its_literal_argument() {
        let (sources, manifests) = inputs_from_files(&[
            (
                "Cargo.toml",
                "[package]\nname = \"include-shadow\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            ),
            (
                "src/lib.rs",
                "macro_rules! include { ($p:literal) => {}; } include!(\"missing.rs\");",
            ),
        ]);
        let mut profile = same_crate_profile();
        profile.manifest_path = PathBuf::from("Cargo.toml");
        let context = build_rust_selected_context(sources, manifests, profile)
            .expect("declared include macro");
        assert!(context.include_splices.is_empty());
        assert!(context.gaps.is_empty(), "{:?}", context.gaps);
    }

    #[test]
    fn absent_include_records_an_active_host_scope_gap() {
        let (sources, manifests) = inputs_from_files(&[
            (
                "Cargo.toml",
                "[package]\nname = \"include-gap\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            ),
            (
                "src/lib.rs",
                "pub mod api { include!(\"generated.rs\"); }\n#[cfg(not(test))] mod inactive { include!(\"disabled.rs\"); }\n",
            ),
        ]);
        let mut profile = same_crate_profile();
        profile.manifest_path = PathBuf::from("Cargo.toml");
        let context = build_rust_selected_context(sources, manifests, profile)
            .expect("build context with an absent expansion");

        assert!(context.include_splices.is_empty());
        assert_eq!(
            context.gaps,
            BTreeSet::from([RustSelectedContextGap::UnsupportedMacroGeneratedModule {
                file: PathBuf::from("src/lib.rs"),
                start_byte: 14,
            }])
        );
    }

    #[test]
    fn present_include_preserves_the_host_module_route() {
        let (sources, manifests) = inputs_from_files(&[
            (
                "Cargo.toml",
                "[package]\nname = \"include-present\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            ),
            (
                "src/lib.rs",
                "pub mod api { include!(\"generated.rs\"); }\n",
            ),
            ("src/generated.rs", "pub fn generated() {}\n"),
        ]);
        let mut profile = same_crate_profile();
        profile.manifest_path = PathBuf::from("Cargo.toml");
        let context = build_rust_selected_context(sources, manifests, profile)
            .expect("build context with a present expansion");

        assert!(context.gaps.is_empty(), "{:?}", context.gaps);
        assert_eq!(context.include_splices.len(), 1);
        let splice = &context.include_splices[0];
        assert_eq!(splice.host_file, Path::new("src/lib.rs"));
        assert_eq!(splice.included_file, Path::new("src/generated.rs"));
        assert_eq!(splice.host_module, "api");
        assert!(context.target_memberships.iter().any(|membership| {
            membership.file == Path::new("src/generated.rs")
                && membership.module_segments.as_ref() == ["api"]
        }));
    }

    #[test]
    fn include_cycles_close_with_a_structured_gap() {
        const FILES: &[(&str, &str)] = &[
            (
                "Cargo.toml",
                "[package]\nname = \"include-cycle\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            ),
            ("src/lib.rs", "include!(\"shared.rs\");\n"),
            ("src/shared.rs", "include!(\"lib.rs\");\n"),
        ];
        let (sources, manifests) = inputs_from_files(FILES);
        let mut profile = same_crate_profile();
        profile.manifest_path = PathBuf::from("Cargo.toml");
        let context = build_rust_selected_context(sources, manifests, profile)
            .expect("close a cyclic include graph");

        assert_eq!(
            context.reachable_files,
            BTreeSet::from([PathBuf::from("src/lib.rs"), PathBuf::from("src/shared.rs")])
        );
        assert_eq!(context.include_splices.len(), 1);
        assert!(context.gaps.iter().any(|gap| {
            matches!(
                gap,
                RustSelectedContextGap::CyclicInclude {
                    file,
                    include_start: _
                } if file == Path::new("src/shared.rs")
            )
        }));
    }

    #[test]
    fn shared_include_fan_in_replays_nested_includes_per_host_module() {
        const FILES: &[(&str, &str)] = &[
            (
                "Cargo.toml",
                "[package]\nname = \"include-fan-in\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            ),
            ("src/lib.rs", "pub mod a;\npub mod b;\n"),
            ("src/a.rs", "include!(\"shared.rs\");\n"),
            ("src/b.rs", "include!(\"shared.rs\");\n"),
            ("src/shared.rs", "include!(\"leaf.rs\");\n"),
            ("src/leaf.rs", "pub fn leaf() {}\n"),
        ];
        let (sources, manifests) = inputs_from_files(FILES);
        let mut profile = same_crate_profile();
        profile.manifest_path = PathBuf::from("Cargo.toml");
        let context = build_rust_selected_context(sources, manifests, profile)
            .expect("replay a shared nested include for each host module");

        assert!(
            context.gaps.is_empty(),
            "unexpected gaps: {:?}",
            context.gaps
        );
        assert_eq!(context.reachable_files.len(), 5);
        assert_eq!(context.target_memberships.len(), 7);
        assert_eq!(context.include_splices.len(), 4);
        assert_eq!(
            context
                .include_splices
                .iter()
                .map(|splice| (splice.host_file.as_path(), splice.included_file.as_path()))
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                (Path::new("src/a.rs"), Path::new("src/shared.rs")),
                (Path::new("src/b.rs"), Path::new("src/shared.rs")),
                (Path::new("src/shared.rs"), Path::new("src/leaf.rs")),
            ])
        );
        assert_eq!(
            context
                .include_splices
                .iter()
                .filter(|splice| splice.included_file == Path::new("src/leaf.rs"))
                .count(),
            2
        );
    }

    #[test]
    fn include_inside_inline_module_inherits_the_inline_membership() {
        const FILES: &[(&str, &str)] = &[
            (
                "Cargo.toml",
                "[package]\nname = \"inline-include\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            ),
            (
                "src/lib.rs",
                "pub mod outer { include!(\"shared.rs\"); }\n#[cfg(not(test))] mod inactive { include!(\"disabled.rs\"); }\n",
            ),
            ("src/shared.rs", "include!(\"leaf.rs\");\n"),
            ("src/leaf.rs", "pub fn included_target() {}\n"),
            ("src/disabled.rs", "pub fn disabled_target() {}\n"),
        ];
        let (sources, manifests) = inputs_from_files(FILES);
        let mut profile = same_crate_profile();
        profile.manifest_path = PathBuf::from("Cargo.toml");
        let context = build_rust_selected_context(sources, manifests, profile)
            .expect("build an inline include route");

        assert!(context.reachable_files.contains(Path::new("src/shared.rs")));
        assert!(
            !context
                .reachable_files
                .contains(Path::new("src/disabled.rs"))
        );
        assert!(context.target_memberships.iter().any(|membership| {
            membership.file == Path::new("src/shared.rs")
                && membership.module_segments.as_ref() == ["outer"]
        }));
        assert!(context.target_memberships.iter().any(|membership| {
            membership.file == Path::new("src/leaf.rs")
                && membership.module_segments.as_ref() == ["outer"]
        }));
        assert!(context.include_splices.iter().any(|splice| {
            splice.host_file == Path::new("src/lib.rs")
                && splice.included_file == Path::new("src/shared.rs")
                && splice.host_module == "outer"
        }));
        assert!(context.include_splices.iter().any(|splice| {
            splice.host_file == Path::new("src/shared.rs")
                && splice.included_file == Path::new("src/leaf.rs")
                && splice.host_module == "outer"
        }));
    }

    #[test]
    fn selected_workspace_profile_progress_stops_atomically_and_retries_exactly() {
        const FILES: &[(&str, &str)] = &[
            (
                "Cargo.toml",
                "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            ),
            ("src/lib.rs", "pub fn library() {}\n"),
            ("src/main.rs", "fn main() {}\n"),
            ("tests/service.rs", "#[test]\nfn service() {}\n"),
        ];
        let (sources, manifests) = inputs_from_files(FILES);
        let topology_sources = topology_sources(sources);
        let mut work = 0_usize;
        let RustSelectedBuildOutcome::Ready(expected) =
            rust_selected_workspace_profiles_with_progress(
                &topology_sources,
                &manifests,
                &mut |_| {
                    work += 1;
                    true
                },
            )
            .expect("measure selected workspace profile enumeration")
        else {
            panic!("an always-live measured profile enumeration must complete")
        };
        assert!(work > 1);

        let mut remaining = work - 1;
        let stopped = rust_selected_workspace_profiles_with_progress(
            &topology_sources,
            &manifests,
            &mut |_| {
                if remaining == 0 {
                    false
                } else {
                    remaining -= 1;
                    true
                }
            },
        )
        .expect("stop one unit before workspace profile completion");
        assert_eq!(stopped, RustSelectedBuildOutcome::Stopped);

        assert_eq!(
            rust_selected_workspace_profiles(&topology_sources, &manifests)
                .expect("retry selected workspace profile enumeration"),
            expected,
        );
    }

    #[test]
    fn integration_target_imports_its_same_package_library() {
        const FILES: &[(&str, &str)] = &[
            (
                "Cargo.toml",
                "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            ),
            ("src/lib.rs", "pub mod covered;\n"),
            ("src/covered.rs", "pub fn direct() {}\n"),
            (
                "tests/service.rs",
                "use fixture::covered::direct;\n#[test]\nfn service() { direct(); }\n",
            ),
        ];
        let (sources, manifests) = inputs_from_files(FILES);
        let profile = RustCallerTargetProfile {
            manifest_path: PathBuf::from("Cargo.toml"),
            target_kind: RustCallerTargetKind::Test,
            target_root: PathBuf::from("tests/service.rs"),
            target_triple: "selected-workspace-unspecified".to_string(),
            cfg_atoms: BTreeSet::new(),
            features: BTreeSet::new(),
            test: true,
        };
        let context = build_rust_selected_context(sources, manifests, profile)
            .expect("build integration target context");

        assert_eq!(
            context.dependency_edges.as_ref(),
            [RustSelectedDependencyEdge {
                source_crate_root: PathBuf::from("tests/service.rs"),
                exposed_name: "fixture".to_string(),
                target_crate_root: PathBuf::from("src/lib.rs"),
            }]
        );
        assert!(context.root_bridges.iter().any(|bridge| {
            bridge.source_file == Path::new("tests/service.rs")
                && bridge.target_file == Path::new("src/covered.rs")
                && bridge.route.as_ref() == ["fixture", "covered"]
                && bridge.source_name == "direct"
                && bridge.target_name == "direct"
                && bridge.namespace == ResolutionNamespace::Value
        }));
        assert!(
            context.gaps.is_empty(),
            "unexpected gaps: {:?}",
            context.gaps
        );
    }

    #[test]
    fn external_dependencies_and_standard_crates_remain_explicit_boundaries() {
        let (sources, manifests) = inputs_from_files(&[
            (
                "Cargo.toml",
                concat!(
                    "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
                    "[dependencies]\nserde = \"1\"\n",
                ),
            ),
            (
                "src/lib.rs",
                concat!(
                    "use serde::Serialize;\n",
                    "use std::path::Path;\n",
                    "use core::fmt::Debug;\n",
                    "use alloc::vec::Vec;\n",
                ),
            ),
        ]);
        let mut profile = same_crate_profile();
        profile.manifest_path = PathBuf::from("Cargo.toml");
        let context = build_rust_selected_context(sources, manifests, profile)
            .expect("build external-boundary context");

        assert_eq!(
            context.gaps,
            ["alloc", "core", "serde", "std"]
                .into_iter()
                .map(|exposed_name| RustSelectedContextGap::ExternalDependency {
                    source_crate_root: PathBuf::from("src/lib.rs"),
                    exposed_name: exposed_name.to_string(),
                })
                .collect()
        );
    }

    #[test]
    fn crates_io_patch_redirects_a_dependency_to_selected_source() {
        let (sources, manifests) = inputs_from_files(&[
            (
                "Cargo.toml",
                concat!(
                    "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
                    "[dependencies]\nserde = \"1\"\n",
                    "[patch.crates-io]\nserde = { path = \"patched-serde\" }\n",
                ),
            ),
            (
                "patched-serde/Cargo.toml",
                "[package]\nname = \"serde\"\nversion = \"1.2.0\"\nedition = \"2024\"\n",
            ),
            ("src/lib.rs", "use serde::Serialize;\n"),
            ("patched-serde/src/lib.rs", "pub trait Serialize {}\n"),
        ]);
        let mut profile = same_crate_profile();
        profile.manifest_path = PathBuf::from("Cargo.toml");
        let context = build_rust_selected_context(sources, manifests, profile)
            .expect("build patched-dependency context");

        assert!(
            context
                .dependency_edges
                .contains(&RustSelectedDependencyEdge {
                    source_crate_root: PathBuf::from("src/lib.rs"),
                    exposed_name: "serde".to_string(),
                    target_crate_root: PathBuf::from("patched-serde/src/lib.rs"),
                }),
            "dependency_edges={:?}, gaps={:?}",
            context.dependency_edges,
            context.gaps,
        );
        assert!(!context.gaps.iter().any(|gap| matches!(
            gap,
            RustSelectedContextGap::ExternalDependency { exposed_name, .. }
                if exposed_name == "serde"
        )));
    }

    #[test]
    fn example_normal_profile_admits_development_dependencies() {
        const FILES: &[(&str, &str)] = &[
            (
                "Cargo.toml",
                "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[dev-dependencies]\ndev-helper = { path = \"dev-helper\" }\n",
            ),
            ("src/lib.rs", "pub fn library() {}\n"),
            (
                "examples/demo.rs",
                "use dev_helper::Helper;\nfn main() { let _ = Helper; }\n",
            ),
            (
                "dev-helper/Cargo.toml",
                "[package]\nname = \"dev-helper\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            ),
            ("dev-helper/src/lib.rs", "pub struct Helper;\n"),
        ];
        let (sources, manifests) = inputs_from_files(FILES);
        let profile = RustCallerTargetProfile {
            manifest_path: PathBuf::from("Cargo.toml"),
            target_kind: RustCallerTargetKind::Example,
            target_root: PathBuf::from("examples/demo.rs"),
            target_triple: "selected-workspace-unspecified".to_string(),
            cfg_atoms: BTreeSet::new(),
            features: BTreeSet::new(),
            test: false,
        };
        let context = build_rust_selected_context(sources, manifests, profile)
            .expect("build a normal example target context");

        assert!(
            context
                .dependency_edges
                .contains(&RustSelectedDependencyEdge {
                    source_crate_root: PathBuf::from("examples/demo.rs"),
                    exposed_name: "dev_helper".to_string(),
                    target_crate_root: PathBuf::from("dev-helper/src/lib.rs"),
                })
        );
        assert!(context.root_bridges.iter().any(|bridge| {
            bridge.source_file == Path::new("examples/demo.rs")
                && bridge.target_file == Path::new("dev-helper/src/lib.rs")
                && bridge.source_name == "Helper"
                && bridge.target_name == "Helper"
                && bridge.namespace == ResolutionNamespace::Type
        }));
    }

    #[test]
    fn topology_build_progress_stops_atomically_and_retries_exactly() {
        let (sources, manifests) = same_crate_inputs();
        let topology_sources = topology_sources(sources);
        let mut work = 0_usize;
        let RustSelectedBuildOutcome::Ready(expected) =
            build_rust_selected_topology_context_with_progress(
                topology_sources.clone(),
                manifests.clone(),
                same_crate_profile(),
                &mut |_| {
                    work += 1;
                    true
                },
            )
            .expect("build a measured selected Rust topology")
        else {
            panic!("an always-live measured topology build must complete")
        };
        assert!(work > 1);

        let mut remaining = work - 1;
        let stopped = build_rust_selected_topology_context_with_progress(
            topology_sources.clone(),
            manifests.clone(),
            same_crate_profile(),
            &mut |_| {
                if remaining == 0 {
                    false
                } else {
                    remaining -= 1;
                    true
                }
            },
        )
        .expect("stop one unit before selected Rust topology completion");
        assert_eq!(stopped, RustSelectedBuildOutcome::Stopped);

        let retried =
            build_rust_selected_topology_context(topology_sources, manifests, same_crate_profile())
                .expect("retry the selected Rust topology from fresh inputs");
        assert_eq!(retried, expected);
    }

    #[test]
    fn prepared_topology_input_and_profile_build_stop_atomically() {
        let (sources, manifests) = same_crate_inputs();
        let topology_sources = topology_sources(sources);
        let mut preparation_work = 0_usize;
        let RustSelectedBuildOutcome::Ready(prepared) =
            prepare_rust_selected_topology_input_with_progress(
                topology_sources.clone(),
                manifests.clone(),
                &mut |_| {
                    preparation_work += 1;
                    true
                },
            )
            .expect("prepare a measured selected Rust topology input")
        else {
            panic!("an always-live topology input preparation must complete")
        };
        assert!(preparation_work > 1);

        let mut profile_work = 0_usize;
        let RustSelectedBuildOutcome::Ready(expected) =
            build_rust_selected_topology_context_from_prepared_with_progress(
                &prepared,
                same_crate_profile(),
                &mut |_| {
                    profile_work += 1;
                    true
                },
            )
            .expect("build a measured prepared selected Rust topology")
        else {
            panic!("an always-live prepared topology build must complete")
        };
        assert!(profile_work > 1);

        let mut remaining = profile_work - 1;
        let stopped = build_rust_selected_topology_context_from_prepared_with_progress(
            &prepared,
            same_crate_profile(),
            &mut |_| {
                if remaining == 0 {
                    false
                } else {
                    remaining -= 1;
                    true
                }
            },
        )
        .expect("stop one unit before prepared selected Rust topology completion");
        assert_eq!(stopped, RustSelectedBuildOutcome::Stopped);

        let retried =
            build_rust_selected_topology_context_from_prepared(&prepared, same_crate_profile())
                .expect("retry the prepared selected Rust topology");
        assert_eq!(retried, expected);
    }

    #[test]
    fn prepared_topology_reuses_source_work_across_profile_scale() {
        let (sources, manifests) = same_crate_inputs();
        let topology_sources = topology_sources(sources);
        let prepared = prepare_rust_selected_topology_input(topology_sources, manifests)
            .expect("prepare one immutable selected Rust topology");
        let source_topologies = prepared
            .source_topologies
            .values()
            .next()
            .map(|source| source as *const RustSelectedPreparedSource);
        let source_paths = prepared.source_paths().collect::<Vec<_>>();
        let mut base = same_crate_profile();
        base.target_kind = RustCallerTargetKind::Library;
        base.target_root = PathBuf::from("src/lib.rs");
        let mut total_profile_work = 0_usize;
        for profile in [
            base.clone(),
            RustCallerTargetProfile {
                features: BTreeSet::new(),
                ..base.clone()
            },
            RustCallerTargetProfile {
                test: true,
                ..base.clone()
            },
            RustCallerTargetProfile {
                target_triple: "aarch64-unknown-linux-gnu".to_string(),
                ..base.clone()
            },
        ] {
            let mut profile_work = 0_usize;
            let RustSelectedBuildOutcome::Ready(context) =
                build_rust_selected_topology_context_from_prepared_with_progress(
                    &prepared,
                    profile,
                    &mut |work| {
                        match work {
                            RustSelectedContextWork::PreparationNode => {
                                panic!("a prepared profile must not rebuild source topology")
                            }
                            RustSelectedContextWork::ScopeNode => profile_work += 1,
                        }
                        true
                    },
                )
                .expect("build profile overlay from prepared topology")
            else {
                panic!("an always-live profile overlay must complete")
            };
            assert!(profile_work > 0);
            total_profile_work += profile_work;
            assert_eq!(
                prepared
                    .source_topologies
                    .values()
                    .next()
                    .map(|source| source as *const RustSelectedPreparedSource),
                source_topologies
            );
            assert_eq!(prepared.source_paths().collect::<Vec<_>>(), source_paths);
            assert_eq!(context.root_bridges.as_ref(), &[]);
        }
        assert!(total_profile_work > 1);
    }

    #[test]
    fn many_inline_scopes_and_imports_cancel_and_retry_exactly() {
        const MODULE_COUNT: usize = 12;
        const IMPORTS_PER_MODULE: usize = 4;

        let mut source = String::new();
        for module in 0..MODULE_COUNT {
            writeln!(&mut source, "pub mod module_{module} {{").expect("write module start");
            writeln!(&mut source, "    pub struct Item;").expect("write module item");
            for import in 0..IMPORTS_PER_MODULE {
                let target = (module + import + 1) % MODULE_COUNT;
                writeln!(
                    &mut source,
                    "    use crate::module_{target}::Item as Alias_{module}_{import};"
                )
                .expect("write module import");
            }
            writeln!(&mut source, "}}").expect("write module end");
        }
        let files = [
            (
                "Cargo.toml",
                "[package]\nname = \"many-inline-imports\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            ),
            ("src/lib.rs", source.as_str()),
        ];
        let (sources, manifests) = inputs_from_files(&files);
        let topology_sources = topology_sources(sources);
        let mut profile = same_crate_profile();
        profile.manifest_path = PathBuf::from("Cargo.toml");
        let mut work = 0_usize;
        let RustSelectedBuildOutcome::Ready(expected) =
            build_rust_selected_topology_context_with_progress(
                topology_sources.clone(),
                manifests.clone(),
                profile,
                &mut |_| {
                    work += 1;
                    true
                },
            )
            .expect("build a measured many-scope selected Rust topology")
        else {
            panic!("an always-live measured topology build must complete")
        };
        assert!(work > MODULE_COUNT + MODULE_COUNT * IMPORTS_PER_MODULE);

        let mut profile = same_crate_profile();
        profile.manifest_path = PathBuf::from("Cargo.toml");
        let mut remaining = work - 1;
        let stopped = build_rust_selected_topology_context_with_progress(
            topology_sources.clone(),
            manifests.clone(),
            profile,
            &mut |_| {
                if remaining == 0 {
                    false
                } else {
                    remaining -= 1;
                    true
                }
            },
        )
        .expect("stop a many-scope selected Rust topology one unit before completion");
        assert_eq!(stopped, RustSelectedBuildOutcome::Stopped);

        let mut profile = same_crate_profile();
        profile.manifest_path = PathBuf::from("Cargo.toml");
        let retried = build_rust_selected_topology_context(topology_sources, manifests, profile)
            .expect("retry a many-scope selected Rust topology from fresh inputs");
        assert_eq!(retried, expected);
    }

    #[test]
    fn per_file_membership_index_preserves_context_and_bounds_route_work() {
        const FILE_COUNT: usize = 24;
        let mut root = String::new();
        let mut owned_files = vec![(
            "Cargo.toml".to_string(),
            "[package]\nname = \"membership-index\"\nversion = \"0.1.0\"\nedition = \"2024\"\n"
                .to_string(),
        )];
        for index in 0..FILE_COUNT {
            writeln!(&mut root, "pub mod module_{index};").expect("write root module");
            let next = (index + 1) % FILE_COUNT;
            owned_files.push((
                format!("src/module_{index}.rs"),
                format!(
                    "pub mod inline_{index} {{ pub struct Item; }}\nuse crate::module_{next}::inline_{next}::Item as Alias_{index};\n"
                ),
            ));
        }
        owned_files.push(("src/lib.rs".to_string(), root));
        let files = owned_files
            .iter()
            .map(|(path, source)| (path.as_str(), source.as_str()))
            .collect::<Vec<_>>();
        let (sources, manifests) = inputs_from_files(&files);
        let topology_sources = topology_sources(sources.clone());
        let mut profile = same_crate_profile();
        profile.manifest_path = PathBuf::from("Cargo.toml");
        let mut work = 0_usize;
        let RustSelectedBuildOutcome::Ready(measured) =
            build_rust_selected_topology_context_with_progress(
                topology_sources.clone(),
                manifests.clone(),
                profile.clone(),
                &mut |_| {
                    work += 1;
                    true
                },
            )
            .expect("build indexed membership topology")
        else {
            panic!("an always-live indexed membership topology must complete")
        };
        assert!(
            work < FILE_COUNT * FILE_COUNT * 4,
            "membership route work unexpectedly grew: {work}"
        );

        let expected = build_rust_selected_topology_context(
            topology_sources.clone(),
            manifests.clone(),
            profile.clone(),
        )
        .expect("rebuild indexed membership topology");
        assert_eq!(measured, expected);
        let permuted = build_rust_selected_topology_context(
            topology_sources.into_iter().rev(),
            manifests.into_iter().rev(),
            profile,
        )
        .expect("build indexed membership topology from permuted inputs");
        assert_eq!(expected, permuted);
    }

    #[test]
    fn fixture_builds_exact_context_from_content_facts_and_selected_inventory() {
        let (sources, manifests) = fixture_inputs();
        let context = build_rust_selected_context(sources, manifests, profile(true, false))
            .expect("build selected Rust context");

        assert_eq!(
            context.target_roots,
            BTreeSet::from([
                PathBuf::from("app/src/main.rs"),
                PathBuf::from("engine/src/lib.rs"),
            ])
        );
        assert!(
            context
                .reachable_files
                .contains(Path::new("engine/src/model.rs"))
        );
        assert!(
            context
                .reachable_files
                .contains(Path::new("app/src/included.rs"))
        );
        assert!(
            context
                .reachable_files
                .contains(Path::new("app/src/tests.rs"))
        );
        let selected = context
            .module_activations
            .iter()
            .filter(|module| {
                module.file == Path::new("app/src/main.rs") && module.module_name == "selected"
            })
            .collect::<Vec<_>>();
        assert_eq!(selected.len(), 2);
        assert_eq!(
            selected
                .iter()
                .filter(|module| module.activation == RustSelectedActivation::Active)
                .count(),
            1
        );
        assert_eq!(context.include_splices.len(), 1);
        assert_eq!(
            context.include_splices[0].included_file,
            Path::new("app/src/included.rs")
        );
        assert!(
            context.include_splices[0]
                .host_bindings
                .iter()
                .any(|binding| binding.local_name == "WidgetAlias")
        );
        assert!(context.root_routes.iter().any(|route| {
            route.kind == RustSelectedRootRouteKind::GlobReexport && route.route == "model"
        }));
        assert!(context.root_routes.iter().any(|route| {
            route.kind == RustSelectedRootRouteKind::NamedUse
                && route.local_name.as_deref() == Some("WidgetAlias")
        }));
        assert!(
            context
                .root_routes
                .iter()
                .filter(|route| {
                    matches!(
                        route.kind,
                        RustSelectedRootRouteKind::ExternCrate
                            | RustSelectedRootRouteKind::NamedUse
                            | RustSelectedRootRouteKind::GlobUse
                            | RustSelectedRootRouteKind::NamedReexport
                            | RustSelectedRootRouteKind::GlobReexport
                    )
                })
                .all(|route| route.source_import_ordinal.is_some())
        );
        assert!(
            context
                .root_routes
                .iter()
                .filter(|route| {
                    matches!(
                        route.kind,
                        RustSelectedRootRouteKind::Module
                            | RustSelectedRootRouteKind::ExportedMacro
                    )
                })
                .all(|route| route.source_import_ordinal.is_none())
        );
        assert_eq!(
            context.dependency_edges.as_ref(),
            [RustSelectedDependencyEdge {
                source_crate_root: PathBuf::from("app/src/main.rs"),
                exposed_name: "engine".to_string(),
                target_crate_root: PathBuf::from("engine/src/lib.rs"),
            }]
        );
        let direct_bridges = context
            .root_bridges
            .iter()
            .filter(|bridge| bridge.source_name == "direct_value")
            .collect::<Vec<_>>();
        assert_eq!(direct_bridges.len(), 1);
        assert!(direct_bridges.iter().all(|bridge| {
            bridge.source_file == Path::new("app/src/main.rs")
                && bridge.target_file == Path::new("engine/src/lib.rs")
                && bridge.route.as_ref() == ["engine"]
                && bridge.target_name == "local_macro_value"
                && bridge.namespace == ResolutionNamespace::Value
        }));
        let module_bridges = context
            .root_bridges
            .iter()
            .filter(|bridge| bridge.source_name == "DirectWidget")
            .collect::<Vec<_>>();
        assert_eq!(module_bridges.len(), 1);
        assert!(module_bridges.iter().all(|bridge| {
            bridge.target_file == Path::new("engine/src/model.rs")
                && bridge.route.as_ref() == ["engine", "model"]
                && bridge.target_name == "Widget"
                && bridge.namespace == ResolutionNamespace::Type
        }));
        let reexport_bridges = context
            .root_bridges
            .iter()
            .filter(|bridge| bridge.source_name == "WidgetAlias")
            .collect::<Vec<_>>();
        assert_eq!(reexport_bridges.len(), 1);
        assert!(reexport_bridges.iter().all(|bridge| {
            bridge.target_file == Path::new("engine/src/model.rs")
                && bridge.route.as_ref() == ["engine"]
                && bridge.target_name == "Widget"
                && bridge.namespace == ResolutionNamespace::Type
        }));
        let import_authorities = context
            .root_bridges
            .iter()
            .map(|bridge| RustSelectedRootImportAuthority {
                source_file: bridge.source_file.clone(),
                source_module_segments: context
                    .target_memberships
                    .iter()
                    .find(|membership| membership.file == bridge.source_file)
                    .expect("fixture bridge source has one target membership")
                    .module_segments
                    .clone(),
                source_root_scope: ResolutionScopeId::new(0),
                route: bridge.route.clone(),
                source_import_ordinal: None,
                anchor: ResolutionRootImportAnchor::Lexical,
                source_name: bridge.source_name.clone(),
                target_name: bridge.target_name.clone(),
                namespace: bridge.namespace,
            })
            .collect::<Vec<_>>();
        let export_authorities = context
            .root_bridges
            .iter()
            .map(|bridge| RustSelectedRootExportAuthority {
                target_file: bridge.target_file.clone(),
                target_module_segments: context
                    .file_root_memberships
                    .iter()
                    .find(|membership| membership.file == bridge.target_file)
                    .expect("fixture bridge target has one file-root membership")
                    .module_segments
                    .clone(),
                target_root_scope: bridge.target_root_scope,
                name: bridge.target_name.clone(),
                namespace: bridge.namespace,
                declaration_authority: Some(test_public_declaration_authority()),
            })
            .collect::<Vec<_>>();
        let topology = compile_rust_selected_root_bridge_topology(
            &context,
            import_authorities.clone(),
            export_authorities.clone(),
        );
        let expected_topology = context
            .root_bridges
            .iter()
            .map(|bridge| RustSelectedRootBridgeTopology {
                source_file: bridge.source_file.clone(),
                source_root_scope: ResolutionScopeId::new(0),
                target_file: bridge.target_file.clone(),
                target_root_scope: bridge.target_root_scope,
                route: bridge.route.clone(),
                source_import_ordinal: None,
                anchor: ResolutionRootImportAnchor::Lexical,
                source_name: bridge.source_name.clone(),
                target_name: bridge.target_name.clone(),
                namespace: bridge.namespace,
                declaration_authority: Some(test_public_declaration_authority()),
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(
            topology.into_iter().collect::<BTreeSet<_>>(),
            expected_topology
        );
        let mut bridge_work = 0_usize;
        let measured = compile_rust_selected_root_bridge_topology_with_progress(
            &context,
            import_authorities.clone(),
            export_authorities.clone(),
            &mut |_| {
                bridge_work += 1;
                true
            },
        );
        assert!(matches!(measured, RustSelectedBuildOutcome::Ready(_)));
        assert!(bridge_work > 1);
        let mut remaining = bridge_work - 1;
        let stopped = compile_rust_selected_root_bridge_topology_with_progress(
            &context,
            import_authorities,
            export_authorities,
            &mut |_| {
                if remaining == 0 {
                    false
                } else {
                    remaining -= 1;
                    true
                }
            },
        );
        assert_eq!(stopped, RustSelectedBuildOutcome::Stopped);
        assert!(context.root_routes.iter().any(|route| {
            route.kind == RustSelectedRootRouteKind::ExportedMacro
                && route.route == "exported_value"
        }));
        let engine_macros = context
            .macro_visibility
            .iter()
            .filter(|definition| definition.file == Path::new("engine/src/lib.rs"))
            .collect::<Vec<_>>();
        assert_eq!(engine_macros.len(), 2);
        assert!(engine_macros[0].visible_after < engine_macros[1].visible_after);
        assert!(
            context.gaps.is_empty(),
            "unexpected gaps: {:?}",
            context.gaps
        );
    }

    #[test]
    fn caller_profile_identity_is_stable_across_a_b_a_and_gates_tests() {
        let (sources, manifests) = fixture_inputs();
        let left =
            build_rust_selected_context(sources.clone(), manifests.clone(), profile(true, false))
                .expect("build left profile");
        let right_test =
            build_rust_selected_context(sources.clone(), manifests.clone(), profile(false, true))
                .expect("build right test profile");
        let left_again = build_rust_selected_context(sources, manifests, profile(true, false))
            .expect("rebuild left profile");

        assert_eq!(left.identity, left_again.identity);
        assert_eq!(left, left_again);
        assert_ne!(left.identity, right_test.identity);
        assert!(
            right_test
                .reachable_files
                .contains(Path::new("app/src/tests.rs"))
        );
        let unknown_right = right_test
            .module_activations
            .iter()
            .filter(|module| {
                module.file == Path::new("app/src/main.rs")
                    && module.module_name == "selected"
                    && module.activation == RustSelectedActivation::Unknown
            })
            .collect::<Vec<_>>();
        assert_eq!(unknown_right.len(), 2);
        for module in unknown_right {
            assert!(
                right_test
                    .gaps
                    .contains(&RustSelectedContextGap::UnknownActivation {
                        file: module.file.clone(),
                        start_byte: module.start_byte,
                    },)
            );
        }
    }

    #[test]
    fn prepared_topology_matches_owning_profiles_and_input_permutations() {
        let (sources, manifests) = fixture_inputs();
        let topology_sources = topology_sources(sources);
        let prepared =
            prepare_rust_selected_topology_input(topology_sources.clone(), manifests.clone())
                .expect("prepare selected Rust topology input");
        let permuted = prepare_rust_selected_topology_input(
            topology_sources.iter().cloned().rev(),
            manifests.iter().cloned().rev(),
        )
        .expect("prepare permuted selected Rust topology input");

        for profile in [profile(true, false), profile(false, true)] {
            let owning = build_rust_selected_topology_context(
                topology_sources.clone(),
                manifests.clone(),
                profile.clone(),
            )
            .expect("build owning selected Rust topology");
            let expected =
                build_rust_selected_topology_context_from_prepared(&prepared, profile.clone())
                    .expect("build prepared selected Rust topology");
            let permuted_context =
                build_rust_selected_topology_context_from_prepared(&permuted, profile)
                    .expect("build permuted prepared selected Rust topology");
            assert_eq!(owning, expected);
            assert_eq!(expected, permuted_context);
        }
    }

    #[test]
    fn unknown_cfg_is_incomplete_instead_of_inactive() {
        let (mut sources, manifests) = fixture_inputs();
        let main = sources
            .iter_mut()
            .find(|mount| mount.relative_path == Path::new("app/src/main.rs"))
            .expect("app main mount");
        let selected = main
            .facts
            .modules
            .iter_mut()
            .find(|module| module.module_name == "selected")
            .expect("selected module");
        selected.cfg_condition = RustCfgCondition::Unknown;
        let selected_start = selected.start_byte;

        let context = build_rust_selected_context(sources, manifests, profile(true, false))
            .expect("build incomplete selected context");
        assert!(
            context
                .gaps
                .contains(&RustSelectedContextGap::UnknownActivation {
                    file: PathBuf::from("app/src/main.rs"),
                    start_byte: selected_start,
                })
        );
    }

    #[test]
    fn feature_gated_module_is_owned_with_a_route_local_activation_gap() {
        let (sources, manifests) = inputs_from_files(&[
            (
                "Cargo.toml",
                concat!(
                    "[package]\n",
                    "name = \"app\"\n",
                    "version = \"0.1.0\"\n",
                    "edition = \"2024\"\n",
                    "\n",
                    "[features]\n",
                    "gated = []\n",
                ),
            ),
            (
                "src/lib.rs",
                "#[cfg(feature = \"gated\")]\nmod gated;\nmod always;\n",
            ),
            ("src/gated.rs", "pub fn gated() {}\n"),
            ("src/always.rs", "pub fn always() {}\n"),
        ]);
        let gated_start = sources
            .iter()
            .find(|source| source.relative_path == Path::new("src/lib.rs"))
            .expect("library source facts")
            .facts
            .module_routes
            .routes
            .iter()
            .find(|route| route.module_name == "gated")
            .expect("feature-gated module route")
            .declaration_start;
        let inventory =
            rust_selected_workspace_profiles(&topology_sources(sources.clone()), &manifests)
                .expect("feature declarations do not make target enumeration incomplete");
        assert!(inventory.target_inventory_complete);
        let profile = inventory
            .profiles
            .iter()
            .find(|profile| profile.target_kind == RustCallerTargetKind::Library && !profile.test)
            .expect("normal library profile");
        let context = build_rust_selected_context(sources, manifests, profile.clone())
            .expect("build a feature-uncertain target context");

        assert_eq!(
            context.gaps,
            BTreeSet::from([RustSelectedContextGap::UnknownActivation {
                file: PathBuf::from("src/lib.rs"),
                start_byte: gated_start,
            }]),
        );
        for target in [Path::new("src/gated.rs"), Path::new("src/always.rs")] {
            assert!(
                context
                    .target_memberships
                    .iter()
                    .any(|membership| membership.file == target),
                "possible module route must retain ownership for {target:?}",
            );
            assert!(
                context
                    .module_edges
                    .iter()
                    .any(|edge| edge.target_file == target),
                "possible module route must retain its structured edge for {target:?}",
            );
        }
    }

    #[test]
    fn selected_inventory_not_live_existence_decides_module_and_include_reachability() {
        let (mut sources, manifests) = fixture_inputs();
        sources.retain(|mount| {
            mount.relative_path != Path::new("engine/src/model.rs")
                && mount.relative_path != Path::new("app/src/included.rs")
        });

        let context = build_rust_selected_context(sources, manifests, profile(true, false))
            .expect("build inventory-limited context");
        assert!(
            !context
                .reachable_files
                .contains(Path::new("engine/src/model.rs"))
        );
        assert!(
            !context
                .reachable_files
                .contains(Path::new("app/src/included.rs"))
        );
        assert!(
            context
                .module_edges
                .iter()
                .all(|edge| { edge.target_file != Path::new("engine/src/model.rs") })
        );
        assert!(context.include_splices.is_empty());
        assert!(context.gaps.iter().any(|gap| matches!(
            gap,
            RustSelectedContextGap::UnsupportedMacroGeneratedModule { file, .. }
                if file == Path::new("app/src/main.rs")
        )));
    }

    #[test]
    fn dependency_module_bridge_requires_every_crossed_module_to_be_public() {
        let (mut sources, manifests) = fixture_inputs();
        let engine = sources
            .iter_mut()
            .find(|mount| mount.relative_path == Path::new("engine/src/lib.rs"))
            .expect("engine root mount");
        let model = engine
            .facts
            .module_routes
            .routes
            .iter_mut()
            .find(|route| route.module_name == "model")
            .expect("engine model route");
        model.visibility = RustVisibility::Private;

        let context = build_rust_selected_context(sources, manifests, profile(true, false))
            .expect("build selected context with private dependency module");
        assert!(
            context
                .root_bridges
                .iter()
                .all(|bridge| bridge.source_name != "DirectWidget")
        );
        assert!(context.root_bridges.iter().any(|bridge| {
            bridge.source_name == "direct_value"
                && bridge.target_file == Path::new("engine/src/lib.rs")
        }));
        assert!(context.root_bridges.iter().any(|bridge| {
            bridge.source_name == "WidgetAlias"
                && bridge.target_file == Path::new("engine/src/model.rs")
                && bridge.namespace == ResolutionNamespace::Type
        }));
    }

    #[test]
    fn named_reexport_chains_forward_to_the_exported_declaration() {
        const FILES: &[(&str, &str)] = &[
            (
                "app/Cargo.toml",
                concat!(
                    "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
                    "[dependencies]\nengine = { path = \"../engine\" }\n",
                ),
            ),
            (
                "engine/Cargo.toml",
                "[package]\nname = \"engine\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            ),
            ("app/src/main.rs", "use engine::PublicItem as Item;\n"),
            (
                "engine/src/lib.rs",
                "mod first;\nmod second;\npub use first::FirstItem as PublicItem;\n",
            ),
            (
                "engine/src/first.rs",
                "pub use crate::second::Item as FirstItem;\n",
            ),
            (
                "engine/src/second.rs",
                "pub struct Item { pub value: () }\n",
            ),
        ];
        let (sources, manifests) = inputs_from_files(FILES);
        let context = build_rust_selected_context(sources, manifests, profile(false, false))
            .expect("build chained named-reexport context");
        let bridges = context
            .root_bridges
            .iter()
            .filter(|bridge| bridge.source_name == "Item")
            .collect::<Vec<_>>();
        assert_eq!(bridges.len(), 1);
        assert!(bridges.iter().all(|bridge| {
            bridge.target_file == Path::new("engine/src/second.rs")
                && bridge.target_name == "Item"
                && bridge.namespace == ResolutionNamespace::Type
        }));
    }

    #[test]
    fn named_reexport_cycles_fail_closed() {
        const FILES: &[(&str, &str)] = &[
            (
                "app/Cargo.toml",
                concat!(
                    "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
                    "[dependencies]\nengine = { path = \"../engine\" }\n",
                ),
            ),
            (
                "engine/Cargo.toml",
                "[package]\nname = \"engine\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            ),
            ("app/src/main.rs", "use engine::PublicItem as Item;\n"),
            (
                "engine/src/lib.rs",
                "mod left;\nmod right;\npub use left::Item as PublicItem;\n",
            ),
            ("engine/src/left.rs", "pub use crate::right::Item;\n"),
            ("engine/src/right.rs", "pub use crate::left::Item;\n"),
        ];
        let (sources, manifests) = inputs_from_files(FILES);
        let context = build_rust_selected_context(sources, manifests, profile(false, false))
            .expect("build cyclic named-reexport context");
        assert!(context.root_bridges.is_empty());
    }

    #[test]
    fn consumer_and_reexport_globs_forward_a_demand_through_a_private_module() {
        const FILES: &[(&str, &str)] = &[
            (
                "app/Cargo.toml",
                concat!(
                    "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
                    "[dependencies]\nengine = { path = \"../engine\" }\n",
                ),
            ),
            (
                "engine/Cargo.toml",
                "[package]\nname = \"engine\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            ),
            (
                "app/src/main.rs",
                "use engine::*;\nfn caller(_: Item) { imported(); imported_macro!(); }\n",
            ),
            ("engine/src/lib.rs", "mod r#hidden;\npub use r#hidden::*;\n"),
            (
                "engine/src/hidden.rs",
                "pub struct Item;\npub fn imported() {}\n#[macro_export]\nmacro_rules! imported_macro { () => {}; }\n",
            ),
        ];
        let (sources, manifests) = inputs_from_files(FILES);
        let context = build_rust_selected_context(sources, manifests, profile(false, false))
            .expect("build glob-reexport context");
        assert!(context.root_routes.iter().any(|route| {
            route.kind == RustSelectedRootRouteKind::GlobReexport
                && route.route_segments.as_deref() == Some(&["hidden".to_string()][..])
        }));
        let bridges = context.root_bridges.iter().collect::<Vec<_>>();
        assert_eq!(bridges.len(), 3);
        assert!(bridges.iter().all(|bridge| {
            bridge.target_file == Path::new("engine/src/hidden.rs")
                && bridge.source_name == bridge.target_name
        }));
        assert!(bridges.iter().any(|bridge| {
            bridge.target_name == "Item" && bridge.namespace == ResolutionNamespace::Type
        }));
        assert!(bridges.iter().any(|bridge| {
            bridge.target_name == "imported" && bridge.namespace == ResolutionNamespace::Value
        }));
        assert!(bridges.iter().any(|bridge| {
            bridge.target_name == "imported_macro" && bridge.namespace == ResolutionNamespace::Macro
        }));
    }

    #[test]
    fn rust_2015_dependency_needs_an_explicit_extern_crate_route() {
        let (sources, mut manifests) = fixture_inputs();
        manifests
            .iter_mut()
            .find(|mount| mount.relative_path == Path::new("app/Cargo.toml"))
            .and_then(|mount| mount.facts.package.as_mut())
            .expect("app package facts")
            .edition = RustCargoPackageEdition::Explicit(RustCargoEdition::Rust2015);

        let context = build_rust_selected_context(sources, manifests, profile(true, false))
            .expect("build Rust 2015 dependency context");
        assert!(context.root_bridges.is_empty());
    }

    #[test]
    fn aliased_extern_crate_selects_the_path_dependency_in_each_edition() {
        const FILES: &[(&str, &str)] = &[
            (
                "app/Cargo.toml",
                concat!(
                    "[package]\nname = \"app\"\nversion = \"0.1.0\"\n",
                    "[dependencies]\nengine = { path = \"../engine\" }\n",
                ),
            ),
            (
                "engine/Cargo.toml",
                "[package]\nname = \"engine\"\nversion = \"0.1.0\"\n",
            ),
            (
                "app/src/lib.rs",
                "extern crate engine as dependency;\nuse dependency::Item as Imported;\n",
            ),
            ("engine/src/lib.rs", "pub struct Item { pub value: () }\n"),
        ];
        let (sources, manifests) = inputs_from_files(FILES);
        for edition in [RustCargoEdition::Rust2015, RustCargoEdition::Rust2024] {
            let mut manifests = manifests.clone();
            manifests
                .iter_mut()
                .find(|manifest| manifest.relative_path == Path::new("app/Cargo.toml"))
                .and_then(|manifest| manifest.facts.package.as_mut())
                .expect("app package facts")
                .edition = RustCargoPackageEdition::Explicit(edition);
            let context =
                build_rust_selected_context(sources.clone(), manifests, same_crate_profile())
                    .expect("build extern-crate context");
            assert!(context.root_routes.iter().any(|route| {
                route.kind == RustSelectedRootRouteKind::ExternCrate
                    && route.local_name.as_deref() == Some("dependency")
                    && route.target_name.as_deref() == Some("engine")
            }));
            let bridges = context
                .root_bridges
                .iter()
                .filter(|bridge| bridge.source_name == "Imported")
                .collect::<Vec<_>>();
            assert_eq!(bridges.len(), 1);
            assert!(bridges.iter().all(|bridge| {
                bridge.target_file == Path::new("engine/src/lib.rs")
                    && bridge.target_name == "Item"
                    && bridge.namespace == ResolutionNamespace::Type
            }));
        }
    }

    #[test]
    fn same_crate_routes_honor_structured_anchors_and_module_visibility() {
        let (sources, manifests) = same_crate_inputs();
        let context =
            build_rust_selected_context(sources.clone(), manifests.clone(), same_crate_profile())
                .expect("build same-crate selected context");

        for (source_name, route, target_file) in [
            (
                "CrateItem",
                &["crate", "parent", "child"][..],
                "app/src/parent/child.rs",
            ),
            (
                "SuperItem",
                &["super", "parent", "child"][..],
                "app/src/parent/child.rs",
            ),
            ("SelfItem", &["self", "own"][..], "app/src/outsider/own.rs"),
            (
                "SelfPublicItem",
                &["self", "own"][..],
                "app/src/outsider/own.rs",
            ),
            ("RelativeItem", &["own"][..], "app/src/outsider/own.rs"),
        ] {
            let bridges = context
                .root_bridges
                .iter()
                .filter(|bridge| bridge.source_name == source_name)
                .collect::<Vec<_>>();
            assert_eq!(bridges.len(), 1, "bridges for {source_name}");
            assert!(bridges.iter().all(|bridge| {
                bridge.source_file == Path::new("app/src/outsider.rs")
                    && bridge.target_file == Path::new(target_file)
                    && bridge.namespace == ResolutionNamespace::Type
                    && bridge
                        .route
                        .iter()
                        .map(String::as_str)
                        .eq(route.iter().copied())
            }));
        }

        let mut private_sources = sources;
        let parent = private_sources
            .iter_mut()
            .find(|mount| mount.relative_path == Path::new("app/src/parent.rs"))
            .expect("parent source mount");
        parent
            .facts
            .module_routes
            .routes
            .iter_mut()
            .find(|route| route.module_name == "child")
            .expect("child module route")
            .visibility = RustVisibility::Private;
        let private_context =
            build_rust_selected_context(private_sources, manifests, same_crate_profile())
                .expect("build context with sibling-private child module");
        assert!(
            private_context.root_bridges.iter().all(|bridge| {
                !matches!(bridge.source_name.as_str(), "CrateItem" | "SuperItem")
            })
        );
        assert!(
            private_context
                .root_bridges
                .iter()
                .any(|bridge| bridge.source_name == "SelfItem")
        );
        assert!(
            private_context
                .root_bridges
                .iter()
                .any(|bridge| bridge.source_name == "RelativeItem")
        );
    }

    #[test]
    fn restricted_visibility_scopes_are_resolved_from_structured_segments() {
        let declaring = ["parent".to_string(), "nested".to_string()];
        let descendant = [
            "parent".to_string(),
            "nested".to_string(),
            "consumer".to_string(),
        ];
        let sibling = ["parent".to_string(), "sibling".to_string()];
        assert!(rust_module_visibility_reaches(
            &RustVisibility::SelfModule,
            true,
            &descendant,
            &declaring,
        ));
        assert!(!rust_module_visibility_reaches(
            &RustVisibility::Private,
            true,
            &sibling,
            &declaring,
        ));
        assert!(rust_module_visibility_reaches(
            &RustVisibility::SuperModule,
            true,
            &sibling,
            &declaring,
        ));
        assert!(rust_module_visibility_reaches(
            &RustVisibility::InPath(vec!["crate".to_string(), "parent".to_string()]),
            true,
            &sibling,
            &declaring,
        ));
        assert!(!rust_module_visibility_reaches(
            &RustVisibility::Crate,
            false,
            &sibling,
            &declaring,
        ));
    }

    #[test]
    fn rust_2015_unprefixed_use_starts_at_the_selected_crate_root() {
        const FILES: &[(&str, &str)] = &[
            (
                "app/Cargo.toml",
                "[package]\nname = \"app\"\nversion = \"0.1.0\"\n",
            ),
            ("app/src/lib.rs", "mod root_item;\nmod consumer;\n"),
            (
                "app/src/root_item.rs",
                "pub struct Item { pub value: () }\n",
            ),
            ("app/src/consumer.rs", "use root_item::Item as RootItem;\n"),
        ];
        let (sources, manifests) = inputs_from_files(FILES);
        let context = build_rust_selected_context(sources, manifests, same_crate_profile())
            .expect("build Rust 2015 selected context");
        let bridges = context
            .root_bridges
            .iter()
            .filter(|bridge| bridge.source_name == "RootItem")
            .collect::<Vec<_>>();
        assert_eq!(bridges.len(), 1);
        assert!(bridges.iter().all(|bridge| {
            bridge.source_file == Path::new("app/src/consumer.rs")
                && bridge.target_file == Path::new("app/src/root_item.rs")
                && bridge.route.as_ref() == ["root_item"]
                && bridge.namespace == ResolutionNamespace::Type
        }));
    }

    #[test]
    fn modern_local_module_shadows_a_same_named_dependency() {
        const FILES: &[(&str, &str)] = &[
            (
                "app/Cargo.toml",
                concat!(
                    "[package]\nname = \"app\"\nversion = \"0.1.0\"\n",
                    "edition = \"2024\"\n",
                    "[dependencies]\nengine = { path = \"../engine\" }\n",
                ),
            ),
            (
                "engine/Cargo.toml",
                "[package]\nname = \"engine\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            ),
            (
                "app/src/lib.rs",
                "mod engine;\nuse engine::Item as SelectedItem;\n",
            ),
            ("app/src/engine.rs", "pub struct Item { pub value: () }\n"),
            ("engine/src/lib.rs", "pub struct Item { pub value: () }\n"),
        ];
        let (sources, manifests) = inputs_from_files(FILES);
        let context = build_rust_selected_context(sources, manifests, same_crate_profile())
            .expect("build local-shadow selected context");
        let bridges = context
            .root_bridges
            .iter()
            .filter(|bridge| bridge.source_name == "SelectedItem")
            .collect::<Vec<_>>();
        assert_eq!(bridges.len(), 1);
        assert!(bridges.iter().all(|bridge| {
            bridge.target_file == Path::new("app/src/engine.rs")
                && bridge.namespace == ResolutionNamespace::Type
        }));
    }

    #[test]
    fn modern_absolute_route_bypasses_a_same_named_local_module() {
        const FILES: &[(&str, &str)] = &[
            (
                "app/Cargo.toml",
                concat!(
                    "[package]\nname = \"app\"\nversion = \"0.1.0\"\n",
                    "edition = \"2024\"\n",
                    "[dependencies]\nengine = { path = \"../engine\" }\n",
                ),
            ),
            (
                "engine/Cargo.toml",
                "[package]\nname = \"engine\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            ),
            (
                "app/src/lib.rs",
                "mod engine;\nuse ::engine::Item as ExternalItem;\n",
            ),
            ("app/src/engine.rs", "pub struct Item;\n"),
            ("engine/src/lib.rs", "pub struct Item;\n"),
        ];
        let (sources, manifests) = inputs_from_files(FILES);
        let context = build_rust_selected_topology_context(
            topology_sources(sources),
            manifests,
            same_crate_profile(),
        )
        .expect("build modern absolute selected context");
        assert!(context.root_routes.iter().any(|route| {
            route.route == "engine"
                && route.anchor == ResolutionRootImportAnchor::Absolute
                && route.local_name.as_deref() == Some("ExternalItem")
        }));
        let source = context
            .target_memberships
            .iter()
            .find(|membership| {
                membership.crate_root == Path::new("app/src/lib.rs")
                    && membership.file == Path::new("app/src/lib.rs")
                    && membership.module_segments.is_empty()
            })
            .expect("app crate root membership");
        let imports = BTreeSet::new();
        let exports = BTreeSet::new();
        let mut progress = |_| true;
        let absolute = selected_topology_import_targets(
            &context,
            source,
            &imports,
            &exports,
            &["engine"],
            ResolutionRootImportAnchor::Absolute,
            &mut progress,
        );
        assert_eq!(
            absolute,
            RustSelectedBuildOutcome::Ready(vec![RustSelectedImportTarget {
                crate_root: PathBuf::from("engine/src/lib.rs"),
                module_segments: Box::new([]),
            }])
        );
        let bare = selected_topology_import_targets(
            &context,
            source,
            &imports,
            &exports,
            &["engine"],
            ResolutionRootImportAnchor::Lexical,
            &mut progress,
        );
        assert_eq!(
            bare,
            RustSelectedBuildOutcome::Ready(vec![RustSelectedImportTarget {
                crate_root: PathBuf::from("app/src/lib.rs"),
                module_segments: vec!["engine".to_string()].into_boxed_slice(),
            }])
        );
    }

    #[test]
    fn rust_2015_absolute_route_starts_at_the_selected_crate_root() {
        const FILES: &[(&str, &str)] = &[
            (
                "app/Cargo.toml",
                "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2015\"\n",
            ),
            (
                "app/src/lib.rs",
                "mod root_model;\nuse ::root_model::Item as AbsoluteItem;\n",
            ),
            ("app/src/root_model.rs", "pub struct Item;\n"),
        ];
        let (sources, manifests) = inputs_from_files(FILES);
        let context = build_rust_selected_topology_context(
            topology_sources(sources),
            manifests,
            same_crate_profile(),
        )
        .expect("build Rust 2015 absolute selected context");
        assert!(context.root_routes.iter().any(|route| {
            route.route == "root_model"
                && route.anchor == ResolutionRootImportAnchor::Absolute
                && route.local_name.as_deref() == Some("AbsoluteItem")
        }));
        let source = context
            .target_memberships
            .iter()
            .find(|membership| {
                membership.crate_root == Path::new("app/src/lib.rs")
                    && membership.file == Path::new("app/src/lib.rs")
                    && membership.module_segments.is_empty()
            })
            .expect("consumer crate-root membership");
        let imports = BTreeSet::new();
        let exports = BTreeSet::new();
        let mut progress = |_| true;
        let absolute = selected_topology_import_targets(
            &context,
            source,
            &imports,
            &exports,
            &["root_model"],
            ResolutionRootImportAnchor::Absolute,
            &mut progress,
        );
        assert_eq!(
            absolute,
            RustSelectedBuildOutcome::Ready(vec![RustSelectedImportTarget {
                crate_root: PathBuf::from("app/src/lib.rs"),
                module_segments: vec!["root_model".to_string()].into_boxed_slice(),
            }])
        );
    }

    #[test]
    fn transient_manifest_bytes_change_identity_without_a_manifest_read() {
        let (sources, mut manifests) = fixture_inputs();
        let clean =
            build_rust_selected_context(sources.clone(), manifests.clone(), profile(true, false))
                .expect("build clean context");
        let dirty_source = M6A_RUST_WORKSPACE_FILES
            .iter()
            .find(|(path, _)| *path == "app/Cargo.toml")
            .map(|(_, source)| format!("{source}\n# transient overlay\n"))
            .expect("app manifest fixture");
        let dirty = RustSelectedManifestMount::from_source("app/Cargo.toml", &dirty_source)
            .expect("parse transient manifest facts");
        *manifests
            .iter_mut()
            .find(|mount| mount.relative_path == Path::new("app/Cargo.toml"))
            .expect("app manifest mount") = dirty;

        let transient = build_rust_selected_context(sources, manifests, profile(true, false))
            .expect("build transient context");
        assert_ne!(clean.identity, transient.identity);
        assert_eq!(clean.target_roots, transient.target_roots);
        assert_eq!(clean.module_edges, transient.module_edges);
    }

    #[test]
    fn every_selected_manifest_must_use_the_current_fact_version() {
        let (sources, mut manifests) = fixture_inputs();
        let stale = manifests
            .iter_mut()
            .find(|manifest| manifest.relative_path == Path::new("engine/Cargo.toml"))
            .expect("engine manifest mount");
        stale.facts.version = RUST_CARGO_MANIFEST_FACT_VERSION - 1;

        let error = build_rust_selected_context(sources, manifests, profile(true, false))
            .expect_err("stale dependency manifest facts must fail context construction");
        assert!(error.contains("engine/Cargo.toml"), "{error}");
    }
}
