//! Cargo configuration files, as Rust analysis reads them (#3768).
//!
//! Cargo merges ancestor configuration with deeper values taking precedence,
//! arrays concatenating, and the legacy `config` winning over `config.toml`.
//! This module interprets caller-supplied parsed inputs; it never opens files.
//! The caller must establish acquisition completeness before this reader can
//! certify dependency source identity or prebuilt stdlib mode. A project-only
//! snapshot is partial if applicable ancestors, Cargo home or includes were not
//! acquired. The user's build-process overrides remain outside this files-only
//! contract; the analyzer's environment is not that build's environment.
//!
//! Configured targets, cfg flags, source identity and stdlib build mode share
//! this reader and its closed key classification. Unknown settings fail closed.
//!
//! All state belongs to the request that built it.

pub mod acquired;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use brokk_bifrost_core::hash::HashMap;
use cfg_expr::targets::{Endian, TargetInfo, get_builtin_target_by_triple};
use cfg_expr::{Expression, Predicate, TargetPredicate};

/// The target triple bifrost is compiled for, which is the host a build that
/// names no target compiles for.
const HOST_TRIPLE: &str = env!("BROKK_BIFROST_RUST_HOST_TRIPLE");

/// Whether `path` is a Cargo configuration file: `config.toml` or the legacy
/// `config` directly inside a `.cargo` directory.
pub fn is_cargo_configuration_path(path: &Path) -> bool {
    path.parent()
        .and_then(Path::file_name)
        .is_some_and(|directory| directory == ".cargo")
        && path
            .file_name()
            .is_some_and(|name| name == "config.toml" || name == "config")
}

/// Whether the acquired Cargo settings establish use of prebuilt standard libraries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RustStdlibBuildMode {
    Prebuilt,
    BuildStd,
    Unknown,
}

/// Closed classification of configuration's effect on dependency source identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RustCargoConfigSourceEffect {
    Preserves,
    Changes,
    Unknown,
}

/// One include declared by a parsed Cargo config. Acquisition resolves its
/// path under the caller's containment policy before supplying its document.
#[derive(Clone, PartialEq, Eq)]
pub struct RustCargoConfigInclude {
    pub path: PathBuf,
    pub optional: bool,
}

impl std::fmt::Debug for RustCargoConfigInclude {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RustCargoConfigInclude")
            .field("optional", &self.optional)
            .finish_non_exhaustive()
    }
}

/// One parsed Cargo configuration file.
#[derive(Clone)]
pub struct RustCargoConfigDocument {
    value: toml::Table,
    included: Vec<(PathBuf, RustCargoConfigDocument)>,
    includes_resolved: bool,
    workspace_paths: bool,
}

// Configuration can contain tokens and proxy credentials. Even diagnostic
// Debug formatting must not expose parsed values or content.
impl std::fmt::Debug for RustCargoConfigDocument {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RustCargoConfigDocument")
            .finish_non_exhaustive()
    }
}

impl RustCargoConfigDocument {
    pub fn from_source_bytes(source: &[u8]) -> Result<Self, String> {
        let source = std::str::from_utf8(source)
            .map_err(|error| format!("Cargo configuration is not UTF-8: {error}"))?;
        let value = toml::from_str(source).map_err(|_| "invalid Cargo configuration".to_owned())?;
        let mut document = Self {
            value,
            included: Vec::new(),
            includes_resolved: false,
            workspace_paths: true,
        };
        document.includes_resolved = document
            .include_specs()
            .is_ok_and(|includes| includes.is_empty());
        Ok(document)
    }

    /// Decode include syntax once, shared by acquisition and classification.
    /// Errors contain no configured path, value or source text.
    pub fn include_specs(&self) -> Result<Vec<RustCargoConfigInclude>, String> {
        let Some(value) = self.value.get("include") else {
            return Ok(Vec::new());
        };
        let error = || "unclassifiable Cargo config include".to_owned();
        let item = |value: &toml::Value| -> Result<RustCargoConfigInclude, String> {
            if let Some(path) = value.as_str() {
                return Ok(RustCargoConfigInclude {
                    path: path.into(),
                    optional: false,
                });
            }
            let table = value.as_table().ok_or_else(error)?;
            if table
                .keys()
                .any(|key| !matches!(key.as_str(), "path" | "optional"))
            {
                return Err(error());
            }
            let path = table
                .get("path")
                .and_then(toml::Value::as_str)
                .ok_or_else(error)?;
            let optional = match table.get("optional") {
                None => false,
                Some(value) => value.as_bool().ok_or_else(error)?,
            };
            Ok(RustCargoConfigInclude {
                path: path.into(),
                optional,
            })
        };
        if value.is_str() {
            return Ok(vec![item(value)?]);
        }
        value
            .as_array()
            .ok_or_else(error)?
            .iter()
            .map(item)
            .collect()
    }

    /// Supply acquired includes in declaration order. Each base is the
    /// workspace-relative directory for that document's relative path values.
    /// Missing documents are accepted only for explicitly optional includes.
    /// Included layers precede the containing document, preserving Cargo's
    /// array concatenation/table precedence and each patch path's provenance.
    pub fn with_included_documents(
        mut self,
        documents: Vec<Option<(PathBuf, RustCargoConfigDocument)>>,
    ) -> Result<Self, String> {
        let specs = self.include_specs()?;
        if specs.len() != documents.len() {
            return Err("incomplete Cargo config includes".into());
        }
        let mut included = Vec::new();
        for (spec, document) in specs.into_iter().zip(documents) {
            match document {
                Some((base, mut document)) if document.includes_resolved => {
                    // Keep the layers flat, so nested includes cannot grow the
                    // Rust call stack during interpretation, cloning or drop.
                    included.append(&mut document.included);
                    included.push((base, document));
                }
                None if spec.optional => {}
                _ => return Err("incomplete Cargo config includes".into()),
            }
        }
        self.included = included;
        self.includes_resolved = true;
        Ok(self)
    }

    fn external_paths(&mut self) {
        self.workspace_paths = false;
        for (_, document) in &mut self.included {
            document.workspace_paths = false;
        }
    }

    /// Digest of the settings this module reads: `[patch]`, `build.target`,
    /// `paths`, `build.rustflags`, each `target.<key>.rustflags`, and raw
    /// `unstable` input when present. An absent unstable key keeps the existing
    /// encoding exactly; ordinary aliases/net/linker edits retain this digest.
    pub fn topology_digest(&self) -> [u8; 32] {
        let mut read = toml::Table::new();
        if !self.included.is_empty() {
            let includes = self
                .included
                .iter()
                .map(|(base, document)| {
                    toml::Value::Table(toml::Table::from_iter([
                        (
                            "base".to_owned(),
                            toml::Value::String(base.to_string_lossy().into_owned()),
                        ),
                        (
                            "digest".to_owned(),
                            toml::Value::String(
                                brokk_bifrost_core::analyzer::canonical_hash::lower_hex_string(
                                    &document.topology_digest(),
                                ),
                            ),
                        ),
                    ]))
                })
                .collect();
            read.insert("acquired-includes".to_owned(), toml::Value::Array(includes));
        }
        // Conditional insertion preserves all identities with no unstable input.
        // Keep malformed/unknown unstable input too: it withdraws certification.
        if let Some(unstable) = self.value.get("unstable") {
            read.insert("unstable".to_owned(), unstable.clone());
        }
        if let Some(patch) = self.value.get("patch") {
            read.insert("patch".to_string(), patch.clone());
        }
        if let Some(paths) = self.value.get("paths") {
            read.insert("paths".to_string(), paths.clone());
        }
        let build = ["target", "rustflags"]
            .into_iter()
            .filter_map(|key| Some((key.to_string(), self.build(key)?.clone())))
            .collect::<toml::Table>();
        if !build.is_empty() {
            read.insert("build".to_string(), build.into());
        }
        let targets = self
            .target_rustflags()
            .map(|(key, flags)| {
                let flags = toml::Table::from_iter([("rustflags".to_string(), flags.clone())]);
                (key.clone(), toml::Value::Table(flags))
            })
            .collect::<toml::Table>();
        if !targets.is_empty() {
            read.insert("target".to_string(), targets.into());
        }
        crate::cargo_manifest::canonical_toml_digest(
            b"cargo configuration",
            &toml::Value::Table(read),
            |_, _| false,
        )
    }

    /// Interpret source-affecting settings once for all discovery consumers.
    /// Unknown keys and malformed known settings never certify source identity.
    pub fn source_effect(&self) -> RustCargoConfigSourceEffect {
        use RustCargoConfigSourceEffect::*;
        let mut effect = self.own_source_effect();
        for (_, document) in &self.included {
            match document.own_source_effect() {
                Unknown => return Unknown,
                Changes if effect != Unknown => effect = Changes,
                _ => {}
            }
        }
        effect
    }

    fn own_source_effect(&self) -> RustCargoConfigSourceEffect {
        use RustCargoConfigSourceEffect::*;
        if !self.includes_resolved {
            return Unknown;
        }
        let mut result = Preserves;
        for (key, value) in &self.value {
            let known = match key.as_str() {
                // `[registry].global-credential-providers` only chooses how
                // credentials are fetched. Every other `[registry]` key can
                // name the default registry or its token, so it keeps Changes.
                "registry"
                    if value.as_table().is_some_and(|table| {
                        !table.is_empty()
                            && table.iter().all(|(key, value)| {
                                key == "global-credential-providers" && string_array(value)
                            })
                    }) =>
                {
                    true
                }
                "source" | "patch" | "registries" | "registry" => {
                    if value.as_table().is_none() {
                        return Unknown;
                    }
                    result = Changes;
                    true
                }
                "paths" => {
                    if !string_array(value) {
                        return Unknown;
                    }
                    result = Changes;
                    true
                }
                // Build settings preserve sources only for the validated sub-keys.
                "build" => known_table(value, |key, value| match key {
                    "target" => string_or_array(value),
                    "rustflags" => classified_rustflags(value),
                    "target-dir" | "build-dir" | "dep-info-basedir" | "rustdoc" | "warnings" => {
                        value.is_str()
                    }
                    "jobs" => value.is_integer(),
                    "incremental" => value.is_bool(),
                    "rustdocflags" => string_or_array(value),
                    _ => false,
                }),
                // Target flags keep their validation; links overrides remain Unknown.
                "target" => known_table(value, |_, target| {
                    known_table(target, |key, value| match key {
                        "linker" => value.is_str(),
                        "runner" | "rustdocflags" => string_or_array(value),
                        "rustflags" => classified_rustflags(value),
                        _ => false,
                    })
                }),
                // Aliases name commands rather than dependency sources.
                "alias" => known_table(value, |_, value| string_or_array(value)),
                // Terminal settings only affect output.
                "term" => known_table(value, |key, value| match key {
                    "quiet" | "verbose" | "hyperlinks" | "unicode" => value.is_bool(),
                    "color" => value
                        .as_str()
                        .is_some_and(|v| matches!(v, "auto" | "always" | "never")),
                    _ => false,
                }),
                // Network policy changes transport, not package identity.
                "net" => known_table(value, |key, value| match key {
                    "offline" | "git-fetch-with-cli" => value.is_bool(),
                    "retry" => value.is_integer(),
                    _ => false,
                }),
                // HTTP settings change transport, not package identity.
                "http" => known_table(value, |key, value| match key {
                    "proxy" | "user-agent" | "cainfo" | "proxy-cainfo" => value.is_str(),
                    "timeout" | "low-speed-limit" => value.is_integer(),
                    "ssl-verify" | "multiplexing" | "debug" | "check-revoke" => value.is_bool(),
                    _ => false,
                }),
                // `[env]` sets process variables for build scripts and
                // `env!`; `[profile]` sets compiler options; the rest below
                // configure the Cargo front end. None of them selects where
                // a package comes from. `[env]` and `[profile]` do change
                // values and `cfg(debug_assertions)`, which source identity
                // does not read.
                "env" => known_table(value, |_, entry| {
                    entry.is_str()
                        || known_table(entry, |key, value| match key {
                            "value" => value.is_str(),
                            "force" | "relative" => value.is_bool(),
                            _ => false,
                        })
                }),
                "profile" | "gc" => known_table(value, |_, value| value.is_table()),
                "doc" => known_table(value, |key, value| {
                    key == "browser" && string_or_array(value)
                }),
                "credential-alias" => known_table(value, |_, value| string_or_array(value)),
                "cargo-new" => known_table(value, |key, value| key == "vcs" && value.is_str()),
                "future-incompat-report" => {
                    known_table(value, |key, value| key == "frequency" && value.is_str())
                }
                "install" => known_table(value, |key, value| key == "root" && value.is_str()),
                "cache" => known_table(value, |key, value| {
                    key == "auto-clean-frequency" && value.is_str()
                }),
                // `[resolver]` and `net.offline` change version selection only
                // when no Cargo.lock exists. Without a lock the evidence is
                // already unresolved ("missing_lockfile",
                // `file_dependency_evidence.rs`), exact versions come only
                // from a lock, and the `log` identity proof in
                // `route_kinds.rs` never selects a version. Neither key can
                // change a certified answer. An unknown key stays Unknown.
                "resolver" => known_table(value, |key, value| {
                    key == "incompatible-rust-versions" && value.is_str()
                }),
                "include" => self.include_specs().is_ok(),
                "unstable" => self.stdlib_build_mode_setting() != RustStdlibBuildMode::Unknown,
                _ => false,
            };
            if !known {
                return Unknown;
            }
        }
        result
    }

    fn stdlib_build_mode_setting(&self) -> RustStdlibBuildMode {
        let Some(unstable) = self.value.get("unstable") else {
            return RustStdlibBuildMode::Prebuilt;
        };
        let Some(table) = unstable.as_table() else {
            return RustStdlibBuildMode::Unknown;
        };
        if table.keys().any(|key| key != "build-std") {
            return RustStdlibBuildMode::Unknown;
        }
        match table.get("build-std") {
            None => RustStdlibBuildMode::Prebuilt,
            Some(value)
                if value.as_array().is_some_and(|items| {
                    !items.is_empty()
                        && items
                            .iter()
                            .all(|item| item.as_str().is_some_and(|s| !s.is_empty()))
                }) =>
            {
                RustStdlibBuildMode::BuildStd
            }
            Some(_) => RustStdlibBuildMode::Unknown,
        }
    }

    fn build(&self, key: &str) -> Option<&toml::Value> {
        self.value.get("build")?.get(key)
    }

    /// Each `target.<key>` table's rustflags, keyed by its triple or
    /// `cfg(...)` spelling.
    fn target_rustflags(&self) -> impl Iterator<Item = (&String, &toml::Value)> {
        self.value
            .get("target")
            .and_then(toml::Value::as_table)
            .into_iter()
            .flatten()
            .filter_map(|(key, table)| Some((key, table.get("rustflags")?)))
    }

    /// The `[patch]` table, `source -> name -> entry`.
    pub(crate) fn patch(&self) -> Option<&toml::Value> {
        self.value.get("patch")
    }
}

fn string_array(value: &toml::Value) -> bool {
    value
        .as_array()
        .is_some_and(|items| items.iter().all(toml::Value::is_str))
}

fn string_or_array(value: &toml::Value) -> bool {
    value.is_str() || string_array(value)
}

// `--check-cfg` declares allowed names/values and does not enable them.
// `--cfg` enables atoms through the existing shared evaluator. Malformed cfg
// flags, external-crate overrides (--extern/-L), or a replaced sysroot cannot
// certify the selected toolchain artifact. rustc documents external crate
// selection at https://doc.rust-lang.org/rustc/command-line-arguments.html.
fn classified_rustflags(value: &toml::Value) -> bool {
    if !string_or_array(value) {
        return false;
    }
    let flags = rustflags(Some(value.clone()));
    let mut arguments = flags.iter();
    while let Some(argument) = arguments.next() {
        if argument == "--sysroot"
            || argument.starts_with("--sysroot=")
            || argument == "--extern"
            || argument.starts_with("--extern=")
            || argument.starts_with("-L")
        {
            return false;
        }
        if argument == "--cfg" {
            if arguments
                .next()
                .and_then(|spec| cfg_flag_atom(spec))
                .is_none()
            {
                return false;
            }
        } else if let Some(spec) = argument.strip_prefix("--cfg=") {
            if cfg_flag_atom(spec).is_none() {
                return false;
            }
        } else if argument == "--check-cfg" {
            if arguments
                .next()
                .is_none_or(|value| value.is_empty() || value.starts_with('-'))
            {
                return false;
            }
        } else if argument == "--check-cfg=" {
            return false;
        }
    }
    true
}

/// Where the value of a build's cfg atom comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CfgAtomSource {
    /// Cargo and rustc supply it without reading Cargo configuration.
    Defaults,
    /// It comes from the configuration files: `build.target` and the
    /// `--cfg` flags of the rustflags.
    Configuration,
}

/// The configuration files a build reads, and the targets it compiles for.
struct ReadConfiguration<'a> {
    levels: &'a [(&'a Path, &'a RustCargoConfigDocument)],
    targets: &'a [String],
}

/// The one derivation of a build's cfg atoms, each tagged with its source.
///
/// `configuration` holds the configuration levels and the build targets when
/// the files were read, and is `None` when the acquisition is unknown. An
/// unknown acquisition keeps exactly the atoms whose source is not the
/// configuration. The other atoms stay absent, which the evaluator reads as
/// unknown (target values) or as unproven (a `--cfg` flag), never as false.
///
/// `test` and `debug_assertions` are `Defaults`: this reader never looks at
/// `[profile.*]` (no `debug-assertions` key is parsed from any configuration
/// file or manifest), so a profile override is a fidelity gap in both modes.
fn tagged_cfg_atoms(configuration: Option<ReadConfiguration>) -> Vec<(CfgAtomSource, String)> {
    let mut atoms = vec![
        (CfgAtomSource::Defaults, "test".to_string()),
        (CfgAtomSource::Defaults, "debug_assertions".to_string()),
    ];
    let Some(ReadConfiguration { levels, targets }) = configuration else {
        return atoms;
    };
    let configured = if let [target] = targets {
        let target_atoms = target_cfg_atoms(target);
        let mut configured = rustflag_cfg_atoms(levels, target, &target_atoms);
        configured.extend(target_atoms);
        configured
    } else {
        targets
            .iter()
            .map(|target| rustflag_cfg_atoms(levels, target, &target_cfg_atoms(target)))
            .reduce(|left, right| left.intersection(&right).cloned().collect())
            .expect("several targets")
    };
    atoms.extend(
        configured
            .into_iter()
            .map(|atom| (CfgAtomSource::Configuration, atom)),
    );
    atoms
}

/// The cfg atoms of a build whose Cargo configuration is unknown: the
/// atoms that never depend on configuration, plus the marker that keeps
/// `feature` atoms unproven.
fn uncertain_cfg_atoms() -> BTreeSet<String> {
    let mut atoms: BTreeSet<_> = tagged_cfg_atoms(None)
        .into_iter()
        .filter(|(source, _)| *source == CfgAtomSource::Defaults)
        .map(|(_, atom)| atom)
        .collect();
    atoms.insert(crate::cfg::INCOMPLETE_FEATURES_ATOM.to_owned());
    atoms
}

fn known_table(value: &toml::Value, known: impl Fn(&str, &toml::Value) -> bool) -> bool {
    value
        .as_table()
        .is_some_and(|table| table.iter().all(|(key, value)| known(key, value)))
}

/// One `[patch.<source>.<name>]` entry of the configuration, merged across
/// files, with the directory its relative `path` resolves against: the one
/// that holds the `.cargo` directory that defined `path`.
pub(crate) struct RustCargoConfigPatch {
    pub(crate) name: String,
    pub(crate) entry: toml::Table,
    pub(crate) base: PathBuf,
}

/// The Cargo configuration files of one workspace, keyed by the directory
/// that holds their `.cargo` directory, relative to the project root.
#[derive(Clone, Default)]
pub struct RustCargoConfiguration {
    files: HashMap<PathBuf, RustCargoConfigDocument>,
    base_layers: Vec<(PathBuf, RustCargoConfigDocument)>,
    acquisition_complete: bool,
    unclassified_inputs: bool,
    recorded: Option<acquired::RustCargoAcquiredConfigView>,
    recorded_layers: std::collections::BTreeMap<PathBuf, Vec<(PathBuf, RustCargoConfigDocument)>>,
}

impl std::fmt::Debug for RustCargoConfiguration {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RustCargoConfiguration")
            .field("local_layers", &self.files.len())
            .field("base_layers", &self.base_layers.len())
            .field("acquisition_complete", &self.acquisition_complete)
            .field("unclassified_inputs", &self.unclassified_inputs)
            .finish_non_exhaustive()
    }
}

impl RustCargoConfiguration {
    /// Add acquired Cargo-home/above-root layers, shallowest first. Their
    /// labels are logical provenance, not filesystem paths to open. External
    /// source overrides are classified but never routed as workspace paths.
    pub fn with_base_layers(
        mut self,
        layers: impl IntoIterator<Item = (PathBuf, RustCargoConfigDocument)>,
    ) -> Self {
        for (label, mut document) in layers {
            document.external_paths();
            self.base_layers.push((label, document));
        }
        self
    }

    /// Complete means both the acquisition boundary and every applicable
    /// included document are established and interpretable.
    pub fn acquisition_is_complete(&self, directory: &Path) -> bool {
        if let Some(view) = &self.recorded {
            return view.complete && view.owner(directory).is_some_and(|owner| owner.complete);
        }
        self.acquisition_complete
            && !self.unclassified_inputs
            && self.levels(directory).iter().all(|(_, document)| {
                document.source_effect() != RustCargoConfigSourceEffect::Unknown
            })
    }

    /// Supply the acquisition result, not an assumption about absent files.
    /// True requires every applicable Cargo layer/include to have been checked.
    pub fn with_acquisition_complete(mut self, complete: bool) -> Self {
        self.acquisition_complete = complete;
        if let Some(view) = &mut self.recorded {
            view.complete = complete;
        }
        self
    }

    /// Mark an input that could not be parsed/classified; no extracted absence
    /// from the remaining documents can certify its effect.
    pub fn with_unclassified_inputs(mut self) -> Self {
        self.unclassified_inputs = true;
        self
    }

    /// The build mode from the same parsed/merged settings as build.target.
    /// A partial view never establishes prebuilt stdlib certification.
    pub fn stdlib_build_mode(&self, directory: &Path) -> RustStdlibBuildMode {
        if let Some(view) = &self.recorded {
            return view
                .owner(directory)
                .filter(|_| self.acquisition_is_complete(directory))
                .map_or(RustStdlibBuildMode::Unknown, |owner| owner.build_mode);
        }
        if !self.acquisition_is_complete(directory) {
            return RustStdlibBuildMode::Unknown;
        }
        let mut mode = RustStdlibBuildMode::Prebuilt;
        for (_, file) in self.levels(directory) {
            if file.source_effect() == RustCargoConfigSourceEffect::Unknown {
                return RustStdlibBuildMode::Unknown;
            }
            match file.stdlib_build_mode_setting() {
                RustStdlibBuildMode::Unknown => return RustStdlibBuildMode::Unknown,
                RustStdlibBuildMode::BuildStd => mode = RustStdlibBuildMode::BuildStd,
                RustStdlibBuildMode::Prebuilt => {}
            }
        }
        mode
    }

    /// Whether the completely acquired view preserves dependency source identity.
    /// Selected snapshots alone cannot rule out an include or an external layer.
    pub fn source_effect(&self, directory: &Path) -> RustCargoConfigSourceEffect {
        if let Some(view) = &self.recorded {
            return view
                .owner(directory)
                .filter(|_| self.acquisition_is_complete(directory))
                .map_or(RustCargoConfigSourceEffect::Unknown, |owner| {
                    owner.source_effect
                });
        }
        if !self.acquisition_is_complete(directory) {
            return RustCargoConfigSourceEffect::Unknown;
        }
        let mut effect = RustCargoConfigSourceEffect::Preserves;
        for (_, file) in self.levels(directory) {
            match file.source_effect() {
                RustCargoConfigSourceEffect::Unknown => {
                    return RustCargoConfigSourceEffect::Unknown;
                }
                RustCargoConfigSourceEffect::Changes => {
                    effect = RustCargoConfigSourceEffect::Changes
                }
                RustCargoConfigSourceEffect::Preserves => {}
            }
        }
        effect
    }

    /// Project-relative candidate paths, bounded exactly like configuration levels.
    /// The caller records absence too; each level's legacy file takes precedence.
    pub fn candidate_paths(directory: &Path) -> Vec<(PathBuf, PathBuf)> {
        directory
            .ancestors()
            .map(|level| {
                (
                    level.join(".cargo/config"),
                    level.join(".cargo/config.toml"),
                )
            })
            .collect()
    }

    /// An explicit extern flag leaves primitive certification open. Include all layers
    /// and target tables, including undecided target predicates, conservatively.
    pub fn has_extern_rustflags(&self, directory: &Path) -> bool {
        if let Some(view) = &self.recorded {
            return !self.acquisition_is_complete(directory)
                || view
                    .owner(directory)
                    .is_none_or(|owner| owner.has_extern_flags);
        }
        self.levels(directory).iter().any(|(_, file)| {
            file.build("rustflags")
                .into_iter()
                .chain(file.target_rustflags().map(|(_, flags)| flags))
                .flat_map(|flags| rustflags(Some(flags.clone())))
                .any(|flag| flag == "--extern" || flag.starts_with("--extern="))
        })
    }

    /// Collect parsed configuration files by their project-relative paths.
    /// Where one `.cargo` directory holds both files, Cargo reads the legacy
    /// `config` and ignores `config.toml`.
    pub fn from_files(files: impl IntoIterator<Item = (PathBuf, RustCargoConfigDocument)>) -> Self {
        let mut by_directory = HashMap::<PathBuf, (bool, RustCargoConfigDocument)>::default();
        for (path, document) in files {
            assert!(
                is_cargo_configuration_path(&path),
                "{path:?} is not a Cargo configuration file"
            );
            let directory = path
                .parent()
                .and_then(Path::parent)
                .expect("a configuration file sits in a .cargo directory")
                .to_path_buf();
            let legacy = path.file_name().is_some_and(|name| name == "config");
            let replaces = by_directory
                .get(&directory)
                .is_none_or(|(present_is_legacy, _)| legacy && !present_is_legacy);
            if replaces {
                by_directory.insert(directory, (legacy, document));
            }
        }
        Self {
            recorded: None,
            recorded_layers: Default::default(),
            acquisition_complete: false,
            unclassified_inputs: false,
            base_layers: Vec::new(),
            files: by_directory
                .into_iter()
                .map(|(directory, (_, document))| (directory, document))
                .collect(),
        }
    }

    /// The files Cargo reads for a build started in `directory`, shallowest
    /// first, so that merging in order lets a deeper file win.
    fn levels<'a>(&'a self, directory: &'a Path) -> Vec<(&'a Path, &'a RustCargoConfigDocument)> {
        fn append<'a>(
            levels: &mut Vec<(&'a Path, &'a RustCargoConfigDocument)>,
            base: &'a Path,
            document: &'a RustCargoConfigDocument,
        ) {
            for (base, included) in &document.included {
                levels.push((base, included));
            }
            levels.push((base, document));
        }
        if self.recorded.is_some() {
            return self
                .recorded_layers
                .get(directory)
                .into_iter()
                .flatten()
                .map(|(base, document)| (base.as_path(), document))
                .collect();
        }
        let mut levels = Vec::new();
        for (label, document) in &self.base_layers {
            append(&mut levels, label, document);
        }
        let local = directory
            .ancestors()
            .filter_map(|level| self.files.get(level).map(|document| (level, document)))
            .collect::<Vec<_>>();
        for (base, document) in local.into_iter().rev() {
            append(&mut levels, base, document);
        }
        levels
    }

    /// Cargo owners whose applicable layers were acquired together. A missing
    /// recorded view exposes no additional contexts and cannot certify absence.
    pub fn acquired_owner_directories(&self) -> Vec<&Path> {
        self.recorded
            .as_ref()
            .into_iter()
            .flat_map(|view| view.owners.keys().map(PathBuf::as_path))
            .collect()
    }

    /// Whether every selected configuration layer preserves a registry package's
    /// identity. A paths override has no package identity until its manifest is
    /// selected, so its presence cannot certify an external package.
    pub fn preserves_registry_package(&self, directory: &Path, package: &str) -> bool {
        if !self.acquisition_is_complete(directory) {
            return false;
        }
        if self.recorded.as_ref().is_some_and(|view| {
            view.owner(directory)
                .is_none_or(|owner| !owner.complete || owner.external_source_unresolved)
        }) {
            return false;
        }
        self.levels(directory).iter().all(|(_, document)| {
            let patched = document
                .patch()
                .and_then(toml::Value::as_table)
                .is_some_and(|sources| {
                    sources.values().any(|entries| {
                        entries.as_table().is_some_and(|entries| {
                            entries.iter().any(|(name, entry)| {
                                name == package
                                    || entry.get("package").and_then(toml::Value::as_str)
                                        == Some(package)
                            })
                        })
                    })
                });
            let paths = document.value.get("paths");
            // Source replacement alone preserves package identities and checksums.
            !patched && paths.is_none_or(|paths| paths.as_array().is_some_and(Vec::is_empty))
        })
    }

    /// Refuse an extern-prelude absence proof if any workspace configuration
    /// layer can supply an extern. Checking all target tables is conservative
    /// when target selection is undecided. topology_digest covers these flags.
    pub fn has_extern_flags(&self, directory: &Path) -> bool {
        if let Some(view) = &self.recorded {
            return !self.acquisition_is_complete(directory)
                || view
                    .owner(directory)
                    .is_none_or(|owner| owner.has_extern_flags);
        }
        self.levels(directory).iter().any(|(_, document)| {
            document
                .build("rustflags")
                .into_iter()
                .chain(document.target_rustflags().map(|(_, flags)| flags))
                .any(|flags| rustflags_have_extern(&rustflags(Some(flags.clone()))))
        })
    }

    /// The cfg set Cargo compiles a build started in `directory` with: the
    /// build target's cfg values, `test` and `debug_assertions` (the selected
    /// default for every workspace member), and the `--cfg` flags of the
    /// rustflags that apply.
    ///
    /// A target rustc does not know, such as a custom target file, has no
    /// described values, so every target cfg stays unknown. So do the values
    /// of a build for several targets, whose crate rows hold one cfg set: only
    /// the flags every target's build sets are in it.
    pub fn cfg_atoms(&self, directory: &Path) -> BTreeSet<String> {
        if let Some(view) = &self.recorded {
            return view
                .owner(directory)
                .filter(|_| self.acquisition_is_complete(directory))
                .map_or_else(uncertain_cfg_atoms, |owner| owner.cfg_atoms.clone());
        }
        let levels = self.levels(directory);
        let targets = self.build_targets(directory);
        tagged_cfg_atoms(Some(ReadConfiguration {
            levels: &levels,
            targets: &targets,
        }))
        .into_iter()
        .map(|(_, atom)| atom)
        .collect()
    }

    fn build_targets(&self, directory: &Path) -> Vec<String> {
        let mut targets = self.configured_build_targets(directory).0;
        if targets.is_empty() {
            targets.push(HOST_TRIPLE.to_string());
        }
        targets
    }

    /// The `build.target` values a build started in `directory` compiles for,
    /// merged across the files Cargo reads, and the directories whose file
    /// sets `build.target`, shallowest first. No targets means the build
    /// compiles for the host.
    pub fn configured_build_targets<'a>(
        &'a self,
        directory: &'a Path,
    ) -> (Vec<String>, Vec<&'a Path>) {
        if let Some(view) = &self.recorded {
            return view.owner(directory).map_or_else(
                || (Vec::new(), Vec::new()),
                |owner| {
                    let targets = if owner.target_unsupported {
                        vec!["bifrost-unsupported-target".to_owned()]
                    } else {
                        owner.targets.clone()
                    };
                    (
                        targets,
                        owner.target_defining.iter().map(PathBuf::as_path).collect(),
                    )
                },
            );
        }
        let levels = self.levels(directory);
        let defining = levels
            .iter()
            .filter(|(_, file)| file.build("target").is_some())
            .map(|(level, _)| *level)
            .collect();
        let targets = match merged(levels.iter().filter_map(|(_, file)| file.build("target"))) {
            Some(toml::Value::Array(items)) => items
                .iter()
                .filter_map(toml::Value::as_str)
                .map(str::to_string)
                .collect(),
            Some(toml::Value::String(target)) => vec![target],
            _ => Vec::new(),
        };
        (targets, defining)
    }

    /// Target dependency tables follow the configured build targets. If the
    /// targets disagree, one placement cannot prove whether the edge is active.
    pub(crate) fn dependency_predicate(&self, directory: &Path, key: &str) -> Option<bool> {
        if self.recorded.is_some() && !self.acquisition_is_complete(directory) {
            return None;
        }
        let mut outcomes = self
            .build_targets(directory)
            .into_iter()
            .map(|target| target_dependency_predicate(&target, key));
        let first = outcomes.next().expect("a build has a target")?;
        outcomes
            .all(|outcome| outcome == Some(first))
            .then_some(first)
    }

    /// Cargo dependency-table selection for host-only units. Like Cargo, this
    /// ignores test/feature cfgs and evaluates target predicates only. The host
    /// triple comes from the recorded view, the same value its digest hashes
    /// (#12604); only a configuration without a recorded view uses the
    /// compile-time triple directly.
    pub(crate) fn host_dependency_predicate(&self, key: &str) -> Option<bool> {
        let host = self
            .recorded
            .as_ref()
            .map_or(HOST_TRIPLE, |view| view.host_triple.as_str());
        target_dependency_predicate(host, key)
    }

    /// Host-only units use the host cfg set even for a configured cross build.
    pub(crate) fn host_cfg_atoms(&self, directory: &Path) -> BTreeSet<String> {
        if let Some(view) = &self.recorded {
            return view
                .owner(directory)
                .filter(|_| self.acquisition_is_complete(directory))
                .map_or_else(uncertain_cfg_atoms, |owner| owner.host_cfg_atoms.clone());
        }
        let levels = self.levels(directory);
        tagged_cfg_atoms(Some(ReadConfiguration {
            levels: &levels,
            targets: &[HOST_TRIPLE.to_string()],
        }))
        .into_iter()
        .map(|(_, atom)| atom)
        .collect()
    }

    /// The `[patch.<source>]` entries of the configuration Cargo reads for a
    /// build started in `directory`, each merged across the files that define
    /// it.
    pub(crate) fn patches(&self, directory: &Path, source: &str) -> Vec<RustCargoConfigPatch> {
        let mut patches = Vec::<RustCargoConfigPatch>::new();
        for (base, file) in self.levels(directory) {
            // External source reconstruction is deliberately unresolved; a
            // logical provenance label must never become a workspace path.
            if !file.workspace_paths {
                continue;
            }
            for (name, entry) in file
                .patch()
                .and_then(|patch| patch.get(source))
                .and_then(toml::Value::as_table)
                .into_iter()
                .flatten()
            {
                let Some(entry) = entry.as_table() else {
                    continue;
                };
                let index = match patches.iter().position(|patch| patch.name == *name) {
                    Some(index) => index,
                    None => {
                        patches.push(RustCargoConfigPatch {
                            name: name.clone(),
                            entry: toml::Table::new(),
                            base: base.to_path_buf(),
                        });
                        patches.len() - 1
                    }
                };
                let patch = &mut patches[index];
                for (key, value) in entry {
                    if key == "path" {
                        patch.base = base.to_path_buf();
                    }
                    let value = merged([patch.entry.get(key), Some(value)].into_iter().flatten())
                        .expect("one value at least");
                    patch.entry.insert(key.clone(), value);
                }
            }
        }
        patches
    }
}

/// The target triple a build that names no target compiles for.
pub fn host_target_triple() -> &'static str {
    HOST_TRIPLE
}

/// The `target_os` and `target_arch` of a target rustc knows, or `None` for
/// a target it does not, such as a custom target file.
pub fn builtin_target_platform(target: &str) -> Option<(&'static str, &'static str)> {
    let info = get_builtin_target_by_triple(target)?;
    // rustc spells a bare-metal target's absent operating system "none".
    Some((
        info.os.as_ref().map_or("none", |os| os.as_str()),
        info.arch.as_str(),
    ))
}

/// Cargo's merge of one key's values, shallowest first: two arrays join with
/// the deeper items last, and any other deeper value replaces the shallower.
fn merged<'a>(values: impl IntoIterator<Item = &'a toml::Value>) -> Option<toml::Value> {
    values.into_iter().fold(None, |merged, value| {
        Some(match (merged, value) {
            (Some(toml::Value::Array(mut items)), toml::Value::Array(deeper)) => {
                items.extend(deeper.iter().cloned());
                toml::Value::Array(items)
            }
            (_, value) => value.clone(),
        })
    })
}

/// The cfg values of a target rustc knows, as `key = "value"` atoms with the
/// bare `unix` and `windows` its families imply. A target rustc does not know
/// has none.
fn target_cfg_atoms(target: &str) -> BTreeSet<String> {
    let Some(info) = get_builtin_target_by_triple(target) else {
        return BTreeSet::new();
    };
    let TargetInfo {
        os,
        arch,
        families,
        pointer_width,
        endian,
        has_atomics,
        ..
    } = info;
    let endian = match endian {
        Endian::little => "little",
        Endian::big => "big",
    };
    let mut atoms = BTreeSet::from([
        // rustc spells a bare-metal target's absent operating system "none".
        format!(
            "target_os = {:?}",
            os.as_ref().map_or("none", |os| os.as_str())
        ),
        format!("target_arch = {:?}", arch.as_str()),
        format!("target_pointer_width = \"{pointer_width}\""),
        format!("target_endian = {endian:?}"),
    ]);
    for family in families.iter().map(|family| family.as_str()) {
        atoms.insert(format!("target_family = {family:?}"));
        if matches!(family, "unix" | "windows") {
            atoms.insert(family.to_string());
        }
    }
    for atomic in has_atomics.iter() {
        atoms.insert(format!("target_has_atomic = {:?}", atomic.to_string()));
    }
    atoms
}

/// The `--cfg` atoms of the rustflags Cargo passes when it builds for
/// `target`: every matching `target.<triple>.rustflags` and
/// `target.<cfg>.rustflags` joined or, when they hold no flag,
/// `build.rustflags`.
///
/// A `cfg(...)` key whose match depends on what the target atoms do not
/// decide (a target feature, a custom cfg) is undecided. Its flags are left
/// out, and when no other key's flags apply, so are `build.rustflags`,
/// because whether Cargo falls back to them is unknown.
fn rustflag_cfg_atoms(
    levels: &[(&Path, &RustCargoConfigDocument)],
    target: &str,
    target_atoms: &BTreeSet<String>,
) -> BTreeSet<String> {
    let mut keys = levels
        .iter()
        .flat_map(|(_, file)| file.target_rustflags().map(|(key, _)| key.as_str()))
        .collect::<Vec<_>>();
    keys.sort_unstable();
    keys.dedup();
    // Cargo names a custom target file's target by its file stem.
    let target_name = match Path::new(target).extension() {
        Some(extension) if extension == "json" => Path::new(target)
            .file_stem()
            .and_then(|stem| stem.to_str())
            .expect("a UTF-8 path with an extension has a UTF-8 stem"),
        _ => target,
    };
    let mut flags = Vec::new();
    let mut undecided = false;
    for key in keys {
        let applies = if key.starts_with("cfg(") {
            // Cargo rejects a configuration whose key does not parse.
            Expression::parse(key).map_or(Some(false), |expression| {
                expression.eval(|predicate| cfg_key_predicate(predicate, target_atoms))
            })
        } else {
            Some(key == target_name)
        };
        match applies {
            Some(true) => flags.extend(rustflags(merged(levels.iter().filter_map(|(_, file)| {
                file.target_rustflags()
                    .find_map(|(candidate, flags)| (candidate == key).then_some(flags))
            })))),
            Some(false) => {}
            None => undecided = true,
        }
    }
    if flags.is_empty() {
        if undecided {
            return BTreeSet::new();
        }
        flags = rustflags(merged(
            levels
                .iter()
                .filter_map(|(_, file)| file.build("rustflags")),
        ));
    }
    let mut atoms = BTreeSet::new();
    let mut arguments = flags.iter();
    while let Some(argument) = arguments.next() {
        let spec = if argument == "--cfg" {
            arguments.next().map(String::as_str)
        } else {
            argument.strip_prefix("--cfg=")
        };
        if let Some(atom) = spec.and_then(cfg_flag_atom) {
            atoms.insert(atom);
        }
    }
    atoms
}

/// Inspect parsed flag values, never Rust source syntax. Both rustc spellings
/// introduce an extern, even when its value is missing or malformed.
fn rustflags_have_extern(flags: &[String]) -> bool {
    flags
        .iter()
        .any(|flag| flag == "--extern" || flag.starts_with("--extern="))
}

/// Rustflags as Cargo reads them: an array of arguments, or one string of
/// arguments separated by whitespace.
fn rustflags(value: Option<toml::Value>) -> Vec<String> {
    match value {
        Some(toml::Value::Array(items)) => items
            .iter()
            .filter_map(toml::Value::as_str)
            .map(str::to_string)
            .collect(),
        Some(toml::Value::String(flags)) => flags.split_whitespace().map(str::to_string).collect(),
        _ => Vec::new(),
    }
}

fn target_dependency_predicate(target: &str, key: &str) -> Option<bool> {
    if key.starts_with("cfg(") {
        let atoms = target_cfg_atoms(target);
        Expression::parse(key)
            .ok()?
            .eval(|predicate| cfg_key_predicate(predicate, &atoms))
    } else {
        Some(key == target)
    }
}

/// Whether a predicate of a `target.<cfg>` key holds for the target, the way
/// Cargo matches the key against `rustc --print cfg`: target values from the
/// described atoms, `debug_assertions` on, and no test harness, proc-macro
/// crate or feature.
fn cfg_key_predicate(predicate: &Predicate<'_>, target_atoms: &BTreeSet<String>) -> Option<bool> {
    let (key, value) = match predicate {
        Predicate::DebugAssertions => return Some(true),
        Predicate::Test | Predicate::ProcMacro | Predicate::Feature(_) => return Some(false),
        Predicate::TargetFeature(_) | Predicate::Flag(_) | Predicate::KeyValue { .. } => {
            return None;
        }
        Predicate::Target(TargetPredicate::Os(os)) => ("target_os", os.as_str().to_string()),
        Predicate::Target(TargetPredicate::Arch(arch)) => {
            ("target_arch", arch.as_str().to_string())
        }
        // `unix` and `windows` parse as families too.
        Predicate::Target(TargetPredicate::Family(family)) => {
            ("target_family", family.as_str().to_string())
        }
        Predicate::Target(TargetPredicate::PointerWidth(width)) => {
            ("target_pointer_width", width.to_string())
        }
        Predicate::Target(TargetPredicate::Endian(endian)) => (
            "target_endian",
            match endian {
                Endian::little => "little",
                Endian::big => "big",
            }
            .to_string(),
        ),
        Predicate::Target(TargetPredicate::HasAtomic(atomic)) => {
            ("target_has_atomic", atomic.to_string())
        }
        Predicate::Target(_) => return None,
    };
    if target_atoms.contains(&format!("{key} = {value:?}")) {
        Some(true)
    } else if crate::cfg::describes_target(|atom| target_atoms.contains(atom)) {
        Some(false)
    } else {
        None
    }
}

/// The atom one `--cfg` flag sets, spelled as source cfg predicates are:
/// `name`, or `name = "value"`. rustc refuses a flag that sets a built-in
/// target cfg, and so does this.
fn cfg_flag_atom(spec: &str) -> Option<String> {
    let expression = Expression::parse(spec).ok()?;
    let mut predicates = expression.predicates();
    let predicate = predicates.next()?;
    if predicates.next().is_some() {
        return None;
    }
    match predicate {
        Predicate::Flag(name) => Some(name.to_string()),
        Predicate::KeyValue { key, val } => Some(format!("{key} = {val:?}")),
        Predicate::Feature(name) => Some(format!("feature = {name:?}")),
        Predicate::Test => Some("test".to_string()),
        Predicate::DebugAssertions => Some("debug_assertions".to_string()),
        Predicate::ProcMacro => Some("proc_macro".to_string()),
        Predicate::Target(_) | Predicate::TargetFeature(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn configuration(files: &[(&str, &str)]) -> RustCargoConfiguration {
        RustCargoConfiguration::from_files(files.iter().map(|(path, source)| {
            (
                PathBuf::from(path),
                RustCargoConfigDocument::from_source_bytes(source.as_bytes()).unwrap(),
            )
        }))
    }

    fn digest(source: &str) -> [u8; 32] {
        RustCargoConfigDocument::from_source_bytes(source.as_bytes())
            .unwrap()
            .topology_digest()
    }

    #[test]
    fn config_debug_and_parse_errors_do_not_echo_credentials() {
        let source = "[registry]\ntoken='private-token-value'";
        let doc = RustCargoConfigDocument::from_source_bytes(source.as_bytes()).unwrap();
        assert!(!format!("{doc:?}").contains("private-token-value"));
        let error =
            RustCargoConfigDocument::from_source_bytes(b"token='private-token-value' invalid")
                .unwrap_err();
        assert!(!error.contains("private-token-value"));
        let includes = document("include='/private-home-value/settings'")
            .include_specs()
            .unwrap();
        assert!(!format!("{includes:?}").contains("private-home-value"));
        let configuration =
            configuration(&[]).with_base_layers([(PathBuf::from("private-home-value"), doc)]);
        assert!(!format!("{configuration:?}").contains("private-home-value"));
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#12926: merged Cargo table classifications contradicted each other"
    )]
    fn source_identity_classification_is_closed() {
        for source in [
            "",
            "[build]\ntarget='x86_64-unknown-linux-gnu'",
            "[alias]\ncheck-all='check --all'",
            "[build]\nrustflags=['-Cmetadata=--extern=example-Lpath']",
            "[target.x86_64-unknown-linux-gnu]\nlinker='cc'",
            "[unstable]\nbuild-std=['std']",
            "[env]\nX='1'\nY={value='2',force=true,relative=true}",
            "[profile.release]\ndebug-assertions=true\n[profile.dev.build-override]\nopt-level=3",
            "[doc]\nbrowser='firefox'",
            "[cargo-new]\nvcs='none'",
            "[future-incompat-report]\nfrequency='always'",
            "[install]\nroot='/opt/tools'",
            "[cache]\nauto-clean-frequency='never'",
            "[gc.auto]\nfrequency='1 day'",
            "[credential-alias]\nmine=['helper','--flag']",
            "[registry]\nglobal-credential-providers=['cargo:token']",
            "[term]\ncolor='never'\n[http]\ntimeout=30",
            "[resolver]\nincompatible-rust-versions='fallback'",
            "[net]\noffline=true\nretry=2\ngit-fetch-with-cli=true",
        ] {
            assert_eq!(
                configuration(&[(".cargo/config.toml", source)])
                    .with_acquisition_complete(true)
                    .source_effect(Path::new("")),
                RustCargoConfigSourceEffect::Preserves,
                "{source}"
            );
        }
        for source in [
            "[source.crates-io]\nreplace-with='local'",
            "[patch.crates-io]\nx={path='x'}",
            "paths=['vendor']",
            "[registries.alt]\nindex='https://example.invalid'",
            "[registry]\ndefault='alt'",
            "[registry]\nglobal-credential-providers='cargo:token'",
            "[registry]\nglobal-credential-providers=['cargo:token']\ndefault='alt'",
            "[env]\nX='1'\n[source.crates-io]\nreplace-with='local'",
        ] {
            assert_eq!(
                configuration(&[(".cargo/config.toml", source)])
                    .with_acquisition_complete(true)
                    .source_effect(Path::new("")),
                RustCargoConfigSourceEffect::Changes,
                "{source}"
            );
        }
        for source in [
            "[future]\nkey=true",
            "[build]\nfuture=true",
            "[build]\nrustflags=['--extern=log=other.rlib']",
            "[build]\nrustflags=['--extern','log=other.rlib']",
            "[build]\nrustflags='--extern=log=other.rlib'",
            "[build]\nrustflags='-L other'",
            "[build]\nrustflags='-Lother'",
            "[build]\nrustflags=['-L','other']",
            "[target.x86_64-unknown-linux-gnu]\nrustflags=['-Lother']",
            "[unstable]\nbuild-std=true",
            "[unstable]\nbuild-std=[]",
            "[unstable]\nunknown=true",
            "[resolver]\nunknown=true",
            "[resolver]\nincompatible-rust-versions=true",
            "[net]\nunknown=1",
            "[env]\nX=1",
            "[env]\nX={value='1',unknown=true}",
            "[profile]\nrelease=1",
        ] {
            assert_eq!(
                configuration(&[(".cargo/config.toml", source)])
                    .with_acquisition_complete(true)
                    .source_effect(Path::new("")),
                RustCargoConfigSourceEffect::Unknown,
                "{source}"
            );
        }
    }

    fn document(source: &str) -> RustCargoConfigDocument {
        RustCargoConfigDocument::from_source_bytes(source.as_bytes()).unwrap()
    }

    #[test]
    fn unresolved_includes_cannot_be_certified_by_a_complete_flag() {
        let configuration = configuration(&[(".cargo/config.toml", "include='overrides.toml'")])
            .with_acquisition_complete(true);
        assert!(!configuration.acquisition_is_complete(Path::new("")));
        assert_eq!(
            configuration.source_effect(Path::new("")),
            RustCargoConfigSourceEffect::Unknown
        );
        assert_eq!(
            configuration.stdlib_build_mode(Path::new("")),
            RustStdlibBuildMode::Unknown
        );
    }

    #[test]
    fn acquired_includes_keep_source_mode_flags_and_patch_bases() {
        let included = document(
            "[unstable]\nbuild-std=['std']\n[build]\nrustflags=['--cfg','included']\n[patch.crates-io]\nwidget={path='widget'}",
        );
        let root = document("include='overrides.toml'\n[build]\nrustflags=['--cfg','root']")
            .with_included_documents(vec![Some((PathBuf::from("config-dir"), included))])
            .unwrap();
        let configuration =
            RustCargoConfiguration::from_files([(PathBuf::from(".cargo/config.toml"), root)])
                .with_acquisition_complete(true);
        assert_eq!(
            configuration.source_effect(Path::new("")),
            RustCargoConfigSourceEffect::Changes
        );
        assert_eq!(
            configuration.stdlib_build_mode(Path::new("")),
            RustStdlibBuildMode::BuildStd
        );
        let atoms = configuration.cfg_atoms(Path::new(""));
        assert!(atoms.contains("included") && atoms.contains("root"));
        assert_eq!(
            configuration.patches(Path::new(""), "crates-io")[0].base,
            PathBuf::from("config-dir")
        );
    }

    #[test]
    fn acquired_include_identity_observes_effective_settings_and_patch_base() {
        let with = |source: &str, base: &str| {
            document("include='settings'")
                .with_included_documents(vec![Some((PathBuf::from(base), document(source)))])
                .unwrap()
                .topology_digest()
        };
        assert_ne!(
            with("[unstable]\nbuild-std=['std']", "config"),
            with("", "config")
        );
        assert_ne!(
            with("[patch.crates-io]\nx={path='x'}", "a"),
            with("[patch.crates-io]\nx={path='x'}", "b")
        );
    }

    #[test]
    fn cargo_home_layers_apply_outside_ancestor_filter_and_preserve_precedence() {
        let home = document(
            "[source.crates-io]\nreplace-with='elsewhere'\n[unstable]\nbuild-std=['std']\n[build]\ntarget='aarch64-apple-darwin'\nrustflags=['--cfg','home']\n[patch.crates-io]\nwidget={path='outside'}",
        );
        let configuration = configuration(&[(
            ".cargo/config.toml",
            "[build]\ntarget='x86_64-unknown-linux-gnu'\nrustflags=['--cfg','local']",
        )])
        .with_base_layers([(PathBuf::from("Cargo-home"), home)])
        .with_acquisition_complete(true);
        assert_eq!(
            configuration.source_effect(Path::new("nested")),
            RustCargoConfigSourceEffect::Changes
        );
        assert_eq!(
            configuration.stdlib_build_mode(Path::new("nested")),
            RustStdlibBuildMode::BuildStd
        );
        assert_eq!(
            configuration
                .configured_build_targets(Path::new("nested"))
                .0,
            vec!["x86_64-unknown-linux-gnu"]
        );
        let atoms = configuration.cfg_atoms(Path::new("nested"));
        assert!(atoms.contains("home") && atoms.contains("local"));
        assert!(
            configuration
                .patches(Path::new("nested"), "crates-io")
                .is_empty()
        );
    }

    #[test]
    fn missing_and_nested_includes_remain_explicit() {
        assert!(
            document("include='required'")
                .with_included_documents(vec![None])
                .is_err()
        );
        let optional = document("include=[{path='missing', optional=true}]")
            .with_included_documents(vec![None])
            .unwrap();
        assert_eq!(
            optional.source_effect(),
            RustCargoConfigSourceEffect::Preserves
        );
        let nested = document("include='nested'");
        assert!(
            document("include='outer'")
                .with_included_documents(vec![Some((PathBuf::new(), nested))])
                .is_err()
        );
    }

    #[test]
    fn source_identity_requires_acquired_includes_and_external_layers() {
        for source in [
            "",
            "include='overrides.toml'",
            "[build]\ntarget='x86_64-unknown-linux-gnu'",
        ] {
            let partial = configuration(&[(".cargo/config.toml", source)]);
            assert_eq!(
                partial.source_effect(Path::new("")),
                RustCargoConfigSourceEffect::Unknown
            );
        }
        assert_eq!(
            configuration(&[])
                .with_acquisition_complete(true)
                .source_effect(Path::new("")),
            RustCargoConfigSourceEffect::Preserves
        );
    }

    #[test]
    fn stdlib_build_mode_requires_complete_interpretable_acquisition() {
        let path = Path::new("");
        assert_eq!(
            configuration(&[]).stdlib_build_mode(path),
            RustStdlibBuildMode::Unknown
        );
        assert_eq!(
            configuration(&[])
                .with_acquisition_complete(true)
                .stdlib_build_mode(path),
            RustStdlibBuildMode::Prebuilt
        );
        assert_eq!(
            configuration(&[])
                .with_unclassified_inputs()
                .with_acquisition_complete(true)
                .stdlib_build_mode(path),
            RustStdlibBuildMode::Unknown
        );
        for (source, expected) in [
            (
                "[unstable]\nbuild-std=['std','core']",
                RustStdlibBuildMode::BuildStd,
            ),
            ("[unstable]\nbuild-std=[]", RustStdlibBuildMode::Unknown),
            ("[unstable]\nbuild-std=true", RustStdlibBuildMode::Unknown),
            ("[unknown]\nkey=true", RustStdlibBuildMode::Unknown),
        ] {
            let config = configuration(&[(".cargo/config.toml", source)]);
            assert_eq!(config.stdlib_build_mode(path), RustStdlibBuildMode::Unknown);
            assert_eq!(
                config
                    .with_acquisition_complete(true)
                    .stdlib_build_mode(path),
                expected
            );
        }
        let config = configuration(&[
            (".cargo/config.toml", "[unstable]\nbuild-std=['std']"),
            (
                "nested/.cargo/config.toml",
                "[build]\ntarget='aarch64-unknown-linux-gnu'",
            ),
        ])
        .with_acquisition_complete(true);
        assert_eq!(
            config.stdlib_build_mode(Path::new("nested")),
            RustStdlibBuildMode::BuildStd
        );
    }

    #[test]
    fn build_std_digest_is_conditional_and_observes_malformed_input() {
        let base = digest("[build]\ntarget='x86_64-unknown-linux-gnu'");
        // Explicitly reproduce the pre-change projection for an absent key.
        let mut old = toml::Table::new();
        old.insert(
            "build".into(),
            toml::Value::Table(toml::Table::from_iter([(
                "target".into(),
                toml::Value::String("x86_64-unknown-linux-gnu".into()),
            )])),
        );
        let old = crate::cargo_manifest::canonical_toml_digest(
            b"cargo configuration",
            &toml::Value::Table(old),
            |_, _| false,
        );
        assert_eq!(base, old);
        assert_ne!(
            base,
            digest("[build]\ntarget='x86_64-unknown-linux-gnu'\n[unstable]\nbuild-std=['std']")
        );
        assert_ne!(digest(""), digest("unstable=true"));
    }

    #[brokk_bifrost_test_macros::hardwon(
        "#4460: a known target's target_has_atomic cfg left gated workspace modules unplaced"
    )]
    #[test]
    fn build_target_selects_that_target_cfg_set() {
        let atoms = configuration(&[(
            ".cargo/config.toml",
            "[build]\ntarget = \"x86_64-pc-windows-msvc\"\n",
        )])
        .cfg_atoms(Path::new(""));
        let expected = [
            "windows",
            "target_os = \"windows\"",
            "target_arch = \"x86_64\"",
            "target_family = \"windows\"",
            "target_pointer_width = \"64\"",
            "target_endian = \"little\"",
            "target_has_atomic = \"8\"",
            "target_has_atomic = \"16\"",
            "target_has_atomic = \"32\"",
            "target_has_atomic = \"64\"",
            "target_has_atomic = \"128\"",
            "target_has_atomic = \"ptr\"",
            "test",
            "debug_assertions",
        ];
        assert_eq!(
            atoms,
            expected.into_iter().map(str::to_string).collect(),
            "{atoms:?}"
        );

        let bare_metal = configuration(&[(
            ".cargo/config",
            "[build]\ntarget = [\"thumbv7em-none-eabihf\"]\n",
        )])
        .cfg_atoms(Path::new(""));
        assert!(
            bare_metal.contains("target_os = \"none\""),
            "{bare_metal:?}"
        );
        assert!(
            !bare_metal
                .iter()
                .any(|atom| atom.starts_with("target_family"))
        );
    }

    #[test]
    fn unknown_acquisition_atoms_are_the_known_atoms_that_read_no_configuration() {
        let known = RustCargoConfiguration::default().cfg_atoms(Path::new(""));
        let host = RustCargoConfiguration::default().host_cfg_atoms(Path::new(""));
        let unknown = RustCargoConfiguration::unknown_acquired();
        let expected = BTreeSet::from([
            "test".to_string(),
            "debug_assertions".to_string(),
            crate::cfg::INCOMPLETE_FEATURES_ATOM.to_string(),
        ]);
        assert_eq!(unknown.cfg_atoms(Path::new("")), expected);
        assert_eq!(unknown.host_cfg_atoms(Path::new("")), expected);
        // Every known atom is either one the unknown set keeps (its source is
        // not the configuration) or a target or rustflag atom it leaves out.
        let target = target_cfg_atoms(HOST_TRIPLE);
        for atom in known.iter().chain(&host) {
            assert!(
                expected.contains(atom) || target.contains(atom),
                "{atom} is neither configuration-free nor a target atom"
            );
        }
        assert!(
            tagged_cfg_atoms(None)
                .iter()
                .all(|(source, _)| *source == CfgAtomSource::Defaults)
        );
    }

    #[test]
    fn an_unknown_or_multiple_target_describes_no_target_values() {
        for source in [
            "[build]\ntarget = \"custom-target.json\"\n",
            "[build]\ntarget = [\"x86_64-unknown-linux-gnu\", \"wasm32-unknown-unknown\"]\n",
        ] {
            let atoms = configuration(&[(".cargo/config.toml", source)]).cfg_atoms(Path::new(""));
            assert_eq!(
                atoms,
                BTreeSet::from(["test".to_string(), "debug_assertions".to_string()]),
                "{source}"
            );
        }
    }

    #[test]
    fn deeper_files_win_and_levels_stop_at_the_build_directory() {
        let configuration = configuration(&[
            (
                ".cargo/config.toml",
                "[build]\ntarget = \"x86_64-pc-windows-msvc\"\n",
            ),
            (
                "ws/.cargo/config.toml",
                "[build]\ntarget = \"aarch64-apple-darwin\"\n",
            ),
            (
                "ws/member/.cargo/config.toml",
                "[build]\ntarget = \"wasm32-unknown-unknown\"\n",
            ),
        ]);
        let workspace = configuration.cfg_atoms(Path::new("ws"));
        assert!(workspace.contains("target_os = \"macos\""), "{workspace:?}");
        let other = configuration.cfg_atoms(Path::new("other"));
        assert!(other.contains("target_os = \"windows\""), "{other:?}");
    }

    #[test]
    fn rustflags_cfgs_follow_cargo_precedence() {
        let cases: &[(&str, &[&str])] = &[
            (
                "[build]\nrustflags = [\"--cfg\", \"plain\", \"--cfg=valued=\\\"v\\\"\", \"-Copt-level=1\"]\n",
                &["plain", "valued = \"v\""],
            ),
            (
                "[build]\nrustflags = \"--cfg spaced --cfg feature=\\\"f\\\"\"\n",
                &["spaced", "feature = \"f\""],
            ),
            // A matching target table replaces build.rustflags.
            (
                "[build]\nrustflags = [\"--cfg\", \"from_build\"]\n\
                 [target.x86_64-unknown-linux-gnu]\nrustflags = [\"--cfg\", \"from_triple\"]\n\
                 [target.'cfg(unix)']\nrustflags = [\"--cfg\", \"from_unix\"]\n\
                 [target.'cfg(windows)']\nrustflags = [\"--cfg\", \"from_windows\"]\n\
                 [target.aarch64-apple-darwin]\nrustflags = [\"--cfg\", \"from_other\"]\n",
                &["from_triple", "from_unix"],
            ),
            // A target table without rustflags does not.
            (
                "[build]\nrustflags = [\"--cfg\", \"from_build\"]\n\
                 [target.x86_64-unknown-linux-gnu]\nlinker = \"clang\"\n",
                &["from_build"],
            ),
            // An undecided key leaves the fallback unknown.
            (
                "[build]\nrustflags = [\"--cfg\", \"from_build\"]\n\
                 [target.'cfg(target_feature = \"avx2\")']\nrustflags = [\"--cfg\", \"avx\"]\n",
                &[],
            ),
            // A built-in target cfg cannot be set by a flag.
            (
                "[build]\nrustflags = [\"--cfg\", \"target_os=\\\"redox\\\"\"]\n",
                &[],
            ),
        ];
        for (flags, expected) in cases {
            let source = flags.replacen(
                "[build]\n",
                "[build]\ntarget = \"x86_64-unknown-linux-gnu\"\n",
                1,
            );
            let atoms = configuration(&[(".cargo/config.toml", &source)]).cfg_atoms(Path::new(""));
            let host = target_cfg_atoms("x86_64-unknown-linux-gnu");
            let flags = atoms
                .iter()
                .filter(|atom| {
                    !host.contains(*atom) && !matches!(atom.as_str(), "test" | "debug_assertions")
                })
                .map(String::as_str)
                .collect::<Vec<_>>();
            let mut expected = expected.to_vec();
            expected.sort_unstable();
            assert_eq!(flags, expected, "{flags:?} from {atoms:?}");
        }
    }

    #[test]
    fn a_custom_target_file_matches_target_tables_by_its_stem() {
        let atoms = configuration(&[(
            ".cargo/config.toml",
            "[build]\ntarget = \"targets/x86_64-kernel.json\"\n\
             [target.x86_64-kernel]\nrustflags = [\"--cfg\", \"kernel\"]\n",
        )])
        .cfg_atoms(Path::new(""));
        assert_eq!(
            atoms,
            ["debug_assertions", "kernel", "test"]
                .into_iter()
                .map(str::to_string)
                .collect(),
            "a custom target describes no values: {atoms:?}"
        );
    }

    #[test]
    fn rustflags_arrays_join_across_levels() {
        let atoms = configuration(&[
            (
                ".cargo/config.toml",
                "[build]\nrustflags = [\"--cfg\", \"outer\"]\n",
            ),
            (
                "ws/.cargo/config.toml",
                "[build]\nrustflags = [\"--cfg\", \"inner\"]\n",
            ),
        ])
        .cfg_atoms(Path::new("ws"));
        assert!(
            atoms.contains("outer") && atoms.contains("inner"),
            "{atoms:?}"
        );
    }

    #[test]
    fn patches_merge_by_name_with_the_defining_directory_as_base() {
        let configuration = configuration(&[
            (
                ".cargo/config.toml",
                "[patch.crates-io]\nfoo = { path = \"vendor/foo\" }\nbar = { path = \"vendor/bar\" }\n",
            ),
            (
                "ws/.cargo/config.toml",
                "[patch.crates-io]\nfoo = { path = \"local/foo\" }\n",
            ),
        ]);
        let mut patches = configuration
            .patches(Path::new("ws"), "crates-io")
            .into_iter()
            .map(|patch| {
                (
                    patch.name,
                    patch.entry["path"].as_str().unwrap().to_string(),
                    patch.base,
                )
            })
            .collect::<Vec<_>>();
        patches.sort();
        assert_eq!(
            patches,
            vec![
                ("bar".to_string(), "vendor/bar".to_string(), PathBuf::new()),
                (
                    "foo".to_string(),
                    "local/foo".to_string(),
                    PathBuf::from("ws")
                ),
            ]
        );
        assert!(
            configuration
                .patches(Path::new("ws"), "https://example.com/repo")
                .is_empty()
        );
    }

    #[test]
    fn topology_digest_follows_only_what_is_read() {
        const BASE: &str = "[build]\ntarget = \"x86_64-pc-windows-msvc\"\nrustflags = [\"--cfg\", \"x\"]\n\
             [target.'cfg(unix)']\nrustflags = [\"--cfg\", \"y\"]\n\
             [patch.crates-io]\nfoo = { path = \"foo\" }\n";
        let base = digest(BASE);
        for unread in [
            format!("# comment\n{BASE}"),
            format!("{BASE}[alias]\nb = \"build\"\n[env]\nX = \"1\"\n"),
            BASE.replace("[build]\n", "[build]\njobs = 4\n"),
            format!("{BASE}[target.x86_64-unknown-linux-gnu]\nlinker = \"clang\"\n"),
        ] {
            assert_eq!(digest(&unread), base, "{unread}");
        }
        for read in [
            BASE.replace("x86_64-pc-windows-msvc", "x86_64-unknown-linux-gnu"),
            BASE.replace("\"x\"", "\"z\""),
            BASE.replace("\"y\"", "\"z\""),
            BASE.replace("path = \"foo\"", "path = \"other\""),
            format!("{BASE}[target.x86_64-unknown-linux-gnu]\nrustflags = []\n"),
        ] {
            assert_ne!(digest(&read), base, "{read}");
        }
    }

    #[test]
    fn configuration_paths_are_config_files_in_a_cargo_directory() {
        for path in [
            ".cargo/config.toml",
            ".cargo/config",
            "sub/.cargo/config.toml",
        ] {
            assert!(is_cargo_configuration_path(Path::new(path)), "{path}");
        }
        for path in [
            "config.toml",
            "cargo/config.toml",
            ".cargo/other.toml",
            "Cargo.toml",
        ] {
            assert!(!is_cargo_configuration_path(Path::new(path)), "{path}");
        }
    }

    #[brokk_bifrost_test_macros::hardwon(
        "#12604: gnu and musl hosts shared a config view digest and host-dependency answer"
    )]
    #[test]
    fn host_triple_is_one_fact_of_the_view_digest_and_the_host_predicate() {
        let view = |host_triple: &str| acquired::RustCargoAcquiredConfigView {
            host_triple: host_triple.to_owned(),
            complete: true,
            ..Default::default()
        };
        let gnu = view("x86_64-unknown-linux-gnu");
        let musl = view("x86_64-unknown-linux-musl");
        assert_ne!(gnu.digest(), musl.digest());
        // The key of `[target.x86_64-unknown-linux-gnu.build-dependencies]`.
        let key = "x86_64-unknown-linux-gnu";
        let answer = |view: &acquired::RustCargoAcquiredConfigView| {
            RustCargoConfiguration::from_acquired_view(view, std::iter::empty())
                .host_dependency_predicate(key)
        };
        assert_eq!(answer(&gnu), Some(true));
        assert_eq!(answer(&musl), Some(false));
    }
}
