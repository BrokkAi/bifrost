//! Cargo configuration files, as Rust analysis reads them (#3768).
//!
//! Cargo reads `.cargo/config.toml`, or the legacy `.cargo/config`, in the
//! directory a build starts in and in each of its ancestors, then
//! `$CARGO_HOME/config.toml`, and merges what it finds: a deeper file's value
//! replaces a shallower one, except that two arrays join with the deeper
//! file's items last, and tables merge key by key. Analysis starts where
//! `cargo check` for a Cargo workspace runs, the workspace root, and stops at
//! the project root. Levels above the project root and `$CARGO_HOME` are
//! outside the workspace: nothing watches them, and they are not read.
//! Environment variables (`RUSTFLAGS`, `CARGO_ENCODED_RUSTFLAGS`,
//! `CARGO_BUILD_TARGET`) belong to one build's process rather than to the
//! workspace, and they are not read either.
//!
//! Three settings change what rustc compiles, and only they are read:
//! - `[patch]`, which Cargo routes merge with the workspace manifest's patch
//!   tables, the configuration winning for a name both patch;
//! - `build.target`, which selects the target whose cfg set applies;
//! - `--cfg` in rustflags: every matching `target.<triple>.rustflags` and
//!   `target.<cfg>.rustflags` joined, or else `build.rustflags`.
//!
//! All state belongs to the request that built it.

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

/// One parsed Cargo configuration file.
#[derive(Clone, Debug)]
pub struct RustCargoConfigDocument {
    value: toml::Table,
}

impl RustCargoConfigDocument {
    pub fn from_source_bytes(source: &[u8]) -> Result<Self, String> {
        let source = std::str::from_utf8(source)
            .map_err(|error| format!("Cargo configuration is not UTF-8: {error}"))?;
        let value = toml::from_str(source)
            .map_err(|error| format!("invalid Cargo configuration: {error}"))?;
        Ok(Self { value })
    }

    /// Digest of the settings this module reads: `[patch]`, `build.target`,
    /// `build.rustflags` and each `target.<key>.rustflags`. An edit to
    /// anything else (aliases, `[env]`, `[net]`, a linker) keeps it.
    pub fn topology_digest(&self) -> [u8; 32] {
        let mut read = toml::Table::new();
        if let Some(patch) = self.value.get("patch") {
            read.insert("patch".to_string(), patch.clone());
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
#[derive(Clone, Debug, Default)]
pub struct RustCargoConfiguration {
    files: HashMap<PathBuf, RustCargoConfigDocument>,
}

impl RustCargoConfiguration {
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
            files: by_directory
                .into_iter()
                .map(|(directory, (_, document))| (directory, document))
                .collect(),
        }
    }

    /// Read the configuration file of `directory` from disk, if it has one
    /// that parses.
    pub(crate) fn read_level(
        root: &Path,
        directory: &Path,
    ) -> Option<(PathBuf, RustCargoConfigDocument)> {
        ["config", "config.toml"].into_iter().find_map(|name| {
            let path = directory.join(".cargo").join(name);
            let source = std::fs::read(root.join(&path)).ok()?;
            Some((
                path,
                RustCargoConfigDocument::from_source_bytes(&source).ok()?,
            ))
        })
    }

    /// The files Cargo reads for a build started in `directory`, shallowest
    /// first, so that merging in order lets a deeper file win.
    fn levels<'a>(&'a self, directory: &'a Path) -> Vec<(&'a Path, &'a RustCargoConfigDocument)> {
        let mut levels = directory
            .ancestors()
            .filter_map(|level| self.files.get(level).map(|document| (level, document)))
            .collect::<Vec<_>>();
        levels.reverse();
        levels
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
        let levels = self.levels(directory);
        let mut targets = match merged(levels.iter().filter_map(|(_, file)| file.build("target"))) {
            Some(toml::Value::Array(items)) => items
                .iter()
                .filter_map(toml::Value::as_str)
                .map(str::to_string)
                .collect(),
            Some(toml::Value::String(target)) => vec![target],
            _ => Vec::new(),
        };
        if targets.is_empty() {
            targets.push(HOST_TRIPLE.to_string());
        }
        let mut atoms = BTreeSet::from(["test".to_string(), "debug_assertions".to_string()]);
        if let [target] = targets.as_slice() {
            let target_atoms = target_cfg_atoms(target);
            atoms.extend(rustflag_cfg_atoms(&levels, target, &target_atoms));
            atoms.extend(target_atoms);
        } else {
            let flags = targets
                .iter()
                .map(|target| rustflag_cfg_atoms(&levels, target, &target_cfg_atoms(target)))
                .reduce(|left, right| left.intersection(&right).cloned().collect())
                .expect("several targets");
            atoms.extend(flags);
        }
        atoms
    }

    /// The `[patch.<source>]` entries of the configuration Cargo reads for a
    /// build started in `directory`, each merged across the files that define
    /// it.
    pub(crate) fn patches(&self, directory: &Path, source: &str) -> Vec<RustCargoConfigPatch> {
        let mut patches = Vec::<RustCargoConfigPatch>::new();
        for (base, file) in self.levels(directory) {
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
}
