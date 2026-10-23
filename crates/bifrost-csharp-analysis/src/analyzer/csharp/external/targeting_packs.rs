//! Reference assemblies of the targeting packs a restore selected.
//!
//! An SDK-style project names its shared frameworks with `FrameworkReference`
//! items, and the SDK does not restore their reference assemblies as package
//! assets. `ProcessFrameworkReferences` matches each one to a
//! `KnownFrameworkReference` row from the SDK's bundled-versions file, uses the
//! targeting pack installed under `<dotnet root>/packs` when that version is
//! present, and otherwise adds a `PackageDownload` for it.
//! `ResolveTargetingPackAssets` then reads the pack's `data/FrameworkList.xml`.
//! `project.assets.json` therefore records the selection -- the framework
//! references, any pack download, and the SDK through
//! `runtimeIdentifierGraphPath` -- but none of the assemblies.
//!
//! This module replays that selection from those persisted inputs. It never
//! runs the SDK or evaluates MSBuild: it reads three kinds of data file at
//! paths it constructs, under SDK and package roots the host approves, and
//! enumerates no directory. Each assembly it returns carries the pack ID,
//! version, target framework and the assembly name the pack's file list
//! declares; production checks that name against the bytes it reads. Any
//! selection it cannot replay exactly becomes a diagnostic, which makes the
//! discovery incomplete rather than silently smaller.

use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use brokk_bifrost_analysis::analyzer::common::local_xml_name;
use quick_xml::Reader;
use quick_xml::events::Event;
use serde_json::Value;

use super::{CSharpAssetsResolution, DotNetAssetRole, ResolvedCSharpAssembly};
use crate::analyzer::csharp::compilation::{attribute, element_attributes};

const BUNDLED_VERSIONS_FILE: &str = "Microsoft.NETCoreSdk.BundledVersions.props";
const MAX_XML_BYTES: u64 = 4 * 1024 * 1024;
const MAX_XML_NODES: usize = 64 * 1024;
const MAX_FRAMEWORK_LIST_FILES: usize = 4_096;

/// Host locations that may hold a .NET SDK installation.
///
/// A restore records its SDK by absolute path, and `project.assets.json` is a
/// workspace file, so the recorded path is only followed into a root listed
/// here: `DOTNET_ROOT`, the per-user and system install locations, and a
/// repository-local `.dotnet`, which Arcade-style repositories install into.
pub(super) fn approved_sdk_roots(workspace_root: &Path) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Some(path) = std::env::var_os("DOTNET_ROOT").map(PathBuf::from) {
        roots.push(path);
    }
    if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
        roots.push(home.join(".dotnet"));
    }
    roots.push(workspace_root.join(".dotnet"));
    if cfg!(target_os = "macos") {
        roots.push(PathBuf::from("/usr/local/share/dotnet"));
        roots.push(PathBuf::from("/usr/local/share/dotnet/x64"));
    } else if cfg!(windows) {
        for variable in ["ProgramFiles", "ProgramFiles(x86)"] {
            if let Some(program_files) = std::env::var_os(variable).map(PathBuf::from) {
                roots.push(program_files.join("dotnet"));
            }
        }
    } else {
        roots.extend(
            [
                "/usr/share/dotnet",
                "/usr/lib/dotnet",
                "/usr/lib64/dotnet",
                "/usr/local/share/dotnet",
            ]
            .map(PathBuf::from),
        );
    }
    let mut roots: Vec<_> = roots
        .into_iter()
        .filter_map(|root| root.canonicalize().ok())
        .collect();
    roots.sort();
    roots.dedup();
    roots
}

/// The reference assemblies of every targeting pack that `assets` selects.
///
/// `package_folders` are the approved, canonical NuGet package folders the
/// restore used; `sdk_roots` come from [`approved_sdk_roots`].
pub(super) fn framework_reference_assemblies(
    assets_path: &Path,
    assets: &Value,
    package_folders: &[PathBuf],
    sdk_roots: &[PathBuf],
) -> CSharpAssetsResolution {
    let mut resolution = CSharpAssetsResolution::default();
    for (framework, entry) in assets
        .pointer("/project/frameworks")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
    {
        let Some(references) = entry
            .get("frameworkReferences")
            .and_then(Value::as_object)
            .filter(|references| !references.is_empty())
        else {
            continue;
        };
        let context = format!("{} framework {framework}", assets_path.display());
        let sdk = match recorded_sdk(entry, sdk_roots) {
            Ok(sdk) => sdk,
            Err(message) => {
                resolution.diagnostics.push(format!(
                    "{context} references {:?} but {message}",
                    references.keys().collect::<Vec<_>>()
                ));
                continue;
            }
        };
        let known = match known_framework_references(&sdk.directory.join(BUNDLED_VERSIONS_FILE)) {
            Ok(known) => known,
            Err(message) => {
                resolution.diagnostics.push(format!("{context}: {message}"));
                continue;
            }
        };
        // KnownFrameworkReference rows name the framework without a platform:
        // `net8.0-windows` selects the `net8.0` rows.
        let framework_version = framework.split('-').next().unwrap_or(framework);
        for name in references.keys() {
            match select_targeting_pack(
                name,
                framework_version,
                &known,
                entry,
                &sdk,
                package_folders,
            )
            .and_then(|pack| pack_assemblies(&pack, name, framework))
            {
                Ok(assemblies) => resolution.assemblies.extend(assemblies),
                Err(message) => resolution
                    .diagnostics
                    .push(format!("{context} framework reference {name}: {message}")),
            }
        }
    }
    resolution
}

struct RecordedSdk {
    /// The approved installation root holding `sdk/` and `packs/`.
    root: PathBuf,
    /// `<root>/sdk/<version>`.
    directory: PathBuf,
}

/// The SDK the restore ran under, from the runtime-identifier graph it read.
fn recorded_sdk(framework: &Value, sdk_roots: &[PathBuf]) -> Result<RecordedSdk, String> {
    let graph = framework
        .get("runtimeIdentifierGraphPath")
        .and_then(Value::as_str)
        .ok_or("the restore recorded no SDK (runtimeIdentifierGraphPath)")?;
    let graph = Path::new(graph);
    if !graph.is_absolute() {
        return Err(format!(
            "the recorded SDK path {} is not absolute",
            graph.display()
        ));
    }
    let graph = graph.canonicalize().map_err(|error| {
        format!(
            "the recorded SDK file {} is unavailable: {error}",
            graph.display()
        )
    })?;
    let directory = graph.parent().expect("a canonical file has a parent");
    let sdks = directory
        .parent()
        .filter(|sdks| sdks.file_name().is_some_and(|name| name == "sdk"))
        .ok_or_else(|| format!("{} is not inside an SDK installation", graph.display()))?;
    let root = sdks.parent().expect("an sdk directory has a parent");
    if !sdk_roots.iter().any(|approved| approved == root) {
        return Err(format!(
            "the recorded SDK installation {} is not an approved SDK root {sdk_roots:?}",
            root.display()
        ));
    }
    Ok(RecordedSdk {
        root: root.to_owned(),
        directory: directory.to_owned(),
    })
}

#[derive(Debug)]
struct KnownFrameworkReference {
    name: String,
    target_framework: String,
    targeting_pack_name: Option<String>,
    targeting_pack_version: Option<String>,
    conditioned: bool,
}

fn known_framework_references(path: &Path) -> Result<Vec<KnownFrameworkReference>, String> {
    let mut rows = Vec::new();
    for_each_element(path, |element, attributes, conditioned| {
        if element != "KnownFrameworkReference" {
            return Ok(());
        }
        if let (Some(name), Some(target_framework)) = (
            attribute(attributes, "Include"),
            attribute(attributes, "TargetFramework"),
        ) {
            rows.push(KnownFrameworkReference {
                name: name.to_owned(),
                target_framework: target_framework.to_owned(),
                targeting_pack_name: attribute(attributes, "TargetingPackName").map(str::to_owned),
                targeting_pack_version: attribute(attributes, "TargetingPackVersion")
                    .map(str::to_owned),
                conditioned,
            });
        }
        Ok(())
    })?;
    Ok(rows)
}

struct SelectedPack {
    id: String,
    version: String,
    directory: PathBuf,
}

/// Replays `ProcessFrameworkReferences` for one framework reference.
fn select_targeting_pack(
    name: &str,
    framework_version: &str,
    known: &[KnownFrameworkReference],
    framework: &Value,
    sdk: &RecordedSdk,
    package_folders: &[PathBuf],
) -> Result<SelectedPack, String> {
    let rows: Vec<_> = known
        .iter()
        .filter(|row| {
            row.name.eq_ignore_ascii_case(name) && row.target_framework == framework_version
        })
        .collect();
    if rows.is_empty() {
        return Err(format!(
            "SDK {} has no KnownFrameworkReference for {framework_version}",
            sdk.directory.display()
        ));
    }
    if rows.iter().any(|row| row.conditioned) {
        return Err(format!(
            "SDK {} selects its KnownFrameworkReference by an MSBuild condition",
            sdk.directory.display()
        ));
    }
    let mut packs: Vec<_> = rows
        .iter()
        .map(|row| (&row.targeting_pack_name, &row.targeting_pack_version))
        .collect();
    packs.sort();
    packs.dedup();
    let [(Some(id), Some(bundled_version))] = packs.as_slice() else {
        return Err(format!(
            "SDK {} has no single targeting pack for {framework_version}: {rows:?}",
            sdk.directory.display()
        ));
    };
    if !is_path_component(id) || !is_path_component(bundled_version) {
        return Err(format!(
            "targeting pack {id} {bundled_version} is not a literal package identity"
        ));
    }
    // A downloaded pack means the SDK did not have this version installed;
    // NuGet placed it in the restore's package folders instead.
    let download = framework
        .get("downloadDependencies")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|download| {
            download
                .get("name")
                .and_then(Value::as_str)
                .is_some_and(|download| download.eq_ignore_ascii_case(id))
        })
        .map(|download| download.get("version").and_then(Value::as_str))
        .collect::<Vec<_>>();
    let (version, directory) = match download.as_slice() {
        [] => (
            bundled_version.clone(),
            contained_directory(
                &sdk.root,
                &Path::new("packs").join(id).join(bundled_version),
            )?,
        ),
        [Some(range)] => {
            let version = exact_version(range)
                .filter(|version| is_path_component(version))
                .ok_or_else(|| format!("pack download {id} {range} is not one exact version"))?;
            let relative = Path::new(&id.to_ascii_lowercase()).join(version.to_ascii_lowercase());
            let found: Vec<_> = package_folders
                .iter()
                .filter_map(|folder| contained_directory(folder, &relative).ok())
                .collect();
            let [directory] = found.as_slice() else {
                return Err(format!(
                    "downloaded pack {id} {version} is in {} approved package folders, not one: {found:?}",
                    found.len()
                ));
            };
            (version.to_owned(), directory.clone())
        }
        _ => {
            return Err(format!(
                "the restore recorded pack download {id} as {download:?}"
            ));
        }
    };
    Ok(SelectedPack {
        id: id.clone(),
        version,
        directory,
    })
}

/// Replays `ResolveTargetingPackAssets` for one selected pack.
fn pack_assemblies(
    pack: &SelectedPack,
    framework_reference: &str,
    target: &str,
) -> Result<Vec<ResolvedCSharpAssembly>, String> {
    let list = pack.directory.join("data").join("FrameworkList.xml");
    let mut assemblies = Vec::new();
    let mut missing = Vec::new();
    for_each_element(&list, |element, attributes, _| {
        if element == "FileList" {
            let framework_name = attribute(attributes, "FrameworkName");
            if framework_name.is_some_and(|name| !name.eq_ignore_ascii_case(framework_reference)) {
                return Err(format!(
                    "{} lists framework {framework_name:?}",
                    list.display()
                ));
            }
            return Ok(());
        }
        if element != "File" {
            return Ok(());
        }
        // The SDK references managed files that are not opted out; analyzers
        // and native files share the list.
        if attribute(attributes, "Type").is_some_and(|kind| kind != "Managed")
            || attribute(attributes, "ReferencedByDefault")
                .is_some_and(|value| value.eq_ignore_ascii_case("false"))
        {
            return Ok(());
        }
        let (Some(relative), Some(assembly_name)) = (
            attribute(attributes, "Path"),
            attribute(attributes, "AssemblyName"),
        ) else {
            return Err(format!(
                "{} lists a file without a path and assembly name",
                list.display()
            ));
        };
        if assemblies.len() + missing.len() == MAX_FRAMEWORK_LIST_FILES {
            return Err(format!(
                "{} lists more than {MAX_FRAMEWORK_LIST_FILES} reference files",
                list.display()
            ));
        }
        match contained_file(&pack.directory, relative) {
            Some(path) => assemblies.push(ResolvedCSharpAssembly {
                path,
                package_name: Some(pack.id.clone()),
                package_version: Some(pack.version.clone()),
                target: Some(target.to_owned()),
                configuration: None,
                role: DotNetAssetRole::Reference,
                project_reference: false,
                assembly_name: Some(assembly_name.to_owned()),
                framework_reference: Some(framework_reference.to_owned()),
            }),
            None => missing.push(relative.to_owned()),
        }
        Ok(())
    })?;
    if !missing.is_empty() {
        return Err(format!(
            "pack {} {} lists reference files that are not regular files inside {}: {missing:?}",
            pack.id,
            pack.version,
            pack.directory.display()
        ));
    }
    if assemblies.is_empty() {
        return Err(format!("{} lists no reference assemblies", list.display()));
    }
    Ok(assemblies)
}

/// Calls `visit` with the local name and attributes of every element in the
/// XML file at `path`, in document order, and whether it or an ancestor
/// carries an MSBuild `Condition`.
fn for_each_element(
    path: &Path,
    mut visit: impl FnMut(&str, &[(String, String)], bool) -> Result<(), String>,
) -> Result<(), String> {
    let mut text = String::new();
    fs::File::open(path)
        .and_then(|file| file.take(MAX_XML_BYTES + 1).read_to_string(&mut text))
        .map_err(|error| format!("could not read {}: {error}", path.display()))?;
    if text.len() as u64 > MAX_XML_BYTES {
        return Err(format!("{} exceeds {MAX_XML_BYTES} bytes", path.display()));
    }
    let malformed = || format!("{} is not well-formed XML", path.display());
    let mut reader = Reader::from_str(&text);
    // Whether each open element is conditioned, itself or by an ancestor.
    let mut conditioned_stack: Vec<bool> = Vec::new();
    let mut nodes = 0usize;
    loop {
        let (start, is_empty) = match reader.read_event().map_err(|_| malformed())? {
            Event::Start(start) => (start, false),
            Event::Empty(empty) => (empty, true),
            Event::End(_) => {
                conditioned_stack.pop().ok_or_else(malformed)?;
                continue;
            }
            Event::Eof => break,
            _ => continue,
        };
        nodes += 1;
        if nodes > MAX_XML_NODES {
            return Err(format!(
                "{} exceeds {MAX_XML_NODES} elements",
                path.display()
            ));
        }
        let name = local_xml_name(start.name().as_ref()).ok_or_else(malformed)?;
        let attributes = element_attributes(&reader, &start).ok_or_else(malformed)?;
        let conditioned = conditioned_stack.last().copied().unwrap_or(false)
            || attribute(&attributes, "Condition").is_some();
        visit(&name, &attributes, conditioned)?;
        if !is_empty {
            conditioned_stack.push(conditioned);
        }
    }
    if conditioned_stack.is_empty() {
        Ok(())
    } else {
        Err(malformed())
    }
}

/// `[1.2.3, 1.2.3]`, the exact range a `PackageDownload` restores.
fn exact_version(range: &str) -> Option<&str> {
    let (lower, upper) = range
        .strip_prefix('[')?
        .strip_suffix(']')?
        .split_once(',')?;
    let lower = lower.trim();
    (!lower.is_empty() && lower == upper.trim()).then_some(lower)
}

fn is_path_component(value: &str) -> bool {
    let mut components = Path::new(value).components();
    matches!(components.next(), Some(Component::Normal(component)) if component == value)
        && components.next().is_none()
}

/// `root/relative` as a canonical directory that stays inside `root`.
fn contained_directory(root: &Path, relative: &Path) -> Result<PathBuf, String> {
    let candidate = root.join(relative);
    match candidate.canonicalize() {
        Ok(directory) if directory.starts_with(root) && directory.is_dir() => Ok(directory),
        Ok(directory) => Err(format!(
            "{} resolves to {}, outside {}",
            candidate.display(),
            directory.display(),
            root.display()
        )),
        Err(error) => Err(format!("{} is not installed: {error}", candidate.display())),
    }
}

/// A file a pack lists by relative path, when it is a regular file inside the
/// pack after resolving links.
fn contained_file(pack: &Path, relative: &str) -> Option<PathBuf> {
    let relative = Path::new(relative);
    if !relative
        .components()
        .all(|component| matches!(component, Component::Normal(_)))
    {
        return None;
    }
    pack.join(relative)
        .canonicalize()
        .ok()
        .filter(|path| path.starts_with(pack) && path.is_file())
}
