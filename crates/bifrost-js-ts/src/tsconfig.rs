//! Resolution of the non-relative module specifiers a JS/TS workspace writes:
//! `tsconfig.json` (and `jsconfig.json`) path aliases
//! (`compilerOptions.baseUrl` + `compilerOptions.paths`), and the names the
//! workspace's own npm packages carry.
//!
//! `scan_usages` and the JS/TS import graph follow *relative* specifiers (`./`, `../`)
//! out of the box, but real monorepos import almost everything through aliases like
//! `@/lib/foo` or `~/utils`. Without alias resolution those callers land in the
//! "external dependency, skip" bucket, so the graph systematically under-counts
//! production callers. This module maps an aliased specifier back to the candidate
//! files on disk, the way `tsserver` / the TS compiler
//! do: walk up to the governing config, follow `extends`, build the `baseUrl`/`paths`
//! map, and expand the specifier against it.
//!
//! Resolution is per *importing file* (a monorepo has several configs with different
//! alias maps), and matches modern TS semantics: child config wins on merge, `paths`
//! are resolved relative to `baseUrl` (or to the declaring config's directory when
//! `baseUrl` is absent), longest matching prefix wins, and a pattern may map to several
//! roots tried in order.
//!
//! An alias map does not cover a monorepo's other non-relative form: a bare
//! specifier that names one of the workspace's own packages
//! (`@tanstack/react-query`). That one is answered from
//! [`crate::workspace_packages`], whose index this resolver builds once, on
//! demand, from the workspace listing it was constructed over.

use crate::workspace_packages::WorkspacePackageIndex;
use brokk_bifrost_core::analyzer::ProjectFile;
use brokk_bifrost_core::analyzer::project::Project;
use brokk_bifrost_core::hash::HashMap;
use brokk_bifrost_core::path_normalization::NormalizePath;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

/// Config file names consulted when walking up from an importing file, in priority
/// order. `tsconfig.json` wins over `jsconfig.json` when both sit in the same directory.
const CONFIG_FILENAMES: [&str; 2] = ["tsconfig.json", "jsconfig.json"];

/// Guards against pathological / circular `extends` chains (per ancestor chain).
const MAX_EXTENDS_DEPTH: usize = 16;

/// Total config reads allowed while resolving one governing config's `extends` graph.
/// Each `extends` entry resolves as an independent chain (so diamonds resolve correctly,
/// matching `tsc`), which means a shared parent can be read more than once; this budget
/// keeps a hostile DAG from fanning out into exponential reads.
const MAX_CONFIG_READS: u32 = 256;

/// Resolves non-relative specifiers for one repository root, caching parsed configs
/// so the hot import-resolution loop parses each `tsconfig.json` at most once, and
/// caching the workspace package index so it reads each `package.json` at most once.
/// Cheap to construct (`new` just stores the project handle); all filesystem work is
/// lazy.
pub struct AliasResolver {
    root: PathBuf,
    /// Symlink-resolved `root`, used to contain `extends` targets to the repo. Falls back
    /// to `root` when canonicalization fails (e.g. the root was deleted out from under us).
    canonical_root: PathBuf,
    /// The workspace this resolver answers for. Held rather than listed eagerly so
    /// constructing a resolver never forces a workspace walk; the listing is the
    /// project's own cached one, so the index inherits its ignore rules.
    project: Arc<dyn Project>,
    /// `directory of importing file` → nearest governing config file (if any).
    nearest: Mutex<HashMap<PathBuf, Option<PathBuf>>>,
    /// `config file path` → its fully-resolved alias map (extends already followed).
    /// `None` means the file was unreadable/unparseable or declared no usable `paths`.
    maps: Mutex<HashMap<PathBuf, Arc<Option<AliasMap>>>>,
    /// The workspace's own npm packages, built on the first bare specifier that no
    /// alias claims.
    packages: OnceLock<Arc<WorkspacePackageIndex>>,
}

/// Hard cap on a config file's size before we read it. Real `tsconfig.json`/`jsconfig.json`
/// files are a few KB; this only exists to stop a hostile repo from OOM-ing the analyzer
/// with a giant (or `extends`-reachable) config.
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

/// The effective TypeScript standard-library selection for one source file.
///
/// The names are the canonical names used by TypeScript's `lib.*.d.ts` files:
/// `lib.es5.d.ts` is `es5`, and `lib.dom.d.ts` is `dom`.  A complete selection
/// is safe to turn into activation evidence.  An incomplete selection is not:
/// callers must leave every built-in library inactive rather than guessing
/// which declaration surface a malformed configuration intended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeScriptLibrarySelection {
    libraries: Vec<String>,
    explicit: bool,
    diagnostics: Vec<String>,
}

impl TypeScriptLibrarySelection {
    pub fn complete(libraries: Vec<String>, explicit: bool) -> Self {
        Self {
            libraries,
            explicit,
            diagnostics: Vec::new(),
        }
    }

    pub fn incomplete(diagnostic: impl Into<String>) -> Self {
        Self {
            libraries: Vec::new(),
            explicit: false,
            diagnostics: vec![diagnostic.into()],
        }
    }

    /// Canonical libraries selected by the effective configuration.
    pub fn libraries(&self) -> &[String] {
        &self.libraries
    }

    /// Whether `compilerOptions.lib` explicitly supplied the selection.
    pub fn is_explicit(&self) -> bool {
        self.explicit
    }

    /// A malformed or unsupported config cannot safely activate a library.
    pub fn is_complete(&self) -> bool {
        self.diagnostics.is_empty()
    }

    pub fn diagnostics(&self) -> &[String] {
        &self.diagnostics
    }
}

/// A flattened alias map ready for matching. `base_dir` is the absolute directory that
/// `replacements` are joined against.
#[derive(Debug, Clone)]
struct AliasMap {
    base_dir: PathBuf,
    entries: Vec<AliasEntry>,
}

#[derive(Debug, Clone)]
struct AliasEntry {
    pattern: Pattern,
    replacements: Vec<String>,
}

#[derive(Debug, Clone)]
enum Pattern {
    /// `"@/env": [...]` — matches the specifier verbatim.
    Exact(String),
    /// `"@/*": [...]` — `prefix`/`suffix` are the text around the single `*`.
    Wildcard { prefix: String, suffix: String },
}

impl AliasResolver {
    pub fn new(project: Arc<dyn Project>) -> Self {
        let root = project.root().to_path_buf();
        let canonical_root = root.canonicalize().unwrap_or_else(|_| root.clone());
        Self {
            root,
            canonical_root,
            project,
            nearest: Mutex::new(HashMap::default()),
            maps: Mutex::new(HashMap::default()),
            packages: OnceLock::new(),
        }
    }

    /// Candidate base paths (relative to the repo root, no extension) for a non-relative
    /// `specifier` imported from `source_file`, in TS precedence order. Empty when the
    /// specifier matches no alias. Extension/index resolution is left to the caller so a
    /// single source of truth (`collect_candidate_paths`) decides what exists on disk.
    pub fn candidate_bases(&self, source_file: &ProjectFile, specifier: &str) -> Vec<PathBuf> {
        let Some(config_path) = self.nearest_config(source_file) else {
            return Vec::new();
        };
        let map = self.alias_map(&config_path);
        let Some(map) = map.as_ref() else {
            return Vec::new();
        };

        let Some(replacements) = best_match(&map.entries, specifier) else {
            return Vec::new();
        };

        let mut bases = Vec::new();
        for replacement in replacements {
            let absolute = map.base_dir.join(&replacement).normalize();
            let Ok(relative) = absolute.strip_prefix(&self.root) else {
                // Alias points outside the repo (e.g. a sibling package not indexed);
                // nothing the graph can resolve to, so skip it.
                continue;
            };
            bases.push(relative.to_path_buf());
        }
        bases
    }

    /// Candidate entry paths (relative to the repo root) for a bare `specifier`
    /// that names one of the workspace's own npm packages, in the order the
    /// package's manifest offers them. Empty when the specifier names no
    /// workspace package -- which is how an external npm dependency keeps
    /// failing closed -- and empty when the specifier carries a subpath.
    ///
    /// A subpath (`@scope/pkg/deep`) is refused rather than guessed: answering
    /// it means resolving the package's `exports` subpath map, including its
    /// pattern forms, and no workspace reference in the corpus needs one. The
    /// boundary is pinned by a test so a later change is a deliberate one.
    pub fn workspace_package_bases(&self, specifier: &str) -> Vec<PathBuf> {
        let Some((package_name, subpath)) =
            crate::imports::npm_package_of_module_specifier(specifier)
        else {
            return Vec::new();
        };
        if subpath.is_some() {
            return Vec::new();
        }
        self.workspace_packages().entry_bases(package_name).to_vec()
    }

    /// Return the effective built-in TypeScript libraries for `source_file`.
    ///
    /// This deliberately shares the same nearest-config and JSONC/`extends`
    /// reader as path aliases.  A missing config means TypeScript's pinned
    /// default target (`ES5`); a malformed or unsupported config returns an
    /// incomplete selection with no libraries, so callers cannot activate an
    /// uncertain built-in surface.
    pub fn effective_library_selection(
        &self,
        source_file: &ProjectFile,
    ) -> TypeScriptLibrarySelection {
        let Some(config_path) = self.nearest_config(source_file) else {
            return TypeScriptLibrarySelection::incomplete(
                "no governing tsconfig could be found for TypeScript library selection",
            );
        };
        effective_library_selection_for_config(&config_path, &self.canonical_root)
    }

    /// The workspace package index, built once per resolver on first use.
    fn workspace_packages(&self) -> &WorkspacePackageIndex {
        self.packages.get_or_init(|| {
            let index = match self.project.all_files_shared() {
                Ok(files) => WorkspacePackageIndex::build(&self.root, &files),
                // A workspace that cannot be listed has no readable manifests
                // either; the empty index leaves every bare specifier external,
                // which is the behavior that predates this index.
                Err(_) => WorkspacePackageIndex::default(),
            };
            Arc::new(index)
        })
    }

    /// Nearest `tsconfig.json`/`jsconfig.json` governing `source_file`, walking up from
    /// the file's directory to the repo root. Cached per directory.
    fn nearest_config(&self, source_file: &ProjectFile) -> Option<PathBuf> {
        let dir = source_file.parent();
        if let Some(cached) = self.nearest.lock().unwrap().get(&dir) {
            return cached.clone();
        }
        let resolved = self.find_config_from(&dir);
        self.nearest.lock().unwrap().insert(dir, resolved.clone());
        resolved
    }

    fn find_config_from(&self, start_rel_dir: &Path) -> Option<PathBuf> {
        let mut current: Option<&Path> = Some(start_rel_dir);
        loop {
            let rel_dir = current.unwrap_or_else(|| Path::new(""));
            let abs_dir = self.root.join(rel_dir);
            for name in CONFIG_FILENAMES {
                let candidate = abs_dir.join(name);
                if candidate.is_file() {
                    return Some(candidate);
                }
            }
            let dir = current?;
            current = dir.parent();
        }
    }

    /// Fully-resolved alias map for a config file, following `extends`. Cached.
    fn alias_map(&self, config_path: &Path) -> Arc<Option<AliasMap>> {
        if let Some(cached) = self.maps.lock().unwrap().get(config_path) {
            return cached.clone();
        }
        let resolved = Arc::new(build_alias_map(config_path, &self.canonical_root));
        self.maps
            .lock()
            .unwrap()
            .insert(config_path.to_path_buf(), resolved.clone());
        resolved
    }
}

/// Resolve a config path with the same bounded JSONC/`extends` reader used by
/// [`AliasResolver`]. This form is for activation/discovery code that already
/// has a config file path but does not own an `Arc<dyn Project>`.
pub fn effective_library_selection_for_config(
    config_path: &Path,
    canonical_root: &Path,
) -> TypeScriptLibrarySelection {
    let Some(root) = canonical_root
        .canonicalize()
        .ok()
        .filter(|path| path.is_dir())
    else {
        return TypeScriptLibrarySelection::incomplete(
            "TypeScript library selection root is not a readable directory",
        );
    };
    let Some(config) = config_path
        .canonicalize()
        .ok()
        .filter(|path| path.is_file() && path.starts_with(&root))
    else {
        return TypeScriptLibrarySelection::incomplete(
            "TypeScript library config is not a regular file under the workspace root",
        );
    };
    let mut budget = MAX_CONFIG_READS;
    let Some(effective) = resolve_effective(&config, &[], &mut budget, &root) else {
        return TypeScriptLibrarySelection::incomplete(
            "tsconfig could not be parsed or its extends chain is unavailable",
        );
    };
    effective.library_selection()
}

/// Pick the alias entry that best matches `specifier` and return its replacements. Exact
/// matches win over wildcards; among wildcards the longest matching prefix wins (TS
/// semantics). Wildcard replacements have their `*` substituted with the matched segment.
fn best_match(entries: &[AliasEntry], specifier: &str) -> Option<Vec<String>> {
    let mut best: Option<(usize, &AliasEntry, Option<String>)> = None;
    for entry in entries {
        match &entry.pattern {
            Pattern::Exact(pattern) => {
                if pattern == specifier {
                    // Exact match is unbeatable; return immediately.
                    return Some(entry.replacements.clone());
                }
            }
            Pattern::Wildcard { prefix, suffix } => {
                if specifier.len() >= prefix.len() + suffix.len()
                    && specifier.starts_with(prefix.as_str())
                    && specifier.ends_with(suffix.as_str())
                {
                    let matched = &specifier[prefix.len()..specifier.len() - suffix.len()];
                    let score = prefix.len();
                    if best
                        .as_ref()
                        .is_none_or(|(best_score, _, _)| score > *best_score)
                    {
                        best = Some((score, entry, Some(matched.to_string())));
                    }
                }
            }
        }
    }

    let (_, entry, matched) = best?;
    let matched = matched.unwrap_or_default();
    Some(
        entry
            .replacements
            .iter()
            .map(|replacement| replacement.replacen('*', &matched, 1))
            .collect(),
    )
}

/// Parse a config file and flatten its `extends` chain into a single alias map.
/// `canonical_root` bounds `extends` resolution to the repo (see [`existing_config_path`]).
fn build_alias_map(config_path: &Path, canonical_root: &Path) -> Option<AliasMap> {
    let mut budget = MAX_CONFIG_READS;
    let effective = resolve_effective(config_path, &[], &mut budget, canonical_root)?;
    let (paths_dir, entries) = effective.paths?;
    if entries.is_empty() {
        return None;
    }
    // `paths` are resolved relative to `baseUrl` when present, otherwise relative to the
    // directory of the config that declared `paths` (modern TS behavior).
    let base_dir = match effective.base_url {
        Some((dir, value)) => dir.join(value).normalize(),
        None => paths_dir,
    };
    Some(AliasMap { base_dir, entries })
}

/// `compilerOptions` values that survive the `extends` merge, each tagged with the
/// absolute directory of the config file that declared them (so relative `baseUrl`/`paths`
/// resolve against the right location).
#[derive(Default)]
struct EffectiveConfig {
    base_url: Option<(PathBuf, String)>,
    paths: Option<(PathBuf, Vec<AliasEntry>)>,
    lib: Option<LibrarySetting>,
    target: Option<TargetSetting>,
    library_invalid: bool,
}

#[derive(Debug, Clone)]
enum LibrarySetting {
    Explicit(Vec<String>),
    Invalid(String),
}

#[derive(Debug, Clone)]
enum TargetSetting {
    Target(String),
    Invalid(String),
}

impl EffectiveConfig {
    /// Overlay `later` on top of `self`, per-field, with `later` winning on conflict.
    /// Used to merge `extends` parents left-to-right (rightmost wins) and to apply the
    /// child config over its inherited base. Fields are independent: a `baseUrl` from one
    /// config and `paths` from another both survive, matching `tsc`.
    fn overlay(self, later: EffectiveConfig) -> EffectiveConfig {
        EffectiveConfig {
            base_url: later.base_url.or(self.base_url),
            paths: later.paths.or(self.paths),
            lib: later.lib.or(self.lib),
            target: later.target.or(self.target),
            library_invalid: self.library_invalid || later.library_invalid,
        }
    }

    fn library_selection(self) -> TypeScriptLibrarySelection {
        if self.library_invalid {
            return TypeScriptLibrarySelection::incomplete(
                "tsconfig contains malformed or unsupported compilerOptions",
            );
        }
        if let Some(lib) = self.lib {
            return match lib {
                LibrarySetting::Explicit(libraries) => {
                    TypeScriptLibrarySelection::complete(libraries, true)
                }
                LibrarySetting::Invalid(diagnostic) => {
                    TypeScriptLibrarySelection::incomplete(diagnostic)
                }
            };
        }
        let target = match self.target {
            Some(TargetSetting::Target(target)) => target,
            Some(TargetSetting::Invalid(diagnostic)) => {
                return TypeScriptLibrarySelection::incomplete(diagnostic);
            }
            None => "es5".to_owned(),
        };
        TypeScriptLibrarySelection::complete(default_libraries(&target), false)
    }
}

/// Resolve a config's effective `baseUrl`/`paths`, following `extends`. `ancestors` is the
/// chain of configs currently being resolved on this branch (for cycle detection only, so
/// sibling `extends` entries resolve independently and diamonds merge correctly). `budget`
/// is shared across the whole graph and bounds total reads.
fn resolve_effective(
    config_path: &Path,
    ancestors: &[PathBuf],
    budget: &mut u32,
    canonical_root: &Path,
) -> Option<EffectiveConfig> {
    if ancestors.len() > MAX_EXTENDS_DEPTH
        || ancestors.iter().any(|seen| seen == config_path)
        || *budget == 0
    {
        return None;
    }
    *budget -= 1;

    // Cap the read so a hostile repo can't OOM the analyzer with a giant config.
    if std::fs::metadata(config_path).ok()?.len() > MAX_CONFIG_BYTES {
        return None;
    }
    let text = std::fs::read_to_string(config_path).ok()?;
    let value: serde_json::Value = serde_json::from_str(&strip_jsonc(&text)).ok()?;
    if !value.is_object() {
        return Some(EffectiveConfig {
            library_invalid: true,
            ..EffectiveConfig::default()
        });
    }
    let dir = config_path
        .parent()
        .unwrap_or_else(|| Path::new(""))
        .to_path_buf();

    let mut chain = ancestors.to_vec();
    chain.push(config_path.to_path_buf());

    // Fold every resolved `extends` parent left-to-right: TS merges all parents, not just
    // the first (rightmost wins on conflict). Each entry gets the same ancestor chain, so a
    // grandparent shared by two siblings (a diamond) contributes to both, like `tsc`.
    let mut inherited = EffectiveConfig::default();
    let extends = match value.get("extends") {
        None => Vec::new(),
        Some(value) => match extends_targets(value) {
            Ok(targets) => targets,
            Err(()) => {
                inherited.library_invalid = true;
                Vec::new()
            }
        },
    };
    for target in extends {
        let Some(path) = resolve_extends_path(&dir, &target, canonical_root) else {
            inherited.library_invalid = true;
            continue;
        };
        match resolve_effective(&path, &chain, budget, canonical_root) {
            Some(parent) => inherited = inherited.overlay(parent),
            None => inherited.library_invalid = true,
        }
    }

    let compiler_options_malformed = value
        .get("compilerOptions")
        .is_some_and(|options| !options.is_object());
    let compiler_options = value
        .get("compilerOptions")
        .filter(|options| options.is_object());

    let own_base_url = compiler_options
        .and_then(|opts| opts.get("baseUrl"))
        .and_then(serde_json::Value::as_str)
        .map(|value| (dir.clone(), value.to_string()));

    let own_paths = compiler_options
        .and_then(|opts| opts.get("paths"))
        .and_then(parse_paths)
        .map(|entries| (dir.clone(), entries));

    let own_lib = compiler_options
        .and_then(|opts| opts.get("lib"))
        .map(|value| {
            parse_library_names(value).map_or_else(
                || {
                    LibrarySetting::Invalid(
                        "compilerOptions.lib must contain only supported library names".to_owned(),
                    )
                },
                LibrarySetting::Explicit,
            )
        });
    let own_target = compiler_options
        .and_then(|opts| opts.get("target"))
        .map(
            |value| match value.as_str().and_then(canonical_target_name) {
                Some(target) => TargetSetting::Target(target.to_owned()),
                None => TargetSetting::Invalid(
                    "compilerOptions.target must be a supported TypeScript target string"
                        .to_owned(),
                ),
            },
        );
    let own_library_invalid = compiler_options_malformed
        || compiler_options.is_some_and(|opts| {
            opts.get("lib").is_some_and(|value| {
                !value.is_array()
                    || value
                        .as_array()
                        .is_some_and(|items| items.iter().any(|item| item.as_str().is_none()))
            }) || opts
                .get("target")
                .is_some_and(|value| value.as_str().and_then(canonical_target_name).is_none())
        });

    // Child wins over everything it inherits; `paths` are replaced wholesale, not
    // deep-merged (TS semantics).
    let own = EffectiveConfig {
        base_url: own_base_url,
        paths: own_paths,
        lib: own_lib,
        target: own_target,
        library_invalid: own_library_invalid,
    };
    Some(inherited.overlay(own))
}

/// `extends` may be a single string or (TS 5.0+) an array of strings applied left to right
/// with later entries winning. Returned in source order; the caller folds them so the
/// rightmost wins on conflict.
fn extends_targets(value: &serde_json::Value) -> Result<Vec<String>, ()> {
    match value {
        serde_json::Value::String(single) if !single.trim().is_empty() => Ok(vec![single.clone()]),
        serde_json::Value::Array(items) => items
            .iter()
            .map(
                |item| match item.as_str().filter(|value| !value.trim().is_empty()) {
                    Some(value) => Ok(value.to_owned()),
                    None => Err(()),
                },
            )
            .collect(),
        _ => Err(()),
    }
}

/// Resolve an `extends` specifier to a config file path. Handles relative paths
/// (`"../tsconfig.base.json"`, with or without the `.json` suffix) and a best-effort
/// `node_modules` lookup for package specifiers (`"@repo/tsconfig/base.json"`). Every
/// candidate is contained to `canonical_root`, and absolute specifiers are refused
/// outright — the analyzed repo is untrusted, so `extends` must never escape it.
fn resolve_extends_path(
    from_dir: &Path,
    specifier: &str,
    canonical_root: &Path,
) -> Option<PathBuf> {
    if Path::new(specifier).is_absolute() {
        return None;
    }
    if specifier.starts_with('.') {
        return existing_config_path(&from_dir.join(specifier), canonical_root);
    }
    // Bare/package specifier: search `node_modules` from this dir upward.
    let mut current = Some(from_dir);
    while let Some(dir) = current {
        let base = dir.join("node_modules").join(specifier);
        if let Some(found) = existing_config_path(&base, canonical_root) {
            return Some(found);
        }
        current = dir.parent();
    }
    None
}

/// Given a path that may omit the extension or point at a directory, return the concrete
/// config file: the path as-is, with `.json` appended, or `<path>/tsconfig.json`. Only
/// files whose symlink-resolved location stays under `canonical_root` are returned, so a
/// malicious `extends` (`"../../../etc/passwd"`, or a repo symlink pointing out of tree)
/// can never be read.
fn existing_config_path(path: &Path, canonical_root: &Path) -> Option<PathBuf> {
    let direct = path.to_path_buf().normalize();
    if is_contained_file(&direct, canonical_root) {
        return Some(direct);
    }
    let with_json = PathBuf::from(format!("{}.json", path.to_string_lossy())).normalize();
    if is_contained_file(&with_json, canonical_root) {
        return Some(with_json);
    }
    let nested = path.join("tsconfig.json").normalize();
    if is_contained_file(&nested, canonical_root) {
        return Some(nested);
    }
    None
}

/// True when `path` is a regular file whose symlink-resolved location is inside
/// `canonical_root`. Canonicalization resolves symlinks, so a within-tree symlink that
/// points outside the repo is rejected too.
fn is_contained_file(path: &Path, canonical_root: &Path) -> bool {
    match path.canonicalize() {
        Ok(resolved) => resolved.is_file() && resolved.starts_with(canonical_root),
        Err(_) => false,
    }
}

fn parse_paths(value: &serde_json::Value) -> Option<Vec<AliasEntry>> {
    let object = value.as_object()?;
    let mut entries = Vec::with_capacity(object.len());
    for (pattern, replacements) in object {
        let replacements: Vec<String> = replacements
            .as_array()?
            .iter()
            .filter_map(|item| item.as_str().map(str::to_string))
            .collect();
        if replacements.is_empty() {
            continue;
        }
        entries.push(AliasEntry {
            pattern: parse_pattern(pattern),
            replacements,
        });
    }
    (!entries.is_empty()).then_some(entries)
}

/// Normalize one `compilerOptions.lib` entry to the spelling used by a
/// `lib.<name>.d.ts` file.  TypeScript accepts both `ES2015` and `es6`; it
/// also accepts a path-like `lib.es2015.d.ts` spelling in a few tool versions,
/// so accepting that exact basename keeps the reader compatible without
/// treating arbitrary paths as declarations.
pub fn canonical_library_name(value: &str) -> Option<String> {
    let mut name = value.trim().to_ascii_lowercase();
    if let Some(stripped) = name.strip_prefix("lib.") {
        name = stripped.to_owned();
    }
    if let Some(stripped) = name.strip_suffix(".d.ts") {
        name = stripped.to_owned();
    }
    if name == "es6" {
        name = "es2015".to_owned();
    } else if name == "es7" {
        name = "es2016".to_owned();
    }
    let supported = matches!(
        name.as_str(),
        "es5"
            | "es2015"
            | "es2015.core"
            | "es2015.collection"
            | "es2015.generator"
            | "es2015.iterable"
            | "es2015.promise"
            | "es2015.proxy"
            | "es2015.reflect"
            | "es2015.symbol"
            | "es2015.symbol.wellknown"
            | "es2016"
            | "es2016.array.include"
            | "es2016.full"
            | "es2016.intl"
            | "es2017"
            | "es2017.arraybuffer"
            | "es2017.date"
            | "es2017.full"
            | "es2017.object"
            | "es2017.sharedmemory"
            | "es2017.string"
            | "es2017.intl"
            | "es2017.typedarrays"
            | "es2018"
            | "es2018.asyncgenerator"
            | "es2018.asynciterable"
            | "es2018.intl"
            | "es2018.promise"
            | "es2018.regexp"
            | "es2018.full"
            | "es2019"
            | "es2019.array"
            | "es2019.full"
            | "es2019.object"
            | "es2019.string"
            | "es2019.symbol"
            | "es2019.intl"
            | "es2020"
            | "es2020.bigint"
            | "es2020.date"
            | "es2020.promise"
            | "es2020.sharedmemory"
            | "es2020.string"
            | "es2020.symbol.wellknown"
            | "es2020.intl"
            | "es2020.number"
            | "es2020.full"
            | "es2021"
            | "es2021.full"
            | "es2021.promise"
            | "es2021.string"
            | "es2021.weakref"
            | "es2021.intl"
            | "es2022"
            | "es2022.array"
            | "es2022.error"
            | "es2022.object"
            | "es2022.regexp"
            | "es2022.string"
            | "es2022.full"
            | "es2022.intl"
            | "es2023"
            | "es2023.array"
            | "es2023.collection"
            | "es2023.full"
            | "es2023.intl"
            | "es2024"
            | "es2024.arraybuffer"
            | "es2024.collection"
            | "es2024.object"
            | "es2024.promise"
            | "es2024.regexp"
            | "es2024.sharedmemory"
            | "es2024.string"
            | "es2024.full"
            | "es2025"
            | "es2025.collection"
            | "es2025.float16"
            | "es2025.full"
            | "es2025.intl"
            | "es2025.iterator"
            | "es2025.promise"
            | "es2025.regexp"
            | "esnext"
            | "esnext.array"
            | "esnext.collection"
            | "esnext.date"
            | "esnext.intl"
            | "esnext.disposable"
            | "esnext.decorators"
            | "esnext.error"
            | "esnext.full"
            | "esnext.sharedmemory"
            | "esnext.temporal"
            | "esnext.typedarrays"
            | "dom"
            | "dom.asynciterable"
            | "dom.iterable"
            | "scripthost"
            | "webworker"
            | "webworker.asynciterable"
            | "webworker.importscripts"
            | "webworker.iterable"
            | "decorators"
            | "decorators.legacy"
    );
    supported.then_some(name)
}

fn parse_library_names(value: &serde_json::Value) -> Option<Vec<String>> {
    let items = value.as_array()?;
    let mut names = items
        .iter()
        .map(|item| item.as_str().and_then(canonical_library_name))
        .collect::<Option<Vec<_>>>()?;
    names.sort_unstable();
    names.dedup();
    Some(names)
}

fn canonical_target_name(value: &str) -> Option<&'static str> {
    match value.trim().to_ascii_lowercase().as_str() {
        "es3" => Some("es3"),
        "es5" => Some("es5"),
        "es6" | "es2015" => Some("es2015"),
        "es7" | "es2016" => Some("es2016"),
        "es2017" => Some("es2017"),
        "es2018" => Some("es2018"),
        "es2019" => Some("es2019"),
        "es2020" => Some("es2020"),
        "es2021" => Some("es2021"),
        "es2022" => Some("es2022"),
        "es2023" => Some("es2023"),
        "es2024" => Some("es2024"),
        "es2025" => Some("es2025"),
        "esnext" | "latest" => Some("esnext"),
        _ => None,
    }
}

fn default_libraries(target: &str) -> Vec<String> {
    let mut libraries = vec!["dom".to_owned(), "scripthost".to_owned()];
    if target != "es3" {
        libraries.push(target.to_owned());
    } else {
        libraries.push("es5".to_owned());
    }
    if target != "es3" && target != "es5" {
        libraries.push("dom.iterable".to_owned());
    }
    libraries.sort_unstable();
    libraries.dedup();
    libraries
}

/// Expand selected aggregate libraries through the pinned TypeScript 7.0.2
/// triple-slash closure. This is the activation-side counterpart to the
/// producer's source-derived closure: the pack is fixed to this manifest, so
/// the mapping remains deterministic even when the workspace has no package
/// source tree available to the config reader.
pub fn typescript_library_activation_closure(selected: &[String]) -> Vec<String> {
    let mut closure = selected
        .iter()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    let mut stack = selected.to_vec();
    while let Some(name) = stack.pop() {
        for dependency in pinned_library_references(&name) {
            if canonical_library_name(dependency).is_some()
                && closure.insert((*dependency).to_owned())
            {
                stack.push((*dependency).to_owned());
            }
        }
    }
    closure.into_iter().collect()
}

fn pinned_library_references(name: &str) -> &'static [&'static str] {
    match name {
        "es5" => &["decorators", "decorators.legacy"],
        "es2015" => &[
            "es5",
            "es2015.core",
            "es2015.collection",
            "es2015.iterable",
            "es2015.generator",
            "es2015.promise",
            "es2015.proxy",
            "es2015.reflect",
            "es2015.symbol",
            "es2015.symbol.wellknown",
        ],
        "es2016" => &["es2015", "es2016.array.include", "es2016.intl"],
        "es2017" => &[
            "es2016",
            "es2017.arraybuffer",
            "es2017.date",
            "es2017.intl",
            "es2017.object",
            "es2017.sharedmemory",
            "es2017.string",
            "es2017.typedarrays",
        ],
        "es2018" => &[
            "es2017",
            "es2018.asyncgenerator",
            "es2018.asynciterable",
            "es2018.intl",
            "es2018.promise",
            "es2018.regexp",
        ],
        "es2019" => &[
            "es2018",
            "es2019.array",
            "es2019.object",
            "es2019.string",
            "es2019.symbol",
            "es2019.intl",
        ],
        "es2020" => &[
            "es2019",
            "es2020.bigint",
            "es2020.date",
            "es2020.number",
            "es2020.promise",
            "es2020.sharedmemory",
            "es2020.string",
            "es2020.symbol.wellknown",
            "es2020.intl",
        ],
        "es2021" => &[
            "es2020",
            "es2021.intl",
            "es2021.promise",
            "es2021.string",
            "es2021.weakref",
        ],
        "es2022" => &[
            "es2021",
            "es2022.array",
            "es2022.error",
            "es2022.intl",
            "es2022.object",
            "es2022.regexp",
            "es2022.string",
        ],
        "es2023" => &["es2022", "es2023.array", "es2023.collection", "es2023.intl"],
        "es2024" => &[
            "es2023",
            "es2024.arraybuffer",
            "es2024.collection",
            "es2024.object",
            "es2024.promise",
            "es2024.regexp",
            "es2024.sharedmemory",
            "es2024.string",
        ],
        "es2025" => &[
            "es2024",
            "es2025.collection",
            "es2025.float16",
            "es2025.intl",
            "es2025.iterator",
            "es2025.promise",
            "es2025.regexp",
        ],
        "esnext" => &[
            "es2025",
            "esnext.array",
            "esnext.collection",
            "esnext.date",
            "esnext.decorators",
            "esnext.disposable",
            "esnext.error",
            "esnext.intl",
            "esnext.sharedmemory",
            "esnext.temporal",
            "esnext.typedarrays",
        ],
        "dom" => &["es2015", "es2018.asynciterable"],
        "es2016.full" => &["es2016", "dom", "scripthost", "webworker"],
        "es2017.full" => &["es2017", "dom", "scripthost", "webworker"],
        "es2018.full" => &["es2018", "dom", "scripthost", "webworker"],
        "es2019.full" => &["es2019", "dom", "scripthost", "webworker"],
        "es2020.full" => &["es2020", "dom", "scripthost", "webworker"],
        "es2021.full" => &["es2021", "dom", "scripthost", "webworker"],
        "es2022.full" => &["es2022", "dom", "scripthost", "webworker"],
        "es2023.full" => &["es2023", "dom", "scripthost", "webworker"],
        "es2024.full" => &["es2024", "dom", "scripthost", "webworker"],
        "es2025.full" => &["es2025", "dom", "scripthost", "webworker"],
        "esnext.full" => &["esnext", "dom", "scripthost", "webworker"],
        _ => &[],
    }
}

fn parse_pattern(pattern: &str) -> Pattern {
    match pattern.split_once('*') {
        Some((prefix, suffix)) => Pattern::Wildcard {
            prefix: prefix.to_string(),
            suffix: suffix.to_string(),
        },
        None => Pattern::Exact(pattern.to_string()),
    }
}

/// Strip JSONC niceties (`//` and `/* */` comments, trailing commas) that `tsconfig.json`
/// permits but `serde_json` rejects. String contents are preserved verbatim.
///
/// Scans byte-by-byte: every delimiter it cares about (`/ " \ * \n`) is ASCII, and UTF-8
/// continuation bytes are all `>= 0x80`, so multibyte characters in comments or strings
/// pass through untouched.
fn strip_jsonc(input: &str) -> String {
    // Editors (notably VS Code on Windows) save `tsconfig.json` with a UTF-8 BOM, which
    // `serde_json` rejects; `tsc` strips it first, so we do too.
    let input = input.strip_prefix('\u{feff}').unwrap_or(input);
    let bytes = input.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    let mut in_string = false;
    while i < bytes.len() {
        let b = bytes[i];
        if in_string {
            out.push(b);
            if b == b'\\' && i + 1 < bytes.len() {
                // Preserve escaped character (incl. an escaped quote) verbatim.
                out.push(bytes[i + 1]);
                i += 2;
                continue;
            }
            if b == b'"' {
                in_string = false;
            }
            i += 1;
            continue;
        }
        match b {
            b'"' => {
                in_string = true;
                out.push(b'"');
                i += 1;
            }
            b'/' if i + 1 < bytes.len() && bytes[i + 1] == b'/' => {
                i += 2;
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if i + 1 < bytes.len() && bytes[i + 1] == b'*' => {
                i += 2;
                while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                    i += 1;
                }
                i += 2;
            }
            _ => {
                out.push(b);
                i += 1;
            }
        }
    }
    strip_trailing_commas(&out)
}

/// Remove commas that immediately precede a closing `}`/`]` (ignoring whitespace), which
/// `tsconfig` allows but `serde_json` does not. Runs after comment stripping. `input` is
/// the byte output of [`strip_jsonc`] (guaranteed valid UTF-8 since only whole bytes were
/// copied through).
fn strip_trailing_commas(input: &[u8]) -> String {
    let mut out: Vec<u8> = Vec::with_capacity(input.len());
    let mut in_string = false;
    for (i, &b) in input.iter().enumerate() {
        if in_string {
            out.push(b);
            if b == b'"' && !preceded_by_odd_backslashes(input, i) {
                in_string = false;
            }
            continue;
        }
        if b == b'"' {
            in_string = true;
            out.push(b'"');
            continue;
        }
        if b == b',' {
            let next = input[i + 1..]
                .iter()
                .find(|c| !c.is_ascii_whitespace())
                .copied();
            if matches!(next, Some(b'}') | Some(b']')) {
                continue;
            }
        }
        out.push(b);
    }
    String::from_utf8(out).unwrap_or_default()
}

fn preceded_by_odd_backslashes(bytes: &[u8], index: usize) -> bool {
    let mut count = 0;
    let mut j = index;
    while j > 0 && bytes[j - 1] == b'\\' {
        count += 1;
        j -= 1;
    }
    count % 2 == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(pattern: &str, replacements: &[&str]) -> AliasEntry {
        AliasEntry {
            pattern: parse_pattern(pattern),
            replacements: replacements.iter().map(|r| r.to_string()).collect(),
        }
    }

    #[test]
    fn matches_trailing_wildcard() {
        let entries = vec![entry("@/*", &["src/*"])];
        assert_eq!(
            best_match(&entries, "@/lib/foo"),
            Some(vec!["src/lib/foo".to_string()])
        );
    }

    #[test]
    fn longest_prefix_wins() {
        let entries = vec![
            entry("@/*", &["src/*"]),
            entry("@/components/*", &["src/ui/components/*"]),
        ];
        assert_eq!(
            best_match(&entries, "@/components/button"),
            Some(vec!["src/ui/components/button".to_string()])
        );
    }

    #[test]
    fn exact_beats_wildcard() {
        let entries = vec![entry("@/*", &["src/*"]), entry("@/env", &["env.ts"])];
        assert_eq!(
            best_match(&entries, "@/env"),
            Some(vec!["env.ts".to_string()])
        );
    }

    #[test]
    fn multiple_roots_preserved_in_order() {
        let entries = vec![entry("@/*", &["src/*", "generated/*"])];
        assert_eq!(
            best_match(&entries, "@/foo"),
            Some(vec!["src/foo".to_string(), "generated/foo".to_string()])
        );
    }

    #[test]
    fn non_matching_specifier_returns_none() {
        let entries = vec![entry("@/*", &["src/*"])];
        assert_eq!(best_match(&entries, "react"), None);
    }

    #[test]
    fn strips_line_and_block_comments_and_trailing_commas() {
        let raw = r#"{
            // a comment
            "compilerOptions": {
                /* block */ "baseUrl": ".",
                "paths": { "@/*": ["src/*"], },
            },
        }"#;
        let value: serde_json::Value = serde_json::from_str(&strip_jsonc(raw)).unwrap();
        assert_eq!(value["compilerOptions"]["baseUrl"], ".");
    }

    #[test]
    fn preserves_non_ascii_bytes() {
        // A unicode comment must not corrupt the following string values.
        let raw = "{\n // café — ünïcode ☕\n \"paths\": { \"@/*\": [\"src/ café/*\"] }\n}";
        let value: serde_json::Value = serde_json::from_str(&strip_jsonc(raw)).unwrap();
        assert_eq!(value["paths"]["@/*"][0], "src/ café/*");
    }

    #[test]
    fn preserves_comment_like_text_inside_strings() {
        let raw = r#"{ "paths": { "@/*": ["./not//a//comment/*"] } }"#;
        let value: serde_json::Value = serde_json::from_str(&strip_jsonc(raw)).unwrap();
        assert_eq!(value["paths"]["@/*"][0], "./not//a//comment/*");
    }

    #[test]
    fn strips_leading_utf8_bom() {
        // VS Code on Windows writes a BOM; serde_json would otherwise reject it.
        let raw = "\u{feff}{ \"compilerOptions\": { \"baseUrl\": \".\" } }";
        let value: serde_json::Value = serde_json::from_str(&strip_jsonc(raw)).unwrap();
        assert_eq!(value["compilerOptions"]["baseUrl"], ".");
    }

    fn resolver_for(root: &Path) -> AliasResolver {
        AliasResolver::new(Arc::new(
            brokk_bifrost_core::analyzer::project::FilesystemProject::new(root)
                .expect("temporary alias-resolution root is a directory"),
        ))
    }

    fn deliver_in(root: &Path) -> ProjectFile {
        ProjectFile::new(root.to_path_buf(), PathBuf::from("src/app/deliver.ts"))
    }

    /// An out-of-root config whose alias maps *back into* the repo (`repo/src/*`). If
    /// `extends` wrongly followed it, `candidate_bases` would return a non-empty in-root
    /// base — so an empty result proves the out-of-root file was never read (not merely
    /// that its target landed outside root and got dropped by the later strip_prefix).
    const OUT_OF_ROOT_CONFIG: &str =
        r#"{ "compilerOptions": { "baseUrl": ".", "paths": { "@/*": ["repo/src/*"] } } }"#;

    #[test]
    fn extends_relative_traversal_out_of_root_is_refused() {
        let base = tempfile::tempdir().unwrap();
        let root = base.path().join("repo");
        std::fs::create_dir_all(root.join("src/app")).unwrap();
        // The escaping target sits beside the repo, reachable only via `../`.
        std::fs::write(base.path().join("secret.json"), OUT_OF_ROOT_CONFIG).unwrap();
        std::fs::write(
            root.join("tsconfig.json"),
            r#"{ "extends": "../secret.json" }"#,
        )
        .unwrap();

        let bases = resolver_for(&root).candidate_bases(&deliver_in(&root), "@/lib/validate");
        assert!(
            bases.is_empty(),
            "extends must not escape the repo root via `../`, got {bases:?}"
        );
    }

    #[test]
    fn extends_absolute_path_is_refused() {
        let base = tempfile::tempdir().unwrap();
        let root = base.path().join("repo");
        std::fs::create_dir_all(root.join("src/app")).unwrap();
        let outside = base.path().join("secret.json");
        std::fs::write(&outside, OUT_OF_ROOT_CONFIG).unwrap();
        let config = format!(
            r#"{{ "extends": {} }}"#,
            serde_json::json!(outside.to_string_lossy())
        );
        std::fs::write(root.join("tsconfig.json"), config).unwrap();

        let bases = resolver_for(&root).candidate_bases(&deliver_in(&root), "@/lib/validate");
        assert!(
            bases.is_empty(),
            "absolute `extends` paths must be refused, got {bases:?}"
        );
    }

    #[test]
    fn oversized_config_is_skipped() {
        let base = tempfile::tempdir().unwrap();
        let root = base.path();
        std::fs::create_dir_all(root.join("src/app")).unwrap();
        let mut huge = String::from(
            r#"{ "compilerOptions": { "baseUrl": ".", "paths": { "@/*": ["src/*"] } }, "_pad": ""#,
        );
        huge.push_str(&"x".repeat((MAX_CONFIG_BYTES as usize) + 1));
        huge.push_str("\" }");
        std::fs::write(root.join("tsconfig.json"), huge).unwrap();

        let bases = resolver_for(root).candidate_bases(&deliver_in(root), "@/lib/validate");
        assert!(
            bases.is_empty(),
            "a config larger than the cap must be skipped, got {bases:?}"
        );
    }

    #[test]
    fn explicit_lib_wins_and_is_canonical() {
        let base = tempfile::tempdir().unwrap();
        let root = base.path();
        std::fs::create_dir_all(root.join("src/app")).unwrap();
        std::fs::write(
            root.join("tsconfig.json"),
            r#"{ "compilerOptions": { "target": "ES2020", "lib": ["ES2015", "DOM"] } }"#,
        )
        .unwrap();
        let selection = resolver_for(root).effective_library_selection(&deliver_in(root));
        assert!(selection.is_complete(), "{selection:?}");
        assert!(selection.is_explicit());
        assert_eq!(selection.libraries(), ["dom", "es2015"]);
    }

    #[test]
    fn target_default_includes_dom_and_target_library() {
        let base = tempfile::tempdir().unwrap();
        let root = base.path();
        std::fs::create_dir_all(root.join("src/app")).unwrap();
        std::fs::write(
            root.join("tsconfig.json"),
            r#"{ "compilerOptions": { "target": "ES2020" } }"#,
        )
        .unwrap();
        let selection = resolver_for(root).effective_library_selection(&deliver_in(root));
        assert!(selection.is_complete(), "{selection:?}");
        assert!(!selection.is_explicit());
        assert_eq!(
            selection.libraries(),
            ["dom", "dom.iterable", "es2020", "scripthost"]
        );
    }

    #[test]
    fn inherited_lib_is_used_and_malformed_lib_is_incomplete() {
        let base = tempfile::tempdir().unwrap();
        let root = base.path();
        std::fs::create_dir_all(root.join("src/app")).unwrap();
        std::fs::write(
            root.join("base.json"),
            r#"{ "compilerOptions": { "lib": ["ES5", "DOM"] } }"#,
        )
        .unwrap();
        std::fs::write(
            root.join("tsconfig.json"),
            r#"{ "extends": "./base.json" }"#,
        )
        .unwrap();
        let resolver = resolver_for(root);
        let inherited = resolver.effective_library_selection(&deliver_in(root));
        assert_eq!(inherited.libraries(), ["dom", "es5"]);
        std::fs::write(
            root.join("tsconfig.json"),
            r#"{ "compilerOptions": { "lib": ["not-a-pinned-library"] } }"#,
        )
        .unwrap();
        let malformed = resolver.effective_library_selection(&deliver_in(root));
        assert!(!malformed.is_complete());
        assert!(malformed.libraries().is_empty());
    }

    #[test]
    fn malformed_shapes_and_missing_config_fail_closed() {
        let base = tempfile::tempdir().unwrap();
        let root = base.path();
        std::fs::create_dir_all(root.join("src")).unwrap();
        let source = deliver_in(root);
        let resolver = resolver_for(root);
        let missing = resolver.effective_library_selection(&source);
        assert!(!missing.is_complete());
        std::fs::write(root.join("tsconfig.json"), r#"{"compilerOptions": []}"#).unwrap();
        let malformed_options = resolver.effective_library_selection(&source);
        assert!(!malformed_options.is_complete());
        std::fs::write(
            root.join("base.json"),
            r#"{"compilerOptions":{"lib":["es5"]}}"#,
        )
        .unwrap();
        std::fs::write(
            root.join("tsconfig.json"),
            r#"{"extends":["./base.json",42]}"#,
        )
        .unwrap();
        let malformed_extends = resolver.effective_library_selection(&source);
        assert!(!malformed_extends.is_complete());
        assert!(canonical_library_name("es2015.full").is_none());
        assert!(canonical_library_name("esnext.iterator").is_none());
    }

    #[test]
    fn config_outside_root_is_not_eligible_for_library_selection() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(
            outside.path().join("tsconfig.json"),
            r#"{"compilerOptions":{"lib":["dom"]}}"#,
        )
        .unwrap();
        let selection = effective_library_selection_for_config(
            &outside.path().join("tsconfig.json"),
            root.path(),
        );
        assert!(!selection.is_complete());
    }

    #[test]
    fn aggregate_activation_closure_keeps_es_core_without_dom() {
        let es2015 = typescript_library_activation_closure(&["es2015".to_owned()]);
        assert!(es2015.contains(&"es5".to_owned()));
        assert!(es2015.contains(&"es2015.core".to_owned()));
        assert!(!es2015.contains(&"dom".to_owned()));
        let es2020 = typescript_library_activation_closure(&["es2020".to_owned()]);
        assert!(es2020.contains(&"es2019".to_owned()));
        assert!(es2020.contains(&"es2020.promise".to_owned()));
        assert!(!es2020.contains(&"dom".to_owned()));
    }
}
