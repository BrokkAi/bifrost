//! The workspace's own npm packages, indexed by the name other workspace files
//! import them under.
//!
//! A monorepo package is addressed by its `package.json` `name`, not by a path:
//! `import { QueryClient } from '@tanstack/react-query'` inside the TanStack
//! repository means `packages/react-query`, and no `tsconfig.json` alias says
//! so. Without this index every such import lands in the "external dependency,
//! skip" bucket, so component and symbol references across workspace packages
//! fail closed even though the declaration is sitting in the same checkout.
//!
//! The index answers one question: which *entry* files can a bare specifier
//! naming a workspace package address? A published package points at build
//! output, which a source checkout does not contain, so the entry targets are
//! collected from every field that can name one and ordered so the ones that
//! name workspace source come first. `collect_candidate_paths` then decides
//! which of them exists, exactly as it does for a relative specifier.

use brokk_bifrost_core::analyzer::ProjectFile;
use brokk_bifrost_core::hash::HashMap;
use brokk_bifrost_core::path_normalization::NormalizePath;
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Hard cap on a manifest's size before we read it. Real `package.json` files
/// are a few KB; this only exists so a hostile repo cannot OOM the analyzer.
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;

/// Depth cap for the `exports` condition walk. Real condition maps nest two or
/// three levels (`{"import": {"types": ..., "default": ...}}`); this bounds a
/// hostile one.
const MAX_CONDITION_DEPTH: u8 = 8;

/// Conditions that name workspace source directly. A monorepo adds them so its
/// own tooling reads `src/` instead of the build output.
const SOURCE_CONDITIONS: [&str; 2] = ["source", "development"];

/// Conditions the ecosystem defines for a *published* package. Every one of
/// them normally names build output, so they are tried after a custom
/// condition, which a monorepo declares precisely to point at its source (the
/// TanStack repository's `@tanstack/custom-condition` is the case that made
/// this ordering necessary).
const RUNTIME_CONDITIONS: [&str; 16] = [
    "import",
    "module",
    "module-sync",
    "require",
    "node",
    "node-addons",
    "deno",
    "bun",
    "browser",
    "react-native",
    "electron",
    "worker",
    "production",
    "style",
    "sass",
    "default",
];

/// Conditions that name generated declaration files. Tried last: a `.d.ts` is
/// build output whose source counterpart is what a workspace reference wants.
const TYPE_CONDITIONS: [&str; 2] = ["types", "typings"];

/// Rank of an entry target. Lower is tried first; the order is the whole
/// selection rule, so it is spelled once, here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum EntryRank {
    /// An `exports` target reached without passing through any condition.
    ExportsUnconditioned,
    /// `exports` under an explicit source condition.
    ExportsSource,
    /// `exports` under a condition the ecosystem does not define, which in a
    /// monorepo is a private "resolve to my source" switch.
    ExportsCustom,
    /// `exports` under a published runtime condition.
    ExportsRuntime,
    /// `exports` under a declaration-file condition.
    ExportsTypes,
    /// The legacy `main` field.
    Main,
    /// The legacy `module` field.
    Module,
}

fn condition_rank(name: &str) -> EntryRank {
    if SOURCE_CONDITIONS.contains(&name) {
        EntryRank::ExportsSource
    } else if TYPE_CONDITIONS.contains(&name) {
        EntryRank::ExportsTypes
    } else if RUNTIME_CONDITIONS.contains(&name) {
        EntryRank::ExportsRuntime
    } else {
        EntryRank::ExportsCustom
    }
}

/// Every workspace package name, mapped to the entry paths a bare specifier
/// naming it may address, in the order they are tried.
#[derive(Debug, Default)]
pub struct WorkspacePackageIndex {
    entries: HashMap<String, Vec<PathBuf>>,
}

impl WorkspacePackageIndex {
    /// Read every workspace `package.json` in `files` and index the named ones.
    ///
    /// `files` is the analyzer's own workspace listing, so the index inherits
    /// its ignore rules and never walks the tree itself. A committed
    /// `node_modules` tree is excluded explicitly: an installed dependency is
    /// an external package that happens to be checked in, not a member of the
    /// workspace, and admitting it would resolve external imports into vendored
    /// copies.
    pub fn build(root: &Path, files: &BTreeSet<ProjectFile>) -> Self {
        let mut entries: HashMap<String, Vec<PathBuf>> = HashMap::default();
        for file in files {
            let rel = file.rel_path();
            if rel.file_name() != Some(std::ffi::OsStr::new("package.json")) {
                continue;
            }
            if rel
                .components()
                .any(|component| component.as_os_str() == "node_modules")
            {
                continue;
            }
            let Some(package_dir) = rel.parent() else {
                continue;
            };
            let Some((name, targets)) = read_manifest(&root.join(rel)) else {
                continue;
            };
            let bases = entries.entry(name).or_default();
            for target in targets {
                // A target is written relative to the package directory. Anything
                // that leaves the workspace is unindexable, and refusing it also
                // keeps a hostile `"main": "../../../etc/passwd"` out of the
                // candidate set.
                let absolute = root.join(package_dir).join(target).normalize();
                let Ok(relative) = absolute.strip_prefix(root) else {
                    continue;
                };
                let relative = relative.to_path_buf();
                if !bases.contains(&relative) {
                    bases.push(relative);
                }
            }
        }
        entries.retain(|_, bases| !bases.is_empty());
        Self { entries }
    }

    /// Candidate entry paths (relative to the repo root, extension included as
    /// written) for `package_name`, in preference order. Empty when no
    /// workspace package carries that name, which is what makes an external
    /// npm package stay external.
    pub fn entry_bases(&self, package_name: &str) -> &[PathBuf] {
        self.entries
            .get(package_name)
            .map_or(&[][..], Vec::as_slice)
    }
}

/// A manifest's package name and its entry targets, best first. `None` when the
/// file is unreadable, unparseable, oversized, or declares no usable name.
fn read_manifest(path: &Path) -> Option<(String, Vec<String>)> {
    if std::fs::metadata(path).ok()?.len() > MAX_MANIFEST_BYTES {
        return None;
    }
    let text = std::fs::read_to_string(path).ok()?;
    let manifest: Value = serde_json::from_str(&text).ok()?;
    let name = manifest
        .get("name")
        .and_then(Value::as_str)
        .filter(|name| !name.is_empty())?
        .to_string();
    Some((name, entry_targets(&manifest)))
}

/// The entry targets a manifest offers for the package root, ordered so the
/// ones that can name workspace source are tried first.
fn entry_targets(manifest: &Value) -> Vec<String> {
    let mut ranked: Vec<(EntryRank, String)> = Vec::new();
    if let Some(root_export) = manifest.get("exports").and_then(exports_root_value) {
        // The seed is the best `exports` rank, so every target's rank is decided
        // by the conditions actually on its path and nothing else.
        collect_condition_targets(root_export, EntryRank::ExportsUnconditioned, 0, &mut ranked);
    }
    for (field, rank) in [("main", EntryRank::Main), ("module", EntryRank::Module)] {
        if let Some(target) = manifest.get(field).and_then(Value::as_str) {
            ranked.push((rank, target.to_string()));
        }
    }
    ranked.sort_by_key(|(rank, _)| *rank);
    let mut targets = Vec::with_capacity(ranked.len());
    for (_, target) in ranked {
        if !target.is_empty() && !targets.contains(&target) {
            targets.push(target);
        }
    }
    targets
}

/// The `exports` value that describes the package root (`"."`).
///
/// `exports` is either a target, a conditions map, or a subpath map. A map is a
/// subpath map exactly when its keys are subpaths (`"."`, `"./sub"`), which is
/// the distinction Node itself draws; otherwise the map conditions the root
/// entry directly.
fn exports_root_value(exports: &Value) -> Option<&Value> {
    match exports {
        Value::String(_) | Value::Array(_) => Some(exports),
        Value::Object(map) => {
            if map.keys().any(|key| key.starts_with('.')) {
                map.get(".")
            } else {
                Some(exports)
            }
        }
        _ => None,
    }
}

/// Flatten one `exports` entry into ranked targets. A string is a target, an
/// array is an ordered fallback list, and an object conditions its values;
/// nested conditions carry the strictest (highest) rank on their path, so
/// `{"import": {"types": ...}}` is ranked as a declaration file rather than as
/// a runtime entry.
fn collect_condition_targets(
    value: &Value,
    rank: EntryRank,
    depth: u8,
    out: &mut Vec<(EntryRank, String)>,
) {
    if depth > MAX_CONDITION_DEPTH {
        return;
    }
    match value {
        Value::String(target) => out.push((rank, target.clone())),
        Value::Array(items) => {
            for item in items {
                collect_condition_targets(item, rank, depth + 1, out);
            }
        }
        Value::Object(map) => {
            for (key, nested) in map {
                // A subpath key inside a conditions map is not a condition; the
                // package root's entry never lives under one.
                if key.starts_with('.') {
                    continue;
                }
                collect_condition_targets(nested, rank.max(condition_rank(key)), depth + 1, out);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn targets(manifest: &str) -> Vec<String> {
        entry_targets(&serde_json::from_str(manifest).unwrap())
    }

    #[test]
    fn custom_condition_outranks_published_runtime_and_type_conditions() {
        // The TanStack shape: only the custom condition names workspace source.
        assert_eq!(
            targets(
                r#"{
                  "name": "@tanstack/react-query",
                  "types": "build/legacy/index.d.ts",
                  "main": "build/legacy/index.cjs",
                  "module": "build/legacy/index.js",
                  "exports": {
                    ".": {
                      "@tanstack/custom-condition": "./src/index.ts",
                      "import": {
                        "types": "./build/modern/index.d.ts",
                        "default": "./build/modern/index.js"
                      }
                    },
                    "./package.json": "./package.json"
                  }
                }"#
            ),
            vec![
                "./src/index.ts",
                "./build/modern/index.js",
                "./build/modern/index.d.ts",
                "build/legacy/index.cjs",
                "build/legacy/index.js",
            ]
        );
    }

    #[test]
    fn explicit_source_condition_outranks_a_custom_one() {
        assert_eq!(
            targets(
                r#"{
                  "name": "pkg",
                  "exports": {
                    "vendor-condition": "./vendor/index.ts",
                    "source": "./src/index.ts",
                    "default": "./dist/index.js"
                  }
                }"#
            ),
            vec!["./src/index.ts", "./vendor/index.ts", "./dist/index.js"]
        );
    }

    #[test]
    fn a_conditions_map_without_subpath_keys_conditions_the_root_entry() {
        // The "sugar" form: `exports` is the root entry's condition map.
        assert_eq!(
            targets(r#"{"name": "pkg", "exports": {"import": "./dist/index.js"}}"#),
            vec!["./dist/index.js"]
        );
    }

    #[test]
    fn a_subpath_map_without_a_root_entry_offers_only_the_legacy_fields() {
        assert_eq!(
            targets(r#"{"name": "pkg", "main": "index.js", "exports": {"./sub": "./sub.js"}}"#),
            vec!["index.js"]
        );
    }

    #[test]
    fn a_fallback_array_keeps_its_written_order() {
        assert_eq!(
            targets(r#"{"name": "pkg", "exports": {".": ["./a.js", "./b.js"]}}"#),
            vec!["./a.js", "./b.js"]
        );
    }

    #[test]
    fn a_manifest_without_a_name_is_not_a_workspace_package() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("package.json");
        std::fs::write(&manifest, r#"{"private": true, "main": "index.js"}"#).unwrap();
        assert!(read_manifest(&manifest).is_none());
    }
}
