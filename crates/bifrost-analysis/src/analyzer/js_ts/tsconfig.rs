//! Resolution of TypeScript/JavaScript `tsconfig.json` (and `jsconfig.json`) path
//! aliases (`compilerOptions.baseUrl` + `compilerOptions.paths`).
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

use crate::analyzer::ProjectFile;
use crate::hash::HashMap;
use crate::path_normalization::NormalizePath;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

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

/// Resolves alias specifiers for one repository root, caching parsed configs so the
/// hot import-resolution loop parses each `tsconfig.json` at most once. Cheap to
/// construct (`new` just stores the root); all filesystem work is lazy.
pub(crate) struct AliasResolver {
    root: PathBuf,
    /// Symlink-resolved `root`, used to contain `extends` targets to the repo. Falls back
    /// to `root` when canonicalization fails (e.g. the root was deleted out from under us).
    canonical_root: PathBuf,
    /// `directory of importing file` → nearest governing config file (if any).
    nearest: Mutex<HashMap<PathBuf, Option<PathBuf>>>,
    /// `config file path` → its fully-resolved alias map (extends already followed).
    /// `None` means the file was unreadable/unparseable or declared no usable `paths`.
    maps: Mutex<HashMap<PathBuf, Arc<Option<AliasMap>>>>,
}

/// Hard cap on a config file's size before we read it. Real `tsconfig.json`/`jsconfig.json`
/// files are a few KB; this only exists to stop a hostile repo from OOM-ing the analyzer
/// with a giant (or `extends`-reachable) config.
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

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
    pub(crate) fn new(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        let canonical_root = root.canonicalize().unwrap_or_else(|_| root.clone());
        Self {
            root,
            canonical_root,
            nearest: Mutex::new(HashMap::default()),
            maps: Mutex::new(HashMap::default()),
        }
    }

    /// Candidate base paths (relative to the repo root, no extension) for a non-relative
    /// `specifier` imported from `source_file`, in TS precedence order. Empty when the
    /// specifier matches no alias. Extension/index resolution is left to the caller so a
    /// single source of truth (`collect_candidate_paths`) decides what exists on disk.
    pub(crate) fn candidate_bases(
        &self,
        source_file: &ProjectFile,
        specifier: &str,
    ) -> Vec<PathBuf> {
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
            match current {
                Some(dir) => current = dir.parent(),
                None => return None,
            }
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
        }
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
    let dir = config_path
        .parent()
        .unwrap_or_else(|| Path::new(""))
        .to_path_buf();

    let mut chain = ancestors.to_vec();
    chain.push(config_path.to_path_buf());

    // Fold every resolved `extends` parent left-to-right: TS merges all parents, not just
    // the first (rightmost wins on conflict). Each entry gets the same ancestor chain, so a
    // grandparent shared by two siblings (a diamond) contributes to both, like `tsc`.
    let inherited = value
        .get("extends")
        .and_then(extends_targets)
        .into_iter()
        .flatten()
        .filter_map(|target| resolve_extends_path(&dir, &target, canonical_root))
        .filter_map(|path| resolve_effective(&path, &chain, budget, canonical_root))
        .fold(EffectiveConfig::default(), EffectiveConfig::overlay);

    let compiler_options = value.get("compilerOptions");

    let own_base_url = compiler_options
        .and_then(|opts| opts.get("baseUrl"))
        .and_then(serde_json::Value::as_str)
        .map(|value| (dir.clone(), value.to_string()));

    let own_paths = compiler_options
        .and_then(|opts| opts.get("paths"))
        .and_then(parse_paths)
        .map(|entries| (dir.clone(), entries));

    // Child wins over everything it inherits; `paths` are replaced wholesale, not
    // deep-merged (TS semantics).
    let own = EffectiveConfig {
        base_url: own_base_url,
        paths: own_paths,
    };
    Some(inherited.overlay(own))
}

/// `extends` may be a single string or (TS 5.0+) an array of strings applied left to right
/// with later entries winning. Returned in source order; the caller folds them so the
/// rightmost wins on conflict.
fn extends_targets(value: &serde_json::Value) -> Option<Vec<String>> {
    match value {
        serde_json::Value::String(single) => Some(vec![single.clone()]),
        serde_json::Value::Array(items) => Some(
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_string))
                .collect(),
        ),
        _ => None,
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
        AliasResolver::new(root.to_path_buf())
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
}
