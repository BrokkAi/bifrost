//! Shared `ImportAnalysisProvider` / `TypeHierarchyProvider` / usage-index
//! implementations for the JavaScript and TypeScript adapters.
//!
//! Both adapters wrap the same `TreeSitterAnalyzer<Adapter>`, the same
//! `JsTsMemoCaches` bucket, the same `AliasResolver`, and differ only in their
//! `Language` tag. Every function here is parameterized over a [`JsTsAnalyzerHost`]
//! so the two `impl` blocks reduce to one-line delegations and the resolution
//! policy lives in exactly one place (no more twin-adapter drift).

use crate::analyzer::CodeUnitIndex;
use crate::analyzer::js_ts::cache::JsTsMemoCaches;
use crate::analyzer::js_ts::hierarchy::{
    build_direct_descendant_index_by_unit, resolve_direct_ancestors,
};
use crate::analyzer::js_ts::imports::{import_info_tokens, resolve_js_ts_import_paths};
use crate::analyzer::usages::js_ts_graph::{
    JsTsUsageIndex, build_jsts_usage_index, build_jsts_usage_index_with_cancellation,
};
use crate::analyzer::{
    AliasResolver, CodeUnit, IAnalyzer, ImportInfo, Language, LanguageAdapter, ProjectFile,
    TreeSitterAnalyzer, TypeHierarchyProvider, memoized_reverse_import_index,
};
use crate::cancellation::CancellationToken;
use crate::hash::{HashMap, HashSet};
use std::sync::Arc;

/// The shared surface the JS/TS provider logic needs from a concrete analyzer:
/// its wrapped tree-sitter analyzer, its cache bucket, its alias resolver, and
/// its language tag. Implemented once per adapter as trivial field accessors.
pub(crate) trait JsTsAnalyzerHost: IAnalyzer + TypeHierarchyProvider {
    type Adapter: LanguageAdapter;

    fn ts_inner(&self) -> &TreeSitterAnalyzer<Self::Adapter>;
    fn memo_caches(&self) -> &JsTsMemoCaches;
    fn alias_resolver(&self) -> &AliasResolver;
    fn js_ts_language(&self) -> Language;
}

// --- ImportAnalysisProvider ------------------------------------------------

pub(crate) fn imported_code_units_of<T: JsTsAnalyzerHost>(
    host: &T,
    file: &ProjectFile,
) -> HashSet<CodeUnit> {
    let caches = host.memo_caches();
    if let Some(cached) = caches.imported_code_units.get(file) {
        return (*cached).clone();
    }

    let resolved = resolve_imported_code_units(host, file, host.ts_inner().import_info_of(file));

    caches
        .imported_code_units
        .insert(file.clone(), Arc::new(resolved.clone()));
    resolved
}

/// `imports` is intentionally unused: `imported_code_units_of`'s cache is keyed by `file` alone and,
/// unlike Python's binding-name-keyed cache, stores a plain `HashSet<CodeUnit>` with no collision risk
/// -- so routing through it (rather than re-resolving from the passed-in `imports`) is both correct and
/// gets the caching this hook exists to provide, shared with `could_import_file` below.
pub(crate) fn imported_code_units_from_infos<T: JsTsAnalyzerHost>(
    host: &T,
    file: &ProjectFile,
    _imports: &[ImportInfo],
) -> Option<HashSet<CodeUnit>> {
    Some(imported_code_units_of(host, file))
}

fn resolve_imported_code_units<T: JsTsAnalyzerHost>(
    host: &T,
    file: &ProjectFile,
    imports: impl IntoIterator<Item = ImportInfo>,
) -> HashSet<CodeUnit> {
    let inner = host.ts_inner();
    let language = host.js_ts_language();
    let alias_resolver = host.alias_resolver();
    let mut resolved = HashSet::default();
    for import in imports {
        for target in
            resolve_js_ts_import_paths(file, &import.raw_snippet, language, Some(alias_resolver))
        {
            let top_level = inner.top_level_declarations(&target);
            if import.is_wildcard {
                resolved.extend(
                    top_level
                        .iter()
                        .filter(|code_unit| !code_unit.is_module())
                        .cloned(),
                );
            } else if let Some(identifier) = import.identifier.as_ref().or(import.alias.as_ref()) {
                let mut matched = false;
                for code_unit in top_level
                    .iter()
                    .filter(|code_unit| code_unit.identifier() == identifier)
                {
                    matched = true;
                    resolved.insert(code_unit.clone());
                }
                if !matched {
                    let module_units = top_level
                        .iter()
                        .filter(|code_unit| code_unit.is_module())
                        .cloned()
                        .collect::<Vec<_>>();
                    if !module_units.is_empty() {
                        resolved.extend(module_units);
                    } else if top_level.len() == 1 && !top_level[0].is_module() {
                        resolved.insert(top_level[0].clone());
                    }
                }
            } else {
                resolved.extend(
                    top_level
                        .iter()
                        .filter(|code_unit| !code_unit.is_module())
                        .cloned(),
                );
            }
        }
    }
    resolved
}

pub(crate) fn referencing_files_of<T: JsTsAnalyzerHost>(
    host: &T,
    file: &ProjectFile,
) -> HashSet<ProjectFile> {
    let caches = host.memo_caches();
    if let Some(cached) = caches.referencing_files.get(file) {
        return (*cached).clone();
    }

    let reverse_index = memoized_reverse_import_index(
        &caches.reverse_import_index,
        || host.ts_inner().all_files(),
        |candidate| imported_code_units_of(host, candidate),
    );
    let referencing = reverse_index
        .get(file)
        .map(|files| (**files).clone())
        .unwrap_or_default();

    caches
        .referencing_files
        .insert(file.clone(), Arc::new(referencing.clone()));
    referencing
}

pub(crate) fn import_infos_for_files<T: JsTsAnalyzerHost>(
    host: &T,
    files: &[ProjectFile],
) -> Option<HashMap<ProjectFile, Vec<ImportInfo>>> {
    Some(host.ts_inner().bulk_import_infos(files.iter().cloned()))
}

pub(crate) fn imported_files_from_infos<T: JsTsAnalyzerHost>(
    host: &T,
    file: &ProjectFile,
    imports: &[ImportInfo],
) -> Option<HashSet<ProjectFile>> {
    let language = host.js_ts_language();
    let alias_resolver = host.alias_resolver();
    Some(
        imports
            .iter()
            .flat_map(|import| {
                resolve_js_ts_import_paths(
                    file,
                    &import.raw_snippet,
                    language,
                    Some(alias_resolver),
                )
            })
            .collect(),
    )
}

pub(crate) fn relevant_imports_for<T: JsTsAnalyzerHost>(
    host: &T,
    code_unit: &CodeUnit,
) -> HashSet<String> {
    let caches = host.memo_caches();
    if let Some(cached) = caches.relevant_imports.get(code_unit) {
        return (*cached).clone();
    }

    let inner = host.ts_inner();
    let source = inner.get_source(code_unit, false).unwrap_or_default();
    let mut relevant = HashSet::default();
    for import in inner.import_info_of(code_unit.source()) {
        let tokens = import_info_tokens(&import);
        if tokens.is_empty() || tokens.iter().any(|token| source.contains(token)) {
            relevant.insert(import.raw_snippet.clone());
        }
    }

    caches
        .relevant_imports
        .insert(code_unit.clone(), Arc::new(relevant.clone()));
    relevant
}

/// `imports` is intentionally unused, for the same reason as `imported_code_units_from_infos` above:
/// the cache is keyed by `source_file` and holds every import's resolved target, so reusing it (instead
/// of re-resolving from the passed-in slice) is correct and gets the caching this hook is for.
pub(crate) fn could_import_file<T: JsTsAnalyzerHost>(
    host: &T,
    source_file: &ProjectFile,
    _imports: &[ImportInfo],
    target: &ProjectFile,
) -> bool {
    resolved_import_target_files(host, source_file).contains(target)
}

/// The file-path resolution targets of `file`'s own imports (module specifier -> file), cached per
/// file. Without this, `could_import_file` re-ran `resolve_js_ts_import_paths` for every
/// (candidate, target) pair the shared usages candidate walker checks -- unbounded per-call cost on a
/// large workspace, never cached before this.
///
/// `get_with` (not get-then-insert): `could_import_file` runs unconditionally for every candidate in
/// the parallelized workspace-wide import-graph walk, so two worker threads can miss the cache for
/// the same file at once. `get_with` guarantees only one thread ever runs the resolution closure per
/// key, matching `PythonAnalyzer::resolve_import_target_files`'s equivalent fix.
fn resolved_import_target_files<T: JsTsAnalyzerHost>(
    host: &T,
    file: &ProjectFile,
) -> Arc<HashSet<ProjectFile>> {
    let caches = host.memo_caches();
    caches.imported_target_files.get_with(file.clone(), || {
        let language = host.js_ts_language();
        let alias_resolver = host.alias_resolver();
        let targets: HashSet<ProjectFile> = host
            .ts_inner()
            .import_info_of(file)
            .iter()
            .flat_map(|import| {
                resolve_js_ts_import_paths(
                    file,
                    &import.raw_snippet,
                    language,
                    Some(alias_resolver),
                )
            })
            .collect();
        Arc::new(targets)
    })
}

// --- TypeHierarchyProvider -------------------------------------------------

pub(crate) fn get_direct_ancestors<T: JsTsAnalyzerHost>(
    host: &T,
    code_unit: &CodeUnit,
) -> Vec<CodeUnit> {
    let caches = host.memo_caches();
    if let Some(cached) = caches.direct_ancestors.get(code_unit) {
        return (*cached).clone();
    }

    let index = jsts_usage_index(host);
    let ancestors = resolve_direct_ancestors(
        host,
        index.as_ref(),
        host.js_ts_language(),
        host.alias_resolver(),
        code_unit,
        &host.ts_inner().raw_supertypes_of(code_unit),
    );
    caches
        .direct_ancestors
        .insert(code_unit.clone(), Arc::new(ancestors.clone()));
    ancestors
}

pub(crate) fn get_direct_descendants<T: JsTsAnalyzerHost>(
    host: &T,
    code_unit: &CodeUnit,
) -> HashSet<CodeUnit> {
    host.memo_caches()
        .direct_descendant_index
        .get_or_init(|| build_direct_descendant_index_by_unit(host, host))
        .descendants(code_unit)
}

// --- Usage index -----------------------------------------------------------

/// Lazily-built, analyzer-cached JS/TS usage-resolution maps for the host's
/// language. Built once per cache bucket and reused until `update`/`update_all`
/// installs a fresh bucket.
pub(crate) fn jsts_usage_index<T: JsTsAnalyzerHost>(host: &T) -> Arc<JsTsUsageIndex> {
    let language = host.js_ts_language();
    host.memo_caches().jsts_usage_index.get_or_build(
        || build_jsts_usage_index(host, language, true),
        || build_jsts_usage_index(host, language, false),
    )
}

pub(crate) fn jsts_usage_index_with_cancellation<T: JsTsAnalyzerHost>(
    host: &T,
    cancellation: &CancellationToken,
) -> Option<Arc<JsTsUsageIndex>> {
    let language = host.js_ts_language();
    host.memo_caches()
        .jsts_usage_index
        .get_or_try_build(
            || {
                build_jsts_usage_index_with_cancellation(host, language, true, Some(cancellation))
                    .ok_or(())
            },
            || {
                build_jsts_usage_index_with_cancellation(host, language, false, Some(cancellation))
                    .ok_or(())
            },
        )
        .ok()
}

pub(crate) fn prewarm_jsts_usage_index<T: JsTsAnalyzerHost>(host: &T) -> Arc<JsTsUsageIndex> {
    let language = host.js_ts_language();
    host.memo_caches().jsts_usage_index.get_or_build_parallel(
        || build_jsts_usage_index(host, language, true),
        || build_jsts_usage_index(host, language, false),
    )
}
