//! The memoizing half of the shared JS/TS provider policy, and the one downcast
//! that produces a source.
//!
//! The resolution policy itself moved to `brokk-bifrost-js-ts`; what stays here
//! is everything that touches the moka bucket. `JsTsMemoCaches` is instance
//! state on the two analyzers -- five moka caches and three
//! `PoolSafeMemo`s -- and moka is deliberately not a dependency of the language
//! crate, exactly as `analyzer/go/imports.rs`, `analyzer/java/imports.rs` and
//! `analyzer/csharp/imports.rs` keep their own get-then-insert wrappers here and
//! call the crate for the uncached work.
//!
//! Both analyzers hold the same bucket type behind an `Arc`, so these are shared
//! free functions over [`JsTsMemoSource`] rather than duplicated methods.

use crate::analyzer::js_ts::cache::JsTsMemoCaches;
use crate::analyzer::{
    CodeUnit, IAnalyzer, ImportInfo, JavascriptAnalyzer, Language, ProjectFile, TypescriptAnalyzer,
    memoized_reverse_import_index, resolve_analyzer,
};
use crate::cancellation::CancellationToken;
use crate::hash::{HashMap, HashSet};
use brokk_bifrost_js_ts::graph::resolver::{
    JsTsUsageIndex, build_jsts_usage_index, build_jsts_usage_index_with_cancellation,
};
use brokk_bifrost_js_ts::hierarchy::build_direct_descendant_index_by_unit;
use brokk_bifrost_js_ts::providers::{
    self, JsTsSource, compute_direct_ancestors, compute_relevant_imports,
    resolve_import_target_files, resolve_imported_code_units,
};
use std::sync::Arc;

/// A JS/TS source that also owns its memo bucket.
///
/// The crate-side [`JsTsSource`] deliberately cannot name `JsTsMemoCaches`
/// (it is moka-backed). This supertrait is the analysis-side extension the
/// caching wrappers below need, implemented by both analyzers as one field
/// accessor.
pub(crate) trait JsTsMemoSource: JsTsSource {
    fn memo_caches(&self) -> &JsTsMemoCaches;
}

/// The one downcast from the framework's `&dyn IAnalyzer` to the JS/TS source
/// surface, for `language`. Every route and SPI boundary that holds only an
/// `IAnalyzer` and needs to call the source-parameterized JS/TS logic comes
/// through here, so `resolve_analyzer::<{Typescript,Javascript}Analyzer>` is
/// written once instead of at each call site.
///
/// `language` selects the analyzer rather than "whichever of the two is
/// present": a workspace can hold both, and the JS and TS analyzers keep
/// separate declaration indices and separate usage indices, so answering a
/// JavaScript question from the TypeScript analyzer would silently read the
/// wrong index.
///
/// `None` when the workspace has no analyzer for `language` -- callers then have
/// no JS/TS declarations to work with either, since every candidate they could
/// produce comes out of that same missing index.
pub(crate) fn resolve_js_ts_source(
    analyzer: &dyn IAnalyzer,
    language: Language,
) -> Option<&dyn JsTsMemoSource> {
    match language {
        Language::TypeScript => {
            Some(resolve_analyzer::<TypescriptAnalyzer>(analyzer)? as &dyn JsTsMemoSource)
        }
        Language::JavaScript => {
            Some(resolve_analyzer::<JavascriptAnalyzer>(analyzer)? as &dyn JsTsMemoSource)
        }
        _ => None,
    }
}

// --- ImportAnalysisProvider ------------------------------------------------

pub(crate) fn imported_code_units_of(
    host: &dyn JsTsMemoSource,
    file: &ProjectFile,
) -> Arc<HashSet<CodeUnit>> {
    let caches = host.memo_caches();
    if let Some(cached) = caches.imported_code_units.get(file) {
        return cached;
    }

    let resolved = Arc::new(resolve_imported_code_units(
        host,
        file,
        host.import_info_of(file),
    ));

    caches
        .imported_code_units
        .insert(file.clone(), Arc::clone(&resolved));
    resolved
}

/// `imports` is intentionally unused: `imported_code_units_of`'s cache is keyed by `file` alone and,
/// unlike Python's binding-name-keyed cache, stores a plain `HashSet<CodeUnit>` with no collision risk
/// -- so routing through it (rather than re-resolving from the passed-in `imports`) is both correct and
/// gets the caching this hook exists to provide, shared with `could_import_file` below.
pub(crate) fn imported_code_units_from_infos(
    host: &dyn JsTsMemoSource,
    file: &ProjectFile,
    _imports: &[ImportInfo],
) -> Option<Arc<HashSet<CodeUnit>>> {
    Some(imported_code_units_of(host, file))
}

pub(crate) fn referencing_files_of(
    host: &dyn JsTsMemoSource,
    file: &ProjectFile,
) -> HashSet<ProjectFile> {
    let caches = host.memo_caches();
    if let Some(cached) = caches.referencing_files.get(file) {
        return (*cached).clone();
    }

    let reverse_index = memoized_reverse_import_index(
        &caches.reverse_import_index,
        || host.all_files(),
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

pub(crate) fn import_infos_for_files(
    host: &dyn JsTsMemoSource,
    files: &[ProjectFile],
) -> Option<HashMap<ProjectFile, Vec<ImportInfo>>> {
    providers::import_infos_for_files(host, files)
}

pub(crate) fn imported_files_from_infos(
    host: &dyn JsTsMemoSource,
    file: &ProjectFile,
    imports: &[ImportInfo],
) -> Option<HashSet<ProjectFile>> {
    providers::imported_files_from_infos(host, file, imports)
}

pub(crate) fn relevant_imports_for(
    host: &dyn JsTsMemoSource,
    code_unit: &CodeUnit,
) -> HashSet<String> {
    let caches = host.memo_caches();
    if let Some(cached) = caches.relevant_imports.get(code_unit) {
        return (*cached).clone();
    }

    let relevant = compute_relevant_imports(host, code_unit);

    caches
        .relevant_imports
        .insert(code_unit.clone(), Arc::new(relevant.clone()));
    relevant
}

/// `imports` is intentionally unused, for the same reason as `imported_code_units_from_infos` above:
/// the cache is keyed by `source_file` and holds every import's resolved target, so reusing it (instead
/// of re-resolving from the passed-in slice) is correct and gets the caching this hook is for.
pub(crate) fn could_import_file(
    host: &dyn JsTsMemoSource,
    source_file: &ProjectFile,
    _imports: &[ImportInfo],
    target: &ProjectFile,
) -> bool {
    resolved_import_target_files(host, source_file).contains(target)
}

/// The file-path resolution targets of `file`'s own imports (module specifier -> file), cached per
/// file. Without this, `could_import_file` re-ran the resolution for every (candidate, target) pair
/// the shared usages candidate walker checks -- unbounded per-call cost on a large workspace, never
/// cached before this.
///
/// `get_with` (not get-then-insert): `could_import_file` runs unconditionally for every candidate in
/// the parallelized workspace-wide import-graph walk, so two worker threads can miss the cache for
/// the same file at once. `get_with` guarantees only one thread ever runs the resolution closure per
/// key, matching `PythonAnalyzer::resolve_import_target_files`'s equivalent fix.
fn resolved_import_target_files(
    host: &dyn JsTsMemoSource,
    file: &ProjectFile,
) -> Arc<HashSet<ProjectFile>> {
    let caches = host.memo_caches();
    caches.imported_target_files.get_with(file.clone(), || {
        Arc::new(resolve_import_target_files(host, file))
    })
}

// --- Skeletons -------------------------------------------------------------

pub(crate) fn module_import_skeleton(
    host: &dyn JsTsMemoSource,
    code_unit: &CodeUnit,
) -> Option<String> {
    providers::module_import_skeleton(host, code_unit)
}

// --- TypeHierarchyProvider -------------------------------------------------

pub(crate) fn get_direct_ancestors(
    host: &dyn JsTsMemoSource,
    code_unit: &CodeUnit,
) -> Vec<CodeUnit> {
    let caches = host.memo_caches();
    if let Some(cached) = caches.direct_ancestors.get(code_unit) {
        return (*cached).clone();
    }

    let ancestors = compute_direct_ancestors(host, code_unit);
    caches
        .direct_ancestors
        .insert(code_unit.clone(), Arc::new(ancestors.clone()));
    ancestors
}

pub(crate) fn get_direct_descendants(
    host: &dyn JsTsMemoSource,
    code_unit: &CodeUnit,
) -> HashSet<CodeUnit> {
    // The builder itself is serial; the memo exists because its per-class
    // ancestor misses transitively enter the rayon-built usage index, so the
    // same closure serves both the off-pool and on-pool arms.
    host.memo_caches()
        .direct_descendant_index
        .get_or_build(
            || build_direct_descendant_index_by_unit(host, host),
            || build_direct_descendant_index_by_unit(host, host),
        )
        .descendants(code_unit)
}

// --- Usage index -----------------------------------------------------------

/// Lazily-built, analyzer-cached JS/TS usage-resolution maps for the host's
/// language. Built once per cache bucket and reused until `update`/`update_all`
/// installs a fresh bucket.
pub(crate) fn jsts_usage_index(host: &dyn JsTsMemoSource) -> Arc<JsTsUsageIndex> {
    let language = host.language();
    host.memo_caches().jsts_usage_index.get_or_build(
        || build_jsts_usage_index(host, host.alias_resolver(), language, true),
        || build_jsts_usage_index(host, host.alias_resolver(), language, false),
    )
}

pub(crate) fn jsts_usage_index_with_cancellation(
    host: &dyn JsTsMemoSource,
    cancellation: &CancellationToken,
) -> Option<Arc<JsTsUsageIndex>> {
    let language = host.language();
    host.memo_caches()
        .jsts_usage_index
        .get_or_try_build(
            || {
                build_jsts_usage_index_with_cancellation(
                    host,
                    host.alias_resolver(),
                    language,
                    true,
                    Some(cancellation),
                )
                .ok_or(())
            },
            || {
                build_jsts_usage_index_with_cancellation(
                    host,
                    host.alias_resolver(),
                    language,
                    false,
                    Some(cancellation),
                )
                .ok_or(())
            },
        )
        .ok()
}

pub(crate) fn prewarm_jsts_usage_index(host: &dyn JsTsMemoSource) -> Arc<JsTsUsageIndex> {
    let language = host.language();
    host.memo_caches().jsts_usage_index.get_or_build_parallel(
        || build_jsts_usage_index(host, host.alias_resolver(), language, true),
        || build_jsts_usage_index(host, host.alias_resolver(), language, false),
    )
}
