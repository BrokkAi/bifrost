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

use brokk_bifrost_core::analyzer::model::CodeUnit;

use brokk_bifrost_core::analyzer::capabilities::DescendantIndexScope;

use brokk_bifrost_analysis::analyzer::ReadKey;
use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

use brokk_bifrost_core::analyzer::model::ImportInfo;

use crate::analyzer::JavascriptAnalyzer;

use brokk_bifrost_core::analyzer::model::Language;

use brokk_bifrost_core::analyzer::model::ProjectFile;

use crate::analyzer::TypescriptAnalyzer;

use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;

use brokk_bifrost_core::cancellation::CancellationToken;

use brokk_bifrost_core::hash::HashMap;

use super::cache::AttributedCache;
use brokk_bifrost_analysis::analyzer::workspace_authority::memo_attribution;
use brokk_bifrost_core::analyzer::query_token::QueryToken;
use brokk_bifrost_core::analyzer::weighted_cache::{
    weight_code_unit_set, weight_code_unit_vec_by_unit, weight_project_file_set,
};
use brokk_bifrost_core::hash::HashSet;
use brokk_bifrost_js_ts::graph::resolver::{
    JsTsUsageIndex, build_jsts_usage_index, build_jsts_usage_index_with_cancellation,
};

use brokk_bifrost_js_ts::providers::{
    self, JsTsSource, compute_direct_ancestors, compute_relevant_imports,
    resolve_import_target_files, resolve_imported_code_units,
};
use std::convert::Infallible;
use std::hash::Hash;
use std::sync::Arc;

const MAX_USAGE_INDEX_RECEIPT_BYTES: usize = 64 * 1024 * 1024;

pub(crate) fn alias_resolver<A: brokk_bifrost_analysis::analyzer::LanguageAdapter>(
    inner: &brokk_bifrost_analysis::analyzer::TreeSitterAnalyzer<A>,
) -> Arc<brokk_bifrost_js_ts::tsconfig::AliasResolver> {
    let recorder =
        brokk_bifrost_analysis::analyzer::workspace_authority::js_ts_configuration_read_recorder(
            inner,
            inner.adapter().language(),
        );
    Arc::new(
        brokk_bifrost_js_ts::tsconfig::AliasResolver::new(inner.shared_project())
            .with_configuration_read_recorder(recorder),
    )
}

/// A JS/TS source that also owns its memo bucket.
///
/// The crate-side [`JsTsSource`] deliberately cannot name `JsTsMemoCaches`
/// (it is moka-backed). This supertrait is the analysis-side extension the
/// caching wrappers below need, implemented by both analyzers as one field
/// accessor.
pub(crate) trait JsTsMemoSource: JsTsSource {
    fn memo_caches(&self) -> &JsTsMemoCaches;

    /// Return the analyzer that owns this memo bucket's request-scoped reads.
    ///
    /// The JS/TS source trait lives in the language provider crate and cannot
    /// itself expose the tree-sitter analyzer's read-ledger state. Keeping the
    /// accessor here lets all memo crossings publish the same workspace export
    /// index dependency, including cache hits, without enumerating files again.
    fn analyzer(&self) -> &dyn IAnalyzer;
}

fn memoized_value<K, V>(
    host: &dyn JsTsMemoSource,
    cache: &AttributedCache<K, V>,
    key: &K,
    weight: impl FnOnce(&K, &Arc<V>) -> u32,
    build: impl FnOnce() -> V,
) -> Arc<V>
where
    K: Clone + Eq + Hash + Send + Sync + 'static,
    V: Send + Sync + 'static,
{
    let value = cache
        .read(&memo_attribution(host.analyzer()), |cache, capture| {
            if let Some(entry) = cache.get(key) {
                return Ok::<_, Infallible>(entry);
            }
            let mut install = false;
            let entry = Arc::new(capture.build_weighted(|| {
                let result = brokk_bifrost_analysis::analyzer::common::complete_query_cache_fill(
                    host.analyzer(),
                    || Arc::new(build()),
                );
                install = result.is_ok();
                let value = result.unwrap_or_else(|value| value);
                let bytes = weight(key, &value) as usize;
                (value, bytes)
            }));
            if install {
                cache.insert(key.clone(), Arc::clone(&entry));
            }
            Ok(entry)
        })
        .expect("infallible memo build");
    Arc::clone(&value)
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
    token: QueryToken<'_>,
    file: &ProjectFile,
) -> Arc<HashSet<CodeUnit>> {
    memoized_value(
        host,
        &host.memo_caches().imported_code_units,
        file,
        weight_code_unit_set,
        || resolve_imported_code_units(host, file, host.import_info_of(token, file)),
    )
}

/// `imports` is intentionally unused: `imported_code_units_of`'s cache is keyed by `file` alone and,
/// unlike Python's binding-name-keyed cache, stores a plain `HashSet<CodeUnit>` with no collision risk
/// -- so routing through it (rather than re-resolving from the passed-in `imports`) is both correct and
/// gets the caching this hook exists to provide, shared with `could_import_file` below.
pub(crate) fn imported_code_units_from_infos(
    host: &dyn JsTsMemoSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    _imports: &[ImportInfo],
) -> Option<Arc<HashSet<CodeUnit>>> {
    Some(imported_code_units_of(host, token, file))
}

pub(crate) fn referencing_files_of(
    host: &dyn JsTsMemoSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
) -> HashSet<ProjectFile> {
    (*memoized_value(
        host,
        &host.memo_caches().referencing_files,
        file,
        weight_project_file_set,
        || {
            let reverse_index = super::workspace_facts::reverse_imports(host, token);
            reverse_index
                .index
                .get(file)
                .map(|files| (**files).clone())
                .unwrap_or_default()
        },
    ))
    .clone()
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
    token: QueryToken<'_>,
    code_unit: &CodeUnit,
) -> HashSet<String> {
    (*memoized_value(
        host,
        &host.memo_caches().relevant_imports,
        code_unit,
        super::cache::weight_string_set,
        || compute_relevant_imports(host, token, code_unit),
    ))
    .clone()
}

/// `imports` is intentionally unused, for the same reason as `imported_code_units_from_infos` above:
/// the cache is keyed by `source_file` and holds every import's resolved target, so reusing it (instead
/// of re-resolving from the passed-in slice) is correct and gets the caching this hook is for.
pub(crate) fn could_import_file(
    host: &dyn JsTsMemoSource,
    token: QueryToken<'_>,
    source_file: &ProjectFile,
    _imports: &[ImportInfo],
    target: &ProjectFile,
) -> bool {
    resolved_import_target_files(host, token, source_file).contains(target)
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
    token: QueryToken<'_>,
    file: &ProjectFile,
) -> Arc<HashSet<ProjectFile>> {
    let value = host
        .memo_caches()
        .imported_target_files
        .read(&memo_attribution(host.analyzer()), |cache, capture| {
            if let Some(entry) = cache.get(file) {
                return Ok::<_, Infallible>(entry);
            }
            let mut install = false;
            let entry = Arc::new(capture.build_weighted(|| {
                let result = brokk_bifrost_analysis::analyzer::common::complete_query_cache_fill(
                    host.analyzer(),
                    || Arc::new(resolve_import_target_files(host, token, file)),
                );
                install = result.is_ok();
                let value = result.unwrap_or_else(|value| value);
                let bytes = weight_project_file_set(file, &value) as usize;
                (value, bytes)
            }));
            if install {
                cache.insert(file.clone(), Arc::clone(&entry));
            }
            Ok(entry)
        })
        .expect("infallible import target build");
    Arc::clone(&value)
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
    (*memoized_value(
        host,
        &host.memo_caches().direct_ancestors,
        code_unit,
        weight_code_unit_vec_by_unit,
        || compute_direct_ancestors(host, code_unit),
    ))
    .clone()
}

pub(crate) fn get_direct_descendants(
    host: &dyn JsTsMemoSource,
    code_unit: &CodeUnit,
) -> HashSet<CodeUnit> {
    brokk_bifrost_analysis::analyzer::whole_workspace_descendants(|scope| {
        get_direct_descendants_within(host, code_unit, scope)
    })
}

/// The memo exists because the per-class ancestor misses behind this build
/// transitively enter the rayon-built usage index, so the same closure serves
/// both the off-pool and on-pool arms.
pub(crate) fn get_direct_descendants_within(
    host: &dyn JsTsMemoSource,
    code_unit: &CodeUnit,
    scope: &DescendantIndexScope<'_>,
) -> Option<HashSet<CodeUnit>> {
    Some(
        super::workspace_facts::descendants(host, scope)?
            .index
            .descendants(code_unit),
    )
}

// --- Usage index -----------------------------------------------------------

fn memoized_usage_index(
    host: &dyn JsTsMemoSource,
    build_parallel: impl FnOnce() -> Option<JsTsUsageIndex>,
    build_serial: impl FnOnce() -> Option<JsTsUsageIndex>,
) -> Option<Arc<JsTsUsageIndex>> {
    memoized_usage_index_with_receipt_limit(
        host,
        MAX_USAGE_INDEX_RECEIPT_BYTES,
        build_parallel,
        build_serial,
    )
}

fn memoized_usage_index_with_receipt_limit(
    host: &dyn JsTsMemoSource,
    receipt_byte_limit: usize,
    build_parallel: impl FnOnce() -> Option<JsTsUsageIndex>,
    build_serial: impl FnOnce() -> Option<JsTsUsageIndex>,
) -> Option<Arc<JsTsUsageIndex>> {
    let attribution = memo_attribution(host.analyzer());
    let index = host
        .memo_caches()
        .jsts_usage_index
        .read(&attribution, |memo, capture| {
            memo.get_or_build_while(
                &|| true,
                || {
                    let mut entry = capture
                        .try_build(|| {
                            record_usage_index_source_scope(host);
                            build_parallel().map(Arc::new).ok_or(())
                        })
                        .ok()?;
                    if entry.retained_read_bytes(usage_index_read_key_heap_bytes)
                        > receipt_byte_limit
                    {
                        entry.refuse_replay();
                    }
                    Some(entry)
                },
                || {
                    let mut entry = capture
                        .try_build(|| {
                            record_usage_index_source_scope(host);
                            build_serial().map(Arc::new).ok_or(())
                        })
                        .ok()?;
                    if entry.retained_read_bytes(usage_index_read_key_heap_bytes)
                        > receipt_byte_limit
                    {
                        entry.refuse_replay();
                    }
                    Some(entry)
                },
            )
            .ok_or(())
        })
        .ok()?;
    Some(Arc::clone(&index))
}

fn record_usage_index_source_scope(host: &dyn JsTsMemoSource) {
    brokk_bifrost_analysis::analyzer::workspace_authority::record_workspace_authority_read(
        host.analyzer(),
        brokk_bifrost_analysis::analyzer::WorkspaceFactFamily::JsTsUsageIndex,
        brokk_bifrost_analysis::analyzer::AuthorityInputs::SourceOf(&[host.language()]),
    );
}

fn usage_index_read_key_heap_bytes(key: &ReadKey) -> usize {
    let mut heap = brokk_bifrost_analysis::analyzer::store::cache_budget::RetainedHeap::default();
    brokk_bifrost_analysis::analyzer::store::cache_budget::retained_read_key(&mut heap, key);
    heap.total()
}

/// Lazily-built, analyzer-cached JS/TS usage-resolution maps for the host's
/// language. Built once per cache bucket and reused until `update`/`update_all`
/// installs a fresh bucket.
pub(crate) fn jsts_usage_index(host: &dyn JsTsMemoSource) -> Option<Arc<JsTsUsageIndex>> {
    let language = host.language();
    memoized_usage_index(
        host,
        || build_jsts_usage_index(host, host.alias_resolver(), language, true),
        || build_jsts_usage_index(host, host.alias_resolver(), language, false),
    )
}

/// Prepare the usage index before a caller starts its own parallel file scan.
///
/// The ordinary accessor switches to a serial builder when invoked from a
/// rayon worker, which is correct for an incidental nested lookup but turns a
/// large workspace prewarm into a minute-scale serial bottleneck. A graph
/// plugin calls this orchestration-specific entry point before its fan-out, so
/// the memo can safely use the parallel builder without any scan task being
/// able to re-enter the in-flight cell.
pub(crate) fn jsts_usage_index_for_parallel_scan(
    host: &dyn JsTsMemoSource,
) -> Option<Arc<JsTsUsageIndex>> {
    let language = host.language();
    memoized_usage_index(
        host,
        || build_jsts_usage_index(host, host.alias_resolver(), language, true),
        || build_jsts_usage_index(host, host.alias_resolver(), language, false),
    )
}

pub(crate) fn jsts_usage_index_with_cancellation(
    host: &dyn JsTsMemoSource,
    cancellation: &CancellationToken,
) -> Option<Arc<JsTsUsageIndex>> {
    let language = host.language();
    memoized_usage_index(
        host,
        || {
            build_jsts_usage_index_with_cancellation(
                host,
                host.alias_resolver(),
                language,
                true,
                Some(cancellation),
            )
        },
        || {
            build_jsts_usage_index_with_cancellation(
                host,
                host.alias_resolver(),
                language,
                false,
                Some(cancellation),
            )
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_analysis::analyzer::semantic::StableDigest;
    use brokk_bifrost_analysis::analyzer::{ReadKey, capture_query_reads};
    use brokk_bifrost_core::analyzer::CodeUnitIndex;
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    #[hardwon(
        "#2445: the configuration recorder's detached analyzer clone hid helper-thread reads"
    )]
    fn configuration_reads_without_a_carried_capture_refuse_reuse() {
        let (_root, file, analyzer) = crate::test_typescript_project("export class Owner {}\n");
        let aliases = analyzer.alias_resolver();
        aliases.candidate_bases(&file, "@/missing");
        let (_, reads) = capture_query_reads(&analyzer, || {
            std::thread::scope(|threads| {
                threads
                    .spawn(|| aliases.candidate_bases(&file, "@/missing"))
                    .join()
                    .expect("configuration helper panicked")
            })
        });
        assert!(reads.unattributed_reads() > 0, "{reads:?}");
        assert!(
            !reads.keys().is_empty(),
            "the observer must also record covering inputs"
        );
    }

    #[test]
    #[hardwon("#2445: warm JS/TS configuration memos omitted config, extends and manifest inputs")]
    fn configuration_memo_hits_record_consulted_files() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("src/deep")).unwrap();
        std::fs::write(
            root.path().join("src/deep/app.ts"),
            "export class App {}
",
        )
        .unwrap();
        std::fs::write(
            root.path().join("tsconfig.json"),
            r#"{"extends":"./shared","compilerOptions":{"paths":{"@/*":["src/*"]}}}"#,
        )
        .unwrap();
        std::fs::write(
            root.path().join("shared.json"),
            r#"{"compilerOptions":{"baseUrl":".","lib":["es5"]}}"#,
        )
        .unwrap();
        std::fs::write(
            root.path().join("package.json"),
            r#"{"name":"local-package","main":"src/deep/app.ts"}"#,
        )
        .unwrap();
        let project =
            brokk_bifrost_analysis::analyzer::TestProject::new(root.path(), Language::TypeScript);
        let analyzer = TypescriptAnalyzer::from_project(project);
        let aliases = analyzer.alias_resolver();
        let file = ProjectFile::new(root.path(), "src/deep/app.ts");
        let read = || {
            assert_eq!(
                aliases.candidate_bases(&file, "@/deep/app"),
                [std::path::PathBuf::from("src/deep/app")]
            );
            assert_eq!(
                aliases.workspace_package_bases("local-package"),
                [std::path::PathBuf::from("src/deep/app.ts")]
            );
            assert!(aliases.effective_library_selection(&file).is_complete());
            assert!(aliases.read_config_path(&ProjectFile::new(root.path(), "shared.json")));
        };
        read();
        let (_, package_reads) = capture_query_reads(&analyzer, || {
            assert_eq!(
                aliases.workspace_package_bases("local-package"),
                [std::path::PathBuf::from("src/deep/app.ts")]
            );
        });
        assert_eq!(package_reads.unattributed_reads(), 0, "{package_reads:?}");
        assert!(package_reads.keys().iter().any(|key| matches!(key,
            ReadKey::Lookup { question: brokk_bifrost_analysis::analyzer::LookupQuestion::WorkspaceFact {
                family: brokk_bifrost_analysis::analyzer::WorkspaceFactFamily::JsTsWorkspacePackages,
                subject: brokk_bifrost_analysis::analyzer::FactSubject::Whole, .. }, .. })), "{package_reads:?}");
        assert!(
            package_reads
                .keys()
                .iter()
                .all(|key| !matches!(key, ReadKey::File { .. } | ReadKey::PathAbsent { .. })),
            "workspace-package Fact must subsume manifest probes: {package_reads:?}"
        );
        for _ in 0..2 {
            let (_, reads) = capture_query_reads(&analyzer, read);
            assert_eq!(reads.unattributed_reads(), 0, "{reads:?}");
            assert!(reads.keys().iter().any(|key| matches!(key,
                ReadKey::Lookup { question: brokk_bifrost_analysis::analyzer::LookupQuestion::WorkspaceFact {
                    family: brokk_bifrost_analysis::analyzer::WorkspaceFactFamily::JsTsWorkspacePackages,
                    subject: brokk_bifrost_analysis::analyzer::FactSubject::Whole, .. }, .. })), "{reads:?}");
            let files = reads
                .keys()
                .into_iter()
                .filter_map(|key| match key {
                    ReadKey::File { rel_path, .. } => Some(rel_path),
                    _ => None,
                })
                .collect::<std::collections::BTreeSet<_>>();
            for path in ["tsconfig.json", "shared.json", "package.json"] {
                assert!(files.contains(path), "{files:?} lacks {path}");
            }
        }
    }

    #[test]
    #[hardwon("#2445: warm JS/TS usage indexes omitted resolver configuration from their receipts")]
    fn usage_index_warm_hit_replays_configuration_inputs() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("src")).unwrap();
        std::fs::write(
            root.path().join("src/app.ts"),
            "import { Owner } from '@/owner'; export class App extends Owner {}\n",
        )
        .unwrap();
        std::fs::write(root.path().join("src/owner.ts"), "export class Owner {}\n").unwrap();
        std::fs::write(
            root.path().join("tsconfig.json"),
            r#"{"compilerOptions":{"baseUrl":".","paths":{"@/*":["src/*"]}}}"#,
        )
        .unwrap();
        let project =
            brokk_bifrost_analysis::analyzer::TestProject::new(root.path(), Language::TypeScript);
        let analyzer = TypescriptAnalyzer::from_project(project);
        jsts_usage_index(&analyzer).expect("usage index builds");
        let (_, reads) = capture_query_reads(&analyzer, || {
            jsts_usage_index(&analyzer).expect("warm usage index")
        });
        let question = reads.keys().into_iter().find_map(|key| match key {
            ReadKey::Lookup { question: brokk_bifrost_analysis::analyzer::LookupQuestion::WorkspaceFact { family: brokk_bifrost_analysis::analyzer::WorkspaceFactFamily::JsTsModulePaths, subject, .. }, digest, .. } => Some((subject, digest)),
            _ => None,
        }).expect("warm receipt replays the selected alias answer");
        std::fs::write(
            root.path().join("tsconfig.json"),
            r#"{"compilerOptions":{"baseUrl":".","paths":{"@/*":["missing/*"]}}}"#,
        )
        .unwrap();
        let project =
            brokk_bifrost_analysis::analyzer::TestProject::new(root.path(), Language::TypeScript);
        let head = TypescriptAnalyzer::from_project(project);
        let current = super::super::workspace_facts::answer(
            &head,
            brokk_bifrost_analysis::analyzer::WorkspaceFactFamily::JsTsModulePaths,
            Language::TypeScript,
            &question.0,
        )
        .unwrap();
        assert_ne!(
            question.1, current,
            "the warm unit's selected alias answer is stale"
        );
    }

    #[test]
    #[hardwon("#2445: an oversized usage-index receipt must make later hits unattributed")]
    fn oversized_usage_index_receipt_refuses_a_warm_hit() {
        let (_root, _file, analyzer) = crate::test_typescript_project("export class Owner {}\n");
        let language = analyzer.language();
        let (_, first_reads) = capture_query_reads(&analyzer, || {
            memoized_usage_index_with_receipt_limit(
                &analyzer,
                0,
                || build_jsts_usage_index(&analyzer, analyzer.alias_resolver(), language, true),
                || build_jsts_usage_index(&analyzer, analyzer.alias_resolver(), language, false),
            )
            .expect("the best-effort index is returned")
        });
        assert!(
            first_reads.unattributed_reads() > 0,
            "the refused receipt cannot certify the initial publication: {first_reads:?}"
        );

        let (_, warm_reads) = capture_query_reads(&analyzer, || {
            memoized_usage_index_with_receipt_limit(
                &analyzer,
                0,
                || panic!("a missing receipt must not trigger a rebuild"),
                || panic!("a missing receipt must not trigger a rebuild"),
            )
            .expect("the cached best-effort index is returned")
        });
        assert!(warm_reads.unattributed_reads() > 0, "{warm_reads:?}");
        assert!(
            warm_reads.keys().is_empty(),
            "the entry retained no receipt: {warm_reads:?}"
        );
    }

    #[test]
    #[hardwon(
        "#2445: generation cache hits did not replay their build's reads into a later capture"
    )]
    fn memo_bucket_hits_replay_inputs() {
        let (_root, file, analyzer) = crate::test_typescript_project(
            "class Owner {}
",
        );
        let caches = analyzer.memo_caches();
        let keys = (0_u8..5)
            .map(|index| ReadKey::Configuration(StableDigest::sha256([index])))
            .collect::<Vec<_>>();
        let read = || {
            memoized_value(
                &analyzer,
                &caches.imported_code_units,
                &file,
                weight_code_unit_set,
                || {
                    analyzer.record_read(keys[0].clone());
                    HashSet::default()
                },
            );
            memoized_value(
                &analyzer,
                &caches.imported_target_files,
                &file,
                weight_project_file_set,
                || {
                    analyzer.record_read(keys[1].clone());
                    HashSet::default()
                },
            );
            memoized_value(
                &analyzer,
                &caches.referencing_files,
                &file,
                weight_project_file_set,
                || {
                    analyzer.record_read(keys[2].clone());
                    HashSet::default()
                },
            );
            let owner = analyzer
                .top_level_declarations(&file)
                .into_iter()
                .find(CodeUnit::is_class)
                .unwrap();
            memoized_value(
                &analyzer,
                &caches.direct_ancestors,
                &owner,
                weight_code_unit_vec_by_unit,
                || {
                    analyzer.record_read(keys[3].clone());
                    Vec::new()
                },
            );
            memoized_value(
                &analyzer,
                &caches.relevant_imports,
                &owner,
                super::super::cache::weight_string_set,
                || {
                    analyzer.record_read(keys[4].clone());
                    HashSet::default()
                },
            );
        };
        read();
        for _ in 0..2 {
            let (_, reads) = capture_query_reads(&analyzer, read);
            assert_eq!(reads.unattributed_reads(), 0, "{reads:?}");
            let captured = reads.keys();
            assert!(keys.iter().all(|key| captured.contains(key)), "{reads:?}");
        }
    }

    #[test]
    fn file_owned_memo_hits_record_the_selected_source() {
        let source = "import * as fs from 'fs'; fs.readFile = replacement;
";
        let (_root, file, analyzer) = crate::test_typescript_project(source);
        let tree = brokk_bifrost_js_ts::test_support::parse_typescript(source);
        let binder = brokk_bifrost_js_ts::syntax::compute_import_binder(source, &tree);
        let lexical =
            brokk_bifrost_js_ts::syntax::JsTsLexicalBindingIndex::build(tree.root_node(), source);
        let memo = brokk_bifrost_js_ts::syntax::JsTsModuleMemberWriteMemo::default();
        let read = || {
            assert!(analyzer.source_facts(&file).is_some());
            assert!(
                memo.writes(tree.root_node(), source, "fs", &lexical, &binder)
                    .mutation("readFile")
                    .is_some()
            );
        };
        read();
        for _ in 0..2 {
            let (_, reads) = capture_query_reads(&analyzer, read);
            assert_eq!(reads.unattributed_reads(), 0, "{reads:?}");
            assert!(reads.keys().iter().any(|key| matches!(key, ReadKey::File { rel_path, .. } if rel_path.as_ref() == "src/app.ts")), "{reads:?}");
        }
    }
}
