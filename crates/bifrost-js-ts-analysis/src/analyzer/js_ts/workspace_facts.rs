//! Position-free answers for the complete JS/TS workspace authorities.
use super::providers::{JsTsMemoSource, imported_code_units_of, resolve_js_ts_source};
use brokk_bifrost_analysis::analyzer::semantic::StableDigest;
use brokk_bifrost_analysis::analyzer::workspace_authority::memo_attribution;
use brokk_bifrost_analysis::analyzer::{
    AuthorityInputs, FactSubject, IAnalyzer, WorkspaceAuthorityMemo, WorkspaceFactFamily,
};
use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;
use brokk_bifrost_core::analyzer::capabilities::{
    DescendantIndexScope, DescendantIndexVariant, DirectDescendantIndex, ReverseFileIndex,
    build_reverse_import_index,
};
use brokk_bifrost_core::analyzer::pool_memo::PoolSafeMemo;
use brokk_bifrost_core::analyzer::query_token::{QueryScope, QueryToken};
use brokk_bifrost_core::analyzer::{CodeUnit, Language};
use brokk_bifrost_core::cancellation::CancellationToken;
use brokk_bifrost_core::path_utils::rel_path_string;
use brokk_bifrost_js_ts::hierarchy::build_direct_descendant_index_by_unit;
use std::sync::Arc;

pub(crate) struct Descendants {
    pub index: DirectDescendantIndex,
    answer: StableDigest,
}

pub(crate) struct DescendantMemos {
    whole: WorkspaceAuthorityMemo<PoolSafeMemo<Descendants>>,
    production: WorkspaceAuthorityMemo<PoolSafeMemo<Descendants>>,
}
impl DescendantMemos {
    pub fn new() -> Self {
        Self {
            whole: WorkspaceAuthorityMemo::new(
                WorkspaceFactFamily::JsTsDescendants,
                PoolSafeMemo::new(),
            ),
            production: WorkspaceAuthorityMemo::new(
                WorkspaceFactFamily::JsTsProductionDescendants,
                PoolSafeMemo::new(),
            ),
        }
    }
}

pub(crate) struct ReverseImports {
    pub index: ReverseFileIndex,
    answer: StableDigest,
}

pub(super) fn unit_identity(unit: &CodeUnit) -> StableDigest {
    StableDigest::sha256(unit.declaration_id().as_str())
}

pub(super) fn descendants(
    host: &dyn JsTsMemoSource,
    scope: &DescendantIndexScope<'_>,
) -> Option<Arc<Descendants>> {
    let family = match scope.variant() {
        DescendantIndexVariant::WholeWorkspace => &host.memo_caches().direct_descendant_index.whole,
        DescendantIndexVariant::ProductionOnly => {
            &host.memo_caches().direct_descendant_index.production
        }
    };
    let build = || {
        complete_descendant_build(host.analyzer(), || {
            let index = build_direct_descendant_index_by_unit(host, host, scope)?;
            // Enumerate the complete row domain, including imported ancestors.
            // The temporary vectors die with this one build; only the digest stays.
            let mut classes = host
                .all_declarations()
                .filter(|class| class.is_class() && scope.admits(class))
                .collect::<Vec<_>>();
            let ancestors = classes
                .iter()
                .flat_map(|class| {
                    super::providers::get_direct_ancestors(host, class)
                        .definite()
                        .to_vec()
                })
                .collect::<Vec<_>>();
            classes.extend(ancestors);
            classes.sort();
            classes.dedup();
            let mut rows = classes
                .iter()
                .map(|class| {
                    let mut children = index
                        .descendants(class)
                        .iter()
                        .map(unit_identity)
                        .collect::<Vec<_>>();
                    children.sort();
                    (unit_identity(class), children)
                })
                .collect::<Vec<_>>();
            rows.sort();
            let mut hash = CanonicalHasher::new(b"js-ts-descendants-v1");
            for (class, children) in rows {
                hash.value(class.as_bytes());
                hash.sequence("descendants", &children, |hash, child| {
                    hash.value(child.as_bytes())
                });
            }
            Some(Descendants {
                index,
                answer: StableDigest::from_array(hash.finish()),
            })
        })
    };
    family.read(
        &memo_attribution(host.analyzer()),
        |memo| memo.get_or_build_while(&scope.keep_going(), build, build),
        |value| match value {
            Some(value) => AuthorityInputs::Fact {
                language: host.language(),
                subject: FactSubject::Whole,
                answer: value.answer,
            },
            None => AuthorityInputs::Unnamed,
        },
    )
}

fn complete_descendant_build<T>(
    analyzer: &dyn IAnalyzer,
    build: impl FnOnce() -> Option<T>,
) -> Option<T> {
    brokk_bifrost_analysis::analyzer::common::complete_query_cache_fill(analyzer, build)
        .ok()
        .flatten()
}

fn reverse_value(index: ReverseFileIndex) -> ReverseImports {
    let mut rows = index
        .iter()
        .map(|(target, sources)| {
            let mut sources = sources.iter().map(rel_path_string).collect::<Vec<_>>();
            sources.sort();
            (rel_path_string(target), sources)
        })
        .collect::<Vec<_>>();
    rows.sort();
    let mut hash = CanonicalHasher::new(b"js-ts-reverse-imports-v1");
    for (target, sources) in rows {
        hash.value(target.as_bytes());
        hash.sequence("importers", &sources, |hash, source| {
            hash.value(source.as_bytes())
        });
    }
    ReverseImports {
        index,
        answer: StableDigest::from_array(hash.finish()),
    }
}

pub(super) fn reverse_imports(
    host: &dyn JsTsMemoSource,
    token: QueryToken<'_>,
) -> Arc<ReverseImports> {
    host.memo_caches().reverse_import_index.read(
        &memo_attribution(host.analyzer()),
        |memo| {
            memo.get_or_try_build(
                || {
                    complete_reverse_import_build(host.analyzer(), || {
                        let files = host.all_files();
                        reverse_value(build_reverse_import_index(
                            &files,
                            |file| imported_code_units_of(host, token, file),
                            true,
                        ))
                    })
                },
                || {
                    complete_reverse_import_build(host.analyzer(), || {
                        let files = host.all_files();
                        reverse_value(build_reverse_import_index(
                            &files,
                            |file| imported_code_units_of(host, token, file),
                            false,
                        ))
                    })
                },
            )
            .unwrap_or_else(Arc::new)
        },
        |value| AuthorityInputs::Fact {
            language: host.language(),
            subject: FactSubject::Whole,
            answer: value.answer,
        },
    )
}

fn complete_reverse_import_build<T>(
    analyzer: &dyn IAnalyzer,
    build: impl FnOnce() -> T,
) -> Result<T, T> {
    brokk_bifrost_analysis::analyzer::common::complete_query_cache_fill(analyzer, build)
}

fn module_paths_answer(host: &dyn JsTsMemoSource, subject: &FactSubject) -> Option<StableDigest> {
    let root = host.project().root().to_path_buf();
    let answer = match subject {
        FactSubject::FileNamedMember {
            rel_path,
            owner,
            member,
            environment: None,
        } if owner.is_empty() => {
            let file = brokk_bifrost_core::analyzer::ProjectFile::new(root, rel_path.as_ref());
            host.alias_resolver()
                .candidate_bases_fact_answer(&file, member)?
        }
        FactSubject::File { rel_path } => {
            let file = brokk_bifrost_core::analyzer::ProjectFile::new(root, rel_path.as_ref());
            host.alias_resolver().library_selection_fact_answer(&file)?
        }
        _ => return None,
    };
    Some(StableDigest::from_array(answer))
}

pub(super) fn answer(
    analyzer: &dyn IAnalyzer,
    family: WorkspaceFactFamily,
    language: Language,
    subject: &FactSubject,
) -> Option<StableDigest> {
    if family == WorkspaceFactFamily::JsTsMemberSurface {
        return super::type_flow::member_surface_fact_answer(analyzer, language, subject);
    }
    if family == WorkspaceFactFamily::JsTsModulePaths {
        let host = resolve_js_ts_source(analyzer, language)?;
        return module_paths_answer(host, subject);
    }
    if !matches!(subject, FactSubject::Whole) {
        return None;
    }
    let host = resolve_js_ts_source(analyzer, language)?;
    let cancellation = CancellationToken::default();
    match family {
        WorkspaceFactFamily::JsTsWorkspacePackages => Some(StableDigest::from_array(
            host.alias_resolver().workspace_package_answer(),
        )),
        WorkspaceFactFamily::JsTsReverseImports => {
            let scope = brokk_bifrost_analysis::analyzer::AnalyzerQueryScope::new(analyzer);
            Some(reverse_imports(host, scope.token()).answer)
        }
        WorkspaceFactFamily::JsTsDescendants => {
            descendants(host, &DescendantIndexScope::whole_workspace(&cancellation))
                .map(|value| value.answer)
        }
        WorkspaceFactFamily::JsTsProductionDescendants => {
            let excluded = |file: &brokk_bifrost_core::analyzer::ProjectFile| {
                brokk_bifrost_core::analyzer::test_paths::is_test_like_path(
                    &rel_path_string(file),
                    language,
                ) || analyzer.file_is_test_only(file)
            };
            descendants(
                host,
                &DescendantIndexScope::excluding_sources(&cancellation, &excluded),
            )
            .map(|value| value.answer)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_analysis::analyzer::semantic::type_flow::{ClassIdentity, MemberAccessKind};
    use brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer;
    use brokk_bifrost_analysis::analyzer::{
        AnalyzerConfig, AnalyzerQueryScope, ChangedFacts, LookupKind, LookupMemo, LookupQuestion,
        LookupReplayLimits, NoSummaryAnswers, QueryReadIncomplete, ReadKey, ReadVerdict,
        capture_query_reads,
    };
    use brokk_bifrost_analysis::inline_project::{BuiltInlineTestProject, InlineTestProject};
    use brokk_bifrost_core::analyzer::pool_memo::PoolSafeMemo;
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    fn path_module_whole_answers_follow_admission_and_identity() {
        for (language, extension) in [(Language::JavaScript, "js"), (Language::TypeScript, "ts")] {
            let name = format!("module.{extension}");
            let other = format!("other.{extension}");
            let fixture = InlineTestProject::with_language(language)
                .file(
                    &name,
                    "import './dependency'; export function run() { return 1; }\n",
                )
                .file(&other, "export const value = 1;\n")
                .build();
            let question = LookupQuestion::WorkspaceFact {
                family: WorkspaceFactFamily::PathSyntheticModules,
                language,
                subject: FactSubject::Whole,
            };
            let answer = || {
                let workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
                let mut memo = LookupMemo::new();
                workspace
                    .analyzer()
                    .test_hooks()
                    .reset_workspace_path_scan_count_for_test();
                let first = memo
                    .answer(
                        &workspace,
                        LookupKind::WorkspaceFact,
                        &question,
                        LookupReplayLimits::default(),
                        &NoSummaryAnswers,
                    )
                    .unwrap();
                assert_eq!(
                    memo.answer(
                        &workspace,
                        LookupKind::WorkspaceFact,
                        &question,
                        LookupReplayLimits::default(),
                        &NoSummaryAnswers
                    ),
                    Some(first)
                );
                assert_eq!(memo.len(), 1);
                assert_eq!(
                    workspace
                        .analyzer()
                        .test_hooks()
                        .workspace_path_scan_count_for_test(),
                    1
                );
                first
            };
            let base = answer();
            fixture
                .file(&name)
                .write("// comment\nimport './dependency'; export function run() { return 2; }\n")
                .unwrap();
            fixture
                .file(&other)
                .write("export const value = 3;\n")
                .unwrap();
            assert_eq!(base, answer(), "comments and bodies are not module facts");
            fixture
                .file(&other)
                .write("import './dependency'; export const value = 3;\n")
                .unwrap();
            let admitted = answer();
            assert_ne!(base, admitted, "first structured import admits a module");
            fixture
                .file(&other)
                .write("export const value = 3;\n")
                .unwrap();
            assert_eq!(base, answer(), "last structured import removes admission");
            let added = format!("added.{extension}");
            fixture
                .file(&added)
                .write("import './dependency';\n")
                .unwrap();
            let with_added = answer();
            assert_ne!(base, with_added, "eligible file addition changes the set");
            let renamed = format!("renamed.{extension}");
            std::fs::rename(
                fixture.file(&added).abs_path(),
                fixture.file(&renamed).abs_path(),
            )
            .unwrap();
            let with_renamed = answer();
            assert_ne!(with_added, with_renamed, "renaming changes module identity");
            assert_ne!(base, with_renamed, "the renamed module remains eligible");
            std::fs::remove_file(fixture.file(&renamed).abs_path()).unwrap();
            let deleted = answer();
            assert_ne!(
                with_renamed, deleted,
                "deleting an eligible file changes the set"
            );
            assert_eq!(base, deleted, "deleting the added module restores the set");
        }
    }

    #[test]
    fn path_module_scans_record_whole_without_scope() {
        use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;
        use brokk_bifrost_analysis::analyzer::read_verification::WorkspaceFactIndex;
        let fixture = InlineTestProject::with_language(Language::JavaScript)
            .file("module.js", "import './dependency';\n")
            .build();
        let workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
        let analyzer = resolve_analyzer::<crate::analyzer::javascript::JavascriptAnalyzer>(
            workspace.analyzer(),
        )
        .unwrap();
        for cancellable in [false, true] {
            let _scope = AnalyzerQueryScope::new(workspace.analyzer());
            workspace
                .analyzer()
                .test_hooks()
                .reset_workspace_path_scan_count_for_test();
            for _ in 0..2 {
                let (_, reads) = capture_query_reads(workspace.analyzer(), || {
                    if cancellable {
                        let result = analyzer
                            .inner()
                            .path_synthetic_modules_cancellable_for_test(None)
                            .unwrap();
                        assert!(result.complete);
                        assert_eq!(result.rows.len(), 1);
                    } else {
                        let result = analyzer.inner().path_synthetic_modules_for_test().unwrap();
                        assert_eq!(result.len(), 1);
                    }
                });
                let keys = reads.keys();
                assert!(
                    keys.iter().any(|key| matches!(
                        key,
                        ReadKey::Lookup {
                            question: LookupQuestion::WorkspaceFact {
                                family: WorkspaceFactFamily::PathSyntheticModules,
                                subject: FactSubject::Whole,
                                ..
                            },
                            ..
                        }
                    )),
                    "{keys:?}"
                );
                assert!(
                    !keys.iter().any(|key| matches!(key, ReadKey::Scope { .. })),
                    "{keys:?}"
                );
                assert_eq!(reads.unattributed_reads(), 0, "{reads:?}");
                assert_eq!(reads.execution_dependences(), 0, "{reads:?}");
                assert_eq!(
                    workspace
                        .analyzer()
                        .test_hooks()
                        .workspace_path_scan_count_for_test(),
                    1,
                    "warm reads must reuse the complete query authority"
                );
            }
        }
        let _scope = AnalyzerQueryScope::new(workspace.analyzer());
        // Populate the cache before cancellation: a warm hit must still stop.
        assert!(
            analyzer
                .inner()
                .path_synthetic_modules_answer_digest()
                .is_some()
        );
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let (_, reads) = capture_query_reads(workspace.analyzer(), || {
            let result = analyzer
                .inner()
                .path_synthetic_modules_cancellable_for_test(Some(&cancellation))
                .unwrap();
            assert!(!result.complete);
        });
        assert!(
            !reads.is_bounded(),
            "cancelled reads cannot certify a complete set"
        );
        let _cancelled_scope =
            AnalyzerQueryScope::with_cancellation(workspace.analyzer(), &cancellation);
        assert_eq!(
            analyzer.inner().path_synthetic_modules_answer_digest(),
            None,
            "an interrupted head answer is unavailable, never the empty-set digest"
        );
    }

    #[test]
    fn path_module_set_preserves_body_edits_but_kept_file_reads_reject_them() {
        use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;
        use brokk_bifrost_analysis::analyzer::read_verification::WorkspaceFactIndex;
        let fixture = InlineTestProject::with_language(Language::JavaScript)
            .file(
                "a.js",
                "import './dep'; export function before() { return 1; }\n",
            )
            .file("b.js", "import './dep'; export function untouched() {}\n")
            .file("c.js", "import './dep'; export class Other {}\n")
            .build();
        let base = fixture.workspace_analyzer(AnalyzerConfig::default());
        let analyzer =
            resolve_analyzer::<crate::analyzer::javascript::JavascriptAnalyzer>(base.analyzer())
                .unwrap();
        let _scope = AnalyzerQueryScope::new(base.analyzer());
        let set_answer = analyzer
            .inner()
            .path_synthetic_modules_answer_digest()
            .unwrap();
        assert_eq!(
            analyzer.inner().path_synthetic_module_hydrations_for_test(),
            0,
            "head verification never hydrates a module"
        );
        let (_, reads) = capture_query_reads(base.analyzer(), || {
            let kept = analyzer
                .inner()
                .path_synthetic_modules_named_for_test("a.js")
                .unwrap();
            assert_eq!(kept.len(), 1);
            assert!(
                base.analyzer()
                    .get_source(&kept[0], true)
                    .unwrap()
                    .contains("before")
            );
        });
        assert_eq!(
            analyzer.inner().path_synthetic_module_hydrations_for_test(),
            1,
            "one-name lookup hydrates one kept module, not all three candidates"
        );
        let child = base
            .analyzer()
            .all_declarations()
            .find(|unit| unit.identifier() == "before")
            .unwrap();
        let before_facts =
            brokk_bifrost_analysis::analyzer::read_ledger::declaration_facts_digest(&child, None);
        let files = reads
            .keys()
            .into_iter()
            .filter(
                |key| matches!(key, ReadKey::File {rel_path, ..} if rel_path.as_ref() == "a.js"),
            )
            .collect::<Vec<_>>();
        assert!(
            !files.is_empty(),
            "the caller must actually read a.js: {reads:?}"
        );
        fixture
            .file("a.js")
            .write("import './dep'; export class After {}\n")
            .unwrap();
        let head = fixture.workspace_analyzer(AnalyzerConfig::default());
        let head_analyzer =
            resolve_analyzer::<crate::analyzer::javascript::JavascriptAnalyzer>(head.analyzer())
                .unwrap();
        assert_eq!(
            Some(set_answer),
            head_analyzer.inner().path_synthetic_modules_answer_digest()
        );
        let child = head
            .analyzer()
            .all_declarations()
            .find(|unit| unit.identifier() == "After")
            .unwrap();
        assert_ne!(
            before_facts,
            brokk_bifrost_analysis::analyzer::read_ledger::declaration_facts_digest(&child, None)
        );
        assert_ne!(
            verify(&head, &ChangedFacts::between(&base, &head), &files),
            ReadVerdict::Unchanged,
            "the caller's File key rejects the content edit despite an equal Whole answer"
        );
    }

    #[test]
    fn path_module_set_excludes_persisted_source_admission_refusals() {
        use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;
        use brokk_bifrost_analysis::analyzer::read_verification::WorkspaceFactIndex;
        let admitted = "import './dep'; export function run() { return 1; }\n";
        let baseline = InlineTestProject::with_language(Language::JavaScript)
            .file("module.js", admitted)
            .build();
        let base = baseline.workspace_analyzer(AnalyzerConfig::default());
        let base_analyzer =
            resolve_analyzer::<crate::analyzer::javascript::JavascriptAnalyzer>(base.analyzer())
                .unwrap();
        let expected = base_analyzer
            .inner()
            .path_synthetic_modules_answer_digest()
            .unwrap();
        // Executable syntax, not bulk string data: the structural-line proof
        // must refuse this under the default limit without changing process env.
        let refused = format!(
            "import './dep'; function bundle() {{ {} }}\n",
            "globalThis.step();"
                .repeat(brokk_bifrost_core::analyzer::common::DEFAULT_MAX_LINE_LENGTH / 10,)
        );
        let fixture = InlineTestProject::with_language(Language::JavaScript)
            .file("module.js", admitted)
            .file("minified.js", refused)
            .build();
        let workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
        let analyzer = resolve_analyzer::<crate::analyzer::javascript::JavascriptAnalyzer>(
            workspace.analyzer(),
        )
        .unwrap();
        let refusals = analyzer
            .inner()
            .selected_source_admission_refusals()
            .unwrap();
        assert_eq!(
            refusals.len(),
            1,
            "must prove admission actually refused the file"
        );
        assert_eq!(refusals[0].file, fixture.file("minified.js"));
        let reason: serde_json::Value = serde_json::from_str(&refusals[0].reason).unwrap();
        assert_eq!(reason["code"], "structural_line");
        let scope = AnalyzerQueryScope::capturing_read_incompleteness(workspace.analyzer());
        workspace
            .analyzer()
            .test_hooks()
            .reset_workspace_path_scan_count_for_test();
        for _ in 0..2 {
            let (result, reads) = capture_query_reads(workspace.analyzer(), || {
                analyzer
                    .inner()
                    .path_synthetic_modules_cancellable_for_test(None)
                    .unwrap()
            });
            assert!(result.complete);
            assert_eq!(result.rows.len(), 1);
            assert_eq!(result.rows[0].source(), &fixture.file("module.js"));
            assert!(reads.is_bounded(), "{reads:?}");
            assert_eq!(
                analyzer.inner().path_synthetic_modules_answer_digest(),
                Some(expected)
            );
            assert!(scope.store_error().is_none());
        }
        assert!(scope.captured_read_incompleteness().is_empty());
        assert_eq!(
            workspace
                .analyzer()
                .test_hooks()
                .workspace_path_scan_count_for_test(),
            1
        );
    }

    #[test]
    fn path_module_failed_build_is_replayed_only_within_its_request() {
        use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;
        use brokk_bifrost_core::analyzer::carried_context::CarriedContext;
        let fixture = InlineTestProject::with_language(Language::JavaScript)
            .file("module.js", "import './dep'; export function run() {}\n")
            .build();
        let workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
        let analyzer = resolve_analyzer::<crate::analyzer::javascript::JavascriptAnalyzer>(
            workspace.analyzer(),
        )
        .unwrap();
        let oid = analyzer
            .inner()
            .live_snapshot()
            .oid_for_path(&fixture.file("module.js"))
            .unwrap();
        analyzer
            .inner()
            .analyzer_store()
            .mark_parsed_blob_incomplete_for_test(&brokk_bifrost_core::gitblob::BlobKey::unvaried(
                oid,
                "javascript",
            ));
        workspace
            .analyzer()
            .test_hooks()
            .reset_workspace_path_scan_count_for_test();
        let fresh_request = CarriedContext::current();
        let request = AnalyzerQueryScope::new(workspace.analyzer());
        let mut errors = Vec::new();
        for _ in 0..2 {
            let lookup = AnalyzerQueryScope::capturing_read_incompleteness(workspace.analyzer());
            assert!(analyzer.inner().path_synthetic_modules_for_test().is_none());
            let error = lookup
                .store_error()
                .expect("each lookup must record its typed failure");
            assert!(
                error
                    .to_string()
                    .contains("path-symbol set inputs are not complete")
            );
            assert!(lookup.captured_read_incompleteness().iter().any(|reason| {
                matches!(reason, QueryReadIncomplete::StoreFailure(failure) if failure == &error)
            }));
            errors.push(error);
        }
        assert_eq!(errors[0], errors[1]);
        assert_eq!(
            workspace
                .analyzer()
                .test_hooks()
                .workspace_path_scan_count_for_test(),
            1
        );
        // An overlapping request cannot inherit the failure slot via the
        // analyzer's shared QueryReadCache. It must try its own construction.
        std::thread::scope(|threads| {
            threads
                .spawn(|| {
                    fresh_request.run(|| {
                        let request = AnalyzerQueryScope::new(workspace.analyzer());
                        assert!(analyzer.inner().path_synthetic_modules_for_test().is_none());
                        assert_eq!(request.store_error(), Some(errors[0].clone()));
                    })
                })
                .join()
                .unwrap();
        });
        assert_eq!(
            workspace
                .analyzer()
                .test_hooks()
                .workspace_path_scan_count_for_test(),
            2
        );
        assert!(analyzer.inner().path_synthetic_modules_for_test().is_none());
        assert_eq!(
            workspace
                .analyzer()
                .test_hooks()
                .workspace_path_scan_count_for_test(),
            2
        );
        drop(request);
        let request = AnalyzerQueryScope::new(workspace.analyzer());
        assert!(analyzer.inner().path_synthetic_modules_for_test().is_none());
        assert!(request.store_error().is_some());
        assert_eq!(
            workspace
                .analyzer()
                .test_hooks()
                .workspace_path_scan_count_for_test(),
            3
        );
    }

    fn project() -> BuiltInlineTestProject {
        InlineTestProject::with_language(Language::TypeScript)
            .file("a.ts", "export class A {}\n")
            .file("b.ts", "export class B {}\n")
            .file("package.json", r#"{"name":"root-package","main":"a.ts"}"#)
            .build()
    }

    #[test]
    #[hardwon("#2445: an unresolved relative module specifier recorded none of its probed paths")]
    fn unresolved_alias_and_relative_modules_record_every_absent_probe() {
        use brokk_bifrost_js_ts::imports::{
            js_ts_module_specifier_probed_paths, resolve_js_ts_module_specifier,
        };
        let project = InlineTestProject::with_language(Language::TypeScript)
            .file("src/app.ts", "export class App {}\n")
            .file(
                "tsconfig.json",
                r#"{"compilerOptions":{"baseUrl":".","paths":{"@/*":["src/*","fallback/*"]}}}"#,
            )
            .build();
        let base = project.workspace_analyzer(AnalyzerConfig::default());
        let host = resolve_js_ts_source(base.analyzer(), Language::TypeScript).unwrap();
        let file =
            brokk_bifrost_core::analyzer::ProjectFile::new(host.project().root(), "src/app.ts");
        let mut captures = Vec::new();
        for specifier in ["@/owner", "./owner"] {
            let expected = js_ts_module_specifier_probed_paths(
                &file,
                specifier,
                Language::TypeScript,
                Some(host.alias_resolver()),
            )
            .iter()
            .map(|path| ReadKey::path_absent(Language::TypeScript, rel_path_string(path)))
            .collect::<Vec<_>>();
            assert!(expected.iter().any(|key| matches!(key, ReadKey::PathAbsent { rel_path, .. } if rel_path.as_ref() == "src/owner.ts")));
            for _ in 0..2 {
                let (files, reads) = capture_query_reads(base.analyzer(), || {
                    resolve_js_ts_module_specifier(
                        &file,
                        specifier,
                        Language::TypeScript,
                        Some(host.alias_resolver()),
                    )
                });
                assert!(files.is_empty());
                assert_eq!(reads.unattributed_reads(), 0, "{reads:?}");
                assert!(
                    reads
                        .keys()
                        .iter()
                        .all(|key| !matches!(key, ReadKey::Scope { .. })),
                    "{specifier}: {reads:?}"
                );
                let mut absent = reads
                    .keys()
                    .into_iter()
                    .filter(|key| matches!(key, ReadKey::PathAbsent { .. }))
                    .collect::<Vec<_>>();
                absent.sort_by_key(ReadKey::canonical_digest);
                let mut expected = expected.clone();
                expected.sort_by_key(ReadKey::canonical_digest);
                assert_eq!(absent, expected, "{specifier}: {reads:?}");
                assert_eq!(
                    verify(&base, &ChangedFacts::between(&base, &base), &absent),
                    ReadVerdict::Unchanged
                );
                captures.push(absent);
            }
        }
        project
            .file("src/owner.ts")
            .write("export class Owner {}\n")
            .unwrap();
        let head = project.workspace_analyzer(AnalyzerConfig::default());
        for reads in captures {
            assert_ne!(
                verify(&head, &ChangedFacts::between(&base, &head), &reads),
                ReadVerdict::Unchanged
            );
        }
    }

    #[test]
    fn module_path_questions_replay_only_selected_answers() {
        let project = InlineTestProject::with_language(Language::TypeScript)
            .file("src/app.ts", "export class App {}\n")
            .file("unrelated.ts", "export class Unrelated {}\n")
            .file("shared.json", r#"{"compilerOptions":{"baseUrl":".","paths":{"@/*":["src/*","fallback/*"]},"lib":["es5"]}}"#)
            .file("tsconfig.json", r#"{"extends":"./shared.json"}"#)
            .build();
        project
            .file("other/tsconfig.json")
            .write(" ".repeat(1024 * 1024 + 1))
            .unwrap();
        let base = project.workspace_analyzer(AnalyzerConfig::default());
        let host = resolve_js_ts_source(base.analyzer(), Language::TypeScript).unwrap();
        let file =
            brokk_bifrost_core::analyzer::ProjectFile::new(host.project().root(), "src/app.ts");
        let unrelated_file =
            brokk_bifrost_core::analyzer::ProjectFile::new(host.project().root(), "other/app.ts");
        assert!(
            host.alias_resolver()
                .candidate_bases(&unrelated_file, "@/owner")
                .is_empty()
        );
        let mut first = None;
        for _ in 0..2 {
            let (_, reads) = capture_query_reads(base.analyzer(), || {
                assert_eq!(
                    host.alias_resolver().candidate_bases(&file, "@/owner"),
                    [
                        std::path::PathBuf::from("src/owner"),
                        std::path::PathBuf::from("fallback/owner")
                    ]
                );
                assert!(
                    host.alias_resolver()
                        .effective_library_selection(&file)
                        .is_complete()
                );
            });
            assert_eq!(reads.unattributed_reads(), 0, "{reads:?}");
            assert_eq!(reads.execution_dependences(), 0, "{reads:?}");
            let keys = reads.keys();
            assert_eq!(keys.len(), 2, "{reads:?}");
            assert!(
                keys.iter().all(|key| matches!(
                    key,
                    ReadKey::Lookup {
                        question: LookupQuestion::WorkspaceFact {
                            family: WorkspaceFactFamily::JsTsModulePaths,
                            ..
                        },
                        ..
                    }
                )),
                "{reads:?}"
            );
            assert_eq!(
                verify(&base, &ChangedFacts::between(&base, &base), &keys),
                ReadVerdict::Unchanged
            );
            if let Some(first) = &first {
                assert_eq!(first, &keys);
            } else {
                first = Some(keys);
            }
        }
        let keys = first.unwrap();
        for (path, source, unchanged) in [
            (
                "unrelated.ts",
                "// unrelated\nexport class Unrelated { other() {} }\n",
                true,
            ),
            (
                "shared.json",
                "// JSONC comment\n{\"compilerOptions\":{\"baseUrl\":\".\",\"paths\":{\"@/*\":[\"src/*\",\"fallback/*\"],\"unused/*\":[\"unused/*\"]},\"lib\":[\"es5\"]}}",
                true,
            ),
            (
                "shared.json",
                r#"{"compilerOptions":{"baseUrl":".","paths":{"@/*":["fallback/*","src/*"]},"lib":["es5"]}}"#,
                false,
            ),
            (
                "shared.json",
                r#"{"compilerOptions":{"baseUrl":"other","paths":{"@/*":["src/*","fallback/*"]},"lib":["es5"]}}"#,
                false,
            ),
            (
                "shared.json",
                r#"{"compilerOptions":{"baseUrl":".","paths":{"@/*":["src/*","fallback/*"]},"lib":["es2020"]}}"#,
                false,
            ),
            ("shared.json", "{ invalid", false),
        ] {
            project.file(path).write(source).unwrap();
            let head = project.workspace_analyzer(AnalyzerConfig::default());
            assert_eq!(
                verify(&head, &ChangedFacts::between(&base, &head), &keys)
                    == ReadVerdict::Unchanged,
                unchanged,
                "{path}: {source}"
            );
        }
        project
            .file("src/tsconfig.json")
            .write(r#"{"compilerOptions":{"paths":{"@/*":["near/*"]},"lib":["dom"]}}"#)
            .unwrap();
        let head = project.workspace_analyzer(AnalyzerConfig::default());
        assert_ne!(
            verify(&head, &ChangedFacts::between(&base, &head), &keys),
            ReadVerdict::Unchanged
        );
    }

    fn receiver(workspace: &WorkspaceAnalyzer) -> CodeUnit {
        workspace
            .analyzer()
            .all_declarations()
            .find(|unit| unit.is_class() && unit.identifier() == "A")
            .unwrap()
    }

    fn subject(workspace: &WorkspaceAnalyzer, family: WorkspaceFactFamily) -> FactSubject {
        if family == WorkspaceFactFamily::JsTsMemberSurface {
            FactSubject::ClassMember {
                class: unit_identity(&receiver(workspace)),
                member: "missing".into(),
            }
        } else {
            FactSubject::Whole
        }
    }

    fn captured_question(
        workspace: &WorkspaceAnalyzer,
        family: WorkspaceFactFamily,
    ) -> Vec<ReadKey> {
        let language = workspace.analyzer().languages().into_iter().next().unwrap();
        let (_, reads) = capture_query_reads(workspace.analyzer(), || {
            if family == WorkspaceFactFamily::JsTsMemberSurface {
                super::super::type_flow::member_lookup(
                    workspace,
                    language,
                    MemberAccessKind::Load,
                    &ClassIdentity::Workspace(receiver(workspace)),
                    "missing",
                );
            } else {
                assert!(
                    answer(workspace.analyzer(), family, language, &FactSubject::Whole).is_some()
                );
            }
        });
        assert_eq!(reads.unattributed_reads(), 0, "{reads:?}");
        let keys = reads.keys().into_iter().filter(|key| matches!(key, ReadKey::Lookup { question: LookupQuestion::WorkspaceFact { family: recorded, .. }, .. } if *recorded == family)).collect::<Vec<_>>();
        assert_eq!(keys.len(), 1, "{reads:?}");
        keys
    }

    fn verify(head: &WorkspaceAnalyzer, changed: &ChangedFacts, keys: &[ReadKey]) -> ReadVerdict {
        brokk_bifrost_analysis::analyzer::read_verification::verify_read_set(
            head,
            changed,
            &brokk_bifrost_analysis::test_support::read_ledger_test_inputs(),
            keys,
            LookupReplayLimits::default(),
            &NoSummaryAnswers,
            &mut LookupMemo::new(),
        )
    }

    fn unimported_edit_is_rejected(family: WorkspaceFactFamily) {
        let project = project();
        let base = project.workspace_analyzer(AnalyzerConfig::default());
        let keys = captured_question(&base, family);
        assert_eq!(
            verify(&base, &ChangedFacts::between(&base, &base), &keys),
            ReadVerdict::Unchanged
        );
        match family {
            WorkspaceFactFamily::JsTsWorkspacePackages => project
                .file("new-package/package.json")
                .write(r#"{"name":"new-package","main":"../a.ts"}"#)
                .unwrap(),
            WorkspaceFactFamily::JsTsMemberSurface => project
                .file("b.ts")
                .write("import {A} from './a'; A.prototype.missing = () => 1;\n")
                .unwrap(),
            _ => project
                .file("b.ts")
                .write("import {A} from './a'; export class B extends A {}\n")
                .unwrap(),
        }
        let head = project.workspace_analyzer(AnalyzerConfig::default());
        assert_ne!(
            verify(&head, &ChangedFacts::between(&base, &head), &keys),
            ReadVerdict::Unchanged,
            "{family:?} retained a changed answer"
        );
    }

    fn same_snapshot_is_stable(family: WorkspaceFactFamily) {
        let project = project();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let question = subject(&workspace, family);
        let first = answer(
            workspace.analyzer(),
            family,
            Language::TypeScript,
            &question,
        )
        .unwrap();
        assert_eq!(
            Some(first),
            answer(
                workspace.analyzer(),
                family,
                Language::TypeScript,
                &question
            )
        );
    }

    fn leading_comment_preserves_answer(family: WorkspaceFactFamily) {
        let project = project();
        if family == WorkspaceFactFamily::JsTsReverseImports {
            project
                .file("b.ts")
                .write("import {A} from './a'; export class B {}\n")
                .unwrap();
        }
        let base = project.workspace_analyzer(AnalyzerConfig::default());
        let question = subject(&base, family);
        let first = answer(base.analyzer(), family, Language::TypeScript, &question).unwrap();
        let (path, source) = match family {
            WorkspaceFactFamily::JsTsMemberSurface => (
                "a.ts",
                "// Comment before the first declaration.\nexport class A {}\n",
            ),
            WorkspaceFactFamily::JsTsReverseImports => (
                "b.ts",
                "// Comment before the first declaration.\nimport {A} from './a'; export class B {}\n",
            ),
            _ => (
                "b.ts",
                "// Comment before the first declaration.\nexport class B {}\n",
            ),
        };
        project.file(path).write(source).unwrap();
        let head = project.workspace_analyzer(AnalyzerConfig::default());
        assert_eq!(
            Some(first),
            answer(head.analyzer(), family, Language::TypeScript, &question)
        );
    }

    macro_rules! family_cases {
        ($module:ident, $family:ident) => {
            mod $module {
                use super::*;
                #[test]
                #[hardwon("#2445: workspace memo hits omitted inputs from unimported files")]
                fn unimported_answer_edit_is_rejected() {
                    unimported_edit_is_rejected(WorkspaceFactFamily::$family);
                }
                #[test]
                fn unchanged_snapshot_has_equal_answers() {
                    same_snapshot_is_stable(WorkspaceFactFamily::$family);
                }
                #[test]
                fn comment_above_first_declaration_preserves_answer() {
                    leading_comment_preserves_answer(WorkspaceFactFamily::$family);
                }
            }
        };
    }
    family_cases!(workspace_packages, JsTsWorkspacePackages);
    family_cases!(descendants, JsTsDescendants);
    family_cases!(production_descendants, JsTsProductionDescendants);
    family_cases!(reverse_imports, JsTsReverseImports);
    family_cases!(member_surface, JsTsMemberSurface);

    #[test]
    #[hardwon("#2445: an incomplete descendant index build was published as complete")]
    fn incomplete_descendant_build_returns_none_without_publication() {
        let project = project();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let memo = PoolSafeMemo::new();
        let incomplete = || {
            complete_descendant_build(workspace.analyzer(), || {
                workspace
                    .analyzer()
                    .record_query_incomplete(QueryReadIncomplete::Cancelled);
                Some(7_u8)
            })
        };

        assert!(
            memo.get_or_build_while(&|| true, incomplete, incomplete)
                .is_none()
        );
        assert!(!memo.is_ready(), "an incomplete answer was published");
    }

    #[test]
    #[hardwon("#2445: an incomplete reverse-import index build was published as complete")]
    fn incomplete_reverse_import_build_returns_value_without_publication() {
        let project = project();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let memo = PoolSafeMemo::new();
        let incomplete = || {
            complete_reverse_import_build(workspace.analyzer(), || {
                workspace
                    .analyzer()
                    .record_query_incomplete(QueryReadIncomplete::Cancelled);
                ReverseImports {
                    index: Default::default(),
                    answer: StableDigest::sha256("partial"),
                }
            })
        };

        let returned = memo
            .get_or_try_build(incomplete, incomplete)
            .unwrap_or_else(Arc::new);
        assert!(
            returned.index.is_empty(),
            "the best-effort value is returned"
        );
        assert!(!memo.is_ready(), "an incomplete answer was published");
    }

    #[test]
    #[hardwon("#2445: warm member-surface survey reuse omitted receiver/member authority reads")]
    fn member_surface_warm_reads_name_the_receiver() {
        let project = project();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let _scope = AnalyzerQueryScope::new(workspace.analyzer());
        for _ in 0..2 {
            let keys = captured_question(&workspace, WorkspaceFactFamily::JsTsMemberSurface);
            assert!(
                matches!(&keys[0], ReadKey::Lookup { kind: LookupKind::WorkspaceFact, question: LookupQuestion::WorkspaceFact { subject: FactSubject::ClassMember { member, .. }, .. }, .. } if member.as_ref() == "missing")
            );
        }
    }
    #[test]
    fn javascript_authorities_record_replayable_questions() {
        let project = InlineTestProject::with_language(Language::JavaScript)
            .file("a.js", "export class A {}\n")
            .file("b.js", "export class B {}\n")
            .file("package.json", r#"{"name":"root-package","main":"a.js"}"#)
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        for family in [
            WorkspaceFactFamily::JsTsWorkspacePackages,
            WorkspaceFactFamily::JsTsDescendants,
            WorkspaceFactFamily::JsTsProductionDescendants,
            WorkspaceFactFamily::JsTsReverseImports,
            WorkspaceFactFamily::JsTsMemberSurface,
        ] {
            let keys = captured_question(&workspace, family);
            assert_eq!(
                verify(
                    &workspace,
                    &ChangedFacts::between(&workspace, &workspace),
                    &keys
                ),
                ReadVerdict::Unchanged
            );
        }
    }
    #[test]
    fn test_only_descendants_do_not_change_the_production_answer() {
        let project = project();
        project
            .file("tests/case.test.ts")
            .write("import {A} from '../a'; class TestOnly extends A {}\n")
            .unwrap();
        let base = project.workspace_analyzer(AnalyzerConfig::default());
        let whole = answer(
            base.analyzer(),
            WorkspaceFactFamily::JsTsDescendants,
            Language::TypeScript,
            &FactSubject::Whole,
        )
        .unwrap();
        let production = answer(
            base.analyzer(),
            WorkspaceFactFamily::JsTsProductionDescendants,
            Language::TypeScript,
            &FactSubject::Whole,
        )
        .unwrap();
        assert_ne!(whole, production);
        project
            .file("tests/case.test.ts")
            .write("import {B} from '../b'; class TestOnly extends B {}\n")
            .unwrap();
        let head = project.workspace_analyzer(AnalyzerConfig::default());
        assert_ne!(
            Some(whole),
            answer(
                head.analyzer(),
                WorkspaceFactFamily::JsTsDescendants,
                Language::TypeScript,
                &FactSubject::Whole
            )
        );
        assert_eq!(
            Some(production),
            answer(
                head.analyzer(),
                WorkspaceFactFamily::JsTsProductionDescendants,
                Language::TypeScript,
                &FactSubject::Whole
            )
        );
    }
}
