//! Position-independent certificates for Java's complete import inventory and
//! individual forward class questions, including empty and ambiguous answers.
use super::JavaAnalyzer;
use brokk_bifrost_analysis::analyzer::analyzer_definition_lookup::ForwardQueryProvider;
use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;
use brokk_bifrost_analysis::analyzer::semantic::{LengthDelimitedDigest, StableDigest};
use brokk_bifrost_analysis::analyzer::workspace_authority::{AuthorityInputs, memo_attribution};
use brokk_bifrost_analysis::analyzer::{
    AnalyzerQueryScope, FactSubject, IAnalyzer, ProjectFile, QueryScope, QueryToken,
    WorkspaceAuthorityMemo, WorkspaceFactFamily,
};
use brokk_bifrost_core::analyzer::CodeUnitIndex;
use brokk_bifrost_core::analyzer::model::{CodeUnit, Language};

fn classes_digest(units: &[CodeUnit], complete: bool) -> StableDigest {
    let mut identities = units
        .iter()
        .map(|unit| {
            (
                brokk_bifrost_analysis::path_utils::workspace_relative_slash_path(
                    unit.source().rel_path(),
                ),
                unit.fq_name(),
            )
        })
        .collect::<Vec<_>>();
    identities.sort();
    let mut digest = LengthDelimitedDigest::new(b"java-workspace-class-answer/v1");
    digest.push(&[u8::from(complete)]);
    // Preserve multiplicity: malformed same-name declarations are still peers.
    for (path, name) in identities {
        digest.push(path.as_bytes());
        digest.push(name.as_bytes());
    }
    digest.finish()
}

impl JavaAnalyzer {
    pub(super) fn import_inventory_answer(&self) -> StableDigest {
        self.import_inventory.read(
            &memo_attribution(self),
            |cell| {
                brokk_bifrost_analysis::analyzer::common::replayable_query_cache_cell(
                    self,
                    cell,
                    || {
                        // The digest covers workspace classes only, so it does not read
                        // the external index: a missing jar changes no byte of it. A
                        // single-type import whose package-prefix split a missing jar
                        // could satisfy is an entry of the file that writes it, and
                        // `JavaAnalyzer::resolve_imports` records the index's gaps for
                        // that entry. Reading the index here made every Java query
                        // partial while any jar was missing (#10470).
                        // Complete enumeration precedes the digest. Retain only the
                        // scalar, not another workspace-sized declaration inventory.
                        let classes = self
                            .all_declarations()
                            .filter(CodeUnit::is_class)
                            .collect::<Vec<_>>();
                        classes_digest(&classes, self.has_complete_symbol_lookup_index())
                    },
                )
            },
            |answer| AuthorityInputs::Fact {
                language: Language::Java,
                subject: FactSubject::Whole,
                answer: *answer,
            },
        )
    }

    pub(super) fn workspace_classes(&self, name: &str) -> Vec<CodeUnit> {
        WorkspaceAuthorityMemo::new(WorkspaceFactFamily::JavaWorkspaceClasses, ()).read(
            &memo_attribution(self),
            |_| {
                ForwardQueryProvider::forward_definition_fqn(self, name)
                    .into_iter()
                    .filter(CodeUnit::is_class)
                    .collect::<Vec<_>>()
            },
            |units| AuthorityInputs::Fact {
                language: Language::Java,
                subject: FactSubject::Named { name: name.into() },
                answer: classes_digest(units, self.has_complete_symbol_lookup_index()),
            },
        )
    }
}

fn imported_type_subject(file: &ProjectFile, name: &str) -> FactSubject {
    FactSubject::FileNamedMember {
        rel_path: brokk_bifrost_analysis::path_utils::workspace_relative_slash_path(
            file.rel_path(),
        )
        .into(),
        owner: "".into(),
        member: name.trim().into(),
        environment: None,
    }
}

/// A name-resolution answer, not a certificate that an import line exists.
/// The shared type-name walker performs bounded seeks for the explicit,
/// on-demand, and package tiers. Its completeness bit is part of this answer;
/// asking the whole-inventory authority here would enumerate unrelated types.
fn imported_type_candidates(
    java: &JavaAnalyzer,
    token: QueryToken<'_>,
    file: &ProjectFile,
    name: &str,
) -> Vec<CodeUnit> {
    use brokk_bifrost_jvm::java::graph_support::{
        forward_source_classes_by_fqn, resolve_java_type_name_with,
    };
    use brokk_bifrost_jvm::java::import_split::JavaImportInventory;

    WorkspaceAuthorityMemo::new(WorkspaceFactFamily::JavaImportedTypeResolution, ()).read(
        &memo_attribution(java),
        |_| {
            let classes_at = |fqn: &str| forward_source_classes_by_fqn(java, file, fqn);
            let inventory = if java.has_complete_symbol_lookup_index() {
                JavaImportInventory::exhaustive(&classes_at)
            } else {
                JavaImportInventory::partial(&classes_at)
            };
            resolve_java_type_name_with(java, token, file, name.trim(), inventory)
        },
        |units| AuthorityInputs::Fact {
            language: Language::Java,
            subject: imported_type_subject(file, name),
            answer: classes_digest(units, java.has_complete_symbol_lookup_index()),
        },
    )
}

pub(super) fn imported_type_name(
    java: &JavaAnalyzer,
    token: QueryToken<'_>,
    file: &ProjectFile,
    name: &str,
) -> Option<CodeUnit> {
    brokk_bifrost_jvm::java::graph_support::unique_candidate(imported_type_candidates(
        java, token, file, name,
    ))
}

pub(super) fn answer(
    analyzer: &dyn IAnalyzer,
    family: WorkspaceFactFamily,
    language: Language,
    subject: &FactSubject,
) -> Option<StableDigest> {
    if language != Language::Java {
        return None;
    }
    let java = resolve_analyzer::<JavaAnalyzer>(analyzer)?;
    match (family, subject) {
        (WorkspaceFactFamily::JavaImportInventory, FactSubject::Whole) => {
            Some(java.import_inventory_answer())
        }
        (
            WorkspaceFactFamily::JavaImportedTypeResolution,
            FactSubject::FileNamedMember {
                rel_path,
                owner,
                member,
                environment: None,
            },
        ) if owner.is_empty() => {
            let file = java
                .project()
                .file_by_rel_path(std::path::Path::new(rel_path.as_ref()))?;
            let scope = AnalyzerQueryScope::new(java);
            Some(classes_digest(
                &imported_type_candidates(java, scope.token(), &file, member),
                java.has_complete_symbol_lookup_index(),
            ))
        }
        (WorkspaceFactFamily::JavaWorkspaceClasses, FactSubject::Named { name }) => {
            Some(classes_digest(
                &java.workspace_classes(name),
                java.has_complete_symbol_lookup_index(),
            ))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_analysis::analyzer::{ReadKey, capture_query_reads};
    use brokk_bifrost_jvm::java::graph_support::JavaSource;
    use brokk_bifrost_test_macros::hardwon;

    fn fixture() -> crate::inline_project::BuiltInlineTestProject {
        InlineTestProject::with_language(Language::Java)
            .file("app/Target.java", "package app; class Target {}\n")
            .file("lib/Base.java", "package lib; public class Base {}\n")
            .build()
    }

    #[test]
    #[hardwon(
        "#8184: a retained replayable fill replayed the enclosing query's unrelated gap to later queries"
    )]
    fn replayable_cell_does_not_replay_enclosing_query_gap() {
        use brokk_bifrost_analysis::analyzer::QueryReadIncomplete;
        use brokk_bifrost_analysis::analyzer::common::{
            QueryCacheCell, replayable_query_cache_cell,
        };

        let project = fixture();
        let java = JavaAnalyzer::new(project.project_arc());
        let cell = QueryCacheCell::new();

        {
            let _scope = AnalyzerQueryScope::capturing_read_incompleteness(&java);
            java.record_query_incomplete(QueryReadIncomplete::SemanticEvidenceGap(
                "unrelated".into(),
            ));
            assert_eq!(replayable_query_cache_cell(&java, &cell, || 7), 7);
        }

        let clean = AnalyzerQueryScope::capturing_read_incompleteness(&java);
        assert_eq!(
            replayable_query_cache_cell(&java, &cell, || panic!("must hit")),
            7
        );
        assert!(clean.captured_read_incompleteness().is_empty());
    }

    #[test]
    fn replayable_cell_preserves_closed_query_obligations_on_warm_reads() {
        use brokk_bifrost_analysis::analyzer::common::{
            QueryCacheCell, ReplayableQueryCacheValue, replayable_query_cache_cell,
        };
        use brokk_bifrost_analysis::analyzer::resolution::{FactResolutionAnswer, QueryObligation, QueryObligations};
        use brokk_bifrost_analysis::analyzer::resolution::query_obligations::replay_observations::{
            answer_for_cache_test, read_closed_answer_for_cache_test,
        };
        let project = fixture();
        let java = JavaAnalyzer::new(project.project_arc());
        let cell: QueryCacheCell<ReplayableQueryCacheValue<FactResolutionAnswer>> =
            QueryCacheCell::new();
        let mut expected = QueryObligations::empty();
        expected.insert(QueryObligation::new(
            "jvm-default-import-package-open",
            "java.lang",
            "unacquired",
        ));
        let cold_answer;
        let mut cold_consumer = QueryObligations::empty();
        {
            let clean = AnalyzerQueryScope::new(&java);
            cold_answer = read_closed_answer_for_cache_test(
                replayable_query_cache_cell(&java, &cell, || {
                    answer_for_cache_test(expected.clone())
                }),
                &mut cold_consumer,
            );
            assert!(clean.read_completion().is_ok());
        }
        assert_eq!(cold_consumer, expected);
        let clean = AnalyzerQueryScope::new(&java);
        let mut warm_consumer = QueryObligations::empty();
        let warm_answer = read_closed_answer_for_cache_test(
            replayable_query_cache_cell(&java, &cell, || panic!("same environment must hit")),
            &mut warm_consumer,
        );
        assert_eq!(warm_answer, cold_answer);
        assert_eq!(warm_consumer, cold_consumer);
        assert!(
            clean.read_completion().is_ok(),
            "obligations are independent of typed read incompleteness"
        );
    }

    #[test]
    fn replayable_answer_cache_misses_on_selected_environment_change() {
        use brokk_bifrost_analysis::analyzer::common::{
            build_replayable_query_cache, read_replayable_query_cache, replayable_query_cache_value,
        };
        use brokk_bifrost_analysis::analyzer::resolution::{FactResolutionAnswer, QueryObligation, QueryObligations};
        use brokk_bifrost_analysis::analyzer::resolution::query_obligations::replay_observations::{
            answer_for_cache_test, read_closed_answer_for_cache_test,
        };
        use brokk_bifrost_core::analyzer::config::JvmSourceToolchainBinding;
        use std::path::PathBuf;
        use std::sync::Arc;
        let project = fixture();
        let file = project.file("app/Target.java");
        let selected = ["unacquired-jdk-a", "unacquired-jdk-b"].map(|name| {
            let home = project.root().join(name);
            assert!(!home.exists());
            let mut config = brokk_bifrost_analysis::test_support::hermetic_jvm_config();
            config.jvm.standard_library_discovery.source_toolchains =
                vec![JvmSourceToolchainBinding::new(PathBuf::new(), home)];
            JavaAnalyzer::new_with_config(project.project_dyn(), config)
        });
        let keys = selected.each_ref().map(|java| {
            java.selected_jdk_home_for_file(&file)
                .unwrap()
                .to_path_buf()
        });
        assert_ne!(keys[0], keys[1]);
        // A cell owner fixes an environment. A cache shared across selections
        // must key it explicitly, even if the two unacquired answers coincide.
        let cache = build_replayable_query_cache(|_: &Arc<FactResolutionAnswer>| {
            std::mem::size_of::<FactResolutionAnswer>()
        });
        let builds = std::cell::Cell::new(0);
        let mut expected = QueryObligations::empty();
        expected.insert(QueryObligation::new(
            "jvm-default-import-package-open",
            "java.lang",
            "unacquired",
        ));
        for (selection, expected_builds) in [(0, 1), (0, 1), (1, 2), (1, 2)] {
            let java = &selected[selection];
            let clean = AnalyzerQueryScope::new(java);
            let answer = read_replayable_query_cache(&cache, &keys[selection], || {
                builds.set(builds.get() + 1);
                replayable_query_cache_value(java, || {
                    Arc::new(answer_for_cache_test(expected.clone()))
                })
            });
            let mut consumer = QueryObligations::empty();
            let value =
                read_closed_answer_for_cache_test(answer.replay().as_ref().clone(), &mut consumer);
            assert_eq!(value.query_obligations, expected);
            assert_eq!(consumer, expected);
            assert_eq!(builds.get(), expected_builds, "selection={selection}");
            assert!(clean.read_completion().is_ok());
        }
    }

    #[test]
    fn replayable_cell_clean_first_stays_clean() {
        use brokk_bifrost_analysis::analyzer::common::{
            QueryCacheCell, replayable_query_cache_cell,
        };

        let project = fixture();
        let java = JavaAnalyzer::new(project.project_arc());
        let cell = QueryCacheCell::new();
        let builds = std::cell::Cell::new(0);

        let first = AnalyzerQueryScope::capturing_read_incompleteness(&java);
        assert_eq!(
            replayable_query_cache_cell(&java, &cell, || {
                builds.set(builds.get() + 1);
                7
            }),
            7
        );
        assert!(first.captured_read_incompleteness().is_empty());
        drop(first);

        let second = AnalyzerQueryScope::capturing_read_incompleteness(&java);
        assert_eq!(
            replayable_query_cache_cell(&java, &cell, || panic!("must hit")),
            7
        );
        assert!(second.captured_read_incompleteness().is_empty());
        assert_eq!(builds.get(), 1);
    }

    #[test]
    #[hardwon(
        "#8184: retained fills must replay every own reason and read channel without caller gaps"
    )]
    fn replayable_cell_replays_all_own_reasons_and_unattributed_reads() {
        use brokk_bifrost_analysis::analyzer::QueryReadIncomplete;
        use brokk_bifrost_analysis::analyzer::common::{
            QueryCacheCell, replayable_query_cache_cell,
        };
        let project = fixture();
        let java = JavaAnalyzer::new(project.project_arc());
        let cell = QueryCacheCell::new();
        let reasons = vec![
            QueryReadIncomplete::ArtifactUnavailable("artifact".into()),
            QueryReadIncomplete::SemanticEvidenceGap("own".into()),
        ];
        {
            let _outer = AnalyzerQueryScope::capturing_read_incompleteness(&java);
            java.record_query_incomplete(QueryReadIncomplete::SemanticEvidenceGap(
                "unrelated".into(),
            ));
            let (_, cold) = capture_query_reads(&java, || {
                replayable_query_cache_cell(&java, &cell, || {
                    for reason in &reasons {
                        java.record_query_incomplete(reason.clone());
                    }
                    java.record_unattributed_read();
                    7
                })
            });
            assert_eq!(cold.unattributed_reads(), 1);
        }
        let clean = AnalyzerQueryScope::capturing_read_incompleteness(&java);
        let (value, warm) = capture_query_reads(&java, || {
            replayable_query_cache_cell(&java, &cell, || panic!("must hit"))
        });
        assert_eq!(value, 7);
        assert_eq!(clean.captured_read_incompleteness(), reasons);
        assert_eq!(warm.unattributed_reads(), 1);
    }

    #[test]
    fn retained_fill_request_domain_is_transported_and_released() {
        use brokk_bifrost_analysis::analyzer::common::{
            QueryCacheCell, replayable_query_cache_cell,
        };
        use brokk_bifrost_core::analyzer::carried_context::CarriedContext;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        let project = fixture();
        let java = JavaAnalyzer::new(project.project_arc());
        let _outer = AnalyzerQueryScope::new(&java);
        let outer_memo = java
            .inner
            .active_query_request_memo::<AtomicUsize>()
            .unwrap();
        outer_memo.store(19, Ordering::Relaxed);
        let cell = QueryCacheCell::new();
        replayable_query_cache_cell(&java, &cell, || {
            let inner_memo = java
                .inner
                .active_query_request_memo::<AtomicUsize>()
                .unwrap();
            assert_eq!(inner_memo.load(Ordering::Relaxed), 0);
            assert!(!Arc::ptr_eq(&outer_memo, &inner_memo));
            inner_memo.store(7, Ordering::Relaxed);
            let carried = CarriedContext::current();
            std::thread::scope(|threads| {
                threads
                    .spawn(|| {
                        carried.run(|| {
                            let _nested = AnalyzerQueryScope::new(&java);
                            let transported = java
                                .inner
                                .active_query_request_memo::<AtomicUsize>()
                                .unwrap();
                            assert!(Arc::ptr_eq(&inner_memo, &transported));
                            assert_eq!(transported.load(Ordering::Relaxed), 7);
                        })
                    })
                    .join()
                    .expect("transported fill worker");
            });
        });
        assert!(Arc::ptr_eq(
            &outer_memo,
            &java
                .inner
                .active_query_request_memo::<AtomicUsize>()
                .unwrap()
        ));
        assert_eq!(outer_memo.load(Ordering::Relaxed), 19);
    }

    /// #10470 re-blessed this test. It used to assert that the inventory fill read
    /// the whole external index, so that a missing artifact's gap rode in the
    /// fill's receipt and was replayed on every hit: every Java query was partial
    /// while any jar was missing. The inventory digest covers workspace classes
    /// only, so it no longer reads the index. The gap now belongs to the one case a
    /// missing jar can change: a single-type import that no workspace class
    /// satisfies, recorded in the fill of the memo that resolves that file's
    /// imports (and so replayed to its readers). The #8108 properties stay: the
    /// inventory fill is retained, the second read rescans nothing, and both reads
    /// carry their input keys.
    #[test]
    #[hardwon(
        "#8108: a missing dependency artifact made the Java import inventory refuse every fill and rescan all declarations per call"
    )]
    fn import_inventory_is_retained_and_a_missing_artifact_is_recorded_for_an_open_import_entry() {
        use brokk_bifrost_analysis::analyzer::{AnalyzerConfig, QueryReadIncomplete};

        let project = InlineTestProject::with_language(Language::Java)
            .file("App.java", "class App {}")
            .file(
                "Open.java",
                "import example.bifrost.issue8108.Thing;\nclass Open {}\n",
            )
            .file("Closed.java", "import java.util.List;\nclass Closed {}\n")
            .file(
                "pom.xml",
                r#"<project><modelVersion>4.0.0</modelVersion>
                <groupId>example</groupId><artifactId>app</artifactId><version>1</version>
                <dependencies><dependency><groupId>example.bifrost.issue8108</groupId>
                <artifactId>missing</artifactId><version>1</version>
                </dependency></dependencies></project>"#,
            )
            .build();
        let mut config = AnalyzerConfig::default();
        config.jvm.standard_library_discovery.discover_java_home = false;
        config.jvm.external_dependencies.repository_roots =
            vec![project.root().join("empty-repository")];
        let base = project.workspace_analyzer(config);
        let java = resolve_analyzer::<JavaAnalyzer>(base.analyzer()).unwrap();
        let missing_artifact = |reasons: &[QueryReadIncomplete]| {
            reasons.iter().any(|reason| {
                matches!(reason,
                QueryReadIncomplete::ArtifactUnavailable(message)
                    if message.contains("jvm.dependency_unresolved"))
            })
        };
        let read = || {
            let scope = AnalyzerQueryScope::capturing_read_incompleteness(java);
            let answer = java.import_inventory_answer();
            (answer, scope.captured_read_incompleteness())
        };
        let ((first, first_reasons), reads) = capture_query_reads(java, read);
        let scans = java.inner.full_declaration_scan_count_for_test();
        let ((second, second_reasons), second_reads) = capture_query_reads(java, read);
        assert_eq!(first, second);
        assert_eq!(second_reads.unattributed_reads(), 0, "{second_reads:?}");
        assert!(!reads.keys().is_empty());
        assert!(!second_reads.keys().is_empty());
        assert!(scans > 0, "the cold inventory must scan declarations");
        assert_eq!(java.inner.full_declaration_scan_count_for_test(), scans);
        for reasons in [&first_reasons, &second_reasons] {
            assert!(
                !missing_artifact(reasons),
                "the workspace-class digest does not depend on a jar: {reasons:?}"
            );
        }

        let imports_of = |name: &str| {
            let file = project.file(name);
            let scope = AnalyzerQueryScope::capturing_read_incompleteness(java);
            java.resolve_imports(scope.token(), &file);
            scope.captured_read_incompleteness()
        };
        for read in 0..2 {
            assert!(
                missing_artifact(&imports_of("Open.java")),
                "read {read}: an import no workspace class satisfies is an entry a missing jar \
                 could satisfy, and the memo's receipt replays that"
            );
            assert!(
                !missing_artifact(&imports_of("Closed.java")),
                "read {read}: no jar can supply a java.* type"
            );
            assert!(!missing_artifact(&imports_of("App.java")));
        }
    }

    #[test]
    #[hardwon(
        "#8108: a retained Java import inventory survived clone_with_project's external-index rebuild"
    )]
    fn import_inventory_refills_after_project_clone() {
        let project = fixture();
        let java = JavaAnalyzer::new(project.project_arc());
        let (answer, _) = capture_query_reads(&java, || java.import_inventory_answer());
        let scans = java.inner.full_declaration_scan_count_for_test();
        let clone = java.clone_with_project(project.project_arc());
        let (cloned_answer, reads) =
            capture_query_reads(&clone, || clone.import_inventory_answer());
        assert_eq!(answer, cloned_answer);
        assert_eq!(reads.unattributed_reads(), 0, "{reads:?}");
        assert!(
            clone.inner.full_declaration_scan_count_for_test() > scans,
            "a fresh external index requires a fresh inventory fill"
        );
        let warm = java.clone_for_index_warm(project.project_arc());
        let scans = java.inner.full_declaration_scan_count_for_test();
        capture_query_reads(&warm, || warm.import_inventory_answer());
        assert_eq!(warm.inner.full_declaration_scan_count_for_test(), scans);
    }

    fn captured_inventory(java: &JavaAnalyzer) -> StableDigest {
        let (_, reads) = capture_query_reads(java, || {
            assert!(java.import_inventory_is_complete());
        });
        assert_eq!(reads.unattributed_reads(), 0);
        let keys = reads.keys();
        assert_eq!(
            keys.len(),
            1,
            "precise inventory subsumes its source scan: {keys:?}"
        );
        let ReadKey::Lookup { digest, .. } = &keys[0] else {
            panic!("expected inventory fact: {keys:?}")
        };
        *digest
    }

    fn captured_classes(java: &JavaAnalyzer) -> StableDigest {
        let (_, reads) = capture_query_reads(java, || {
            JavaSource::forward_definition_fqn(java, "lib.Base");
        });
        assert_eq!(reads.unattributed_reads(), 0);
        let keys = reads.keys();
        assert_eq!(
            keys.len(),
            1,
            "precise name answer subsumes its lookup reads: {keys:?}"
        );
        let ReadKey::Lookup { digest, .. } = &keys[0] else {
            panic!("expected class fact: {keys:?}")
        };
        *digest
    }

    fn unimported_edit_is_rejected(family: WorkspaceFactFamily, subject: FactSubject) {
        use brokk_bifrost_analysis::analyzer::{
            AnalyzerConfig, ChangedFacts, LookupMemo, LookupReplayLimits, NoSummaryAnswers,
            ReadVerdict,
        };
        let project = fixture();
        let base = project.workspace_analyzer(AnalyzerConfig::default());
        let (_, reads) = capture_query_reads(base.analyzer(), || {
            assert!(answer(base.analyzer(), family, Language::Java, &subject).is_some());
        });
        assert_eq!(reads.unattributed_reads(), 0);
        let keys = reads.keys();
        assert_eq!(keys.len(), 1, "{keys:?}");
        let verify = |head: &brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer| {
            brokk_bifrost_analysis::analyzer::read_verification::verify_read_set(
                head,
                &ChangedFacts::between(&base, head),
                &brokk_bifrost_analysis::test_support::read_ledger_test_inputs(),
                &keys,
                LookupReplayLimits::default(),
                &NoSummaryAnswers,
                &mut LookupMemo::new(),
            )
        };
        assert_eq!(verify(&base), ReadVerdict::Unchanged);
        project
            .file("lib/Base.java")
            .write("package lib; class Replacement {}\n")
            .unwrap();
        let head = project.workspace_analyzer(AnalyzerConfig::default());
        assert_ne!(
            verify(&head),
            ReadVerdict::Unchanged,
            "{family:?} retained a changed answer"
        );
    }

    #[test]
    fn import_inventory_rejects_an_unimported_class_edit() {
        unimported_edit_is_rejected(WorkspaceFactFamily::JavaImportInventory, FactSubject::Whole);
    }

    #[test]
    fn import_inventory_digest_repeats_on_a_warm_generation() {
        let project = fixture();
        let java = JavaAnalyzer::new(project.project_arc());
        assert_eq!(captured_inventory(&java), captured_inventory(&java));
    }

    #[test]
    fn import_inventory_ignores_a_comment_above_the_first_class() {
        let project = fixture();
        let java = JavaAnalyzer::new(project.project_arc());
        let before = captured_inventory(&java);
        project
            .file("lib/Base.java")
            .write("// comment\npackage lib; public class Base {}\n")
            .unwrap();
        let head = JavaAnalyzer::new(project.project_arc());
        assert_eq!(before, captured_inventory(&head));
    }

    #[test]
    fn workspace_classes_reject_an_unimported_class_edit() {
        unimported_edit_is_rejected(
            WorkspaceFactFamily::JavaWorkspaceClasses,
            FactSubject::Named {
                name: "lib.Base".into(),
            },
        );
    }

    #[test]
    fn workspace_class_digest_repeats_on_a_warm_generation() {
        let project = fixture();
        let java = JavaAnalyzer::new(project.project_arc());
        assert_eq!(captured_classes(&java), captured_classes(&java));
    }

    #[test]
    fn workspace_classes_ignore_a_comment_above_the_first_class() {
        let project = fixture();
        let java = JavaAnalyzer::new(project.project_arc());
        let before = captured_classes(&java);
        project
            .file("lib/Base.java")
            .write("// comment\npackage lib; public class Base {}\n")
            .unwrap();
        let head = JavaAnalyzer::new(project.project_arc());
        assert_eq!(before, captured_classes(&head));
    }
    #[test]
    fn file_projection_hits_record_selected_content() {
        use brokk_bifrost_analysis::analyzer::AnalyzerQueryScope;
        use brokk_bifrost_core::analyzer::query_token::QueryScope;
        let project = fixture();
        let java = JavaAnalyzer::new(project.project_arc());
        let file = project.file("lib/Base.java");
        // Keep the request-owned class index alive while the two independent
        // captures attach and detach, so both reads really use a warm entry.
        let scope = AnalyzerQueryScope::new(&java);
        let source_read = || {
            assert!(
                java.declaration_source_facts(scope.token(), &file)
                    .is_some()
            );
        };
        let index_read = || {
            assert!(matches!(
                java.unique_class_by_fqn_in_file("lib.Base", &file),
                brokk_bifrost_jvm::java::graph_support::UniqueClassInFile::Unique(_)
            ));
        };
        let readers: [&dyn Fn(); 2] = [&source_read, &index_read];
        for read in readers {
            read();
            let (_, reads) = capture_query_reads(&java, read);
            let (_, second_reads) = capture_query_reads(&java, read);
            assert_eq!(reads.unattributed_reads(), 0);
            assert_eq!(second_reads.unattributed_reads(), 0);
            assert_eq!(reads.keys(), second_reads.keys());
            assert!(
                reads.keys().iter().any(|key| matches!(key,
                    ReadKey::File { rel_path, .. } if rel_path.as_ref() == "lib/Base.java"
                )),
                "each file-only hit retains its own selected content: {reads:?}"
            );
        }
    }

    #[test]
    #[hardwon(
        "#8618: JavaFileClassIndexMemo kept an index built after StructureUnavailable and its hits did not replay the gap"
    )]
    fn file_class_index_replays_structure_gap_in_later_retained_fill() {
        use brokk_bifrost_analysis::analyzer::{AnalyzerQueryScope, QueryReadIncomplete};
        let project = fixture();
        project
            .file("lib/Base.java")
            .write("package lib;\0class Base {}")
            .unwrap();
        let java = JavaAnalyzer::new(project.project_arc());
        let file = project.file("lib/Base.java");
        let _request = AnalyzerQueryScope::new(&java);
        for _ in 0..2 {
            let fill = AnalyzerQueryScope::for_retained_fill(&java);
            assert!(matches!(
                java.unique_class_by_fqn_in_file("lib.Base", &file),
                brokk_bifrost_jvm::java::graph_support::UniqueClassInFile::None
            ));
            assert!(matches!(
                fill.read_completion(),
                Err(QueryReadIncomplete::StructureUnavailable(_))
            ));
        }
    }
}

#[cfg(test)]
mod scope_authority_tests {
    use super::*;
    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_analysis::analyzer::{ReadKey, capture_query_reads};
    use brokk_bifrost_core::analyzer::capabilities::{
        ImportAnalysisProvider, TypeHierarchyProvider,
    };

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#7496: warm JVM authority hits omitted their inputs from policy read sets"
    )]
    fn warm_reference_and_descendant_indexes_name_the_source_realm() {
        let project = InlineTestProject::with_language(Language::Java)
            .file("lib/Base.java", "package lib; public class Base {}")
            .file(
                "app/Use.java",
                "package app; import lib.Base; class Use extends Base {}",
            )
            .build();
        let java = JavaAnalyzer::new(project.project_arc());
        let file = project.file("lib/Base.java");
        let owner = java
            .all_declarations()
            .find(|unit| unit.fq_name() == "lib.Base")
            .unwrap();
        let read = || {
            assert!(!java.referencing_files_of(&file).is_empty());
            java.same_package_reference_index();
            assert!(
                !java
                    .get_direct_descendants(&owner)
                    .definite()
                    .to_vec()
                    .is_empty()
            );
        };
        read();
        let references = || {
            java.referencing_files_of(&file);
        };
        let reverse = || {
            java.reverse_import_index();
        };
        let same_package = || {
            java.same_package_reference_index();
        };
        let descendants = || {
            assert!(java.get_direct_descendants(&owner).is_complete());
        };
        let readers: [&dyn Fn(); 4] = [&references, &reverse, &same_package, &descendants];
        for reader in readers.into_iter().cycle().take(8) {
            let (_, reads) = capture_query_reads(&java, reader);
            assert_eq!(reads.unattributed_reads(), 0, "{reads:?}");
            assert!(
                reads
                    .keys()
                    .iter()
                    .any(|key| matches!(key, ReadKey::Scope { .. })),
                "{reads:?}"
            );
        }
        // Evict only the per-question cache: this forces the warm reverse and
        // same-package authorities to feed a fresh referencing answer.
        java.memo_caches.referencing_files.invalidate_all();
        let (_, reads) = capture_query_reads(&java, read);
        assert_eq!(reads.unattributed_reads(), 0, "{reads:?}");
        assert!(
            reads
                .keys()
                .iter()
                .any(|key| matches!(key, ReadKey::Scope { .. })),
            "{reads:?}"
        );
    }
}

#[cfg(test)]
mod merged_cache_read_tests {
    use super::*;
    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_analysis::analyzer::{ReadKey, capture_query_reads};
    use brokk_bifrost_jvm::java::graph_support::JavaSource;
    use std::sync::Arc;

    fn source_key(reads: &brokk_bifrost_analysis::analyzer::ReadLedger, path: &str, source: &str) {
        let blob = git2::Oid::hash_object(git2::ObjectType::Blob, source.as_bytes()).unwrap();
        assert_eq!(reads.unattributed_reads(), 0, "{reads:?}");
        assert!(
            reads.keys().iter().any(|key| matches!(key,
            ReadKey::File { rel_path, blob: actual, .. }
            if rel_path.as_ref() == path && *actual == blob)),
            "{reads:?}"
        );
    }

    #[test]
    fn warm_package_names_record_selected_source() {
        let source = "package app; class Sample {}";
        let project = InlineTestProject::with_language(Language::Java)
            .file("app/Sample.java", source)
            .build();
        let java = JavaAnalyzer::new(project.project_arc());
        let file = project.file("app/Sample.java");
        let warm = java.cached_package_name(&file).unwrap();
        for _ in 0..2 {
            let (hit, reads) =
                capture_query_reads(&java, || java.cached_package_name(&file).unwrap());
            assert!(
                Arc::ptr_eq(&warm, &hit),
                "must exercise the retained package value"
            );
            source_key(&reads, "app/Sample.java", source);
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#7496: Java enum-switch fact hits lost the type resolver's reads"
    )]
    fn warm_statement_facts_replay_enum_resolution_reads() {
        let source = "package app; import lib.Mode; class Sample { void f(Mode m) { switch (m) { case A: break; } } }";
        let project = InlineTestProject::with_language(Language::Java)
            .file("app/Sample.java", source)
            .file("lib/Mode.java", "package lib; public enum Mode { A, B }")
            .build();
        let java = JavaAnalyzer::new(project.project_arc());
        let file = project.file("app/Sample.java");
        let (warm, cold_reads) =
            capture_query_reads(&java, || java.statement_source_facts(&file).unwrap());
        assert!(!warm.switches.is_empty(), "must run enum-switch resolution");
        assert!(
            cold_reads.keys().len() > 1,
            "must consult inputs beyond the source blob: {cold_reads:?}"
        );
        for _ in 0..2 {
            let (hit, reads) =
                capture_query_reads(&java, || java.statement_source_facts(&file).unwrap());
            assert!(
                Arc::ptr_eq(&warm, &hit),
                "must exercise the retained statement facts"
            );
            source_key(&reads, "app/Sample.java", source);
            assert_eq!(
                cold_reads.keys(),
                reads.keys(),
                "warm hits must replay every resolver input"
            );
        }
    }

    #[test]
    fn changed_statement_blob_misses_retained_facts() {
        let original = "class Sample { void f() {} }";
        let changed = "class Sample { void f() { if (true) {} } }";
        let project = InlineTestProject::with_language(Language::Java)
            .file("Sample.java", original)
            .build();
        let java = JavaAnalyzer::new(project.project_arc());
        let file = project.file("Sample.java");
        let old = java.statement_source_facts(&file).unwrap();
        project.file("Sample.java").write(changed).unwrap();
        let mut head = JavaAnalyzer::new(project.project_arc());
        // Share storage deliberately: this must test the blob key, rather
        // than pass just because a new generation starts with an empty cache.
        head.memo_caches = Arc::clone(&java.memo_caches);
        let (fresh, reads) =
            capture_query_reads(&head, || head.statement_source_facts(&file).unwrap());
        assert!(!Arc::ptr_eq(&old, &fresh));
        assert!(fresh.conditions.len() > old.conditions.len());
        source_key(&reads, "Sample.java", changed);
        let (hit, reads) =
            capture_query_reads(&head, || head.statement_source_facts(&file).unwrap());
        assert!(Arc::ptr_eq(&fresh, &hit));
        source_key(&reads, "Sample.java", changed);
    }
}

#[cfg(test)]
mod external_receipt_budget_tests {
    use super::*;
    use crate::inline_project::InlineTestProject;

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#2445: evicted JVM external receipts certified live indexes using new inputs"
    )]
    fn live_external_indexes_refuse_after_receipt_eviction() {
        let project = InlineTestProject::with_language(Language::Java)
            .file("App.java", "class App {}")
            .file("pom.xml", "<project/>")
            .build();
        let config = brokk_bifrost_analysis::analyzer::AnalyzerConfig {
            retention_budget_bytes: Some(4 * (8)),
            ..Default::default()
        };
        let analyzer = JavaAnalyzer::new_with_config(project.project_arc(), config);
        crate::analyzer::jvm::authority::assert_receipt_loss_refuses_live_index(
            &analyzer,
            &analyzer.external_index,
            || {
                analyzer.external_declaration_index();
            },
        );
    }
}

#[cfg(test)]
mod imported_type_resolution_tests {
    use super::*;
    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_analysis::analyzer::{
        AnalyzerConfig, ChangedFacts, LookupKind, LookupMemo, LookupQuestion, NoSummaryAnswers,
        ReadKey, ReadVerdict, TypeHierarchyProvider, capture_query_reads, resolve_analyzer,
        verify_read_set,
    };
    use brokk_bifrost_jvm::java::graph_support::JavaSource;
    use brokk_bifrost_test_macros::hardwon;

    const CHILD: &str = "package app;\nimport lib.*;\nclass Child extends Base {}\n";

    fn fixture() -> crate::inline_project::BuiltInlineTestProject {
        InlineTestProject::with_language(Language::Java)
            .with_git()
            .file("app/Child.java", CHILD)
            .file("lib/Base.java", "package lib; public class Base {}\n")
            .file("extra/Base.java", "package extra; public class Base {}\n")
            .build()
    }

    fn capture_name(java: &JavaAnalyzer, file: &ProjectFile) -> (Option<String>, Vec<ReadKey>) {
        java.test_hooks()
            .reset_full_declaration_scan_count_for_test();
        let scope = AnalyzerQueryScope::new(java);
        let (resolved, reads) = capture_query_reads(java, || {
            JavaSource::resolve_imported_type_name(java, scope.token(), file, "Base")
                .map(|unit| unit.fq_name())
        });
        assert_eq!(reads.unattributed_reads(), 0);
        assert_eq!(java.test_hooks().full_declaration_scan_count_for_test(), 0);
        let keys = reads.keys();
        assert_eq!(
            keys.len(),
            1,
            "the resolved-name Fact subsumes its seeks: {keys:?}"
        );
        assert!(matches!(
            &keys[0],
            ReadKey::Lookup {
                kind: LookupKind::WorkspaceFact,
                question: LookupQuestion::WorkspaceFact {
                    family: WorkspaceFactFamily::JavaImportedTypeResolution,
                    language: Language::Java,
                    subject,
                },
                ..
            } if subject == &imported_type_subject(file, "Base")
        ));
        (resolved, keys)
    }

    fn verify(
        base: &brokk_bifrost_analysis::analyzer::WorkspaceAnalyzer,
        head: &brokk_bifrost_analysis::analyzer::WorkspaceAnalyzer,
        keys: &[ReadKey],
    ) -> ReadVerdict {
        head.analyzer()
            .test_hooks()
            .reset_full_declaration_scan_count_for_test();
        let verdict = verify_read_set(
            head,
            &ChangedFacts::between(base, head),
            &brokk_bifrost_analysis::test_support::read_ledger_test_inputs(),
            keys,
            Default::default(),
            &NoSummaryAnswers,
            &mut LookupMemo::new(),
        );
        assert_eq!(
            head.analyzer()
                .test_hooks()
                .full_declaration_scan_count_for_test(),
            0
        );
        verdict
    }

    #[test]
    #[hardwon(
        "#2445: ancestor import proof scanned the whole inventory instead of the named answer"
    )]
    fn ancestors_replay_imported_name_facts_without_a_global_inventory_scan() {
        let project = fixture();
        let java = JavaAnalyzer::new(project.project_arc());
        let file = project.file("app/Child.java");
        let child = java
            .declarations(&file)
            .into_iter()
            .find(|unit| unit.fq_name() == "app.Child")
            .expect("fixture child");
        java.test_hooks()
            .reset_full_declaration_scan_count_for_test();
        let ancestors = java.get_direct_ancestors(&child).definite().to_vec();
        assert_eq!(
            ancestors.iter().map(CodeUnit::fq_name).collect::<Vec<_>>(),
            vec!["lib.Base"]
        );
        let (warm, reads) = capture_query_reads(&java, || {
            java.get_direct_ancestors(&child).definite().to_vec()
        });
        assert_eq!(warm, ancestors);
        assert_eq!(reads.unattributed_reads(), 0);
        assert_eq!(java.test_hooks().full_declaration_scan_count_for_test(), 0);
        let keys = reads.keys();
        assert!(
            keys.iter().any(|key| matches!(
                key,
                ReadKey::Lookup {
                    question: LookupQuestion::WorkspaceFact {
                        family: WorkspaceFactFamily::JavaImportedTypeResolution,
                        ..
                    },
                    ..
                }
            )),
            "warm ancestors must replay the imported-name question: {keys:?}"
        );
        assert!(
            !keys.iter().any(|key| matches!(
                key,
                ReadKey::Lookup {
                    question: LookupQuestion::WorkspaceFact {
                        family: WorkspaceFactFamily::JavaImportInventory,
                        ..
                    },
                    ..
                }
            )),
            "a single ancestor question must not read the Whole inventory: {keys:?}"
        );
    }

    #[test]
    fn an_unimported_class_edit_changes_an_absent_imported_name() {
        let project = InlineTestProject::with_language(Language::Java)
            .with_git()
            .file("app/Child.java", CHILD)
            .file("lib/Other.java", "package lib; public class Other {}\n")
            .build();
        let base = project.workspace_analyzer(AnalyzerConfig::default());
        let java = resolve_analyzer::<JavaAnalyzer>(base.analyzer()).unwrap();
        let file = project.file("app/Child.java");
        let (resolved, keys) = capture_name(java, &file);
        assert!(resolved.is_none());
        assert_eq!(verify(&base, &base, &keys), ReadVerdict::Unchanged);
        project
            .file("lib/Other.java")
            .write("package lib; public class Base {}\n")
            .unwrap();
        let head = project.workspace_analyzer(AnalyzerConfig::default());
        assert_ne!(verify(&base, &head, &keys), ReadVerdict::Unchanged);
        let java = resolve_analyzer::<JavaAnalyzer>(head.analyzer()).unwrap();
        assert_eq!(capture_name(java, &file).0.as_deref(), Some("lib.Base"));
    }

    #[test]
    fn an_added_wildcard_import_changes_the_resolved_name_answer() {
        let project = fixture();
        let base = project.workspace_analyzer(AnalyzerConfig::default());
        let java = resolve_analyzer::<JavaAnalyzer>(base.analyzer()).unwrap();
        let file = project.file("app/Child.java");
        let (resolved, keys) = capture_name(java, &file);
        assert_eq!(resolved.as_deref(), Some("lib.Base"));
        assert_eq!(verify(&base, &base, &keys), ReadVerdict::Unchanged);
        project
            .file("app/Child.java")
            .write("package app;\nimport lib.*;\nimport extra.*;\nclass Child extends Base {}\n")
            .unwrap();
        let head = project.workspace_analyzer(AnalyzerConfig::default());
        assert_ne!(verify(&base, &head, &keys), ReadVerdict::Unchanged);
        let java = resolve_analyzer::<JavaAnalyzer>(head.analyzer()).unwrap();
        let (resolved, changed_keys) = capture_name(java, &file);
        assert!(
            resolved.is_none(),
            "the two on-demand candidates are ambiguous"
        );
        assert_ne!(keys, changed_keys);
    }

    #[test]
    fn imported_type_resolution_repeats_in_the_same_generation() {
        let project = fixture();
        let java = JavaAnalyzer::new(project.project_arc());
        let file = project.file("app/Child.java");
        let first = capture_name(&java, &file);
        assert_eq!(first.0.as_deref(), Some("lib.Base"));
        assert_eq!(first, capture_name(&java, &file));
    }

    #[test]
    fn a_comment_above_the_import_target_keeps_its_name_answer() {
        let project = fixture();
        let base = project.workspace_analyzer(AnalyzerConfig::default());
        let java = resolve_analyzer::<JavaAnalyzer>(base.analyzer()).unwrap();
        let file = project.file("app/Child.java");
        let first = capture_name(java, &file);
        assert_eq!(first.0.as_deref(), Some("lib.Base"));
        project
            .file("lib/Base.java")
            .write("// shifted declaration\npackage lib; public class Base {}\n")
            .unwrap();
        let head = project.workspace_analyzer(AnalyzerConfig::default());
        assert_eq!(verify(&base, &head, &first.1), ReadVerdict::Unchanged);
        let java = resolve_analyzer::<JavaAnalyzer>(head.analyzer()).unwrap();
        assert_eq!(first, capture_name(java, &file));
    }
}
