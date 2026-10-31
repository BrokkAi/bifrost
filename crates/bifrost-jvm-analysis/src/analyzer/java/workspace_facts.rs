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
        "#8108: a missing dependency artifact made the Java import inventory refuse every fill and rescan all declarations per call"
    )]
    fn import_inventory_replays_missing_artifact_on_hits() {
        use brokk_bifrost_analysis::analyzer::{AnalyzerConfig, QueryReadIncomplete};

        let project = InlineTestProject::with_language(Language::Java)
            .file("App.java", "class App {}")
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
        let read = || {
            let scope = AnalyzerQueryScope::capturing_read_incompleteness(java);
            let answer = java.import_inventory_answer();
            (answer, scope.captured_read_incompleteness())
        };
        let ((first, first_reasons), reads) = capture_query_reads(java, || {
            let scope = AnalyzerQueryScope::capturing_read_incompleteness(java);
            java.external_declaration_index();
            let answer = java.import_inventory_answer();
            (answer, scope.captured_read_incompleteness())
        });
        let scans = java.inner.full_declaration_scan_count_for_test();
        let ((second, second_reasons), second_reads) = capture_query_reads(java, read);
        assert_eq!(first, second);
        assert_eq!(second_reads.unattributed_reads(), 0, "{second_reads:?}");
        assert!(!reads.keys().is_empty());
        assert!(!second_reads.keys().is_empty());
        assert!(scans > 0, "the cold inventory must scan declarations");
        assert_eq!(java.inner.full_declaration_scan_count_for_test(), scans);
        for reasons in [first_reasons, second_reasons] {
            assert!(
                reasons.iter().any(|reason| matches!(reason,
                QueryReadIncomplete::ArtifactUnavailable(message)
                    if message.contains("jvm.dependency_unresolved"))),
                "{reasons:?}"
            );
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
            memo_cache_budget_bytes: Some(8),
            ..Default::default()
        };
        let analyzer = JavaAnalyzer::new_with_config(project.project_arc(), config);
        crate::analyzer::jvm::authority::assert_receipt_loss_refuses_live_index(
            &analyzer,
            &analyzer.external_index,
            &analyzer.external_inputs,
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
