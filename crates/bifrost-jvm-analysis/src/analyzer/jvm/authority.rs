//! Every primitive JVM authority accessor crosses a named recording funnel.
//! Scope-tier answers include the entire JVM source realm; dependency-backed
//! answers additionally name manifests and negative build-file probes.
use brokk_bifrost_analysis::analyzer::workspace_authority::{
    AuthorityInputs, record_workspace_authority_read, workspace_authority_file_input,
    workspace_file_inventory_answer,
};
use brokk_bifrost_analysis::analyzer::{FactSubject, IAnalyzer, WorkspaceFactFamily};
use brokk_bifrost_core::analyzer::model::Language;
use brokk_bifrost_jvm::proof::JvmRetainedExternalIndex;

pub(crate) fn source_read(analyzer: &dyn IAnalyzer, family: WorkspaceFactFamily) {
    record_workspace_authority_read(
        analyzer,
        family,
        AuthorityInputs::SourceOf(&[Language::Java, Language::Kotlin, Language::Scala]),
    );
}

// Read a retained index through its receipt before classifying its state.
pub(crate) fn retained_external_index(
    analyzer: &dyn IAnalyzer,
    index: &brokk_bifrost_analysis::analyzer::common::QueryCacheCell<
        brokk_bifrost_analysis::analyzer::common::ReplayableQueryCacheValue<
            std::sync::Arc<super::external::JvmExternalDeclarationIndex>,
        >,
    >,
    memo: &super::hierarchy::DerivedMemo<(), ()>,
) -> JvmRetainedExternalIndex {
    external_read(analyzer, index, memo);
    super::retained_external_index_state(index.get().map(|entry| entry.replay().as_ref()))
}

// A live index may outlast its bounded receipt. Never sample new inputs for
// that old value: loss of its build receipt refuses certification instead.
pub(crate) fn external_read(
    analyzer: &dyn IAnalyzer,
    index: &brokk_bifrost_analysis::analyzer::common::QueryCacheCell<
        brokk_bifrost_analysis::analyzer::common::ReplayableQueryCacheValue<
            std::sync::Arc<super::external::JvmExternalDeclarationIndex>,
        >,
    >,
    memo: &super::hierarchy::DerivedMemo<(), ()>,
) {
    if index.get().is_none() {
        return; // A retained-only peek has not consumed an external index.
    }
    memo.read(
        &brokk_bifrost_analysis::analyzer::workspace_authority::memo_attribution(analyzer),
        |cache, capture| {
            Ok::<_, std::convert::Infallible>(cache.get(&()).unwrap_or_else(|| {
                std::sync::Arc::new(capture.build(|| {
                    analyzer.record_unattributed_read();
                    std::sync::Arc::new(())
                }))
            }))
        },
    )
    .expect("external receipt lookup is infallible");
}

pub(crate) fn initialize_external_index(
    analyzer: &dyn IAnalyzer,
    authority: (Language, WorkspaceFactFamily),
    index: &brokk_bifrost_analysis::analyzer::common::QueryCacheCell<
        brokk_bifrost_analysis::analyzer::common::ReplayableQueryCacheValue<
            std::sync::Arc<super::external::JvmExternalDeclarationIndex>,
        >,
    >,
    memo: &super::hierarchy::DerivedMemo<(), ()>,
    build: impl FnOnce() -> std::sync::Arc<super::external::JvmExternalDeclarationIndex>,
) -> std::sync::Arc<super::external::JvmExternalDeclarationIndex> {
    let mut result = None;
    memo.read(
        &brokk_bifrost_analysis::analyzer::workspace_authority::memo_attribution(analyzer),
        |cache, capture| {
            let mut built = None;
            let value = brokk_bifrost_analysis::analyzer::common::replayable_query_cache_cell(
                analyzer,
                index,
                || {
                    let mut value = None;
                    let receipt = std::sync::Arc::new(capture.build_weighted(|| {
                        record_external_inputs(analyzer, authority.0, authority.1);
                        value = Some(build());
                        (std::sync::Arc::new(()), 0)
                    }));
                    let value = value.expect("builder produced an index");
                    built = Some((std::sync::Arc::clone(&value), receipt));
                    value
                },
            );
            let retained = index
                .get()
                .is_some_and(|retained| std::sync::Arc::ptr_eq(retained, &value));
            if retained
                && let Some((built_value, receipt)) = &built
                && std::sync::Arc::ptr_eq(built_value, &value)
            {
                cache.insert((), std::sync::Arc::clone(receipt));
            }
            result = Some(value);
            let receipt = if retained {
                cache.get(&())
            } else {
                built.map(|(_, receipt)| receipt)
            };
            Ok::<_, std::convert::Infallible>(receipt.unwrap_or_else(|| {
                std::sync::Arc::new(capture.build(|| {
                    // A winning index whose bounded receipt was evicted cannot
                    // be certified from freshly sampled inputs.
                    analyzer.record_unattributed_read();
                    std::sync::Arc::new(())
                }))
            }))
        },
    )
    .expect("external index initialization is infallible");
    result.expect("external lookup produced an owned index")
}

fn record_external_inputs(
    analyzer: &dyn IAnalyzer,
    language: Language,
    family: WorkspaceFactFamily,
) {
    // The inventory certifies newly appearing nested manifests too. Negative
    // probes below pin the conventional candidates even in an empty project.
    let project = analyzer.project();
    let inventory = match workspace_file_inventory_answer(project) {
        Ok(inventory) => inventory,
        Err(error) => {
            analyzer.record_query_failure(
                brokk_bifrost_analysis::analyzer::store::StoreError::new(format!(
                    "JVM dependency inventory IO: {error}"
                )),
            );
            return;
        }
    };
    record_workspace_authority_read(
        analyzer,
        WorkspaceFactFamily::WorkspaceFileInventory,
        AuthorityInputs::Fact {
            language: Language::None,
            subject: FactSubject::Whole,
            answer: inventory,
        },
    );
    let files = match project.all_files() {
        Ok(files) => files,
        Err(error) => {
            analyzer.record_query_failure(
                brokk_bifrost_analysis::analyzer::store::StoreError::new(format!(
                    "JVM dependency inventory IO: {error}"
                )),
            );
            return;
        }
    };
    let mut paths = files
        .iter()
        .filter(|file| super::dependency_discovery::is_jvm_dependency_input(file))
        .map(|file| file.rel_path().to_path_buf())
        .collect::<Vec<_>>();
    paths.extend(
        [
            "pom.xml",
            "settings.xml",
            "build.gradle",
            "build.gradle.kts",
            "settings.gradle",
            "settings.gradle.kts",
            "gradle.properties",
            "gradle.lockfile",
            "gradle/libs.versions.toml",
            "gradle/wrapper/gradle-wrapper.properties",
            ".mvn/maven.config",
            ".mvn/jvm.config",
            ".mvn/extensions.xml",
            ".mvn/wrapper/maven-wrapper.properties",
        ]
        .map(std::path::PathBuf::from),
    );
    paths.sort();
    paths.dedup();
    let keys = paths
        .iter()
        .filter_map(|path| {
            let key = workspace_authority_file_input(
                analyzer,
                language,
                &brokk_bifrost_analysis::path_utils::workspace_relative_slash_path(path),
            );
            if key.is_none() {
                analyzer.record_unattributed_read();
            }
            key
        })
        .collect::<Vec<_>>();
    record_workspace_authority_read(
        analyzer,
        family,
        AuthorityInputs::SourceAndFiles {
            languages: &[Language::Java, Language::Kotlin, Language::Scala],
            files: keys.into(),
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_analysis::analyzer::{
        AnalyzerConfig, ChangedFacts, LookupMemo, LookupReplayLimits, NoSummaryAnswers, ReadKey,
        ReadVerdict, capture_query_reads,
    };

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#8148: a binary .mvn/wrapper/maven-wrapper.jar authority input refused every JVM external index fill"
    )]
    fn binary_wrapper_inputs_retain_external_index_and_properties_invalidate() {
        let project = InlineTestProject::with_language(Language::Java)
            .file("App.java", "class App {}")
            .file("pom.xml", "<project/>")
            .file(".mvn/wrapper/maven-wrapper.jar", "PK\0\0")
            .file("buildSrc/resource.bin", "binary\0resource")
            .file(
                ".mvn/wrapper/maven-wrapper.properties",
                "distributionUrl=first",
            )
            .build();
        for path in [".mvn/wrapper/maven-wrapper.jar", "buildSrc/resource.bin"] {
            std::fs::write(project.file(path).abs_path(), b"PK\0\xff").unwrap();
        }
        let base = project.workspace_analyzer(AnalyzerConfig::default());
        let java = brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer::<
            crate::analyzer::java::JavaAnalyzer,
        >(base.analyzer())
        .unwrap();
        let (first, reads) =
            capture_query_reads(base.analyzer(), || java.external_declaration_index());
        let (second, warm) =
            capture_query_reads(base.analyzer(), || java.external_declaration_index());
        assert!(
            std::sync::Arc::ptr_eq(&first, &second),
            "external index rebuilt"
        );
        assert_eq!(reads.unattributed_reads(), 0, "{reads:?}");
        assert_eq!(warm.unattributed_reads(), 0, "{warm:?}");
        assert_eq!(reads.keys(), warm.keys());
        assert!(
            warm.keys()
                .iter()
                .any(|key| matches!(key, ReadKey::File { rel_path, .. }
            if rel_path.as_ref() == "buildSrc/resource.bin")),
            "{warm:?}"
        );
        assert!(
            !warm
                .keys()
                .iter()
                .any(|key| matches!(key, ReadKey::File { rel_path, .. }
            if rel_path.as_ref() == ".mvn/wrapper/maven-wrapper.jar")),
            "{warm:?}"
        );
        let verify = |head: &brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer| {
            brokk_bifrost_analysis::analyzer::read_verification::verify_read_set(
                head,
                &ChangedFacts::between(&base, head),
                &brokk_bifrost_analysis::test_support::read_ledger_test_inputs(),
                &warm.keys(),
                LookupReplayLimits::default(),
                &NoSummaryAnswers,
                &mut LookupMemo::new(),
            )
        };
        assert_eq!(verify(&base), ReadVerdict::Unchanged);
        project
            .file(".mvn/wrapper/maven-wrapper.properties")
            .write("distributionUrl=second")
            .unwrap();
        let edited = project.workspace_analyzer(AnalyzerConfig::default());
        assert_ne!(verify(&edited), ReadVerdict::Unchanged);
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#7496: warm JVM authority hits omitted their inputs from policy read sets"
    )]
    fn warm_external_indexes_record_build_files_and_absent_candidates() {
        for language in [Language::Java, Language::Kotlin, Language::Scala] {
            let (name, source) = match language {
                Language::Java => ("App.java", "class App {}"),
                Language::Kotlin => ("App.kt", "class App"),
                Language::Scala => ("App.scala", "class App"),
                _ => unreachable!(),
            };
            let project = InlineTestProject::with_language(language)
                .file(name, source)
                .file("pom.xml", "<project/>")
                .file("build.gradle.kts", "plugins {}")
                .build();
            let base = project.workspace_analyzer(AnalyzerConfig::default());
            let read = || match language {
                Language::Java => {
                    let java =
                        brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer::<
                            crate::analyzer::java::JavaAnalyzer,
                        >(base.analyzer())
                        .unwrap();
                    java.external_declaration_index()
                        .dispatch_behavior_identity()
                }
                Language::Kotlin => {
                    let kotlin =
                        brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer::<
                            crate::analyzer::kotlin::KotlinAnalyzer,
                        >(base.analyzer())
                        .unwrap();
                    kotlin
                        .external_declaration_index()
                        .dispatch_behavior_identity()
                }
                Language::Scala => {
                    let scala =
                        brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer::<
                            crate::analyzer::scala::ScalaAnalyzer,
                        >(base.analyzer())
                        .unwrap();
                    scala
                        .external_declaration_index()
                        .dispatch_behavior_identity()
                }
                _ => unreachable!(),
            };
            let warmed = read();
            // The receipt belongs to the uncaptured fill. Deliberately edit
            // the mutable project before attaching a capture, and require the
            // old blob rather than certifying the old index with new inputs.
            project
                .file("pom.xml")
                .write("<project><!-- before capture --></project>")
                .unwrap();
            let (identity, reads) = capture_query_reads(base.analyzer(), read);
            let (again_identity, again) = capture_query_reads(base.analyzer(), read);
            assert_eq!(warmed, identity);
            assert_eq!(identity, again_identity);
            let filled_blob =
                git2::Oid::hash_object(git2::ObjectType::Blob, b"<project/>").unwrap();
            assert!(
                reads.keys().iter().any(|key| matches!(key,
                ReadKey::File { rel_path, blob, .. }
                if rel_path.as_ref() == "pom.xml" && *blob == filled_blob)),
                "{reads:?}"
            );
            project.file("pom.xml").write("<project/>").unwrap();
            assert_eq!(reads.unattributed_reads(), 0, "{reads:?}");
            assert_eq!(reads.keys(), again.keys());
            for input in ["pom.xml", "build.gradle.kts"] {
                assert!(
                    reads.keys().iter().any(|key| matches!(key,
                    ReadKey::File { rel_path, .. } if rel_path.as_ref() == input)),
                    "{reads:?}"
                );
            }
            assert!(
                reads.keys().iter().any(|key| matches!(key,
                ReadKey::PathAbsent { rel_path, .. } if rel_path.as_ref() == "gradle.lockfile")),
                "{reads:?}"
            );
            let verify = |head: &brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer| {
                brokk_bifrost_analysis::analyzer::read_verification::verify_read_set(
                    head,
                    &ChangedFacts::between(&base, head),
                    &brokk_bifrost_analysis::test_support::read_ledger_test_inputs(),
                    &reads.keys(),
                    LookupReplayLimits::default(),
                    &NoSummaryAnswers,
                    &mut LookupMemo::new(),
                )
            };
            assert_eq!(verify(&base), ReadVerdict::Unchanged);
            project
                .file("pom.xml")
                .write("<project><!-- changed --></project>")
                .unwrap();
            let edited = project.workspace_analyzer(AnalyzerConfig::default());
            assert_ne!(verify(&edited), ReadVerdict::Unchanged);
            project.file("pom.xml").write("<project/>").unwrap();
            project
                .file("build.gradle.kts")
                .write("plugins {} // changed")
                .unwrap();
            let gradle_edit = project.workspace_analyzer(AnalyzerConfig::default());
            assert_ne!(verify(&gradle_edit), ReadVerdict::Unchanged);
            project
                .file("build.gradle.kts")
                .write("plugins {}")
                .unwrap();
            project
                .file("gradle.lockfile")
                .write("# lockfile created")
                .unwrap();
            let added = project.workspace_analyzer(AnalyzerConfig::default());
            assert_ne!(verify(&added), ReadVerdict::Unchanged);
        }
    }
}

#[cfg(test)]
pub(crate) fn assert_receipt_loss_refuses_live_index(
    analyzer: &dyn IAnalyzer,
    index: &brokk_bifrost_analysis::analyzer::common::QueryCacheCell<
        brokk_bifrost_analysis::analyzer::common::ReplayableQueryCacheValue<
            std::sync::Arc<super::external::JvmExternalDeclarationIndex>,
        >,
    >,
    memo: &super::hierarchy::DerivedMemo<(), ()>,
    read: impl Fn(),
) {
    use brokk_bifrost_analysis::analyzer::{ReadKey, capture_query_reads};
    read();
    let built = std::sync::Arc::clone(index.get().expect("must build the real language index"));
    assert_eq!(
        memo.account(|cache| {
            cache.run_pending_tasks();
            usize::from(cache.get(&()).is_none())
        }),
        1,
        "the tiny receipt budget must actually discard the receipt"
    );
    std::fs::write(
        analyzer.project().root().join("pom.xml"),
        "<project><!-- changed after build --></project>",
    )
    .unwrap();
    for _ in 0..2 {
        let (_, reads) = capture_query_reads(analyzer, &read);
        assert!(
            reads.unattributed_reads() > 0,
            "a live index without its receipt must refuse: {reads:?}"
        );
        assert!(
            !reads.keys().iter().any(|key| matches!(key,
            ReadKey::File { rel_path, .. } if rel_path.as_ref() == "pom.xml")),
            "a lost receipt must never be recreated from current manifests: {reads:?}"
        );
        assert!(
            std::sync::Arc::ptr_eq(&built, index.get().unwrap().replay()),
            "must keep the original index"
        );
    }
}

#[cfg(test)]
mod failed_input_tests {
    use super::*;
    use crate::analyzer::scala::ScalaAnalyzer;
    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_analysis::analyzer::{LookupQuestion, ReadKey, capture_query_reads};

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#2445: Scala external inputs omitted inventory and absent manifests"
    )]
    fn scala_external_index_build_records_inventory_and_absent_manifests() {
        let project = InlineTestProject::with_language(Language::Scala)
            .file("App.scala", "class App")
            .build();
        let scala = ScalaAnalyzer::new(project.project_arc());
        scala.external_declaration_index();
        let (_, reads) = capture_query_reads(&scala, || {
            scala.external_declaration_index();
        });
        assert_eq!(reads.unattributed_reads(), 0, "{reads:?}");
        assert!(
            reads.keys().iter().any(|key| matches!(
                key,
                ReadKey::Lookup {
                    question: LookupQuestion::WorkspaceFact {
                        family: WorkspaceFactFamily::WorkspaceFileInventory,
                        ..
                    },
                    ..
                }
            )),
            "{reads:?}"
        );
        for candidate in ["pom.xml", "build.gradle", "gradle.lockfile"] {
            assert!(reads.keys().iter().any(|key| matches!(key,
                ReadKey::PathAbsent { language: Language::Scala, rel_path } if rel_path.as_ref() == candidate)), "{reads:?}");
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#2445: failed Scala manifest snapshots were silently dropped from receipts"
    )]
    fn failed_manifest_snapshot_refuses_subsequent_external_index_hits() {
        let project = InlineTestProject::with_language(Language::Scala)
            .file("App.scala", "class App")
            .build();
        std::fs::create_dir(project.root().join("pom.xml")).unwrap();
        let scala = ScalaAnalyzer::new(project.project_arc());
        scala.external_declaration_index();
        for _ in 0..2 {
            let (_, reads) = capture_query_reads(&scala, || {
                scala.external_declaration_index();
            });
            assert!(
                reads.unattributed_reads() > 0,
                "failed snapshots must remain a refusal: {reads:?}"
            );
        }
    }
}
