//! Complete, position-independent Kotlin star-import inventory certificates.
use super::KotlinAnalyzer;
use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;
use brokk_bifrost_analysis::analyzer::semantic::{LengthDelimitedDigest, StableDigest};
use brokk_bifrost_analysis::analyzer::workspace_authority::{AuthorityInputs, memo_attribution};
use brokk_bifrost_analysis::analyzer::{FactSubject, IAnalyzer, WorkspaceFactFamily};
use brokk_bifrost_core::analyzer::{CodeUnit, CodeUnitIndex, Language};
use brokk_bifrost_core::hash::HashMap;
use std::sync::Arc;

pub(super) struct TopLevelInventory {
    pub(super) by_package: Arc<HashMap<String, Arc<Vec<CodeUnit>>>>,
    digest: StableDigest,
    complete: bool,
}

fn build_top_level_inventory(kotlin: &KotlinAnalyzer) -> TopLevelInventory {
    use brokk_bifrost_analysis::path_utils::workspace_relative_slash_path;
    use brokk_bifrost_jvm::kotlin::imports::build_kotlin_top_level_declarations_by_package;

    let scope = brokk_bifrost_analysis::analyzer::AnalyzerQueryScope::new(kotlin);
    let by_package = build_kotlin_top_level_declarations_by_package(kotlin);
    let mut identities = by_package
        .iter()
        .flat_map(|(package, units)| {
            units.iter().map(move |unit| {
                (
                    package.as_str(),
                    workspace_relative_slash_path(unit.source().rel_path()),
                    unit.fq_name(),
                    unit.kind(),
                )
            })
        })
        .collect::<Vec<_>>();
    identities.sort();
    let mut hash = LengthDelimitedDigest::new(b"kotlin-top-level-inventory/v1");
    hash.push(&[u8::from(kotlin.has_complete_symbol_lookup_index())]);
    for (package, path, name, kind) in identities {
        hash.push(package.as_bytes());
        hash.push(path.as_bytes());
        hash.push(name.as_bytes());
        hash.push(format!("{kind:?}").as_bytes());
    }
    // Retain only the existing declaration inventory and a scalar certificate.
    // Failed builds return only their current answer; the shared cell stays empty.
    TopLevelInventory {
        by_package: Arc::new(by_package),
        digest: hash.finish(),
        complete: scope.read_completion().is_ok(),
    }
}

impl KotlinAnalyzer {
    pub(super) fn top_level_inventory(&self) -> Arc<TopLevelInventory> {
        self.top_level_declarations_by_package.read(
            &memo_attribution(self),
            |cell| {
                brokk_bifrost_analysis::analyzer::common::complete_query_cache_arc_cell(
                    self,
                    cell,
                    || build_top_level_inventory(self),
                )
            },
            |value| {
                if !value.complete {
                    self.record_unattributed_read();
                }
                AuthorityInputs::Fact {
                    language: Language::Kotlin,
                    subject: FactSubject::Whole,
                    answer: value.digest,
                }
            },
        )
    }
}

pub(super) fn answer(
    analyzer: &dyn IAnalyzer,
    family: WorkspaceFactFamily,
    language: Language,
    subject: &FactSubject,
) -> Option<StableDigest> {
    if language != Language::Kotlin
        || family != WorkspaceFactFamily::KotlinTopLevelDeclarations
        || !matches!(subject, FactSubject::Whole)
    {
        return None;
    }
    let inventory = resolve_analyzer::<KotlinAnalyzer>(analyzer)?.top_level_inventory();
    inventory.complete.then_some(inventory.digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_analysis::analyzer::{AnalyzerConfig, ReadKey, capture_query_reads};
    use brokk_bifrost_core::analyzer::capabilities::{
        ImportAnalysisProvider, TypeHierarchyProvider,
    };
    use brokk_bifrost_core::analyzer::query_token::QueryScope;

    fn fixture() -> crate::inline_project::BuiltInlineTestProject {
        InlineTestProject::with_language(Language::Kotlin)
            .file(
                "app/Use.kt",
                "package app\nimport lib.Base\nclass Use : Base()",
            )
            .file("lib/Base.kt", "package lib\nopen class Base")
            .file("elsewhere/Extra.kt", "package elsewhere\nclass Extra")
            .build()
    }

    fn captured_inventory(kotlin: &KotlinAnalyzer) -> StableDigest {
        let (digest, reads) = capture_query_reads(kotlin, || kotlin.top_level_inventory().digest);
        assert_eq!(reads.unattributed_reads(), 0, "{reads:?}");
        assert_eq!(reads.keys().len(), 1, "{reads:?}");
        assert!(
            matches!(&reads.keys()[0], ReadKey::Lookup { .. }),
            "{reads:?}"
        );
        digest
    }

    #[test]
    fn top_level_inventory_rejects_an_unimported_declaration_edit() {
        use brokk_bifrost_analysis::analyzer::{
            ChangedFacts, LookupMemo, LookupReplayLimits, NoSummaryAnswers, ReadVerdict,
        };
        let project = fixture();
        let base = project.workspace_analyzer(AnalyzerConfig::default());
        let (_, reads) = capture_query_reads(base.analyzer(), || {
            assert!(
                answer(
                    base.analyzer(),
                    WorkspaceFactFamily::KotlinTopLevelDeclarations,
                    Language::Kotlin,
                    &FactSubject::Whole
                )
                .is_some()
            );
        });
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
        // This file is not imported by Use.kt; its package still contributes
        // to the complete authority, including negative star-import answers.
        project
            .file("elsewhere/Extra.kt")
            .write("package elsewhere\nclass Replacement")
            .unwrap();
        let head = project.workspace_analyzer(AnalyzerConfig::default());
        assert_ne!(verify(&head), ReadVerdict::Unchanged);
    }

    #[test]
    fn top_level_inventory_digest_repeats_on_a_warm_generation() {
        let project = fixture();
        let kotlin = KotlinAnalyzer::new(project.project_arc());
        assert_eq!(captured_inventory(&kotlin), captured_inventory(&kotlin));
    }

    #[test]
    fn top_level_inventory_ignores_comments_above_the_first_declaration() {
        let project = fixture();
        let before = captured_inventory(&KotlinAnalyzer::new(project.project_arc()));
        project
            .file("lib/Base.kt")
            .write("// comment\npackage lib\nopen class Base")
            .unwrap();
        assert_eq!(
            before,
            captured_inventory(&KotlinAnalyzer::new(project.project_arc()))
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#7496: warm JVM authority hits omitted their inputs from policy read sets"
    )]
    fn warm_kotlin_reference_dependency_and_descendant_indexes_name_the_source_realm() {
        let project = fixture();
        let kotlin = KotlinAnalyzer::new(project.project_arc());
        let file = project.file("lib/Base.kt");
        let owner = kotlin
            .all_declarations()
            .find(|unit| unit.fq_name() == "lib.Base")
            .unwrap();
        let files = kotlin.inner.all_files().to_vec();
        let cancellation = brokk_bifrost_core::cancellation::CancellationToken::default();
        kotlin.prefetch_file_dependency_targets(&files, None, &cancellation);
        let read = || {
            assert!(!kotlin.referencing_files_of(&file).is_empty());
            kotlin.same_package_reference_index();
            assert!(kotlin.imported_files_from_infos(&file, &[]).is_some());
            assert!(!kotlin.get_direct_descendants(&owner).is_empty());
        };
        read();
        let references = || {
            kotlin.referencing_files_of(&file);
        };
        let reverse = || {
            kotlin.reverse_import_index();
        };
        let same_package = || {
            kotlin.same_package_reference_index();
        };
        let dependencies = || {
            kotlin.imported_files_from_infos(&file, &[]);
        };
        let descendants = || {
            kotlin.get_direct_descendants(&owner);
        };
        let readers: [&dyn Fn(); 5] = [
            &references,
            &reverse,
            &same_package,
            &dependencies,
            &descendants,
        ];
        for reader in readers.into_iter().cycle().take(10) {
            let (_, reads) = capture_query_reads(&kotlin, reader);
            assert_eq!(reads.unattributed_reads(), 0, "{reads:?}");
            assert!(
                reads
                    .keys()
                    .iter()
                    .any(|key| matches!(key, ReadKey::Scope { .. })),
                "{reads:?}"
            );
        }
        kotlin.referencing_files.invalidate_all();
        let (_, reads) = capture_query_reads(&kotlin, read);
        assert_eq!(reads.unattributed_reads(), 0, "{reads:?}");
        assert!(
            reads
                .keys()
                .iter()
                .any(|key| matches!(key, ReadKey::Scope { .. })),
            "{reads:?}"
        );
        let scope = brokk_bifrost_analysis::analyzer::AnalyzerQueryScope::new(&kotlin);
        let realm = crate::analyzer::jvm::realm_builder::jvm_source_realm(&kotlin);
        // Exercise the separately owned realm descendant cell as well.
        let descendant_scope =
            brokk_bifrost_core::analyzer::capabilities::DescendantIndexScope::whole_workspace(
                &cancellation,
            );
        let realm_read = || {
            assert!(
                kotlin
                    .direct_descendants_in_realm(
                        scope.token(),
                        &owner,
                        Some(&realm),
                        &descendant_scope
                    )
                    .is_some()
            );
        };
        realm_read();
        let (_, reads) = capture_query_reads(&kotlin, realm_read);
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
mod dead_code_tests {
    use super::*;
    use crate::analyzer::kotlin::{DeadCodeBulkProof, KotlinDeadCodeBulk};
    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_analysis::analyzer::{ReadKey, capture_query_reads};

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#7496: warm JVM authority hits omitted their inputs from policy read sets"
    )]
    fn warm_dead_code_edges_name_the_source_realm() {
        let project = InlineTestProject::with_language(Language::Kotlin)
            .file("App.kt", "fun leaf() {}\nfun caller() { leaf() }")
            .build();
        let kotlin = KotlinAnalyzer::new(project.project_arc());
        let candidates = kotlin.all_declarations().collect::<Vec<_>>();
        let read = || assert!(KotlinDeadCodeBulk.build(&kotlin, &candidates).is_some());
        read();
        for _ in 0..2 {
            let (_, reads) = capture_query_reads(&kotlin, read);
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
        let project = InlineTestProject::with_language(Language::Kotlin)
            .file("App.kt", "class App {}")
            .file("pom.xml", "<project/>")
            .build();
        let config = brokk_bifrost_analysis::analyzer::AnalyzerConfig {
            memo_cache_budget_bytes: Some(8),
            ..Default::default()
        };
        let analyzer = KotlinAnalyzer::new_with_config(project.project_arc(), config);
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
