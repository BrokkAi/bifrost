//! Engine bridge for the selected store's borrowed service capability.

use std::sync::Arc;

use super::semantic_model::runtime::ResolvedActiveSemanticModels;
use super::store::resolution_operation::{SelectedAnalyzerServices, SelectedModelAuthority};
use super::store::resolution_operation::{
    SelectedMacroFrontierReads, SelectedResolutionStageOutcome,
};
use super::{CodeUnit, IAnalyzer, ProjectFile};
use crate::analyzer::i_analyzer::capture_nested_reads;
use crate::analyzer::read_ledger::{
    LookupKind, LookupQuestion, ReadKey, declaration_candidate_set_digest,
};
use brokk_bifrost_core::analyzer::memo_attribution::ReadReuseRefusal;

#[doc(hidden)]
pub struct AnalyzerSelectedServices<'a>(pub &'a dyn IAnalyzer);

impl SelectedMacroFrontierReads for &dyn IAnalyzer {
    fn capture(
        &self,
        prepare: &mut dyn FnMut() -> super::store::Result<SelectedResolutionStageOutcome>,
    ) -> (
        super::store::Result<SelectedResolutionStageOutcome>,
        Box<dyn std::any::Any + Send + Sync>,
    ) {
        let (outcome, reads) = super::i_analyzer::capture_query_reads(*self, prepare);
        (outcome, Box::new(reads))
    }

    fn replay(&self, receipt: &(dyn std::any::Any + Send + Sync)) {
        let reads = receipt
            .downcast_ref::<Arc<super::read_ledger::ReadLedger>>()
            .expect("macro frontier receipt belongs to the analyzer read ledger");
        super::i_analyzer::replay_query_reads(*self, reads);
    }

    fn receipt_bytes(&self, receipt: &(dyn std::any::Any + Send + Sync)) -> usize {
        let reads = receipt
            .downcast_ref::<Arc<super::read_ledger::ReadLedger>>()
            .expect("macro frontier receipt belongs to the analyzer read ledger");
        format!("{reads:?}").len()
    }

    fn policy_unit_label(&self) -> Option<String> {
        super::i_analyzer::current_policy_unit_label()
    }
}

impl ReadReuseRefusal for AnalyzerSelectedServices<'_> {
    fn refuse_read_reuse(&self) {
        super::i_analyzer::record_reuse_refusal(
            || self.0.read_ledger_attached(),
            || self.0.read_ledger_contexts(),
        );
    }

    fn record_language_scope_read(&self, language: super::Language) {
        self.0
            .record_read(self.0.workspace_scope_read_key(&[language]));
    }
}

impl SelectedAnalyzerServices for AnalyzerSelectedServices<'_> {
    fn certify_selected_configuration(
        &self,
        language: super::Language,
        snapshot: &super::store::WorkspaceSnapshotId,
        input_identity: &[u8; 32],
        connection: &rusqlite::Connection,
    ) -> super::store::resolution_operation::ConfigurationCertificate {
        self.0
            .certify_selected_configuration(language, snapshot, input_identity, connection)
    }

    fn admit_selected_external_binding(
        &self,
        request: &super::store::resolution_operation::SelectedExternalBindingRequest<'_>,
        cancellation: &crate::CancellationToken,
    ) -> super::store::resolution_operation::SelectedExternalBindingRead {
        super::languages::language_support_for_hook(
            request.language,
            "admit_selected_external_binding",
        )
        .map_or_else(
            super::store::resolution_operation::SelectedExternalBindingRead::unavailable,
            |support| support.admit_selected_external_binding(self.0, request, cancellation),
        )
    }

    fn declarations_named(&self, file: &ProjectFile, name: &str) -> Vec<CodeUnit> {
        self.0.declarations_named(file, name)
    }

    fn verified_declaration(&self, expected: &CodeUnit) -> Option<CodeUnit> {
        let select = || {
            self.0
                .declarations_named(expected.source(), expected.identifier())
                .into_iter()
                .find(|unit| unit == expected)
        };
        if !super::read_attribution_records_reads(|| self.0.read_ledger_attached()) {
            return select();
        }
        let question = LookupQuestion::declaration(expected);
        let read = || {
            let selected = select();
            // A rendered FQ spelling can hide different segment boundaries,
            // including a different terminal identifier. The key certifies
            // every parser unit matching the persisted question, not only the
            // identifier slice used by the hydration check.
            let candidates = self
                .0
                .declaration_candidates_for_question(expected.source(), &question);
            (selected, candidates)
        };
        let ((selected, candidates), captured) = capture_nested_reads(self.0, read);
        let Some(candidates) =
            candidates.filter(|_| self.0.current_query_read_completion().is_ok())
        else {
            for key in captured {
                self.0.record_read(key);
            }
            self.0.record_unattributed_read();
            return selected;
        };
        let source_path = crate::path_utils::rel_path_string(expected.source());
        // The candidate set replaces only this file's whole-file read. Keep
        // every other dependency the analyzer reported during the inventory.
        for key in captured {
            if !matches!(&key, ReadKey::File { language, rel_path, .. }
                if *language == expected.source().language()
                    && rel_path.as_ref() == source_path.as_str())
            {
                self.0.record_read(key);
            }
        }
        let digest = declaration_candidate_set_digest(&question, &candidates);
        self.0.record_read(ReadKey::lookup(
            LookupKind::DeclarationCandidates,
            question,
            digest,
        ));
        selected
    }

    fn external_inventory_providers(&self) -> Vec<String> {
        super::languages::selected_external_inventory_providers(self.0)
    }

    fn active_models(&self) -> Option<Arc<ResolvedActiveSemanticModels>> {
        self.0
            .active_semantic_model_snapshot()
            .map(|snapshot| Arc::clone(snapshot.active_models()))
    }

    fn model_authority(&self) -> Option<Arc<dyn SelectedModelAuthority + Send + Sync>> {
        self.0
            .semantic_model_overlay()
            .map(|overlay| overlay as Arc<dyn SelectedModelAuthority + Send + Sync>)
    }

    fn record_model_authority_read(&self, hash: &str) {
        self.0
            .record_read(crate::analyzer::read_ledger::ReadKey::Models(
                crate::analyzer::semantic::ids::StableDigest::sha256(hash),
            ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::store::StoreLanguageAdapter;
    use crate::analyzer::tree_sitter_analyzer::{LanguageAdapter, ParsedFile, TreeSitterAnalyzer};
    use crate::analyzer::{AnalyzerQueryScope, Language, Project, TestProject};
    use brokk_bifrost_test_macros::hardwon;
    use std::sync::Arc;

    struct EmptyPythonAdapter;

    impl StoreLanguageAdapter for EmptyPythonAdapter {
        fn parse_time_semantic_lowerer(
            &self,
        ) -> Option<crate::analyzer::semantic::service::ParseTimeSemanticLowerer> {
            None
        }

        fn language(&self) -> Language {
            Language::Python
        }
    }

    impl LanguageAdapter for EmptyPythonAdapter {
        fn line_data_kinds(&self) -> brokk_bifrost_core::analyzer::tree_walk::LineDataKinds {
            brokk_bifrost_core::analyzer::tree_walk::LineDataKinds {
                literals: &[],
                interpolations: &[],
                composites: &[],
            }
        }
        fn query_directory(&self) -> &'static str {
            "python"
        }

        fn file_extension(&self) -> &'static str {
            "py"
        }

        fn extract_call_receiver(&self, _reference: &str) -> Option<String> {
            None
        }

        fn parse_file(
            &self,
            _file: &ProjectFile,
            _source: &str,
            _tree: &tree_sitter::Tree,
        ) -> ParsedFile {
            unimplemented!("the read bridge does not parse source")
        }
    }

    #[test]
    #[hardwon("#9575: selected reuse refusal was discarded by nested read abstraction")]
    fn selected_service_refusal_survives_nested_shadowing_and_replay() {
        let temp = tempfile::tempdir().expect("temporary workspace");
        let root = temp.path().canonicalize().expect("absolute workspace root");
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Python));
        let _rules =
            crate::analyzer::languages::neutral_fixture::neutral_rules_fixture(&[Language::Python]);
        let analyzer = TreeSitterAnalyzer::new(project, EmptyPythonAdapter);
        let bridge = AnalyzerSelectedServices(&analyzer);
        let service: &dyn SelectedAnalyzerServices = &bridge;
        let outer = Arc::new(crate::analyzer::read_ledger::ReadLedger::new());
        {
            let _scope = AnalyzerQueryScope::with_read_ledger(&analyzer, Arc::clone(&outer));
            let (_, inner) = crate::analyzer::i_analyzer::capture_query_reads(&analyzer, || {
                let (_, keys) = capture_nested_reads(&analyzer, || service.refuse_read_reuse());
                assert!(keys.is_empty());
            });
            assert!(inner.reuse_refused());
            assert!(outer.reuse_refused());
            assert_eq!(outer.unattributed_reads(), 0);
            assert_eq!(outer.execution_dependences(), 0);
        }
        let replayed = Arc::new(crate::analyzer::read_ledger::ReadLedger::new());
        let _scope = AnalyzerQueryScope::with_read_ledger(&analyzer, Arc::clone(&replayed));
        crate::analyzer::i_analyzer::replay_query_reads(&analyzer, &outer);
        assert!(replayed.reuse_refused());
        assert!(!replayed.is_bounded());
    }

    #[test]
    #[hardwon("#9575: a borrowed selected service must attribute refusal to each current consumer")]
    fn borrowed_selected_service_uses_the_current_capture_consumer() {
        let temp = tempfile::tempdir().expect("temporary workspace");
        let root = temp.path().canonicalize().expect("absolute workspace root");
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Python));
        let _rules =
            crate::analyzer::languages::neutral_fixture::neutral_rules_fixture(&[Language::Python]);
        let analyzer = TreeSitterAnalyzer::new(project, EmptyPythonAdapter);
        let bridge = AnalyzerSelectedServices(&analyzer);
        let service: &dyn SelectedAnalyzerServices = &bridge;

        for _ in 0..2 {
            let consumer = Arc::new(crate::analyzer::read_ledger::ReadLedger::new());
            let (_, captured) = {
                let _scope = AnalyzerQueryScope::with_read_ledger(&analyzer, Arc::clone(&consumer));
                crate::analyzer::i_analyzer::capture_query_reads(&analyzer, || {
                    service.refuse_read_reuse();
                })
            };
            assert!(captured.reuse_refused());
            assert!(consumer.reuse_refused());
            assert_eq!(consumer.unattributed_reads(), 0);
        }
    }

    #[test]
    #[hardwon(
        "#9575: deferred and subsumed receipts lost explicit reuse refusal across capture boundaries"
    )]
    fn selected_refusal_deferred_and_subsumed_receipts_reach_actual_consumers() {
        let temp = tempfile::tempdir().expect("temporary workspace");
        let root = temp.path().canonicalize().expect("absolute workspace root");
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Python));
        let _rules =
            crate::analyzer::languages::neutral_fixture::neutral_rules_fixture(&[Language::Python]);
        let analyzer = TreeSitterAnalyzer::new(project, EmptyPythonAdapter);
        let bridge = AnalyzerSelectedServices(&analyzer);
        let service: &dyn SelectedAnalyzerServices = &bridge;

        let enclosing = Arc::new(crate::analyzer::read_ledger::ReadLedger::new());
        let deferred = {
            let _scope = AnalyzerQueryScope::with_read_ledger(&analyzer, Arc::clone(&enclosing));
            let (_, receipt) =
                crate::analyzer::i_analyzer::capture_query_reads_deferred(&analyzer, || {
                    service.refuse_read_reuse();
                    analyzer.mark_execution_dependent();
                });
            assert!(
                enclosing.is_bounded(),
                "deferred partition has no consumer yet"
            );
            assert_eq!(enclosing.unattributed_reads(), 0);
            assert_eq!(enclosing.execution_dependences(), 0);
            receipt
        };
        assert!(deferred.reuse_refused());
        assert!(deferred.keys().is_empty());
        assert_eq!(deferred.execution_dependences(), 1);
        let consumer = Arc::new(crate::analyzer::read_ledger::ReadLedger::new());
        {
            let _scope = AnalyzerQueryScope::with_read_ledger(&analyzer, Arc::clone(&consumer));
            crate::analyzer::i_analyzer::replay_query_reads(&analyzer, &deferred);
        }
        assert!(consumer.reuse_refused());
        assert!(!consumer.is_bounded());
        assert_eq!(consumer.unattributed_reads(), 0);
        assert_eq!(consumer.execution_dependences(), 1);

        let authority_consumer = Arc::new(crate::analyzer::read_ledger::ReadLedger::new());
        let receipt = {
            let _scope =
                AnalyzerQueryScope::with_read_ledger(&analyzer, Arc::clone(&authority_consumer));
            let (_, receipt) =
                crate::analyzer::i_analyzer::capture_subsumed_query_read_receipt(&analyzer, || {
                    service.refuse_read_reuse()
                });
            receipt
        };
        assert!(receipt.keys.is_empty());
        assert!(receipt.channels.reuse_refused);
        assert_eq!(receipt.channels.unattributed_reads, 0);
        assert_eq!(receipt.channels.execution_dependences, 0);
        assert!(!authority_consumer.is_bounded());
        let later_consumer = Arc::new(crate::analyzer::read_ledger::ReadLedger::new());
        {
            let _scope =
                AnalyzerQueryScope::with_read_ledger(&analyzer, Arc::clone(&later_consumer));
            crate::analyzer::i_analyzer::replay_shared_query_read_receipt(
                &analyzer,
                &receipt.keys,
                receipt.channels,
            );
        }
        assert!(later_consumer.reuse_refused());
        assert!(!later_consumer.is_bounded());
        assert_eq!(later_consumer.unattributed_reads(), 0);
        assert_eq!(later_consumer.execution_dependences(), 0);
    }

    #[test]
    #[hardwon(
        "#9575: ordinary nested implementation reads must remain replaceable by a named question"
    )]
    fn nested_ordinary_read_can_be_replaced_by_named_question() {
        let temp = tempfile::tempdir().expect("temporary workspace");
        let root = temp.path().canonicalize().expect("absolute workspace root");
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Python));
        let _rules =
            crate::analyzer::languages::neutral_fixture::neutral_rules_fixture(&[Language::Python]);
        let analyzer = TreeSitterAnalyzer::new(project, EmptyPythonAdapter);
        let outer = Arc::new(crate::analyzer::read_ledger::ReadLedger::new());
        let key = ReadKey::lookup(
            LookupKind::DeclarationCandidates,
            LookupQuestion::Name {
                language: Some(Language::Python),
                name: "named-question-control".into(),
            },
            crate::analyzer::semantic::ids::StableDigest::sha256("empty-answer"),
        );
        {
            let _scope = AnalyzerQueryScope::with_read_ledger(&analyzer, Arc::clone(&outer));
            let (_, implementation_keys) = capture_nested_reads(&analyzer, || {
                analyzer.record_unattributed_read();
            });
            assert!(implementation_keys.is_empty());
            analyzer.record_read(key.clone());
        }
        assert!(outer.is_bounded());
        assert!(!outer.reuse_refused());
        assert_eq!(outer.unattributed_reads(), 0);
        assert_eq!(outer.keys(), vec![key]);
    }
}
