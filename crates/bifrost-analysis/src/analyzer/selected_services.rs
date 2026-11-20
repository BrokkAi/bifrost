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

#[cfg(any(test, feature = "test-support"))]
thread_local! {
    static REFUSE_SELECTED_RECEIVER_PROOF_CAPTURE_AFTER: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
    static REFUSE_CURRENT_INSTANCE_RECEIVER_PROOF_CAPTURE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static CURRENT_INSTANCE_RECEIVER_PROOF_CAPTURE_HITS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static REFUSE_OWNER_APPLICATION_PROOF_REPLAY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static OWNER_APPLICATION_PROOF_REPLAY_HITS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static REFUSE_CURRENT_INSTANCE_RECEIVER_PROOF_REPLAY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static CURRENT_INSTANCE_RECEIVER_PROOF_REPLAY_HITS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Make the next real selected receiver-proof capture refuse reuse through
/// the analyzer's ordinary refusal channel. The proof read still runs inside
/// the actual captured ledger, which is then forwarded normally.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn with_unpublishable_selected_receiver_proof_capture_for_test<T>(
    run: impl FnOnce() -> T,
) -> T {
    with_unpublishable_selected_receiver_proof_capture_after_for_test(0, run)
}

/// Refuse a selected receiver-proof capture after `successful_captures` real
/// captures have completed. This lets a composite proof keep its nested
/// owner receipt while refusing the enclosing Base capture.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn with_unpublishable_selected_receiver_proof_capture_after_for_test<T>(
    successful_captures: usize,
    run: impl FnOnce() -> T,
) -> T {
    struct Restore(Option<usize>);
    impl Drop for Restore {
        fn drop(&mut self) {
            REFUSE_SELECTED_RECEIVER_PROOF_CAPTURE_AFTER.with(|flag| flag.set(self.0));
        }
    }

    let previous = REFUSE_SELECTED_RECEIVER_PROOF_CAPTURE_AFTER
        .with(|flag| flag.replace(Some(successful_captures)));
    let _restore = Restore(previous);
    run()
}

/// Refuse the real current-instance transfer capture, if the normal query
/// reaches one, and return the number of matching captures refused.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn with_unpublishable_current_instance_receiver_proof_capture_for_test<T>(
    run: impl FnOnce() -> T,
) -> (T, usize) {
    struct Restore(bool, usize);
    impl Drop for Restore {
        fn drop(&mut self) {
            REFUSE_CURRENT_INSTANCE_RECEIVER_PROOF_CAPTURE.with(|flag| flag.set(self.0));
            CURRENT_INSTANCE_RECEIVER_PROOF_CAPTURE_HITS.with(|hits| hits.set(self.1));
        }
    }

    let previous = REFUSE_CURRENT_INSTANCE_RECEIVER_PROOF_CAPTURE.with(|flag| flag.replace(true));
    let previous_hits = CURRENT_INSTANCE_RECEIVER_PROOF_CAPTURE_HITS.with(|hits| hits.replace(0));
    let _restore = Restore(previous, previous_hits);
    let result = run();
    let hits = CURRENT_INSTANCE_RECEIVER_PROOF_CAPTURE_HITS.with(std::cell::Cell::get);
    (result, hits)
}

/// Refuse a stored selected-read receipt only after a real current-instance
/// memo replay begins; the normal replay still forwards every ledger channel.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn with_unpublishable_current_instance_receiver_proof_replay_for_test<T>(
    run: impl FnOnce() -> T,
) -> (T, usize) {
    struct Restore(bool, usize);
    impl Drop for Restore {
        fn drop(&mut self) {
            REFUSE_CURRENT_INSTANCE_RECEIVER_PROOF_REPLAY.with(|flag| flag.set(self.0));
            CURRENT_INSTANCE_RECEIVER_PROOF_REPLAY_HITS.with(|hits| hits.set(self.1));
        }
    }

    let previous = REFUSE_CURRENT_INSTANCE_RECEIVER_PROOF_REPLAY.with(|flag| flag.replace(true));
    let previous_hits = CURRENT_INSTANCE_RECEIVER_PROOF_REPLAY_HITS.with(|hits| hits.replace(0));
    let _restore = Restore(previous, previous_hits);
    let result = run();
    let hits = CURRENT_INSTANCE_RECEIVER_PROOF_REPLAY_HITS.with(std::cell::Cell::get);
    (result, hits)
}

/// Refuse only a real owner-application memo replay through the normal ledger.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn with_unpublishable_owner_application_proof_replay_for_test<T>(
    run: impl FnOnce() -> T,
) -> (T, usize) {
    struct Restore(bool, usize);
    impl Drop for Restore {
        fn drop(&mut self) {
            REFUSE_OWNER_APPLICATION_PROOF_REPLAY.with(|flag| flag.set(self.0));
            OWNER_APPLICATION_PROOF_REPLAY_HITS.with(|hits| hits.set(self.1));
        }
    }
    let previous = REFUSE_OWNER_APPLICATION_PROOF_REPLAY.with(|flag| flag.replace(true));
    let previous_hits = OWNER_APPLICATION_PROOF_REPLAY_HITS.with(|hits| hits.replace(0));
    let _restore = Restore(previous, previous_hits);
    let result = run();
    (
        result,
        OWNER_APPLICATION_PROOF_REPLAY_HITS.with(std::cell::Cell::get),
    )
}

#[cfg(any(test, feature = "test-support"))]
fn is_current_instance_receiver_proof_ledger(ledger: &super::read_ledger::ReadLedger) -> bool {
    ledger.keys().iter().any(|key| {
        matches!(
            key,
            ReadKey::Lookup {
                kind: LookupKind::SelectedReceiverProof,
                question: LookupQuestion::SelectedReceiverProof(
                    super::semantic::read_ledger::SelectedReceiverProofQuestion::CurrentInstanceTransfer { .. }
                ),
                ..
            }
        )
    })
}

#[doc(hidden)]
pub struct AnalyzerSelectedServices<'a>(pub &'a dyn IAnalyzer);

// Keep this exhaustive: a new receipt kind needs an explicit currency proof
// before a retained frontier can replay it without reading its inputs again.
#[derive(Clone, Copy, PartialEq, Eq)]
enum MacroFrontierCoverage {
    MainStore,
    ModelSet,
    Uncovered,
}

fn macro_frontier_coverage(key: &ReadKey) -> MacroFrontierCoverage {
    match key {
        // Selected mounts change fingerprint/routing/generation on content or overlay changes.
        ReadKey::File {
            language: _,
            rel_path: _,
            blob: _,
            parse_variant: _,
        } => MacroFrontierCoverage::MainStore,
        // An in-memory index may read inputs outside the selected main database.
        ReadKey::Index { family: _, key: _ } => MacroFrontierCoverage::Uncovered,
        // Disk absence can change without a main publication or selected mount change.
        ReadKey::PathAbsent {
            language: _,
            rel_path: _,
        } => MacroFrontierCoverage::Uncovered,
        // Derived/external lookup sources have no established main-store currency proof.
        ReadKey::Lookup {
            kind: _,
            question: _,
            digest: _,
        } => MacroFrontierCoverage::Uncovered,
        // An artifact can depend on external or attached inputs, not just selected rows.
        ReadKey::Artifact { id: _, rel_path: _ } => MacroFrontierCoverage::Uncovered,
        // Workspace scope can include non-selected or external state.
        ReadKey::Scope {
            languages: _,
            identity: _,
        } => MacroFrontierCoverage::Uncovered,
        // The optional authority hash is stored and compared at adoption.
        ReadKey::Models(_) => MacroFrontierCoverage::ModelSet,
        // Policy text is not part of selected mount authority.
        ReadKey::Policy {
            semantic_hash: _,
            source: _,
        } => MacroFrontierCoverage::Uncovered,
        // Analyzer configuration has no independent frontier adoption check.
        ReadKey::Configuration(_) => MacroFrontierCoverage::Uncovered,
        // Engine epochs have no independent frontier adoption check.
        ReadKey::Epoch(_) => MacroFrontierCoverage::Uncovered,
    }
}

// Owned keys prevent a caller's replay ledger from keeping evicted receipt backing alive.
struct MacroFrontReceipt {
    keys: Vec<super::read_ledger::ReadKey>,
    active_model_set_hash: Option<String>,
    channels: brokk_bifrost_core::analyzer::memo_attribution::ReadChannels,
    first_refusal: Option<brokk_bifrost_core::profiling::ReadRefusal>,
    first_execution_refusal: Option<brokk_bifrost_core::profiling::ReadRefusal>,
    runtime_cache_touched: bool,
}

impl SelectedMacroFrontierReads for &dyn IAnalyzer {
    fn capture(
        &self,
        active_model_set_hash: Option<&str>,
        prepare: &mut dyn FnMut() -> super::store::Result<SelectedResolutionStageOutcome>,
    ) -> (
        super::store::Result<SelectedResolutionStageOutcome>,
        Box<dyn std::any::Any + Send + Sync>,
    ) {
        let (outcome, reads) = super::i_analyzer::capture_query_reads(*self, prepare);
        (
            outcome,
            Box::new(MacroFrontReceipt {
                keys: reads.unordered_keys(),
                active_model_set_hash: active_model_set_hash.map(str::to_owned),
                channels: reads.channels(),
                first_refusal: reads.first_refusal(),
                first_execution_refusal: reads.first_execution_refusal(),
                runtime_cache_touched: reads.runtime_cache_touched(),
            }),
        )
    }

    fn replay(&self, receipt: &(dyn std::any::Any + Send + Sync)) {
        let receipt = receipt
            .downcast_ref::<MacroFrontReceipt>()
            .expect("macro frontier receipt belongs to the analyzer read ledger");
        let _refusal =
            brokk_bifrost_core::profiling::read_refusal_scope(receipt.first_refusal.clone());
        let _execution = brokk_bifrost_core::profiling::read_execution_refusal_scope(
            receipt.first_execution_refusal.clone(),
        );
        if receipt.runtime_cache_touched {
            self.mark_runtime_cache_touched();
        }
        super::i_analyzer::replay_query_read_receipt(
            *self,
            receipt.keys.iter().cloned(),
            receipt.channels,
        );
    }

    fn receipt_bytes(&self, receipt: &(dyn std::any::Any + Send + Sync)) -> usize {
        use brokk_bifrost_core::retention_budget::RetainedBytes;
        let receipt = receipt
            .downcast_ref::<MacroFrontReceipt>()
            .expect("macro frontier receipt belongs to the analyzer read ledger");
        std::mem::size_of_val(receipt) + receipt.keys.retained_bytes()
            - std::mem::size_of_val(&receipt.keys)
            + receipt.active_model_set_hash.retained_bytes()
            - std::mem::size_of_val(&receipt.active_model_set_hash)
            + receipt
                .first_refusal
                .as_ref()
                .map_or(0, |r| r.reason.capacity())
            + receipt
                .first_execution_refusal
                .as_ref()
                .map_or(0, |r| r.reason.capacity())
    }

    fn receipt_is_reusable(
        &self,
        receipt: &(dyn std::any::Any + Send + Sync),
        active_model_set_hash: Option<&str>,
    ) -> bool {
        let receipt = receipt
            .downcast_ref::<MacroFrontReceipt>()
            .expect("macro frontier receipt belongs to the analyzer read ledger");
        receipt.active_model_set_hash.as_deref() == active_model_set_hash
            && receipt
                .keys
                .iter()
                .all(|key| match macro_frontier_coverage(key) {
                    MacroFrontierCoverage::MainStore => true,
                    MacroFrontierCoverage::ModelSet => matches!(key, ReadKey::Models(hash)
                    if *hash == super::i_analyzer::current_model_set_digest(active_model_set_hash)),
                    MacroFrontierCoverage::Uncovered => false,
                })
            && receipt.channels.explicit_verdict.is_content()
            && receipt.channels.budget_dependences == 0
            && receipt.channels.execution_dependences == 0
            && receipt.channels.unattributed_reads == 0
            && receipt.channels.persistence_refusals == 0
            && !receipt.channels.reuse_refused
            && !receipt.channels.store_failed
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
    fn certify_selected_source_file(
        &self,
        expected: &super::store::resolution_operation::SelectedSourceFileCertificate<'_>,
    ) -> bool {
        self.0.certify_selected_source_file(expected)
    }

    fn selected_read_recorder(
        &self,
    ) -> Option<super::store::selected_read::SelectedReadRecorder<'_>> {
        self.0
            .supports_selected_read_recording()
            .then(|| super::store::selected_read::SelectedReadRecorder::new(self))
    }
    fn record_selected_dependency(
        &self,
        dependency: &super::store::selected_read::SelectedDependency,
    ) -> super::store::Result<()> {
        use super::store::selected_read::SelectedDependency;
        match dependency {
            SelectedDependency::Path {
                language,
                rel_path,
                selected,
            } => self.0.record_read(match selected {
                Some((blob, parse_variant)) => ReadKey::File {
                    language: *language,
                    rel_path: rel_path.clone(),
                    blob: *blob,
                    parse_variant: *parse_variant,
                },
                None => ReadKey::PathAbsent {
                    language: *language,
                    rel_path: rel_path.clone(),
                },
            }),
            SelectedDependency::Scope { languages } => self
                .0
                .record_read(self.0.workspace_scope_read_key(languages)),
            SelectedDependency::WorkspaceFactDigest { question, digest } => self.0.record_read(
                ReadKey::lookup(LookupKind::WorkspaceFact, (**question).clone(), *digest),
            ),
            SelectedDependency::WorkspaceFact {
                family,
                question: _,
                snapshot,
                base_profile,
            } => {
                let language =
                    super::Language::from_config_label(&snapshot.lang).ok_or_else(|| {
                        super::store::StoreError::new("unknown selected dependency language")
                    })?;
                super::languages::language_support_for_hook(
                    language,
                    "record_selected_build_dependency",
                )
                .ok_or_else(|| {
                    super::store::StoreError::new("selected build recorder unavailable")
                })?
                // The owner records its full build authority, a conservative
                // superset of the declared question, never less than it asks.
                .record_selected_build_dependency(
                    self.0,
                    *family,
                    snapshot,
                    *base_profile,
                )?;
            }
        }
        Ok(())
    }

    fn selected_read_failed(&self, error: &super::store::StoreError, cancelled: bool) {
        use super::store::selected_read::SelectedReadRecording;
        self.failed(error, cancelled);
    }

    fn record_selected_derivation(
        &self,
        inventory: &super::store::resolution_selection::SelectedResolutionMountInventory<'_>,
        kind: super::semantic::derivation::DerivationKindId,
        question: &super::semantic::derivation::DerivationQuestion,
    ) {
        use brokk_bifrost_semantic::analyzer::semantic::derivation::ReplayedDemand;
        let Some(host) = self.0.derivations() else {
            self.refuse_read_reuse();
            return;
        };
        match host.demand_selected_question(self.0, inventory, kind, question) {
            ReplayedDemand::Available { retained: true, .. } => {}
            // Unavailable or request-owned evidence still permits the current
            // answer, but cannot certify a retained policy receipt.
            _ => self.refuse_read_reuse(),
        }
    }

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

    fn record_selected_signature_metadata(
        &self,
        declaration: &CodeUnit,
        metadata: Option<&[brokk_bifrost_core::analyzer::model::SignatureMetadata]>,
    ) {
        let digest = metadata.map_or_else(
            super::read_ledger::absent_signature_metadata_digest,
            |metadata| super::read_ledger::signature_metadata_digest(declaration, metadata),
        );
        self.0.record_read(ReadKey::lookup(
            LookupKind::SignatureMetadata,
            LookupQuestion::declaration(declaration),
            digest,
        ));
    }

    fn record_selected_receiver_proof(
        &self,
        question: &super::semantic::read_ledger::SelectedReceiverProofQuestion,
        answer: &super::semantic::read_ledger::SelectedReceiverProofAnswer,
    ) {
        self.0.record_read(ReadKey::lookup(
            LookupKind::SelectedReceiverProof,
            LookupQuestion::SelectedReceiverProof(question.clone()),
            answer.canonical_digest(),
        ));
    }

    fn capture_selected_receiver_proof(
        &self,
        read: &mut dyn FnMut() -> super::store::Result<()>,
    ) -> (
        super::store::Result<()>,
        Option<Arc<dyn std::any::Any + Send + Sync>>,
    ) {
        let (outcome, reads) = super::i_analyzer::capture_query_reads(self.0, || {
            let outcome = read();
            #[cfg(any(test, feature = "test-support"))]
            if REFUSE_CURRENT_INSTANCE_RECEIVER_PROOF_CAPTURE.with(std::cell::Cell::get)
                && self
                    .0
                    .current_thread_read_ledger()
                    .is_some_and(|ledger| is_current_instance_receiver_proof_ledger(&ledger))
            {
                CURRENT_INSTANCE_RECEIVER_PROOF_CAPTURE_HITS.with(|hits| hits.set(hits.get() + 1));
                self.refuse_read_reuse();
            }
            #[cfg(any(test, feature = "test-support"))]
            if REFUSE_SELECTED_RECEIVER_PROOF_CAPTURE_AFTER.with(|flag| match flag.get() {
                Some(0) => {
                    flag.set(None);
                    true
                }
                Some(remaining) => {
                    flag.set(Some(remaining - 1));
                    false
                }
                None => false,
            }) {
                self.refuse_read_reuse();
            }
            outcome
        });
        let receipt = reads
            .publishable_keys()
            .is_some()
            .then(|| Arc::new(reads) as Arc<dyn std::any::Any + Send + Sync>);
        (outcome, receipt)
    }

    fn replay_selected_receiver_proof(
        &self,
        receipt: &(dyn std::any::Any + Send + Sync),
    ) -> Option<Arc<dyn std::any::Any + Send + Sync>> {
        let reads = receipt
            .downcast_ref::<Arc<super::read_ledger::ReadLedger>>()
            .expect("receiver proof receipt belongs to the analyzer read ledger");
        #[cfg(any(test, feature = "test-support"))]
        if REFUSE_CURRENT_INSTANCE_RECEIVER_PROOF_REPLAY.with(std::cell::Cell::get)
            && is_current_instance_receiver_proof_ledger(reads)
        {
            CURRENT_INSTANCE_RECEIVER_PROOF_REPLAY_HITS.with(|hits| hits.set(hits.get() + 1));
            reads.refuse_read_reuse();
        }
        #[cfg(any(test, feature = "test-support"))]
        if REFUSE_OWNER_APPLICATION_PROOF_REPLAY.with(std::cell::Cell::get)
            && reads.keys().iter().any(|key| matches!(key, ReadKey::Lookup {
                kind: LookupKind::SelectedReceiverProof,
                question: LookupQuestion::SelectedReceiverProof(super::semantic::read_ledger::SelectedReceiverProofQuestion::OwnerApplication { .. }), ..
            })) {
            OWNER_APPLICATION_PROOF_REPLAY_HITS.with(|hits| hits.set(hits.get() + 1));
            reads.refuse_read_reuse();
        }
        super::i_analyzer::replay_query_reads(self.0, reads);
        reads
            .publishable_keys()
            .is_some()
            .then(|| Arc::clone(reads) as Arc<dyn std::any::Any + Send + Sync>)
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

    fn external_inventory_providers(&self, models: &ResolvedActiveSemanticModels) -> Vec<String> {
        // Publish request-owned inventory before the retained index is checked.
        if let Some(open) = models.gate_inventory_providers(&mut Vec::new()) {
            self.record_model_family_open(open);
        }
        let mut providers = super::languages::selected_external_inventory_providers(self.0, models);
        if let Some(open) = models.gate_inventory_providers(&mut providers) {
            self.record_model_family_open(open);
        }
        providers
    }

    fn active_models(&self) -> Option<Arc<ResolvedActiveSemanticModels>> {
        self.0
            .active_semantic_model_snapshot()
            .map(|snapshot| Arc::clone(snapshot.active_models()))
    }

    fn model_authority(&self) -> Option<Arc<dyn SelectedModelAuthority + Send + Sync>> {
        self.0
            .semantic_model_overlay_read()
            .published()
            .map(|overlay| overlay as Arc<dyn SelectedModelAuthority + Send + Sync>)
    }

    fn record_model_family_open(&self, open: crate::analyzer::semantic_model::runtime::FamilyOpen) {
        let reason = if open.is_cancellation() {
            crate::analyzer::QueryReadIncomplete::Cancelled
        } else {
            crate::analyzer::QueryReadIncomplete::SemanticEvidenceUnavailable(
                format!("semantic-model lookup is open: {}", open.reason).into(),
            )
        };
        self.0.record_query_incomplete(reason);
    }

    fn record_source_read(&self, file: &ProjectFile) {
        crate::analyzer::record_position_read(self.0, file);
    }

    fn record_selected_rust_inventory(
        &self,
        kind: LookupKind,
        question: LookupQuestion,
        digest: crate::analyzer::semantic::ids::StableDigest,
    ) -> bool {
        self.0.record_read(ReadKey::lookup(kind, question, digest));
        true
    }

    fn record_rust_macro_invocations(
        &self,
        question: LookupQuestion,
        digest: crate::analyzer::semantic::ids::StableDigest,
    ) {
        self.0.record_read(ReadKey::lookup(
            LookupKind::RustMacroInvocations,
            question,
            digest,
        ));
    }

    fn record_model_authority_read(&self, hash: &str) {
        self.0
            .record_read(crate::analyzer::read_ledger::ReadKey::Models(
                crate::analyzer::semantic::ids::StableDigest::sha256(hash),
            ));
    }
}

impl super::store::selected_read::SelectedReadRecording for AnalyzerSelectedServices<'_> {
    fn capture(
        &self,
        work: &mut dyn FnMut() -> super::store::Result<()>,
    ) -> (
        super::store::Result<()>,
        Arc<dyn std::any::Any + Send + Sync>,
    ) {
        let (answer, receipt) = super::i_analyzer::QueryReadReceipt::capture(self.0, work);
        (answer, Arc::new(receipt))
    }
    fn replay(&self, receipt: &(dyn std::any::Any + Send + Sync)) {
        receipt
            .downcast_ref::<super::i_analyzer::QueryReadReceipt>()
            .expect("selected receipt belongs to analyzer")
            .replay(self.0);
    }
    fn reusable(&self, receipt: &(dyn std::any::Any + Send + Sync)) -> bool {
        receipt
            .downcast_ref::<super::i_analyzer::QueryReadReceipt>()
            .expect("selected receipt belongs to analyzer")
            .reusable()
    }
    fn receipt_bytes(&self, receipt: &(dyn std::any::Any + Send + Sync)) -> usize {
        let mut heap = super::store::cache_budget::RetainedHeap::default();
        receipt
            .downcast_ref::<super::i_analyzer::QueryReadReceipt>()
            .expect("selected receipt belongs to analyzer")
            .retained_heap(&mut heap);
        heap.bytes() + std::mem::size_of::<super::i_analyzer::QueryReadReceipt>()
    }
    fn failed(&self, error: &super::store::StoreError, cancelled: bool) {
        if cancelled {
            self.0
                .record_query_incomplete(super::QueryReadIncomplete::Cancelled);
        } else {
            self.0.record_query_failure(error.clone());
        }
    }
    fn matches_frame(
        &self,
        owner: brokk_bifrost_semantic::analyzer::semantic::derivation::DerivationKindId,
        revision: &dyn std::any::Any,
        authority: &dyn std::any::Any,
        inventory: &super::store::resolution_selection::SelectedResolutionMountInventory<'_>,
    ) -> bool {
        let Some(revision) = revision.downcast_ref::<super::store::reader_binding::ReaderBinding>()
        else {
            return false;
        };
        let Some(authority) =
            authority.downcast_ref::<super::derivation_host::authority::AnalyzerAuthority>()
        else {
            return false;
        };
        inventory.derivation_reader_binding().is_ok_and(|bound| {
            &bound == revision
                && inventory.derivation_read_still_bound(revision)
                && *authority
                    == super::derivation_host::authority::AnalyzerAuthority::for_kind(
                        revision, owner,
                    )
        })
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

    /// A language without a wrapper-supplied extension hashes nothing beyond
    /// its own content identity (#13307).
    #[test]
    fn a_language_without_an_identity_extension_keeps_its_content_identity() {
        let temp = tempfile::tempdir().expect("temporary workspace");
        let root = temp.path().canonicalize().expect("absolute workspace root");
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Python));
        let _rules =
            crate::analyzer::languages::neutral_fixture::neutral_rules_fixture(&[Language::Python]);
        let analyzer = TreeSitterAnalyzer::new(project, EmptyPythonAdapter);
        assert_eq!(
            crate::analyzer::IAnalyzer::workspace_content_identities(&analyzer),
            Some(
                crate::analyzer::content_identity::WorkspaceContentIdentities::new([(
                    Language::Python,
                    analyzer.language_content_identity_with_omissions(),
                )])
            )
        );
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
    fn selected_receiver_proof_receipts_require_publishable_read_ledgers() {
        let temp = tempfile::tempdir().expect("temporary workspace");
        let root = temp.path().canonicalize().expect("absolute workspace root");
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Python));
        let _rules =
            crate::analyzer::languages::neutral_fixture::neutral_rules_fixture(&[Language::Python]);
        let analyzer = TreeSitterAnalyzer::new(project, EmptyPythonAdapter);
        let bridge = AnalyzerSelectedServices(&analyzer);
        let service: &dyn SelectedAnalyzerServices = &bridge;

        let (outcome, publishable) = service.capture_selected_receiver_proof(&mut || Ok(()));
        assert!(outcome.is_ok());
        let publishable = publishable.expect("empty bounded capture is publishable");
        let consumer = Arc::new(crate::analyzer::read_ledger::ReadLedger::new());
        {
            let _scope = AnalyzerQueryScope::with_read_ledger(&analyzer, Arc::clone(&consumer));
            assert!(
                service
                    .replay_selected_receiver_proof(publishable.as_ref())
                    .is_some()
            );
        }
        assert!(consumer.is_bounded());

        let (outcome, unattributed) = service.capture_selected_receiver_proof(&mut || {
            analyzer.record_unattributed_read();
            Ok(())
        });
        assert!(outcome.is_ok());
        assert!(unattributed.is_none());

        let (outcome, execution_dependent) = service.capture_selected_receiver_proof(&mut || {
            analyzer.mark_execution_dependent();
            Ok(())
        });
        assert!(outcome.is_ok());
        assert!(execution_dependent.is_none());

        let (outcome, refused) = service.capture_selected_receiver_proof(&mut || {
            service.refuse_read_reuse();
            Ok(())
        });
        assert!(outcome.is_ok());
        assert!(refused.is_none());

        let unpublishable = crate::analyzer::read_ledger::ReadLedger::new();
        unpublishable.record_unattributed();
        let unpublishable: Arc<dyn std::any::Any + Send + Sync> = Arc::new(Arc::new(unpublishable));
        let consumer = Arc::new(crate::analyzer::read_ledger::ReadLedger::new());
        {
            let _scope = AnalyzerQueryScope::with_read_ledger(&analyzer, Arc::clone(&consumer));
            assert!(
                service
                    .replay_selected_receiver_proof(unpublishable.as_ref())
                    .is_none()
            );
        }
        assert_eq!(consumer.unattributed_reads(), 1);
        assert!(!consumer.is_bounded());
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
