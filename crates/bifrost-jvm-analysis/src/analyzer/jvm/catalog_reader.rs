//! Request-owned JVM catalog membership and row access.
use brokk_bifrost_analysis::analyzer::store::jvm_external_publication::jvm_external_provider_id;
use brokk_bifrost_semantic::analyzer::semantic_model::dependency::{
    JvmDependencyGap, JvmDependencyGapCause,
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use brokk_bifrost_analysis::analyzer::semantic_model::FamilyOpen;
use brokk_bifrost_analysis::analyzer::semantic_model::catalog::CatalogError;
use brokk_bifrost_analysis::analyzer::semantic_model::catalog::PinnedCatalogStatus;
use brokk_bifrost_analysis::analyzer::semantic_model::catalog::{
    ExpectedCatalogEntry, PinnedCatalogReader, PinnedCatalogRow, PinnedCatalogSource,
    PinnedReaderError,
};
use brokk_bifrost_analysis::analyzer::semantic_model::{Completeness, MemberFact, TypeFact};
use brokk_bifrost_analysis::analyzer::store::AnalyzerStore;
use brokk_bifrost_analysis::analyzer::store::StoreError;
use brokk_bifrost_analysis::analyzer::store::jvm_external_inventory::jvm_external_projection;
use brokk_bifrost_analysis::analyzer::store::jvm_external_publication::JvmExternalCertificate;
use brokk_bifrost_analysis::analyzer::store::jvm_external_publication::{
    JvmExternalProjection, JvmExternalPublication,
};
use brokk_bifrost_analysis::analyzer::store::model_catalog::{
    CatalogPackSourceKind, CatalogRowReader, OwnedCatalogRows, ReaderBinding, RequestRowReader,
    RequestRowReaderSource,
};
use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;
use brokk_bifrost_core::analyzer::external_selection::{
    ExternalSelectionAuthority, ExternalSelectionQuestionKind, SelectionRetry, VerifiedSelection,
};
use brokk_bifrost_core::analyzer::outer_request::{
    AdmittedSelection, JvmCatalogReaderKey, OuterRequest, RequestEntryKey, RequestResource,
    RequestResourceError,
};
use brokk_bifrost_core::analyzer::project::Project;
use brokk_bifrost_core::cancellation::CancellationToken;
use rusqlite::{Params, types::Value};

use super::external::{ExternalInventorySelection, SelectedJdk};
use brokk_bifrost_analysis::analyzer::store::active_models::{
    CatalogShardDatabase, ResolvedActiveSemanticModels,
};

pub struct JvmSelectionAuthority {
    pub config: brokk_bifrost_core::analyzer::config::JvmAnalyzerConfig,
    pub project: Arc<dyn Project>,
    /// The analyzer store's budget-charged region, shared by every JVM
    /// analyzer of the workspace: the JDK selection streams its content
    /// digests through it.
    pub verifications:
        Arc<brokk_bifrost_core::analyzer::external_selection::ToolchainVerifications>,
    pub digests: brokk_bifrost_core::content_digest::ContentDigestCache,
}

impl ExternalSelectionAuthority for JvmSelectionAuthority {
    fn answer(
        &self,
        request: &OuterRequest,
        question: &brokk_bifrost_core::analyzer::external_selection::ExternalSelectionQuestion,
        retry: &SelectionRetry,
        cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
    ) -> Result<
        Arc<VerifiedSelection>,
        brokk_bifrost_core::analyzer::external_selection::SelectionRefused,
    > {
        assert!(
            self.questions()
                .iter()
                .any(|candidate| candidate == question)
        );
        request.external_selection(self.project.as_ref(), question.digest, || {
            super::verified_selection::verify_selection_with(
                &self.config,
                self.project.as_ref(),
                &self.digests,
                &self.verifications,
                question,
                retry,
                cancellation,
            )
        })
    }

    fn questions(
        &self,
    ) -> Vec<brokk_bifrost_core::analyzer::external_selection::ExternalSelectionQuestion> {
        brokk_bifrost_core::analyzer::external_selection::ExternalSelectionQuestion::for_jvm(
            &self.config,
        )
    }

    fn basis(
        &self,
        question: &brokk_bifrost_core::analyzer::external_selection::ExternalSelectionQuestion,
        answer: [u8; 32],
    ) -> Option<brokk_bifrost_core::analyzer::external_selection::JvmDependencyBasis> {
        if super::dependency_discovery::manifest_scope(self.project.as_ref(), &self.config)
            .uses_project_build()
        {
            // A live build outside the source subset is not a frozen export's
            // tree part. Its receipt must re-ask the current authority.
            return None;
        }
        let basis = super::external::jvm_dependency_basis(&self.config, self.project.as_ref())?;
        (self.answer_under_basis(question, &basis)? == answer).then_some(basis)
    }

    fn answer_under_basis(
        &self,
        question: &brokk_bifrost_core::analyzer::external_selection::ExternalSelectionQuestion,
        basis: &brokk_bifrost_core::analyzer::external_selection::JvmDependencyBasis,
    ) -> Option<[u8; 32]> {
        if super::dependency_discovery::manifest_scope(self.project.as_ref(), &self.config)
            .uses_project_build()
        {
            return None;
        }
        use brokk_bifrost_core::analyzer::external_selection::ExternalSelectionQuestionKind;
        match question.kind {
            ExternalSelectionQuestionKind::Dependencies => {
                super::verified_selection::dependencies_answer_under_basis(
                    &self.config,
                    self.project.root(),
                    question,
                    basis,
                )
            }
            ExternalSelectionQuestionKind::Jdk | ExternalSelectionQuestionKind::RustToolchain => {
                None
            }
        }
    }
}

pub struct JvmRequestRowReaderSource {
    pub questions_digest: std::sync::OnceLock<[u8; 32]>,
    pub authority: Arc<dyn ExternalSelectionAuthority>,
    pub project: Arc<dyn Project>,
    pub catalog: PinnedCatalogSource,
    pub store: Arc<AnalyzerStore>,
}

impl std::fmt::Debug for JvmRequestRowReaderSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("JvmRequestRowReaderSource")
    }
}

impl RequestRowReaderSource for JvmRequestRowReaderSource {
    fn publish_activation(
        &self,
        activation: &ResolvedActiveSemanticModels,
        cancellation: &CancellationToken,
    ) -> Result<(), CatalogError> {
        let diagnostic = |provider: &str, cause: String| {
            let message = format!("JVM activation provider {provider}: {cause}");
            if std::env::var_os("BIFROST_TIMING").is_some() {
                eprintln!("{message}");
            }
            let mut diagnostics = activation
                .report
                .publication_diagnostics
                .lock()
                .expect("publication diagnostics lock");
            if !diagnostics.contains(&message) {
                diagnostics.push(message);
            }
        };
        if cancellation.is_cancelled() {
            return Err(CatalogError::Cancelled);
        }
        let writable = self.store.conn.execute(|conn| -> rusqlite::Result<bool> {
            Ok(!conn.is_readonly(rusqlite::MAIN_DB)?
                && !conn.pragma_query_value(None, "query_only", |row| row.get::<_, bool>(0))?)
        });
        let mut providers = std::collections::BTreeMap::<String, Vec<ExpectedCatalogEntry>>::new();
        for shard in activation
            .shards
            .iter()
            .filter(|shard| shard.request_owned())
        {
            let (provider, expected) = if shard.source_kind == CatalogPackSourceKind::Generated {
                let digest = shard
                    .source_id
                    .strip_prefix("production:")
                    .expect("generated activation source is a production");
                (
                    digest.to_owned(),
                    ExpectedCatalogEntry::Production {
                        production_digest: digest.to_owned(),
                    },
                )
            } else if matches!(
                shard.source_kind,
                CatalogPackSourceKind::Installed
                    | CatalogPackSourceKind::PreShipped
                    | CatalogPackSourceKind::Embedded
            ) {
                (
                    shard.manifest.semantic_sha256.clone(),
                    ExpectedCatalogEntry::Shard {
                        kind: shard.source_kind,
                        manifest_digest: shard.manifest.content_sha256.clone(),
                        shard_id: shard.descriptor.shard_id.clone(),
                    },
                )
            } else {
                continue;
            };
            let entries = providers.entry(provider).or_default();
            if shard.source_kind != CatalogPackSourceKind::Generated || entries.is_empty() {
                entries.push(expected);
            }
        }
        for (provider, expected) in providers {
            if cancellation.is_cancelled() {
                return Err(CatalogError::Cancelled);
            }
            match &writable {
                Ok(false) => continue,
                Err(error) => {
                    diagnostic(&provider, format!("store check failed: {error}"));
                    continue;
                }
                Ok(true) => {}
            }
            let partial = activation.shards.iter().filter(|shard|
                shard.manifest.semantic_sha256 == provider).any(|shard|
                shard.manifest.shards.iter().any(|descriptor|
                    descriptor.payload_kind == brokk_bifrost_analysis::analyzer::semantic_model::artifact::PayloadKind::DeclarationFacts
                    && !activation.shards.iter().any(|selected|
                        selected.manifest.semantic_sha256 == provider
                        && selected.descriptor.shard_id == descriptor.shard_id
                        && selected.request_owned())));
            if partial {
                diagnostic(&provider, "curated JVM pack partially selected".into());
                continue;
            }
            let reader = match self
                .catalog
                .pinned_jvm_reader(&expected, cancellation.clone())
            {
                Ok(reader) => reader,
                Err(PinnedReaderError::Cancelled) => return Err(CatalogError::Cancelled),
                Err(error) => {
                    diagnostic(&provider, format!("catalog pin failed: {error:?}"));
                    continue;
                }
            };
            let projections = ProviderProjections {
                reader: &reader,
                #[cfg(test)]
                projection_calls: &std::sync::atomic::AtomicUsize::new(0),
            };
            match projections.publish_providers(&self.store, cancellation, |_| {}) {
                Err(JvmCatalogReaderError::Reader(PinnedReaderError::Cancelled)) => {
                    return Err(CatalogError::Cancelled);
                }
                Err(error) => diagnostic(&provider, format!("publication failed: {error:?}")),
                Ok(outcomes) => {
                    if outcomes.is_empty() {
                        diagnostic(
                            &provider,
                            "no declaration projection: pinned provider has no declaration-facts shards".into(),
                        );
                    } else if outcomes
                        .iter()
                        .any(|(_, status)| *status != ProviderPublication::Certified)
                    {
                        diagnostic(
                            &provider,
                            format!("publication not Certified: {outcomes:?}"),
                        );
                    }
                }
            }
        }

        Ok(())
    }

    fn identity(&self) -> Option<[u8; 32]> {
        let mut hash = CanonicalHasher::new(b"jvm-request-row-source-v1");
        for question in self.authority.questions() {
            hash.field("question", &question.digest);
        }
        if let Some(stamp) = self.project.view_stamp() {
            stamp.hash_into(&mut hash);
        }
        hash.field(
            "generation",
            &self.project.analysis_generation().to_be_bytes(),
        );
        Some(hash.finish())
    }

    // Selection SQL runs on PinnedCatalogReader's BEGIN transaction, pinned across
    // main and session before membership expansion (catalog/pinned_reader.rs).
    // The source never retains ReaderDerivationMemo: it is obtained exclusively
    // from the current OuterRequest's resource map below. A new OuterRequest
    // therefore creates both a fresh reader and a fresh publication clock.
    // OuterRequest::resource retains that reader until request close. Certificates
    // and publication outcomes are also filled once on that handle. Thus a memo
    // never substitutes a fresh catalog/store snapshot for the request's pinned one.
    fn jvm_reader(
        &self,
        activation: &ResolvedActiveSemanticModels,
    ) -> Result<RequestRowReader, FamilyOpen> {
        let request = brokk_bifrost_analysis::analyzer::i_analyzer::current_outer_request()
            .ok_or_else(|| {
                brokk_bifrost_analysis::analyzer::i_analyzer::refuse_request_row_read_reuse();
                FamilyOpen::jvm("no request scope")
            })?;
        if request.is_closed() {
            brokk_bifrost_analysis::analyzer::i_analyzer::refuse_request_row_read_reuse();
            return Err(FamilyOpen::jvm("JVM catalog closed"));
        }
        if brokk_bifrost_analysis::analyzer::i_analyzer::current_query_cancellation()
            .is_some_and(|token| token.is_cancelled())
        {
            return Err(cancelled_open());
        }
        let key = self.reader_entry_key(activation);
        let memo = request
            .resource::<ReaderDerivationMemo, std::convert::Infallible>(key, || {
                Ok(Arc::new(ReaderDerivationMemo::default()))
            })
            .map_err(|_| {
                brokk_bifrost_analysis::analyzer::i_analyzer::refuse_request_row_read_reuse();
                FamilyOpen::jvm("JVM catalog closed")
            })?;
        memo.get_or_derive(|| self.derive_jvm_reader(activation))
    }
}

#[derive(Default)]
struct ReaderDerivationMemo {
    #[cfg(test)]
    fills: std::sync::atomic::AtomicUsize,
    value: Mutex<
        Option<(
            Result<RequestRowReader, FamilyOpen>,
            brokk_bifrost_analysis::analyzer::common::QueryCacheBuildReceipt,
        )>,
    >,
}

impl ReaderDerivationMemo {
    fn get_or_derive(
        &self,
        derive: impl FnOnce() -> Result<RequestRowReader, FamilyOpen>,
    ) -> Result<RequestRowReader, FamilyOpen> {
        // The slot mutex spans the fill: carried helper threads share one derivation.
        let mut slot = self.value.lock().expect("reader derivation poisoned");
        if let Some((result, receipt)) = slot.as_ref() {
            receipt.replay();
            return result.clone();
        }
        #[cfg(test)]
        self.fills.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let (result, receipt) =
            brokk_bifrost_analysis::analyzer::common::capture_current_query_cache_build(derive);
        // Keep resolved readers, incomplete/uncertified selections, missing productions,
        // conflicts, publication unavailable, stale and closed outcomes only. Never keep
        // cancellation, budget/deadline exhaustion, or store failures.
        let deterministic = result.as_ref().err().is_none_or(|open| {
            matches!(
                open.reason,
                "JVM selection incomplete"
                    | "JVM provider certificate conflict"
                    | "JVM provider publication unavailable"
                    | "JVM catalog unavailable"
                    | "JVM catalog stale"
                    | "JVM catalog closed"
                    | "JVM selection shards unavailable"
                    | "JVM production partially excluded"
                    | "curated JVM pack partially selected"
            )
        });
        if deterministic && receipt.request_memo_admissible() {
            *slot = Some((result.clone(), receipt));
        }
        result
    }
}

impl RequestResource for ReaderDerivationMemo {
    fn close(&self) {}
}

impl JvmRequestRowReaderSource {
    fn reader_entry_key(&self, activation: &ResolvedActiveSemanticModels) -> RequestEntryKey {
        RequestEntryKey::JvmReaderDerivation {
            activation: activation.active_model_set_hash().to_owned(),
            view: *activation
                .request_view_digest
                .get_or_init(|| view_digest(&request_owned_view(activation))),
            excluded: activation.excluded_shards.digest(),
            questions: *self.questions_digest.get_or_init(|| {
                let mut hash = CanonicalHasher::new(b"jvm-request-authority-questions-v1");
                for question in self.authority.questions() {
                    hash.field("question", &question.digest);
                }
                hash.finish()
            }),
            view_stamp: self.project.view_stamp(),
            generation: self.project.analysis_generation(),
        }
    }

    fn derive_jvm_reader(
        &self,
        activation: &ResolvedActiveSemanticModels,
    ) -> Result<RequestRowReader, FamilyOpen> {
        let result = (|| {
            let request = brokk_bifrost_analysis::analyzer::i_analyzer::current_outer_request()
                .ok_or(FamilyOpen::jvm("no request scope"))?;
            let cancellation =
                brokk_bifrost_analysis::analyzer::i_analyzer::current_query_cancellation()
                    .unwrap_or_default();
            let access = jvm_catalog_reader_for_request(
                self.authority.as_ref(),
                activation,
                Some(&request),
                Arc::clone(&self.project),
                &self.catalog,
                &self.store,
                // Analyzer stores are writable; P1 publishes the provider certificate.
                true,
                cancellation.clone(),
            );
            let handle = match access {
                Ok(JvmCatalogReaderAccess::Ready(handle)) => handle,
                Ok(JvmCatalogReaderAccess::SelectionIncomplete) => {
                    return Err(FamilyOpen::jvm("JVM selection incomplete"));
                }
                Ok(JvmCatalogReaderAccess::CertificateConflict) => {
                    return Err(FamilyOpen::jvm("JVM provider certificate conflict"));
                }
                Ok(JvmCatalogReaderAccess::ProviderPublicationUnavailable) => {
                    return Err(FamilyOpen::jvm("JVM provider publication unavailable"));
                }
                Ok(JvmCatalogReaderAccess::Unavailable(_)) => {
                    return Err(FamilyOpen::jvm("JVM catalog unavailable"));
                }
                Ok(JvmCatalogReaderAccess::Stale) => {
                    return Err(FamilyOpen::jvm("JVM catalog stale"));
                }
                Ok(JvmCatalogReaderAccess::Closed) => {
                    return Err(FamilyOpen::jvm("JVM catalog closed"));
                }
                Ok(JvmCatalogReaderAccess::Cancelled) => return Err(cancelled_open()),
                Err(error) => return Err(reader_failure_open(error)),
            };
            // A listing omission that could hide a manifest is not owned by any
            // declared dependency: a hidden manifest could add a candidate to
            // any name, or make a miss a hit. So every answer that reads the
            // selection carries it, positive or not, and none is Complete.
            for gap in handle.jvm_dependency_gaps().iter().filter(|gap| {
                matches!(
                    gap.cause,
                    JvmDependencyGapCause::ListingOmitted(_)
                        | JvmDependencyGapCause::MissingRevisionBuildAuthority
                )
            }) {
                brokk_bifrost_analysis::analyzer::i_analyzer::record_current_query_incomplete(
                    brokk_bifrost_analysis::analyzer::i_analyzer::QueryReadIncomplete::SemanticEvidenceUnavailable(
                        gap.message().into(),
                    ),
                );
            }
            let mut guard = handle.bindings.lock().expect("JVM bindings mutex poisoned");
            let bindings = &mut *guard;
            {
                let active = request_owned_view(activation);
                let rows = handle.membership().map_err(reader_failure_open)?;
                // Recorded failures have no expected row. Any unavailable row here
                // is unaccounted membership and must still refuse the whole family.
                if rows.iter().any(|row| {
                    row.status != PinnedCatalogStatus::Present || row.shard_key.is_none()
                }) {
                    return Err(FamilyOpen::jvm("JVM selection shards unavailable"));
                }
                let pinned_all = rows
                    .iter()
                    .map(|row| {
                        (
                            row.kind.shard_database(),
                            row.shard_key.expect("present row has a shard key"),
                        )
                    })
                    .collect::<std::collections::HashSet<_>>();
                // A rejection after activation takes effect at the next activation,
                // not per request; the activation's CuratedAuthority keeps the manifest expected until then.
                // Only rows outside active need exclusions, so an exclusion key never removes the active winner.
                if !active.is_subset(&pinned_all)
                    || rows.iter().any(|row| {
                        !active.contains(&(
                            row.kind.shard_database(),
                            row.shard_key.expect("present row has a shard key"),
                        )) && !row
                            .manifest_digest
                            .as_ref()
                            .zip(row.shard_id.as_ref())
                            .is_some_and(|(manifest, shard)| {
                                activation.excluded_shards.contains(manifest, shard)
                            })
                    })
                {
                    return Err(FamilyOpen::jvm("JVM selection shards unavailable"));
                }
                // Publication writes each generated production's whole projection,
                // without shard provenance, under its semantic digest, and store
                // resolution reads every provider that an active shard of any source
                // names by that digest. So an excluded generated shard is safe only
                // when no active shard names its provider; otherwise its declarations
                // would answer as complete.
                let active_providers = activation
                    .shards
                    .iter()
                    .map(|shard| shard.manifest.semantic_sha256.as_str())
                    .collect::<std::collections::HashSet<_>>();
                if rows.iter().any(|row| {
                    row.kind == CatalogPackSourceKind::Generated
                        && !active.contains(&(
                            row.kind.shard_database(),
                            row.shard_key.expect("present row has a shard key"),
                        ))
                        && active_providers.contains(
                            row.manifest
                                .as_ref()
                                .expect("present row has a manifest")
                                .semantic_sha256
                                .as_str(),
                        )
                }) {
                    return Err(FamilyOpen::jvm("JVM production partially excluded"));
                }
                if rows.iter().any(|row| {
                    matches!(
                        row.kind,
                        CatalogPackSourceKind::Installed
                            | CatalogPackSourceKind::PreShipped
                            | CatalogPackSourceKind::Embedded
                    ) && !active.contains(&(
                        row.kind.shard_database(),
                        row.shard_key.expect("present row has a shard key"),
                    )) && active_providers.contains(
                        row.manifest
                            .as_ref()
                            .expect("present row has a manifest")
                            .semantic_sha256
                            .as_str(),
                    )
                }) {
                    return Err(FamilyOpen::jvm("curated JVM pack partially selected"));
                }
                // The pinned reader loads every Present membership row into its active
                // view, including shards the activation excluded. Narrow the view to
                // the activation's shards so no read returns an excluded shard's rows.
                // Provider publication already ran on the full membership at open.
                // The reader key carries the view's digest, so every activation
                // bound to this handle asks for the same view.
                match &bindings.view {
                    Some(view) => assert_eq!(*view, active, "a JVM reader handle serves one view"),
                    None => {
                        handle
                            .reader
                            .restrict_active_shards(&active, &cancellation)
                            .map_err(|error| {
                                reader_failure_open(JvmCatalogReaderError::Reader(error))
                            })?;
                        bindings.view = Some(active);
                    }
                }
            }
            let binding = {
                let key = handle.key();
                let mut hash = CanonicalHasher::new(b"jvm-request-reader-binding-v1");
                for selection in [&key.dependencies, &key.jdk] {
                    hash.field("question", &selection.question_digest);
                    hash.field("has_view", &[u8::from(selection.view_stamp.is_some())]);
                    if let Some(stamp) = &selection.view_stamp {
                        stamp.hash_into(&mut hash);
                    }
                    hash.field("answer", &selection.answer_digest);
                }
                hash.field("curated", &key.curated);
                hash.field("view", &key.view);
                hash.field("rules", &key.rules);
                hash.field("generation", &key.generation.to_be_bytes());
                hash.field(
                    "active_models",
                    activation.active_model_set_hash().as_bytes(),
                );
                // Only certificates used by this request's bind participate.
                // The runtime generation guard below is not a persisted identity.
                let mut certificates = handle
                    .provider_certificates
                    .lock()
                    .expect("provider certificates poisoned")
                    .clone();
                let certified = handle.certified_providers();
                certificates.retain(|certificate| certified.contains(&certificate.provider_id));
                hash_provider_certificates(&mut hash, certificates);
                // ProjectViewStamp contains a process-local view ID. This binding is an
                // in-memory request key and never enters a persisted read receipt.
                ReaderBinding(hash.finish())
            };
            drop(guard);
            let selections = [&handle.key().dependencies, &handle.key().jdk];
            // A later run asks the authority again and compares its digest, so
            // the key names the authority's answer even when bind-time
            // PartialCoverage gaps changed what this request is bound to. The
            // gaps themselves are covered by `ReadKey::Models`.
            if selections.iter().all(|selection| selection.replayable) {
                use brokk_bifrost_analysis::analyzer::read_ledger::{
                    LookupKind, LookupQuestion, ReadKey,
                };
                for selection in selections {
                    brokk_bifrost_analysis::analyzer::i_analyzer::record_request_row_selection_read(
                        ReadKey::Lookup {
                            kind: LookupKind::ExternalSelection,
                            question: LookupQuestion::ExternalSelection {
                                question_digest: selection.question_digest,
                            },
                            digest: brokk_bifrost_analysis::analyzer::semantic::ids::StableDigest::from_array(selection.authority_answer_digest),
                        },
                    );
                }
            } else {
                // The request pinned this selection (one reader per request),
                // so its answers hold for the request but no later request can
                // verify them (#14322).
                brokk_bifrost_analysis::analyzer::i_analyzer::record_request_pinned_input();
            }
            let inventory_generation = self
                .store
                .jvm_external_certified_generation(
                    handle
                        .provider_certificates
                        .lock()
                        .expect("provider certificates poisoned")
                        .clone(),
                )
                .map_err(|error| reader_failure_open(store_failure(error)))?
                .ok_or_else(|| FamilyOpen::jvm("JVM provider publication unavailable"))?;
            Ok(RequestRowReader {
                derivation_extension: Default::default(),
                certified_providers: handle.certified_providers(),
                inventory_generation: Some(inventory_generation),
                inventory_clock: Some(
                    self.store
                        .jvm_inventory_publication_clock(inventory_generation),
                ),
                reader: handle,
                binding,
            })
        })();
        if let Err(open) = &result {
            brokk_bifrost_core::profiling::note_with(|| {
                format!("jvm_request_owner open reason={}", open.reason)
            });
            brokk_bifrost_analysis::analyzer::i_analyzer::refuse_request_row_read_reuse();
        }
        result
    }
}

pub const JVM_CATALOG_COMPOSITION_RULE: &[u8] = b"jvm-catalog-composition:v1";
pub const JVM_CATALOG_PRECEDENCE_RULE: &[u8] = b"jvm-catalog-precedence:v1";

/// Immutable activation authority, supplied before opening the catalog reader.
#[derive(Debug, Clone)]
pub struct CuratedAuthority {
    pub admitted_digest: [u8; 32],
    pub shards: Vec<CuratedShard>,
}

#[derive(Debug, Clone)]
pub struct CuratedShard {
    pub kind: CatalogPackSourceKind,
    pub manifest_digest: String,
    pub shard_id: String,
}

/// The activation's request-owned active shards: the pinned view a reader
/// handle narrows to, and the membership the bind checks.
fn request_owned_view(
    activation: &ResolvedActiveSemanticModels,
) -> std::collections::HashSet<(CatalogShardDatabase, i64)> {
    activation
        .shards
        .iter()
        .filter(|shard| {
            brokk_bifrost_analysis::analyzer::store::active_models::shard_owner_index(
                shard,
                None,
                Some(0),
            ) == Some(0)
        })
        .filter_map(|shard| shard.row_store.map(|row| (row.database, row.shard_key)))
        .collect()
}

fn view_digest(view: &std::collections::HashSet<(CatalogShardDatabase, i64)>) -> [u8; 32] {
    let mut shards = view
        .iter()
        .map(|(database, shard_key)| {
            let database = match database {
                CatalogShardDatabase::Durable => 0u8,
                CatalogShardDatabase::Session => 1u8,
            };
            (database, *shard_key)
        })
        .collect::<Vec<_>>();
    shards.sort_unstable();
    let mut hash = CanonicalHasher::new(b"jvm-catalog-reader-view-v1");
    for (database, shard_key) in shards {
        hash.field("database", &[database]);
        hash.field("shard_key", &shard_key.to_be_bytes());
    }
    hash.finish()
}

/// The Open answer of a cancelled JVM read, wherever the bind observes it.
fn cancelled_open() -> FamilyOpen {
    brokk_bifrost_analysis::analyzer::i_analyzer::record_request_row_read_cancelled();
    FamilyOpen::jvm_cancelled()
}

/// The Open answer of a reader failure, keeping its cause class.
fn reader_failure_open(error: JvmCatalogReaderError) -> FamilyOpen {
    match error {
        JvmCatalogReaderError::Open(reason) => FamilyOpen::jvm(reason),
        JvmCatalogReaderError::Store(error)
            if error.kind()
                == brokk_bifrost_analysis::analyzer::store::StoreErrorKind::NotWritable =>
        {
            FamilyOpen::jvm("analyzer store not writable")
        }
        JvmCatalogReaderError::Store(_) => FamilyOpen::jvm("analyzer store unavailable"),
        JvmCatalogReaderError::Reader(PinnedReaderError::Cancelled) => cancelled_open(),
        JvmCatalogReaderError::Closed
        | JvmCatalogReaderError::Reader(PinnedReaderError::Closed) => {
            FamilyOpen::jvm("JVM catalog closed")
        }
        error @ JvmCatalogReaderError::Reader(PinnedReaderError::Catalog(_)) => {
            brokk_bifrost_analysis::analyzer::i_analyzer::record_current_query_incomplete(
                brokk_bifrost_analysis::analyzer::i_analyzer::QueryReadIncomplete::SemanticEvidenceUnavailable(
                    format!("JVM catalog reader failed: {error:?}").into(),
                ),
            );
            FamilyOpen::jvm("JVM catalog reader failed")
        }
        JvmCatalogReaderError::Stale => FamilyOpen::jvm("JVM catalog stale"),
        JvmCatalogReaderError::InvalidProjection(_) => {
            FamilyOpen::jvm("JVM catalog reader invalidated")
        }
    }
}

#[derive(Debug)]
pub enum JvmCatalogReaderError {
    Open(&'static str),
    Closed,
    Stale,
    Reader(PinnedReaderError),
    InvalidProjection(String),
    Store(StoreError),
}

/// A store write stopped by cancellation is the request's cancellation, not a
/// store failure, so the request entry reports it as Cancelled.
fn store_failure(error: StoreError) -> JvmCatalogReaderError {
    match error.kind() {
        brokk_bifrost_analysis::analyzer::store::StoreErrorKind::Cancelled => {
            JvmCatalogReaderError::Reader(PinnedReaderError::Cancelled)
        }
        _ => JvmCatalogReaderError::Store(error),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderPublication {
    Certified,
    Unavailable,
    Conflict,
    Missing,
    Quarantined,
    Stale,
}

pub struct JvmCatalogReaderHandle {
    key: JvmCatalogReaderKey,
    project: Arc<dyn Project>,
    reader: PinnedCatalogReader,
    #[cfg(test)]
    projection_calls: std::sync::atomic::AtomicUsize,
    dependency_gaps: Vec<JvmDependencyGap>,
    provider_outcomes: Mutex<Option<Vec<(usize, ProviderPublication)>>>,
    provider_certificates: Mutex<Vec<JvmExternalCertificate>>,
    bindings: Mutex<HandleBindings>,
}

// Process-local identity: future persistence must also bind the engine build.
fn hash_provider_certificates(
    hash: &mut CanonicalHasher,
    mut certificates: Vec<JvmExternalCertificate>,
) {
    certificates.sort_unstable();
    for certificate in certificates {
        hash.field("provider", certificate.provider_id.as_bytes());
        hash.field("projection_identity", &certificate.projection_identity);
        hash.field("source_identity", certificate.source_identity.as_bytes());
        hash.field("projection_digest", &certificate.projection_digest);
    }
}

/// A handle serves one active view: the first bind narrows the pinned reader's
/// `active_catalog_*` views to its activation's request-owned shards, and a later
/// bind must request exactly that set. One request uses one activation.
#[derive(Default)]
struct HandleBindings {
    /// `None` until the first bind narrows the reader.
    view: Option<std::collections::HashSet<(CatalogShardDatabase, i64)>>,
}

impl JvmCatalogReaderHandle {
    pub fn provider_outcomes(&self) -> Option<Vec<(usize, ProviderPublication)>> {
        self.provider_outcomes
            .lock()
            .expect("provider outcomes poisoned")
            .clone()
    }

    pub fn certified_providers(&self) -> std::collections::HashSet<String> {
        let outcomes = self.provider_outcomes().unwrap_or_default();
        self.reader
            .membership
            .iter()
            .filter(|row| outcomes.contains(&(row.ordinal, ProviderPublication::Certified)))
            .filter_map(|row| {
                row.manifest
                    .as_ref()
                    .map(|manifest| jvm_external_provider_id(&manifest.semantic_sha256))
            })
            .collect()
    }

    pub fn key(&self) -> &JvmCatalogReaderKey {
        &self.key
    }

    fn retain_provider_certificate(&self, certificate: JvmExternalCertificate) {
        let mut certificates = self
            .provider_certificates
            .lock()
            .expect("provider certificates poisoned");
        certificates.retain(|old| old.provider_id != certificate.provider_id);
        certificates.push(certificate);
    }

    pub fn publish_providers(
        &self,
        store: &AnalyzerStore,
        cancellation: &CancellationToken,
    ) -> Result<Vec<(usize, ProviderPublication)>, JvmCatalogReaderError> {
        self.guard()?;
        self.projections()
            .publish_providers(store, cancellation, |certificate| {
                self.retain_provider_certificate(certificate);
            })
    }

    fn projections(&self) -> ProviderProjections<'_> {
        ProviderProjections {
            reader: &self.reader,
            #[cfg(test)]
            projection_calls: &self.projection_calls,
        }
    }

    pub fn provider_certificate_status(
        &self,
        store: &AnalyzerStore,
        cancellation: &CancellationToken,
    ) -> Result<Vec<(usize, ProviderPublication)>, JvmCatalogReaderError> {
        self.guard()?;
        self.projections().for_each_provider(
            store,
            cancellation,
            |certificate| self.retain_provider_certificate(certificate),
            |projection| {
                let (status, certificate) = store
                    .jvm_external_publication_status_with_certificate(projection)
                    .map_err(store_failure)?;
                Ok((
                    match status {
                        JvmExternalPublication::Available => ProviderPublication::Certified,
                        JvmExternalPublication::Unavailable => ProviderPublication::Unavailable,
                        JvmExternalPublication::Conflict => ProviderPublication::Conflict,
                    },
                    certificate,
                ))
            },
        )
    }

    pub fn external_projection(
        &self,
        membership: &PinnedCatalogRow,
        cancellation: &CancellationToken,
    ) -> Result<Option<JvmExternalProjection>, JvmCatalogReaderError> {
        self.guard()?;
        self.projections()
            .external_projection(membership, cancellation)
    }
    fn guard(&self) -> Result<(), JvmCatalogReaderError> {
        // The reader checks its own closed state under its connection lock.
        // Checking it first here preserves Closed precedence over stale views.
        if self.reader.is_closed() {
            return Err(JvmCatalogReaderError::Closed);
        }
        if self.project.analysis_generation() != self.key.generation
            || self.project.view_stamp() != self.key.dependencies.view_stamp
            || self.project.view_stamp() != self.key.jdk.view_stamp
        {
            return Err(JvmCatalogReaderError::Stale);
        }
        Ok(())
    }

    pub fn membership(&self) -> Result<Vec<PinnedCatalogRow>, JvmCatalogReaderError> {
        self.guard()?;
        Ok(self.reader.membership.clone())
    }

    /// Rows of one read, cancelled by the caller's own token.
    pub fn owned_rows(
        &self,
        statement: &str,
        bindings: impl Params,
        cancellation: &CancellationToken,
    ) -> Result<Vec<Vec<Value>>, JvmCatalogReaderError> {
        self.guard()?;
        self.reader
            .owned_rows(statement, bindings, cancellation)
            .map_err(|error| match error {
                PinnedReaderError::Closed => JvmCatalogReaderError::Closed,
                error => JvmCatalogReaderError::Reader(error),
            })
    }
}

// Both activation and request binding project the same pinned catalog rows.
struct ProviderProjections<'a> {
    reader: &'a PinnedCatalogReader,
    #[cfg(test)]
    projection_calls: &'a std::sync::atomic::AtomicUsize,
}
impl ProviderProjections<'_> {
    // A generated production owns one provider even when its manifest has several shards.
    // The pinned membership retains manifest shard order for the combined projection.
    fn for_each_provider(
        &self,
        store: &AnalyzerStore,
        cancellation: &CancellationToken,
        mut retain_certificate: impl FnMut(JvmExternalCertificate),
        mut visit: impl FnMut(
            JvmExternalProjection,
        ) -> Result<
            (ProviderPublication, Option<JvmExternalCertificate>),
            JvmCatalogReaderError,
        >,
    ) -> Result<Vec<(usize, ProviderPublication)>, JvmCatalogReaderError> {
        let providers = self
            .reader
            .membership
            .iter()
            .filter_map(|row| {
                row.manifest
                    .as_ref()
                    .map(|manifest| jvm_external_provider_id(&manifest.semantic_sha256))
            })
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let mut certificates = store
            .jvm_external_source_certificates(&providers)
            .map_err(store_failure)?
            .into_iter()
            .map(|certificate| {
                (
                    (
                        certificate.provider_id.clone(),
                        certificate.source_identity.clone(),
                    ),
                    certificate,
                )
            })
            .collect::<HashMap<_, _>>();
        let mut outcomes = Vec::new();
        let mut offset = 0;
        while offset < self.reader.membership.len() {
            if cancellation.is_cancelled() {
                return Err(JvmCatalogReaderError::Reader(PinnedReaderError::Cancelled));
            }
            let ordinal = self.reader.membership[offset].ordinal;
            let end = offset
                + self.reader.membership[offset..].partition_point(|row| row.ordinal == ordinal);
            let rows = &self.reader.membership[offset..end];
            offset = end;
            if rows[0].kind != CatalogPackSourceKind::Generated {
                continue;
            }
            let status = rows.iter().find_map(|row| match row.status {
                PinnedCatalogStatus::Present => None,
                PinnedCatalogStatus::Missing => Some(ProviderPublication::Missing),
                PinnedCatalogStatus::Quarantined => Some(ProviderPublication::Quarantined),
                PinnedCatalogStatus::Stale => Some(ProviderPublication::Stale),
            });
            if let Some(status) = status {
                outcomes.push((ordinal, status));
                continue;
            }
            let first = &rows[0];
            let manifest_digest = first
                .manifest_digest
                .as_ref()
                .expect("present manifest digest");
            let production_digest = first
                .production_digest
                .as_ref()
                .expect("generated production digest");
            let mut combined = JvmExternalProjection {
                semantic_sha256: first
                    .manifest
                    .as_ref()
                    .expect("present manifest")
                    .semantic_sha256
                    .clone(),
                provider_id: jvm_external_provider_id(
                    &first
                        .manifest
                        .as_ref()
                        .expect("present manifest")
                        .semantic_sha256,
                ),
                source_identity: format!("generated:{manifest_digest}:{production_digest}"),
                owners: Vec::new(),
                members: Vec::new(),
                supertypes: Vec::new(),
            };
            if let Some(certificate) = certificates
                .get(&(
                    combined.provider_id.clone(),
                    combined.source_identity.clone(),
                ))
                .cloned()
            {
                if std::env::var_os("BIFROST_TIMING").is_some() {
                    eprintln!(
                        "JVM projection certificate hit provider={} source={}",
                        combined.provider_id, combined.source_identity
                    );
                }
                retain_certificate(certificate);
                outcomes.push((ordinal, ProviderPublication::Certified));
                continue;
            }
            for row in rows {
                assert_eq!(row.manifest_digest.as_ref(), Some(manifest_digest));
                let shard = self
                    .external_projection(row, cancellation)?
                    .expect("present shard projects");
                assert_eq!(shard.provider_id, combined.provider_id);
                combined.owners.extend(shard.owners);
                combined.members.extend(shard.members);
                combined.supertypes.extend(shard.supertypes);
            }
            let (outcome, certificate) = visit(combined)?;
            if let Some(certificate) = certificate {
                // Later expectations can name this production again. Reuse the
                // certificate just published in this pass as well as batch hits.
                certificates.insert(
                    (
                        certificate.provider_id.clone(),
                        certificate.source_identity.clone(),
                    ),
                    certificate.clone(),
                );
                retain_certificate(certificate);
            }
            outcomes.push((ordinal, outcome));
        }
        // Curated registrations can name the same semantic provider more than once.
        // Project its declaration shards once, in the manifest's declared order.
        let mut providers = std::collections::HashSet::new();
        for first in &self.reader.membership {
            if !matches!(
                first.kind,
                CatalogPackSourceKind::Installed
                    | CatalogPackSourceKind::PreShipped
                    | CatalogPackSourceKind::Embedded
            ) {
                continue;
            }
            let Some(manifest) = &first.manifest else {
                continue;
            };
            if !manifest.shards.iter().any(|shard| shard.payload_kind == brokk_bifrost_analysis::analyzer::semantic_model::artifact::PayloadKind::DeclarationFacts) { continue; }
            if !providers.insert(manifest.semantic_sha256.clone()) {
                continue;
            }
            let mut combined = JvmExternalProjection {
                semantic_sha256: manifest.semantic_sha256.clone(),
                provider_id: jvm_external_provider_id(&manifest.semantic_sha256),
                source_identity: format!(
                    "{}:{}",
                    first.kind.as_str(),
                    first
                        .manifest_digest
                        .as_ref()
                        .expect("present manifest digest")
                ),
                owners: Vec::new(),
                members: Vec::new(),
                supertypes: Vec::new(),
            };
            let mut selected_rows = Vec::new();
            for descriptor in &manifest.shards {
                if descriptor.payload_kind != brokk_bifrost_analysis::analyzer::semantic_model::artifact::PayloadKind::DeclarationFacts { continue; }
                let Some(row) = self.reader.membership.iter().find(|row| {
                    matches!(
                        row.kind,
                        CatalogPackSourceKind::Installed
                            | CatalogPackSourceKind::PreShipped
                            | CatalogPackSourceKind::Embedded
                    ) && row
                        .manifest
                        .as_ref()
                        .is_some_and(|m| m.semantic_sha256 == manifest.semantic_sha256)
                        && row.shard_id.as_ref() == Some(&descriptor.shard_id)
                }) else {
                    return Err(JvmCatalogReaderError::Open(
                        "curated JVM pack partially selected",
                    ));
                };
                if row.status != PinnedCatalogStatus::Present {
                    return Err(JvmCatalogReaderError::Open(
                        "JVM selection shards unavailable",
                    ));
                }
                selected_rows.push(row);
            }
            let generated_outcome = self.reader.membership.iter().find_map(|row| {
                (row.kind == CatalogPackSourceKind::Generated
                    && row
                        .manifest
                        .as_ref()
                        .is_some_and(|m| m.semantic_sha256 == manifest.semantic_sha256))
                .then(|| {
                    outcomes
                        .iter()
                        .find(|(ordinal, _)| *ordinal == row.ordinal)
                        .map(|(_, outcome)| *outcome)
                })
                .flatten()
            });
            let outcome = match generated_outcome {
                Some(outcome) => outcome,
                None => {
                    if let Some(certificate) = certificates
                        .get(&(
                            combined.provider_id.clone(),
                            combined.source_identity.clone(),
                        ))
                        .cloned()
                    {
                        if std::env::var_os("BIFROST_TIMING").is_some() {
                            eprintln!(
                                "JVM projection certificate hit provider={} source={}",
                                combined.provider_id, combined.source_identity
                            );
                        }
                        retain_certificate(certificate);
                        ProviderPublication::Certified
                    } else {
                        for row in selected_rows {
                            let shard = self
                                .external_projection(row, cancellation)?
                                .expect("present shard projects");
                            combined.owners.extend(shard.owners);
                            combined.members.extend(shard.members);
                            combined.supertypes.extend(shard.supertypes);
                        }
                        let (outcome, certificate) = visit(combined)?;
                        if let Some(certificate) = certificate {
                            retain_certificate(certificate);
                        }
                        outcome
                    }
                }
            };
            for row in &self.reader.membership {
                if row
                    .manifest
                    .as_ref()
                    .is_some_and(|m| m.semantic_sha256 == manifest.semantic_sha256)
                {
                    outcomes.push((row.ordinal, outcome));
                }
            }
        }
        Ok(outcomes)
    }

    pub fn publish_providers(
        &self,
        store: &AnalyzerStore,
        cancellation: &CancellationToken,
        retain_certificate: impl FnMut(JvmExternalCertificate),
    ) -> Result<Vec<(usize, ProviderPublication)>, JvmCatalogReaderError> {
        self.for_each_provider(store, cancellation, retain_certificate, |projection| {
            let curated = self.reader.membership.iter().any(|row| {
                matches!(
                    row.kind,
                    CatalogPackSourceKind::Installed
                        | CatalogPackSourceKind::PreShipped
                        | CatalogPackSourceKind::Embedded
                ) && row
                    .manifest
                    .as_ref()
                    .is_some_and(|manifest| manifest.semantic_sha256 == projection.semantic_sha256)
            });
            let cancellation = cancellation.clone();
            let timing = std::env::var_os("BIFROST_TIMING").is_some();
            let started = std::time::Instant::now();
            let provider = projection.provider_id.clone();
            let owners = projection.owners.len();
            let members = projection.members.len();
            let (status, certificate) = store
                    .publish_jvm_external_projection_with_certificate(
                        || Ok(Some(projection)),
                        move || cancellation.is_cancelled(),
                    )
                    .map_err(|error| {
                        if curated && error.kind() == brokk_bifrost_analysis::analyzer::store::StoreErrorKind::NotWritable {
                            JvmCatalogReaderError::Open("curated JVM provider unpublished on a read-only store")
                        } else { store_failure(error) }
                    })?;
            let outcome = match status {
                    JvmExternalPublication::Available => ProviderPublication::Certified,
                    JvmExternalPublication::Unavailable => ProviderPublication::Unavailable,
                    JvmExternalPublication::Conflict => ProviderPublication::Conflict,
                };
            if timing {
                eprintln!("JVM projection publication provider={provider} owners={owners} members={members} outcome={outcome:?} elapsed_ms={:.1}", started.elapsed().as_secs_f64() * 1000.0);
            }
            Ok((outcome, certificate))
        })
    }

    /// Project exactly one present shard from the pinned pair of snapshots.
    pub fn external_projection(
        &self,
        membership: &PinnedCatalogRow,
        cancellation: &CancellationToken,
    ) -> Result<Option<JvmExternalProjection>, JvmCatalogReaderError> {
        #[cfg(test)]
        self.projection_calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if membership.status != PinnedCatalogStatus::Present {
            return Ok(None);
        }
        let manifest = membership
            .manifest
            .as_ref()
            .expect("present shard has manifest");
        let shard_key = membership.shard_key.expect("present shard has key");
        let shard_id = membership.shard_id.as_ref().expect("present shard has ID");
        let source_db = match membership.kind.shard_database() {
            CatalogShardDatabase::Session => "session",
            CatalogShardDatabase::Durable => "durable",
        };
        let read = |table: &str| -> Result<Vec<String>, JvmCatalogReaderError> {
            let statement = format!(
                "SELECT record_json FROM active_catalog_{table} WHERE source_db=?1 AND shard_key=?2 ORDER BY record_key"
            );
            self.reader
                .owned_rows(&statement, (source_db, shard_key), cancellation)
                .map_err(JvmCatalogReaderError::Reader)?
                .into_iter()
                .map(|row| match row.as_slice() {
                    [Value::Text(value)] => Ok(value.clone()),
                    _ => Err(JvmCatalogReaderError::InvalidProjection(
                        "catalog declaration record is not text".into(),
                    )),
                })
                .collect()
        };
        let types = read("declaration_types")?
            .into_iter()
            .map(|json| {
                serde_json::from_str::<TypeFact>(&json)
                    .map_err(|error| JvmCatalogReaderError::InvalidProjection(error.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let members = read("declaration_members")?
            .into_iter()
            .map(|json| {
                serde_json::from_str::<MemberFact>(&json)
                    .map_err(|error| JvmCatalogReaderError::InvalidProjection(error.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let source_identity = format!(
            "{}:{}:{}",
            membership.kind.as_str(),
            membership
                .manifest_digest
                .as_ref()
                .expect("present shard has digest"),
            shard_id
        );
        Ok(Some(
            jvm_external_projection(
                manifest.semantic_sha256.clone(),
                source_identity,
                types.iter().filter(|owner| owner.guard.is_none()),
                members.iter(),
                manifest.completeness == Completeness::Complete,
            )
            .map_err(|error| JvmCatalogReaderError::InvalidProjection(error.to_string()))?,
        ))
    }
}

impl CatalogRowReader for JvmCatalogReaderHandle {
    fn jvm_dependency_gaps(&self) -> &[JvmDependencyGap] {
        &self.dependency_gaps
    }

    fn owned_rows(
        &self,
        statement: &str,
        bindings: &[(&str, &dyn rusqlite::ToSql)],
        cancellation: &CancellationToken,
    ) -> Result<OwnedCatalogRows, CatalogError> {
        self.guard().map_err(|_| {
            brokk_bifrost_core::profiling::note_with(|| {
                "jvm_request_owner open reason=invalidated".to_owned()
            });
            CatalogError::FamilyOpen(FamilyOpen::jvm("JVM catalog reader invalidated"))
        })?;
        // Catalog row questions pass no token of their own. A read through the
        // request owner stops when the operation running it is cancelled: the
        // query context's token (searched through enclosing scopes), never
        // another caller's, and an explicit token that is already cancelled.
        if cancellation.is_cancelled() {
            brokk_bifrost_core::profiling::note_with(|| {
                "jvm_request_owner open reason=cancelled".to_owned()
            });
            brokk_bifrost_analysis::analyzer::i_analyzer::record_request_row_read_cancelled();
            return Err(CatalogError::Cancelled);
        }
        let current = brokk_bifrost_analysis::analyzer::i_analyzer::current_query_cancellation();
        let combined = current
            .as_ref()
            .map(|operation| cancellation.combined_with(operation));
        self.reader
            .owned_named_rows(
                statement,
                bindings,
                combined.as_ref().unwrap_or(cancellation),
            )
            .map_err(|error| match error {
                PinnedReaderError::Catalog(CatalogError::Unavailable) => {
                    brokk_bifrost_core::profiling::note_with(|| {
                        "jvm_request_owner open reason=unavailable".to_owned()
                    });
                    CatalogError::FamilyOpen(FamilyOpen::jvm("JVM catalog busy"))
                }
                PinnedReaderError::Catalog(CatalogError::Sqlite { ref source, .. })
                    if matches!(
                        source.sqlite_error_code(),
                        Some(
                            rusqlite::ErrorCode::DatabaseBusy
                                | rusqlite::ErrorCode::DatabaseLocked
                                | rusqlite::ErrorCode::FileLockingProtocolFailed
                        )
                    ) =>
                {
                    brokk_bifrost_core::profiling::note_with(|| {
                        "jvm_request_owner open reason=busy".to_owned()
                    });
                    CatalogError::FamilyOpen(FamilyOpen::jvm("JVM catalog busy"))
                }
                PinnedReaderError::Catalog(error) => error,
                PinnedReaderError::Cancelled => {
                    brokk_bifrost_core::profiling::note_with(|| {
                        "jvm_request_owner open reason=cancelled".to_owned()
                    });
                    brokk_bifrost_analysis::analyzer::i_analyzer::record_request_row_read_cancelled(
                    );
                    CatalogError::Cancelled
                }
                // A request that closes between the guard and the read leaves
                // the JVM part open, like a guard failure.
                PinnedReaderError::Closed => {
                    brokk_bifrost_core::profiling::note_with(|| {
                        "jvm_request_owner open reason=invalidated".to_owned()
                    });
                    CatalogError::FamilyOpen(FamilyOpen::jvm("JVM catalog reader invalidated"))
                }
            })
    }
}

impl RequestResource for JvmCatalogReaderHandle {
    fn close(&self) {
        match self.reader.close() {
            Ok(()) | Err(PinnedReaderError::Closed) => {}
            Err(error) => panic!("closing request-owned JVM catalog reader: {error:?}"),
        }
    }
}

#[allow(clippy::too_many_arguments)] // The admitted inputs are independently owned authorities.
pub fn open_jvm_catalog_reader(
    request: &OuterRequest,
    project: Arc<dyn Project>,
    catalog: &PinnedCatalogSource,
    dependencies: &VerifiedSelection,
    jdk: &VerifiedSelection,
    jdk_expectations: Vec<ExpectedCatalogEntry>,
    curated: CuratedAuthority,
    view: [u8; 32],
    cancellation: CancellationToken,
) -> Result<Arc<JvmCatalogReaderHandle>, RequestResourceError<PinnedReaderError>> {
    let admitted = |selection: &VerifiedSelection| AdmittedSelection {
        certified: selection.certified,
        complete: selection.complete,
        replayable: selection.replayable(),
        question_digest: selection.question_digest,
        view_stamp: selection.view_stamp.clone(),
        answer_digest: selection.answer_digest,
        authority_answer_digest: selection.answer_digest,
    };
    // Only the dependency selection has gaps folded in at bind.
    let admitted_dependencies = {
        let mut admitted = admitted(dependencies);
        let inventory = dependencies
            .records
            .downcast_ref::<Option<ExternalInventorySelection>>()
            .expect("JVM dependency selection contains its typed inventory");
        if let Some(authority) = inventory
            .as_ref()
            .and_then(|inventory| inventory.authority_answer_digest)
        {
            admitted.authority_answer_digest = authority;
        }
        admitted
    };
    let mut rules = CanonicalHasher::new(b"bifrost-jvm-catalog-reader-rules:v1");
    rules.field("composition", JVM_CATALOG_COMPOSITION_RULE);
    rules.field("precedence", JVM_CATALOG_PRECEDENCE_RULE);
    let key = JvmCatalogReaderKey {
        dependencies: admitted_dependencies,
        jdk: admitted(jdk),
        curated: curated.admitted_digest,
        view,
        rules: rules.finish(),
        generation: project.analysis_generation(),
    };
    request.resource(RequestEntryKey::JvmCatalogReader(key.clone()), || {
        let inventory = dependencies
            .records
            .downcast_ref::<Option<ExternalInventorySelection>>()
            .expect("JVM dependency selection contains its typed inventory");
        let mut expected = inventory
            .as_ref()
            .expect("failed dependency capture checked before opening the reader")
            .catalog_expectations();
        expected.extend(jdk_expectations);
        expected.extend(
            curated
                .shards
                .into_iter()
                .map(|shard| ExpectedCatalogEntry::Shard {
                    kind: shard.kind,
                    manifest_digest: shard.manifest_digest,
                    shard_id: shard.shard_id,
                }),
        );
        let reader = catalog.pinned_jvm_reader(&expected, cancellation)?;
        Ok(Arc::new(JvmCatalogReaderHandle {
            key,
            project,
            reader,
            #[cfg(test)]
            projection_calls: std::sync::atomic::AtomicUsize::new(0),
            dependency_gaps: if dependencies.complete {
                Vec::new()
            } else {
                inventory
                    .as_ref()
                    .unwrap()
                    .completeness
                    .only_gaps()
                    .unwrap_or_default()
            },
            provider_outcomes: Mutex::new(None),
            provider_certificates: Mutex::default(),
            bindings: Mutex::new(HandleBindings::default()),
        }))
    })
}

pub(crate) fn jvm_preparation_failures(
    activation: &ResolvedActiveSemanticModels,
) -> Vec<brokk_bifrost_semantic::analyzer::semantic_model::dependency::RecordedPreparationFailure> {
    activation
        .preparation_failures
        .iter()
        .filter(|failure| {
            matches!(
                failure.dependency.evidence.language.as_str(),
                "java" | "kotlin" | "scala"
            )
        })
        .cloned()
        .collect()
}

fn activation_view_digest(activation: &ResolvedActiveSemanticModels) -> [u8; 32] {
    let mut view_hash = CanonicalHasher::new(b"jvm-activation-failure-view-v1");
    view_hash.field("view", &view_digest(&request_owned_view(activation)));
    view_hash.field(
        "preparation_failures",
        &brokk_bifrost_semantic::analyzer::semantic_model::dependency::preparation_failures_digest(
            &jvm_preparation_failures(activation),
        ),
    );
    view_hash.finish()
}

/// Typed result of asking an activation for its request-owned JVM reader.
pub enum JvmCatalogReaderAccess {
    Ready(Arc<JvmCatalogReaderHandle>),
    Unavailable(String),
    SelectionIncomplete,
    CertificateConflict,
    ProviderPublicationUnavailable,
    Stale,
    Closed,
    Cancelled,
}

/// Lazily open and bind the JVM catalog reader on the first request need.
#[allow(clippy::too_many_arguments)]
pub fn jvm_catalog_reader_for_request(
    authority: &dyn ExternalSelectionAuthority,
    activation: &ResolvedActiveSemanticModels,
    request: Option<&OuterRequest>,
    project: Arc<dyn Project>,
    catalog: &PinnedCatalogSource,
    store: &AnalyzerStore,
    store_writable: bool,
    cancellation: CancellationToken,
) -> Result<JvmCatalogReaderAccess, JvmCatalogReaderError> {
    let Some(request) = request else {
        return Ok(JvmCatalogReaderAccess::Unavailable("no query scope".into()));
    };
    if request.is_closed() {
        return Ok(JvmCatalogReaderAccess::Closed);
    }
    if cancellation.is_cancelled() {
        return Ok(JvmCatalogReaderAccess::Cancelled);
    }
    for failure in &jvm_preparation_failures(activation) {
        // Staleness verifies what a record observed. An unbound record has no
        // inputs, so there is nothing to verify and it is not stale. It never
        // replays: carry refuses while any failure exists, and a
        // PreparationFailure gap is excluded from replay (#9559 3d).
        if failure.inputs.changed_since_binding() {
            return Ok(JvmCatalogReaderAccess::Stale);
        }
    }
    let activation_id = activation.active_model_set_hash();
    let view = activation_view_digest(activation);
    if let Some(key) = request.jvm_catalog_binding(activation_id, view) {
        return match request.resource::<JvmCatalogReaderHandle, PinnedReaderError>(
            RequestEntryKey::JvmCatalogReader(key),
            || unreachable!("bound JVM reader is already open"),
        ) {
            Ok(handle) => match handle.guard() {
                Ok(()) => Ok(JvmCatalogReaderAccess::Ready(handle)),
                Err(JvmCatalogReaderError::Closed) => Ok(JvmCatalogReaderAccess::Closed),
                Err(JvmCatalogReaderError::Stale) => Ok(JvmCatalogReaderAccess::Stale),
                Err(error) => Err(error),
            },
            Err(RequestResourceError::Closed) => Ok(JvmCatalogReaderAccess::Closed),
            Err(RequestResourceError::Open(error)) => Err(JvmCatalogReaderError::Reader(error)),
        };
    }
    let questions = authority.questions();
    let Some(dependency_question) = questions
        .iter()
        .find(|q| q.kind == ExternalSelectionQuestionKind::Dependencies)
    else {
        return Ok(JvmCatalogReaderAccess::Unavailable(
            "dependency selection question missing".into(),
        ));
    };
    let Some(jdk_question) = questions
        .iter()
        .find(|q| q.kind == ExternalSelectionQuestionKind::Jdk)
    else {
        return Ok(JvmCatalogReaderAccess::Unavailable(
            "JDK selection question missing".into(),
        ));
    };
    let retry = SelectionRetry::default();
    let dependencies = match authority.answer(request, dependency_question, &retry, &cancellation) {
        Ok(selection) => selection,
        Err(brokk_bifrost_core::analyzer::external_selection::SelectionRefused::Cancelled) => {
            return Ok(JvmCatalogReaderAccess::Cancelled);
        }
        Err(_) => return Ok(JvmCatalogReaderAccess::Stale),
    };
    let preparation_failures = jvm_preparation_failures(activation);
    let gaps = brokk_bifrost_analysis::analyzer::semantic_model::overlay::dependency_gaps(
        &preparation_failures,
        activation,
    );
    let dependencies =
        if gaps.is_empty() {
            dependencies
        } else {
            let mut inventory = dependencies
                .records
                .downcast_ref::<Option<ExternalInventorySelection>>()
                .expect("typed JVM dependency selection")
                .clone();
            let Some(selection) = &mut inventory else {
                return Ok(JvmCatalogReaderAccess::SelectionIncomplete);
            };
            selection.completeness.record(
                super::external::ExternalSelectionFailure::DependencyGaps(gaps),
            );
            selection.preparation_failures = preparation_failures;
            selection.authority_answer_digest = Some(dependencies.answer_digest);
            // `verified` stays the authority's provenance. The folded selection is
            // replayable only when every gap, the authority's and the folded ones,
            // is fixed for unchanged inputs: a pack's partial coverage or an
            // unresolved coordinate. Any other gap, such as a preparation failure
            // that may succeed next time, makes the answer unreplayable. No case
            // makes the selection complete or certified: absence is not provable.
            let only_replayable_gaps = selection.completeness.only_replayable_gaps();
            Arc::new(VerifiedSelection {
                answer_digest: selection.answer_digest(false, false),
                records: Arc::new(inventory),
                question_digest: dependencies.question_digest,
                view_stamp: dependencies.view_stamp.clone(),
                verified: dependencies.verified,
                complete: false,
                certified: false,
                only_replayable_gaps,
            })
        };
    let inventory = dependencies
        .records
        .downcast_ref::<Option<ExternalInventorySelection>>()
        .expect("JVM dependency selection contains its typed inventory");
    // #10470 M2 and #9559: admit dependency-scoped gaps; other failures refuse binding.
    if !dependencies.complete
        && !inventory
            .as_ref()
            .is_some_and(|selection| selection.completeness.only_gaps().is_some())
    {
        return Ok(JvmCatalogReaderAccess::SelectionIncomplete);
    }
    if inventory.is_none() {
        return Ok(JvmCatalogReaderAccess::Unavailable(
            "JVM dependency inventory capture failed".into(),
        ));
    }
    let jdk = match authority.answer(request, jdk_question, &retry, &cancellation) {
        Ok(selection) => selection,
        Err(brokk_bifrost_core::analyzer::external_selection::SelectionRefused::Cancelled) => {
            return Ok(JvmCatalogReaderAccess::Cancelled);
        }
        Err(_) => return Ok(JvmCatalogReaderAccess::Stale),
    };
    if !jdk.complete {
        return Ok(JvmCatalogReaderAccess::SelectionIncomplete);
    }
    // PartialCoverage leaves the installed inventory readable. Only gaps for
    // unavailable dependencies require the stronger JDK certification boundary.
    let partial_coverage_only = inventory
        .as_ref()
        .is_some_and(|selection| selection.completeness.only_partial_coverage());
    if !dependencies.complete && !jdk.certified && !partial_coverage_only {
        return Ok(JvmCatalogReaderAccess::SelectionIncomplete);
    }
    let selected_jdk = jdk
        .records
        .downcast_ref::<SelectedJdk>()
        .expect("JVM JDK selection contains its typed inventory");
    // The reader pins exactly the curated shards it owns, by the same predicate
    // that `JvmRequestRowReaderSource::jvm_reader` uses for the activation side
    // of its membership check, so a shard the activation keeps (non-JVM, or a
    // generator-rule shard) never makes the two sets differ.
    let curated = CuratedAuthority {
        admitted_digest: activation.indexes.admission().curated,
        shards: activation
            .shards
            .iter()
            .filter(|shard| {
                shard.request_owned()
                    && matches!(
                        shard.source_kind,
                        CatalogPackSourceKind::Installed
                            | CatalogPackSourceKind::PreShipped
                            | CatalogPackSourceKind::Embedded
                    )
            })
            .map(|shard| CuratedShard {
                kind: shard.source_kind,
                manifest_digest: shard.manifest.content_sha256.clone(),
                shard_id: shard.descriptor.shard_id.clone(),
            })
            .collect(),
    };
    let handle = match open_jvm_catalog_reader(
        request,
        project,
        catalog,
        &dependencies,
        &jdk,
        selected_jdk.catalog_expectations(),
        curated,
        view,
        cancellation.clone(),
    ) {
        Ok(handle) => handle,
        Err(
            RequestResourceError::Closed | RequestResourceError::Open(PinnedReaderError::Closed),
        ) => return Ok(JvmCatalogReaderAccess::Closed),
        Err(RequestResourceError::Open(PinnedReaderError::Cancelled)) => {
            return Ok(JvmCatalogReaderAccess::Cancelled);
        }
        Err(RequestResourceError::Open(error)) => return Err(JvmCatalogReaderError::Reader(error)),
    };
    {
        let mut outcomes = handle
            .provider_outcomes
            .lock()
            .expect("provider outcomes poisoned");
        if outcomes.is_none() {
            let publication = if store_writable {
                handle.publish_providers(store, &cancellation)
            } else {
                handle.provider_certificate_status(store, &cancellation)
            };
            *outcomes = Some(match publication {
                Ok(outcomes) => outcomes,
                Err(JvmCatalogReaderError::Reader(PinnedReaderError::Cancelled)) => {
                    return Ok(JvmCatalogReaderAccess::Cancelled);
                }
                Err(JvmCatalogReaderError::Closed) => return Ok(JvmCatalogReaderAccess::Closed),
                Err(JvmCatalogReaderError::Stale) => return Ok(JvmCatalogReaderAccess::Stale),
                Err(error) => return Err(error),
            });
        }
        if !store_writable
            && outcomes
                .as_ref()
                .expect("initialized outcomes")
                .iter()
                .any(|(ordinal, outcome)| {
                    *outcome != ProviderPublication::Certified
                        && handle.reader.membership.iter().any(|row| {
                            row.ordinal == *ordinal
                                && matches!(
                                    row.kind,
                                    CatalogPackSourceKind::Installed
                                        | CatalogPackSourceKind::PreShipped
                                        | CatalogPackSourceKind::Embedded
                                )
                        })
                })
        {
            brokk_bifrost_core::profiling::note_with(|| {
                "jvm_request_owner open reason=curated JVM provider unpublished on a read-only store".into()
            });
            return Err(JvmCatalogReaderError::Open(
                "curated JVM provider unpublished on a read-only store",
            ));
        }
        if outcomes
            .as_ref()
            .expect("provider outcomes initialized")
            .iter()
            .any(|(_, outcome)| *outcome == ProviderPublication::Conflict)
        {
            return Ok(JvmCatalogReaderAccess::CertificateConflict);
        }
        // A writable store answers Unavailable only when the projection
        // callback yields none, which the catalog's never does, so this
        // refuses a fault rather than a routine outcome. Consumers of the
        // projected inventory do not check certificates.
        if outcomes
            .as_ref()
            .expect("provider outcomes initialized")
            .iter()
            .any(|(_, outcome)| *outcome == ProviderPublication::Unavailable)
        {
            return Ok(JvmCatalogReaderAccess::ProviderPublicationUnavailable);
        }
    }
    if request.is_closed() {
        return Ok(JvmCatalogReaderAccess::Closed);
    }
    if cancellation.is_cancelled() {
        return Ok(JvmCatalogReaderAccess::Cancelled);
    }
    match handle.guard() {
        Ok(()) => {}
        Err(JvmCatalogReaderError::Closed) => return Ok(JvmCatalogReaderAccess::Closed),
        Err(JvmCatalogReaderError::Stale) => return Ok(JvmCatalogReaderAccess::Stale),
        Err(error) => return Err(error),
    }
    request.bind_jvm_catalog(activation_id.to_owned(), view, handle.key().clone());
    if request.is_closed() {
        return Ok(JvmCatalogReaderAccess::Closed);
    }
    Ok(JvmCatalogReaderAccess::Ready(handle))
}

#[cfg(test)]
mod tests {
    // Simulate another binary's certificate while retaining its own inventory.
    fn rewrite_test_certificates(store: &super::AnalyzerStore, change: &str) {
        let change = change.to_owned();
        store.conn.execute(move |conn| -> brokk_bifrost_analysis::analyzer::store::Result<()> {
            let tx = conn.transaction()?;
            let writes: i64 = tx.query_row("SELECT count FROM publication_writes", [], |row| row.get(0))?;
            tx.execute_batch("CREATE TEMP TABLE stale_certificate AS SELECT *,provider_id AS old_id FROM jvm_external_provider_publications;
                CREATE TEMP TABLE saved_owners AS SELECT * FROM jvm_external_owners;
                CREATE TEMP TABLE saved_members AS SELECT * FROM jvm_external_owner_members;
                CREATE TEMP TABLE saved_supertypes AS SELECT * FROM jvm_external_owner_supertypes;
                DELETE FROM jvm_external_provider_publications;")?;
            tx.execute_batch(&change)?;
            let identities = tx.prepare("SELECT semantic_sha256,projection_identity FROM stale_certificate")?.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, [u8;32]>(1)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
            for (artifact, identity) in identities {
                tx.execute("UPDATE stale_certificate SET provider_id=?1 WHERE semantic_sha256=?2 AND projection_identity=?3", rusqlite::params![brokk_bifrost_analysis::analyzer::store::jvm_external_publication::jvm_external_provider_id_for_identity(&artifact, &identity), artifact, identity])?;
            }
            for table in ["saved_owners", "saved_members", "saved_supertypes"] {
                tx.execute_batch(&format!("UPDATE {table} SET provider_id=(SELECT provider_id FROM stale_certificate WHERE old_id={table}.provider_id)"))?;
            }
            tx.execute_batch("INSERT INTO jvm_external_owners SELECT * FROM saved_owners;
                INSERT INTO jvm_external_owner_members SELECT * FROM saved_members;
                INSERT INTO jvm_external_owner_supertypes SELECT * FROM saved_supertypes;
                INSERT INTO jvm_external_provider_publications(publication_sequence,provider_id,semantic_sha256,source_identity,publication_state,projection_identity,projected_rows_sha256,owner_count,member_count,supertype_count)
                    SELECT publication_sequence,provider_id,semantic_sha256,source_identity,publication_state,projection_identity,projected_rows_sha256,owner_count,member_count,supertype_count FROM stale_certificate;
                DROP TABLE saved_owners; DROP TABLE saved_members; DROP TABLE saved_supertypes; DROP TABLE stale_certificate;")?;
            tx.execute("UPDATE publication_writes SET count=?1", [writes])?;
            tx.commit()?;
            Ok(())
        }).unwrap();
    }

    fn fixture_producer_version(version: &str) -> String {
        brokk_bifrost_analysis::analyzer::semantic_model::Producer {
            name: "artifact-scanner".into(),
            version: version.into(),
        }
        .with_dependency_revision()
        .version
    }
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#9559: JVM reader derivation repeated within one request"
    )]
    fn request_reader_memo_single_flight_and_receipt_replay() {
        use super::*;
        use brokk_bifrost_analysis::analyzer::read_ledger::{
            LookupKind, LookupQuestion, ReadKey, ReadLedger,
        };
        use brokk_bifrost_analysis::analyzer::read_verification::{
            ChangedFacts, HeadInputs, LookupMemo, LookupReplayLimits, NoSummaryAnswers,
            verify_read_set,
        };
        use brokk_bifrost_analysis::analyzer::semantic::ids::StableDigest;
        use brokk_bifrost_analysis::analyzer::{AnalyzerDelegate, WorkspaceAnalyzer};
        use brokk_bifrost_analysis::analyzer::{AnalyzerQueryScope, MultiAnalyzer};
        use std::sync::atomic::{AtomicUsize, Ordering};
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("pom.xml"), "<project><modelVersion>4.0.0</modelVersion><groupId>memo</groupId><artifactId>memo</artifactId><version>1</version></project>").unwrap();
        let project: Arc<dyn Project> = Arc::new(
            brokk_bifrost_core::analyzer::project::FilesystemProject::new(root.path()).unwrap(),
        );
        let head = WorkspaceAnalyzer::Multi(Box::new(MultiAnalyzer::new(
            std::collections::BTreeMap::from([(
                Language::Java,
                AnalyzerDelegate::new(crate::analyzer::java::JavaAnalyzer::new(project)),
            )]),
        )));
        let analyzer = head.analyzer();
        let authorities = analyzer.external_selection_authorities();
        let authority = authorities.first().expect("Java selection authority");
        let question = authority
            .questions()
            .into_iter()
            .find(|question| question.kind == ExternalSelectionQuestionKind::Dependencies)
            .unwrap();
        let answer = authority
            .answer(
                &OuterRequest::new(),
                &question,
                &SelectionRetry::default(),
                &CancellationToken::new(),
            )
            .unwrap();
        assert!(answer.complete && answer.certified, "{answer:?}");
        let _scope = AnalyzerQueryScope::with_outer_request(analyzer, OuterRequest::new());
        let memo = ReaderDerivationMemo::default();
        let fills = AtomicUsize::new(0);
        let key = ReadKey::Lookup {
            kind: LookupKind::ExternalSelection,
            question: LookupQuestion::ExternalSelection {
                question_digest: question.digest,
            },
            digest: StableDigest::from_array(answer.answer_digest),
        };
        let carried = brokk_bifrost_core::analyzer::carried_context::CarriedContext::current();
        std::thread::scope(|threads| {
            for _ in 0..8 {
                threads.spawn(|| carried.run(|| {
                    assert!(memo.get_or_derive(|| {
                        fills.fetch_add(1, Ordering::SeqCst);
                        brokk_bifrost_analysis::analyzer::i_analyzer::record_request_row_selection_read(key.clone());
                        Err(FamilyOpen::jvm("JVM selection incomplete"))
                    }).is_err());
                }));
            }
        });
        assert_eq!(fills.load(Ordering::SeqCst), 1);
        let ledger = Arc::new(ReadLedger::new());
        {
            let _capture = AnalyzerQueryScope::with_read_ledger(analyzer, Arc::clone(&ledger));
            assert!(
                memo.get_or_derive(|| panic!("memo hit must replay"))
                    .is_err()
            );
        }
        assert!(ledger.keys().contains(&key));
        let changed = ReadKey::Lookup {
            kind: LookupKind::ExternalSelection,
            question: LookupQuestion::ExternalSelection {
                question_digest: question.digest,
            },
            digest: StableDigest::from_array([9; 32]),
        };
        let zero = StableDigest::from_array([0; 32]);
        let inputs = HeadInputs {
            models: zero,
            policy_semantic_hash: zero,
            policy_source: zero,
            configuration: zero,
            epoch: zero,
        };
        let verify = |keys: &[ReadKey]| {
            verify_read_set(
                &head,
                &ChangedFacts::without_base(),
                &inputs,
                keys,
                LookupReplayLimits::default(),
                &NoSummaryAnswers,
                &mut LookupMemo::new(),
            )
        };
        assert!(verify(&ledger.keys()).is_unchanged());
        assert!(
            !verify(&[changed]).is_unchanged(),
            "perturbed selection must invalidate the captured product"
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#9559: transient reader derivations must not be retained"
    )]
    fn request_reader_memo_retries_cancelled_and_budget_exhausted_fill() {
        use super::*;
        use brokk_bifrost_analysis::analyzer::{AnalyzerQueryScope, MultiAnalyzer};
        let analyzer = MultiAnalyzer::default();
        let _scope = AnalyzerQueryScope::with_outer_request(&analyzer, OuterRequest::new());
        struct UnusedRows;
        impl CatalogRowReader for UnusedRows {
            fn owned_rows(
                &self,
                _: &str,
                _: &[(&str, &dyn rusqlite::ToSql)],
                _: &CancellationToken,
            ) -> Result<OwnedCatalogRows, CatalogError> {
                unimplemented!("the pin only opens the reader")
            }
        }
        let success = || {
            Ok(RequestRowReader {
                derivation_extension: Default::default(),
                reader: Arc::new(UnusedRows),
                certified_providers: Default::default(),
                inventory_generation: None,
                inventory_clock: None,
                binding: ReaderBinding([0; 32]),
            })
        };
        let memo = ReaderDerivationMemo::default();
        assert!(memo.get_or_derive(|| Err(cancelled_open())).is_err());
        assert!(memo.value.lock().unwrap().is_none());
        assert!(
            memo.get_or_derive(|| {
                use brokk_bifrost_analysis::analyzer::semantic::{SemanticBudget, SemanticWork};
                let mut limits = SemanticBudget::default().limits();
                limits.nested_entries = 1;
                let budget = SemanticBudget::new(limits).unwrap();
                assert!(
                    budget
                        .check_admission(SemanticWork {
                            nested_entries: 2,
                            ..Default::default()
                        })
                        .is_err()
                );
                Err(FamilyOpen::jvm("JVM selection incomplete"))
            })
            .is_err()
        );
        assert!(memo.value.lock().unwrap().is_none());
        assert!(memo.get_or_derive(success).is_ok());
        assert!(memo.value.lock().unwrap().is_some());
    }

    #[test]
    fn certificate_identity_is_order_independent_and_complete() {
        use super::*;
        let certificate = JvmExternalCertificate {
            provider_id: "provider".into(),
            projection_identity: [1; 32],
            source_identity: "source".into(),
            projection_digest: vec![1; 32],
        };
        let binding = |certificates| {
            let mut hash = CanonicalHasher::new(b"test-request-binding");
            hash_provider_certificates(&mut hash, certificates);
            ReaderBinding(hash.finish())
        };
        let original = binding(vec![certificate.clone()]);
        assert_eq!(original, binding(vec![certificate.clone()]));
        for changed in [
            JvmExternalCertificate {
                provider_id: "other".into(),
                ..certificate.clone()
            },
            JvmExternalCertificate {
                projection_identity: [2; 32],
                ..certificate.clone()
            },
            JvmExternalCertificate {
                source_identity: "other".into(),
                ..certificate.clone()
            },
            JvmExternalCertificate {
                projection_digest: vec![2; 32],
                ..certificate.clone()
            },
        ] {
            assert_ne!(original, binding(vec![changed.clone()]));
            assert_eq!(
                binding(vec![certificate.clone(), changed.clone()]),
                binding(vec![changed, certificate.clone()])
            );
        }
        assert_ne!(original, binding(Vec::new()));
    }

    use super::*;

    /// A configuration that reads no host JDK: fixture catalogs hold no shard
    /// for whatever JDK `JAVA_HOME` or `java` on `PATH` names on the test host.
    fn hermetic_analyzer_config() -> brokk_bifrost_core::analyzer::config::AnalyzerConfig {
        brokk_bifrost_core::analyzer::config::AnalyzerConfig {
            jvm: hermetic_jvm_config(),
            ..Default::default()
        }
    }

    fn hermetic_jvm_config() -> JvmAnalyzerConfig {
        let mut config = JvmAnalyzerConfig::default();
        config.standard_library_discovery.discover_java_home = false;
        config
    }
    use brokk_bifrost_analysis::analyzer::i_analyzer::{AnalyzerQueryScope, IAnalyzer};
    use brokk_bifrost_analysis::analyzer::semantic_model::catalog::{
        CatalogOpenMode, CatalogOptions, GeneratedProductionKey, PinnedCatalogStatus,
        SemanticPackCatalog,
    };
    use brokk_bifrost_core::analyzer::config::JvmAnalyzerConfig;
    use brokk_bifrost_core::analyzer::external_selection::{
        ExternalSelectionQuestion, SelectionRefused,
    };
    use brokk_bifrost_core::analyzer::model::Language;
    use brokk_bifrost_core::analyzer::project::{OverlayProject, TestProject};
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    #[hardwon("#9559: an artifactless JDK without an installed pack must leave the request Open")]
    fn artifactless_jdk_without_pack_leaves_request_open() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("jdk");
        std::fs::create_dir(&home).unwrap();
        std::fs::write(home.join("release"), "JAVA_VERSION=\"21.0.2\"\n").unwrap();
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root.path(), Language::Java));
        let mut config = brokk_bifrost_core::analyzer::config::AnalyzerConfig::default();
        config.jvm.standard_library_discovery.jdk_homes = vec![home];
        config.jvm.standard_library_discovery.discover_java_home = false;
        config.jvm.dependency_discovery.mode =
            brokk_bifrost_core::analyzer::config::JvmDependencyDiscoveryMode::Disabled;
        let analyzer =
            crate::analyzer::java::JavaAnalyzer::new_with_config(Arc::clone(&project), config);
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        let source = analyzer
            .request_row_reader_source(&catalog.pinned_catalog_source(
                &brokk_bifrost_analysis::analyzer::store::cache_budget::StoreCacheBudget::new(
                    &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
                ),
            ))
            .unwrap();
        let active = ResolvedActiveSemanticModels::default();
        let _scope = AnalyzerQueryScope::with_outer_request(&analyzer, OuterRequest::new());
        assert_eq!(
            source.jvm_reader(&active).err(),
            Some(FamilyOpen::jvm("JVM selection shards unavailable")),
        );
    }

    #[test]
    #[hardwon(
        "#9559: a provider choice the activation never made bound because the membership check was one-way"
    )]
    #[hardwon("#9559: the bind exclusion filter removed the active winner of a shadowed duplicate")]
    fn installed_jdk_pack_after_activation_leaves_request_open() {
        use brokk_bifrost_analysis::analyzer::semantic_model::catalog::{
            DurablePackSource, DurablePackSourceKind,
        };
        use brokk_bifrost_analysis::analyzer::semantic_model::runtime::{
            SemanticModelActivationRequest, SemanticModelRuntimeOutcome,
            acquire_active_semantic_models,
        };
        use brokk_bifrost_analysis::analyzer::semantic_model::{
            AuthoredSemanticModelPack, CompilerOptions, compile_pack,
        };
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("jdk");
        std::fs::create_dir(&home).unwrap();
        std::fs::write(home.join("release"), "JAVA_VERSION=\"21.0.2\"\n").unwrap();
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root.path(), Language::Java));
        let mut config = brokk_bifrost_core::analyzer::config::AnalyzerConfig::default();
        config.jvm.standard_library_discovery.jdk_homes = vec![home];
        config.jvm.standard_library_discovery.discover_java_home = false;
        config.jvm.dependency_discovery.mode =
            brokk_bifrost_core::analyzer::config::JvmDependencyDiscoveryMode::Disabled;
        let analyzer =
            crate::analyzer::java::JavaAnalyzer::new_with_config(Arc::clone(&project), config);
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        // Test-only complete JDK surface; no local artifact can produce it.
        let mut authored: serde_json::Value = serde_json::from_str(
            r#"{
  "schema_version": 2,
  "pack_id": "fixture.jdk",
  "version": "21.0.2",
  "producer": { "name": "bifrost-fixture", "version": "1.0.0" },
  "language": "java",
  "ecosystem": "jdk",
  "compatibility": {
    "bifrost": ">=0.8.0, <1.0.0",
    "toolchains": [{ "name": "jdk", "requirement": "=21.0.2" }]
  },
  "provenance": { "source": "checked-in test source", "revision": "fixture-v1" },
  "license": "GPL-2.0-only WITH Classpath-exception-2.0",
  "completeness": "complete",
  "safety": { "generated_code_only": false, "review_required": false },
  "shards": [{
    "id": "jdk.core",
    "activation": [{
      "toolchain": { "name": "jdk", "version": "=21.0.2" },
      "targets": ["jvm"]
    }],
    "payload": {
      "kind": "declaration_facts",
      "types": [{
        "id": "jdk.java-util-arraylist",
        "name": "java.util.ArrayList",
        "type_kind": "class",
        "visibility": "public",
        "type_parameters": [],
        "hierarchy": [],
        "aliases": [],
        "extension_surfaces": [],
        "locator": {
          "kind": "artifact",
          "path": "java.base/java/util/ArrayList.java",
          "symbol": "java.util.ArrayList"
        }
      }],
      "members": [],
      "relations": []
    }
  }]
}"#,
        )
        .unwrap();
        let install = |authored: &serde_json::Value| {
            let pack = compile_pack(
                &serde_json::from_value::<AuthoredSemanticModelPack>(authored.clone()).unwrap(),
                &CompilerOptions::default(),
            )
            .unwrap();
            catalog
                .install(
                    &pack,
                    &DurablePackSource {
                        kind: DurablePackSourceKind::PreShipped,
                        source_id: "test:jdk".into(),
                    },
                )
                .unwrap();
        };
        install(&authored);
        let request = SemanticModelActivationRequest {
            host_activation: brokk_bifrost_analysis::analyzer::semantic_model::HostActivationContext::library_none(),
            bifrost_version: semver::Version::new(0, 15, 1),
            approximate_standard_libraries: Vec::new(),
            evidence: vec![brokk_bifrost_analysis::analyzer::semantic_model::runtime::SemanticModelActivationEvidence {
                language: "java".into(), ecosystem: "jdk".into(), package: None, module: None,
                toolchain: Some(brokk_bifrost_analysis::analyzer::semantic_model::catalog::CatalogCoordinate { name: "jdk".into(), version: Some(semver::Version::new(21, 0, 2)) }),
                target: Some("jvm".into()), configuration: None, production_input_digest: None,
verified_raw_artifacts: Vec::new(),
            }],
            controls: Vec::new(),
            limits: Default::default(),
        };
        let SemanticModelRuntimeOutcome::Ready { active, .. } = acquire_active_semantic_models(
            &analyzer,
            &catalog,
            None,
            &request,
            &CancellationToken::new(),
        ) else {
            panic!("JDK activation ready")
        };
        assert!(!active.shards.is_empty());
        let source = analyzer
            .request_row_reader_source(&catalog.pinned_catalog_source(
                &brokk_bifrost_analysis::analyzer::store::cache_budget::StoreCacheBudget::new(
                    &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
                ),
            ))
            .unwrap();
        {
            let _scope = AnalyzerQueryScope::with_outer_request(&analyzer, OuterRequest::new());
            assert!(source.jvm_reader(&active).is_ok());
        }
        // The same manifest supplied by another source shares its exclusion key
        // with the winner. It must not remove the winner from the pinned set.
        let pack = compile_pack(
            &serde_json::from_value::<AuthoredSemanticModelPack>(authored.clone()).unwrap(),
            &CompilerOptions::default(),
        )
        .unwrap();
        catalog
            .install(
                &pack,
                &DurablePackSource {
                    kind: DurablePackSourceKind::Installed,
                    source_id: "test:duplicate-jdk".into(),
                },
            )
            .unwrap();
        let SemanticModelRuntimeOutcome::Ready {
            active: duplicate_active,
            ..
        } = acquire_active_semantic_models(
            &analyzer,
            &catalog,
            None,
            &request,
            &CancellationToken::new(),
        )
        else {
            panic!("duplicate JDK activation ready")
        };
        assert!(!duplicate_active.shards.is_empty());
        assert!(
            duplicate_active
                .excluded_shards
                .contains(&pack.manifest.content_sha256, "jdk.core")
        );
        {
            let _scope = AnalyzerQueryScope::with_outer_request(&analyzer, OuterRequest::new());
            source
                .jvm_reader(&duplicate_active)
                .expect("shadowed duplicate must bind");
        }
        authored["version"] = serde_json::json!("21.0.3");
        install(&authored);
        let _scope = AnalyzerQueryScope::with_outer_request(&analyzer, OuterRequest::new());
        let cell = brokk_bifrost_analysis::analyzer::common::QueryCacheCell::new();
        for _ in 0..2 {
            brokk_bifrost_analysis::analyzer::common::replayable_query_cache_cell(
                &analyzer,
                &cell,
                || {
                    assert_eq!(
                        source.jvm_reader(&active).err(),
                        Some(FamilyOpen::jvm("JVM selection shards unavailable"))
                    );
                    true
                },
            );
            assert!(cell.get().is_none(), "failed binding cannot retain a fill");
        }
    }

    // A provider with one selected and one selector-rejected shard is a partial
    // selection: publication refuses it before the bind's membership check runs,
    // so this answers Open by the accepted limit in #10712. The bind's exclusion
    // allowance is pinned by the shadowed-duplicate case above.
    #[test]
    fn curated_selector_rejected_shard_reaches_partial_selection_guard() {
        use brokk_bifrost_analysis::analyzer::semantic_model::catalog::{
            DurablePackSource, DurablePackSourceKind,
        };
        use brokk_bifrost_analysis::analyzer::semantic_model::runtime::{
            SemanticModelActivationRequest, SemanticModelRuntimeOutcome,
            acquire_active_semantic_models,
        };
        use brokk_bifrost_analysis::analyzer::semantic_model::{
            AuthoredSemanticModelPack, CompilerOptions, compile_pack,
        };
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("jdk");
        std::fs::create_dir(&home).unwrap();
        std::fs::write(home.join("release"), "JAVA_VERSION=\"21.0.2\"\n").unwrap();
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root.path(), Language::Java));
        let mut config = brokk_bifrost_core::analyzer::config::AnalyzerConfig::default();
        config.jvm.standard_library_discovery.jdk_homes = vec![home];
        config.jvm.standard_library_discovery.discover_java_home = false;
        config.jvm.dependency_discovery.mode =
            brokk_bifrost_core::analyzer::config::JvmDependencyDiscoveryMode::Disabled;
        let analyzer =
            crate::analyzer::java::JavaAnalyzer::new_with_config(Arc::clone(&project), config);
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        // Test-only curated declaration fixture; the second shard requires a
        // package absent from this JDK activation's evidence.
        let mut authored: serde_json::Value = serde_json::from_slice(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../bifrost-analysis/testdata/semantic-model-packs/declarations-v1.json"
        )))
        .unwrap();
        authored["schema_version"] = serde_json::json!(
            brokk_bifrost_analysis::analyzer::semantic_model::SEMANTIC_MODEL_SCHEMA_VERSION
        );
        authored["ecosystem"] = serde_json::json!("jdk");
        authored["compatibility"] = serde_json::json!({});
        authored["shards"][0]["activation"] = serde_json::json!([{}]);
        let mut rejected: serde_json::Value = serde_json::from_str(
            &authored["shards"][0]
                .to_string()
                .replace("widget", "rejected")
                .replace("Widget", "Rejected"),
        )
        .unwrap();
        rejected["id"] = serde_json::json!("declarations.rejected");
        rejected["activation"] = serde_json::json!([{
            "package": { "name": "com.acme:missing", "version": ">=1.0.0" }
        }]);
        authored["shards"].as_array_mut().unwrap().push(rejected);
        let install = |authored: &serde_json::Value| {
            let pack = compile_pack(
                &serde_json::from_value::<AuthoredSemanticModelPack>(authored.clone()).unwrap(),
                &CompilerOptions::default(),
            )
            .unwrap();
            catalog
                .install(
                    &pack,
                    &DurablePackSource {
                        kind: DurablePackSourceKind::PreShipped,
                        source_id: "test:jdk".into(),
                    },
                )
                .unwrap();
        };
        install(&authored);
        let request = SemanticModelActivationRequest {
            host_activation: brokk_bifrost_analysis::analyzer::semantic_model::HostActivationContext::library_none(),
            bifrost_version: semver::Version::new(0, 15, 1),
            approximate_standard_libraries: Vec::new(),
            evidence: vec![brokk_bifrost_analysis::analyzer::semantic_model::runtime::SemanticModelActivationEvidence {
                language: "java".into(), ecosystem: "jdk".into(), package: None, module: None,
                toolchain: Some(brokk_bifrost_analysis::analyzer::semantic_model::catalog::CatalogCoordinate { name: "jdk".into(), version: Some(semver::Version::new(21, 0, 2)) }),
                target: Some("jvm".into()), configuration: None, production_input_digest: None,
verified_raw_artifacts: Vec::new(),
            }],
            controls: Vec::new(),
            limits: Default::default(),
        };
        let SemanticModelRuntimeOutcome::Ready { active, .. } = acquire_active_semantic_models(
            &analyzer,
            &catalog,
            None,
            &request,
            &CancellationToken::new(),
        ) else {
            panic!("JDK activation ready")
        };
        assert_eq!(active.shards.len(), 1, "{:?}", active.report);
        assert!(
            active.excluded_shards.contains(
                &active.shards[0].manifest.content_sha256,
                "declarations.rejected",
            ),
            "{:?}",
            active.report
        );
        let source = analyzer
            .request_row_reader_source(&catalog.pinned_catalog_source(
                &brokk_bifrost_analysis::analyzer::store::cache_budget::StoreCacheBudget::new(
                    &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
                ),
            ))
            .unwrap();
        let _scope = AnalyzerQueryScope::with_outer_request(&analyzer, OuterRequest::new());
        assert_eq!(
            source.jvm_reader(&active).err(),
            Some(FamilyOpen::jvm("curated JVM pack partially selected"))
        );
    }

    #[test]
    fn composite_request_source_refuses_multiple_jvm_owners() {
        use brokk_bifrost_analysis::analyzer::multi_analyzer::{AnalyzerDelegate, MultiAnalyzer};
        use brokk_bifrost_analysis::analyzer::store::active_models::{
            MatcherIndexes, SemanticModelActivationReport,
        };
        use brokk_bifrost_core::analyzer::config::AnalyzerConfig;
        use std::collections::BTreeMap;

        let root = tempfile::tempdir().unwrap();
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root.path(), Language::Java));
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        let activation = ResolvedActiveSemanticModels::new(
            "empty-jvm-activation".into(),
            None,
            Vec::new(),
            MatcherIndexes::default(),
            Vec::new(),
            Default::default(),
            Default::default(),
            SemanticModelActivationReport::default(),
        );
        let composite = |second_config: AnalyzerConfig| {
            MultiAnalyzer::new(BTreeMap::from([
                (
                    Language::Java,
                    AnalyzerDelegate::new(crate::analyzer::java::JavaAnalyzer::new(Arc::clone(
                        &project,
                    ))),
                ),
                (
                    Language::Kotlin,
                    AnalyzerDelegate::new(
                        crate::analyzer::kotlin::KotlinAnalyzer::new_with_config(
                            Arc::clone(&project),
                            second_config,
                        ),
                    ),
                ),
            ]))
        };
        let same_config = composite(AnalyzerConfig::default());
        let same_source = same_config
            .request_row_reader_source(&catalog.pinned_catalog_source(
                &brokk_bifrost_analysis::analyzer::store::cache_budget::StoreCacheBudget::new(
                    &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
                ),
            ))
            .unwrap();
        assert_eq!(
            same_source.jvm_reader(&activation).err(),
            Some(FamilyOpen::jvm("no request scope"))
        );

        let mut other_config = AnalyzerConfig::default();
        other_config
            .jvm
            .standard_library_discovery
            .discover_java_home = false;
        let different_config = composite(other_config);
        let different_source = different_config
            .request_row_reader_source(&catalog.pinned_catalog_source(
                &brokk_bifrost_analysis::analyzer::store::cache_budget::StoreCacheBudget::new(
                    &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
                ),
            ))
            .unwrap();
        assert_eq!(
            different_source.jvm_reader(&activation).err(),
            Some(FamilyOpen::jvm("several JVM selection configurations"))
        );
    }

    #[test]
    #[hardwon(
        "#9559: an active JVM generator-rule shard stayed in the reader's pinned curated set but left the activation side, so every request-owned JVM read was Open"
    )]
    #[hardwon(
        "#9559: a control-excluded shard of a selected JVM production made every request-owned read Open"
    )]
    fn real_request_reader_binds_with_an_active_jvm_generator_rule_shard() {
        use brokk_bifrost_analysis::analyzer::semantic_model::catalog::{
            SessionPackSource, SessionPackSourceKind,
        };
        use brokk_bifrost_analysis::analyzer::semantic_model::runtime::{
            SemanticModelActivationControl, SemanticModelActivationEvidence,
            SemanticModelActivationRequest, SemanticModelControlAction, SemanticModelControlScope,
            SemanticModelPackSelector, SemanticModelRuntimeLimits, SemanticModelRuntimeOutcome,
            acquire_active_semantic_models,
        };
        use brokk_bifrost_analysis::analyzer::semantic_model::{
            AuthoredSemanticModelPack, CompilerOptions, PayloadKind, compile_pack,
        };
        use serde_json::{Value as JsonValue, json};

        let root = tempfile::tempdir().unwrap();
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root.path(), Language::Java));
        let analyzer = crate::analyzer::java::JavaAnalyzer::new_with_config(
            Arc::clone(&project),
            hermetic_analyzer_config(),
        );
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        for (authored, source_id) in [
            (
                &include_bytes!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../bifrost-analysis/testdata/semantic-model-packs/generator-rules-v1.json"
                ))[..],
                "generator-fixture",
            ),
            (
                &include_bytes!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../bifrost-analysis/testdata/semantic-model-packs/declarations-v1.json"
                ))[..],
                "declarations-fixture",
            ),
        ] {
            let mut authored: JsonValue = serde_json::from_slice(authored).unwrap();
            authored["schema_version"] = json!(
                brokk_bifrost_analysis::analyzer::semantic_model::SEMANTIC_MODEL_SCHEMA_VERSION
            );
            authored["compatibility"] = json!({});
            authored["shards"][0]["activation"] = json!([{}]);
            let pack = compile_pack(
                &serde_json::from_value::<AuthoredSemanticModelPack>(authored).unwrap(),
                &CompilerOptions::default(),
            )
            .unwrap();
            catalog
                .register_compiled_pack(
                    &pack,
                    &SessionPackSource {
                        kind: SessionPackSourceKind::Embedded,
                        source_id: source_id.into(),
                    },
                )
                .unwrap();
        }
        let source = analyzer
            .request_row_reader_source(&catalog.pinned_catalog_source(
                &brokk_bifrost_analysis::analyzer::store::cache_budget::StoreCacheBudget::new(
                    &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
                ),
            ))
            .unwrap();
        let activation = SemanticModelActivationRequest {
            host_activation: brokk_bifrost_analysis::analyzer::semantic_model::HostActivationContext::library_none(),
            bifrost_version: semver::Version::new(0, 15, 1),
            approximate_standard_libraries: Vec::new(),
            evidence: vec![SemanticModelActivationEvidence {
                language: "java".into(),
                ecosystem: "maven".into(),
                package: None,
                module: None,
                toolchain: None,
                target: None,
                configuration: None,
                production_input_digest: None,
                verified_raw_artifacts: Vec::new(),
            }],
            // Both fixture packs require review, so a workspace control enables them.
            controls: ["acme.builders", "acme.widget"]
                .into_iter()
                .map(|pack_id| SemanticModelActivationControl {
                    scope: SemanticModelControlScope::Workspace,
                    action: SemanticModelControlAction::Enable,
                    selector: SemanticModelPackSelector {
                        pack_id: pack_id.into(),
                        version: None,
                        manifest_digest: None,
                    },
                })
                .collect(),
            limits: SemanticModelRuntimeLimits::default(),
        };
        let SemanticModelRuntimeOutcome::Ready { active, .. } = acquire_active_semantic_models(
            &analyzer,
            &catalog,
            None,
            &activation,
            &CancellationToken::new(),
        ) else {
            panic!("request owner activation ready")
        };
        let kinds = active
            .shards
            .iter()
            .map(|shard| (shard.descriptor.payload_kind, shard.request_owned()))
            .collect::<Vec<_>>();
        assert!(
            kinds.contains(&(PayloadKind::GeneratorRules, false))
                && kinds.iter().any(|(_, owned)| *owned),
            "{kinds:?} {:?}",
            active.report
        );
        // Inventory is the first request read: it must bind before touching
        // durable rows, including when an earlier request left rows behind.
        let expected = active
            .shards()
            .iter()
            .map(|shard| jvm_external_provider_id(&shard.manifest.semantic_sha256))
            .collect::<Vec<_>>();
        let mut failed_models = ResolvedActiveSemanticModels::default();
        failed_models.shards = active.shards().to_vec();
        failed_models
            .install_request_source(Some(Arc::new(
                brokk_bifrost_analysis::analyzer::store::model_catalog::RefusingRowReaderSource {
                    reason: FamilyOpen::jvm("test bind unavailable"),
                },
            )))
            .unwrap();
        let cell = brokk_bifrost_analysis::analyzer::common::QueryCacheCell::new();
        let retained = brokk_bifrost_analysis::analyzer::common::replayable_query_cache_cell(
            &analyzer,
            &cell,
            || expected.clone(),
        );
        let mut unavailable = retained.clone();
        assert!(
            failed_models
                .gate_inventory_providers(&mut unavailable)
                .is_some()
        );
        assert!(
            cell.get().is_some(),
            "failed bind leaves discovery retained"
        );
        assert_eq!(retained, expected, "failed bind cannot shrink discovery");
        assert!(
            active
                .shards()
                .iter()
                .filter(|shard| shard.request_owned())
                .all(|shard| !unavailable
                    .contains(&jvm_external_provider_id(&shard.manifest.semantic_sha256)))
        );
        for _ in 0..2 {
            let _scope = AnalyzerQueryScope::with_outer_request(&analyzer, OuterRequest::new());
            let mut providers =
                brokk_bifrost_analysis::analyzer::common::replayable_query_cache_cell(
                    &analyzer,
                    &cell,
                    || unreachable!("discovery remains retained"),
                );
            assert_eq!(active.gate_inventory_providers(&mut providers), None);
            assert_eq!(providers, expected);
        }
        let _scope = AnalyzerQueryScope::with_outer_request(&analyzer, OuterRequest::new());
        source
            .jvm_reader(&active)
            .expect("the generator-rule shard stays with the activation owner");
        drop(_scope);
        let mut activation = activation;
        activation.controls[1].action = SemanticModelControlAction::Disable;
        activation.limits.max_explanations = 0;
        let brokk_bifrost_analysis::analyzer::semantic_model::runtime::SemanticModelResolutionOutcome::Ready(active) =
            brokk_bifrost_analysis::analyzer::semantic_model::runtime::resolve_row_backed_semantic_models_for_test(
                &catalog, &activation, &CancellationToken::new(), &[],
            )
        else { panic!("disabled pack activation ready") };
        assert!(active.report.explanations.is_empty());
        assert!(!active.excluded_shards.is_empty());
        let _scope = AnalyzerQueryScope::with_outer_request(&analyzer, OuterRequest::new());
        source
            .jvm_reader(&active)
            .expect("explicit exclusions bind even when explanations are capped");
    }

    #[test]
    fn catalog_installation_between_requests_rotates_binding() {
        use brokk_bifrost_analysis::analyzer::semantic_model::catalog::{
            SessionPackSource, SessionPackSourceKind,
        };
        use brokk_bifrost_analysis::analyzer::semantic_model::runtime::{
            SemanticModelActivationEvidence, SemanticModelActivationRequest,
            SemanticModelRuntimeLimits, SemanticModelRuntimeOutcome,
            acquire_active_semantic_models,
        };
        use brokk_bifrost_analysis::analyzer::semantic_model::{
            AuthoredSemanticModelPack, CompilerOptions, compile_pack,
        };
        use serde_json::{Value as JsonValue, json};

        let root = tempfile::tempdir().unwrap();
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root.path(), Language::Java));
        let analyzer = crate::analyzer::java::JavaAnalyzer::new_with_config(
            Arc::clone(&project),
            hermetic_analyzer_config(),
        );
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        let source = analyzer
            .request_row_reader_source(&catalog.pinned_catalog_source(
                &brokk_bifrost_analysis::analyzer::store::cache_budget::StoreCacheBudget::new(
                    &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
                ),
            ))
            .unwrap();
        let activation = SemanticModelActivationRequest {
            host_activation: brokk_bifrost_analysis::analyzer::semantic_model::HostActivationContext::library_none(),
            bifrost_version: semver::Version::new(0, 15, 1),
            approximate_standard_libraries: Vec::new(),
            evidence: vec![SemanticModelActivationEvidence {
                language: "java".into(),
                ecosystem: "maven".into(),
                package: None,
                module: None,
                toolchain: None,
                target: None,
                configuration: None,
                production_input_digest: None,
                verified_raw_artifacts: Vec::new(),
            }],
            controls: Vec::new(),
            limits: SemanticModelRuntimeLimits::default(),
        };
        let acquire = || {
            let SemanticModelRuntimeOutcome::Ready { active, .. } = acquire_active_semantic_models(
                &analyzer,
                &catalog,
                None,
                &activation,
                &CancellationToken::new(),
            ) else {
                panic!("JVM activation ready")
            };
            active
        };
        let before = acquire();
        let first_binding = {
            let request = OuterRequest::new();
            let _scope = AnalyzerQueryScope::with_outer_request(&analyzer, request);
            source
                .jvm_reader(&before)
                .expect("first JVM reader")
                .binding
        };

        let mut authored: JsonValue = serde_json::from_slice(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../bifrost-analysis/testdata/semantic-model-packs/declarations-v1.json"
        )))
        .unwrap();
        authored["schema_version"] =
            json!(brokk_bifrost_analysis::analyzer::semantic_model::SEMANTIC_MODEL_SCHEMA_VERSION);
        authored["compatibility"] = json!({});
        authored["shards"][0]["activation"] = json!([{}]);
        let pack = compile_pack(
            &serde_json::from_value::<AuthoredSemanticModelPack>(authored).unwrap(),
            &CompilerOptions::default(),
        )
        .unwrap();
        catalog
            .register_compiled_pack(
                &pack,
                &SessionPackSource {
                    kind: SessionPackSourceKind::EphemeralWorkspace,
                    source_id: "binding-rotation-fixture".into(),
                },
            )
            .unwrap();
        let after = acquire();
        assert_ne!(
            before.active_model_set_hash(),
            after.active_model_set_hash(),
            "after activation: {:?}",
            after.report
        );
        let second_binding = {
            let request = OuterRequest::new();
            let _scope = AnalyzerQueryScope::with_outer_request(&analyzer, request);
            source
                .jvm_reader(&after)
                .expect("second JVM reader")
                .binding
        };
        assert_ne!(first_binding, second_binding);
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#9559: a non-JVM model read bound the JVM request owner and recorded its selection reads"
    )]
    fn scoped_overlay_reads_record_only_the_requested_selection_family() {
        let _languages =
            brokk_bifrost_analysis::analyzer::languages::neutral_fixture::neutral_rules_fixture(&[
                Language::Python,
            ]);
        use brokk_bifrost_analysis::analyzer::read_ledger::{LookupKind, ReadKey, ReadLedger};
        use brokk_bifrost_analysis::analyzer::semantic::ids::StableDigest;
        use brokk_bifrost_analysis::analyzer::semantic_model::catalog::{
            SessionPackSource, SessionPackSourceKind,
        };
        use brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay;
        use brokk_bifrost_analysis::analyzer::semantic_model::runtime::{
            SemanticModelActivationEvidence, SemanticModelActivationRequest,
            SemanticModelResolutionOutcome, SemanticModelRuntimeLimits,
            resolve_active_semantic_models,
        };
        use brokk_bifrost_analysis::analyzer::semantic_model::{
            AuthoredSemanticModelPack, CompilerOptions, compile_pack,
        };
        use serde_json::{Value as JsonValue, json};

        let root = tempfile::tempdir().unwrap();
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root.path(), Language::Java));
        let analyzer = crate::analyzer::java::JavaAnalyzer::new_with_config(
            Arc::clone(&project),
            hermetic_analyzer_config(),
        );
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        let inventory_store = Arc::new(AnalyzerStore::open_ephemeral().unwrap());
        for (language, ecosystem) in [("python", "pypi"), ("java", "maven")] {
            let mut authored: JsonValue = serde_json::from_slice(include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../bifrost-analysis/testdata/semantic-model-packs/declarations-v1.json"
            )))
            .unwrap();
            authored["schema_version"] = json!(
                brokk_bifrost_analysis::analyzer::semantic_model::SEMANTIC_MODEL_SCHEMA_VERSION
            );
            authored["compatibility"] = json!({});
            authored["pack_id"] = json!(format!("ledger.{language}"));
            authored["language"] = json!(language);
            authored["ecosystem"] = json!(ecosystem);
            authored["shards"][0]["activation"] = json!([{}]);
            let pack = compile_pack(
                &serde_json::from_value::<AuthoredSemanticModelPack>(authored).unwrap(),
                &CompilerOptions::default(),
            )
            .unwrap();
            catalog
                .register_compiled_pack(
                    &pack,
                    &SessionPackSource {
                        kind: SessionPackSourceKind::Embedded,
                        source_id: format!("ledger-{language}"),
                    },
                )
                .unwrap();
        }
        let activation = SemanticModelActivationRequest {
            host_activation: brokk_bifrost_analysis::analyzer::semantic_model::HostActivationContext::library_none(),
            bifrost_version: semver::Version::new(0, 15, 1),
            approximate_standard_libraries: Vec::new(),
            evidence: [("python", "pypi"), ("java", "maven")]
                .into_iter()
                .map(|(language, ecosystem)| SemanticModelActivationEvidence {
                    language: language.into(),
                    ecosystem: ecosystem.into(),
                    package: None,
                    module: None,
                    toolchain: None,
                    target: None,
                    configuration: None,
                    production_input_digest: None,
                    verified_raw_artifacts: Vec::new(),
                })
                .collect(),
            controls: Vec::new(),
            limits: SemanticModelRuntimeLimits::default(),
        };
        let SemanticModelResolutionOutcome::Ready(mut active) =
            resolve_active_semantic_models(&catalog, &activation, &CancellationToken::new())
        else {
            panic!("mixed activation ready")
        };
        assert_eq!(active.shards.len(), 2);
        for shard in &mut active.shards {
            let metadata = (*shard.metadata).clone();
            *shard = Arc::new(
                brokk_bifrost_analysis::analyzer::store::active_models::ActiveSemanticModelShard {
                    metadata: Arc::new(metadata),
                    decoded: None,
                },
            );
        }
        struct CertifiedAuthority(JvmSelectionAuthority, bool);
        impl ExternalSelectionAuthority for CertifiedAuthority {
            fn basis(
                &self,
                _question: &brokk_bifrost_core::analyzer::external_selection::ExternalSelectionQuestion,
                _answer: [u8; 32],
            ) -> Option<brokk_bifrost_core::analyzer::external_selection::JvmDependencyBasis>
            {
                None
            }
            fn answer_under_basis(
                &self,
                _question: &brokk_bifrost_core::analyzer::external_selection::ExternalSelectionQuestion,
                _basis: &brokk_bifrost_core::analyzer::external_selection::JvmDependencyBasis,
            ) -> Option<[u8; 32]> {
                None
            }

            fn questions(
                &self,
            ) -> Vec<brokk_bifrost_core::analyzer::external_selection::ExternalSelectionQuestion>
            {
                self.0.questions()
            }
            fn answer(
                &self,
                request: &OuterRequest,
                question: &brokk_bifrost_core::analyzer::external_selection::ExternalSelectionQuestion,
                retry: &SelectionRetry,
                _cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
            ) -> Result<
                Arc<VerifiedSelection>,
                brokk_bifrost_core::analyzer::external_selection::SelectionRefused,
            > {
                let answer = self.0.answer(request, question, retry, _cancellation)?;
                Ok(Arc::new(VerifiedSelection {
                    question_digest: answer.question_digest,
                    answer_digest: answer.answer_digest,
                    view_stamp: answer.view_stamp.clone(),
                    verified: question.kind == ExternalSelectionQuestionKind::Dependencies
                        || self.1,
                    certified: answer.complete
                        && (question.kind == ExternalSelectionQuestionKind::Dependencies || self.1),
                    complete: answer.complete,
                    only_replayable_gaps: answer.only_replayable_gaps,
                    records: Arc::clone(&answer.records),
                }))
            }
        }
        {
            let installed_source: Option<Arc<dyn brokk_bifrost_analysis::analyzer::store::model_catalog::RequestRowReaderSource>> = Some(Arc::new(JvmRequestRowReaderSource {
                questions_digest: Default::default(),
                authority: Arc::new(CertifiedAuthority(
                    JvmSelectionAuthority {

                        config: hermetic_jvm_config(),
                        project: Arc::clone(&project),
                        digests: super::super::external::test_digests(),
                        verifications: Arc::new(Default::default()),
                    },
                    true,
                )),
                project: Arc::clone(&project),
                catalog: catalog.pinned_catalog_source(&brokk_bifrost_analysis::analyzer::store::cache_budget::StoreCacheBudget::new(&brokk_bifrost_core::retention_budget::RetentionBudget::for_tests())),
                store: Arc::clone(&inventory_store),
            }));
            active.install_request_source(installed_source).unwrap();
        };
        let active = Arc::new(active);
        let slot = super::super::authority::JvmExternalIndexSlot::new(8 << 20);
        for request_number in 0..2 {
            let _request = AnalyzerQueryScope::with_outer_request(&analyzer, OuterRequest::new());
            let ledger = Arc::new(ReadLedger::new());
            let _capture = AnalyzerQueryScope::with_read_ledger(&analyzer, Arc::clone(&ledger));
            let index = slot.get_or_build(
                &analyzer,
                (
                    Language::Java,
                    brokk_bifrost_analysis::analyzer::WorkspaceFactFamily::JavaExternalDeclarations,
                ),
                || {
                    super::super::external::dependency_discovery_sample(
                        &analyzer,
                        &Default::default(),
                        project.as_ref(),
                    )
                },
                || {
                    super::super::external::fresh_dependency_discovery_sample(
                        &analyzer,
                        &Default::default(),
                        project.as_ref(),
                    )
                },
                |_| {},
                || {
                    assert_eq!(request_number, 0, "second request must reuse the index");
                    super::super::external::JvmExternalDeclarationIndex::build_for_project(
                        &Default::default(),
                        project.as_ref(),
                    )
                },
            );
            assert_eq!(
                ledger
                    .keys()
                    .iter()
                    .filter(|key| matches!(
                        key,
                        ReadKey::Lookup {
                            kind: LookupKind::ExternalSelection,
                            ..
                        }
                    ))
                    .count(),
                0,
                "fill must not bind request selection",
            );
            assert!(
                !ledger
                    .keys()
                    .iter()
                    .any(|key| matches!(key, ReadKey::Models(_)))
            );
            // A retained index is data, never request certification.
            let mut providers = active
                .shards()
                .iter()
                .map(|shard| shard.inventory_provider_id())
                .collect();
            assert_eq!(active.gate_inventory_providers(&mut providers), None);
            assert!(slot.is_built());
            assert_eq!(
                ledger
                    .keys()
                    .iter()
                    .filter(|key| matches!(
                        key,
                        ReadKey::Lookup {
                            kind: LookupKind::ExternalSelection,
                            ..
                        }
                    ))
                    .count(),
                2
            );
            drop(index);
        }
        let _scope = AnalyzerQueryScope::with_outer_request(&analyzer, OuterRequest::new());
        let overlay = SemanticModelOverlay::build(
            &analyzer,
            &active,
            &CancellationToken::new(),
            64 << 20,
            &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
        )
        .unwrap();
        for language in ["python", "java"] {
            let ledger = Arc::new(ReadLedger::new());
            let answer = {
                let _capture = AnalyzerQueryScope::with_read_ledger(&analyzer, Arc::clone(&ledger));
                // Match IAnalyzer::semantic_model_overlay's publication read before composition.
                analyzer.record_read(ReadKey::Models(StableDigest::sha256(
                    active.active_model_set_hash(),
                )));
                overlay.symbols_with_id_for("type.widget", language)
            };
            let selections = ledger
                .keys()
                .into_iter()
                .filter(|key| {
                    matches!(
                        key,
                        ReadKey::Lookup {
                            kind: LookupKind::ExternalSelection,
                            ..
                        }
                    )
                })
                .collect::<Vec<_>>();
            assert_eq!(
                selections.len(),
                if language == "python" { 0 } else { 2 },
                "{language}: {selections:?}"
            );
            assert!(!answer.records.is_empty(), "{language}: {answer:?}");
            assert!(!ledger.reuse_refused(), "{language}");
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#9559: a non-JVM model read bound the JVM request owner and recorded its selection reads"
    )]
    fn pooled_overlay_reads_record_only_the_requested_selection_family() {
        let _languages =
            brokk_bifrost_analysis::analyzer::languages::neutral_fixture::neutral_rules_fixture(&[
                Language::Python,
            ]);
        use brokk_bifrost_analysis::analyzer::read_ledger::{LookupKind, ReadKey, ReadLedger};
        use brokk_bifrost_analysis::analyzer::semantic::ids::StableDigest;
        use brokk_bifrost_analysis::analyzer::semantic_model::catalog::{
            SessionPackSource, SessionPackSourceKind,
        };
        use brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay;
        use brokk_bifrost_analysis::analyzer::semantic_model::runtime::{
            SemanticModelActivationEvidence, SemanticModelActivationRequest,
            SemanticModelResolutionOutcome, SemanticModelRuntimeLimits,
            resolve_active_semantic_models,
        };
        use brokk_bifrost_analysis::analyzer::semantic_model::{
            AuthoredSemanticModelPack, CompilerOptions, compile_pack,
        };
        use serde_json::{Value as JsonValue, json};

        let root = tempfile::tempdir().unwrap();
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root.path(), Language::Java));
        let analyzer = crate::analyzer::java::JavaAnalyzer::new(Arc::clone(&project));
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        for (language, ecosystem) in [("python", "pypi"), ("java", "maven")] {
            let mut authored: JsonValue = serde_json::from_slice(include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../bifrost-analysis/testdata/semantic-model-packs/declarations-v1.json"
            )))
            .unwrap();
            authored["schema_version"] = json!(
                brokk_bifrost_analysis::analyzer::semantic_model::SEMANTIC_MODEL_SCHEMA_VERSION
            );
            authored["compatibility"] = json!({});
            authored["pack_id"] = json!(format!("ledger.{language}"));
            authored["language"] = json!(language);
            authored["ecosystem"] = json!(ecosystem);
            authored["shards"][0]["activation"] = json!([{}]);
            let pack = compile_pack(
                &serde_json::from_value::<AuthoredSemanticModelPack>(authored).unwrap(),
                &CompilerOptions::default(),
            )
            .unwrap();
            catalog
                .register_compiled_pack(
                    &pack,
                    &SessionPackSource {
                        kind: SessionPackSourceKind::Embedded,
                        source_id: format!("ledger-{language}"),
                    },
                )
                .unwrap();
        }
        let activation = SemanticModelActivationRequest {
            host_activation: brokk_bifrost_analysis::analyzer::semantic_model::HostActivationContext::library_none(),
            bifrost_version: semver::Version::new(0, 15, 1),
            approximate_standard_libraries: Vec::new(),
            evidence: [("python", "pypi"), ("java", "maven")]
                .into_iter()
                .map(|(language, ecosystem)| SemanticModelActivationEvidence {
                    language: language.into(),
                    ecosystem: ecosystem.into(),
                    package: None,
                    module: None,
                    toolchain: None,
                    target: None,
                    configuration: None,
                    production_input_digest: None,
                    verified_raw_artifacts: Vec::new(),
                })
                .collect(),
            controls: Vec::new(),
            limits: SemanticModelRuntimeLimits::default(),
        };
        let SemanticModelResolutionOutcome::Ready(mut active) =
            resolve_active_semantic_models(&catalog, &activation, &CancellationToken::new())
        else {
            panic!("mixed activation ready")
        };
        assert_eq!(active.shards.len(), 2);
        for shard in &mut active.shards {
            let metadata = (*shard.metadata).clone();
            *shard = Arc::new(
                brokk_bifrost_analysis::analyzer::store::active_models::ActiveSemanticModelShard {
                    metadata: Arc::new(metadata),
                    decoded: None,
                },
            );
        }
        struct CertifiedAuthority(JvmSelectionAuthority, bool);
        impl ExternalSelectionAuthority for CertifiedAuthority {
            fn basis(
                &self,
                _question: &brokk_bifrost_core::analyzer::external_selection::ExternalSelectionQuestion,
                _answer: [u8; 32],
            ) -> Option<brokk_bifrost_core::analyzer::external_selection::JvmDependencyBasis>
            {
                None
            }
            fn answer_under_basis(
                &self,
                _question: &brokk_bifrost_core::analyzer::external_selection::ExternalSelectionQuestion,
                _basis: &brokk_bifrost_core::analyzer::external_selection::JvmDependencyBasis,
            ) -> Option<[u8; 32]> {
                None
            }

            fn questions(
                &self,
            ) -> Vec<brokk_bifrost_core::analyzer::external_selection::ExternalSelectionQuestion>
            {
                self.0.questions()
            }
            fn answer(
                &self,
                request: &OuterRequest,
                question: &brokk_bifrost_core::analyzer::external_selection::ExternalSelectionQuestion,
                retry: &SelectionRetry,
                _cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
            ) -> Result<
                Arc<VerifiedSelection>,
                brokk_bifrost_core::analyzer::external_selection::SelectionRefused,
            > {
                let answer = self.0.answer(request, question, retry, _cancellation)?;
                Ok(Arc::new(VerifiedSelection {
                    question_digest: answer.question_digest,
                    answer_digest: answer.answer_digest,
                    view_stamp: answer.view_stamp.clone(),
                    verified: question.kind == ExternalSelectionQuestionKind::Dependencies
                        || self.1,
                    certified: answer.complete
                        && (question.kind == ExternalSelectionQuestionKind::Dependencies || self.1),
                    complete: answer.complete,
                    only_replayable_gaps: answer.only_replayable_gaps,
                    records: Arc::clone(&answer.records),
                }))
            }
        }
        {
            let installed_source: Option<Arc<dyn brokk_bifrost_analysis::analyzer::store::model_catalog::RequestRowReaderSource>> = Some(Arc::new(JvmRequestRowReaderSource {
                questions_digest: Default::default(),
                authority: Arc::new(CertifiedAuthority(
                    JvmSelectionAuthority {
                        config: hermetic_jvm_config(),
                        project: Arc::clone(&project),
                        digests: super::super::external::test_digests(),
                        verifications: Arc::new(Default::default()),
                    },
                    true,
                )),
                project: Arc::clone(&project),
                catalog: catalog.pinned_catalog_source(&brokk_bifrost_analysis::analyzer::store::cache_budget::StoreCacheBudget::new(&brokk_bifrost_core::retention_budget::RetentionBudget::for_tests())),
                store: Arc::new(AnalyzerStore::open_ephemeral().unwrap()),
            }));
            active.install_request_source(installed_source).unwrap();
        };
        let active = Arc::new(active);
        let patterns = brokk_bifrost_analysis::analyzer::SearchSymbolPatternBatch::compile(
            vec![".*".into()],
            false,
            None,
        );
        let mut observations = Vec::new();
        for pooled in [false, true] {
            let _scope = AnalyzerQueryScope::with_outer_request(&analyzer, OuterRequest::new());
            let overlay = SemanticModelOverlay::build(
                &analyzer,
                &active,
                &CancellationToken::new(),
                64 << 20,
                &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
            )
            .unwrap();
            for language in ["python", "java"] {
                let ledger = Arc::new(ReadLedger::new());
                let answer = {
                    let _capture =
                        AnalyzerQueryScope::with_read_ledger(&analyzer, Arc::clone(&ledger));
                    // Match IAnalyzer::semantic_model_overlay's publication read before composition.
                    analyzer.record_read(ReadKey::Models(StableDigest::sha256(
                        active.active_model_set_hash(),
                    )));
                    overlay.symbols_with_id_for("type.widget", language)
                };
                let selections = ledger
                    .keys()
                    .into_iter()
                    .filter(|key| {
                        matches!(
                            key,
                            ReadKey::Lookup {
                                kind: LookupKind::ExternalSelection,
                                ..
                            }
                        )
                    })
                    .collect::<Vec<_>>();
                assert_eq!(
                    selections.len(),
                    if language == "python" { 0 } else { 2 },
                    "{language}: {selections:?}"
                );
                assert!(!answer.records.is_empty(), "{language}: {answer:?}");
                assert!(!ledger.reuse_refused(), "{language}");
                if language == "java" {
                    let _capture =
                        AnalyzerQueryScope::with_read_ledger(&analyzer, Arc::clone(&ledger));
                    let members = overlay.members_of_for("type.widget", language);
                    let relations = overlay.relations_from_for("member.widget.create", language);
                    assert!(!members.records.is_empty(), "{members:?}");
                    assert!(!relations.records.is_empty(), "{relations:?}");
                    // Search reports candidate visits, but this layer has no work-budget counter.
                    let search = overlay.search_with_limit(&patterns, usize::MAX, None);
                    observations.push((
                        ledger
                            .keys()
                            .into_iter()
                            .collect::<std::collections::HashSet<_>>(),
                        format!("{answer:?} {members:?} {relations:?} {search:?}"),
                        search.1,
                    ));
                }
            }
            let reader = active
                .request_source()
                .unwrap()
                .jvm_reader(&active)
                .unwrap();
            let marker = reader
                .reader
                .owned_rows("PRAGMA temp.cache_size", &[], &CancellationToken::new())
                .unwrap();
            assert_eq!(marker.rows == vec![vec![Value::Integer(-12345)]], pooled);
            if !pooled {
                reader
                    .reader
                    .owned_rows(
                        "PRAGMA temp.cache_size=-12345",
                        &[],
                        &CancellationToken::new(),
                    )
                    .unwrap();
            }
        }
        assert_eq!(observations[0], observations[1]);
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon("#9559: real owner capture must refuse retained reuse")]
    fn real_owner_capture_refuses_reuse() {
        use brokk_bifrost_analysis::analyzer::semantic_model::runtime::{
            SemanticModelActivationRequest, SemanticModelRuntimeLimits,
            SemanticModelRuntimeOutcome, acquire_active_semantic_models,
        };
        let root = tempfile::tempdir().unwrap();
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root.path(), Language::Java));
        let analyzer = crate::analyzer::java::JavaAnalyzer::new(project);
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        let activation = SemanticModelActivationRequest {
            host_activation: brokk_bifrost_analysis::analyzer::semantic_model::HostActivationContext::library_none(),
            bifrost_version: semver::Version::new(0, 15, 1),
            approximate_standard_libraries: Vec::new(),
            evidence: Vec::new(),
            controls: Vec::new(),
            limits: SemanticModelRuntimeLimits::default(),
        };
        let SemanticModelRuntimeOutcome::Ready { active, .. } = acquire_active_semantic_models(
            &analyzer,
            &catalog,
            None,
            &activation,
            &CancellationToken::new(),
        ) else {
            panic!("real owner activation ready")
        };
        let _scope = AnalyzerQueryScope::new(&analyzer);
        let captured =
            brokk_bifrost_analysis::analyzer::common::complete_query_cache_fill(&analyzer, || {
                active.question_row_owners(Some("jvm"));
                true
            });
        assert_eq!(captured, Err(true));
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#9559: request reader cancellation panicked and ignored the explicit token mid-read"
    )]
    fn real_request_source_reuses_one_binding_per_activation() {
        use brokk_bifrost_analysis::analyzer::semantic_model::runtime::{
            SemanticModelActivationRequest, SemanticModelRuntimeLimits,
            SemanticModelRuntimeOutcome, acquire_active_semantic_models,
            acquire_eager_semantic_models_for_test,
        };
        let root = tempfile::tempdir().unwrap();
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root.path(), Language::Java));
        let analyzer = crate::analyzer::java::JavaAnalyzer::new_with_config(
            Arc::clone(&project),
            hermetic_analyzer_config(),
        );
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        let store = Arc::new(AnalyzerStore::open_ephemeral().unwrap());
        let source = JvmRequestRowReaderSource {
            questions_digest: Default::default(),
            authority: Arc::new(JvmSelectionAuthority {
                config: hermetic_jvm_config(),
                project: project.clone(),
                digests: store.content_digests(),
                verifications: store.toolchain_verifications(),
            }),
            project: project.clone(),
            catalog: catalog.pinned_catalog_source(
                &brokk_bifrost_analysis::analyzer::store::cache_budget::StoreCacheBudget::new(
                    &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
                ),
            ),
            store,
        };
        let activation = SemanticModelActivationRequest {
            host_activation: brokk_bifrost_analysis::analyzer::semantic_model::HostActivationContext::library_none(),
            bifrost_version: semver::Version::new(0, 15, 1),
            approximate_standard_libraries: Vec::new(),
            evidence: Vec::new(),
            controls: Vec::new(),
            limits: SemanticModelRuntimeLimits::default(),
        };
        let SemanticModelRuntimeOutcome::Ready { active: off, .. } =
            acquire_eager_semantic_models_for_test(
                &analyzer,
                &catalog,
                &activation,
                &CancellationToken::new(),
            )
        else {
            panic!("empty activation ready")
        };
        assert!(off.request_source().unwrap().identity().is_none());
        let SemanticModelRuntimeOutcome::Ready { active, .. } = acquire_active_semantic_models(
            &analyzer,
            &catalog,
            None,
            &activation,
            &CancellationToken::new(),
        ) else {
            panic!("request owner activation ready")
        };
        assert!(active.request_source().unwrap().identity().is_some());
        let request = OuterRequest::new();
        let _scope = AnalyzerQueryScope::with_outer_request(&analyzer, Arc::clone(&request));
        let first = source.jvm_reader(&active).expect("real JVM reader");
        let second = source.jvm_reader(&active).expect("reused JVM reader");
        let carried = brokk_bifrost_core::analyzer::carried_context::CarriedContext::current();
        std::thread::scope(|threads| {
            for _ in 0..8 {
                let source = &source;
                let active = &active;
                let carried = &carried;
                threads.spawn(move || carried.run(|| source.jvm_reader(active).unwrap()));
            }
        });
        let memo = request
            .resource::<ReaderDerivationMemo, std::convert::Infallible>(
                RequestEntryKey::JvmReaderDerivation {
                    activation: active.active_model_set_hash().to_owned(),
                    view: view_digest(&request_owned_view(&active)),
                    excluded: active.excluded_shards.digest(),
                    questions: *source.questions_digest.get().unwrap(),
                    view_stamp: source.project.view_stamp(),
                    generation: source.project.analysis_generation(),
                },
                || unreachable!("memo already derived"),
            )
            .unwrap();
        assert_eq!(memo.fills.load(std::sync::atomic::Ordering::SeqCst), 1);
        let live = Arc::new(brokk_bifrost_core::analyzer::project::OverlayProject::new(
            Arc::new(
                brokk_bifrost_core::analyzer::project::FilesystemProject::new(root.path()).unwrap(),
            ),
        ));
        let live_source = JvmRequestRowReaderSource {
            questions_digest: Default::default(),
            authority: source.authority.clone(),
            project: live.clone(),
            catalog: source.catalog.clone(),
            store: source.store.clone(),
        };
        let before = live_source.reader_entry_key(&active);
        live.set(root.path().join("Live.java"), "class Live {}".into());
        let after = live_source.reader_entry_key(&active);
        match (&before, &after) {
            (
                RequestEntryKey::JvmReaderDerivation {
                    view_stamp: a,
                    generation: ag,
                    ..
                },
                RequestEntryKey::JvmReaderDerivation {
                    view_stamp: b,
                    generation: bg,
                    ..
                },
            ) => {
                assert_ne!(a, b);
                assert_ne!(ag, bg);
            }
            _ => unreachable!(),
        }
        let entry = |key| {
            request
                .resource::<ReaderDerivationMemo, std::convert::Infallible>(key, || {
                    Ok(Arc::new(ReaderDerivationMemo::default()))
                })
                .unwrap()
        };
        assert!(!Arc::ptr_eq(&entry(before), &entry(after)));

        assert_eq!(first.binding, second.binding);
        assert!(Arc::ptr_eq(&first.reader, &second.reader));
        let key = request
            .jvm_catalog_binding(
                active.active_model_set_hash(),
                super::activation_view_digest(&active),
            )
            .unwrap();
        let handle = request
            .resource::<JvmCatalogReaderHandle, PinnedReaderError>(
                RequestEntryKey::JvmCatalogReader(key),
                || unreachable!("reader already opened"),
            )
            .unwrap();
        assert!(handle.bindings.lock().unwrap().view.is_some());
        let ledger = Arc::new(brokk_bifrost_analysis::analyzer::read_ledger::ReadLedger::new());
        {
            let _capture = AnalyzerQueryScope::with_read_ledger(&analyzer, Arc::clone(&ledger));
            source.jvm_reader(&active).expect("captured JVM reader");
        }
        assert!(ledger.request_pinned_dependences() > 0);
        // A cached product filled from a read through the request owner is
        // never retained, so a later request cannot reuse it warm; the same
        // fill without that read is retained.
        let through_owner =
            brokk_bifrost_analysis::analyzer::common::complete_query_cache_fill(&analyzer, || {
                source.jvm_reader(&active).is_ok()
            });
        assert_eq!(through_owner, Err(true));
        let without_owner =
            brokk_bifrost_analysis::analyzer::common::complete_query_cache_fill(&analyzer, || true);
        assert_eq!(without_owner, Ok(true));
        // Install the placeholder explicitly: production activation uses the real owner.
        let placeholder_source = Arc::new(
            brokk_bifrost_analysis::analyzer::store::model_catalog::ActivationRowReaderSource::new(
                Arc::clone(off.source_reader.as_ref().unwrap()),
                off.active_model_set_hash(),
            ),
        );
        let mut placeholder_active = brokk_bifrost_analysis::analyzer::store::active_models::ResolvedActiveSemanticModels::default();
        placeholder_active
            .install_request_source(Some(placeholder_source))
            .unwrap();
        let placeholder =
            brokk_bifrost_analysis::analyzer::common::complete_query_cache_fill(&analyzer, || {
                placeholder_active.question_row_owners(Some("jvm"));
                true
            });
        assert_eq!(placeholder, Ok(true));
        struct CertifiedAuthority(JvmSelectionAuthority, bool);
        impl ExternalSelectionAuthority for CertifiedAuthority {
            fn basis(
                &self,
                _question: &brokk_bifrost_core::analyzer::external_selection::ExternalSelectionQuestion,
                _answer: [u8; 32],
            ) -> Option<brokk_bifrost_core::analyzer::external_selection::JvmDependencyBasis>
            {
                None
            }
            fn answer_under_basis(
                &self,
                _question: &brokk_bifrost_core::analyzer::external_selection::ExternalSelectionQuestion,
                _basis: &brokk_bifrost_core::analyzer::external_selection::JvmDependencyBasis,
            ) -> Option<[u8; 32]> {
                None
            }

            fn questions(
                &self,
            ) -> Vec<brokk_bifrost_core::analyzer::external_selection::ExternalSelectionQuestion>
            {
                self.0.questions()
            }
            fn answer(
                &self,
                request: &OuterRequest,
                question: &brokk_bifrost_core::analyzer::external_selection::ExternalSelectionQuestion,
                retry: &SelectionRetry,
                _cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
            ) -> Result<
                Arc<VerifiedSelection>,
                brokk_bifrost_core::analyzer::external_selection::SelectionRefused,
            > {
                let answer = self.0.answer(request, question, retry, _cancellation)?;
                Ok(Arc::new(VerifiedSelection {
                    question_digest: answer.question_digest,
                    answer_digest: answer.answer_digest,
                    view_stamp: answer.view_stamp.clone(),
                    verified: question.kind == ExternalSelectionQuestionKind::Dependencies
                        || self.1,
                    certified: answer.complete
                        && (question.kind == ExternalSelectionQuestionKind::Dependencies || self.1),
                    complete: answer.complete,
                    only_replayable_gaps: answer.only_replayable_gaps,
                    records: Arc::clone(&answer.records),
                }))
            }
        }
        let certified = JvmRequestRowReaderSource {
            questions_digest: Default::default(),
            authority: Arc::new(CertifiedAuthority(
                JvmSelectionAuthority {
                    config: hermetic_jvm_config(),
                    project: Arc::clone(&project),
                    digests: super::super::external::test_digests(),
                    verifications: Arc::new(Default::default()),
                },
                true,
            )),
            project: Arc::clone(&project),
            catalog: catalog.pinned_catalog_source(
                &brokk_bifrost_analysis::analyzer::store::cache_budget::StoreCacheBudget::new(
                    &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
                ),
            ),
            store: Arc::new(AnalyzerStore::open_ephemeral().unwrap()),
        };
        let certified_scope =
            AnalyzerQueryScope::with_outer_request(&analyzer, OuterRequest::new());
        let mut captured = Vec::new();
        for _ in 0..2 {
            let ledger = Arc::new(brokk_bifrost_analysis::analyzer::read_ledger::ReadLedger::new());
            {
                let _capture = AnalyzerQueryScope::with_read_ledger(&analyzer, Arc::clone(&ledger));
                certified.jvm_reader(&active).expect("certified reader");
            }
            assert!(!ledger.reuse_refused());
            captured.push(ledger.keys().into_iter().filter(|key| matches!(key, brokk_bifrost_analysis::analyzer::read_ledger::ReadKey::Lookup { kind: brokk_bifrost_analysis::analyzer::read_ledger::LookupKind::ExternalSelection, .. })).collect::<Vec<_>>());
        }
        assert_eq!(captured[0], captured[1]);
        assert_eq!(captured[0].len(), 2);
        let retained =
            brokk_bifrost_analysis::analyzer::common::complete_query_cache_fill(&analyzer, || {
                certified.jvm_reader(&active).is_ok()
            });
        assert_eq!(retained, Ok(true));
        drop(certified_scope);
        let mixed = JvmRequestRowReaderSource {
            questions_digest: Default::default(),
            authority: Arc::new(CertifiedAuthority(
                JvmSelectionAuthority {
                    config: hermetic_jvm_config(),
                    project: Arc::clone(&project),
                    digests: super::super::external::test_digests(),
                    verifications: Arc::new(Default::default()),
                },
                false,
            )),
            project: Arc::clone(&project),
            catalog: catalog.pinned_catalog_source(
                &brokk_bifrost_analysis::analyzer::store::cache_budget::StoreCacheBudget::new(
                    &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
                ),
            ),
            store: Arc::new(AnalyzerStore::open_ephemeral().unwrap()),
        };
        {
            let _scope = AnalyzerQueryScope::with_outer_request(&analyzer, OuterRequest::new());
            let ledger = Arc::new(brokk_bifrost_analysis::analyzer::read_ledger::ReadLedger::new());
            {
                let _capture = AnalyzerQueryScope::with_read_ledger(&analyzer, Arc::clone(&ledger));
                mixed
                    .jvm_reader(&active)
                    .expect("mixed certification reader");
            }
            assert!(ledger.request_pinned_dependences() > 0);
            assert!(ledger.keys_satisfy(|key| !matches!(key, brokk_bifrost_analysis::analyzer::read_ledger::ReadKey::Lookup { kind: brokk_bifrost_analysis::analyzer::read_ledger::LookupKind::ExternalSelection, .. })));
            assert_eq!(
                brokk_bifrost_analysis::analyzer::common::complete_query_cache_fill(
                    &analyzer,
                    || mixed.jvm_reader(&active).is_ok()
                ),
                Err(true)
            );
        }
        // An ordinary row question through the request owner observes the
        // running operation's cancellation even though it passes no token.
        let reader = source.jvm_reader(&active).expect("bound JVM reader").reader;
        for explicit_stops in [true, false] {
            let stopping = CancellationToken::cancel_after_checks_for_test(8);
            let continuing = CancellationToken::new();
            let (explicit, operation) = if explicit_stops {
                (&stopping, &continuing)
            } else {
                (&continuing, &stopping)
            };
            let scope = AnalyzerQueryScope::with_cancellation(&analyzer, operation);
            let answer = CatalogRowReader::owned_rows(
                reader.as_ref(),
                "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<100) SELECT x FROM n",
                &[],
                explicit,
            );
            let open =
                brokk_bifrost_analysis::analyzer::store::model_catalog::semantic_catalog_question(
                    "cancellation",
                    (),
                    answer,
                )
                .unwrap_err();
            assert!(open.is_cancellation());
            let content = FamilyOpen::jvm("busy");
            assert!(content.merge(open).is_cancellation());
            assert!(open.merge(content).is_cancellation());
            assert!(matches!(brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelOverlayBuildError::from(open), brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelOverlayBuildError::Cancelled));
            assert_eq!(
                scope.read_completion(),
                Err(brokk_bifrost_analysis::analyzer::QueryReadIncomplete::Cancelled)
            );
            drop(scope);
            let fresh_scope =
                AnalyzerQueryScope::with_outer_request(&analyzer, OuterRequest::new());
            let fresh = source
                .jvm_reader(&active)
                .expect("new request can read after cancellation");
            assert_eq!(
                CatalogRowReader::owned_rows(
                    fresh.reader.as_ref(),
                    "SELECT 1",
                    &[],
                    &CancellationToken::new()
                )
                .unwrap()
                .rows
                .len(),
                1
            );
            drop(fresh_scope);
        }
        let token = CancellationToken::new();
        let _cancellable = AnalyzerQueryScope::with_cancellation(&analyzer, &token);
        token.cancel();
        assert!(matches!(
            (reader.as_ref() as &dyn CatalogRowReader).raw_rows(
                "SELECT t.* FROM active_catalog_declaration_types t",
                &[],
                &active.shards,
                |_| Ok(()),
            ),
            Err(CatalogError::Cancelled)
        ));
    }

    #[test]
    #[expect(
        clippy::disallowed_methods,
        reason = "#12820: non-answer (writer, schema, GC or diagnostics); must not produce answers"
    )]
    fn activation_binding_shares_one_request_and_reads_status_without_writing() {
        use brokk_bifrost_analysis::analyzer::store::active_models::{
            MatcherIndexes, SemanticModelActivationReport,
        };
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct Authority {
            project: Arc<dyn Project>,
            fills: AtomicUsize,
            failed_capture: bool,
        }
        impl ExternalSelectionAuthority for Authority {
            fn basis(
                &self,
                _question: &brokk_bifrost_core::analyzer::external_selection::ExternalSelectionQuestion,
                _answer: [u8; 32],
            ) -> Option<brokk_bifrost_core::analyzer::external_selection::JvmDependencyBasis>
            {
                None
            }
            fn answer_under_basis(
                &self,
                _question: &brokk_bifrost_core::analyzer::external_selection::ExternalSelectionQuestion,
                _basis: &brokk_bifrost_core::analyzer::external_selection::JvmDependencyBasis,
            ) -> Option<[u8; 32]> {
                None
            }

            fn questions(&self) -> Vec<ExternalSelectionQuestion> {
                vec![
                    ExternalSelectionQuestion {
                        kind: ExternalSelectionQuestionKind::Dependencies,
                        digest: [1; 32],
                        uncertified: false,
                    },
                    ExternalSelectionQuestion {
                        kind: ExternalSelectionQuestionKind::Jdk,
                        digest: [2; 32],
                        uncertified: true,
                    },
                ]
            }
            fn answer(
                &self,
                request: &OuterRequest,
                question: &ExternalSelectionQuestion,
                _: &SelectionRetry,
                _cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
            ) -> Result<Arc<VerifiedSelection>, SelectionRefused> {
                request.external_selection(self.project.as_ref(), question.digest, || {
                    self.fills.fetch_add(1, Ordering::SeqCst);
                    let records: Arc<dyn std::any::Any + Send + Sync> = match question.kind {
                        ExternalSelectionQuestionKind::RustToolchain => {
                            unreachable!("JVM question")
                        }
                        ExternalSelectionQuestionKind::Dependencies => Arc::new(
                            (!self.failed_capture)
                                .then(ExternalInventorySelection::empty_for_catalog_reader_test),
                        ),
                        ExternalSelectionQuestionKind::Jdk => Arc::new(
                            super::super::external::JvmExternalDeclarationIndex::select_jdk(
                                &hermetic_jvm_config(),
                                self.project.as_ref(),
                                &super::super::external::test_digests(),
                                None,
                            )
                            .unwrap(),
                        ),
                    };
                    Ok(VerifiedSelection {
                        question_digest: question.digest,
                        answer_digest: question.digest,
                        view_stamp: self.project.view_stamp(),
                        verified: false,
                        certified: false,
                        complete: !self.failed_capture,
                        only_replayable_gaps: false,
                        records,
                    })
                })
            }
        }
        let root = tempfile::tempdir().unwrap();
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root.path(), Language::Java));
        let authority = Authority {
            project: Arc::clone(&project),
            fills: AtomicUsize::new(0),
            failed_capture: false,
        };
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let activation = ResolvedActiveSemanticModels::new(
            "empty-jvm-activation".into(),
            None,
            Vec::new(),
            MatcherIndexes::default(),
            Vec::new(),
            Default::default(),
            Default::default(),
            SemanticModelActivationReport::default(),
        );
        let source = JvmRequestRowReaderSource {
            questions_digest: Default::default(),
            authority: Arc::new(JvmSelectionAuthority {
                config: hermetic_jvm_config(),
                project: Arc::clone(&project),
                digests: super::super::external::test_digests(),
                verifications: Arc::new(Default::default()),
            }),
            project: Arc::clone(&project),
            catalog: catalog.pinned_catalog_source(
                &brokk_bifrost_analysis::analyzer::store::cache_budget::StoreCacheBudget::new(
                    &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
                ),
            ),
            store: Arc::new(AnalyzerStore::open_ephemeral().unwrap()),
        };
        assert_eq!(
            source.jvm_reader(&activation).err(),
            Some(FamilyOpen::jvm("no request scope"))
        );
        let get = |request: Option<&OuterRequest>| {
            jvm_catalog_reader_for_request(
                &authority,
                &activation,
                request,
                Arc::clone(&project),
                &catalog.pinned_catalog_source(
                    &brokk_bifrost_analysis::analyzer::store::cache_budget::StoreCacheBudget::new(
                        &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
                    ),
                ),
                &store,
                false,
                CancellationToken::new(),
            )
            .unwrap()
        };
        assert!(matches!(get(None), JvmCatalogReaderAccess::Unavailable(_)));
        let first_request = OuterRequest::new();
        let JvmCatalogReaderAccess::Ready(first) = get(Some(&first_request)) else {
            panic!("first reader unavailable")
        };
        assert_eq!(first.provider_outcomes(), Some(Vec::new()));
        let JvmCatalogReaderAccess::Ready(shared) = get(Some(&first_request)) else {
            panic!("shared reader unavailable")
        };
        assert!(Arc::ptr_eq(&first, &shared));
        assert_eq!(authority.fills.load(Ordering::SeqCst), 2);
        let second_request = OuterRequest::new();
        let JvmCatalogReaderAccess::Ready(other) = get(Some(&second_request)) else {
            panic!("second reader unavailable")
        };
        assert!(!Arc::ptr_eq(&first, &other));
        assert_eq!(authority.fills.load(Ordering::SeqCst), 4);
        let count: i64 = store
            .read_conn()
            .unwrap()
            .query_row(
                "SELECT count(*) FROM jvm_external_provider_publications",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
        let failed_authority = Authority {
            project: Arc::clone(&project),
            fills: AtomicUsize::new(0),
            failed_capture: true,
        };
        // #10470 M2: missing capture records keep the selection incomplete.
        let failed_request = OuterRequest::new();
        assert!(matches!(
            jvm_catalog_reader_for_request(
                &failed_authority,
                &activation,
                Some(&failed_request),
                Arc::clone(&project),
                &catalog.pinned_catalog_source(
                    &brokk_bifrost_analysis::analyzer::store::cache_budget::StoreCacheBudget::new(
                        &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests()
                    )
                ),
                &store,
                false,
                CancellationToken::new(),
            )
            .unwrap(),
            JvmCatalogReaderAccess::SelectionIncomplete
        ));
        assert_eq!(failed_authority.fills.load(Ordering::SeqCst), 1);
        first_request.close();
        assert!(matches!(
            get(Some(&first_request)),
            JvmCatalogReaderAccess::Closed
        ));
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#9559: a PartialCoverage selection refused reuse, so every search refilled (82-90 s CPU) and 168 of 1615 policy units were recomputed on JSON-java"
    )]
    fn partial_coverage_selection_records_external_selection_key_bound_to_pack_and_gap_set() {
        use brokk_bifrost_analysis::analyzer::read_ledger::{LookupKind, ReadKey, ReadLedger};
        use brokk_bifrost_analysis::analyzer::semantic_model::catalog::{
            SessionPackSource, SessionPackSourceKind,
        };
        use brokk_bifrost_analysis::analyzer::semantic_model::runtime::{
            SemanticModelActivationEvidence, SemanticModelActivationRequest,
            SemanticModelResolutionOutcome, resolve_active_semantic_models,
        };
        use brokk_bifrost_analysis::analyzer::semantic_model::{
            AuthoredSemanticModelPack, CompilerOptions, compile_pack,
        };
        struct CertifiedAuthority(Authority);
        impl ExternalSelectionAuthority for CertifiedAuthority {
            fn basis(
                &self,
                _question: &brokk_bifrost_core::analyzer::external_selection::ExternalSelectionQuestion,
                _answer: [u8; 32],
            ) -> Option<brokk_bifrost_core::analyzer::external_selection::JvmDependencyBasis>
            {
                None
            }
            fn answer_under_basis(
                &self,
                _question: &brokk_bifrost_core::analyzer::external_selection::ExternalSelectionQuestion,
                _basis: &brokk_bifrost_core::analyzer::external_selection::JvmDependencyBasis,
            ) -> Option<[u8; 32]> {
                None
            }

            fn questions(&self) -> Vec<ExternalSelectionQuestion> {
                self.0.questions()
            }
            fn answer(
                &self,
                request: &OuterRequest,
                question: &ExternalSelectionQuestion,
                retry: &SelectionRetry,
                cancellation: &CancellationToken,
            ) -> Result<Arc<VerifiedSelection>, SelectionRefused> {
                let original = self.0.answer(request, question, retry, cancellation)?;
                Ok(Arc::new(VerifiedSelection {
                    verified: true,
                    certified: original.complete,
                    complete: original.complete,
                    only_replayable_gaps: original.only_replayable_gaps,
                    question_digest: original.question_digest,
                    answer_digest: original.answer_digest,
                    view_stamp: original.view_stamp.clone(),
                    records: Arc::clone(&original.records),
                }))
            }
        }
        /// What one bind of a catalog with the given partial packs produced.
        struct Bound {
            gap_ids: Vec<String>,
            dependencies: brokk_bifrost_core::analyzer::outer_request::AdmittedSelection,
            models: String,
            binding: ReaderBinding,
            reuse_refused: bool,
            keys: Vec<([u8; 32], [u8; 32])>,
            authority_digests: Vec<[u8; 32]>,
        }
        /// Each pack is (pack id, name of the one type it declares), so two
        /// binds can differ in pack content with the same gap set.
        fn bind(packs: &[(&str, &str)]) -> Bound {
            let root = tempfile::tempdir().unwrap();
            let (_, catalog, key, mut source, _) = generated_jvm_source(root.path());
            for (pack_id, type_name) in packs {
                let mut authored: serde_json::Value =
                    serde_json::from_slice(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/../bifrost-analysis/testdata/semantic-model-packs/declarations-v1.json"
                    )))
                    .unwrap();
                authored["schema_version"] = serde_json::json!(
                    brokk_bifrost_analysis::analyzer::semantic_model::SEMANTIC_MODEL_SCHEMA_VERSION
                );
                authored["compatibility"] = serde_json::json!({});
                authored["pack_id"] = serde_json::json!(pack_id);
                authored["completeness"] = serde_json::json!("partial");
                authored["shards"][0]["activation"] = serde_json::json!([{}]);
                authored["shards"][0]["payload"]["types"][0]["name"] = serde_json::json!(type_name);
                let pack = compile_pack(
                    &serde_json::from_value::<AuthoredSemanticModelPack>(authored).unwrap(),
                    &CompilerOptions::default(),
                )
                .unwrap();
                catalog
                    .register_compiled_pack(
                        &pack,
                        &SessionPackSource {
                            kind: SessionPackSourceKind::Embedded,
                            source_id: format!("partial-coverage-test-{pack_id}"),
                        },
                    )
                    .unwrap();
            }
            let request = SemanticModelActivationRequest {
                host_activation: brokk_bifrost_analysis::analyzer::semantic_model::HostActivationContext::library_none(),
                bifrost_version: semver::Version::new(0, 15, 1),
                evidence: vec![SemanticModelActivationEvidence {
                    language: "java".into(),
                    ecosystem: "maven".into(),
                    package: None,
                    module: None,
                    toolchain: None,
                    target: None,
                    configuration: None,
                    production_input_digest: None,
                    verified_raw_artifacts: Vec::new(),
                }],
                approximate_standard_libraries: Vec::new(),
                controls: Vec::new(),
                limits: Default::default(),
            };
            let SemanticModelResolutionOutcome::Ready(active) =
                resolve_active_semantic_models(&catalog, &request, &CancellationToken::new())
            else {
                panic!("partial packs activate")
            };
            source.authority = Arc::new(CertifiedAuthority(Authority {
                project: Arc::clone(&source.project),
                key,
                complete: true,
            }));
            let analyzer = crate::analyzer::java::JavaAnalyzer::new(Arc::clone(&source.project));
            let ledger = Arc::new(ReadLedger::new());
            let outer = OuterRequest::new();
            let _request = AnalyzerQueryScope::with_outer_request(&analyzer, Arc::clone(&outer));
            let _capture = AnalyzerQueryScope::with_read_ledger(&analyzer, Arc::clone(&ledger));
            let result = source
                .jvm_reader(&active)
                .expect("partial coverage remains readable");
            let JvmCatalogReaderAccess::Ready(handle) = jvm_catalog_reader_for_request(
                source.authority.as_ref(),
                &active,
                Some(&outer),
                Arc::clone(&source.project),
                &source.catalog,
                &source.store,
                false,
                CancellationToken::new(),
            )
            .unwrap() else {
                panic!("partial reader admitted")
            };
            // What the read-key validator does on the next run: ask the
            // authority again, in a request of its own.
            let authority_digests = source
                .authority
                .questions()
                .iter()
                .map(|question| {
                    let answer = source
                        .authority
                        .answer(
                            &OuterRequest::new(),
                            question,
                            &SelectionRetry::default(),
                            &CancellationToken::new(),
                        )
                        .unwrap();
                    assert!(answer.complete && answer.certified);
                    answer.answer_digest
                })
                .collect();
            Bound {
                gap_ids: result
                    .reader
                    .jvm_dependency_gaps()
                    .iter()
                    .map(|gap| {
                        assert_eq!(gap.cause, JvmDependencyGapCause::PartialCoverage);
                        gap.dependency_id.clone()
                    })
                    .collect(),
                dependencies: handle.key().dependencies.clone(),
                models: active.active_model_set_hash().to_owned(),
                binding: result.binding,
                reuse_refused: ledger.reuse_refused(),
                keys: ledger
                    .keys()
                    .iter()
                    .filter_map(|key| match key {
                        ReadKey::Lookup {
                            kind: LookupKind::ExternalSelection,
                            question:
                                brokk_bifrost_analysis::analyzer::read_ledger::LookupQuestion::ExternalSelection {
                                    question_digest,
                                },
                            digest,
                        } => Some((*question_digest, *digest.as_bytes())),
                        _ => None,
                    })
                    .collect(),
                authority_digests,
            }
        }
        let base = bind(&[("test.partial-coverage", "com.acme.Widget")]);
        // The selection is replayable and not complete, so not certified: absence
        // is not provable, and the gap stays visible to every reader.
        assert!(!base.dependencies.certified);
        assert!(!base.dependencies.complete);
        assert!(base.dependencies.replayable);
        assert_eq!(base.gap_ids.len(), 1, "{:?}", base.gap_ids);
        assert!(!base.reuse_refused);
        // Each key names the digest the authority answers on the next run, not
        // the gap-extended digest this request is bound to.
        assert_eq!(base.keys.len(), 2, "{:?}", base.keys);
        for ((question, digest), authority) in base.keys.iter().zip(&base.authority_digests) {
            assert_eq!(digest, authority, "{question:?}");
        }
        assert_ne!(
            base.dependencies.answer_digest, base.dependencies.authority_answer_digest,
            "the bound answer includes the gap set"
        );

        // A second run over the same inputs binds and records the same.
        let again = bind(&[("test.partial-coverage", "com.acme.Widget")]);
        assert_eq!(again.keys, base.keys);
        assert_eq!(
            again.dependencies.answer_digest,
            base.dependencies.answer_digest
        );
        assert_eq!(again.binding, base.binding);

        // Changed pack content moves the active model set, which unit keys and
        // `ReadKey::Models` carry, and the request's reader binding.
        let changed = bind(&[("test.partial-coverage", "com.acme.Gadget")]);
        assert_ne!(changed.models, base.models);
        assert_ne!(changed.binding, base.binding);
        assert!(!changed.reuse_refused);

        // A different set of partial shards moves the gap set and so the bound
        // answer, even though the authority answers the same.
        let wider = bind(&[
            ("test.partial-coverage", "com.acme.Widget"),
            ("test.partial-coverage-two", "com.acme.Other"),
        ]);
        assert_eq!(wider.gap_ids.len(), 2, "{:?}", wider.gap_ids);
        assert_ne!(
            wider.dependencies.answer_digest,
            base.dependencies.answer_digest
        );
        assert_ne!(wider.models, base.models);
        assert_ne!(wider.binding, base.binding);
        assert_eq!(wider.keys, base.keys);
    }

    #[test]
    fn request_owner_admits_only_gaps() {
        use super::super::external::{
            ExternalSelectionFailure as Failure, JvmExternalDeclarationIndex,
        };
        struct CauseAuthority {
            project: Arc<dyn Project>,
            failures: Vec<fn() -> Failure>,
            filesystem: Option<JvmAnalyzerConfig>,
            jdk_complete: bool,
            jdk_certified: bool,
        }
        impl ExternalSelectionAuthority for CauseAuthority {
            fn basis(
                &self,
                _question: &brokk_bifrost_core::analyzer::external_selection::ExternalSelectionQuestion,
                _answer: [u8; 32],
            ) -> Option<brokk_bifrost_core::analyzer::external_selection::JvmDependencyBasis>
            {
                None
            }
            fn answer_under_basis(
                &self,
                _question: &brokk_bifrost_core::analyzer::external_selection::ExternalSelectionQuestion,
                _basis: &brokk_bifrost_core::analyzer::external_selection::JvmDependencyBasis,
            ) -> Option<[u8; 32]> {
                None
            }

            fn questions(&self) -> Vec<ExternalSelectionQuestion> {
                [
                    ExternalSelectionQuestionKind::Dependencies,
                    ExternalSelectionQuestionKind::Jdk,
                ]
                .into_iter()
                .enumerate()
                .map(|(i, kind)| ExternalSelectionQuestion {
                    kind,
                    digest: [i as u8; 32],
                    uncertified: false,
                })
                .collect()
            }
            fn answer(
                &self,
                _: &OuterRequest,
                question: &ExternalSelectionQuestion,
                _: &SelectionRetry,
                _: &CancellationToken,
            ) -> Result<Arc<VerifiedSelection>, SelectionRefused> {
                let dependency = question.kind == ExternalSelectionQuestionKind::Dependencies;
                let records: Arc<dyn std::any::Any + Send + Sync> = if dependency {
                    let mut selection = if let Some(config) = &self.filesystem {
                        JvmExternalDeclarationIndex::select_external_inventory(
                            config,
                            self.project.as_ref(),
                            &super::super::dependency_discovery::manifest_scope(
                                self.project.as_ref(),
                                config,
                            ),
                            |_| Ok::<_, std::convert::Infallible>(()),
                        )
                        .unwrap()
                    } else {
                        ExternalInventorySelection::empty_for_catalog_reader_test()
                    };
                    for failure in &self.failures {
                        selection.completeness.record(failure());
                    }
                    Arc::new(Some(selection))
                } else {
                    Arc::new(
                        JvmExternalDeclarationIndex::select_jdk(
                            &hermetic_jvm_config(),
                            self.project.as_ref(),
                            &super::super::external::test_digests(),
                            None,
                        )
                        .unwrap(),
                    )
                };
                Ok(Arc::new(VerifiedSelection {
                    question_digest: question.digest,
                    answer_digest: question.digest,
                    view_stamp: self.project.view_stamp(),
                    verified: dependency || self.jdk_certified,
                    certified: !dependency && self.jdk_complete && self.jdk_certified,
                    complete: !dependency && self.jdk_complete,
                    only_replayable_gaps: dependency
                        && records
                            .downcast_ref::<Option<ExternalInventorySelection>>()
                            .is_some_and(|selection| {
                                selection.as_ref().is_some_and(|selection| {
                                    selection.completeness.only_replayable_gaps()
                                })
                            }),
                    records,
                }))
            }
        }
        let missing: fn() -> Failure = || {
            Failure::DependencyGaps(vec![JvmDependencyGap::unresolved(
                "g:missing:1".to_owned(),
                Vec::new(),
            )])
        };
        let partial: fn() -> Failure = || Failure::PartialManifest("pom.xml".into());
        let unreadable: fn() -> Failure =
            || Failure::UnreadableProbe("blocked/artifact.jar".into());
        // Selection-level causes isolate the admission contract from discovery's filesystem recipes.
        type AdmissionCase = (&'static str, Vec<fn() -> Failure>, bool, bool, bool);
        let cases: Vec<AdmissionCase> = vec![
            ("missing", vec![missing], true, true, true),
            (
                "discovery limit",
                vec![|| Failure::Discovery],
                true,
                true,
                false,
            ),
            (
                "discovery error",
                vec![|| Failure::Discovery],
                true,
                true,
                false,
            ),
            (
                "suppressed",
                vec![missing, || Failure::Discovery],
                true,
                true,
                false,
            ),
            ("partial", vec![partial], true, true, false),
            (
                "read",
                vec![|| Failure::ArtifactRead("blocked/a.jar".into())],
                true,
                true,
                false,
            ),
            ("missing jdk uncertified", vec![missing], true, false, false),
            ("probe", vec![unreadable], true, true, false),
            ("missing partial", vec![missing, partial], true, true, false),
            (
                "missing probe",
                vec![missing, unreadable],
                true,
                true,
                false,
            ),
            ("jdk incomplete", vec![missing], false, true, false),
            ("jdk uncertified", vec![missing], true, false, false),
        ];
        let mut cases = cases;
        for (name, admitted) in [
            ("filesystem missing", true),
            ("filesystem removed", true),
            ("filesystem prior warning", true),
            ("filesystem malformed", false),
            // Windows reports a path below a regular file as not found, so the
            // probe is absent rather than unreadable and the missing jar is
            // the sole failure.
            ("filesystem probe", cfg!(windows)),
        ] {
            cases.push((name, Vec::new(), true, true, admitted));
        }
        for (name, failures, jdk_complete, jdk_certified, admitted) in cases {
            let root = tempfile::tempdir().unwrap();
            let (_, catalog, _, mut source, mut active) = generated_jvm_source(root.path());
            let project = Arc::clone(&source.project);
            let analyzer = crate::analyzer::java::JavaAnalyzer::new_with_config(
                Arc::clone(&project),
                hermetic_analyzer_config(),
            );
            let mut retained_index = None;
            let filesystem = name.starts_with("filesystem").then(|| {
                use brokk_bifrost_core::analyzer::config::{
                    JvmExternalDependencies, JvmMavenCoordinate,
                };
                let repository = root.path().join("repository");
                std::fs::create_dir_all(&repository).unwrap();
                if name == "filesystem malformed" {
                    std::fs::write(root.path().join("pom.xml"), "<project><broken>").unwrap();
                }
                if name == "filesystem probe" {
                    std::fs::write(repository.join("g"), "not a directory").unwrap();
                }
                let config = JvmAnalyzerConfig {
                    external_dependencies: JvmExternalDependencies {
                        coordinates: vec![JvmMavenCoordinate::new("g", "missing", "1")],
                        repository_roots: vec![repository.clone()],
                        ..Default::default()
                    },
                    ..Default::default()
                };
                if name == "filesystem removed" {
                    let jar = repository.join("g/missing/1/missing-1.jar");
                    std::fs::create_dir_all(jar.parent().unwrap()).unwrap();
                    zip::ZipWriter::new(std::fs::File::create(&jar).unwrap())
                        .finish()
                        .unwrap();
                    retained_index = Some(JvmExternalDeclarationIndex::build_for_project(
                        &config,
                        project.as_ref(),
                    ));
                    std::fs::remove_file(jar).unwrap();
                }
                config
            });
            let authority = CauseAuthority {
                filesystem,
                project: Arc::clone(&project),
                failures,
                jdk_complete,
                jdk_certified,
            };
            let ledger = Arc::new(brokk_bifrost_analysis::analyzer::read_ledger::ReadLedger::new());
            source.authority = Arc::new(authority);
            let _request = AnalyzerQueryScope::with_outer_request(&analyzer, OuterRequest::new());
            let _capture = AnalyzerQueryScope::with_read_ledger(&analyzer, Arc::clone(&ledger));
            let result = source.jvm_reader(&active);
            assert_eq!(
                result.is_ok(),
                admitted,
                "{name}: {:?}",
                result.as_ref().err()
            );
            if admitted {
                drop(_capture);
                // The probes are host paths from the filesystem cases; the
                // contract here is which coordinate is the gap, and why.
                let expected = ("g:missing:1", "unresolved");
                assert_eq!(
                    result
                        .unwrap()
                        .reader
                        .jvm_dependency_gaps()
                        .iter()
                        .map(|gap| (gap.dependency_id.as_str(), gap.cause_label()))
                        .collect::<Vec<_>>(),
                    [expected],
                    "{name}"
                );
                use brokk_bifrost_analysis::analyzer::semantic_model::catalog::{
                    SessionPackSource, SessionPackSourceKind,
                };
                use brokk_bifrost_analysis::analyzer::semantic_model::runtime::{
                    SemanticModelActivationEvidence, SemanticModelActivationRequest,
                    SemanticModelResolutionOutcome, SemanticModelRuntimeLimits,
                    resolve_active_semantic_models,
                };
                use brokk_bifrost_analysis::analyzer::semantic_model::{
                    AuthoredSemanticModelPack, CompilerOptions, compile_pack,
                };
                let mut authored: serde_json::Value =
                    serde_json::from_slice(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/../bifrost-analysis/testdata/semantic-model-packs/declarations-v1.json"
                    )))
                    .unwrap();
                authored["schema_version"] = serde_json::json!(
                    brokk_bifrost_analysis::analyzer::semantic_model::SEMANTIC_MODEL_SCHEMA_VERSION
                );
                authored["compatibility"] = serde_json::json!({});
                authored["ecosystem"] = serde_json::json!("jdk");
                authored["shards"][0]["activation"] = serde_json::json!([{}]);
                authored["shards"][0]["payload"]["types"][0]["name"] =
                    serde_json::json!("java.test.Widget");
                authored["shards"][0]["payload"]["types"][0]["hierarchy"] = serde_json::json!([]);
                let pack = compile_pack(
                    &serde_json::from_value::<AuthoredSemanticModelPack>(authored).unwrap(),
                    &CompilerOptions::default(),
                )
                .unwrap();
                catalog
                    .register_compiled_pack(
                        &pack,
                        &SessionPackSource {
                            kind: SessionPackSourceKind::Embedded,
                            source_id: "10470-test-jdk".into(),
                        },
                    )
                    .unwrap();
                let activation = SemanticModelActivationRequest {
                    host_activation: brokk_bifrost_analysis::analyzer::semantic_model::HostActivationContext::library_none(),
                    bifrost_version: semver::Version::new(0, 15, 2),
                    approximate_standard_libraries: Vec::new(),
                    evidence: vec![SemanticModelActivationEvidence {
                        language: "java".into(),
                        ecosystem: "jdk".into(),
                        package: None,
                        module: None,
                        toolchain: None,
                        target: None,
                        configuration: None,
                        production_input_digest: None,
                        verified_raw_artifacts: Vec::new(),
                    }],
                    controls: Vec::new(),
                    limits: SemanticModelRuntimeLimits::default(),
                };
                let SemanticModelResolutionOutcome::Ready(resolved) =
                    resolve_active_semantic_models(
                        &catalog,
                        &activation,
                        &CancellationToken::new(),
                    )
                else {
                    panic!("JDK fixture activation ready")
                };
                active = resolved;
                source.catalog = catalog.pinned_catalog_source(
                    &brokk_bifrost_analysis::analyzer::store::cache_budget::StoreCacheBudget::new(
                        &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
                    ),
                );
                active
                    .install_request_source(Some(Arc::new(source)))
                    .unwrap();
                let overlay = Arc::new(brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay::build(
                    &analyzer, &Arc::new(active), &CancellationToken::new(), 64 << 20,
                    &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
                ).unwrap());
                let _lookup_capture =
                    AnalyzerQueryScope::with_read_ledger(&analyzer, Arc::clone(&ledger));
                let index = retained_index
                    .unwrap_or_else(|| Arc::new(JvmExternalDeclarationIndex::default()));
                let mut index = index;
                if name == "filesystem prior warning" {
                    Arc::get_mut(&mut index).unwrap().add_discovery_gap_for_catalog_reader_test(
                        brokk_bifrost_analysis::analyzer::semantic_model::dependency::DependencyPackDiagnostic {
                            severity: brokk_bifrost_analysis::analyzer::semantic_model::dependency::DependencyPackDiagnosticSeverity::Warning,
                            code: super::super::producer_codes::KOTLIN_CLASSIFICATION_INCOMPLETE.code.into(),
                            dependency_id: Some("g:missing:1".into()), location: None,
                            message: "retained Kotlin classification warning".into(),
                        });
                }
                let gaps = std::cell::RefCell::new(Vec::new());
                let recorder = super::super::external::QueryGapRecorder::collecting(&gaps);
                if name == "filesystem removed" {
                    super::super::external::JvmExternalDeclarations::new(index.as_ref(), None)
                        .get(&recorder, "g.Missing");
                    assert!(!format!("{:?}", gaps.borrow()).contains("g:missing:1"));
                    gaps.borrow_mut().clear();
                }
                let surface = super::super::external::JvmExternalDeclarations::new(
                    index.as_ref(),
                    Some(overlay),
                );
                let owner = surface
                    .resolve_canonical_jdk_owner("java.test.Widget")
                    .expect("unshadowable JDK fixture owner");
                assert!(
                    surface
                        .resolve_model_signature_type(&recorder, "java.test.Widget", Some(&owner))
                        .is_some()
                );
                assert!(
                    !format!("{:?}", gaps.borrow()).contains(expected.0),
                    "{name}: JDK lookup {:?}",
                    gaps.borrow()
                );
                // A miss records nothing by itself; the lookup that is the whole
                // outcome records it.
                surface.or_record_miss(&recorder, surface.get(&recorder, "g.Missing"));
                assert!(
                    format!("{:?}", gaps.borrow()).contains(expected.0),
                    "{name}: {:?}",
                    gaps.borrow()
                );
            }
            // The only dependency gaps these cases admit are an unresolved
            // coordinate and a dependency past the artifact cap. Both are
            // fixed for unchanged inputs and the JDK is
            // complete and certified, so an admitted reader stays reusable.
            // Every other incompleteness is refused before it is bound, or
            // refuses reuse.
            let reusable = admitted;
            let refused = ledger.reuse_refused() || ledger.request_pinned_dependences() > 0;
            assert_eq!(refused, !reusable, "{name}");
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#10470: an artifact-index hit lost an unavailable request owner's typed incompleteness"
    )]
    fn artifact_hit_reports_open_request_owner() {
        use super::super::external::{
            JvmExternalDeclarationIndex, JvmExternalDeclarations, QueryGapRecorder,
        };
        use brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay;
        use brokk_bifrost_analysis::analyzer::store::model_catalog::RefusingRowReaderSource;
        use brokk_bifrost_core::analyzer::config::{JvmExternalArtifact, JvmExternalDependencies};
        use std::io::Write;
        let root = tempfile::tempdir().unwrap();
        let jar = root.path().join("present-sources.jar");
        let mut zip = zip::ZipWriter::new(std::fs::File::create(&jar).unwrap());
        zip.start_file("g/Present.java", zip::write::SimpleFileOptions::default())
            .unwrap();
        zip.write_all(b"package g; public class Present {}")
            .unwrap();
        zip.finish().unwrap();
        let index = JvmExternalDeclarationIndex::build(
            &JvmExternalDependencies {
                artifact_paths: vec![JvmExternalArtifact {
                    artifact_path: jar,
                    ..Default::default()
                }],
                ..Default::default()
            },
            root.path(),
        );
        for open in [
            FamilyOpen::jvm("JVM selection incomplete"),
            FamilyOpen::jvm_cancelled(),
        ] {
            let (_, _catalog, _, source, mut active) = generated_jvm_source(root.path());
            let analyzer = crate::analyzer::java::JavaAnalyzer::new_with_config(
                Arc::clone(&source.project),
                hermetic_analyzer_config(),
            );
            active
                .install_request_source(Some(Arc::new(RefusingRowReaderSource { reason: open })))
                .unwrap();
            let overlay = SemanticModelOverlay::build(
                &analyzer,
                &Arc::new(active),
                &CancellationToken::new(),
                64 << 20,
                &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
            )
            .unwrap();
            let gaps = std::cell::RefCell::new(Vec::new());
            let recorder = QueryGapRecorder::collecting(&gaps);
            let surface = JvmExternalDeclarations::new(&index, Some(Arc::new(overlay)));
            assert!(surface.get(&recorder, "g.Present").is_some());
            assert!(
                gaps.borrow()
                    .contains(&SemanticModelOverlay::open_read_incompleteness(open)),
                "{:?}",
                gaps.borrow()
            );
        }
    }

    /// A fixed-key generated-production authority for request-reader tests.
    struct Authority {
        project: Arc<dyn Project>,
        key: GeneratedProductionKey,
        complete: bool,
    }
    impl ExternalSelectionAuthority for Authority {
        fn basis(
            &self,
            _question: &brokk_bifrost_core::analyzer::external_selection::ExternalSelectionQuestion,
            _answer: [u8; 32],
        ) -> Option<brokk_bifrost_core::analyzer::external_selection::JvmDependencyBasis> {
            None
        }
        fn answer_under_basis(
            &self,
            _question: &brokk_bifrost_core::analyzer::external_selection::ExternalSelectionQuestion,
            _basis: &brokk_bifrost_core::analyzer::external_selection::JvmDependencyBasis,
        ) -> Option<[u8; 32]> {
            None
        }

        fn questions(&self) -> Vec<ExternalSelectionQuestion> {
            vec![
                ExternalSelectionQuestion {
                    kind: ExternalSelectionQuestionKind::Dependencies,
                    digest: [1; 32],
                    uncertified: false,
                },
                ExternalSelectionQuestion {
                    kind: ExternalSelectionQuestionKind::Jdk,
                    digest: [2; 32],
                    uncertified: true,
                },
            ]
        }
        fn answer(
            &self,
            request: &OuterRequest,
            question: &ExternalSelectionQuestion,
            _: &SelectionRetry,
            _cancellation: &CancellationToken,
        ) -> Result<Arc<VerifiedSelection>, SelectionRefused> {
            request.external_selection(self.project.as_ref(), question.digest, || {
                let records: Arc<dyn std::any::Any + Send + Sync> = match question.kind {
                    ExternalSelectionQuestionKind::RustToolchain => unreachable!("JVM question"),
                    ExternalSelectionQuestionKind::Dependencies => Arc::new(Some(
                        ExternalInventorySelection::empty_for_catalog_reader_test()
                            .with_generated_key_for_catalog_reader_test(self.key.clone()),
                    )),
                    ExternalSelectionQuestionKind::Jdk => Arc::new(
                        super::super::external::JvmExternalDeclarationIndex::select_jdk(
                            &hermetic_jvm_config(),
                            self.project.as_ref(),
                            &super::super::external::test_digests(),
                            None,
                        )
                        .unwrap(),
                    ),
                };
                Ok(VerifiedSelection {
                    question_digest: question.digest,
                    answer_digest: question.digest,
                    view_stamp: self.project.view_stamp(),
                    verified: false,
                    certified: false,
                    complete: self.complete,
                    only_replayable_gaps: false,
                    records,
                })
            })
        }
    }

    /// A generated JVM production installed in a fresh catalog under `root`,
    /// a real request source over an ephemeral analyzer store, and an empty
    /// activation.
    fn generated_jvm_source(
        root: &std::path::Path,
    ) -> (
        brokk_bifrost_analysis::analyzer::semantic_model::CompiledSemanticModelPack,
        SemanticPackCatalog,
        GeneratedProductionKey,
        JvmRequestRowReaderSource,
        ResolvedActiveSemanticModels,
    ) {
        use brokk_bifrost_analysis::analyzer::semantic_model::{
            AuthoredSemanticModelPack, CompilerOptions, compile_pack,
        };
        use brokk_bifrost_analysis::analyzer::store::active_models::{
            MatcherIndexes, SemanticModelActivationReport,
        };
        use serde_json::{Value as JsonValue, json};
        let mut source: JsonValue = serde_json::from_slice(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../bifrost-analysis/testdata/semantic-model-packs/declarations-v1.json"
        )))
        .unwrap();
        source["schema_version"] =
            json!(brokk_bifrost_analysis::analyzer::semantic_model::SEMANTIC_MODEL_SCHEMA_VERSION);
        source["compatibility"] = json!({});
        source["shards"][0]["activation"] = json!([{}]);
        let pack = compile_pack(
            &serde_json::from_value::<AuthoredSemanticModelPack>(source).unwrap(),
            &CompilerOptions::default(),
        )
        .unwrap();
        let catalog =
            SemanticPackCatalog::open(root, CatalogOpenMode::ReadWrite, CatalogOptions::default())
                .unwrap();
        let key = GeneratedProductionKey::new(
            "a".repeat(64),
            "artifact-scanner",
            fixture_producer_version("2.0.0"),
            brokk_bifrost_analysis::analyzer::semantic_model::SEMANTIC_MODEL_SCHEMA_VERSION,
        )
        .unwrap();
        let pack = brokk_bifrost_analysis::test_support::generated_pack_fixture(
            &pack,
            key.input_digest(),
            &brokk_bifrost_analysis::test_support::generated_input_slots(),
        );
        catalog
            .install_generated(
                &key,
                &pack,
                &brokk_bifrost_analysis::test_support::generated_input_slots(),
            )
            .unwrap();
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Java));
        let source = JvmRequestRowReaderSource {
            questions_digest: Default::default(),
            authority: Arc::new(Authority {
                project: Arc::clone(&project),
                key: key.clone(),
                complete: true,
            }),
            project,
            catalog: catalog.pinned_catalog_source(
                &brokk_bifrost_analysis::analyzer::store::cache_budget::StoreCacheBudget::new(
                    &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
                ),
            ),
            store: Arc::new(AnalyzerStore::open_ephemeral().unwrap()),
        };
        let activation = ResolvedActiveSemanticModels::new(
            "generated-jvm-test".into(),
            None,
            Vec::new(),
            MatcherIndexes::default(),
            Vec::new(),
            Default::default(),
            Default::default(),
            SemanticModelActivationReport::default(),
        );
        (pack, catalog, key, source, activation)
    }

    #[test]
    #[hardwon("#9559: a cold first JVM request published every provider projection")]
    fn activation_and_bind_publish_once() {
        use brokk_bifrost_analysis::analyzer::semantic_model::runtime::{
            SemanticModelActivationEvidence, SemanticModelActivationRequest,
            SemanticModelResolutionOutcome, SemanticModelRuntimeLimits,
            resolve_active_semantic_models,
        };
        for mode in [0, 1, 2] {
            let root = tempfile::tempdir().unwrap();
            let (_, catalog, _, source, empty) = generated_jvm_source(root.path());
            let request = SemanticModelActivationRequest {
                host_activation: brokk_bifrost_analysis::analyzer::semantic_model::HostActivationContext::library_none(),
                bifrost_version: semver::Version::new(0, 15, 1),
                approximate_standard_libraries: Vec::new(),
                evidence: vec![SemanticModelActivationEvidence {
                    language: "java".into(),
                    ecosystem: "maven".into(),
                    package: None,
                    module: None,
                    toolchain: None,
                    target: None,
                    configuration: None,
                    production_input_digest: Some("a".repeat(64)),
                    verified_raw_artifacts:
                        brokk_bifrost_analysis::test_support::generated_input_slots(),
                }],
                controls: Vec::new(),
                limits: SemanticModelRuntimeLimits::default(),
            };
            let SemanticModelResolutionOutcome::Ready(active) =
                resolve_active_semantic_models(&catalog, &request, &CancellationToken::new())
            else {
                panic!("production activates")
            };
            source
                .store
                .conn
                .execute(|conn| {
                    conn.execute_batch(
                        "CREATE TABLE publication_writes(count INTEGER NOT NULL);
                 INSERT INTO publication_writes VALUES(0);
                 CREATE TRIGGER count_publication_writes AFTER INSERT ON jvm_external_owners
                 BEGIN UPDATE publication_writes SET count=count+1; END;",
                    )
                })
                .unwrap();
            let writes = || {
                source
                    .store
                    .conn
                    .execute(|conn| {
                        conn.query_row("SELECT count FROM publication_writes", [], |row| {
                            row.get::<_, i64>(0)
                        })
                    })
                    .unwrap()
            };
            let bind = || {
                let analyzer =
                    crate::analyzer::java::JavaAnalyzer::new(Arc::clone(&source.project));
                let _scope = AnalyzerQueryScope::with_outer_request(&analyzer, OuterRequest::new());
                source.jvm_reader(&active).unwrap();
            };
            if mode == 2 {
                // Empty activation leaves this production request-owned.
                source
                    .publish_activation(&empty, &CancellationToken::new())
                    .unwrap();
                assert_eq!(writes(), 0);
                bind();
            } else if mode == 1 {
                let barrier = std::sync::Barrier::new(2);
                std::thread::scope(|scope| {
                    let task = scope.spawn(|| {
                        barrier.wait();
                        source
                            .publish_activation(&active, &CancellationToken::new())
                            .unwrap();
                    });
                    barrier.wait();
                    bind();
                    task.join().unwrap();
                });
            } else {
                source
                    .store
                    .conn
                    .execute(|conn| conn.execute_batch("PRAGMA query_only=ON"))
                    .unwrap();
                source
                    .publish_activation(&active, &CancellationToken::new())
                    .unwrap();
                assert_eq!(writes(), 0);
                source
                    .store
                    .conn
                    .execute(|conn| conn.execute_batch("PRAGMA query_only=OFF"))
                    .unwrap();
                let cancelled = CancellationToken::new();
                cancelled.cancel();
                assert!(matches!(
                    source.publish_activation(&active, &cancelled),
                    Err(CatalogError::Cancelled)
                ));
                assert_eq!(writes(), 0);
                source
                    .publish_activation(&active, &CancellationToken::new())
                    .unwrap();
                let before = writes();
                assert!(before > 0);
                bind();
                assert_eq!(writes(), before);
            }
            let expected = source
                .store
                .conn
                .execute(|conn| {
                    conn.query_row("SELECT count(*) FROM jvm_external_owners", [], |row| {
                        row.get::<_, i64>(0)
                    })
                })
                .unwrap();
            assert!(expected > 0);
            assert_eq!(writes(), expected);
            // A different projection identity must be replaced on activation.
            rewrite_test_certificates(
                &source.store,
                "UPDATE stale_certificate SET projection_identity=zeroblob(32)",
            );
            source
                .publish_activation(&active, &CancellationToken::new())
                .unwrap();
            assert_eq!(writes(), expected * 2);
            // A different source identity retains the existing equality contract:
            // equal rows certify availability without rewriting either rows or identity.
            rewrite_test_certificates(
                &source.store,
                "UPDATE stale_certificate SET source_identity='other-source'",
            );
            source
                .publish_activation(&active, &CancellationToken::new())
                .unwrap();
            assert_eq!(writes(), expected * 2);
            // A different identity with a conflicting certified projection stays
            // unavailable instead of overwriting a provider with different rows.
            rewrite_test_certificates(
                &source.store,
                "UPDATE stale_certificate SET projected_rows_sha256=zeroblob(32)",
            );
            source
                .publish_activation(&active, &CancellationToken::new())
                .unwrap();
            let diagnostics = active
                .report
                .publication_diagnostics
                .lock()
                .unwrap()
                .clone();
            assert!(
                diagnostics
                    .iter()
                    .any(|message| message.contains("Conflict") && message.contains("provider")),
                "{diagnostics:?}"
            );
            // A real store write error must also preserve successful activation.
            source.store.conn.execute(|conn| conn.execute_batch(
                "DELETE FROM jvm_external_provider_publications;
                 CREATE TRIGGER reject_publication BEFORE INSERT ON jvm_external_provider_publications
                 BEGIN SELECT RAISE(ABORT, 'forced publication write error'); END;"
            )).unwrap();
            source
                .publish_activation(&active, &CancellationToken::new())
                .unwrap();
            let diagnostics = active
                .report
                .publication_diagnostics
                .lock()
                .unwrap()
                .clone();
            assert!(
                diagnostics
                    .iter()
                    .any(|message| message.contains("forced publication write error")
                        && message.contains("provider")),
                "{diagnostics:?}"
            );
            assert_eq!(writes(), expected * 2);
        }
    }

    #[test]
    #[hardwon("#2887: one unresolved coordinate opened every JVM answer under the request owner")]
    fn discovery_incomplete_request_refuses_resolved_production() {
        struct PartialAuthority(Authority);
        impl ExternalSelectionAuthority for PartialAuthority {
            fn basis(
                &self,
                _question: &brokk_bifrost_core::analyzer::external_selection::ExternalSelectionQuestion,
                _answer: [u8; 32],
            ) -> Option<brokk_bifrost_core::analyzer::external_selection::JvmDependencyBasis>
            {
                None
            }
            fn answer_under_basis(
                &self,
                _question: &brokk_bifrost_core::analyzer::external_selection::ExternalSelectionQuestion,
                _basis: &brokk_bifrost_core::analyzer::external_selection::JvmDependencyBasis,
            ) -> Option<[u8; 32]> {
                None
            }

            fn questions(&self) -> Vec<ExternalSelectionQuestion> {
                self.0.questions()
            }
            fn answer(
                &self,
                request: &OuterRequest,
                question: &ExternalSelectionQuestion,
                retry: &SelectionRetry,
                cancellation: &CancellationToken,
            ) -> Result<Arc<VerifiedSelection>, SelectionRefused> {
                if question.kind == ExternalSelectionQuestionKind::Jdk {
                    return self.0.answer(request, question, retry, cancellation);
                }
                request.external_selection(self.0.project.as_ref(), question.digest, || {
                    Ok(VerifiedSelection {
                        question_digest: question.digest,
                        answer_digest: question.digest,
                        view_stamp: self.0.project.view_stamp(),
                        verified: false,
                        certified: false,
                        complete: false,
                        only_replayable_gaps: false,
                        records: Arc::new(Some(
                            ExternalInventorySelection::empty_for_catalog_reader_test()
                                .with_generated_key_for_catalog_reader_test(self.0.key.clone())
                                .with_discovery_failure_for_catalog_reader_test(),
                        )),
                    })
                })
            }
        }
        let root = tempfile::tempdir().unwrap();
        use brokk_bifrost_analysis::analyzer::semantic_model::runtime::{
            SemanticModelActivationEvidence, SemanticModelActivationRequest,
            SemanticModelResolutionOutcome, SemanticModelRuntimeLimits,
            resolve_active_semantic_models,
        };
        let (_pack, catalog, key, mut source, _) = generated_jvm_source(root.path());
        source.authority = Arc::new(PartialAuthority(Authority {
            project: Arc::clone(&source.project),
            key,
            complete: true,
        }));
        let analyzer = crate::analyzer::java::JavaAnalyzer::new(Arc::clone(&source.project));
        let activation_request = SemanticModelActivationRequest {
            host_activation: brokk_bifrost_analysis::analyzer::semantic_model::HostActivationContext::library_none(),
            bifrost_version: semver::Version::new(0, 15, 1),
            approximate_standard_libraries: Vec::new(),
            evidence: vec![SemanticModelActivationEvidence {
                language: "java".into(),
                ecosystem: "maven".into(),
                package: None,
                module: None,
                toolchain: None,
                target: None,
                configuration: None,
                production_input_digest: Some("a".repeat(64)),
                verified_raw_artifacts: brokk_bifrost_analysis::test_support::generated_input_slots(
                ),
            }],
            controls: Vec::new(),
            limits: SemanticModelRuntimeLimits::default(),
        };
        let SemanticModelResolutionOutcome::Ready(mut active) = resolve_active_semantic_models(
            &catalog,
            &activation_request,
            &CancellationToken::new(),
        ) else {
            panic!("resolved production activates")
        };
        active
            .install_request_source(Some(Arc::new(source)))
            .unwrap();
        let _scope = AnalyzerQueryScope::with_outer_request(&analyzer, OuterRequest::new());
        let overlay =
            brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay::build(
                &analyzer,
                &Arc::new(active),
                &CancellationToken::new(),
                64 << 20,
                &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
            )
            .unwrap();
        let answer = overlay.symbols_named("com.acme.Widget");
        // #10470 M2: a generic discovery failure cannot admit the resolved inventory.
        assert!(matches!(
            answer.disposition,
            brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelOverlayDisposition::Open(
                _
            )
        ));
    }

    #[test]
    #[hardwon(
        "#9559: the JVM bind admitted a provider whose projection publication was unavailable"
    )]
    fn request_source_refuses_unavailable_provider_publication() {
        let root = tempfile::tempdir().unwrap();
        let (pack, _catalog, _key, source, mut activation) = generated_jvm_source(root.path());
        // Admit the production through an evaluated exclusion, as
        // request_source_opens_family_when_provider_publication_is_not_writable
        // does, so that without the refusal this bind is Ready.
        activation.excluded_shards =
            brokk_bifrost_analysis::analyzer::store::active_models::ActivationExclusions::new(
                [(
                    pack.manifest.content_sha256.clone(),
                    "declarations.widget".into(),
                )]
                .into(),
            );
        let analyzer = crate::analyzer::java::JavaAnalyzer::new_with_config(
            Arc::clone(&source.project),
            hermetic_analyzer_config(),
        );
        let request = OuterRequest::new();
        let cancellation = CancellationToken::new();
        let selections = source
            .authority
            .questions()
            .iter()
            .map(|question| {
                source
                    .authority
                    .answer(
                        &request,
                        question,
                        &SelectionRetry::default(),
                        &cancellation,
                    )
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let jdk = selections[1].records.downcast_ref::<SelectedJdk>().unwrap();
        // The bind finds this request's handle, so its publication cache is
        // where an Unavailable outcome can be placed: a writable store always
        // produces a projection.
        let handle = open_jvm_catalog_reader(
            &request,
            Arc::clone(&source.project),
            &source.catalog,
            &selections[0],
            &selections[1],
            jdk.catalog_expectations(),
            CuratedAuthority {
                admitted_digest: activation.indexes.admission().curated,
                shards: Vec::new(),
            },
            activation_view_digest(&activation),
            cancellation,
        )
        .unwrap();
        let ordinal = handle
            .reader
            .membership
            .iter()
            .find(|row| row.kind == CatalogPackSourceKind::Generated)
            .unwrap()
            .ordinal;
        *handle.provider_outcomes.lock().unwrap() =
            Some(vec![(ordinal, ProviderPublication::Unavailable)]);
        let _scope = AnalyzerQueryScope::with_outer_request(&analyzer, request);
        assert_eq!(
            source.jvm_reader(&activation).err(),
            Some(FamilyOpen::jvm("JVM provider publication unavailable"))
        );
    }

    #[test]
    #[hardwon("#9559: conflicting provider certificates admitted a Ready reader")]
    #[expect(
        clippy::disallowed_methods,
        reason = "#12820: non-answer (writer, schema, GC or diagnostics); must not produce answers"
    )]
    fn request_source_opens_family_when_provider_publication_is_not_writable() {
        use brokk_bifrost_analysis::analyzer::store::writer::StoreWriter;
        let root = tempfile::tempdir().unwrap();
        let (pack, catalog, key, source, mut activation) = generated_jvm_source(root.path());
        let StoreWriter::Local(writer) = &source.store.conn else {
            panic!("ephemeral writer")
        };
        writer
            .lock()
            .unwrap()
            .execute_batch("PRAGMA query_only=ON")
            .unwrap();
        let analyzer = crate::analyzer::java::JavaAnalyzer::new_with_config(
            Arc::clone(&source.project),
            hermetic_analyzer_config(),
        );
        let incomplete = JvmRequestRowReaderSource {
            questions_digest: Default::default(),
            authority: Arc::new(Authority {
                project: Arc::clone(&source.project),
                key: key.clone(),
                complete: false,
            }),
            project: Arc::clone(&source.project),
            catalog: source.catalog.clone(),
            store: Arc::clone(&source.store),
        };
        {
            let _scope = AnalyzerQueryScope::with_outer_request(&analyzer, OuterRequest::new());
            assert_eq!(
                incomplete.jvm_reader(&activation).err(),
                Some(FamilyOpen::jvm("JVM selection incomplete"))
            );
        }
        let _scope = AnalyzerQueryScope::with_outer_request(&analyzer, OuterRequest::new());
        assert_eq!(
            source.jvm_reader(&activation).err(),
            Some(FamilyOpen::jvm("analyzer store not writable"))
        );
        drop(_scope);
        writer
            .lock()
            .unwrap()
            .execute_batch("PRAGMA query_only=OFF")
            .unwrap();
        let _scope = AnalyzerQueryScope::with_outer_request(&analyzer, OuterRequest::new());
        assert_eq!(
            source.jvm_reader(&activation).err(),
            Some(FamilyOpen::jvm("JVM selection shards unavailable"))
        );
        activation.excluded_shards =
            brokk_bifrost_analysis::analyzer::store::active_models::ActivationExclusions::new(
                [(
                    pack.manifest.content_sha256.clone(),
                    "declarations.widget".into(),
                )]
                .into(),
            );
        source
            .jvm_reader(&activation)
            .expect("evaluated exclusion permits a selected production");
        // The active hash is unchanged: membership must also key exclusions.
        activation.excluded_shards = Default::default();
        assert_eq!(
            source.jvm_reader(&activation).err(),
            Some(FamilyOpen::jvm("JVM selection shards unavailable"))
        );
        drop(_scope);
        let conflicting_key = GeneratedProductionKey::new(
            "c".repeat(64),
            "artifact-scanner",
            fixture_producer_version("2.0.0"),
            brokk_bifrost_analysis::analyzer::semantic_model::SEMANTIC_MODEL_SCHEMA_VERSION,
        )
        .unwrap();
        let pack = brokk_bifrost_analysis::test_support::generated_pack_fixture(
            &pack,
            conflicting_key.input_digest(),
            &brokk_bifrost_analysis::test_support::generated_input_slots(),
        );
        catalog
            .install_generated(
                &conflicting_key,
                &pack,
                &brokk_bifrost_analysis::test_support::generated_input_slots(),
            )
            .unwrap();
        let conflicting = JvmRequestRowReaderSource {
            questions_digest: Default::default(),
            authority: Arc::new(Authority {
                project: Arc::clone(&source.project),
                key: conflicting_key,
                complete: true,
            }),
            project: Arc::clone(&source.project),
            catalog: source.catalog.clone(),
            store: Arc::new(AnalyzerStore::open_ephemeral().unwrap()),
        };
        let _scope = AnalyzerQueryScope::with_outer_request(&analyzer, OuterRequest::new());
        assert_eq!(
            conflicting.jvm_reader(&activation).err(),
            Some(FamilyOpen::jvm("JVM selection shards unavailable"))
        );
        drop(_scope);
        activation.excluded_shards =
            brokk_bifrost_analysis::analyzer::store::active_models::ActivationExclusions::new(
                [(
                    pack.manifest.content_sha256.clone(),
                    "declarations.widget".into(),
                )]
                .into(),
            );
        {
            let _scope = AnalyzerQueryScope::with_outer_request(&analyzer, OuterRequest::new());
            conflicting
                .jvm_reader(&activation)
                .expect("identical projected rows certify another generated source");
        }
        let provider_id: String = conflicting
            .store
            .read_conn()
            .unwrap()
            .query_row(
                "SELECT semantic_sha256 FROM jvm_external_provider_publications",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let mismatched_store = Arc::new(AnalyzerStore::open_ephemeral().unwrap());
        assert_eq!(
            mismatched_store
                .publish_jvm_external_projection(
                    || Ok(Some(JvmExternalProjection {
                        provider_id: jvm_external_provider_id(&provider_id),
                        semantic_sha256: provider_id,
                        source_identity: "test:empty-projection".into(),
                        owners: Vec::new(),
                        members: Vec::new(),
                        supertypes: Vec::new(),
                    })),
                    || false,
                )
                .unwrap(),
            JvmExternalPublication::Available
        );
        let mismatched = JvmRequestRowReaderSource {
            questions_digest: Default::default(),
            store: mismatched_store,
            ..conflicting
        };
        {
            let _scope = AnalyzerQueryScope::with_outer_request(&analyzer, OuterRequest::new());
            assert_eq!(
                mismatched.jvm_reader(&activation).err(),
                Some(FamilyOpen::jvm("JVM provider certificate conflict"))
            );
        }
        let missing = JvmRequestRowReaderSource {
            questions_digest: Default::default(),
            authority: Arc::new(Authority {
                project: Arc::clone(&source.project),
                key: GeneratedProductionKey::new(
                    "b".repeat(64),
                    "artifact-scanner",
                    fixture_producer_version("2.0.0"),
                    brokk_bifrost_analysis::analyzer::semantic_model::SEMANTIC_MODEL_SCHEMA_VERSION,
                )
                .unwrap(),
                complete: true,
            }),
            project: Arc::clone(&source.project),
            catalog: source.catalog.clone(),
            store: Arc::clone(&source.store),
        };
        let _scope = AnalyzerQueryScope::with_outer_request(&analyzer, OuterRequest::new());
        assert_eq!(
            missing.jvm_reader(&activation).err(),
            Some(FamilyOpen::jvm("JVM selection shards unavailable"))
        );
    }

    #[test]
    #[hardwon(
        "#9559: an excluded generated shard's published provider, named by an active shard's semantic digest, let its declarations resolve as complete, and a request's second activation with another view was refused or reached the first view's handle"
    )]
    fn request_reader_view_holds_only_the_activation_shards() {
        use brokk_bifrost_analysis::analyzer::semantic_model::catalog::statements;
        use brokk_bifrost_analysis::analyzer::semantic_model::runtime::{
            SemanticModelActivationEvidence, SemanticModelActivationRequest,
            SemanticModelRuntimeLimits, SemanticModelRuntimeOutcome,
            acquire_active_semantic_models,
        };
        use brokk_bifrost_analysis::analyzer::semantic_model::{
            AuthoredSemanticModelPack, CompilerOptions, compile_pack,
        };
        use brokk_bifrost_analysis::analyzer::store::active_models::{
            MatcherIndexes, SemanticModelActivationReport,
        };
        use serde_json::{Value as JsonValue, json};

        // One generated production, two shards: "widget" matches the evidence and
        // "gadget" requires a package the evidence lacks, so the activation excludes it.
        let mut authored: JsonValue = serde_json::from_slice(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../bifrost-analysis/testdata/semantic-model-packs/declarations-v1.json"
        )))
        .unwrap();
        authored["schema_version"] =
            json!(brokk_bifrost_analysis::analyzer::semantic_model::SEMANTIC_MODEL_SCHEMA_VERSION);
        authored["compatibility"] = json!({});
        authored["shards"][0]["activation"] = json!([{}]);
        let gadget: JsonValue = serde_json::from_str(
            &authored["shards"][0]
                .to_string()
                .replace("widget", "gadget")
                .replace("Widget", "Gadget"),
        )
        .unwrap();
        authored["shards"].as_array_mut().unwrap().push(gadget);
        authored["shards"][1]["activation"] = json!([{
            "package": { "name": "com.acme:gadget", "version": ">=1.0.0, <2.0.0" },
            "targets": ["jvm"],
            "configurations": ["release"]
        }]);
        let pack = compile_pack(
            &serde_json::from_value::<AuthoredSemanticModelPack>(authored).unwrap(),
            &CompilerOptions::default(),
        )
        .unwrap();
        let root = tempfile::tempdir().unwrap();
        let catalog = SemanticPackCatalog::open(
            root.path(),
            CatalogOpenMode::ReadWrite,
            CatalogOptions::default(),
        )
        .unwrap();
        let key = GeneratedProductionKey::new(
            "a".repeat(64),
            "artifact-scanner",
            fixture_producer_version("2.0.0"),
            brokk_bifrost_analysis::analyzer::semantic_model::SEMANTIC_MODEL_SCHEMA_VERSION,
        )
        .unwrap();
        let pack = brokk_bifrost_analysis::test_support::generated_pack_fixture(
            &pack,
            key.input_digest(),
            &brokk_bifrost_analysis::test_support::generated_input_slots(),
        );
        catalog
            .install_generated(
                &key,
                &pack,
                &brokk_bifrost_analysis::test_support::generated_input_slots(),
            )
            .unwrap();
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root.path(), Language::Java));
        let analyzer = crate::analyzer::java::JavaAnalyzer::new_with_config(
            Arc::clone(&project),
            hermetic_analyzer_config(),
        );
        let request = SemanticModelActivationRequest {
            host_activation: brokk_bifrost_analysis::analyzer::semantic_model::HostActivationContext::library_none(),
            bifrost_version: semver::Version::new(0, 15, 1),
            approximate_standard_libraries: Vec::new(),
            evidence: vec![SemanticModelActivationEvidence {
                language: "java".into(),
                ecosystem: "maven".into(),
                package: None,
                module: None,
                toolchain: None,
                target: None,
                configuration: None,
                production_input_digest: Some("a".repeat(64)),
                verified_raw_artifacts: brokk_bifrost_analysis::test_support::generated_input_slots(
                ),
            }],
            controls: Vec::new(),
            limits: SemanticModelRuntimeLimits::default(),
        };
        let SemanticModelRuntimeOutcome::Ready { active, .. } = acquire_active_semantic_models(
            &analyzer,
            &catalog,
            None,
            &request,
            &CancellationToken::new(),
        ) else {
            panic!("generated production activation ready")
        };
        let owned = active
            .shards
            .iter()
            .filter(|shard| {
                brokk_bifrost_analysis::analyzer::store::active_models::shard_owner_index(
                    shard,
                    None,
                    Some(0),
                ) == Some(0)
            })
            .collect::<Vec<_>>();
        assert_eq!(owned.len(), 1, "{:?}", active.report);
        assert_eq!(owned[0].descriptor.shard_id, "declarations.widget");
        assert!(
            active
                .excluded_shards
                .contains(&pack.manifest.content_sha256, "declarations.gadget"),
            "{:?}",
            active.report
        );

        let store = Arc::new(AnalyzerStore::open_ephemeral().unwrap());
        let source = JvmRequestRowReaderSource {
            questions_digest: Default::default(),
            authority: Arc::new(Authority {
                project: Arc::clone(&project),
                key,
                complete: true,
            }),
            project,
            catalog: catalog.pinned_catalog_source(
                &brokk_bifrost_analysis::analyzer::store::cache_budget::StoreCacheBudget::new(
                    &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
                ),
            ),
            store,
        };
        let _scope = AnalyzerQueryScope::with_outer_request(&analyzer, OuterRequest::new());
        assert_eq!(
            source.jvm_reader(&active).err(),
            Some(FamilyOpen::jvm("JVM production partially excluded"))
        );

        // Evidence for the gadget package activates the whole production. Its
        // view differs from the wholly excluded activation below, and both bind
        // in the same request: each view opens its own handle.
        let mut whole_request = request.clone();
        whole_request
            .evidence
            .push(SemanticModelActivationEvidence {
                language: "java".into(),
                ecosystem: "maven".into(),
                package: Some(
                    brokk_bifrost_analysis::analyzer::semantic_model::catalog::CatalogCoordinate {
                        name: "com.acme:gadget".into(),
                        version: Some(semver::Version::new(1, 2, 0)),
                    },
                ),
                module: None,
                toolchain: None,
                target: Some("jvm".into()),
                configuration: Some("release".into()),
                production_input_digest: Some("a".repeat(64)),
                verified_raw_artifacts: brokk_bifrost_analysis::test_support::generated_input_slots(
                ),
            });
        let SemanticModelRuntimeOutcome::Ready { active: whole, .. } =
            acquire_active_semantic_models(
                &analyzer,
                &catalog,
                None,
                &whole_request,
                &CancellationToken::new(),
            )
        else {
            panic!("whole production activation ready")
        };
        assert_eq!(
            whole
                .shards
                .iter()
                .filter(|shard| {
                    brokk_bifrost_analysis::analyzer::store::active_models::shard_owner_index(
                        shard,
                        None,
                        Some(0),
                    ) == Some(0)
                })
                .count(),
            2,
            "{:?}",
            whole.report
        );
        let whole_rows = |source: &JvmRequestRowReaderSource| {
            let reader = source.jvm_reader(&whole).expect("whole production binds");
            reader
                .reader
                .owned_rows(
                    statements::SEARCH_TYPE_IDENTITIES,
                    &[],
                    &CancellationToken::new(),
                )
                .unwrap()
                .rows
                .len()
        };
        let whole_before = whole_rows(&source);
        assert!(whole_before > 0);

        // Excluding the entire production is safe: no active shard selects its
        // published provider, and the narrowed catalog view must be empty.
        let other = ResolvedActiveSemanticModels::new(
            whole.active_model_set_hash().to_owned(),
            None,
            Vec::new(),
            MatcherIndexes::build(
                &active.shards,
                SemanticModelRuntimeLimits::default(),
                &CancellationToken::new(),
                &mut SemanticModelActivationReport::default(),
            )
            .unwrap(),
            Vec::new(),
            Default::default(),
            brokk_bifrost_analysis::analyzer::store::active_models::ActivationExclusions::new(
                [
                    (
                        pack.manifest.content_sha256.clone(),
                        "declarations.widget".into(),
                    ),
                    (
                        pack.manifest.content_sha256.clone(),
                        "declarations.gadget".into(),
                    ),
                ]
                .into(),
            ),
            SemanticModelActivationReport::default(),
        );
        let reader = source
            .jvm_reader(&other)
            .expect("wholly excluded production binds");
        let handle = &reader.reader;
        let cancellation = CancellationToken::new();
        let rows = handle
            .owned_rows(statements::SEARCH_TYPE_IDENTITIES, &[], &cancellation)
            .unwrap();
        assert!(rows.rows.is_empty(), "excluded production rows: {rows:?}");
        let raw = (&**handle as &dyn CatalogRowReader)
            .raw_rows(
                statements::SEARCH_TYPE_IDENTITIES,
                &[],
                &other.shards,
                |row| row.get::<_, i64>("record_key"),
            )
            .expect("wholly excluded rows are absent from the active view");
        assert!(raw.is_empty());
        assert_eq!(whole_rows(&source), whole_before);
        assert_eq!(
            source.jvm_reader(&active).err(),
            Some(FamilyOpen::jvm("JVM production partially excluded"))
        );

        // The same contents as a higher-precedence workspace pack: its widget shard
        // is active (activation-owned), and the generated production is wholly
        // excluded (widget shadowed, gadget unmatched). The workspace shard still
        // names the generated production's published provider by semantic digest,
        // which carries gadget, so the bind fails closed.
        catalog
            .register_session_pack(
                &pack,
                &brokk_bifrost_analysis::analyzer::semantic_model::catalog::SessionPackSource {
                    kind: brokk_bifrost_analysis::analyzer::semantic_model::catalog::SessionPackSourceKind::EphemeralWorkspace,
                    source_id: "workspace-copy".into(),
                },
            )
            .unwrap();
        let SemanticModelRuntimeOutcome::Ready {
            active: shadowed, ..
        } = acquire_active_semantic_models(
            &analyzer,
            &catalog,
            None,
            &request,
            &CancellationToken::new(),
        )
        else {
            panic!("workspace-shadowed activation ready")
        };
        assert!(
            shadowed
                .shards
                .iter()
                .all(|shard| shard.source_kind == CatalogPackSourceKind::EphemeralWorkspace),
            "{:?}",
            shadowed.report
        );
        assert_eq!(
            source.jvm_reader(&shadowed).err(),
            Some(FamilyOpen::jvm("JVM production partially excluded"))
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#11374: session registration rejected generated selectors despite their recorded production origin"
    )]
    #[hardwon(
        "#9559: warm binding and duplicate production expectations rebuilt declaration projections"
    )]
    #[expect(
        clippy::disallowed_methods,
        reason = "#12820: non-answer (writer, schema, GC or diagnostics); must not produce answers"
    )]
    fn generated_provider_publication_and_status() {
        use brokk_bifrost_analysis::analyzer::semantic_model::catalog::GeneratedProductionKey;
        use brokk_bifrost_analysis::analyzer::semantic_model::{
            AuthoredSemanticModelPack, CompilerOptions, compile_pack,
        };
        use brokk_bifrost_analysis::analyzer::store::writer::StoreWriter;
        use serde_json::{Value as JsonValue, json};

        let mut source: JsonValue = serde_json::from_slice(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../bifrost-analysis/testdata/semantic-model-packs/declarations-v1.json"
        )))
        .unwrap();
        source["schema_version"] =
            json!(brokk_bifrost_analysis::analyzer::semantic_model::SEMANTIC_MODEL_SCHEMA_VERSION);
        source["compatibility"] = json!({});
        source["shards"][0]["activation"] = json!([{}]);
        let second: JsonValue = serde_json::from_str(
            &serde_json::to_string(&source["shards"][0])
                .unwrap()
                .replace("widget", "gadget")
                .replace("Widget", "Gadget"),
        )
        .unwrap();
        source["shards"].as_array_mut().unwrap().push(second);
        let pack = compile_pack(
            &serde_json::from_value::<AuthoredSemanticModelPack>(source).unwrap(),
            &CompilerOptions::default(),
        )
        .unwrap();
        let root = tempfile::tempdir().unwrap();
        let catalog = SemanticPackCatalog::open(
            root.path(),
            CatalogOpenMode::ReadWrite,
            CatalogOptions::default(),
        )
        .unwrap();
        let key = GeneratedProductionKey::new(
            "a".repeat(64),
            "artifact-scanner",
            fixture_producer_version("2.0.0"),
            brokk_bifrost_analysis::analyzer::semantic_model::SEMANTIC_MODEL_SCHEMA_VERSION,
        )
        .unwrap();
        let pack = brokk_bifrost_analysis::test_support::generated_pack_fixture(
            &pack,
            key.input_digest(),
            &brokk_bifrost_analysis::test_support::generated_input_slots(),
        );
        catalog
            .install_generated(
                &key,
                &pack,
                &brokk_bifrost_analysis::test_support::generated_input_slots(),
            )
            .unwrap();
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root.path(), Language::Java));
        let selection = |digest, records: Arc<dyn std::any::Any + Send + Sync>| VerifiedSelection {
            question_digest: [1; 32],
            answer_digest: digest,
            view_stamp: project.view_stamp(),
            verified: false,
            certified: false,
            complete: true,
            only_replayable_gaps: false,
            records,
        };
        let dependencies = selection(
            [2; 32],
            Arc::new(Some(
                ExternalInventorySelection::empty_for_catalog_reader_test(),
            )),
        );
        let jdk = selection([3; 32], Arc::new(()));
        let open = |production_digest: String| {
            let request = OuterRequest::new();
            let handle = open_jvm_catalog_reader(
                &request,
                Arc::clone(&project),
                &catalog.pinned_catalog_source(
                    &brokk_bifrost_analysis::analyzer::store::cache_budget::StoreCacheBudget::new(
                        &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
                    ),
                ),
                &dependencies,
                &jdk,
                vec![
                    ExpectedCatalogEntry::Production { production_digest },
                    ExpectedCatalogEntry::MissingProduction,
                ],
                CuratedAuthority {
                    admitted_digest: [4; 32],
                    shards: vec![],
                },
                [0; 32],
                CancellationToken::new(),
            )
            .unwrap();
            (request, handle)
        };
        // A curated registration certifies the same complete manifest before
        // the generated registration is used. The latter must reuse its digest.
        use brokk_bifrost_analysis::analyzer::semantic_model::catalog::{
            SessionPackSource, SessionPackSourceKind,
        };
        catalog
            .register_compiled_pack(
                &pack,
                &SessionPackSource {
                    kind: SessionPackSourceKind::Embedded,
                    source_id: "curated-publication".into(),
                },
            )
            .unwrap();
        let curated_request = OuterRequest::new();
        let curated = open_jvm_catalog_reader(
            &curated_request,
            Arc::clone(&project),
            &catalog.pinned_catalog_source(
                &brokk_bifrost_analysis::analyzer::store::cache_budget::StoreCacheBudget::new(
                    &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
                ),
            ),
            &dependencies,
            &jdk,
            Vec::new(),
            CuratedAuthority {
                admitted_digest: [8; 32],
                shards: pack
                    .manifest
                    .shards
                    .iter()
                    .map(|shard| CuratedShard {
                        kind: CatalogPackSourceKind::Embedded,
                        manifest_digest: pack.manifest.content_sha256.clone(),
                        shard_id: shard.shard_id.clone(),
                    })
                    .collect(),
            },
            [0; 32],
            CancellationToken::new(),
        )
        .unwrap();
        let partial_request = OuterRequest::new();
        let partial = open_jvm_catalog_reader(
            &partial_request,
            Arc::clone(&project),
            &catalog.pinned_catalog_source(
                &brokk_bifrost_analysis::analyzer::store::cache_budget::StoreCacheBudget::new(
                    &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
                ),
            ),
            &dependencies,
            &jdk,
            Vec::new(),
            CuratedAuthority {
                admitted_digest: [9; 32],
                shards: vec![CuratedShard {
                    kind: CatalogPackSourceKind::Embedded,
                    manifest_digest: pack.manifest.content_sha256.clone(),
                    shard_id: pack.manifest.shards[0].shard_id.clone(),
                }],
            },
            [0; 32],
            CancellationToken::new(),
        )
        .unwrap();
        let partial_store = AnalyzerStore::open_ephemeral().unwrap();
        assert!(matches!(
            partial.publish_providers(&partial_store, &CancellationToken::new()),
            Err(JvmCatalogReaderError::Open(
                "curated JVM pack partially selected"
            ))
        ));
        let readonly = AnalyzerStore::open_ephemeral().unwrap();
        let StoreWriter::Local(writer) = &readonly.conn else {
            panic!("local writer")
        };
        writer
            .lock()
            .unwrap()
            .execute_batch("PRAGMA query_only=ON")
            .unwrap();
        assert!(matches!(
            curated.publish_providers(&readonly, &CancellationToken::new()),
            Err(JvmCatalogReaderError::Open(
                "curated JVM provider unpublished on a read-only store"
            ))
        ));
        let curated_store = AnalyzerStore::open_ephemeral().unwrap();
        let token = CancellationToken::new();
        assert!(
            curated
                .provider_certificate_status(&curated_store, &token)
                .unwrap()
                .iter()
                .all(|(_, status)| *status == ProviderPublication::Unavailable)
        );
        assert!(
            curated
                .publish_providers(&curated_store, &token)
                .unwrap()
                .iter()
                .all(|(_, status)| *status == ProviderPublication::Certified)
        );
        let (_request, handle) = open(key.production_digest().to_owned());
        assert_eq!(
            handle.publish_providers(&curated_store, &token).unwrap()[0].1,
            ProviderPublication::Certified
        );
        let duplicate_store = AnalyzerStore::open_ephemeral().unwrap();
        let duplicate_reader = catalog
            .pinned_catalog_source(
                &brokk_bifrost_analysis::analyzer::store::cache_budget::StoreCacheBudget::new(
                    &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
                ),
            )
            .pinned_jvm_reader(
                &[
                    ExpectedCatalogEntry::Production {
                        production_digest: key.production_digest().to_owned(),
                    },
                    ExpectedCatalogEntry::Production {
                        production_digest: key.production_digest().to_owned(),
                    },
                ],
                CancellationToken::new(),
            )
            .unwrap();
        let duplicate_calls = std::sync::atomic::AtomicUsize::new(0);
        let outcomes = ProviderProjections {
            reader: &duplicate_reader,
            projection_calls: &duplicate_calls,
        }
        .for_each_provider(
            &duplicate_store,
            &token,
            |_| {},
            |projection| {
                let (status, certificate) = duplicate_store
                    .publish_jvm_external_projection_with_certificate(
                        || Ok(Some(projection)),
                        || false,
                    )
                    .map_err(store_failure)?;
                assert_eq!(status, JvmExternalPublication::Available);
                Ok((ProviderPublication::Certified, certificate))
            },
        )
        .unwrap();
        assert_eq!(
            outcomes,
            vec![
                (0, ProviderPublication::Certified),
                (1, ProviderPublication::Certified)
            ]
        );
        assert_eq!(
            duplicate_calls.load(std::sync::atomic::Ordering::Relaxed),
            pack.manifest.shards.len(),
            "duplicate expectation reprojected declaration shards"
        );
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let token = CancellationToken::new();
        assert_eq!(
            handle.provider_certificate_status(&store, &token).unwrap(),
            vec![
                (0, ProviderPublication::Unavailable),
                (1, ProviderPublication::Missing)
            ]
        );
        let count = || -> i64 {
            store
                .read_conn()
                .unwrap()
                .query_row(
                    "SELECT count(*) FROM jvm_external_provider_publications",
                    [],
                    |row| row.get(0),
                )
                .unwrap()
        };
        assert_eq!(count(), 0);
        assert_eq!(
            handle.publish_providers(&store, &token).unwrap(),
            vec![
                (0, ProviderPublication::Certified),
                (1, ProviderPublication::Missing)
            ]
        );
        assert_eq!(count(), 1);
        let calls = handle
            .projection_calls
            .load(std::sync::atomic::Ordering::Relaxed);
        assert_eq!(
            handle.publish_providers(&store, &token).unwrap(),
            vec![
                (0, ProviderPublication::Certified),
                (1, ProviderPublication::Missing)
            ]
        );
        assert_eq!(count(), 1);
        assert_eq!(
            handle
                .projection_calls
                .load(std::sync::atomic::Ordering::Relaxed),
            calls,
            "warm publication rebuilt projection"
        );
        assert_eq!(
            handle.provider_certificate_status(&store, &token).unwrap()[0].1,
            ProviderPublication::Certified
        );

        let unwritable = AnalyzerStore::open_ephemeral().unwrap();
        let StoreWriter::Local(writer) = &unwritable.conn else {
            panic!("ephemeral test store has a local writer")
        };
        writer
            .lock()
            .unwrap()
            .execute_batch("PRAGMA query_only=ON")
            .unwrap();
        let Err(JvmCatalogReaderError::Store(error)) =
            handle.publish_providers(&unwritable, &token)
        else {
            panic!("provider publication must fail on a read-only store")
        };
        assert_eq!(
            error.kind(),
            brokk_bifrost_analysis::analyzer::store::StoreErrorKind::NotWritable
        );

        // A live certificate cannot override stale membership in the pinned view.
        let mut stale_reader = catalog
            .pinned_catalog_source(
                &brokk_bifrost_analysis::analyzer::store::cache_budget::StoreCacheBudget::new(
                    &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
                ),
            )
            .pinned_jvm_reader(
                &[ExpectedCatalogEntry::Production {
                    production_digest: key.production_digest().to_owned(),
                }],
                CancellationToken::new(),
            )
            .unwrap();
        stale_reader.membership[0].status = PinnedCatalogStatus::Stale;
        let stale = JvmCatalogReaderHandle {
            key: handle.key.clone(),
            project: Arc::clone(&project),
            reader: stale_reader,
            dependency_gaps: Vec::new(),
            projection_calls: std::sync::atomic::AtomicUsize::new(0),
            provider_outcomes: Mutex::new(None),
            provider_certificates: Mutex::default(),
            bindings: Mutex::new(HandleBindings::default()),
        };
        assert_eq!(
            stale.publish_providers(&store, &token).unwrap(),
            vec![(0, ProviderPublication::Stale)]
        );
        assert_eq!(
            stale.provider_certificate_status(&store, &token).unwrap(),
            vec![(0, ProviderPublication::Stale)]
        );

        // The semantic SHA is the provider key. A different immutable production
        // under that key reuses the same certified projection.
        let other = GeneratedProductionKey::new(
            key.input_digest(),
            "artifact-scanner",
            fixture_producer_version("2.0.1"),
            brokk_bifrost_analysis::analyzer::semantic_model::SEMANTIC_MODEL_SCHEMA_VERSION,
        )
        .unwrap();
        let validated = brokk_bifrost_analysis::analyzer::semantic_model::catalog::validate_pack(
            &pack,
            &Default::default(),
        )
        .unwrap();
        let mut revised = brokk_bifrost_analysis::analyzer::semantic_model::artifact::authored_pack_from_compiled_shard(&validated.shards[0].decoded);
        revised.shards = validated.shards.iter().flat_map(|shard| brokk_bifrost_analysis::analyzer::semantic_model::artifact::authored_pack_from_compiled_shard(&shard.decoded).shards).collect();
        revised.producer.version = fixture_producer_version("2.0.1");
        let revised =
            brokk_bifrost_analysis::analyzer::semantic_model::compiler::compile_generated_pack(
                &revised,
                &Default::default(),
            )
            .unwrap();
        assert_eq!(
            revised.manifest.semantic_sha256,
            pack.manifest.semantic_sha256
        );
        assert_ne!(
            revised.manifest.content_sha256,
            pack.manifest.content_sha256
        );
        let pack = revised;
        catalog
            .install_generated(
                &other,
                &pack,
                &brokk_bifrost_analysis::test_support::generated_input_slots(),
            )
            .unwrap();
        let (_second_request, second) = open(other.production_digest().to_owned());
        assert_eq!(
            second.publish_providers(&store, &token).unwrap()[0].1,
            ProviderPublication::Certified
        );
        assert_eq!(count(), 1);
        assert_eq!(
            handle.provider_certificate_status(&store, &token).unwrap()[0].1,
            ProviderPublication::Certified
        );
    }

    /// The two readers that serve one row site must agree: the activation's
    /// reader and a request's pinned reader over the same shard answer a keyed
    /// question and a whole-table scan with the same rows.
    #[test]
    fn activation_and_pinned_readers_return_the_same_rows() {
        use brokk_bifrost_analysis::analyzer::semantic_model::catalog::{
            SessionPackSource, SessionPackSourceKind, statements,
        };
        use brokk_bifrost_analysis::analyzer::semantic_model::{
            AuthoredSemanticModelPack, CompilerOptions, compile_pack,
        };
        use serde_json::{Value as JsonValue, json};
        let mut source: JsonValue = serde_json::from_slice(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../bifrost-analysis/testdata/semantic-model-packs/declarations-v1.json"
        )))
        .unwrap();
        source["schema_version"] =
            json!(brokk_bifrost_analysis::analyzer::semantic_model::SEMANTIC_MODEL_SCHEMA_VERSION);
        source["compatibility"] = json!({});
        source["shards"][0]["activation"] = json!([{}]);
        let pack = compile_pack(
            &serde_json::from_value::<AuthoredSemanticModelPack>(source).unwrap(),
            &CompilerOptions::default(),
        )
        .unwrap();
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        catalog
            .register_compiled_pack(
                &pack,
                &SessionPackSource {
                    kind: SessionPackSourceKind::EphemeralWorkspace,
                    source_id: "reader-parity".into(),
                },
            )
            .unwrap();
        let manifest_digest = pack.manifest.content_sha256.clone();
        let shard_id = pack.manifest.shards[0].shard_id.clone();
        let activation = catalog
            .runtime_source_reader([(
                manifest_digest.as_str(),
                shard_id.as_str(),
                CatalogPackSourceKind::EphemeralWorkspace,
            )])
            .unwrap();
        let root = tempfile::tempdir().unwrap();
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root.path(), Language::Java));
        let selection = |digest, records: Arc<dyn std::any::Any + Send + Sync>| VerifiedSelection {
            question_digest: [1; 32],
            answer_digest: digest,
            view_stamp: project.view_stamp(),
            verified: false,
            certified: false,
            complete: true,
            only_replayable_gaps: false,
            records,
        };
        let dependencies = selection(
            [2; 32],
            Arc::new(Some(
                ExternalInventorySelection::empty_for_catalog_reader_test(),
            )),
        );
        let jdk = selection([3; 32], Arc::new(()));
        let request = OuterRequest::new();
        let handle = open_jvm_catalog_reader(
            &request,
            project,
            &catalog.pinned_catalog_source(
                &brokk_bifrost_analysis::analyzer::store::cache_budget::StoreCacheBudget::new(
                    &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
                ),
            ),
            &dependencies,
            &jdk,
            Vec::new(),
            CuratedAuthority {
                admitted_digest: [4; 32],
                shards: vec![CuratedShard {
                    kind: CatalogPackSourceKind::EphemeralWorkspace,
                    manifest_digest,
                    shard_id,
                }],
            },
            [0; 32],
            CancellationToken::new(),
        )
        .unwrap();
        let cancellation = CancellationToken::new();
        let rows = |reader: &dyn CatalogRowReader,
                    statement: &str,
                    bindings: &[(&str, &dyn rusqlite::ToSql)]| {
            let rows = reader
                .owned_rows(statement, bindings, &cancellation)
                .unwrap();
            let mut values = rows
                .rows
                .iter()
                .map(|row| format!("{row:?}"))
                .collect::<Vec<_>>();
            values.sort();
            (rows.columns, values)
        };
        type Bindings<'a> = &'a [(&'a str, &'a dyn rusqlite::ToSql)];
        let cases: [(&str, Bindings); 2] = [
            (
                statements::TYPES_BY_ID,
                rusqlite::named_params! { ":id": "type.widget" },
            ),
            (statements::SEARCH_TYPE_IDENTITIES, &[]),
        ];
        for (statement, bindings) in cases {
            let expected = rows(&activation, statement, bindings);
            assert!(!expected.1.is_empty(), "{statement}: fixture has rows");
            assert_eq!(
                rows(handle.as_ref(), statement, bindings),
                expected,
                "{statement}"
            );
        }
    }

    #[test]
    #[hardwon(
        "#11148: catalog-backed JVM projection must preserve abstract flags from the same typed declarations as decoded facts"
    )]
    fn pinned_declaration_projection_matches_decoded_facts() {
        use brokk_bifrost_analysis::analyzer::semantic_model::catalog::{
            SessionPackSource, SessionPackSourceKind, validate_pack,
        };
        use brokk_bifrost_analysis::analyzer::semantic_model::{
            AuthoredSemanticModelPack, CompilerOptions, DecodeLimits, compile_pack,
        };
        use serde_json::{Value as JsonValue, json};
        let mut source: JsonValue = serde_json::from_slice(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../bifrost-analysis/testdata/semantic-model-packs/declarations-v1.json"
        )))
        .unwrap();
        source["schema_version"] =
            json!(brokk_bifrost_analysis::analyzer::semantic_model::SEMANTIC_MODEL_SCHEMA_VERSION);
        source["compatibility"] = json!({});
        source["shards"][0]["activation"] = json!([{}]);
        let payload = &mut source["shards"][0]["payload"];
        let base = payload["types"][0].clone();
        let member = payload["members"][0].clone();
        payload["types"][0]["hierarchy"] =
            json!([{"hierarchy_kind":"extends","target":{"kind":"declared","id":"type.base"}}]);
        let mut additional = member.clone();
        additional["id"] = json!("member.additional");
        additional["name"] = json!("additional");
        additional["is_abstract"] = json!(true);
        additional["is_static"] = json!(false);
        additional["is_virtual"] = json!(true);
        payload["types"][0]["is_abstract"] = json!(true);
        payload["members"][0]["is_abstract"] = json!(false);
        payload["types"][0]["jvm_inventory"] = json!({"callables_complete":true,"values_complete":true,"types_complete":true,"supertypes_complete":true,"supertypes":[{"hierarchy_kind":"extends","target":{"kind":"declared","id":"type.base"}}],"nested_types":[{"name":"Inner","owner_fqn":"com.acme.Widget.Inner","visibility":"public","is_static":true}],"additional_members":[additional]});
        let mut base_owner = base;
        base_owner["id"] = json!("type.base");
        base_owner["name"] = json!("com.acme.Base");
        base_owner["hierarchy"] = json!([]);
        payload["types"].as_array_mut().unwrap().push(base_owner);
        let mut guarded = member;
        guarded["id"] = json!("member.guarded");
        guarded["guard"] = json!({"required_targets":["jvm"]});
        payload["members"].as_array_mut().unwrap().push(guarded);
        let mut guarded_owner = payload["types"][0].clone();
        guarded_owner["id"] = json!("type.guarded");
        guarded_owner["name"] = json!("com.acme.Guarded");
        guarded_owner["guard"] = json!({"required_targets":["jvm"]});
        payload["types"].as_array_mut().unwrap().push(guarded_owner);
        let authored: AuthoredSemanticModelPack = serde_json::from_value(source).unwrap();
        let pack = compile_pack(&authored, &CompilerOptions::default()).unwrap();
        let validated = validate_pack(&pack, &DecodeLimits::default()).unwrap();
        let (types, members, _) = validated.shards[0]
            .decoded
            .payload()
            .declaration_facts()
            .unwrap();
        let expected = jvm_external_projection(
            pack.manifest.semantic_sha256.clone(),
            String::new(),
            types
                .iter()
                .map(AsRef::as_ref)
                .filter(|owner| owner.guard.is_none()),
            members.iter().map(AsRef::as_ref),
            true,
        )
        .unwrap();
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        catalog
            .register_compiled_pack(
                &pack,
                &SessionPackSource {
                    kind: SessionPackSourceKind::EphemeralWorkspace,
                    source_id: "projection-parity".into(),
                },
            )
            .unwrap();
        let root = tempfile::tempdir().unwrap();
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root.path(), Language::Java));
        let selection = |digest, records: Arc<dyn std::any::Any + Send + Sync>| VerifiedSelection {
            question_digest: [1; 32],
            answer_digest: digest,
            view_stamp: project.view_stamp(),
            verified: false,
            certified: false,
            complete: true,
            only_replayable_gaps: false,
            records,
        };
        let dependencies = selection(
            [2; 32],
            Arc::new(Some(
                ExternalInventorySelection::empty_for_catalog_reader_test(),
            )),
        );
        let jdk = selection([3; 32], Arc::new(()));
        let request = OuterRequest::new();
        let handle = open_jvm_catalog_reader(
            &request,
            project,
            &catalog.pinned_catalog_source(
                &brokk_bifrost_analysis::analyzer::store::cache_budget::StoreCacheBudget::new(
                    &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
                ),
            ),
            &dependencies,
            &jdk,
            Vec::new(),
            CuratedAuthority {
                admitted_digest: [4; 32],
                shards: vec![CuratedShard {
                    kind: CatalogPackSourceKind::EphemeralWorkspace,
                    manifest_digest: pack.manifest.content_sha256.clone(),
                    shard_id: pack.manifest.shards[0].shard_id.clone(),
                }],
            },
            [0; 32],
            CancellationToken::new(),
        )
        .unwrap();
        let membership = handle.membership().unwrap();
        let actual = handle
            .external_projection(&membership[0], &CancellationToken::new())
            .unwrap()
            .unwrap();
        assert_eq!(actual.owners.len(), 2);
        assert_eq!(actual.members.len(), 3);
        assert_eq!(actual.supertypes.len(), 1);
        assert_eq!(actual.provider_id, expected.provider_id);
        assert_eq!(actual.owners, expected.owners);
        let flags = actual
            .members
            .iter()
            .map(|row| (row[3].clone(), row[12].clone()))
            .collect::<Vec<_>>();
        assert!(
            flags
                .iter()
                .any(|(name, flag)| name == &Value::Text("additional".into())
                    && flag == &Value::Integer(1)),
            "{flags:?}"
        );
        assert!(
            flags
                .iter()
                .any(|(name, flag)| name != &Value::Text("additional".into())
                    && flag == &Value::Integer(0)),
            "{flags:?}"
        );
        assert_eq!(actual.members, expected.members);
        assert_eq!(actual.supertypes, expected.supertypes);
    }

    #[test]
    #[hardwon("#9559: a catalog lock after the request guard panicked instead of leaving JVM Open")]
    fn request_keys_lifetime_and_generation() {
        let root = tempfile::tempdir().unwrap();
        let catalog = SemanticPackCatalog::open(
            root.path(),
            CatalogOpenMode::ReadWrite,
            CatalogOptions::default(),
        )
        .unwrap();
        let base: Arc<dyn Project> = Arc::new(TestProject::new(root.path(), Language::Java));
        let overlay = Arc::new(OverlayProject::new(base));
        let project: Arc<dyn Project> = overlay.clone();
        let selection =
            |answer_digest, records: Arc<dyn std::any::Any + Send + Sync>| VerifiedSelection {
                question_digest: [1; 32],
                answer_digest,
                view_stamp: project.view_stamp(),
                verified: false,
                certified: false,
                complete: true,
                only_replayable_gaps: false,
                records,
            };
        let dependencies = selection(
            [2; 32],
            Arc::new(Some(
                ExternalInventorySelection::empty_for_catalog_reader_test(),
            )),
        );
        let jdk = selection([3; 32], Arc::new(()));
        let curated = |digest| CuratedAuthority {
            admitted_digest: digest,
            shards: Vec::new(),
        };
        let request = OuterRequest::new();
        let open = |jdk: &VerifiedSelection, digest| {
            open_jvm_catalog_reader(
                &request,
                project.clone(),
                &catalog.pinned_catalog_source(
                    &brokk_bifrost_analysis::analyzer::store::cache_budget::StoreCacheBudget::new(
                        &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
                    ),
                ),
                &dependencies,
                jdk,
                vec![ExpectedCatalogEntry::MissingProduction],
                curated(digest),
                [0; 32],
                CancellationToken::new(),
            )
            .unwrap()
        };
        let first = open(&jdk, [4; 32]);
        assert_eq!(
            first.membership().unwrap()[0].status,
            PinnedCatalogStatus::Missing
        );
        assert!(Arc::ptr_eq(&first, &open(&jdk, [4; 32])));
        // A separate rollback-journal database gives a deterministic SQLite
        // lock failure after the request guard has already admitted this handle.
        // The catalog connection refuses symlinked paths (SQLITE_OPEN_NOFOLLOW),
        // and macOS temp roots sit under the /var -> /private/var symlink, so
        // attach through the canonical path.
        let locked_path = root.path().canonicalize().unwrap().join("locked.sqlite");
        let locked = rusqlite::Connection::open(&locked_path).unwrap();
        locked
            .execute_batch(
                "CREATE TABLE locked_value(value INTEGER); INSERT INTO locked_value VALUES(1)",
            )
            .unwrap();
        CatalogRowReader::owned_rows(
            first.as_ref(),
            "ATTACH DATABASE :path AS locked",
            &[(":path", &locked_path.to_str().unwrap())],
            &CancellationToken::new(),
        )
        .unwrap();
        CatalogRowReader::owned_rows(
            first.as_ref(),
            "PRAGMA busy_timeout=1",
            &[],
            &CancellationToken::new(),
        )
        .unwrap();
        locked.execute_batch("BEGIN EXCLUSIVE").unwrap();
        assert!(matches!(
            CatalogRowReader::owned_rows(first.as_ref(), "SELECT * FROM locked.locked_value", &[], &CancellationToken::new()),
            Err(CatalogError::FamilyOpen(open)) if open == FamilyOpen::jvm("JVM catalog busy")
        ));
        locked.execute_batch("ROLLBACK").unwrap();
        let changed_jdk = selection([5; 32], Arc::new(()));
        assert!(!Arc::ptr_eq(&first, &open(&changed_jdk, [4; 32])));
        assert!(!Arc::ptr_eq(&first, &open(&jdk, [6; 32])));
        overlay.set(root.path().join("Changed.java"), "class Changed {}".into());
        assert!(matches!(
            first.membership(),
            Err(JvmCatalogReaderError::Stale)
        ));
        request.close();
        assert!(matches!(
            first.membership(),
            Err(JvmCatalogReaderError::Closed)
        ));
        assert!(matches!(
            CatalogRowReader::owned_rows(first.as_ref(), "SELECT 1", &[], &CancellationToken::new()),
            Err(CatalogError::FamilyOpen(open)) if open == FamilyOpen::jvm("JVM catalog reader invalidated")
        ));
    }
}
