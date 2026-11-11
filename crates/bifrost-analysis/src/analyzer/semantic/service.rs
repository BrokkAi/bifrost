//! Shared snapshot, publication, and complete-cache mechanics for language lowerers.

use crate::analyzer::{IAnalyzer, QueryScope};
use brokk_bifrost_core::budgeted_value_cache::{BudgetedValueAcquisition, BudgetedValuePermit};
use brokk_bifrost_core::gitblob::BlobKey;

use crate::analyzer::read_ledger::{LookupKind, LookupQuestion, ReadKey};
use crate::analyzer::semantic::partial_flow::ProcedurePartialFlows;
use crate::analyzer::semantic::read_ledger::{
    REFUSED_PROVENANCE, StoredSemanticIrPublicationAnswer, StoredSemanticIrPublicationQuestion,
};
use crate::analyzer::semantic::{
    ContentIdentity, ProcedureHandle, ProcedureId, ProcedureSemanticsParts, SemanticArtifact,
    SemanticArtifactKey, SemanticOutcome, SemanticProviderError, SemanticRequest, SemanticWork,
    StableDigest, WorkspaceMountId, WorkspaceRelativePath,
};
use crate::analyzer::semantic::{
    StoredSemanticIrObservation, StoredSemanticIrPublicationHead, StoredSemanticIrRead,
    StoredSemanticIrSelection, classify,
};
use crate::analyzer::store::semantic_ir::SemanticIrHeadObservation;
use crate::analyzer::store::semantic_ir::{
    SemanticIrMountFields, SemanticIrMountScope, StoredFootprintCoverage, StoredFootprintRefusal,
};
use crate::analyzer::tree_sitter_analyzer::{
    PreparedSourceFailure, PreparedSourceOrigin, PreparedSyntaxLimitedOutcome,
};
use crate::analyzer::{
    LanguageAdapter, LanguageDialect, ProjectFile, ProjectSourceOrigin, TreeSitterAnalyzer,
};
use brokk_bifrost_core::cancellation::CancellationToken;
use brokk_bifrost_core::path_utils::rel_path_string;
pub use brokk_bifrost_semantic::analyzer::semantic::service::*;
use std::sync::Arc;

pub use brokk_bifrost_semantic::analyzer::semantic::{
    FootprintAdmission, FootprintAdmissionRefusal,
};

impl<A: LanguageAdapter> TreeSitterAnalyzer<A> {
    pub fn stored_footprint_coverage(
        &self,
        procedure: &ProcedureHandle,
        _request: &mut SemanticRequest<'_>,
    ) -> Result<FootprintAdmission, SemanticProviderError> {
        let key = procedure.artifact().key();
        let file = ProjectFile::new(self.project().root().to_path_buf(), key.path().as_path());
        let Some(result) = admitted_stored_child(
            self,
            &file,
            *key.revision().content().as_bytes(),
            |store, blob| {
                store.read_footprint_coverage_with_observation(
                    blob,
                    key.revision().content(),
                    procedure.id(),
                )
            },
        )?
        else {
            return Ok(FootprintAdmission::Refused(
                FootprintAdmissionRefusal::CoverageUnavailable,
            ));
        };
        Ok(match result {
            StoredFootprintCoverage::Admitted {
                call_target_obligations,
            } => FootprintAdmission::Admitted {
                call_target_obligations,
            },
            StoredFootprintCoverage::Refused(reason) => FootprintAdmission::Refused(match reason {
                StoredFootprintRefusal::CoverageUnavailable => {
                    FootprintAdmissionRefusal::CoverageUnavailable
                }
                StoredFootprintRefusal::OldContract => FootprintAdmissionRefusal::OldContract,
                StoredFootprintRefusal::UnknownCode => FootprintAdmissionRefusal::UnknownCode,
                StoredFootprintRefusal::DuplicateClass => FootprintAdmissionRefusal::DuplicateClass,
                StoredFootprintRefusal::MissingClass => FootprintAdmissionRefusal::MissingClass,
                StoredFootprintRefusal::RefusedCoverage => {
                    FootprintAdmissionRefusal::RefusedCoverage
                }
            }),
        })
    }
    pub fn stored_call_control_coverage(
        &self,
        procedure: &ProcedureHandle,
        _request: &mut SemanticRequest<'_>,
    ) -> Result<FootprintAdmission, SemanticProviderError> {
        let key = procedure.artifact().key();
        let file = ProjectFile::new(self.project().root().to_path_buf(), key.path().as_path());
        let Some(oid) = self.reusable_live_oid(&file) else {
            return Ok(FootprintAdmission::Refused(
                FootprintAdmissionRefusal::CoverageUnavailable,
            ));
        };
        let variant = self.selected_parse_variant(&file).ok_or_else(|| {
            SemanticProviderError::internal(format!(
                "selected parse variant unreadable for {file:?}"
            ))
        })?;
        let blob = BlobKey {
            oid,
            lang: self.adapter().storage_language_key_for_file(&file).into(),
            variant,
        };
        let result = self
            .analyzer_store()
            .read_call_control_coverage(&blob, key.revision().content(), procedure.id())
            .map_err(|error| SemanticProviderError::internal(error.to_string()))?;
        Ok(match result {
            StoredFootprintCoverage::Admitted {
                call_target_obligations,
            } => FootprintAdmission::Admitted {
                call_target_obligations,
            },
            StoredFootprintCoverage::Refused(reason) => FootprintAdmission::Refused(match reason {
                StoredFootprintRefusal::CoverageUnavailable => {
                    FootprintAdmissionRefusal::CoverageUnavailable
                }
                StoredFootprintRefusal::OldContract => FootprintAdmissionRefusal::OldContract,
                StoredFootprintRefusal::UnknownCode => FootprintAdmissionRefusal::UnknownCode,
                StoredFootprintRefusal::DuplicateClass => FootprintAdmissionRefusal::DuplicateClass,
                StoredFootprintRefusal::MissingClass => FootprintAdmissionRefusal::MissingClass,
                StoredFootprintRefusal::RefusedCoverage => {
                    FootprintAdmissionRefusal::RefusedCoverage
                }
            }),
        })
    }
}

#[doc(hidden)]
pub use primary_declarations::lower_with_primary_declarations;
pub(crate) fn validate_semantic_file<A: LanguageAdapter>(
    analyzer: &TreeSitterAnalyzer<A>,
    file: &ProjectFile,
) -> Result<(), SemanticProviderError> {
    if file.root() != analyzer.project().root() {
        return Err(SemanticProviderError::invalid_identity(format!(
            "semantic file root `{}` does not match analyzer root `{}`",
            file.root().display(),
            analyzer.project().root().display()
        )));
    }
    let file_language = crate::analyzer::common::language_for_file(file);
    if file_language != analyzer.adapter().language() {
        return Err(SemanticProviderError::invalid_identity(format!(
            "semantic file language {} does not match {} adapter",
            file_language.config_label(),
            analyzer.adapter().language().config_label()
        )));
    }
    Ok(())
}

/// Capture current source and derive its complete artifact identity from the
/// same atomic project snapshot. This deliberately does not parse, consult the
/// artifact cache, lower procedures, or mutate a semantic budget.
#[doc(hidden)]
pub fn current_artifact_source_with_lowerer<A: LanguageAdapter>(
    analyzer: &TreeSitterAnalyzer<A>,
    lowerer: &dyn ProgramSemanticsLowerer,
    file: &ProjectFile,
    max_source_bytes: usize,
) -> Result<Option<crate::analyzer::semantic::SemanticArtifactSourceSnapshot>, SemanticProviderError>
{
    validate_semantic_file(analyzer, file)?;
    let (source_identity, snapshot) = match analyzer.source_snapshot_limited(file, max_source_bytes)
    {
        Ok(Some(resolved)) => resolved,
        Ok(None) => {
            return Err(SemanticProviderError::source_access(format!(
                "could not capture the current source snapshot for `{file}`"
            )));
        }
        Err(PreparedSourceFailure::Exceeded(_)) => return Ok(None),
        Err(PreparedSourceFailure::Refused(reason)) => {
            return Err(SemanticProviderError::source_admission_refused(
                file.clone(),
                reason,
            ));
        }
    };
    let overlay_revision = match snapshot.origin() {
        ProjectSourceOrigin::Disk => None,
        ProjectSourceOrigin::Overlay(revision) => Some(revision),
    };
    let source = snapshot.into_source();
    // Identity of exactly these bytes, hashed once per distinct content rather
    // than once per freshness check: this path runs for every call site the
    // dispatch oracle resolves, and re-hashing a file it has already hashed is
    // the residual #2295 named.
    let digests = analyzer.semantic_source_digests();
    let blob_key = BlobKey {
        oid: source_identity,
        lang: analyzer
            .adapter()
            .storage_language_key_for_file(file)
            .into(),
        variant: analyzer.selected_parse_variant(file).ok_or_else(|| {
            SemanticProviderError::internal(format!(
                "selected parse variant unreadable for {file:?}"
            ))
        })?,
    };
    let content = match digests.get(blob_key.clone()) {
        Some(content) => content,
        None => {
            let content = ContentIdentity::from_source_bytes(
                source.as_bytes(),
                analyzer.adapter().language(),
                blob_key.variant,
            );
            digests.record(blob_key, content);
            content
        }
    };
    let key = semantic_artifact_key_from_content(
        file,
        LanguageDialect::for_path(analyzer.adapter().language(), file.rel_path()),
        content,
        overlay_revision,
        lowerer.identity(),
    )?;
    Ok(Some(
        crate::analyzer::semantic::SemanticArtifactSourceSnapshot::new(key, source),
    ))
}

/// Materialize against exactly one prepared syntax snapshot.
///
/// The content digest, source origin, dialect, tree, and source mappings all
/// come from `prepared_syntax`; no second source read can race key derivation.
#[doc(hidden)]
pub fn materialize_with_lowerer<A: LanguageAdapter>(
    analyzer: &TreeSitterAnalyzer<A>,
    cache: &CompleteSemanticArtifactCache,
    lowerer: &dyn ProgramSemanticsLowerer,
    file: &ProjectFile,
    request: &mut SemanticRequest<'_>,
) -> Result<SemanticOutcome<Arc<SemanticArtifact>>, SemanticProviderError> {
    let outcome = materialize_with_lowerer_inner(analyzer, cache, lowerer, file, request)?;
    // The artifact is the unit of consumption, and its public fingerprint is
    // the one identity that names it without the workspace mount. Recorded on
    // the cache-hit path as well as the fresh path: a hit in a later request is
    // still a read of that artifact.
    if let Some(artifact) = outcome.available_value() {
        analyzer.record_reads(|sink| {
            sink.push(crate::analyzer::read_ledger::ReadKey::artifact(
                crate::analyzer::invalidation::DerivedArtifactId::semantic_artifact(
                    artifact.key().public_fingerprint(),
                ),
                Some(artifact.key().path().as_str()),
            ));
        });
    }
    Ok(outcome)
}

pub(crate) fn materialize_with_lowerer_inner<A: LanguageAdapter>(
    analyzer: &TreeSitterAnalyzer<A>,
    cache: &CompleteSemanticArtifactCache,
    lowerer: &dyn ProgramSemanticsLowerer,
    file: &ProjectFile,
    request: &mut SemanticRequest<'_>,
) -> Result<SemanticOutcome<Arc<SemanticArtifact>>, SemanticProviderError> {
    let started_work = request.budget.used();
    if request.cancellation.is_cancelled() {
        return Ok(SemanticOutcome::Cancelled {
            partial: None,
            work: SemanticWork::default(),
        });
    }

    // Admit the file and its top-level traversal before preparing source or
    // consulting the artifact cache. A cache hit is still a materialized file
    // in this request, and a rejected file must perform no hidden work.
    if !request.charge_execution_traversal(1) || !request.admit_materialization(file) {
        return Ok(SemanticOutcome::Unknown {
            partial: None,
            work: SemanticWork::default(),
        });
    }

    validate_semantic_file(analyzer, file)?;

    // A repeat touch of an unchanged file must not read and hash it again.
    // This is the only path that can answer before the source is read, so it
    // is also the only one that can charge a lookup rather than a file.
    if let Some(artifact) = served_from_unchanged_source(analyzer, cache, lowerer, file, request)? {
        let staged_budget = request.budget.clone();
        let outcome = publish_cached(
            cache,
            artifact,
            SemanticWork::default(),
            staged_budget,
            request,
        );
        observe_complete_artifact(file, &outcome, request);
        return outcome;
    }

    // A blob whose complete semantic IR rows the store holds is served from
    // those rows: its source is neither read nor parsed.
    if let Some(oid) = analyzer.reusable_live_oid(file) {
        let fields = SemanticIrMountFields {
            mount: WorkspaceMountId::from_root(file.root()),
            path: WorkspaceRelativePath::try_from_path(file.rel_path())
                .expect("validated semantic path"),
            language: LanguageDialect::for_path(analyzer.adapter().language(), file.rel_path()),
        };
        let (read, parts) = stored_semantic_ir_publication_read(
            analyzer,
            file,
            |store, blob| store.read_semantic_ir_with_observed_scope(blob, &fields),
            None,
            request.cancellation,
        )?;
        let (content, source_bytes, parts, built_from) = match read {
            StoredSemanticIrRead::Observed(observation) => match &observation.head {
                StoredSemanticIrPublicationHead::Present {
                    content,
                    source_bytes,
                    ..
                } => {
                    record_stored_publication(analyzer, &observation, *content);
                    let built_from = publication_built_from(&observation, *content);
                    (
                        ContentIdentity::from_digest(StableDigest::from_array(*content)),
                        *source_bytes,
                        parts.expect("complete publication has rows"),
                        built_from,
                    )
                }
                _ => {
                    note_serve(
                        &SERVE_COUNTS.rows_misses,
                        "rows_miss",
                        file.rel_path().display(),
                    );
                    return materialize_with_lowerer_after_miss(
                        analyzer,
                        cache,
                        lowerer,
                        file,
                        request,
                        started_work,
                    );
                }
            },
            StoredSemanticIrRead::Refused => {
                analyzer.refuse_read_reuse();
                note_serve(
                    &SERVE_COUNTS.rows_misses,
                    "rows_miss",
                    file.rel_path().display(),
                );
                return materialize_with_lowerer_after_miss(
                    analyzer,
                    cache,
                    lowerer,
                    file,
                    request,
                    started_work,
                );
            }
        };
        note_serve(
            &SERVE_COUNTS.rows_hits,
            "rows_hit",
            file.rel_path().display(),
        );
        analyzer.semantic_source_digests().record(
            BlobKey {
                oid,
                lang: analyzer
                    .adapter()
                    .storage_language_key_for_file(file)
                    .into(),
                variant: analyzer.selected_parse_variant(file).ok_or_else(|| {
                    SemanticProviderError::internal(format!(
                        "selected parse variant unreadable for {file:?}"
                    ))
                })?,
            },
            content,
        );
        let key = semantic_artifact_key_from_content(
            file,
            LanguageDialect::for_path(analyzer.adapter().language(), file.rel_path()),
            content,
            None,
            lowerer.identity(),
        )?;
        let (acquisition, _cache_wait) = cache.acquire(
            &ProvenancedArtifactKey {
                artifact: key.clone(),
                built_from,
            },
            request.cancellation,
        );
        let staged_budget = request.budget.clone();
        let outcome = match acquisition {
            BudgetedValueAcquisition::Cached { value: artifact } => publish_cached(
                cache,
                Arc::clone(artifact.arc()),
                SemanticWork::default(),
                staged_budget,
                request,
            ),
            BudgetedValueAcquisition::Leader { permit } => publish_from_semantic_ir_rows(
                analyzer,
                cache,
                lowerer,
                key,
                source_bytes,
                parts,
                Some(permit),
                SemanticWork::default(),
                staged_budget,
                started_work,
                request,
            ),
            BudgetedValueAcquisition::Rejected => {
                unreachable!("semantic artifact cache never publishes rejected flights")
            }
            BudgetedValueAcquisition::Cancelled => Ok(SemanticOutcome::Cancelled {
                partial: None,
                work: SemanticWork::default(),
            }),
        };
        observe_complete_artifact(file, &outcome, request);
        return outcome;
    }

    materialize_with_lowerer_after_miss(analyzer, cache, lowerer, file, request, started_work)
}

/// Lowers a file that no semantic IR rows or unchanged-source artifact served.
pub(crate) fn materialize_with_lowerer_after_miss<A: LanguageAdapter>(
    analyzer: &TreeSitterAnalyzer<A>,
    cache: &CompleteSemanticArtifactCache,
    lowerer: &dyn ProgramSemanticsLowerer,
    file: &ProjectFile,
    request: &mut SemanticRequest<'_>,
    started_work: SemanticWork,
) -> Result<SemanticOutcome<Arc<SemanticArtifact>>, SemanticProviderError> {
    let mut producer_budget = crate::analyzer::semantic::SemanticBudget::producer();
    let max_source_bytes = producer_budget.remaining().source_bytes;
    let scope = crate::analyzer::AnalyzerQueryScope::new(analyzer);
    let (source_identity, prepared) = match analyzer.prepared_syntax_limited_cancellable(
        scope.token(),
        file,
        max_source_bytes,
        Some(request.cancellation),
    ) {
        PreparedSyntaxLimitedOutcome::Available(oid, prepared) => (oid, prepared),
        PreparedSyntaxLimitedOutcome::Refused(reason) => {
            return Err(SemanticProviderError::source_admission_refused(
                file.clone(),
                reason,
            ));
        }
        PreparedSyntaxLimitedOutcome::Cancelled => {
            return Ok(SemanticOutcome::Cancelled {
                partial: None,
                work: started_work,
            });
        }
        PreparedSyntaxLimitedOutcome::Unavailable => {
            return Err(SemanticProviderError::source_access(format!(
                "could not prepare the current source snapshot for `{file}`"
            )));
        }
        PreparedSyntaxLimitedOutcome::Exceeded(limit) => {
            let work = SemanticWork {
                source_bytes: limit.minimum_source_bytes(),
                ..SemanticWork::default()
            };
            let exceeded = producer_budget.check_admission(work).map_or_else(
                |exceeded| exceeded,
                |_| {
                    unreachable!(
                        "a source snapshot larger than the producer source budget must exceed it"
                    )
                },
            );
            return Ok(SemanticOutcome::ExceededBudget {
                partial: None,
                exceeded,
                work,
            });
        }
    };
    let source_work = SemanticWork {
        source_bytes: prepared.source().len(),
        ..SemanticWork::default()
    };

    if request.cancellation.is_cancelled() {
        request.budget.record_performed_work(source_work);
        return Ok(SemanticOutcome::Cancelled {
            partial: None,
            work: source_work,
        });
    }
    let staged_budget = request.budget.clone();

    let identity = lowerer.identity();
    // Reuse the prepared snapshot's digest. Recording it against the blob
    // identity also lets the next touch skip source preparation entirely.
    let content = ContentIdentity::from_source_digest(
        StableDigest::from_array(prepared.source_sha256()),
        prepared.dialect().language(),
        prepared.parse_variant(),
    );
    debug_assert_eq!(
        analyzer
            .selected_parse_variant(file)
            .ok_or_else(|| SemanticProviderError::internal(format!(
                "selected parse variant unreadable for {file:?}"
            )))?,
        prepared.parse_variant(),
        "prepared source and served source must select the same parse variant"
    );
    analyzer.semantic_source_digests().record(
        BlobKey {
            oid: source_identity,
            lang: analyzer
                .adapter()
                .storage_language_key_for_file(file)
                .into(),
            variant: prepared.parse_variant(),
        },
        content,
    );
    let key = semantic_artifact_key_for_prepared(file, &prepared, content, identity)?;
    // The selected live OID can be reread under the same authority as other
    // stored readers. A byte OID alone supplies no reusable selection.
    let fields = SemanticIrMountFields {
        mount: key.mount(),
        path: key.path().clone(),
        language: key.language(),
    };
    let (read, parts) = if analyzer.reusable_live_oid(file).is_some() {
        stored_semantic_ir_publication_read(
            analyzer,
            file,
            |store, blob| store.read_semantic_ir_with_observed_scope(blob, &fields),
            None,
            request.cancellation,
        )?
    } else {
        analyzer.refuse_read_reuse();
        // Content-addressed rows remain usable, but this read is unrecorded
        // because a byte OID is not an authoritative live selection.
        let blob = BlobKey {
            oid: source_identity,
            lang: analyzer
                .adapter()
                .storage_language_key_for_file(file)
                .into(),
            variant: prepared.parse_variant(),
        };
        let (head, parts) = if matches!(prepared.origin(), PreparedSourceOrigin::Disk) {
            analyzer
                .analyzer_store()
                .read_semantic_ir_with_observed_scope(&blob, &fields)
                .map_err(|error| SemanticProviderError::internal(error.to_string()))?
        } else {
            (SemanticIrHeadObservation::Missing, None)
        };
        let read = match head {
            SemanticIrHeadObservation::Present {
                active_epoch,
                row_digest,
                content: observed,
                source_bytes,
                ..
            } => StoredSemanticIrRead::Observed(Box::new(StoredSemanticIrObservation {
                selection: StoredSemanticIrSelection {
                    rel_path: rel_path_string(file).into_boxed_str(),
                    oid: source_identity,
                    storage_language: blob.lang.into(),
                    variant: prepared.parse_variant(),
                },
                head: StoredSemanticIrPublicationHead::Present {
                    active_epoch: active_epoch.into_boxed_str(),
                    row_digest: *row_digest.as_bytes(),
                    content: *observed.as_bytes(),
                    source_bytes,
                },
                source_content: None,
                rows: None,
            })),
            _ => StoredSemanticIrRead::Refused,
        };
        (read, parts)
    };
    let built_from = read_built_from(&read, *content.as_bytes());
    let permit = {
        let (acquisition, cache_wait) = cache.acquire(
            &ProvenancedArtifactKey {
                artifact: key.clone(),
                built_from,
            },
            request.cancellation,
        );
        if cache_wait.wait_ns > 0 {
            crate::profiling::note_with(|| {
                format!(
                    "semantic.complete_cache_wait waits={} wait_ns={}",
                    cache_wait.waits, cache_wait.wait_ns
                )
            });
        }
        match acquisition {
            BudgetedValueAcquisition::Cached { value: artifact } => {
                if let StoredSemanticIrRead::Observed(observation) = &read
                    && analyzer.reusable_live_oid(file).is_some()
                {
                    record_stored_publication(analyzer, observation, *content.as_bytes());
                }
                drop(prepared);
                let outcome = publish_cached(
                    cache,
                    Arc::clone(artifact.arc()),
                    source_work,
                    staged_budget,
                    request,
                );
                request.budget.record_performed_work(source_work);
                observe_complete_artifact(file, &outcome, request);
                return outcome;
            }
            BudgetedValueAcquisition::Leader { permit: leader } => Some(leader),
            BudgetedValueAcquisition::Rejected => {
                unreachable!("semantic artifact cache never publishes rejected flights")
            }
            BudgetedValueAcquisition::Cancelled => {
                return Ok(SemanticOutcome::Cancelled {
                    partial: None,
                    work: source_work,
                });
            }
        }
    };
    if let StoredSemanticIrRead::Observed(observation) = read {
        let answer = classify(&observation, *content.as_bytes());
        if analyzer.reusable_live_oid(file).is_some() {
            record_stored_publication(analyzer, &observation, *content.as_bytes());
        }
        if matches!(answer, StoredSemanticIrPublicationAnswer::Present { .. }) {
            let StoredSemanticIrPublicationHead::Present { source_bytes, .. } = observation.head
            else {
                unreachable!()
            };
            note_serve(
                &SERVE_COUNTS.rows_hits,
                "rows_hit",
                file.rel_path().display(),
            );
            drop(prepared);
            let mut staged_budget = staged_budget;
            staged_budget.record_performed_work(source_work);
            let outcome = publish_from_semantic_ir_rows(
                analyzer,
                cache,
                lowerer,
                key,
                source_bytes,
                parts.expect("complete publication has rows"),
                permit,
                source_work,
                staged_budget,
                started_work,
                request,
            );
            observe_complete_artifact(file, &outcome, request);
            return outcome;
        }
    } else {
        analyzer.refuse_read_reuse();
    }

    producer_budget
        .admit(source_work)
        .expect("prepared source fits the producer source limit");
    note_serve(&SERVE_COUNTS.lowerings, "lowering", key.path().as_str());
    #[cfg(any(test, feature = "test-support"))]
    cache.record_lowering(key.path());
    let repeat = crate::profiling::enabled() && producer_budget.record_lowering(key.fingerprint());
    let lowerer_started = std::time::Instant::now();
    producer_budget.start_lowering_work();
    let lowered = if let Some(primary_lowerer) = lowerer.primary_declaration_lowerer() {
        lower_with_primary_declarations(
            primary_lowerer,
            file,
            &prepared,
            &producer_budget,
            request.cancellation,
            || {
                analyzer
                    .adapter()
                    .parse_file_preprocessed(
                        file,
                        prepared.source(),
                        prepared.tree(),
                        prepared.preprocessor().map(|p| p.as_ref()),
                    )
                    .0
            },
        )
    } else {
        lowerer.lower(file, &prepared, &producer_budget, request.cancellation)
    };
    let lowerer_ns = u64::try_from(lowerer_started.elapsed().as_nanos()).unwrap_or(u64::MAX);
    SERVE_COUNTS
        .lowerer_ns
        .fetch_add(lowerer_ns, Ordering::Relaxed);
    if repeat {
        SERVE_COUNTS
            .repeat_lowerer_ns
            .fetch_add(lowerer_ns, Ordering::Relaxed);
    }
    crate::profiling::note_with(|| {
        format!(
            "semantic.lowerer_duration {} lowerer_seconds={:.9} repeat_lowerer_seconds={:.9}",
            file.rel_path().display(),
            SERVE_COUNTS.lowerer_ns.load(Ordering::Relaxed) as f64 / 1e9,
            SERVE_COUNTS.repeat_lowerer_ns.load(Ordering::Relaxed) as f64 / 1e9,
        )
    });
    drop(prepared);
    // Source and builder allocations close on every exit, while accepted
    // binding traversal survives cancellation, a partial result, and errors.
    producer_budget.finish_lowering_work();
    let producer_work = producer_budget.performed();
    let produced_source = SemanticWork {
        source_bytes: producer_work.source_bytes,
        ..SemanticWork::default()
    };
    request.budget.record_performed_work(produced_source);
    request
        .budget
        .charge_work(producer_work.saturating_sub(produced_source));
    let lowered = match lowered {
        Ok(lowered) => lowered,
        Err(error) => {
            return Err(error);
        }
    };
    if request.cancellation.is_cancelled() {
        if let SemanticOutcome::Cancelled {
            partial: Some(_), ..
        } = &lowered
        {
            // A lowerer-supplied partial still has to pass ordinary publication
            // below before it can be retained by a cancelled outcome.
        } else {
            let work = source_work.component_max(lowered.work());
            return Ok(SemanticOutcome::Cancelled {
                partial: None,
                work,
            });
        }
    }

    let produced = {
        let mut producer_request = SemanticRequest::new(&mut producer_budget, request.cancellation);
        publish_lowered(
            cache.retention_budget(),
            key,
            lowerer.capabilities(),
            lowered,
            source_work,
            SemanticWork::default(),
            crate::analyzer::semantic::SemanticBudget::producer(),
            &mut producer_request,
        )?
    };
    let outcome = match produced {
        SemanticOutcome::Complete { value, work } => {
            if let Some(permit) = permit {
                cache.publish(permit, &value);
            }
            let census = value.work();
            request
                .budget
                .charge_work(work.saturating_sub(census).saturating_sub(producer_work));
            match publish_cached(cache, value, source_work, request.budget.clone(), request) {
                Ok(SemanticOutcome::Complete { value, .. }) => {
                    Ok(SemanticOutcome::Complete { value, work })
                }
                other => other,
            }
        }
        other => {
            request
                .budget
                .charge_work(other.work().saturating_sub(producer_work));
            Ok(other)
        }
    };
    observe_complete_artifact(file, &outcome, request);
    outcome
}

/// Serve one already-lowered artifact for a file whose content the workspace
/// can identify without reading it.
///
/// Three facts have to line up, and any one of them missing falls through to
/// the ordinary read-and-lower path rather than guessing:
///
/// 1. the workspace has a reusable blob identity for the file, either paired
///    with an unchanged stat or owned by the current explicit-update
///    generation (`reusable_live_oid` refuses overlays);
/// 2. the content digest for that blob identity has already been derived, so
///    the artifact key can be rebuilt without hashing the file;
/// 3. the complete-artifact cache already holds that exact key.
///
/// Everything in the key other than the content digest is derived the same way
/// `current_artifact_source_with_lowerer` derives it, from the path and the
/// lowerer's identity, so a stale adapter, configuration, dependency, or IR
/// version cannot be served: it produces a different key, which misses.
pub(crate) fn served_from_unchanged_source<A: LanguageAdapter>(
    analyzer: &TreeSitterAnalyzer<A>,
    cache: &CompleteSemanticArtifactCache,
    lowerer: &dyn ProgramSemanticsLowerer,
    file: &ProjectFile,
    request: &SemanticRequest<'_>,
) -> Result<Option<Arc<SemanticArtifact>>, SemanticProviderError> {
    let Some(source_identity) = analyzer.reusable_live_oid(file) else {
        return Ok(None);
    };
    let Some(content) = analyzer.semantic_source_digests().get(BlobKey {
        oid: source_identity,
        lang: analyzer
            .adapter()
            .storage_language_key_for_file(file)
            .into(),
        variant: analyzer.selected_parse_variant(file).ok_or_else(|| {
            SemanticProviderError::internal(format!(
                "selected parse variant unreadable for {file:?}"
            ))
        })?,
    }) else {
        return Ok(None);
    };
    let key = semantic_artifact_key_from_content(
        file,
        LanguageDialect::for_path(analyzer.adapter().language(), file.rel_path()),
        content,
        None,
        lowerer.identity(),
    )?;
    let (read, _) = stored_semantic_ir_publication_read(
        analyzer,
        file,
        |store, blob| {
            store
                .semantic_ir_head_observation(blob)
                .map(|head| (head, None::<()>))
        },
        None,
        request.cancellation,
    )?;
    if matches!(read, StoredSemanticIrRead::Refused) {
        analyzer.refuse_read_reuse();
    }
    let built_from = read_built_from(&read, *content.as_bytes());
    let hit = cache.get_ready(
        &ProvenancedArtifactKey {
            artifact: key,
            built_from,
        },
        request.cancellation,
    );
    if hit.is_some()
        && let StoredSemanticIrRead::Observed(observation) = &read
    {
        record_stored_publication(analyzer, observation, *content.as_bytes());
    }
    Ok(hit)
}

/// The blob's complete semantic IR rows under the active producer epoch. Any
/// other publication outcome is not served: the caller lowers the file.
/// Bind selection, one SQLite observation, and the post-observation selection.
pub fn stored_semantic_ir_publication_read<A: LanguageAdapter, T>(
    analyzer: &TreeSitterAnalyzer<A>,
    file: &ProjectFile,
    child_read: impl FnOnce(
        &crate::analyzer::store::AnalyzerStore,
        &BlobKey,
    )
        -> crate::analyzer::store::Result<(SemanticIrHeadObservation, Option<T>)>,
    source_byte_cap: Option<usize>,
    cancellation: &CancellationToken,
) -> Result<(StoredSemanticIrRead, Option<T>), SemanticProviderError> {
    if validate_semantic_file(analyzer, file).is_err() {
        return Ok((StoredSemanticIrRead::Refused, None));
    }
    let sample = || {
        Some(StoredSemanticIrSelection {
            rel_path: rel_path_string(file).into_boxed_str(),
            oid: analyzer.reusable_live_oid(file)?,
            storage_language: analyzer
                .adapter()
                .storage_language_key_for_file(file)
                .into(),
            variant: {
                let selected = analyzer.selected_parse_variant(file)?;
                #[cfg(any(test, feature = "test-support"))]
                let selected =
                    STORED_READ_VARIANT_OVERRIDE.with(|slot| slot.get().unwrap_or(selected));
                selected
            },
        })
    };
    if cancellation.is_cancelled() {
        return Ok((StoredSemanticIrRead::Refused, None));
    }
    let Some(selection) = sample() else {
        return Ok((StoredSemanticIrRead::Refused, None));
    };
    let key = BlobKey {
        oid: selection.oid,
        lang: selection.storage_language.as_ref().into(),
        variant: selection.variant,
    };
    let store = analyzer.analyzer_store();
    let (observation, child) = child_read(store, &key)
        .map_err(|error| SemanticProviderError::internal(error.to_string()))?;
    #[cfg(any(test, feature = "test-support"))]
    STORED_READ_AFTER_OBSERVATION.with(|hook| {
        if let Some(hook) = hook.borrow_mut().take() {
            hook();
        }
    });
    if cancellation.is_cancelled() || sample().as_ref() != Some(&selection) {
        return Ok((StoredSemanticIrRead::Refused, None));
    }
    let mut source_content = None;
    let head = match observation {
        SemanticIrHeadObservation::Missing => StoredSemanticIrPublicationHead::NoHead,
        SemanticIrHeadObservation::StaleEpoch => StoredSemanticIrPublicationHead::StaleEpoch,
        SemanticIrHeadObservation::NotComplete | SemanticIrHeadObservation::LegacyNoDigest => {
            return Ok((StoredSemanticIrRead::Refused, None));
        }
        SemanticIrHeadObservation::Present {
            active_epoch,
            row_digest,
            content,
            source_bytes,
            ..
        } => StoredSemanticIrPublicationHead::Present {
            active_epoch: active_epoch.into_boxed_str(),
            row_digest: *row_digest.as_bytes(),
            content: *content.as_bytes(),
            source_bytes,
        },
    };
    if matches!(
        head,
        StoredSemanticIrPublicationHead::NoHead | StoredSemanticIrPublicationHead::StaleEpoch
    ) && let Some(cap) = source_byte_cap
    {
        if cancellation.is_cancelled() {
            return Ok((StoredSemanticIrRead::Refused, None));
        }
        let Ok(Some((oid, snapshot))) = analyzer.source_snapshot_limited(file, cap) else {
            return Ok((StoredSemanticIrRead::Refused, None));
        };
        if oid != selection.oid
            || cancellation.is_cancelled()
            || sample().as_ref() != Some(&selection)
        {
            return Ok((StoredSemanticIrRead::Refused, None));
        }
        source_content = Some(
            *ContentIdentity::from_source_bytes(
                snapshot.into_source().as_bytes(),
                analyzer.adapter().language(),
                selection.variant,
            )
            .as_bytes(),
        );
    }
    Ok((
        StoredSemanticIrRead::Observed(Box::new(StoredSemanticIrObservation {
            selection,
            head,
            source_content,
            rows: None,
        })),
        child,
    ))
}

fn publication_built_from(
    observation: &StoredSemanticIrObservation,
    subject: [u8; 32],
) -> StableDigest {
    StoredSemanticIrPublicationQuestion::new(
        observation.selection.rel_path.clone(),
        observation.selection.storage_language.clone(),
        subject,
        observation.selection.variant,
    )
    .built_from_digest(&classify(observation, subject))
}

fn read_built_from(read: &StoredSemanticIrRead, subject: [u8; 32]) -> StableDigest {
    match read {
        StoredSemanticIrRead::Observed(observation) => publication_built_from(observation, subject),
        StoredSemanticIrRead::Refused => *REFUSED_PROVENANCE,
    }
}

#[cfg(test)]
mod provenance_tests {
    use super::*;

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#9784: review found a row-built artifact sharing REFUSED cache provenance"
    )]
    fn observed_rows_use_publication_provenance_without_live_authority() {
        let observation = |row_digest| {
            StoredSemanticIrRead::Observed(Box::new(StoredSemanticIrObservation {
                selection: StoredSemanticIrSelection {
                    rel_path: "Sample.java".into(),
                    oid: git2::Oid::zero(),
                    storage_language: "java".into(),
                    variant: brokk_bifrost_core::gitblob::ParseVariant::Empty,
                },
                head: StoredSemanticIrPublicationHead::Present {
                    active_epoch: "test".into(),
                    row_digest,
                    content: [1; 32],
                    source_bytes: 10,
                },
                source_content: None,
                rows: None,
            }))
        };
        let first = read_built_from(&observation([2; 32]), [1; 32]);
        let second = read_built_from(&observation([3; 32]), [1; 32]);
        assert_ne!(first, second);
        assert_ne!(first, *REFUSED_PROVENANCE);
        assert_ne!(second, *REFUSED_PROVENANCE);
        assert_eq!(
            read_built_from(&StoredSemanticIrRead::Refused, [1; 32]),
            *REFUSED_PROVENANCE
        );
    }
}

fn record_stored_publication<A: LanguageAdapter>(
    analyzer: &TreeSitterAnalyzer<A>,
    observation: &StoredSemanticIrObservation,
    subject: [u8; 32],
) {
    let question = StoredSemanticIrPublicationQuestion::new(
        observation.selection.rel_path.clone(),
        observation.selection.storage_language.clone(),
        subject,
        observation.selection.variant,
    );
    analyzer.record_read(ReadKey::lookup(
        LookupKind::StoredSemanticIrPublication,
        LookupQuestion::StoredSemanticIrPublication(question),
        classify(observation, subject).canonical_digest(),
    ));
}

fn admitted_stored_child<A: LanguageAdapter, T>(
    analyzer: &TreeSitterAnalyzer<A>,
    file: &ProjectFile,
    subject: [u8; 32],
    child_read: impl FnOnce(
        &crate::analyzer::store::AnalyzerStore,
        &BlobKey,
    )
        -> crate::analyzer::store::Result<(SemanticIrHeadObservation, Option<T>)>,
) -> Result<Option<T>, SemanticProviderError> {
    let (read, child) = stored_semantic_ir_publication_read(
        analyzer,
        file,
        child_read,
        None,
        &CancellationToken::default(),
    )?;
    let StoredSemanticIrRead::Observed(observation) = read else {
        analyzer.refuse_read_reuse();
        return Ok(None);
    };
    let present = matches!(
        classify(&observation, subject),
        StoredSemanticIrPublicationAnswer::Present { .. }
    );
    record_stored_publication(analyzer, &observation, subject);
    if present { Ok(child) } else { Ok(None) }
}

#[cfg(any(test, feature = "test-support"))]
thread_local! {
    static STORED_READ_AFTER_OBSERVATION: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
    static STORED_READ_VARIANT_OVERRIDE: std::cell::Cell<Option<brokk_bifrost_core::gitblob::ParseVariant>> =
        const { std::cell::Cell::new(None) };
}

#[cfg(any(test, feature = "test-support"))]
pub fn on_stored_read_after_observation(hook: impl FnOnce() + 'static) {
    STORED_READ_AFTER_OBSERVATION.with(|slot| {
        assert!(slot.borrow_mut().replace(Box::new(hook)).is_none());
    });
}

#[cfg(any(test, feature = "test-support"))]
pub fn override_stored_read_variant(variant: Option<brokk_bifrost_core::gitblob::ParseVariant>) {
    STORED_READ_VARIANT_OVERRIDE.with(|slot| slot.set(variant));
}

/// One procedure's stored partial flows, when the file's complete publication
/// carries the artifact `key`. `None` when there is no complete
/// publication, or its content is another revision's; the caller then computes
/// the flows at query time.
pub(crate) fn stored_partial_flows<A: LanguageAdapter>(
    analyzer: &TreeSitterAnalyzer<A>,
    file: &ProjectFile,
    key: &SemanticArtifactKey,
    procedure: ProcedureId,
) -> Result<Option<ProcedurePartialFlows>, SemanticProviderError> {
    let scope = SemanticIrMountScope {
        mount: key.mount(),
        path: key.path().clone(),
        language: key.language(),
        content: key.revision().content(),
    };
    admitted_stored_child(
        analyzer,
        file,
        *key.revision().content().as_bytes(),
        |store, blob| store.read_partial_flows_with_observation(blob, &scope, procedure),
    )
}

/// Decode the selected procedure without reconstructing every procedure of
/// the blob. Publication and content checks match the whole-blob reader.
pub(crate) fn stored_semantic_ir_procedure<A: LanguageAdapter>(
    analyzer: &TreeSitterAnalyzer<A>,
    file: &ProjectFile,
    key: &SemanticArtifactKey,
    procedure: ProcedureId,
) -> Result<Option<ProcedureSemanticsParts>, SemanticProviderError> {
    let scope = SemanticIrMountScope {
        mount: key.mount(),
        path: key.path().clone(),
        language: key.language(),
        content: key.revision().content(),
    };
    admitted_stored_child(
        analyzer,
        file,
        *key.revision().content().as_bytes(),
        |store, blob| store.read_semantic_ir_procedure_with_observation(blob, &scope, procedure),
    )
}

/// Whether the file's complete semantic IR publication carries the content of
/// the artifact `key`.
pub(crate) fn has_complete_semantic_ir_rows<A: LanguageAdapter>(
    analyzer: &TreeSitterAnalyzer<A>,
    file: &ProjectFile,
    key: &SemanticArtifactKey,
) -> Result<bool, SemanticProviderError> {
    Ok(admitted_stored_child(
        analyzer,
        file,
        *key.revision().content().as_bytes(),
        |store, blob| {
            store
                .semantic_ir_head_observation(blob)
                .map(|head| (head, Some(())))
        },
    )?
    .is_some())
}

/// Decodes one blob's rows and publishes them as the artifact that lowering
/// the same source produces. The caller holds the flight `permit` for `key`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn publish_from_semantic_ir_rows(
    analyzer: &TreeSitterAnalyzer<impl LanguageAdapter>,
    cache: &CompleteSemanticArtifactCache,
    lowerer: &dyn ProgramSemanticsLowerer,
    key: SemanticArtifactKey,
    source_bytes: usize,
    parts: Vec<ProcedureSemanticsParts>,
    permit: Option<
        BudgetedValuePermit<
            ProvenancedArtifactKey,
            brokk_bifrost_store::analyzer::semantic::service::CachedSemanticArtifact,
        >,
    >,
    source_work: SemanticWork,
    staged_budget: crate::analyzer::semantic::SemanticBudget,
    started_work: SemanticWork,
    request: &mut SemanticRequest<'_>,
) -> Result<SemanticOutcome<Arc<SemanticArtifact>>, SemanticProviderError> {
    let work = SemanticWork {
        source_bytes,
        ..SemanticWork::default()
    };
    let outcome = publish_lowered(
        analyzer.analyzer_store().retention_budget(),
        key,
        lowerer.capabilities(),
        SemanticOutcome::Complete { value: parts, work },
        source_work,
        started_work,
        staged_budget,
        request,
    );
    if let Ok(SemanticOutcome::Complete { value, .. }) = &outcome
        && let Some(permit) = permit
    {
        cache.publish(permit, value);
    }
    outcome
}

use std::sync::atomic::Ordering;
