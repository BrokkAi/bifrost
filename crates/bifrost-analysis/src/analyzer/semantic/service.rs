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
        Err(failure @ PreparedSourceFailure::Exceeded(_)) => {
            // No artifact source carries the refused limit; it joins the
            // current captures, where its ambient mark went.
            analyzer.join_reuse_verdict(
                crate::analyzer::reuse_verdict::CarriesReuseVerdict::reuse_verdict(&failure),
            );
            return Ok(None);
        }
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

pub(crate) fn record_stored_publication<A: LanguageAdapter>(
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

/// Reconstruct guarded parts in their complete base context. The publication
/// authority check records the head; the guarded decoder verifies the seal.
/// Nothing here selects an alternate for execution or retains it across queries.
pub(crate) fn stored_candidate_macro_artifact<A: LanguageAdapter>(
    analyzer: &TreeSitterAnalyzer<A>,
    file: &ProjectFile,
    key: &SemanticArtifactKey,
    capabilities: &crate::analyzer::semantic::SemanticCapabilities,
    request: &mut SemanticRequest<'_>,
) -> Result<
    SemanticOutcome<Option<crate::analyzer::semantic::StoredCandidateMacroArtifact>>,
    SemanticProviderError,
> {
    stored_candidate_macro_with_projection(
        analyzer,
        file,
        key,
        capabilities,
        |guarded, source_bytes| {
            let work = SemanticWork {
                source_bytes,
                ..Default::default()
            };
            let alternates = guarded
                .into_iter()
                .map(|guarded| (guarded.parts, guarded.candidates.into_boxed_slice()))
                .collect();
            (alternates, work)
        },
        request,
    )
}

fn stored_candidate_macro_with_projection<A: LanguageAdapter>(
    analyzer: &TreeSitterAnalyzer<A>,
    file: &ProjectFile,
    key: &SemanticArtifactKey,
    capabilities: &crate::analyzer::semantic::SemanticCapabilities,
    project: impl FnOnce(
        Vec<crate::analyzer::store::semantic_ir::GuardedProcedure>,
        usize,
    ) -> (
        Vec<(
            ProcedureSemanticsParts,
            Box<[crate::analyzer::semantic::CandidateRecord]>,
        )>,
        SemanticWork,
    ),
    request: &mut crate::analyzer::semantic::SemanticRequest<'_>,
) -> Result<
    SemanticOutcome<Option<crate::analyzer::semantic::StoredCandidateMacroArtifact>>,
    SemanticProviderError,
> {
    if request.cancellation.is_cancelled() {
        return Ok(SemanticOutcome::Cancelled {
            partial: None,
            work: SemanticWork::default(),
        });
    }
    let scope = SemanticIrMountScope {
        mount: key.mount(),
        path: key.path().clone(),
        language: key.language(),
        content: key.revision().content(),
    };
    let (read, rows) = stored_semantic_ir_publication_read(
        analyzer,
        file,
        |store, blob| store.semantic_ir_candidate_macro_alternate(blob, &scope),
        Some(request.budget.limits().source_bytes),
        request.cancellation,
    )?;
    if request.cancellation.is_cancelled() {
        return Ok(SemanticOutcome::Cancelled {
            partial: None,
            work: SemanticWork::default(),
        });
    }
    let StoredSemanticIrRead::Observed(observation) = read else {
        analyzer.refuse_read_reuse();
        return Ok(SemanticOutcome::Complete {
            value: None,
            work: SemanticWork::default(),
        });
    };
    let subject = *key.revision().content().as_bytes();
    record_stored_publication(analyzer, &observation, subject);
    if !matches!(
        classify(&observation, subject),
        StoredSemanticIrPublicationAnswer::Present { .. }
    ) {
        return Ok(SemanticOutcome::Complete {
            value: None,
            work: SemanticWork::default(),
        });
    }
    let Some((base, guarded)) = rows else {
        return Ok(SemanticOutcome::Complete {
            value: None,
            work: SemanticWork::default(),
        });
    };
    if request.cancellation.is_cancelled() {
        return Ok(SemanticOutcome::Cancelled {
            partial: None,
            work: SemanticWork::default(),
        });
    }
    let StoredSemanticIrPublicationHead::Present { source_bytes, .. } = observation.head else {
        unreachable!()
    };
    let (alternates, read_work) = project(guarded, source_bytes);
    if let Err(exceeded) = request.budget.admit_artifact_rows(read_work) {
        return Ok(SemanticOutcome::ExceededBudget {
            partial: None,
            exceeded,
            work: SemanticWork::default(),
        });
    }
    let artifact = SemanticArtifact::try_new_with_candidate_alternates_and_budget(
        key.clone(),
        capabilities.clone(),
        base,
        alternates,
        request.budget,
        request.cancellation,
    );
    let mut artifact = match artifact {
        Ok(artifact) => artifact,
        Err(crate::analyzer::semantic::SemanticArtifactBuildError::Cancelled) => {
            return Ok(SemanticOutcome::Cancelled {
                partial: None,
                work: read_work,
            });
        }
        Err(crate::analyzer::semantic::SemanticArtifactBuildError::Invalid(error)) => {
            return Err(error.into());
        }
        Err(crate::analyzer::semantic::SemanticArtifactBuildError::ExceededBudget(exceeded)) => {
            return Ok(SemanticOutcome::ExceededBudget {
                partial: None,
                exceeded,
                work: read_work,
            });
        }
    };
    let work = read_work.saturating_add(artifact.work());
    if request.cancellation.is_cancelled() {
        return Ok(SemanticOutcome::Cancelled {
            partial: None,
            work,
        });
    }
    artifact.include_candidate_census(read_work);
    artifact.charge_guarded_arena(analyzer.analyzer_store().retention_budget());
    let artifact = Arc::new(artifact);
    request
        .budget
        .record_charged_artifact(artifact.key().fingerprint());
    request.budget.track_resident_artifact(&artifact);
    Ok(SemanticOutcome::Complete {
        work,
        value: Some(crate::analyzer::semantic::StoredCandidateMacroArtifact { artifact }),
    })
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

/// Completed native reconstruction shared only inside one request. Native
/// body receipts replay in batch order around each demanded target's guard.
#[derive(Debug)]
pub struct OwnershipFileBase {
    pub artifact: Arc<SemanticArtifact>,
    pub native_work: Box<[SemanticWork]>,
    pub native_rows: Box<[SemanticWork]>,
    pub prepass_work: SemanticWork,
    pub native_peaks: Box<[crate::analyzer::semantic::SemanticAdmissionPeak]>,
    pub metadata_charge: brokk_bifrost_core::retention_budget::AllocationCharge,
}

/// A cold reconstruction interleaves a lexical macro target in uncached batch
/// order. Other targets are built afterward in their own capture. Only the
/// native base enters the file memo.
#[derive(Debug)]
pub struct OwnershipFileBuild {
    pub base: Arc<OwnershipFileBase>,
    /// Only a lexical macro target is built inside the pure file capture.
    /// Executable certificates belong to the subsequent per-procedure capture.
    pub target: Option<OwnershipProcedureBuild>,
}
#[derive(Debug)]
pub struct OwnershipProcedureBuild {
    pub artifact: Arc<SemanticArtifact>,
    pub work: SemanticWork,
}

/// Factual disposition of one requested executable rule. Pending carries no
/// settled answer or digest; its unavailable inputs remain in the receipt.
#[derive(Debug)]
pub enum ExecutableRuleOutcome<T> {
    Realized(T),
    Opaque,
    Pending,
}

/// Body parts produced by language rules. Only the acquisition owner freezes
/// these parts into an executable interpretation and mints its handle.
#[derive(Debug)]
pub struct ExecutableProcedureBuild {
    pub parts: crate::analyzer::semantic::ProcedureSemanticsParts,
}

/// Transient read owner shared by every rule in one executable acquisition.
/// Required inputs replay immediately; unanswered optional needs are joined
/// only after strict admission. Every other exit publishes them on drop.
pub struct ExecutableRuleContext<'a> {
    analyzer: &'a dyn IAnalyzer,
    unserved_observations: Option<crate::analyzer::i_analyzer::QueryReadReceipt>,
    realizations: usize,
}

impl<'a> ExecutableRuleContext<'a> {
    fn new(analyzer: &'a dyn IAnalyzer) -> Self {
        Self {
            analyzer,
            unserved_observations: None,
            realizations: 0,
        }
    }

    pub fn analyzer(&self) -> &'a dyn IAnalyzer {
        self.analyzer
    }

    pub fn has_realizations(&self) -> bool {
        self.realizations != 0
    }

    pub fn capture<T>(
        &mut self,
        request: &mut SemanticRequest<'_>,
        rule: impl FnOnce(
            &dyn IAnalyzer,
            &mut SemanticRequest<'_>,
        )
            -> Result<SemanticOutcome<ExecutableRuleOutcome<T>>, SemanticProviderError>,
    ) -> Result<SemanticOutcome<Option<T>>, SemanticProviderError> {
        use crate::analyzer::i_analyzer::QueryReadReceipt;
        use crate::analyzer::read_ledger::DerivationExecutionCause;
        use brokk_bifrost_core::analyzer::reuse_verdict::{ExecutionCause, ReuseVerdict};
        let ((judged, refusal), reads) = QueryReadReceipt::capture_deferred(self.analyzer, || {
            request.judged_with_refusal(|request| rule(self.analyzer, request))
        });
        let outcome = judged.value;
        let work = outcome
            .as_ref()
            .map_or(SemanticWork::default(), SemanticOutcome::work);
        if let Some(refusal) = refusal {
            reads.replay(self.analyzer);
            return Ok(if request.cancellation.is_cancelled() {
                SemanticOutcome::Cancelled {
                    partial: None,
                    work,
                }
            } else {
                SemanticOutcome::ExceededBudget {
                    partial: None,
                    exceeded: refusal.exceeded,
                    work,
                }
            });
        }
        match judged.reuse {
            ReuseVerdict::Content => {}
            ReuseVerdict::ExecutionDependent(ExecutionCause::BudgetRefusal) => {
                unreachable!("a scoped refusal was handled with its recorded cause")
            }
            ReuseVerdict::ExecutionDependent(ExecutionCause::Other) => {
                reads.replay(self.analyzer);
                if request.cancellation.is_cancelled() {
                    return Ok(SemanticOutcome::Cancelled {
                        partial: None,
                        work,
                    });
                }
                // An execution-ledger stop has no semantic resident dimension.
                self.analyzer.record_query_incomplete(
                    crate::analyzer::i_analyzer::QueryReadIncomplete::ProofStopped {
                        reason: "executable rule acquisition stopped",
                        cause: Some(DerivationExecutionCause::Budget),
                    },
                );
                return Ok(SemanticOutcome::Unknown {
                    partial: None,
                    work,
                });
            }
            ReuseVerdict::ExecutionDependent(ExecutionCause::ConfiguredCap) => {
                unreachable!("request judging observes refusals and cancellation, not result caps")
            }
        }
        match outcome {
            Ok(SemanticOutcome::Complete { value, work }) => {
                let value = match value {
                    ExecutableRuleOutcome::Realized(value) => {
                        reads.replay(self.analyzer);
                        self.realizations = self.realizations.saturating_add(1);
                        Some(value)
                    }
                    ExecutableRuleOutcome::Opaque => {
                        assert!(
                            reads
                                .incomplete_reasons()
                                .iter()
                                .all(|reason| !reason.is_execution_dependent()),
                            "a settled opaque rule cannot conceal an unanswered or stopped input"
                        );
                        reads.replay(self.analyzer);
                        None
                    }
                    ExecutableRuleOutcome::Pending => {
                        assert!(
                            reads.incomplete_reasons().iter().any(|reason| {
                                reason.execution_cause() == Some(DerivationExecutionCause::Provider)
                            }),
                            "a pending rule must retain its unavailable input"
                        );
                        assert!(
                            reads.incomplete_reasons().iter().all(|reason| !matches!(
                                reason.execution_cause(),
                                Some(
                                    DerivationExecutionCause::Budget
                                        | DerivationExecutionCause::Cancelled
                                )
                            )),
                            "operational stops cannot be packaged as pending"
                        );
                        if let Some(unserved) = self.unserved_observations.as_mut() {
                            unserved.extend(&reads);
                        } else {
                            self.unserved_observations = Some(reads);
                        }
                        None
                    }
                };
                Ok(SemanticOutcome::Complete { value, work })
            }
            other => {
                reads.replay(self.analyzer);
                other.map(|outcome| {
                    outcome.map(|_| unreachable!("a stopped rule produces no realization"))
                })
            }
        }
    }
}

impl Drop for ExecutableRuleContext<'_> {
    fn drop(&mut self) {
        if let Some(unserved) = self.unserved_observations.take() {
            unserved.replay(self.analyzer);
        }
    }
}

/// A completed ownership proof and observations of optional needs it could not
/// serve. Required evidence stays in the enclosing strict acquisition capture.
/// The service checks that capture before publishing these observations, then
/// retains one merged receipt in the existing request-local procedure memo.
#[derive(Debug)]
pub struct OwnershipProcedureSelection {
    selected: SelectedProcedureHandle,
    unserved_observations: Option<crate::analyzer::i_analyzer::QueryReadReceipt>,
}

impl OwnershipProcedureSelection {
    pub fn new(
        selected: SelectedProcedureHandle,
        unserved_observations: Option<crate::analyzer::i_analyzer::QueryReadReceipt>,
    ) -> Self {
        assert!(
            unserved_observations
                .as_ref()
                .is_none_or(|reads| !reads.incomplete_reasons().is_empty()),
            "unserved ownership observations must name their incomplete needs"
        );
        Self {
            selected,
            unserved_observations,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct QueryOwnershipFile {
    file: Arc<OwnershipFileBase>,
    receipt: crate::analyzer::i_analyzer::QueryReadReceipt,
    _charge: Arc<brokk_bifrost_core::retention_budget::AllocationCharge>,
}

#[derive(Debug)]
pub(crate) struct OwnershipFileSlot {
    value: std::sync::Mutex<Option<QueryOwnershipFile>>,
    _charge: brokk_bifrost_core::retention_budget::AllocationCharge,
}
impl OwnershipFileSlot {
    fn new(workspace: &crate::analyzer::workspace::WorkspaceAnalyzer) -> Self {
        Self {
            value: Default::default(),
            _charge: brokk_bifrost_core::retention_budget::AllocationCharge::acquire(
                workspace.retention_budget(),
                std::mem::size_of::<Self>().saturating_add(128),
            ),
        }
    }
}

/// An admitted ownership interpretation lives only in its outer request.
/// Executable selections have a separate memo and cannot consume this view.
#[derive(Debug, Clone)]
pub(crate) struct QueryOwnershipProcedure {
    selected: SelectedProcedureHandle,
    receipt: crate::analyzer::i_analyzer::QueryReadReceipt,
    _charge: Arc<brokk_bifrost_core::retention_budget::AllocationCharge>,
}

fn observe_ownership_artifact(
    workspace: &crate::analyzer::workspace::WorkspaceAnalyzer,
    selected: &SelectedProcedureHandle,
    request: &SemanticRequest<'_>,
) {
    if let Some(collector) = request.artifact_collector() {
        let file = ProjectFile::new(
            workspace.analyzer().project().root().to_path_buf(),
            selected.handle.artifact().key().path().as_path(),
        );
        collector.observe_complete(&file, selected.handle.artifact());
    }
}

fn record_ownership_acquisition_stopped(
    analyzer: &dyn IAnalyzer,
    cause: crate::analyzer::read_ledger::DerivationExecutionCause,
) {
    analyzer.record_query_incomplete(
        crate::analyzer::i_analyzer::QueryReadIncomplete::ProofStopped {
            reason: "ownership lexical guard acquisition stopped",
            cause: Some(cause),
        },
    );
}

fn ownership_acquisition_stopped<T>(
    analyzer: &dyn IAnalyzer,
    cause: crate::analyzer::read_ledger::DerivationExecutionCause,
    work: SemanticWork,
) -> SemanticOutcome<T> {
    record_ownership_acquisition_stopped(analyzer, cause);
    SemanticOutcome::Unknown {
        partial: None,
        work,
    }
}

/// Replay only an exact handle already admitted into this request's ownership
/// memo. In particular, a base handle and an independently minted alternate
/// cannot acquire an ownership interpretation through this transport path.
pub(crate) fn replay_ownership_procedure_handle(
    workspace: &crate::analyzer::workspace::WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
    request: &mut SemanticRequest<'_>,
) -> Result<SemanticOutcome<Option<ProcedureHandle>>, SemanticProviderError> {
    use crate::analyzer::read_ledger::DerivationExecutionCause;
    let outcome = replay_acquired_procedure(workspace, procedure, request)?;
    Ok(match outcome {
        SemanticOutcome::Cancelled { work, .. } => ownership_acquisition_stopped(
            workspace.analyzer(),
            DerivationExecutionCause::Cancelled,
            work,
        ),
        SemanticOutcome::ExceededBudget { work, .. } => ownership_acquisition_stopped(
            workspace.analyzer(),
            DerivationExecutionCause::Budget,
            work,
        ),
        outcome => outcome.map(|selected| selected.map(|selected| selected.handle)),
    })
}

/// Both authorities transport the exact acquiring receipt. The legacy
/// ownership entry alone translates operational stops to its old protocol.
fn replay_acquired_procedure(
    workspace: &crate::analyzer::workspace::WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
    request: &mut SemanticRequest<'_>,
) -> Result<SemanticOutcome<Option<SelectedProcedureHandle>>, SemanticProviderError> {
    use crate::analyzer::read_ledger::DerivationExecutionCause;
    let unchanged = || SemanticOutcome::Complete {
        value: None,
        work: SemanticWork::default(),
    };
    if !procedure.is_guarded_alternate() {
        return Ok(unchanged());
    }
    let without_receipt = || match procedure.interpretation() {
        crate::analyzer::semantic::ProcedureInterpretation::Base
        | crate::analyzer::semantic::ProcedureInterpretation::CandidateAlternate => unchanged(),
        crate::analyzer::semantic::ProcedureInterpretation::ExecutableAlternate => {
            workspace.analyzer().record_query_incomplete(
                crate::analyzer::i_analyzer::QueryReadIncomplete::ProofStopped {
                    reason: "executable body has no acquiring request receipt",
                    cause: Some(DerivationExecutionCause::Provider),
                },
            );
            SemanticOutcome::Unknown {
                partial: None,
                work: SemanticWork::default(),
            }
        }
    };
    let Some(query) = crate::analyzer::i_analyzer::candidate_overlay_query_context() else {
        return Ok(without_receipt());
    };
    let hit = query
        .ownership_procedures
        .lock()
        .expect("ownership selection lock")
        .get(&procedure.durable_key())
        .filter(|entry| entry.selected.handle == *procedure)
        .cloned();
    let Some(hit) = hit else {
        return Ok(without_receipt());
    };
    hit.receipt.replay(workspace.analyzer());
    if request.cancellation.is_cancelled() {
        return Ok(SemanticOutcome::Cancelled {
            partial: None,
            work: SemanticWork::default(),
        });
    }
    if let Err(exceeded) = request
        .budget
        .charge_complete_artifact(procedure.artifact())
    {
        return Ok(SemanticOutcome::ExceededBudget {
            partial: None,
            exceeded,
            work: SemanticWork::default(),
        });
    }
    observe_ownership_artifact(workspace, &hit.selected, request);
    Ok(SemanticOutcome::Complete {
        value: Some(hit.selected),
        work: SemanticWork::default(),
    })
}

/// Demand-only ownership acquisition. Never publishes native IR or retains a
/// stopped result, and never changes ordinary executable-selection memos.
pub(crate) fn ownership_procedure_handle(
    workspace: &crate::analyzer::workspace::WorkspaceAnalyzer,
    base: &ProcedureHandle,
    request: &mut SemanticRequest<'_>,
) -> Result<SemanticOutcome<SelectedProcedureHandle>, SemanticProviderError> {
    use crate::analyzer::read_ledger::DerivationExecutionCause;
    let outcome = acquire_owned_procedure(workspace, base, request, &OwnershipViewFactory)?;
    Ok(match outcome {
        SemanticOutcome::Cancelled { work, .. } => ownership_acquisition_stopped(
            workspace.analyzer(),
            DerivationExecutionCause::Cancelled,
            work,
        ),
        SemanticOutcome::ExceededBudget { work, .. } => ownership_acquisition_stopped(
            workspace.analyzer(),
            DerivationExecutionCause::Budget,
            work,
        ),
        outcome => outcome,
    })
}

pub(crate) fn executable_procedure_handle(
    workspace: &crate::analyzer::workspace::WorkspaceAnalyzer,
    base: &ProcedureHandle,
    request: &mut SemanticRequest<'_>,
) -> Result<SemanticOutcome<SelectedProcedureHandle>, SemanticProviderError> {
    use crate::analyzer::read_ledger::DerivationExecutionCause;
    let outcome = if base.interpretation()
        == crate::analyzer::semantic::ProcedureInterpretation::ExecutableAlternate
    {
        replay_acquired_procedure(workspace, base, request)?.map(|selected| {
            selected.expect("an executable body without its acquiring receipt is refused")
        })
    } else {
        acquire_owned_procedure(workspace, base, request, &ExecutableFactory)?
    };
    let cause = match &outcome {
        SemanticOutcome::Cancelled { .. } => Some(DerivationExecutionCause::Cancelled),
        SemanticOutcome::ExceededBudget { .. } => Some(DerivationExecutionCause::Budget),
        _ => None,
    };
    if let Some(cause) = cause {
        record_ownership_acquisition_stopped(workspace.analyzer(), cause);
    }
    Ok(outcome)
}

type OwnershipFileResult =
    Result<SemanticOutcome<Option<OwnershipFileBuild>>, SemanticProviderError>;
type OwnershipTargetResult =
    Result<SemanticOutcome<Option<OwnershipProcedureSelection>>, SemanticProviderError>;

/// Admission rules select the language factory, not a second acquisition
/// algorithm. Both consumers share the file slot, unit ledger and one receipt.
trait OwnershipAcquisitionFactory {
    /// Cache identity of the requested authority, not a mode of acquisition.
    /// A proved Base result still belongs to the authority that acquired it.
    fn interpretation(&self) -> crate::analyzer::semantic::ProcedureInterpretation;

    fn memo_key(&self, base: &ProcedureHandle) -> crate::analyzer::semantic::DurableProcedureKey {
        let mut key = base.base_interpretation().durable_key();
        key.2 = self.interpretation();
        key
    }

    fn can_refine(
        &self,
        _support: Option<&dyn crate::analyzer::languages::LanguageSupport>,
        _base: &ProcedureHandle,
    ) -> bool {
        true
    }
    fn accepts_selection(&self, selected: &SelectedProcedureHandle) -> bool;
    fn file_base(
        &self,
        support: &dyn crate::analyzer::languages::LanguageSupport,
        workspace: &crate::analyzer::workspace::WorkspaceAnalyzer,
        base: &ProcedureHandle,
        request: &mut SemanticRequest<'_>,
    ) -> OwnershipFileResult;
    fn target(
        &self,
        support: &dyn crate::analyzer::languages::LanguageSupport,
        workspace: &crate::analyzer::workspace::WorkspaceAnalyzer,
        base: &ProcedureHandle,
        shared: &OwnershipFileBase,
        request: &mut SemanticRequest<'_>,
    ) -> OwnershipTargetResult;
    fn admit_first(
        &self,
        support: &dyn crate::analyzer::languages::LanguageSupport,
        workspace: &crate::analyzer::workspace::WorkspaceAnalyzer,
        base: &ProcedureHandle,
        built: &OwnershipProcedureBuild,
        request: &mut SemanticRequest<'_>,
    ) -> OwnershipTargetResult {
        support.admit_ownership_procedure(workspace, base, built, request)
    }
}

struct OwnershipViewFactory;
impl OwnershipAcquisitionFactory for OwnershipViewFactory {
    fn interpretation(&self) -> crate::analyzer::semantic::ProcedureInterpretation {
        crate::analyzer::semantic::ProcedureInterpretation::CandidateAlternate
    }
    fn accepts_selection(&self, selected: &SelectedProcedureHandle) -> bool {
        selected.handle.interpretation()
            != crate::analyzer::semantic::ProcedureInterpretation::ExecutableAlternate
    }
    fn file_base(
        &self,
        support: &dyn crate::analyzer::languages::LanguageSupport,
        workspace: &crate::analyzer::workspace::WorkspaceAnalyzer,
        base: &ProcedureHandle,
        request: &mut SemanticRequest<'_>,
    ) -> OwnershipFileResult {
        support.ownership_file_base(workspace, base, request)
    }
    fn target(
        &self,
        support: &dyn crate::analyzer::languages::LanguageSupport,
        workspace: &crate::analyzer::workspace::WorkspaceAnalyzer,
        base: &ProcedureHandle,
        shared: &OwnershipFileBase,
        request: &mut SemanticRequest<'_>,
    ) -> OwnershipTargetResult {
        support.ownership_procedure_interpretation(workspace, base, shared, request)
    }
}

struct ExecutableFactory;
impl OwnershipAcquisitionFactory for ExecutableFactory {
    fn interpretation(&self) -> crate::analyzer::semantic::ProcedureInterpretation {
        crate::analyzer::semantic::ProcedureInterpretation::ExecutableAlternate
    }
    fn can_refine(
        &self,
        support: Option<&dyn crate::analyzer::languages::LanguageSupport>,
        base: &ProcedureHandle,
    ) -> bool {
        support.is_some_and(|support| support.executable_procedure_may_refine(base))
    }
    fn accepts_selection(&self, selected: &SelectedProcedureHandle) -> bool {
        selected.handle.interpretation()
            == crate::analyzer::semantic::ProcedureInterpretation::ExecutableAlternate
    }
    fn file_base(
        &self,
        support: &dyn crate::analyzer::languages::LanguageSupport,
        workspace: &crate::analyzer::workspace::WorkspaceAnalyzer,
        base: &ProcedureHandle,
        request: &mut SemanticRequest<'_>,
    ) -> OwnershipFileResult {
        support.executable_file_base(workspace, base, request)
    }
    fn target(
        &self,
        support: &dyn crate::analyzer::languages::LanguageSupport,
        workspace: &crate::analyzer::workspace::WorkspaceAnalyzer,
        base: &ProcedureHandle,
        shared: &OwnershipFileBase,
        request: &mut SemanticRequest<'_>,
    ) -> OwnershipTargetResult {
        use crate::analyzer::semantic::SemanticArtifactBuildError;
        let mut rules = ExecutableRuleContext::new(workspace.analyzer());
        let outcome = support
            .executable_procedure_interpretation(workspace, base, shared, &mut rules, request)?;
        let work = outcome.work();
        let parts = match outcome {
            SemanticOutcome::Complete {
                value: Some(build), ..
            } => {
                assert!(
                    rules.has_realizations(),
                    "an executable body needs an actual realized rule"
                );
                build.parts
            }
            SemanticOutcome::Complete { value: None, .. } => {
                return Ok(SemanticOutcome::Complete { value: None, work });
            }
            other => return Ok(other.map(|_| unreachable!("a stopped factory has no body"))),
        };
        let artifact = match SemanticArtifact::try_executable_projection(
            shared.artifact.clone(),
            parts,
            shared.native_rows[base.id().index()],
            &mut request.budget.clone(),
            request.cancellation,
        ) {
            Ok(mut artifact) => {
                artifact.charge_guarded_arena(workspace.retention_budget());
                Arc::new(artifact)
            }
            Err(SemanticArtifactBuildError::ExceededBudget(exceeded)) => {
                return Ok(SemanticOutcome::ExceededBudget {
                    partial: None,
                    exceeded,
                    work,
                });
            }
            Err(SemanticArtifactBuildError::Cancelled) => {
                return Ok(SemanticOutcome::Cancelled {
                    partial: None,
                    work,
                });
            }
            Err(SemanticArtifactBuildError::Invalid(error)) => {
                return Err(SemanticProviderError::internal(error.to_string()));
            }
        };
        if let Err(exceeded) = request.budget.charge_complete_artifact(&artifact) {
            return Ok(SemanticOutcome::ExceededBudget {
                partial: None,
                exceeded,
                work,
            });
        }
        let handle = artifact
            .executable_alternate_handle(base.id())
            .expect("the executable factory froze its requested body");
        Ok(SemanticOutcome::Complete {
            value: Some(OwnershipProcedureSelection::new(
                SelectedProcedureHandle {
                    handle,
                    side: CandidateProcedureSide::Alternate,
                    refusals: Vec::new(),
                },
                rules.unserved_observations.take(),
            )),
            work,
        })
    }
    fn admit_first(
        &self,
        _support: &dyn crate::analyzer::languages::LanguageSupport,
        _workspace: &crate::analyzer::workspace::WorkspaceAnalyzer,
        _base: &ProcedureHandle,
        _built: &OwnershipProcedureBuild,
        _request: &mut SemanticRequest<'_>,
    ) -> OwnershipTargetResult {
        unreachable!("an executable file factory never builds a lexical target")
    }
}

fn acquire_owned_procedure(
    workspace: &crate::analyzer::workspace::WorkspaceAnalyzer,
    base: &ProcedureHandle,
    request: &mut SemanticRequest<'_>,
    factory: &dyn OwnershipAcquisitionFactory,
) -> Result<SemanticOutcome<SelectedProcedureHandle>, SemanticProviderError> {
    let analyzer = workspace.analyzer();
    if request.cancellation.is_cancelled() {
        return Ok(SemanticOutcome::Cancelled {
            partial: None,
            work: SemanticWork::default(),
        });
    }
    let base = base.base_interpretation();
    // The caller holds the base handle, so this function performs no lookup.
    // A base already resident in this request costs nothing more; a handle
    // acquired under another request is admitted here and can stop on the
    // budget. Preserve the acquisition factory's typed operational stop.
    if let Err(exceeded) = request.budget.admit_held_artifact(base.artifact()) {
        return Ok(SemanticOutcome::ExceededBudget {
            partial: None,
            exceeded,
            work: SemanticWork::default(),
        });
    }
    let support =
        crate::analyzer::languages::language_support(base.artifact().key().language().language());
    if !factory.can_refine(support, &base) {
        return workspace.selected_procedure_handle(&base, request);
    }
    // Preserve the executable candidate contract for mixed bodies.
    let original = workspace.selected_procedure_handle(&base, request)?;
    let original = match original {
        complete @ SemanticOutcome::Complete { .. } => complete,
        outcome => return Ok(outcome),
    };
    if base.semantics().candidate_macro_alternate().is_some() {
        return Ok(original);
    }
    let query = crate::analyzer::i_analyzer::candidate_overlay_query_context();
    let key = factory.memo_key(&base);
    let hit = query.as_ref().and_then(|query| {
        query
            .ownership_procedures
            .lock()
            .expect("ownership selection lock")
            .get(&key)
            .filter(|entry| factory.accepts_selection(&entry.selected))
            .cloned()
    });
    if let Some(hit) = hit {
        hit.receipt.replay(analyzer);
        if request.cancellation.is_cancelled() {
            return Ok(SemanticOutcome::Cancelled {
                partial: None,
                work: SemanticWork::default(),
            });
        }
        if let Err(exceeded) = request
            .budget
            .charge_complete_artifact(hit.selected.handle.artifact())
        {
            return Ok(SemanticOutcome::ExceededBudget {
                partial: None,
                exceeded,
                work: SemanticWork::default(),
            });
        }
        observe_ownership_artifact(workspace, &hit.selected, request);
        return Ok(SemanticOutcome::Complete {
            value: hit.selected,
            work: SemanticWork::default(),
        });
    }
    let Some(support) = support else {
        return Ok(original);
    };
    // Refinement is an independent proof unit: its refusal must not poison
    // the caller's already-completed base analysis. Reserve the caller's live
    // census under the same limits, and charge every attempted unit of work
    // back to the caller. Only a completed arena transfers a resident hold.
    let mut proof_budget = request.budget.unit_ledger();
    if let Err(exceeded) = proof_budget.admit(request.budget.resident()) {
        return Ok(SemanticOutcome::ExceededBudget {
            partial: None,
            exceeded,
            work: SemanticWork::default(),
        });
    }
    let inherited_work = proof_budget.performed();
    let (outcome, mut receipt) =
        crate::analyzer::i_analyzer::QueryReadReceipt::capture(analyzer, || {
            let file_key = base.artifact().materialization_id();
            let slot = query.as_ref().map_or_else(
                || Arc::new(OwnershipFileSlot::new(workspace)),
                |query| {
                    query
                        .ownership_files
                        .lock()
                        .expect("ownership file lock")
                        .entry(file_key)
                        .or_insert_with(|| Arc::new(OwnershipFileSlot::new(workspace)))
                        .clone()
                },
            );
            // The per-file lock covers cold construction only, never target
            // lowering. Concurrent targets share one completed base.
            let mut cache = slot.value.lock().expect("ownership base construction lock");
            if let Some(hit) = cache.as_ref() {
                hit.receipt.replay(analyzer);
                let shared = hit.file.clone();
                drop(cache);
                return factory.target(
                    support,
                    workspace,
                    &base,
                    &shared,
                    &mut request.staged(&mut proof_budget),
                );
            }
            let (built, reads) =
                crate::analyzer::i_analyzer::QueryReadReceipt::capture(analyzer, || {
                    factory.file_base(
                        support,
                        workspace,
                        &base,
                        &mut request.staged(&mut proof_budget),
                    )
                });
            let built = match built? {
                SemanticOutcome::Complete {
                    value: Some(built), ..
                } => built,
                SemanticOutcome::Complete { value: None, work } => {
                    return Ok(SemanticOutcome::Complete { value: None, work });
                }
                other => return Ok(other.map(|_| unreachable!("stopped file has no value"))),
            };
            let target_work = built
                .target
                .as_ref()
                .map_or(SemanticWork::default(), |target| target.work);
            if request.cancellation.is_cancelled() {
                return Ok(SemanticOutcome::Cancelled {
                    partial: None,
                    work: target_work,
                });
            }
            if reads
                .incomplete_reasons()
                .iter()
                .any(|reason| reason.is_execution_dependent())
            {
                return Ok(SemanticOutcome::Unknown {
                    partial: None,
                    work: target_work,
                });
            }
            let receipt_bytes = reads
                .retained_bytes()
                .saturating_add(std::mem::size_of::<QueryOwnershipFile>());
            let shared = built.base.clone();
            *cache = Some(QueryOwnershipFile {
                file: built.base,
                receipt: reads,
                _charge: Arc::new(
                    brokk_bifrost_core::retention_budget::AllocationCharge::acquire(
                        workspace.retention_budget(),
                        receipt_bytes,
                    ),
                ),
            });
            drop(cache);
            if let Some(target) = built.target {
                factory.admit_first(
                    support,
                    workspace,
                    &base,
                    &target,
                    &mut request.staged(&mut proof_budget),
                )
            } else {
                factory.target(
                    support,
                    workspace,
                    &base,
                    &shared,
                    &mut request.staged(&mut proof_budget),
                )
            }
        });
    request
        .budget
        .charge_work(proof_budget.performed().saturating_sub(inherited_work));
    receipt.replay(analyzer);
    match outcome? {
        SemanticOutcome::Complete {
            value: Some(selection),
            work,
        } => {
            let OwnershipProcedureSelection {
                selected,
                unserved_observations,
            } = selection;
            if request.cancellation.is_cancelled() {
                if let Some(unserved) = &unserved_observations {
                    unserved.replay(analyzer);
                }
                return Ok(SemanticOutcome::Cancelled {
                    partial: None,
                    work,
                });
            }
            if receipt
                .incomplete_reasons()
                .iter()
                .any(|reason| reason.is_execution_dependent())
            {
                if let Some(unserved) = &unserved_observations {
                    unserved.replay(analyzer);
                }
                return Ok(SemanticOutcome::Unknown {
                    partial: None,
                    work,
                });
            }
            // Unserved optional needs never authorize this selection. Keep
            // their causes after strict admission so a useful proved body can
            // coexist with Partial coverage and forbid durable unit reuse.
            if let Some(unserved) = unserved_observations {
                receipt.extend(&unserved);
                receipt.replay(analyzer);
            }
            assert!(
                factory.accepts_selection(&selected),
                "a factory only mints its own admitted interpretation"
            );
            if let Err(exceeded) = request
                .budget
                .charge_complete_artifact(selected.handle.artifact())
            {
                return Ok(SemanticOutcome::ExceededBudget {
                    partial: None,
                    exceeded,
                    work,
                });
            }
            observe_ownership_artifact(workspace, &selected, request);
            // This memo is request-local, not a reusable derived product. An
            // unrelated outer gap may forbid durable reuse without invalidating
            // the completed proof in this frozen request.
            if let Some(query) =
                query.filter(|_| !request.stop_observed() && proof_budget.refusal_count() == 0)
            {
                let bytes = receipt
                    .retained_bytes()
                    .saturating_add(std::mem::size_of::<QueryOwnershipProcedure>())
                    .saturating_add(std::mem::size_of_val(&key))
                    .saturating_add(key.0.path().as_str().len().saturating_mul(2))
                    .saturating_add(key.0.adapter().name().len().saturating_mul(2))
                    .saturating_add(128);
                let charge = Arc::new(
                    brokk_bifrost_core::retention_budget::AllocationCharge::acquire(
                        workspace.retention_budget(),
                        bytes,
                    ),
                );
                query
                    .ownership_procedures
                    .lock()
                    .expect("ownership selection lock")
                    .insert(
                        key,
                        QueryOwnershipProcedure {
                            selected: selected.clone(),
                            receipt,
                            _charge: charge,
                        },
                    );
            }
            Ok(SemanticOutcome::Complete {
                value: selected,
                work,
            })
        }
        SemanticOutcome::Complete { value: None, .. } => Ok(original),
        SemanticOutcome::ExceededBudget { exceeded, work, .. } => {
            Ok(SemanticOutcome::ExceededBudget {
                partial: None,
                exceeded,
                work,
            })
        }
        SemanticOutcome::Cancelled { work, .. } => Ok(SemanticOutcome::Cancelled {
            partial: None,
            work,
        }),
        outcome => Ok(outcome
            .map(|_| unreachable!("incomplete ownership acquisitions have no selected value"))),
    }
}

/// Select a whole guarded procedure using the registered language's admission proof.
/// Callers retain the ordered answers and receipts with the selected IR/flow pair.
/// `alternate_flows` solves (or recalls) the partial flows of the alternate
/// when the admission selects it; it is not called for the base side.
pub fn procedure_semantics_and_partial_flows(
    prepared: &crate::analyzer::semantic::StoredCandidateMacroArtifact,
    base: &ProcedureHandle,
    base_flows: Option<&ProcedurePartialFlows>,
    alternate_flows: impl FnOnce(&ProcedureHandle) -> Option<ProcedurePartialFlows>,
    context: crate::analyzer::languages::CandidateMacroAdmissionRequest<'_>,
    request: &mut SemanticRequest<'_>,
) -> Result<
    CandidateProcedureOutcome<Vec<crate::analyzer::languages::CandidateMacroAdmissionAnswer>>,
    SemanticProviderError,
> {
    assert_eq!(context.head, base.artifact().key());
    assert_eq!(context.procedure, base.id());
    assert_eq!(
        &context.syntax.source_sha256(),
        context.head.revision().content().as_bytes()
    );
    assert!(std::ptr::eq(context.cancellation, request.cancellation));
    let entry = candidate_procedure_decision(prepared, base, context, request)?;
    match entry.status {
        CandidateSelectionStatus::Cancelled => return Ok(CandidateProcedureOutcome::Cancelled),
        CandidateSelectionStatus::ExceededBudget(exceeded) => {
            return Ok(CandidateProcedureOutcome::ExceededBudget(exceeded));
        }
        CandidateSelectionStatus::ExecutionDependent(reason) => {
            return Err(SemanticProviderError::internal(format!(
                "candidate admission stopped: {reason:?}"
            )));
        }
        CandidateSelectionStatus::Complete => {}
    }
    let side = entry.side;
    let answers = entry.answers.clone();
    let receipt = entry.receipt.clone();
    let key = entry.digest;
    let query = crate::analyzer::i_analyzer::candidate_overlay_query_context();
    let mut outcome = select_candidate_procedure(
        prepared,
        base,
        base_flows,
        alternate_flows,
        |_, _| match side {
            CandidateProcedureSide::Alternate => CandidateProcedureSelection::Alternate(answers),
            CandidateProcedureSide::Base => CandidateProcedureSelection::Base(answers),
        },
        request,
    )?;
    if let CandidateProcedureOutcome::Selected(selected) = &mut outcome {
        selected.procedure = entry.handle.clone();
    }
    if let CandidateProcedureOutcome::Selected(selected) = &outcome
        && selected.flows.outcome
            == brokk_bifrost_semantic::analyzer::semantic::partial_flow::PartialFlowOutcome::Complete
        && receipt.reusable()
        && let Some(query) = query
    {
        let mut digest = brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher::new(
            b"candidate-macro-overlay-output:v1",
        );
        digest.value(&key);
        digest.value(format!("{:?}:{:?}", selected.side, selected.flows).as_bytes());
        *query
            .candidate_macro_procedure_overlay
            .lock()
            .expect("overlay lock") = Some(CandidateMacroProcedureOverlay {
            key,
            output_digest: digest.finish(),
            receipt,
        });
    }
    Ok(outcome)
}

/// The side a candidate's admission answers select, for both selection paths:
/// Alternate when there is exactly one answer per candidate id, in id order,
/// and every answer is Admitted; Base when that shape holds and an answer
/// refuses. `None` when the shape breaks LanguageSupport's
/// one-ordered-answer-per-candidate contract (an empty, truncated, reordered or
/// duplicated vector), which neither path may read as either side (#11910).
fn candidate_admission_side<'a>(
    ids: &[crate::analyzer::semantic::CallSiteId],
    answers: impl ExactSizeIterator<
        Item = (
            crate::analyzer::semantic::CallSiteId,
            &'a crate::analyzer::languages::CandidateMacroDecision,
        ),
    >,
) -> Option<CandidateProcedureSide> {
    if answers.len() != ids.len() {
        return None;
    }
    let mut admitted = true;
    for ((region, decision), id) in answers.zip(ids) {
        if region != *id {
            return None;
        }
        admitted &= matches!(
            decision,
            crate::analyzer::languages::CandidateMacroDecision::Admitted { .. }
        );
    }
    Some(if admitted {
        CandidateProcedureSide::Alternate
    } else {
        CandidateProcedureSide::Base
    })
}

#[cfg(test)]
mod candidate_admission_tests {
    use super::{CandidateProcedureSide, candidate_admission_side};
    use crate::analyzer::languages::{CandidateMacroDecision, CandidateMacroRefusal};
    use crate::analyzer::semantic::CallSiteId;

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#11910: the two candidate admission paths chose different sides on a malformed answer vector"
    )]
    fn a_malformed_admission_vector_selects_no_side() {
        let (c0, c1) = (CallSiteId::new(0), CallSiteId::new(1));
        let admitted = CandidateMacroDecision::Admitted {
            package_identity_digest: [0; 32],
        };
        let refused = CandidateMacroDecision::Refused(CandidateMacroRefusal::UnsupportedLanguage);
        let side = |answers: &[(CallSiteId, &CandidateMacroDecision)]| {
            candidate_admission_side(&[c0, c1], answers.iter().copied())
        };
        // Empty, truncated, reordered and duplicated vectors select no side.
        assert_eq!(side(&[]), None);
        assert_eq!(side(&[(c0, &admitted)]), None);
        assert_eq!(side(&[(c1, &admitted), (c0, &admitted)]), None);
        assert_eq!(side(&[(c0, &admitted), (c0, &admitted)]), None);
        // A well-formed vector selects Alternate only when every answer admits.
        assert_eq!(
            side(&[(c0, &admitted), (c1, &admitted)]),
            Some(CandidateProcedureSide::Alternate)
        );
        assert_eq!(
            side(&[(c0, &admitted), (c1, &refused)]),
            Some(CandidateProcedureSide::Base)
        );
    }
}

/// The side a candidate's ordered admission answers select, with the answers,
/// or the provider error for an answer vector that breaks the contract.
type CandidateAdmission = Result<
    (
        CandidateProcedureSide,
        Vec<crate::analyzer::languages::CandidateMacroAdmissionAnswer>,
    ),
    SemanticProviderError,
>;

fn candidate_macro_admission(
    prepared: &crate::analyzer::semantic::StoredCandidateMacroArtifact,
    base: &ProcedureHandle,
    context: &crate::analyzer::languages::CandidateMacroAdmissionRequest<'_>,
) -> (
    (CandidateAdmission, [u8; 32]),
    crate::analyzer::i_analyzer::QueryReadReceipt,
) {
    use crate::analyzer::languages::{
        CandidateMacroAdmissionAnswer, CandidateMacroDecision, CandidateMacroInvocation,
        CandidateMacroRealization, CandidateMacroRefusal,
    };
    use crate::analyzer::semantic::CandidateRealization;
    let ((admission, key), receipt) = crate::analyzer::i_analyzer::QueryReadReceipt::capture(
        context.analyzer,
        || {
            context.analyzer.record_read(ReadKey::artifact(
                crate::analyzer::invalidation::DerivedArtifactId::semantic_artifact(
                    context.head.public_fingerprint(),
                ),
                Some(context.head.path().as_str()),
            ));
            let procedure = prepared
                .artifact
                .procedure(base.id())
                .expect("validated procedure");
            let (alternate, records) = procedure
                .candidate_macro_alternate()
                .unwrap_or((procedure, &[]));
            let ids = records
                .iter()
                .map(|record| record.base_call)
                .collect::<Vec<_>>();
            let candidates = records
                .iter()
                .map(|record| CandidateMacroInvocation {
                    realization: match record.realization {
                        CandidateRealization::RuntimeCall(id) => {
                            CandidateMacroRealization::RuntimeCall {
                                runtime_argument_count: alternate
                                    .call_site(id)
                                    .expect("validated candidate call")
                                    .arguments
                                    .len(),
                            }
                        }
                        CandidateRealization::Intrinsic => CandidateMacroRealization::Intrinsic,
                        CandidateRealization::LexicalNoItemsIntroduced => {
                            CandidateMacroRealization::LexicalNoItemsIntroduced
                        }
                    },
                    region: record.base_call,
                    anchor: record.anchor,
                })
                .collect::<Vec<_>>();
            let support =
                crate::analyzer::languages::language_support(context.syntax.dialect().language());
            let answers = support
                .map(|support| {
                    support.admit_candidate_macros(
                        crate::analyzer::languages::CandidateMacroAdmissionRequest {
                            candidates: &candidates,
                            ..*context
                        },
                    )
                })
                .unwrap_or_else(|| {
                    candidates
                        .iter()
                        .map(|candidate| {
                            let (_, reads) = crate::analyzer::i_analyzer::QueryReadReceipt::capture(
                                context.analyzer,
                                || (),
                            );
                            CandidateMacroAdmissionAnswer::new(
                                candidate.region,
                                CandidateMacroDecision::Refused(
                                    CandidateMacroRefusal::UnsupportedLanguage,
                                ),
                                reads,
                            )
                        })
                        .collect()
                });
            let mut key = brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher::new(
                b"candidate-macro-overlay:v1",
            );
            key.value(format!("{:?}:{:?}", context.head, context.procedure).as_bytes());
            for answer in &answers {
                key.value(format!("{:?}", answer.region).as_bytes());
                key.value(&answer.answer_digest);
            }
            let side = candidate_admission_side(
                &ids,
                answers
                    .iter()
                    .map(|answer| (answer.region, &answer.decision)),
            );
            let admission = match side {
                Some(side) => Ok((side, answers)),
                None => Err(SemanticProviderError::internal(format!(
                    "candidate macro admission contract violated: expected ordered regions {ids:?}, received {:?}",
                    answers
                        .iter()
                        .map(|answer| (answer.region, &answer.decision))
                        .collect::<Vec<_>>()
                ))),
            };
            (admission, key.finish())
        },
    );
    ((admission, key), receipt)
}

/// Execution-dependent stops are retained only by this query's selection table.
#[derive(Debug, Clone)]
pub(crate) enum CandidateSelectionStatus {
    Complete,
    Cancelled,
    ExecutionDependent(crate::analyzer::i_analyzer::QueryReadIncomplete),
    ExceededBudget(crate::analyzer::semantic::SemanticBudgetExceeded),
}

/// Admission inputs are pinned at first observation for the root query's
/// lifetime (one request). A hit neither re-validates nor re-runs admission,
/// since that would give one request two selections for one procedure.
/// Only real admission outcomes (complete, or a typed execution-dependent
/// stop) are retained. A cancelled or over-budget acquisition selected nothing
/// and is local to that acquisition, so a later one in the same query runs
/// admission. Durable products built on a selection carry its receipt through
/// replay.
#[derive(Debug, Clone)]
pub(crate) struct QuerySelectedProcedure {
    pub(crate) handle: ProcedureHandle,
    pub(crate) side: CandidateProcedureSide,
    pub(crate) refusals: Vec<CandidateMacroRefusalEvidence>,
    answers: Vec<crate::analyzer::languages::CandidateMacroAdmissionAnswer>,
    receipt: crate::analyzer::i_analyzer::QueryReadReceipt,
    digest: [u8; 32],
    pub(crate) status: CandidateSelectionStatus,
}

pub(crate) fn candidate_procedure_decision(
    prepared: &crate::analyzer::semantic::StoredCandidateMacroArtifact,
    base: &ProcedureHandle,
    context: crate::analyzer::languages::CandidateMacroAdmissionRequest<'_>,
    request: &mut SemanticRequest<'_>,
) -> Result<QuerySelectedProcedure, SemanticProviderError> {
    use crate::analyzer::languages::CandidateMacroDecision;
    let query = crate::analyzer::i_analyzer::candidate_overlay_query_context();
    // A value key, so a selected alternate handle passed back in finds the
    // selection its base made.
    let key = base.base_interpretation().durable_key();
    // Admission can perform route queries. Never hold the selection mutex while
    // calling language code; concurrent acquisitions use the first published entry.
    if let Some(query) = &query {
        let entry = query
            .selected_procedures
            .lock()
            .expect("selection lock")
            .get(&key)
            .cloned();
        if let Some(entry) = entry {
            entry.receipt.replay(context.analyzer);
            return Ok(entry);
        }
    }
    let (alternate, records) = prepared
        .artifact
        .procedure(base.id())
        .expect("validated procedure")
        .candidate_macro_alternate()
        .expect("candidate alternate");
    let candidate_work = SemanticWork {
        call_sites: records.len(),
        ..Default::default()
    };
    let mut status = if request.cancellation.is_cancelled() {
        CandidateSelectionStatus::Cancelled
    } else if let Err(exceeded) = request.budget.check_admission(candidate_work) {
        CandidateSelectionStatus::ExceededBudget(exceeded)
    } else {
        CandidateSelectionStatus::Complete
    };
    let admitted = matches!(status, CandidateSelectionStatus::Complete);
    let ((admission, digest), receipt) = if admitted {
        candidate_macro_admission(prepared, base, &context)
    } else {
        let (_, receipt) =
            crate::analyzer::i_analyzer::QueryReadReceipt::capture(context.analyzer, || ());
        (
            (Ok((CandidateProcedureSide::Base, Vec::new())), [0; 32]),
            receipt,
        )
    };
    receipt.replay(context.analyzer);
    let (side, answers) = admission?;
    if admitted {
        assert_eq!(answers.len(), records.len());
    }
    if request.cancellation.is_cancelled()
        || answers.iter().any(|answer| {
            matches!(
                answer.decision,
                CandidateMacroDecision::Refused(
                    crate::analyzer::languages::CandidateMacroRefusal::Cancelled
                )
            )
        })
    {
        status = CandidateSelectionStatus::Cancelled;
    }
    if matches!(status, CandidateSelectionStatus::Complete)
        && let Some(reason) = receipt
            .incomplete_reasons()
            .iter()
            .find(|reason| reason.is_execution_dependent())
    {
        status = if matches!(
            reason.base_cause(),
            crate::analyzer::i_analyzer::QueryReadIncomplete::Cancelled
        ) {
            CandidateSelectionStatus::Cancelled
        } else {
            CandidateSelectionStatus::ExecutionDependent(reason.clone())
        };
    }
    let refusals = answers
        .iter()
        .zip(records)
        .filter_map(|(answer, record)| {
            let CandidateMacroDecision::Refused(reason) = &answer.decision else {
                return None;
            };
            Some(
                crate::analyzer::semantic::service::CandidateMacroRefusalEvidence {
                    anchor: alternate.candidate_source_anchor(record),
                    reason: reason.clone(),
                },
            )
        })
        .collect();
    let handle = match side {
        CandidateProcedureSide::Base => base.base_interpretation(),
        CandidateProcedureSide::Alternate => prepared
            .artifact
            .candidate_alternate_handle(base.id())
            .expect("candidate alternate"),
    };
    let entry = QuerySelectedProcedure {
        handle,
        side,
        refusals,
        answers,
        receipt,
        digest,
        status,
    };
    // Cancellation and budget stops belong to this acquisition: a later caller
    // in the same query with a live token or a larger budget runs admission.
    if matches!(
        entry.status,
        CandidateSelectionStatus::Complete | CandidateSelectionStatus::ExecutionDependent(_)
    ) && let Some(query) = &query
    {
        let winner = query
            .selected_procedures
            .lock()
            .expect("selection lock")
            .entry(key)
            .or_insert(entry)
            .clone();
        winner.receipt.replay(context.analyzer);
        return Ok(winner);
    }
    Ok(entry)
}

/// Query-local receipt observation for complete flow acquisition.
/// This slot never chooses an interpretation or serves a flow cache hit;
/// `selected_procedures` is the sole selection owner.
pub struct CandidateMacroProcedureOverlay {
    key: [u8; 32],
    output_digest: [u8; 32],
    receipt: crate::analyzer::i_analyzer::QueryReadReceipt,
}

impl std::fmt::Debug for CandidateMacroProcedureOverlay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CandidateMacroProcedureOverlay")
            .field("key", &self.key)
            .field("output_digest", &self.output_digest)
            .finish_non_exhaustive()
    }
}

/// Forward underlying reads directly into a persisted consumer's active ledger.
pub fn candidate_macro_overlay_receipt() -> Option<crate::analyzer::i_analyzer::QueryReadReceipt> {
    crate::analyzer::i_analyzer::candidate_overlay_query_context().and_then(|query| {
        query
            .candidate_macro_procedure_overlay
            .lock()
            .expect("overlay lock")
            .as_ref()
            .map(|overlay| overlay.receipt.clone())
    })
}

#[cfg(test)]
mod executable_rule_tests {
    use super::*;
    use crate::analyzer::i_analyzer::{AnalyzerQueryScope, QueryReadIncomplete, QueryReadReceipt};
    use crate::analyzer::{MultiAnalyzer, ReadLedger};

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#13075: no-refinement executable acquisition skipped the current request's held artifact admission"
    )]
    fn executable_rule_nonrefined_held_base_obeys_current_request_budget() {
        use crate::analyzer::semantic::*;
        let fixture = crate::inline_project::InlineTestProject::new()
            .file("main.ts", "function caller() {}\n")
            .build();
        let workspace = crate::analyzer::WorkspaceAnalyzer::Empty(
            crate::analyzer::workspace::EmptyAnalyzer::new(fixture.project_dyn()),
        );
        let digest = StableDigest::sha256(b"held-body-budget");
        let key = SemanticArtifactKey::new(
            WorkspaceMountId::from_root(fixture.root()),
            WorkspaceRelativePath::new("main.ts").unwrap(),
            SemanticLanguage::Standard(crate::analyzer::Language::TypeScript),
            SourceRevision::Disk {
                content: ContentIdentity::from_digest(digest),
            },
            AdapterSemanticsVersion::new("typescript", digest).unwrap(),
            SemanticIrVersion::from_digest(digest),
            ConfigurationFingerprint::from_digest(digest),
            DependencyFingerprint::from_digest(digest),
        );
        let locator = crate::test_support::named_file_function_locator(
            &key,
            "main.ts",
            "caller",
            crate::test_support::source_anchor(0, 1, 0),
            SemanticRole::Procedure,
        );
        let parts = crate::test_support::minimal_semantic_procedure(
            ProcedureId::new(0),
            locator,
            ProcedureKind::Function,
        );
        let artifact = Arc::new(
            SemanticArtifact::try_new(
                key,
                crate::test_support::complete_semantic_capabilities(&[]),
                vec![parts],
            )
            .unwrap(),
        );
        let base = artifact.procedure_handle(ProcedureId::new(0)).unwrap();
        assert!(!ExecutableFactory.can_refine(
            crate::analyzer::languages::language_support(crate::analyzer::Language::TypeScript),
            &base,
        ));
        let mut earlier_request = SemanticBudget::default();
        earlier_request.charge_complete_artifact(&artifact).unwrap();
        let cancellation = CancellationToken::new();
        let select = |budget: &mut SemanticBudget| {
            executable_procedure_handle(
                &workspace,
                &base,
                &mut SemanticRequest::new(budget, &cancellation),
            )
            .unwrap()
        };
        let mut limits = SemanticBudget::default().limits();
        limits.program_points = 1;
        assert!(artifact.work().program_points > limits.program_points);
        let mut refused = SemanticBudget::new(limits).unwrap();
        assert!(!refused.shares_scope_with(&earlier_request.scope_identity()));
        assert!(matches!(
            select(&mut refused),
            SemanticOutcome::ExceededBudget { partial: None, .. }
        ));
        assert!(!refused.has_charged_artifact(artifact.key().fingerprint()));

        let mut admitted = SemanticBudget::default();
        assert!(
            matches!(select(&mut admitted), SemanticOutcome::Complete { value, .. } if value.handle == base)
        );
        assert!(admitted.has_charged_artifact(artifact.key().fingerprint()));
        let state = |budget: &SemanticBudget| {
            (
                budget.performed(),
                budget.resident(),
                budget.resident_peak(),
            )
        };
        let once = state(&admitted);
        assert!(
            matches!(select(&mut admitted), SemanticOutcome::Complete { value, .. } if value.handle == base)
        );
        assert_eq!(
            state(&admitted),
            once,
            "an already admitted held body adds no lookup or census"
        );
    }

    #[test]
    fn executable_rule_pending_joins_only_after_strict_inputs_and_replays() {
        let analyzer = MultiAnalyzer::default();
        let ledger = Arc::new(ReadLedger::new());
        let _reads = AnalyzerQueryScope::with_read_ledger(&analyzer, Arc::clone(&ledger));
        let proved = ReadKey::Configuration(StableDigest::sha256(b"proved input"));
        let pending = ReadKey::Configuration(StableDigest::sha256(b"pending input context"));
        let mut rules = ExecutableRuleContext::new(&analyzer);
        let mut budget = crate::analyzer::semantic::SemanticBudget::default();
        let cancellation = CancellationToken::new();
        let mut request = SemanticRequest::new(&mut budget, &cancellation);
        let (unserved, mut strict) = QueryReadReceipt::capture(&analyzer, || {
            let realized = rules
                .capture(&mut request, |analyzer, _request| {
                    analyzer.record_read(proved.clone());
                    Ok(SemanticOutcome::Complete {
                        value: ExecutableRuleOutcome::Realized(7u8),
                        work: SemanticWork::default(),
                    })
                })
                .unwrap();
            assert_eq!(realized.available_value(), Some(&Some(7)));
            let unanswered = rules
                .capture::<u8>(&mut request, |analyzer, _request| {
                    analyzer.record_read(pending.clone());
                    analyzer.record_query_incomplete(QueryReadIncomplete::SemanticModelsPending);
                    Ok(SemanticOutcome::Complete {
                        value: ExecutableRuleOutcome::Pending,
                        work: SemanticWork::default(),
                    })
                })
                .unwrap();
            assert_eq!(unanswered.available_value(), Some(&None));
            let opaque = rules
                .capture::<u8>(&mut request, |analyzer, _request| {
                    analyzer.record_query_incomplete(QueryReadIncomplete::SemanticEvidenceGap(
                        "test-only unsupported rule shape".into(),
                    ));
                    Ok(SemanticOutcome::Complete {
                        value: ExecutableRuleOutcome::Opaque,
                        work: SemanticWork::default(),
                    })
                })
                .unwrap();
            assert_eq!(opaque.available_value(), Some(&None));
            rules.unserved_observations.take().unwrap()
        });
        // The enclosing capture publishes after its frame closes. Required
        // reads are present then, while Pending remains held by the rule owner.
        assert!(ledger.keys().contains(&proved));
        assert!(!ledger.keys().contains(&pending));
        assert!(
            strict
                .incomplete_reasons()
                .iter()
                .all(|reason| !reason.is_execution_dependent())
        );
        strict.extend(&unserved);
        strict.replay(&analyzer);
        assert!(ledger.keys().contains(&pending));
        assert!(
            strict
                .incomplete_reasons()
                .contains(&QueryReadIncomplete::SemanticModelsPending)
        );
        budget.charge_work(strict.retain_root());
        let (_, replay) = QueryReadReceipt::capture(&analyzer, || strict.replay(&analyzer));
        assert_eq!(replay.digest(), strict.digest());
        assert_eq!(replay.incomplete_reasons(), strict.incomplete_reasons());
    }

    #[test]
    fn executable_rule_stops_preserve_pending_and_do_not_become_fallbacks() {
        use crate::analyzer::semantic::{SemanticBudgetDimension, SemanticBudgetExceeded};
        let analyzer = MultiAnalyzer::default();
        let stopped = [
            Ok(SemanticOutcome::Cancelled {
                partial: None,
                work: SemanticWork::default(),
            }),
            Ok(SemanticOutcome::ExceededBudget {
                partial: None,
                exceeded: SemanticBudgetExceeded::new(SemanticBudgetDimension::NestedEntries, 0, 1),
                work: SemanticWork::default(),
            }),
            Ok(SemanticOutcome::Unknown {
                partial: None,
                work: SemanticWork::default(),
            }),
            Err(SemanticProviderError::internal(
                "test-only required provider failure",
            )),
        ];
        for stop in stopped {
            let expected = match &stop {
                Ok(SemanticOutcome::Cancelled { .. }) => "cancelled",
                Ok(SemanticOutcome::ExceededBudget { .. }) => "budget",
                Ok(SemanticOutcome::Unknown { .. }) => "unknown",
                Err(_) => "error",
                _ => unreachable!(),
            };
            let mut budget = crate::analyzer::semantic::SemanticBudget::default();
            let cancellation = CancellationToken::new();
            let mut request = SemanticRequest::new(&mut budget, &cancellation);
            let (_, receipt) = QueryReadReceipt::capture(&analyzer, || {
                let mut rules = ExecutableRuleContext::new(&analyzer);
                let pending = rules
                    .capture::<()>(&mut request, |analyzer, _request| {
                        analyzer
                            .record_query_incomplete(QueryReadIncomplete::SemanticModelsPending);
                        Ok(SemanticOutcome::Complete {
                            value: ExecutableRuleOutcome::Pending,
                            work: SemanticWork::default(),
                        })
                    })
                    .unwrap();
                assert_eq!(pending.available_value(), Some(&None));
                let result = rules.capture::<()>(&mut request, |_, _request| stop);
                let actual = match result {
                    Ok(SemanticOutcome::Cancelled { partial: None, .. }) => "cancelled",
                    Ok(SemanticOutcome::ExceededBudget { partial: None, .. }) => "budget",
                    Ok(SemanticOutcome::Unknown { partial: None, .. }) => "unknown",
                    Err(_) => "error",
                    other => panic!("a stopped rule cannot become a fallback: {other:?}"),
                };
                assert_eq!(actual, expected);
            });
            assert_eq!(
                receipt.incomplete_reasons(),
                &[QueryReadIncomplete::SemanticModelsPending],
                "unserved observations survive every unsuccessful exit"
            );
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#4967: a staged check_admission refusal panicked executable rule capture"
    )]
    fn executable_rule_probe_refusal_keeps_its_real_dimension() {
        use crate::analyzer::semantic::{SemanticBudget, SemanticBudgetDimension};
        use brokk_bifrost_core::analyzer::carried_context::CarriedContext;
        let analyzer = MultiAnalyzer::default();
        let blank = std::thread::spawn(CarriedContext::current).join().unwrap();
        for disposition in [
            ExecutableRuleOutcome::Realized(()),
            ExecutableRuleOutcome::Opaque,
            ExecutableRuleOutcome::Pending,
        ] {
            let mut budget = SemanticBudget::uniform(1).unwrap();
            assert!(
                budget
                    .check_admission(SemanticWork {
                        source_bytes: 2,
                        ..SemanticWork::default()
                    })
                    .is_err()
            );
            let mark = budget.refusal_mark();
            let foreign = budget.clone();
            let cancellation = CancellationToken::new();
            let mut request =
                SemanticRequest::new(&mut budget, &cancellation).observing_refusals_since(mark);
            let (result, receipt) = QueryReadReceipt::capture(&analyzer, || {
                let mut rules = ExecutableRuleContext::new(&analyzer);
                rules
                    .capture::<()>(&mut request, |analyzer, _request| {
                        analyzer
                            .record_query_incomplete(QueryReadIncomplete::SemanticModelsPending);
                        Ok(SemanticOutcome::Complete {
                            value: ExecutableRuleOutcome::Pending,
                            work: SemanticWork::default(),
                        })
                    })
                    .unwrap();
                let result = rules.capture(&mut request, |_, request| {
                    let probe = request.budget.clone();
                    let carried = CarriedContext::current();
                    assert!(
                        std::thread::spawn(move || carried.run(|| {
                            probe.check_admission(SemanticWork {
                                nested_entries: 2,
                                ..SemanticWork::default()
                            })
                        }))
                        .join()
                        .unwrap()
                        .is_err()
                    );
                    blank.run(|| {
                        assert!(
                            foreign
                                .check_admission(SemanticWork {
                                    values: 3,
                                    ..SemanticWork::default()
                                })
                                .is_err()
                        );
                    });
                    Ok(SemanticOutcome::Complete {
                        value: disposition,
                        work: SemanticWork::default(),
                    })
                });
                assert!(!rules.has_realizations());
                result
            });
            let SemanticOutcome::ExceededBudget {
                partial: None,
                exceeded,
                ..
            } = result.unwrap()
            else {
                panic!("a rule's admission probe must remain a typed budget stop");
            };
            assert_eq!(exceeded.dimension(), SemanticBudgetDimension::NestedEntries);
            assert_eq!(exceeded.limit(), 1);
            assert_eq!(exceeded.attempted(), 2);
            assert_eq!(budget.refusal_count(), 3);
            assert_eq!(
                budget.first_refusal().unwrap().exceeded.dimension(),
                SemanticBudgetDimension::SourceBytes
            );
            assert!(
                receipt
                    .incomplete_reasons()
                    .contains(&QueryReadIncomplete::SemanticModelsPending)
            );
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#4967: a foreign unit's refusal on a ledger clone stopped an unrelated capture"
    )]
    fn executable_rule_ignores_a_foreign_units_refusal() {
        use crate::analyzer::semantic::SemanticBudget;
        use brokk_bifrost_core::analyzer::carried_context::CarriedContext;
        let analyzer = MultiAnalyzer::default();
        let blank = std::thread::spawn(CarriedContext::current).join().unwrap();
        let mut budget = SemanticBudget::uniform(1).unwrap();
        let foreign = budget.clone();
        let cancellation = CancellationToken::new();
        let mut request = SemanticRequest::new(&mut budget, &cancellation);
        let mut rules = ExecutableRuleContext::new(&analyzer);
        let result = rules
            .capture(&mut request, |_, _| {
                blank.run(|| {
                    assert!(
                        foreign
                            .check_admission(SemanticWork {
                                values: 3,
                                ..SemanticWork::default()
                            })
                            .is_err()
                    );
                });
                Ok(SemanticOutcome::Complete {
                    value: ExecutableRuleOutcome::Realized(()),
                    work: SemanticWork::default(),
                })
            })
            .unwrap();
        assert_eq!(result.available_value(), Some(&Some(())));
        assert!(rules.has_realizations());
        assert_eq!(budget.refusal_count(), 1);
    }

    #[test]
    fn executable_rule_cannot_hide_a_ledger_stop_in_any_disposition() {
        use crate::analyzer::semantic::{
            SemanticBudget, SemanticBudgetDimension, SemanticExecutionBudget,
        };
        let analyzer = MultiAnalyzer::default();
        for disposition in [
            ExecutableRuleOutcome::Realized(()),
            ExecutableRuleOutcome::Opaque,
            ExecutableRuleOutcome::Pending,
        ] {
            let mut budget = SemanticBudget::uniform(1).unwrap();
            let cancellation = CancellationToken::new();
            let mut request = SemanticRequest::new(&mut budget, &cancellation);
            let (result, receipt) = QueryReadReceipt::capture(&analyzer, || {
                let mut rules = ExecutableRuleContext::new(&analyzer);
                rules
                    .capture::<()>(&mut request, |analyzer, _request| {
                        analyzer
                            .record_query_incomplete(QueryReadIncomplete::SemanticModelsPending);
                        Ok(SemanticOutcome::Complete {
                            value: ExecutableRuleOutcome::Pending,
                            work: SemanticWork::default(),
                        })
                    })
                    .unwrap();
                rules.capture(&mut request, |_, request| {
                    assert!(
                        request
                            .budget
                            .admit(SemanticWork {
                                nested_entries: 2,
                                ..SemanticWork::default()
                            })
                            .is_err()
                    );
                    Ok(SemanticOutcome::Complete {
                        value: disposition,
                        work: SemanticWork::default(),
                    })
                })
            });
            match result.unwrap() {
                SemanticOutcome::ExceededBudget {
                    partial: None,
                    exceeded,
                    ..
                } => {
                    assert_eq!(exceeded.dimension(), SemanticBudgetDimension::NestedEntries);
                    assert_eq!(exceeded.limit(), 1);
                    assert_eq!(exceeded.attempted(), 2);
                }
                other => panic!("a rule concealed its resident refusal: {other:?}"),
            }
            assert!(
                receipt
                    .incomplete_reasons()
                    .contains(&QueryReadIncomplete::SemanticModelsPending)
            );
        }
        let mut budget = SemanticBudget::default();
        let cancellation = CancellationToken::new();
        let execution = SemanticExecutionBudget::for_fixpoint(1);
        let mut request =
            SemanticRequest::with_execution_budget(&mut budget, &cancellation, &execution);
        let (result, receipt) = QueryReadReceipt::capture(&analyzer, || {
            let mut rules = ExecutableRuleContext::new(&analyzer);
            rules.capture::<()>(&mut request, |_, request| {
                assert!(!request.charge_execution_traversal(2));
                Ok(SemanticOutcome::Complete {
                    value: ExecutableRuleOutcome::Opaque,
                    work: SemanticWork::default(),
                })
            })
        });
        assert!(matches!(
            result.unwrap(),
            SemanticOutcome::Unknown { partial: None, .. }
        ));
        assert!(receipt.incomplete_reasons().iter().any(|reason| {
            reason.execution_cause()
                == Some(crate::analyzer::read_ledger::DerivationExecutionCause::Budget)
        }));
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#4967: ownership and executable selections overwrote each other's acquiring receipt"
    )]
    fn acquired_authorities_keep_both_receipts_in_either_order() {
        use crate::analyzer::semantic::*;
        let workspace = crate::analyzer::WorkspaceAnalyzer::Multi(Box::default());
        let workspace = &workspace;
        let key = crate::test_support::semantic_artifact_key_fixture(
            "acquired-authority",
            "memo.ts",
            SemanticLanguage::Standard(crate::analyzer::Language::TypeScript),
            SourceRevision::Disk {
                content: ContentIdentity::hash_bytes(b"fixture"),
            },
            "typescript",
            "fixture",
            "ir",
            "configuration",
            "dependencies",
        );
        let locator = crate::test_support::named_file_function_locator(
            &key,
            "memo.ts",
            "caller",
            crate::test_support::source_anchor(0, 1, 0),
            SemanticRole::Procedure,
        );
        let mut parts = crate::test_support::minimal_semantic_procedure(
            ProcedureId::new(0),
            locator,
            ProcedureKind::Function,
        );
        let source = SourceMappingId::new(0);
        let evidence = EvidenceId::new(0);
        let call = CallSiteId::new(0);
        let target = CallableTargetResolution::Proven(CallableTarget::Local(parts.id));
        parts.values.push(SemanticValue {
            id: ValueId::new(0),
            kind: SemanticValueKind::Callable,
            source,
            evidence,
            static_type_class: Default::default(),
            static_type_origin: None,
        });
        parts.call_sites.push(SemanticCallSite {
            id: call,
            point: ProgramPointId::new(0),
            invocation_mode: CallInvocationMode::Ordinary,
            execution_timing: ExecutionTiming::SameEvaluation,
            callee: ValueId::new(0),
            receiver: None,
            member_selection: None,
            arguments: Box::new([]),
            normal_results: Box::new([]),
            result: None,
            thrown: None,
            declared_targets: target.clone(),
            target_evidence: evidence,
            normal_continuation: ControlContinuation::Target(ProgramPointId::new(1)),
            exceptional_continuation: ControlContinuation::Target(ProgramPointId::new(2)),
            source,
            evidence,
        });
        let mut entry = parts.points[0].events.to_vec();
        entry.extend([
            SemanticEvent::new(
                SemanticEffect::CallableReference {
                    result: ValueId::new(0),
                    callable: CallableValue {
                        kind: CallableReferenceKind::Function,
                        targets: target,
                        target_evidence: evidence,
                        bound_receiver: None,
                        environment: None,
                    },
                },
                source,
                evidence,
            ),
            SemanticEvent::new(SemanticEffect::Invoke { call_site: call }, source, evidence),
        ]);
        parts.points[0].events = entry.into_boxed_slice();
        for (point, kind) in [
            (1, CallContinuationKind::Normal),
            (2, CallContinuationKind::Exceptional),
        ] {
            let mut events = parts.points[point].events.to_vec();
            events.push(SemanticEvent::new(
                SemanticEffect::CallContinuation {
                    call_site: call,
                    kind,
                },
                source,
                evidence,
            ));
            parts.points[point].events = events.into_boxed_slice();
        }
        let artifact = Arc::new(
            SemanticArtifact::try_new(
                key,
                crate::test_support::complete_semantic_capabilities(&[
                    SemanticCapability::Values,
                    SemanticCapability::CallableReferences,
                    SemanticCapability::Calls,
                    SemanticCapability::NormalCallContinuation,
                    SemanticCapability::ExceptionalCallContinuation,
                ]),
                vec![parts.clone()],
            )
            .unwrap(),
        );
        let base_handle = artifact.procedure_handle(parts.id).unwrap();
        let base = &base_handle;
        let census = crate::analyzer::semantic::ir::measure_procedure_work(&parts);
        let candidates = vec![CandidateRecord {
            anchor: CandidateAnchor::of_call(&parts, call).unwrap(),
            base_call: call,
            realization: CandidateRealization::LexicalNoItemsIntroduced,
        }]
        .into_boxed_slice();
        let cancellation = CancellationToken::new();
        let owned = Arc::new(
            SemanticArtifact::try_ownership_projection(
                base.artifact().clone(),
                parts.clone(),
                candidates,
                census,
                &mut crate::analyzer::semantic::SemanticBudget::default(),
                &cancellation,
            )
            .unwrap(),
        )
        .candidate_alternate_handle(base.id())
        .unwrap();
        let executable = Arc::new(
            SemanticArtifact::try_executable_projection(
                base.artifact().clone(),
                parts,
                census,
                &mut crate::analyzer::semantic::SemanticBudget::default(),
                &cancellation,
            )
            .unwrap(),
        )
        .executable_alternate_handle(base.id())
        .unwrap();
        assert_ne!(
            OwnershipViewFactory.memo_key(base),
            ExecutableFactory.memo_key(base)
        );
        assert_eq!(OwnershipViewFactory.memo_key(base), owned.durable_key());
        assert_eq!(ExecutableFactory.memo_key(base), executable.durable_key());
        let selection = |handle: ProcedureHandle| SelectedProcedureHandle {
            handle,
            side: CandidateProcedureSide::Alternate,
            refusals: Vec::new(),
        };
        assert!(!OwnershipViewFactory.accepts_selection(&selection(executable.clone())));
        assert!(!ExecutableFactory.accepts_selection(&selection(owned.clone())));
        for order in [[&owned, &executable], [&executable, &owned]] {
            let _scope = AnalyzerQueryScope::new(workspace.analyzer());
            let query = crate::analyzer::i_analyzer::candidate_overlay_query_context().unwrap();
            let mut expected = Vec::new();
            for handle in order {
                let marker = ReadKey::Configuration(StableDigest::sha256(format!(
                    "acquired {:?}",
                    handle.interpretation()
                )));
                let (_, receipt) = QueryReadReceipt::capture_deferred(workspace.analyzer(), || {
                    workspace.analyzer().record_read(marker);
                });
                expected.push((handle, receipt.clone()));
                query.ownership_procedures.lock().unwrap().insert(
                    handle.durable_key(),
                    QueryOwnershipProcedure {
                        selected: selection(handle.clone()),
                        receipt,
                        _charge: Arc::new(
                            brokk_bifrost_core::retention_budget::AllocationCharge::acquire(
                                workspace.retention_budget(),
                                1,
                            ),
                        ),
                    },
                );
            }
            assert_eq!(query.ownership_procedures.lock().unwrap().len(), 2);
            for (handle, expected) in expected {
                let mut budget = crate::analyzer::semantic::SemanticBudget::default();
                let mut request = SemanticRequest::new(&mut budget, &cancellation);
                let (replayed, receipt) = QueryReadReceipt::capture(workspace.analyzer(), || {
                    if handle.interpretation() == ProcedureInterpretation::ExecutableAlternate {
                        workspace
                            .executable_procedure_handle(handle, &mut request)
                            .map(|outcome| outcome.map(|selected| Some(selected.handle)))
                    } else {
                        workspace.replay_ownership_procedure_handle(handle, &mut request)
                    }
                });
                assert_eq!(
                    replayed.unwrap().available_value(),
                    Some(&Some(handle.clone()))
                );
                assert_eq!(receipt.digest(), expected.digest());
            }
        }
        let _fresh_request = AnalyzerQueryScope::new(workspace.analyzer());
        let mut budget = crate::analyzer::semantic::SemanticBudget::default();
        let refused = workspace
            .executable_procedure_handle(
                &executable,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .unwrap();
        assert!(matches!(
            refused,
            SemanticOutcome::Unknown { partial: None, .. }
        ));
    }
}
