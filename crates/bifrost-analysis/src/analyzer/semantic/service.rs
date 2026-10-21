//! Shared snapshot, publication, and complete-cache mechanics for language lowerers.

use crate::analyzer::QueryScope;
use crate::analyzer::complete_value_cache::{CompleteValueAcquisition, CompleteValuePermit};

use crate::analyzer::semantic::partial_flow::ProcedurePartialFlows;
use crate::analyzer::semantic::{
    ContentIdentity, ProcedureId, SemanticArtifact, SemanticArtifactKey, SemanticOutcome,
    SemanticProviderError, SemanticRequest, SemanticWork, StableDigest,
};
use crate::analyzer::store::semantic_ir::{
    SemanticIrMountScope, SemanticIrPublication, SemanticIrPublicationOutcome,
};
use crate::analyzer::tree_sitter_analyzer::{
    PreparedSourceFailure, PreparedSourceOrigin, PreparedSyntaxLimitedOutcome,
};
use crate::analyzer::{
    LanguageAdapter, LanguageDialect, ProjectFile, ProjectSourceOrigin, TreeSitterAnalyzer,
};
pub use brokk_bifrost_semantic::analyzer::semantic::service::*;
use git2::Oid;
use std::sync::Arc;

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
            return Err(SemanticProviderError::SourceAdmissionRefused {
                file: file.clone(),
                reason,
            });
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
    let content = match digests.get(source_identity) {
        Some(content) => content,
        None => {
            let content = ContentIdentity::hash_bytes(source.as_bytes());
            digests.record(source_identity, content);
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
        let Some(publication) = complete_semantic_ir_publication(analyzer, file, oid)? else {
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
        };
        note_serve(
            &SERVE_COUNTS.rows_hits,
            "rows_hit",
            file.rel_path().display(),
        );
        let content = publication.content;
        analyzer.semantic_source_digests().record(oid, content);
        let key = semantic_artifact_key_from_content(
            file,
            LanguageDialect::for_path(analyzer.adapter().language(), file.rel_path()),
            content,
            None,
            lowerer.identity(),
        )?;
        let (acquisition, _cache_wait) = cache.acquire(&key, request.cancellation);
        let staged_budget = request.budget.clone();
        let outcome = match acquisition {
            CompleteValueAcquisition::Cached { value: artifact } => publish_cached(
                cache,
                artifact,
                SemanticWork::default(),
                staged_budget,
                request,
            ),
            CompleteValueAcquisition::Leader { permit } => publish_from_semantic_ir_rows(
                analyzer,
                lowerer,
                key,
                &publication,
                permit,
                SemanticWork::default(),
                staged_budget,
                started_work,
                request,
            ),
            CompleteValueAcquisition::Rejected => {
                unreachable!("semantic artifact cache never publishes rejected flights")
            }
            CompleteValueAcquisition::Cancelled => Ok(SemanticOutcome::Cancelled {
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
    let max_source_bytes = request.budget.remaining().source_bytes;
    let scope = crate::analyzer::AnalyzerQueryScope::new(analyzer);
    let (source_identity, prepared) = match analyzer.prepared_syntax_limited_cancellable(
        scope.token(),
        file,
        max_source_bytes,
        Some(request.cancellation),
    ) {
        PreparedSyntaxLimitedOutcome::Available(oid, prepared) => (oid, prepared),
        PreparedSyntaxLimitedOutcome::Refused(reason) => {
            return Err(SemanticProviderError::SourceAdmissionRefused {
                file: file.clone(),
                reason,
            });
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
            let exceeded = request.budget.check_admission(work).map_or_else(
                |exceeded| exceeded,
                |_| {
                    unreachable!(
                        "a source snapshot larger than the remaining source budget must exceed it"
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
        return Ok(SemanticOutcome::Cancelled {
            partial: None,
            work: source_work,
        });
    }
    let mut staged_budget = request.budget.clone();
    if let Err(exceeded) = staged_budget.admit(source_work) {
        return Ok(SemanticOutcome::ExceededBudget {
            partial: None,
            exceeded,
            work: source_work,
        });
    }

    let identity = lowerer.identity();
    // Reuse the prepared snapshot's digest. Recording it against the blob
    // identity also lets the next touch skip source preparation entirely.
    let content = ContentIdentity::from_digest(StableDigest::from_array(prepared.source_sha256()));
    analyzer
        .semantic_source_digests()
        .record(source_identity, content);
    let key = semantic_artifact_key_for_prepared(file, &prepared, content, identity)?;
    let (acquisition, cache_wait) = cache.acquire(&key, request.cancellation);
    if cache_wait.wait_ns > 0 {
        crate::profiling::note_with(|| {
            format!(
                "semantic.complete_cache_wait waits={} wait_ns={}",
                cache_wait.waits, cache_wait.wait_ns
            )
        });
    }
    let permit = match acquisition {
        CompleteValueAcquisition::Cached { value: artifact } => {
            drop(prepared);
            staged_budget.release_admission(source_work);
            let outcome = publish_cached(cache, artifact, source_work, staged_budget, request);
            observe_complete_artifact(file, &outcome, request);
            return outcome;
        }
        CompleteValueAcquisition::Leader { permit } => permit,
        CompleteValueAcquisition::Rejected => {
            unreachable!("semantic artifact cache never publishes rejected flights")
        }
        CompleteValueAcquisition::Cancelled => {
            return Ok(SemanticOutcome::Cancelled {
                partial: None,
                work: source_work,
            });
        }
    };

    if request.cancellation.is_cancelled() {
        return Ok(SemanticOutcome::Cancelled {
            partial: None,
            work: source_work,
        });
    }

    // A file that had no reusable blob was parsed above. Its blob may still
    // have complete rows, which serve the artifact without lowering.
    if analyzer.reusable_live_oid(file).is_none()
        && matches!(prepared.origin(), PreparedSourceOrigin::Disk)
        && let Some(publication) =
            complete_semantic_ir_publication(analyzer, file, source_identity)?
    {
        assert_eq!(
            publication.content, content,
            "semantic IR rows for blob {source_identity} must describe its parsed source"
        );
        note_serve(
            &SERVE_COUNTS.rows_hits,
            "rows_hit",
            file.rel_path().display(),
        );
        let outcome = publish_from_semantic_ir_rows(
            analyzer,
            lowerer,
            key,
            &publication,
            permit,
            source_work,
            staged_budget,
            started_work,
            request,
        );
        observe_complete_artifact(file, &outcome, request);
        return outcome;
    }

    note_serve(&SERVE_COUNTS.lowerings, "lowering", key.path().as_str());
    #[cfg(any(test, feature = "test-support"))]
    cache.record_lowering(key.path());
    let repeat = crate::profiling::enabled() && staged_budget.record_lowering(key.fingerprint());
    let lowerer_started = std::time::Instant::now();
    staged_budget.start_lowering_work();
    let lowered = if let Some(primary_lowerer) = lowerer.primary_declaration_lowerer() {
        lower_with_primary_declarations(
            primary_lowerer,
            file,
            &prepared,
            &staged_budget,
            request.cancellation,
            || {
                analyzer
                    .adapter()
                    .parse_file(file, prepared.source(), prepared.tree())
            },
        )
    } else {
        lowerer.lower(file, &prepared, &staged_budget, request.cancellation)
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
    staged_budget.release_admission(source_work);
    // Source and builder allocations close on every exit, while accepted
    // binding traversal survives cancellation, a partial result, and errors.
    staged_budget.finish_lowering_work();
    let lowered = match lowered {
        Ok(lowered) => lowered,
        Err(error) => {
            *request.budget = staged_budget;
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
            *request.budget = staged_budget;
            return Ok(SemanticOutcome::Cancelled {
                partial: None,
                work,
            });
        }
    }

    let outcome = publish_lowered(
        key,
        lowerer.capabilities(),
        lowered,
        source_work,
        started_work,
        staged_budget,
        request,
    );
    if let Ok(SemanticOutcome::Complete { value, .. }) = &outcome {
        permit.publish_complete(Arc::clone(value));
    }
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
    let Some(content) = analyzer.semantic_source_digests().get(source_identity) else {
        return Ok(None);
    };
    let key = semantic_artifact_key_from_content(
        file,
        LanguageDialect::for_path(analyzer.adapter().language(), file.rel_path()),
        content,
        None,
        lowerer.identity(),
    )?;
    Ok(cache.get_ready(&key, request.cancellation))
}

/// The blob's complete semantic IR rows under the active producer epoch. Any
/// other publication outcome is not served: the caller lowers the file.
pub(crate) fn complete_semantic_ir_publication<A: LanguageAdapter>(
    analyzer: &TreeSitterAnalyzer<A>,
    file: &ProjectFile,
    oid: Oid,
) -> Result<Option<SemanticIrPublication>, SemanticProviderError> {
    let storage_language = analyzer.adapter().storage_language_key_for_file(file);
    let publication = analyzer
        .analyzer_store()
        .semantic_ir_publication(oid, storage_language)
        .map_err(|error| SemanticProviderError::internal(error.to_string()))?;
    Ok(publication.filter(|publication| {
        matches!(publication.outcome, SemanticIrPublicationOutcome::Complete)
    }))
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
    let Some(oid) = analyzer.reusable_live_oid(file) else {
        return Ok(None);
    };
    let Some(publication) = complete_semantic_ir_publication(analyzer, file, oid)? else {
        return Ok(None);
    };
    if publication.content != key.revision().content() {
        return Ok(None);
    }
    let scope = SemanticIrMountScope {
        mount: key.mount(),
        path: key.path().clone(),
        language: key.language(),
        content: key.revision().content(),
    };
    analyzer
        .analyzer_store()
        .read_partial_flows(publication.blob_id, procedure, &scope)
        .map_err(|error| SemanticProviderError::internal(error.to_string()))
}

/// Whether the file's complete semantic IR publication carries the content of
/// the artifact `key`.
pub(crate) fn has_complete_semantic_ir_rows<A: LanguageAdapter>(
    analyzer: &TreeSitterAnalyzer<A>,
    file: &ProjectFile,
    key: &SemanticArtifactKey,
) -> Result<bool, SemanticProviderError> {
    let Some(oid) = analyzer.reusable_live_oid(file) else {
        return Ok(false);
    };
    let Some(publication) = complete_semantic_ir_publication(analyzer, file, oid)? else {
        return Ok(false);
    };
    Ok(publication.content == key.revision().content())
}

/// Decodes one blob's rows and publishes them as the artifact that lowering
/// the same source produces. The caller holds the flight `permit` for `key`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn publish_from_semantic_ir_rows<A: LanguageAdapter>(
    analyzer: &TreeSitterAnalyzer<A>,
    lowerer: &dyn ProgramSemanticsLowerer,
    key: SemanticArtifactKey,
    publication: &SemanticIrPublication,
    permit: CompleteValuePermit<SemanticArtifactKey, SemanticArtifact>,
    source_work: SemanticWork,
    staged_budget: crate::analyzer::semantic::SemanticBudget,
    started_work: SemanticWork,
    request: &mut SemanticRequest<'_>,
) -> Result<SemanticOutcome<Arc<SemanticArtifact>>, SemanticProviderError> {
    let scope = SemanticIrMountScope {
        mount: key.mount(),
        path: key.path().clone(),
        language: key.language(),
        content: key.revision().content(),
    };
    let parts = analyzer
        .analyzer_store()
        .read_semantic_ir(publication.blob_id, &scope)
        .map_err(|error| SemanticProviderError::internal(error.to_string()))?;
    let work = SemanticWork {
        source_bytes: publication.source_bytes,
        ..SemanticWork::default()
    };
    let outcome = publish_lowered(
        key,
        lowerer.capabilities(),
        SemanticOutcome::Complete { value: parts, work },
        source_work,
        started_work,
        staged_budget,
        request,
    );
    if let Ok(SemanticOutcome::Complete { value, .. }) = &outcome {
        permit.publish_complete(Arc::clone(value));
    }
    outcome
}

use std::sync::atomic::Ordering;
