//! Query-local speculative native call targets for retained Rust reverse sites.
//! The parent alone materializes artifacts, projects semantics, and charges
//! scalar and execution work in its original call order.
//!
//! This is the Rust implementation of the shared reverse-site prefetch. It
//! lives in the Rust module because it opens the selected Rust definition
//! operation and reads Rust trees; the shared dispatch pool reaches it through
//! `LanguageSupport::prefetch_reverse_call_targets`, so framework code never
//! names this language module.

use crate::analyzer::read_ledger::ReadLedger;
use crate::analyzer::resolution::ResolutionIdentityTranslation;
use crate::analyzer::resolution::worker_transport::{WorkerAnswer, run_selected_worker};
use crate::analyzer::rust::native_points::RustDefinitionOperationFactory;
use crate::analyzer::semantic::ContentIdentity;
use crate::analyzer::store::resolution_operation::{
    SelectedResolutionOperationOpenOutcome, SelectedResolutionOperationOutcome,
};
use crate::analyzer::store::{Result, StoreError};
use crate::analyzer::usages::call_relations::{
    CallRelationWork, CallSite, PrefetchedCallFile, request_for_callee_range,
};
use crate::analyzer::usages::get_definition::{
    CallTargetLookupOutcome, DefinitionLookupStatus, exact_call_reference_for_reverse_site,
    parse_tree_for_language, resolve_call_target_batch_in_operation,
};
use crate::analyzer::{
    AnalyzerQueryScope, Language, ProjectFile, Range, WorkspaceAnalyzer, capture_query_reads,
    replay_query_reads,
};
use crate::cancellation::CancellationToken;
use crate::hash::HashMap;
use std::sync::{Arc, Mutex};

/// One status per submitted reverse site, even for unsupported structural
/// shapes and deadline-shortened batches. No empty answer claims completeness.
enum PrefetchedSite {
    Resolved {
        callee: Range,
        outcome: Box<CallTargetLookupOutcome>,
    },
    Unattempted,
}

struct CallerFileAnswer {
    source_identity: Option<ContentIdentity>,
    sites: Vec<PrefetchedSite>,
    work: CallRelationWork,
    reads: Arc<ReadLedger>,
}

impl WorkerAnswer for CallerFileAnswer {
    fn translate(self, _: &impl ResolutionIdentityTranslation) -> Self {
        // CallTargetLookupOutcome is the checked native publication vocabulary:
        // CodeUnits, source ranges, strings and declaration-side evidence.
        // It has no operation-local identity or semantic artifact handle.
        // The selected forward producer captures forward_identity_digests
        // before its stage cleanup; projection here retains no such aliases.
        self
    }
}

pub(crate) fn prefetch_caller_files(
    workspace: &WorkspaceAnalyzer,
    sites: &[CallSite],
    cancellation: &CancellationToken,
    snapshot: Option<Arc<crate::analyzer::semantic_model::ActiveSemanticModelSnapshot>>,
) -> Result<HashMap<ProjectFile, PrefetchedCallFile>> {
    let analyzer = workspace.analyzer();
    crate::analyzer::ensure_global_rayon_pool();
    if rayon::current_num_threads() == 1 || cancellation.is_cancelled() {
        return Ok(HashMap::default());
    }
    let Some(factory) = RustDefinitionOperationFactory::new(analyzer, cancellation) else {
        return Ok(HashMap::default());
    };
    let mut files = Vec::<(ProjectFile, Vec<Range>)>::new();
    let mut by_file = HashMap::default();
    for site in sites
        .iter()
        .filter(|site| site.file.language() == Language::Rust)
    {
        let next = files.len();
        let index = *by_file.entry(site.file.clone()).or_insert_with(|| {
            files.push((site.file.clone(), Vec::new()));
            next
        });
        files[index].1.push(site.range);
    }
    if files.is_empty() {
        return Ok(HashMap::default());
    }
    let selected = match factory.open(cancellation)? {
        SelectedResolutionOperationOpenOutcome::Ready(selected) => *selected,
        _ => return Ok(HashMap::default()),
    };
    let store = selected.worker_store();
    if store.uses_single_connection_reads() {
        return Ok(HashMap::default());
    }
    let input = selected.worker_input();
    let results = files.iter().map(|_| Mutex::new(None)).collect::<Vec<_>>();
    rayon::scope(|scope| {
        for ((file, ranges), result) in files.iter().zip(&results) {
            if cancellation.soft_deadline_passed() || cancellation.is_cancelled() {
                break;
            }
            let factory = &factory;
            let snapshot = &snapshot;
            scope.spawn(move |_| {
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let _cancellation =
                        AnalyzerQueryScope::with_cancellation(analyzer, cancellation);
                    let _models = AnalyzerQueryScope::with_active_semantic_model_snapshot(
                        analyzer,
                        snapshot.clone(),
                    );
                    run_selected_worker(store, input, cancellation, |operation| {
                        let (answer, reads) = capture_query_reads(analyzer, || -> Result<_> {
                            let mut answer = CallerFileAnswer {
                                source_identity: None,
                                sites: ranges.iter().map(|_| PrefetchedSite::Unattempted).collect(),
                                work: CallRelationWork::default(),
                                reads: Arc::new(ReadLedger::new()),
                            };
                            if cancellation.soft_deadline_passed() || cancellation.is_cancelled() {
                                return Ok(answer);
                            }
                            // This reads an exact source snapshot, not a semantic
                            // artifact; it admits no file on the execution ledger.
                            let Some(source) = workspace
                                .current_program_semantics_artifact_source(file, usize::MAX)
                                .map_err(|error| StoreError::new(error.to_string()))?
                            else {
                                return Ok(answer);
                            };
                            let (_, source) = source.into_parts();
                            let Some(tree) = parse_tree_for_language(file, Language::Rust, &source)
                            else {
                                return Ok(answer);
                            };
                            let mut references = Vec::new();
                            let mut indices = HashMap::default();
                            let keys = ranges
                                .iter()
                                .map(|range| {
                                    let callee = exact_call_reference_for_reverse_site(
                                        &tree,
                                        Language::Rust,
                                        range,
                                    )?;
                                    let next = references.len();
                                    let index = *indices
                                        .entry((callee.start_byte, callee.end_byte))
                                        .or_insert_with(|| {
                                            references.push(callee);
                                            next
                                        });
                                    Some((callee, index))
                                })
                                .collect::<Vec<_>>();
                            answer.source_identity =
                                Some(ContentIdentity::hash_bytes(source.as_bytes()));
                            answer.work = CallRelationWork {
                                scanned_files: 1,
                                scanned_source_bytes: source.len(),
                                examined_candidates: 1,
                            };
                            let requests = references
                                .iter()
                                .map(|range| request_for_callee_range(file, *range))
                                .collect();
                            let outcomes = resolve_call_target_batch_in_operation(
                                analyzer,
                                requests,
                                file.clone(),
                                source,
                                cancellation,
                                factory,
                                operation,
                            );
                            if !cancellation.is_cancelled() {
                                for (site, key) in answer.sites.iter_mut().zip(keys) {
                                    if let Some((callee, index)) = key
                                        && let Some(outcome) = outcomes.get(index)
                                        && outcome.outcome.status
                                            != DefinitionLookupStatus::Cancelled
                                    {
                                        *site = PrefetchedSite::Resolved {
                                            callee,
                                            outcome: Box::new(outcome.clone()),
                                        };
                                    }
                                }
                            }
                            Ok(answer)
                        });
                        let mut answer = answer?;
                        answer.reads = reads;
                        Ok(SelectedResolutionOperationOutcome::Native(answer))
                    })
                }));
                let outcome = match outcome {
                    Ok(outcome) => outcome,
                    Err(panic) => Err(StoreError::new(format!(
                        "caller native worker panicked for {file}: {}",
                        brokk_bifrost_core::panic_report::panic_payload_message(panic.as_ref()),
                    ))),
                };
                *result.lock().expect("caller worker result lock") = Some(outcome);
            });
        }
    });
    let mut prefetched = HashMap::default();
    for ((file, _), result) in files.into_iter().zip(results) {
        let Some(result) = result.into_inner().expect("caller worker result lock") else {
            continue;
        };
        let SelectedResolutionOperationOutcome::Native(answer) = result? else {
            continue;
        };
        let answer = answer.reintern(&selected, [], cancellation)?;
        replay_query_reads(analyzer, &answer.reads);
        let Some(source_identity) = answer.source_identity else {
            continue;
        };
        let mut outcomes = Vec::new();
        for site in answer.sites {
            if let PrefetchedSite::Resolved { callee, outcome } = site {
                outcomes.push(((callee.start_byte, callee.end_byte), *outcome));
            }
        }
        if crate::profiling::enabled() {
            crate::profiling::note(format!(
                "taint.compose.callers.prefetch file={file} sites={}",
                outcomes.len()
            ));
        }
        prefetched.insert(
            file,
            PrefetchedCallFile {
                source_identity,
                outcomes,
                work: answer.work,
                native_execution_delta: 0,
            },
        );
    }
    Ok(prefetched)
}
