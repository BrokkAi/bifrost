//! Query-local selected native call targets for forward and reverse sites.
//! The parent alone materializes artifacts, projects semantics, and charges
//! scalar and execution work in its original call order.
//!
//! Rust owns selected readers and grammar handling. Framework callers use the
//! forward and reverse LanguageSupport capabilities; both share the file-worker
//! scheduler here and transport checked answers back in request order.

use brokk_bifrost_analysis::analyzer::languages::ExternalCalleeFileEvidence;

use brokk_bifrost_analysis::analyzer::languages::ExternalCalleeSite;

use brokk_bifrost_analysis::analyzer::read_ledger::ReadLedger;

use brokk_bifrost_analysis::analyzer::resolution::local_identity::ResolutionIdentityTranslation;

use brokk_bifrost_analysis::analyzer::resolution::worker_transport::WorkerAnswer;

use brokk_bifrost_analysis::analyzer::resolution::worker_transport::run_selected_worker;

use crate::analyzer::rust::native_points::RustDefinitionOperationFactory;
use crate::analyzer::semantic::ContentIdentity;

use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperation;

use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperationOpenOutcome;

use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperationOutcome;

use brokk_bifrost_analysis::analyzer::store::Result;

use brokk_bifrost_analysis::analyzer::store::StoreError;

use crate::analyzer::usages::call_relations::CallRelationWork;

use brokk_bifrost_analysis::analyzer::usages::call_relations::CallSite;

use brokk_bifrost_analysis::analyzer::usages::call_relations::CompletedExpansion;

use brokk_bifrost_analysis::analyzer::usages::call_relations::PrefetchedCallFile;

use brokk_bifrost_analysis::analyzer::usages::call_relations::PrefetchedCallTargets;

use brokk_bifrost_analysis::analyzer::usages::call_relations::request_for_callee_range;

use crate::analyzer::usages::get_definition::rust::resolve_call_target_batch_in_operation;

use brokk_bifrost_analysis::analyzer::usages::get_definition::CallTargetLookupOutcome;

use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupStatus;

use brokk_bifrost_analysis::analyzer::usages::get_definition::call_sites::exact_call_reference_for_reverse_site;

use brokk_bifrost_analysis::analyzer::usages::get_definition::parse_tree_for_language;

use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;

use brokk_bifrost_core::analyzer::model::Language;

use brokk_bifrost_core::analyzer::model::ProjectFile;

use brokk_bifrost_core::analyzer::model::Range;

use brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer;

use brokk_bifrost_analysis::analyzer::i_analyzer::capture_query_reads;

use brokk_bifrost_analysis::analyzer::i_analyzer::replay_query_reads;

use brokk_bifrost_core::cancellation::CancellationToken;

use brokk_bifrost_core::hash::HashMap;
use std::sync::{Arc, Mutex};

/// One status per submitted reverse site, even for unsupported structural
/// shapes and deadline-shortened batches. No empty answer claims completeness.
enum PrefetchedSite {
    Resolved {
        callee: Range,
        outcome: Box<CallTargetLookupOutcome>,
        expansion: Option<Box<CompletedExpansion>>,
    },
    Unattempted,
}

struct CallerFileAnswer {
    source_identity: Option<ContentIdentity>,
    sites: Vec<PrefetchedSite>,
    work: CallRelationWork,
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
    snapshot: Option<
        Arc<brokk_bifrost_analysis::analyzer::semantic_model::runtime::ActiveSemanticModelSnapshot>,
    >,
) -> Result<HashMap<ProjectFile, PrefetchedCallFile>> {
    let analyzer = workspace.analyzer();
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
    let answers = prefetch_file_groups(
        workspace,
        &files,
        cancellation,
        snapshot,
        |factory, operation, file, ranges| {
            let mut answer = CallerFileAnswer {
                source_identity: None,
                sites: ranges.iter().map(|_| PrefetchedSite::Unattempted).collect(),
                work: CallRelationWork::default(),
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
            let Some(tree) = parse_tree_for_language(file, Language::Rust, &source) else {
                return Ok(answer);
            };
            let mut references = Vec::new();
            let mut indices = HashMap::default();
            let keys = ranges
                .iter()
                .map(|range| {
                    let callee =
                        exact_call_reference_for_reverse_site(&tree, Language::Rust, range)?;
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
            answer.source_identity = Some(ContentIdentity::hash_bytes(source.as_bytes()));
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
                Arc::clone(&source),
                cancellation,
                factory,
                operation,
            );
            if !cancellation.is_cancelled() {
                for (site, key) in answer.sites.iter_mut().zip(keys) {
                    if let Some((callee, index)) = key
                        && let Some(outcome) = outcomes.get(index)
                        && outcome.outcome.status != DefinitionLookupStatus::Cancelled
                    {
                        let expansion = if matches!(
                            outcome.outcome.status,
                            DefinitionLookupStatus::NoDefinition
                                | DefinitionLookupStatus::UnresolvableImportBoundary
                        ) && let Some(text) =
                            outcome.outcome.resolved_reference_target()
                        {
                            let file_evidence = ExternalCalleeFileEvidence::default();
                            let external_site = ExternalCalleeSite {
                                source: &source,
                                tree: &tree,
                                callee_start_byte: callee.start_byte,
                                file_evidence: &file_evidence,
                            };

                            use crate::analyzer::rust::std_types::RustProofAttempt;

                            use crate::analyzer::rust::std_types::completed_proof;
                            let attempt = completed_proof(Some(cancellation), || {
                                crate::analyzer::rust::expand_rust_imported_external_callee_attempt_with_operation(
                                                    analyzer, file, text, Some(&external_site), Some(factory), Some(&mut *operation),
                                                ).into_value()
                            });
                            match attempt {
                                RustProofAttempt::Complete(answer) => Some(answer.map(|answer| {
                                    (
                                        answer
                                            .exact_external_call
                                            .expect("Rust expansion proves its callable"),
                                        answer
                                            .external_callee_identity
                                            .expect("Rust expansion proves its identity"),
                                    )
                                })),
                                RustProofAttempt::Incomplete { reason, .. } => {
                                    if brokk_bifrost_core::profiling::enabled() {
                                        brokk_bifrost_core::profiling::note(format!(
                                            "taint.compose.callers.prefetch expansion_incomplete file={file} callee={callee:?} reason={reason}"
                                        ));
                                    }
                                    None
                                }
                            }
                        } else {
                            None
                        };
                        *site = PrefetchedSite::Resolved {
                            callee,
                            outcome: Box::new(outcome.clone()),
                            expansion: expansion.map(Box::new),
                        };
                    }
                }
            }
            Ok(answer)
        },
    )?;
    let mut prefetched = HashMap::default();
    for (file, answer, _) in answers {
        let Some(source_identity) = answer.source_identity else {
            continue;
        };
        let mut outcomes = Vec::new();
        for site in answer.sites {
            if let PrefetchedSite::Resolved {
                callee,
                outcome,
                expansion,
            } = site
            {
                outcomes.push((
                    (callee.start_byte, callee.end_byte),
                    *outcome,
                    expansion.map(|answer| *answer),
                ));
            }
        }
        if brokk_bifrost_core::profiling::enabled() {
            brokk_bifrost_core::profiling::note(format!(
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

/// Capture reader authority and query dependencies once per independent file
/// worker. Both forward candidates and reverse confirmation use this scheduler.
struct FileAnswer<A> {
    value: A,
    reads: Arc<ReadLedger>,
}

impl<A: WorkerAnswer> WorkerAnswer for FileAnswer<A> {
    fn translate(self, translation: &impl ResolutionIdentityTranslation) -> Self {
        Self {
            value: self.value.translate(translation),
            reads: self.reads,
        }
    }
}

fn prefetch_file_groups<'a, A: WorkerAnswer>(
    workspace: &'a WorkspaceAnalyzer,
    files: &[(ProjectFile, Vec<Range>)],
    cancellation: &CancellationToken,
    snapshot: Option<
        Arc<brokk_bifrost_analysis::analyzer::semantic_model::runtime::ActiveSemanticModelSnapshot>,
    >,
    work: impl for<'selection> Fn(
        &'selection RustDefinitionOperationFactory<'a>,
        &mut SelectedResolutionOperation<'a, 'selection>,
        &ProjectFile,
        &[Range],
    ) -> Result<A>
    + Sync,
) -> Result<Vec<(ProjectFile, A, Arc<ReadLedger>)>> {
    let analyzer = workspace.analyzer();
    brokk_bifrost_core::analyzer::config::ensure_global_rayon_pool();
    if files.is_empty() || rayon::current_num_threads() == 1 || cancellation.is_cancelled() {
        return Ok(Vec::new());
    }
    let Some(factory) = RustDefinitionOperationFactory::new(analyzer, cancellation) else {
        return Ok(Vec::new());
    };
    let selected = match factory.open(cancellation)? {
        SelectedResolutionOperationOpenOutcome::Ready(selected) => *selected,
        _ => return Ok(Vec::new()),
    };
    let store = selected.worker_store();
    if store.uses_single_connection_reads() {
        return Ok(Vec::new());
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
            let work = &work;
            scope.spawn(move |_| {
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let _cancellation =
                        AnalyzerQueryScope::with_cancellation(analyzer, cancellation);
                    let _models = AnalyzerQueryScope::with_active_semantic_model_snapshot(
                        analyzer,
                        snapshot.clone(),
                    );
                    run_selected_worker(store, input, cancellation, |operation| {
                        let (value, reads) = capture_query_reads(analyzer, || {
                            work(factory, operation, file, ranges)
                        });
                        Ok(SelectedResolutionOperationOutcome::Native(FileAnswer {
                            value: value?,
                            reads,
                        }))
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
    let mut answers = Vec::new();
    // Request order controls identity handback and ledger replay, never worker
    // completion order. Unattempted work stays on the caller's terminal path.
    for ((file, _), result) in files.iter().zip(results) {
        let Some(result) = result.into_inner().expect("caller worker result lock") else {
            continue;
        };
        let SelectedResolutionOperationOutcome::Native(answer) = result? else {
            continue;
        };
        let answer = answer.reintern(&selected, [], cancellation)?;
        replay_query_reads(analyzer, &answer.reads);
        answers.push((file.clone(), answer.value, answer.reads));
    }
    Ok(answers)
}

struct SelectedFileTargets(Vec<(Range, CallTargetLookupOutcome)>);

impl WorkerAnswer for SelectedFileTargets {
    fn translate(self, _: &impl ResolutionIdentityTranslation) -> Self {
        // The checked publication vocabulary contains no operation-local ids.
        self
    }
}

pub(crate) fn prefetch_selected_files(
    workspace: &WorkspaceAnalyzer,
    files: &[(ProjectFile, Vec<Range>)],
    cancellation: &CancellationToken,
    snapshot: Option<
        Arc<brokk_bifrost_analysis::analyzer::semantic_model::runtime::ActiveSemanticModelSnapshot>,
    >,
) -> Result<Vec<(ProjectFile, PrefetchedCallTargets)>> {
    let files = files
        .iter()
        .filter(|(file, _)| file.language() == Language::Rust)
        .cloned()
        .collect::<Vec<_>>();
    let answers = prefetch_file_groups(
        workspace,
        &files,
        cancellation,
        snapshot,
        |factory, operation, file, ranges| {
            if cancellation.soft_deadline_passed() || cancellation.is_cancelled() {
                return Ok(SelectedFileTargets(Vec::new()));
            }
            let Some(source) = workspace
                .analyzer()
                .indexed_source(file)
                .map(Arc::<str>::from)
            else {
                return Ok(SelectedFileTargets(Vec::new()));
            };
            let requests = ranges
                .iter()
                .map(|range| request_for_callee_range(file, *range))
                .collect();
            let outcomes = resolve_call_target_batch_in_operation(
                workspace.analyzer(),
                requests,
                file.clone(),
                source,
                cancellation,
                factory,
                operation,
            );
            assert_eq!(ranges.len(), outcomes.len());
            Ok(SelectedFileTargets(
                ranges.iter().copied().zip(outcomes).collect(),
            ))
        },
    )?;
    Ok(answers
        .into_iter()
        .map(|(file, answer, reads)| {
            (
                file,
                PrefetchedCallTargets {
                    targets: answer.0,
                    reads,
                },
            )
        })
        .collect())
}
