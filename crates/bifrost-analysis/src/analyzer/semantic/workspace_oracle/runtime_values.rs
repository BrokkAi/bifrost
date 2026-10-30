//! Activation-bound evidence for source-owned runtime keyed loads.
//!
//! Runtime model records identify an exposure and read behavior; syntax identifies
//! an occurrence. Neither is an executable value until it joins a MemoryLoad in
//! the exact immutable semantic artifact. This module owns that join.

use crate::analyzer::common::same_byte_range;
use crate::analyzer::semantic::workspace_oracle::{
    WorkspaceSemanticOracle, exact_source_for_procedure,
};
use crate::analyzer::semantic::{
    EvidenceCompleteness, MemoryLocationId, ProofStatus, ValueAtPoint,
};
use crate::analyzer::semantic::{
    LengthDelimitedDigest, ProcedureHandle, SemanticCapability, SemanticOutcome,
    SemanticProviderError, SemanticRequest, SemanticWork,
};
use crate::analyzer::workspace_authority::{
    AuthorityInputs, WorkspaceAuthorityMemo, memo_attribution,
};
use crate::analyzer::{FactSubject, WorkspaceFactFamily};
use crate::analyzer::{LanguageDialect, parser_language_for_dialect};
use crate::analyzer::{ProjectFile, Range};
pub use brokk_bifrost_semantic::analyzer::semantic::workspace_oracle::runtime_values::*;
use std::sync::Arc;

pub(super) type AttributedRuntimeWriteFootprintCache = WorkspaceAuthorityMemo<
    brokk_bifrost_semantic::analyzer::semantic::workspace_oracle::runtime_values::WorkspaceRuntimeWriteFootprintCache,
>;

pub(super) fn attributed_runtime_write_footprint_cache() -> AttributedRuntimeWriteFootprintCache {
    WorkspaceAuthorityMemo::new(WorkspaceFactFamily::RuntimeRootWriteFootprint,
        brokk_bifrost_semantic::analyzer::semantic::workspace_oracle::runtime_values::workspace_runtime_write_footprint_cache())
}

fn footprint_digest(
    answer: WorkspaceRuntimeWriteFootprint,
) -> crate::analyzer::semantic::StableDigest {
    let mut digest = LengthDelimitedDigest::new(b"bifrost.runtime-root-write-footprint.v1");
    digest.push(match answer {
        WorkspaceRuntimeWriteFootprint::Closed => b"closed",
        WorkspaceRuntimeWriteFootprint::RuntimeRootWrite => b"runtime-root-write",
        WorkspaceRuntimeWriteFootprint::CoverageLimited => b"coverage-limited",
    });
    digest.finish()
}

fn footprint_inputs(
    file: &ProjectFile,
    answer: WorkspaceRuntimeWriteFootprint,
) -> AuthorityInputs<'static> {
    AuthorityInputs::Fact {
        language: file.language(),
        subject: FactSubject::File {
            rel_path: crate::path_utils::rel_path_string(file).into(),
        },
        answer: footprint_digest(answer),
    }
}

pub(crate) fn runtime_footprint_answer(
    workspace: &crate::analyzer::WorkspaceAnalyzer,
    file: &ProjectFile,
    limits: SemanticWork,
) -> Option<crate::analyzer::semantic::StableDigest> {
    let oracle = WorkspaceSemanticOracle::new(workspace);
    let mut budget = crate::analyzer::semantic::SemanticBudget::new(limits).ok()?;
    let cancellation = crate::CancellationToken::default();
    let (answer, _) = oracle
        .workspace_runtime_write_footprint(
            file,
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .ok()?;
    // An incomplete scan cannot certify an old answer, even another incomplete scan.
    (answer != WorkspaceRuntimeWriteFootprint::CoverageLimited).then(|| footprint_digest(answer))
}

impl WorkspaceSemanticOracle<'_> {
    /// Bind a structured source candidate to its exact executable load.
    pub fn runtime_keyed_read_at_source(
        &self,
        file: &ProjectFile,
        range: Range,
        filter: &RuntimeKeyedReadFilter,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<RuntimeKeyedReadResult>, SemanticProviderError> {
        if request.cancellation.is_cancelled() {
            return Ok(SemanticOutcome::Cancelled {
                partial: None,
                work: SemanticWork::default(),
            });
        }
        let materialized = self
            .workspace
            .materialize_program_semantics(file, request)?;
        let Some(artifact) = materialized.available_value() else {
            return Ok(materialized.map(|_| RuntimeKeyedReadResult::default()));
        };
        if !RUNTIME_KEYED_READ_LANGUAGES.contains(&artifact.key().language().language()) {
            return Ok(SemanticOutcome::Unsupported {
                capability: SemanticCapability::Values,
                partial: None,
                work: materialized.work(),
            });
        }
        let mut result = RuntimeKeyedReadResult::default();
        if !matches!(materialized, SemanticOutcome::Complete { .. }) {
            result
                .limitations
                .push(RuntimeReadLimitation::MaterializationIncomplete);
        }
        let mut work = materialized.work();
        for procedure in artifact.procedures() {
            let handle = artifact
                .procedure_handle(procedure.id())
                .expect("artifact procedure exists");
            let outcome = self.runtime_reads_for_procedure(&handle, request)?;
            work = work.conservative_add(outcome.work());
            if let Some(reads) = outcome.available_value() {
                let candidate_matches = |candidate: &RuntimeKeyedReadCandidate| {
                    same_byte_range(candidate.anchor, range)
                        && candidate.global == filter.global
                        && candidate.container == filter.container
                        // Missing key identity retains dynamic/unsupported
                        // limitations for this surface; it is not a filtered zero.
                        && candidate.key.as_ref().is_none_or(|key| filter.accepts_key(key))
                };
                for endpoint in &reads.endpoints {
                    if (same_byte_range(endpoint.expression, range)
                        || same_byte_range(endpoint.candidate_anchor, range))
                        && endpoint.runtime == filter.runtime
                        && endpoint.global == filter.global
                        && endpoint.container == filter.container
                        && filter.accepts_key(&endpoint.key)
                        && (!filter.pristine_input
                            || endpoint.source_origin
                                == RuntimeReadSourceOrigin::PristineRuntimeInput)
                    {
                        result.endpoints.push(endpoint.clone());
                    }
                }
                if reads.candidates.iter().any(candidate_matches) {
                    for limitation in &reads.limitations {
                        if !result.limitations.contains(limitation) {
                            result.limitations.push(*limitation);
                        }
                    }
                }
                result.conclusive_exclusion |= reads
                    .candidates
                    .iter()
                    .any(|candidate| candidate.excluded && candidate_matches(candidate));
            }
            if !outcome.is_complete() && outcome.available_value().is_none() {
                result
                    .limitations
                    .push(RuntimeReadLimitation::MaterializationIncomplete);
            }
            match outcome {
                SemanticOutcome::Cancelled { .. } => {
                    return Ok(SemanticOutcome::Cancelled {
                        partial: Some(result),
                        work,
                    });
                }
                SemanticOutcome::ExceededBudget { exceeded, .. } => {
                    return Ok(SemanticOutcome::ExceededBudget {
                        partial: Some(result),
                        exceeded,
                        work,
                    });
                }
                _ => {}
            }
        }
        if !result.limitations.is_empty() {
            result.conclusive_exclusion = false;
        }
        Ok(if result.limitations.is_empty() {
            SemanticOutcome::Complete {
                value: result,
                work,
            }
        } else {
            SemanticOutcome::Unproven {
                partial: result,
                work,
            }
        })
    }
}

use crate::analyzer::complete_value_cache::CompleteValueAcquisition;
impl WorkspaceSemanticOracle<'_> {
    #[doc(hidden)]
    pub fn runtime_syntax_for_source(
        &self,
        dialect: LanguageDialect,
        source: &str,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<Arc<RuntimeSyntaxSnapshot>>, SemanticProviderError> {
        let before = request.budget.replay_snapshot();
        let mut identity =
            LengthDelimitedDigest::new(b"bifrost.runtime-syntax.v4-returned-refinement-census");
        identity.push(dialect.stable_label().as_bytes());
        identity.push(source.as_bytes());
        let key = identity.finish();
        let (acquisition, _) = self.runtime_syntax.acquire(&key, request.cancellation);
        let permit = match acquisition {
            CompleteValueAcquisition::Cached { value } => {
                let repeat = request.budget.has_replay_holder(&value.owner);
                let mut replay = value.work;
                if repeat {
                    replay.retained = SemanticWork::default();
                }
                let work = replay.cumulative;
                let charge = request.budget.replay_continuation(replay);
                if let Err(exceeded) = charge {
                    return Ok(SemanticOutcome::ExceededBudget {
                        partial: None,
                        exceeded,
                        work,
                    });
                }
                if !repeat {
                    request
                        .budget
                        .track_replay_holder(&value.owner, value.work.retained);
                    request.budget.record_charged_artifact(key);
                }
                // The execution ledger measures traversal actually performed;
                // reuse imports the census but only performs one lookup.
                if !request.charge_execution_traversal(1) {
                    return Ok(SemanticOutcome::Unproven {
                        partial: value,
                        work,
                    });
                }
                return Ok(SemanticOutcome::Complete { value, work });
            }
            CompleteValueAcquisition::Leader { permit } => permit,
            CompleteValueAcquisition::Cancelled => {
                return Ok(SemanticOutcome::Cancelled {
                    partial: None,
                    work: SemanticWork::default(),
                });
            }
            CompleteValueAcquisition::Rejected => {
                unreachable!("runtime syntax never rejects a flight")
            }
        };
        let mut work = SemanticWork {
            source_bytes: source.len(),
            ..SemanticWork::default()
        };
        request.budget.charge_work(work);
        let grammar = parser_language_for_dialect(dialect)
            .ok_or_else(|| SemanticProviderError::internal("runtime-read dialect has no parser"))?;
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&grammar)
            .map_err(|error| SemanticProviderError::internal(error.to_string()))?;
        let mut input = |offset: usize, _| &source.as_bytes()[offset..];
        let mut progress = |_: &tree_sitter::ParseState| request.cancellation.is_cancelled();
        let tree = parser.parse_with_options(
            &mut input,
            None,
            Some(tree_sitter::ParseOptions::new().progress_callback(&mut progress)),
        );
        if request.cancellation.is_cancelled() {
            return Ok(SemanticOutcome::Cancelled {
                partial: None,
                work,
            });
        }
        let Some(tree) = tree else {
            return Ok(SemanticOutcome::Unknown {
                partial: None,
                work,
            });
        };
        let facts = runtime_syntax_facts(dialect.language(), tree.root_node(), source, usize::MAX);
        let scan_work = SemanticWork {
            nested_entries: facts.visited_nodes,
            ..SemanticWork::default()
        };
        let retained_work = SemanticWork {
            nested_entries: facts.reads.len().saturating_add(facts.writes.len()),
            ..SemanticWork::default()
        };
        let fact_work = scan_work.conservative_add(retained_work);
        work = work.conservative_add(fact_work);
        request.budget.charge_work(scan_work);
        if let Err(exceeded) = request.budget.admit(retained_work) {
            return Ok(SemanticOutcome::ExceededBudget {
                partial: None,
                exceeded,
                work,
            });
        }
        if request.cancellation.is_cancelled() {
            request.budget.release_admission(retained_work);
            return Ok(SemanticOutcome::Cancelled {
                partial: None,
                work,
            });
        }
        let traversed = request.charge_execution_traversal(facts.visited_nodes);
        let replay = request.budget.replay_since(&before);
        let owner = Arc::new(());
        request.budget.bind_replay_holder(&owner, &before);
        let value = Arc::new(RuntimeSyntaxSnapshot {
            facts,
            has_error: tree.root_node().has_error(),
            work: replay,
            owner,
        });
        if !traversed || !value.facts.complete {
            return Ok(SemanticOutcome::Unproven {
                partial: value,
                work,
            });
        }
        request.budget.record_charged_artifact(key);
        permit.publish_complete(Arc::clone(&value));
        Ok(SemanticOutcome::Complete { value, work })
    }

    /// Inspect every other JavaScript or TypeScript module once per captured
    /// oracle for the runtime-root writes the pristine-input model names.
    ///
    /// The scan is bounded by the request budget: a module the budget cannot
    /// cover keeps the answer incomplete rather than clean. Results are cached
    /// per current module, because one keyed-read request evaluates every
    /// procedure of that module.
    fn workspace_runtime_write_footprint(
        &self,
        current: &ProjectFile,
        request: &mut SemanticRequest<'_>,
    ) -> Result<(WorkspaceRuntimeWriteFootprint, SemanticWork), SemanticProviderError> {
        self.runtime_write_footprints.read(
            &memo_attribution(self.workspace.analyzer()),
            |memo| {
                let (acquisition, _) = memo.acquire(current, request.cancellation);
                let permit = match acquisition {
                    CompleteValueAcquisition::Cached { value } => {
                        let work = SemanticWork {
                            nested_entries: 1,
                            ..SemanticWork::default()
                        };
                        request.budget.charge_work(work);
                        return Ok((*value, work));
                    }
                    CompleteValueAcquisition::Leader { permit } => permit,
                    CompleteValueAcquisition::Cancelled | CompleteValueAcquisition::Rejected => {
                        return Ok((
                            WorkspaceRuntimeWriteFootprint::CoverageLimited,
                            SemanticWork::default(),
                        ));
                    }
                };
                let (footprint, work) = self.scan_workspace_runtime_writes(current, request)?;
                if footprint != WorkspaceRuntimeWriteFootprint::CoverageLimited {
                    permit.publish_complete(Arc::new(footprint));
                }
                Ok((footprint, work))
            },
            |outcome| match outcome {
                Ok((answer, _)) => footprint_inputs(current, *answer),
                Err(_) => AuthorityInputs::Unnamed,
            },
        )
    }

    fn scan_workspace_runtime_writes(
        &self,
        current: &ProjectFile,
        request: &mut SemanticRequest<'_>,
    ) -> Result<(WorkspaceRuntimeWriteFootprint, SemanticWork), SemanticProviderError> {
        let mut footprint = WorkspaceRuntimeWriteFootprint::Closed;
        let mut work = SemanticWork::default();
        let project = self.workspace.analyzer().project();
        let files = project
            .all_files_shared()
            .map_err(|error| SemanticProviderError::internal(error.to_string()))?;
        for file in files.iter() {
            // Only a module of the same language can spell a write to this
            // runtime root: the exposure's binder is that language's own.
            if file == current || file.language() != current.language() {
                continue;
            }
            if request.cancellation.is_cancelled() {
                return Ok((WorkspaceRuntimeWriteFootprint::CoverageLimited, work));
            }
            // A previously paid source must still be readable for exact identity
            // validation after its allowance has been consumed. The syntax cache
            // charges any new content before parsing or returning its facts.
            let max_bytes = request.budget.limits().source_bytes;
            let snapshot = project
                .read_source_snapshot_limited(file, max_bytes)
                .map_err(|error| SemanticProviderError::internal(error.to_string()))?;
            let Some(snapshot) = snapshot else {
                return Ok((WorkspaceRuntimeWriteFootprint::CoverageLimited, work));
            };
            let outcome = self.runtime_syntax_for_source(
                LanguageDialect::for_path(file.language(), file.rel_path()),
                snapshot.source(),
                request,
            )?;
            work = work.conservative_add(outcome.work());
            let SemanticOutcome::Complete { value, .. } = outcome else {
                return Ok((WorkspaceRuntimeWriteFootprint::CoverageLimited, work));
            };
            if value.has_error {
                return Ok((WorkspaceRuntimeWriteFootprint::CoverageLimited, work));
            }
            let facts = &value.facts;
            if !facts.writes.is_empty() {
                footprint = WorkspaceRuntimeWriteFootprint::RuntimeRootWrite;
            }
        }
        Ok((footprint, work))
    }

    /// Whether the procedure's language proves that dropping every parameter
    /// and `let` binding runs no user code (#3757), for consumers that judge
    /// the procedure's raw gaps without the snapshot sweep, such as exit
    /// profiles. A procedure with no `InertDropGlue` obligation answers
    /// `false` without reading its source.
    pub(crate) fn procedure_drops_proven_inert(
        &self,
        procedure: &ProcedureHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<bool, SemanticProviderError> {
        let Some(gap) = procedure.semantics().gaps().iter().find(|gap| {
            gap.discharge == crate::analyzer::semantic::SemanticGapDischarge::InertDropGlue
        }) else {
            return Ok(false);
        };
        crate::analyzer::semantic::workspace_oracle::inert_drop_glue_discharges_gap(
            gap,
            procedure,
            self.workspace,
            request,
            &mut None,
        )
    }

    /// Ordinary semantic consumers pay no parse cost when the captured model
    /// snapshot has no runtime-value contracts to apply.
    pub(crate) fn runtime_refinements_for_procedure(
        &self,
        procedure: &ProcedureHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<RuntimeKeyedReadResult>, SemanticProviderError> {
        if !self
            .active_semantic_models()
            .is_some_and(|active| active.runtime_values().next().is_some())
        {
            return Ok(SemanticOutcome::Complete {
                value: RuntimeKeyedReadResult::default(),
                work: SemanticWork::default(),
            });
        }
        self.runtime_reads_for_procedure(procedure, request)
    }

    /// The cache is owned by this immutable oracle activation snapshot, and the
    /// key retains exact artifact-instance identity. It never crosses snapshots.
    #[doc(hidden)]
    pub fn runtime_reads_for_procedure(
        &self,
        procedure: &ProcedureHandle,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<RuntimeKeyedReadResult>, SemanticProviderError> {
        self.workspace
            .analyzer()
            .record_read(crate::analyzer::ReadKey::semantic_artifact(
                procedure.artifact().key(),
            ));
        self.active_semantic_models();
        if !RUNTIME_KEYED_READ_LANGUAGES.contains(&procedure.artifact().key().language().language())
        {
            return Ok(SemanticOutcome::Complete {
                value: RuntimeKeyedReadResult::default(),
                work: SemanticWork::default(),
            });
        }
        // Validate the current source before a hit as well as before a build.
        // An oracle may outlive an editor update; a retained artifact must not.
        let source = exact_source_for_procedure(
            self.workspace,
            procedure,
            request.budget.limits().source_bytes,
        );
        let (file, source) = match source {
            Err(SemanticProviderError::InvalidIdentity(_)) => {
                return Ok(SemanticOutcome::Unproven {
                    partial: RuntimeKeyedReadResult {
                        limitations: vec![RuntimeReadLimitation::StaleEvidence],
                        ..RuntimeKeyedReadResult::default()
                    },
                    work: SemanticWork::default(),
                });
            }
            Err(error) => return Err(error),
            Ok(None) => {
                return Ok(SemanticOutcome::Unknown {
                    partial: None,
                    work: SemanticWork::default(),
                });
            }
            Ok(Some(source)) => source,
        };
        let (acquisition, _) = self.runtime_reads.acquire(procedure, request.cancellation);
        let permit = match acquisition {
            CompleteValueAcquisition::Cached { value } => {
                debug_assert!(
                    value.limitations.is_empty(),
                    "only complete runtime reads are cached"
                );
                self.record_closed_runtime_footprint(&file);

                let work = SemanticWork {
                    nested_entries: value.endpoints.len()
                        + value.limitations.len()
                        + value.candidates.len()
                        + 1,
                    ..SemanticWork::default()
                };
                if let Err(exceeded) = request.budget.admit(work) {
                    return Ok(SemanticOutcome::ExceededBudget {
                        partial: None,
                        exceeded,
                        work,
                    });
                }
                return Ok(SemanticOutcome::Complete {
                    value: (*value).clone(),
                    work,
                });
            }
            CompleteValueAcquisition::Leader { permit } => permit,
            CompleteValueAcquisition::Cancelled => {
                return Ok(SemanticOutcome::Cancelled {
                    partial: None,
                    work: SemanticWork::default(),
                });
            }
            CompleteValueAcquisition::Rejected => {
                return Ok(SemanticOutcome::Unknown {
                    partial: None,
                    work: SemanticWork::default(),
                });
            }
        };
        let outcome = self.build_runtime_reads(procedure, &file, &source, request)?;
        if let SemanticOutcome::Complete { value, .. } = &outcome {
            permit.publish_complete(Arc::new(value.clone()));
        }
        Ok(outcome)
    }

    // A complete runtime-read result was built only under a closed footprint.
    // Re-state that authority question on every result-cache hit.
    fn record_closed_runtime_footprint(&self, file: &ProjectFile) {
        let analyzer = self.workspace.analyzer();
        crate::analyzer::workspace_authority::record_workspace_authority_read(
            analyzer,
            WorkspaceFactFamily::RuntimeRootWriteFootprint,
            footprint_inputs(file, WorkspaceRuntimeWriteFootprint::Closed),
        );
        if let Some(ledger) = crate::analyzer::i_analyzer::innermost_read_ledger() {
            debug_assert!(ledger.keys().iter().any(|key| matches!(key,
                crate::analyzer::ReadKey::Lookup { question: crate::analyzer::LookupQuestion::WorkspaceFact {
                    family: WorkspaceFactFamily::RuntimeRootWriteFootprint,
                    language,
                    subject: FactSubject::File { rel_path },
                }, digest, .. } if *language == file.language()
                    && rel_path.as_ref() == crate::path_utils::rel_path_string(file)
                    && *digest == footprint_digest(WorkspaceRuntimeWriteFootprint::Closed)
            )), "runtime-result hits must record the precise closed-footprint fact");
        }
    }

    fn build_runtime_reads(
        &self,
        procedure: &ProcedureHandle,
        file: &ProjectFile,
        source: &str,
        request: &mut SemanticRequest<'_>,
    ) -> Result<SemanticOutcome<RuntimeKeyedReadResult>, SemanticProviderError> {
        let mut result = RuntimeKeyedReadResult::default();
        let mut work = SemanticWork {
            procedures: 1,
            ..SemanticWork::default()
        };
        request.budget.charge_work(work);
        // The runtime initialization footprint spans the whole workspace, not
        // only the module that spells the read. Every other JavaScript or
        // TypeScript module is inspected for the runtime-root writes that the
        // reviewed `pristine-input-until-write` model names; an unreadable or
        // unparseable sibling keeps the answer incomplete instead of clean.
        let (footprint, footprint_work) = self.workspace_runtime_write_footprint(file, request)?;
        work = work.conservative_add(footprint_work);
        // A footprint that is not closed still reports the read's own typed
        // limitation. The extraction below keeps every candidate so a query
        // anchored on this read sees the boundary instead of an empty answer.
        let footprint_limitation = match footprint {
            WorkspaceRuntimeWriteFootprint::Closed => None,
            WorkspaceRuntimeWriteFootprint::RuntimeRootWrite => {
                Some(RuntimeReadLimitation::MutationIncomplete)
            }
            WorkspaceRuntimeWriteFootprint::CoverageLimited => {
                Some(RuntimeReadLimitation::CoverageLimited)
            }
        };
        let syntax =
            self.runtime_syntax_for_source(procedure.artifact().key().language(), source, request)?;
        work = work.conservative_add(syntax.work());
        let snapshot = match syntax {
            SemanticOutcome::Complete { value, .. } => value,
            SemanticOutcome::Unproven { partial, .. } => {
                if partial.facts.complete {
                    result
                        .limitations
                        .push(RuntimeReadLimitation::BudgetExhausted);
                    return Ok(SemanticOutcome::Unproven {
                        partial: result,
                        work,
                    });
                }
                result
                    .limitations
                    .push(RuntimeReadLimitation::CoverageLimited);
                partial
            }
            SemanticOutcome::ExceededBudget { exceeded, .. } => {
                return Ok(SemanticOutcome::ExceededBudget {
                    partial: None,
                    exceeded,
                    work,
                });
            }
            SemanticOutcome::Cancelled { .. } => {
                return Ok(SemanticOutcome::Cancelled {
                    partial: None,
                    work,
                });
            }
            _ => {
                result
                    .limitations
                    .push(RuntimeReadLimitation::MaterializationIncomplete);
                return Ok(SemanticOutcome::Unproven {
                    partial: result,
                    work,
                });
            }
        };
        if snapshot.has_error {
            result
                .limitations
                .push(RuntimeReadLimitation::CoverageLimited);
        }
        let facts = &snapshot.facts;
        for read in &facts.reads {
            let loads = loads_at_range(procedure, read.range);
            if loads.is_empty() {
                continue;
            }
            if let Err(limitation) = read.key {
                result.limitations.push(limitation);
            }
            result.candidates.push(RuntimeKeyedReadCandidate {
                anchor: read.candidate_anchor,
                global: read.root_name.clone(),
                container: read.container.clone(),
                key: read.key.clone().ok(),
                excluded: read.root == RuntimeSyntaxRoot::Excluded,
            });
            let Ok(key) = read.key.clone() else {
                continue;
            };
            if read.root == RuntimeSyntaxRoot::Excluded {
                continue;
            }
            // Accessor and effect hazards are scoped to the read's own
            // execution context; direct writes stay module-wide in the
            // extractor's mutation evidence. An external call in a sibling
            // function must not poison this read, or a reviewed sink call
            // could never share a module with its source.
            if read.accessor_open {
                result
                    .limitations
                    .push(RuntimeReadLimitation::AccessorOrProxyIncomplete);
                continue;
            }
            if read.root != RuntimeSyntaxRoot::Modeled {
                result
                    .limitations
                    .push(RuntimeReadLimitation::LexicalBindingIndeterminate);
                continue;
            }
            if loads.len() != 1 {
                result
                    .limitations
                    .push(RuntimeReadLimitation::AmbiguousOwner);
                continue;
            }
            if read.mutated {
                result
                    .limitations
                    .push(RuntimeReadLimitation::MutationIncomplete);
                continue;
            }
            // Model selection and effect closure must precede publication. This
            // helper binds only contracts from the captured activation snapshot.
            self.bind_runtime_read_contract(procedure, file, read, key, &loads[0], &mut result)?;
        }
        // Every runtime-shaped read in the closed footprint needs a modeled
        // effect contract. An unmodeled sibling may mutate the selected root.
        if let Some(limitation) = footprint_limitation {
            result.limitations.push(limitation);
        }
        if !result.limitations.is_empty() {
            result.endpoints.clear();
        }
        result.limitations.sort_by_key(|limit| limit.label());
        result.limitations.dedup();
        if request.cancellation.is_cancelled() {
            return Ok(SemanticOutcome::Cancelled {
                partial: Some(result),
                work,
            });
        }
        Ok(if result.limitations.is_empty() {
            SemanticOutcome::Complete {
                value: result,
                work,
            }
        } else {
            SemanticOutcome::Unproven {
                partial: result,
                work,
            }
        })
    }
}

use crate::analyzer::semantic_model::{
    RuntimeAcceptedKeys, RuntimeCoverageStatus, RuntimeExceptionBehavior,
    RuntimeExposureActivation, RuntimeMaterialization, RuntimeMutationModel,
};
impl WorkspaceSemanticOracle<'_> {
    fn bind_runtime_read_contract(
        &self,
        procedure: &ProcedureHandle,
        file: &ProjectFile,
        read: &RuntimeSyntaxRead,
        key: RuntimeAccessKey,
        load: &(ValueAtPoint, MemoryLocationId),
        result: &mut RuntimeKeyedReadResult,
    ) -> Result<(), SemanticProviderError> {
        let Some(active) = self.active_semantic_models() else {
            result
                .limitations
                .push(RuntimeReadLimitation::ActivationMissing);
            return Ok(());
        };
        if active
            .activation_report()
            .explanations
            .iter()
            .any(|explanation| {
                explanation.status
                    == crate::analyzer::semantic_model::SemanticModelActivationStatus::Conflict
            })
        {
            result
                .limitations
                .push(RuntimeReadLimitation::ActivationConflict);
            return Ok(());
        }
        if active.runtime_contracts().next().is_some() {
            // Portable bindings carry producer-owned locator schemes and effect
            // evidence. Until those join this artifact through a supported
            // producer adapter, catalog presence cannot authorize a native load
            // or silently fall back to a potentially conflicting older profile.
            result
                .limitations
                .push(RuntimeReadLimitation::ActivationUnsupported);
            return Ok(());
        }
        let mut matches = Vec::new();
        for (payload, shard) in active.runtime_values() {
            for (exposure_index, exposure) in payload.exposures.iter().enumerate() {
                if exposure.binding_name != read.root_name
                    || !exposure
                        .languages
                        .contains(&shard.matched_evidence.language)
                    || !exposure.members.contains(&read.container)
                {
                    continue;
                }
                // A host must explicitly select the complete execution
                // profile. Catalog availability and the source language do not
                // establish it. An exposure authored as `enabled` is
                // intrinsically eligible within its model; it does not bypass
                // pack activation. The pack-level `safety.review_required`
                // gate remains the explicit user authorization, enforced by
                // the activation resolver before this join ever runs.
                //
                // The evidence must bind exactly the applicability the
                // exposure claims. A build-specific contract is selected only
                // by its own artifact coordinates and digest; a contract the
                // language's standard library guarantees claims no artifact,
                // and evidence naming one would bind something it never said.
                if shard.matched_evidence.configuration.as_deref()
                    != Some(&exposure.runtime_profile_digest)
                    || !evidence_binds_runtime_artifact(&shard.matched_evidence, &exposure.runtime)
                    || exposure.activation != RuntimeExposureActivation::Enabled
                {
                    continue;
                }
                for (behavior_index, behavior) in payload.behaviors.iter().enumerate() {
                    if behavior.exposure_id == exposure.exposure_id
                        && behavior.container_member == read.container
                    {
                        matches.push((
                            std::sync::Arc::clone(&payload),
                            exposure_index,
                            behavior_index,
                            std::sync::Arc::clone(&shard),
                        ));
                    }
                }
            }
        }
        let [(payload, exposure_index, behavior_index, shard)] = matches.as_slice() else {
            result.limitations.push(if matches.is_empty() {
                RuntimeReadLimitation::ActivationMissing
            } else {
                RuntimeReadLimitation::ActivationConflict
            });
            return Ok(());
        };
        let exposure = &payload.exposures[*exposure_index];
        let behavior = &payload.behaviors[*behavior_index];
        let identity = &exposure.root_identity;
        let runtime_identity_matches = identity.scheme == "csmi.runtime-global"
            && identity.scheme_version == "0.1.0"
            && identity.descriptors.len() == 2
            && identity.descriptors.iter().any(|descriptor| {
                descriptor.role == crate::analyzer::semantic_model::RuntimeRootRole::Runtime
                    && descriptor.name == exposure.runtime.runtime_family
            })
            && identity.descriptors.iter().any(|descriptor| {
                descriptor.role == crate::analyzer::semantic_model::RuntimeRootRole::Global
                    && descriptor.name == exposure.binding_name
            });
        if !runtime_identity_matches {
            result
                .limitations
                .push(RuntimeReadLimitation::ActivationUnsupported);
            return Ok(());
        }
        if exposure.coverage.status != RuntimeCoverageStatus::Complete
            || behavior.coverage.status != RuntimeCoverageStatus::Complete
            || !exposure.coverage.limitations.is_empty()
            || !behavior.coverage.limitations.is_empty()
            || active.activation_report().suppressed_explanations != 0
        {
            result
                .limitations
                .push(RuntimeReadLimitation::CoverageLimited);
            return Ok(());
        }
        if !matches!(
            (&key, behavior.accepted_keys),
            (
                RuntimeAccessKey::Property(_),
                RuntimeAcceptedKeys::StaticProperty
            ) | (RuntimeAccessKey::Index(_), RuntimeAcceptedKeys::StaticIndex)
        ) {
            result
                .limitations
                .push(RuntimeReadLimitation::UnsupportedIndex);
            return Ok(());
        }
        // A reviewed behavior that may raise still observes exactly the
        // reviewed input on the normal path: a read that abandons control
        // produces no result at all. What it cannot do is discharge the
        // load's exceptional-control-flow claim, which stays open below.
        if behavior.exception_behavior == RuntimeExceptionBehavior::Unknown {
            result
                .limitations
                .push(RuntimeReadLimitation::ExceptionBehaviorIndeterminate);
            return Ok(());
        }
        if behavior.materialization != RuntimeMaterialization::Eager {
            result
                .limitations
                .push(RuntimeReadLimitation::MaterializationIncomplete);
            return Ok(());
        }
        if !engine_implements_profile(&exposure.runtime) {
            result
                .limitations
                .push(RuntimeReadLimitation::MutationIncomplete);
            return Ok(());
        }
        if behavior.mutation_model != RuntimeMutationModel::PristineInputUntilWrite {
            result
                .limitations
                .push(RuntimeReadLimitation::MutationIncomplete);
            return Ok(());
        }
        let containers = loads_at_range(procedure, read.container_range);
        let [(container, container_location)] = containers.as_slice() else {
            result
                .limitations
                .push(RuntimeReadLimitation::AmbiguousOwner);
            return Ok(());
        };
        let terminal = procedure
            .semantics()
            .memory_location(load.1)
            .expect("validated load location");
        let base = match terminal.kind {
            crate::analyzer::semantic::MemoryLocationKind::Field { base, .. }
            | crate::analyzer::semantic::MemoryLocationKind::Property { base, .. }
            | crate::analyzer::semantic::MemoryLocationKind::Index { base, .. } => base,
            _ => {
                result
                    .limitations
                    .push(RuntimeReadLimitation::AmbiguousOwner);
                return Ok(());
            }
        };
        let key_agrees = match (&terminal.kind, &key) {
            (
                crate::analyzer::semantic::MemoryLocationKind::Property { key: actual, .. },
                RuntimeAccessKey::Property(expected),
            ) => actual == expected,
            (
                crate::analyzer::semantic::MemoryLocationKind::Index {
                    constant_index: Some(actual),
                    ..
                },
                RuntimeAccessKey::Index(expected),
            ) => actual == expected,
            _ => false,
        };
        if !key_agrees {
            result
                .limitations
                .push(RuntimeReadLimitation::AmbiguousOwner);
            return Ok(());
        }
        if base != container.value().id() {
            result
                .limitations
                .push(RuntimeReadLimitation::AmbiguousOwner);
            return Ok(());
        }
        // The load's own result mapping carries the structural identity of the
        // AST-derived seed the query addresses. A dot-member read is its own
        // field access; a subscript read is represented by the base of its
        // access chain, and the lowerer publishes that seed identity on the
        // subscript load. A mapping without one stays a typed materialization
        // boundary instead of being re-derived from the container occurrence.
        let identity_row = procedure
            .semantics()
            .value(load.0.value().id())
            .expect("validated runtime identity observation");
        let identity_mapping = procedure
            .semantics()
            .source_mapping(identity_row.source)
            .expect("validated runtime identity source");
        let Some(structural_identity) = identity_mapping.ast_identity else {
            result
                .limitations
                .push(RuntimeReadLimitation::MaterializationIncomplete);
            return Ok(());
        };
        let mut identity = LengthDelimitedDigest::new(b"bifrost.runtime-read.v1");
        identity.push(procedure.artifact().key().public_fingerprint().as_bytes());
        identity.push(active.active_model_set_hash().as_bytes());
        identity.push(exposure.runtime_profile_digest.as_bytes());
        identity.push(shard.manifest.content_sha256.as_bytes());
        procedure
            .semantics()
            .locator()
            .push_stable_identity(&mut identity);
        identity.push(exposure.exposure_id.as_bytes());
        identity.push(behavior.behavior_id.as_bytes());
        identity.push(&(read.range.start_byte as u64).to_le_bytes());
        identity.push(&(read.range.end_byte as u64).to_le_bytes());
        let nonthrowing = behavior.exception_behavior == RuntimeExceptionBehavior::Nonthrowing;
        let discharged_gaps = procedure
            .semantics()
            .gaps()
            .iter()
            .filter(|gap| {
                gap_belongs_to_load(gap, &load.0, load.1, nonthrowing)
                    || gap_belongs_to_load(gap, container, *container_location, nonthrowing)
            })
            .map(|gap| gap.id)
            .collect::<Vec<_>>();
        let refinement_identity = identity.finish();
        let mut object_identity = LengthDelimitedDigest::new(b"bifrost.runtime-object.v1");
        object_identity.push(procedure.artifact().key().public_fingerprint().as_bytes());
        object_identity.push(active.active_model_set_hash().as_bytes());
        object_identity.push(exposure.runtime_profile_digest.as_bytes());
        object_identity.push(exposure.exposure_id.as_bytes());
        object_identity.push(read.container.as_bytes());
        object_identity.push(exposure.runtime.initialization_boundary.as_bytes());
        let activation = crate::analyzer::semantic::RuntimeObjectActivation::captured(
            active.active_model_set_hash().to_owned(),
            exposure.runtime_profile_digest.clone(),
            shard.manifest.content_sha256.clone(),
            shard.descriptor.shard_id.as_str().to_owned(),
            exposure.exposure_id.clone(),
            behavior.behavior_id.clone(),
            shard.source_id.clone(),
        )
        .expect("validated runtime activation retains nonempty ownership");
        let runtime_object = crate::analyzer::semantic::RuntimeObjectRoot::captured_single_realm(
            exposure.runtime_profile_digest.clone(),
            exposure.runtime.realm.clone(),
            exposure.exposure_id.clone(),
            read.container.clone(),
            exposure.runtime.initialization_boundary.clone(),
            object_identity.finish(),
            activation,
        )
        .expect("unique main realm runtime proof agrees with captured activation");
        result.endpoints.push(RuntimeKeyedReadEndpoint {
            file: file.clone(),
            expression: read.range,
            candidate_anchor: read.candidate_anchor,
            structural_identity,
            runtime: exposure.runtime.runtime_family.clone(),
            global: read.root_name.clone(),
            container: read.container.clone(),
            key,
            observation: load.0.clone(),
            proof: ProofStatus::Proven,
            completeness: EvidenceCompleteness::Complete,
            active_model_set_hash: active.active_model_set_hash().to_owned(),
            refinement_identity,
            exposure_id: exposure.exposure_id.clone(),
            behavior_id: behavior.behavior_id.clone(),
            manifest_digest: shard.manifest.content_sha256.clone(),
            shard_id: shard.descriptor.shard_id.as_str().to_owned(),
            activation_source: shard.source_id.clone(),
            producer: format!(
                "{}@{}",
                shard.manifest.producer.name, shard.manifest.producer.version
            ),
            runtime_profile_digest: exposure.runtime_profile_digest.clone(),
            source_origin: RuntimeReadSourceOrigin::PristineRuntimeInput,
            location: load.1,
            container_observation: container.clone(),
            container_location: *container_location,
            runtime_object,
            discharged_gaps: discharged_gaps.into(),
        });
        Ok(())
    }
}

impl WorkspaceSemanticOracle<'_> {
    /// Reacquire the activation-bound proof before consuming a retained endpoint.
    /// The ordinary full-expression source projection remains the only heap path.
    pub fn pointees_for_keyed_read(
        &self,
        endpoint: &RuntimeKeyedReadEndpoint,
        request: &mut SemanticRequest<'_>,
    ) -> Result<
        SemanticOutcome<crate::analyzer::semantic::workspace_oracle::SourcePointsToResult>,
        SemanticProviderError,
    > {
        let filter = RuntimeKeyedReadFilter {
            runtime: endpoint.runtime.clone(),
            global: endpoint.global.clone(),
            container: endpoint.container.clone(),
            property: match &endpoint.key {
                RuntimeAccessKey::Property(key) => Some(key.clone()),
                _ => None,
            },
            index: match endpoint.key {
                RuntimeAccessKey::Index(index) => Some(index),
                _ => None,
            },
            pristine_input: true,
            ..RuntimeKeyedReadFilter::default()
        };
        let rebound = self.runtime_keyed_read_at_source(
            &endpoint.file,
            endpoint.expression,
            &filter,
            request,
        )?;
        match &rebound {
            SemanticOutcome::Cancelled { work, .. } => {
                return Ok(SemanticOutcome::Cancelled {
                    partial: None,
                    work: *work,
                });
            }
            SemanticOutcome::ExceededBudget { exceeded, work, .. } => {
                return Ok(SemanticOutcome::ExceededBudget {
                    partial: None,
                    exceeded: *exceeded,
                    work: *work,
                });
            }
            _ => {}
        }
        let valid = matches!(rebound, SemanticOutcome::Complete { .. })
            && rebound.available_value().is_some_and(|reads| {
                reads.endpoints.iter().any(|current| {
                    current.refinement_identity == endpoint.refinement_identity
                        && current.observation == endpoint.observation
                        && current.location == endpoint.location
                        && current.structural_identity == endpoint.structural_identity
                        && current.container_observation == endpoint.container_observation
                        && current.container_location == endpoint.container_location
                        && current.runtime_object == endpoint.runtime_object
                })
            });
        if !valid {
            return Ok(SemanticOutcome::Unknown {
                partial: None,
                work: rebound.work(),
            });
        }
        let mut outcome = self.pointees_at_source(&endpoint.file, endpoint.expression, request)?;
        let work = match &mut outcome {
            SemanticOutcome::Complete { work, .. }
            | SemanticOutcome::Unproven { work, .. }
            | SemanticOutcome::Unknown { work, .. }
            | SemanticOutcome::Ambiguous { work, .. }
            | SemanticOutcome::Unsupported { work, .. }
            | SemanticOutcome::Cancelled { work, .. }
            | SemanticOutcome::ExceededBudget { work, .. } => work,
        };
        *work = work.conservative_add(rebound.work());
        Ok(outcome)
    }
}

#[cfg(test)]
mod syntax_memo_input_tests {
    use super::*;
    use crate::CancellationToken;
    use crate::analyzer::semantic::SemanticBudget;
    use crate::analyzer::{Language, WorkspaceAnalyzer, capture_query_reads};

    #[test]
    fn runtime_syntax_hits_use_the_exact_source_and_dialect() {
        let workspace = WorkspaceAnalyzer::Multi(Box::default());
        let oracle = WorkspaceSemanticOracle::new(&workspace);
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let mut request = SemanticRequest::new(&mut budget, &cancellation);
        let dialect =
            LanguageDialect::for_path(Language::JavaScript, std::path::Path::new("memo.js"));
        let mut read = |source: &str| {
            let (outcome, reads) = capture_query_reads(workspace.analyzer(), || {
                oracle
                    .runtime_syntax_for_source(dialect, source, &mut request)
                    .unwrap()
            });
            (outcome.available_value().unwrap().clone(), reads)
        };
        let (first, first_reads) = read("const value = 1;\n");
        let (hit, hit_reads) = read("const value = 1;\n");
        assert!(Arc::ptr_eq(&first, &hit));
        assert_eq!(first_reads.keys(), hit_reads.keys());
        let (changed, _) = read("process.env.PATH = 'replacement';\n");
        assert!(!Arc::ptr_eq(&first, &changed));
        assert!(!changed.facts.writes.is_empty());
        let typescript =
            LanguageDialect::for_path(Language::TypeScript, std::path::Path::new("memo.ts"));
        let other_dialect = oracle
            .runtime_syntax_for_source(typescript, "const value = 1;\n", &mut request)
            .unwrap();
        assert!(!Arc::ptr_eq(
            &first,
            other_dialect.available_value().unwrap()
        ));
    }
}

#[cfg(test)]
mod runtime_root_write_footprint {
    use super::*;
    use crate::analyzer::read_verification::workspace_fact_test_support::{
        source_workspace, verdict_without_field_slots,
    };
    use crate::analyzer::semantic::SemanticBudget;
    use crate::analyzer::{Language, WorkspaceAnalyzer, capture_query_reads};
    use crate::inline_project::InlineTestProject;

    fn capture(
        workspace: &WorkspaceAnalyzer,
        file: &ProjectFile,
    ) -> (
        WorkspaceRuntimeWriteFootprint,
        Arc<crate::analyzer::ReadLedger>,
    ) {
        let oracle = WorkspaceSemanticOracle::new(workspace);
        let mut budget = SemanticBudget::default();
        let cancel = crate::CancellationToken::default();
        let (answer, reads) = capture_query_reads(workspace.analyzer(), || {
            oracle
                .workspace_runtime_write_footprint(
                    file,
                    &mut SemanticRequest::new(&mut budget, &cancel),
                )
                .unwrap()
                .0
        });
        assert_eq!(reads.unattributed_reads(), 0);
        assert_eq!(
            reads.keys().len(),
            1,
            "the precise fact subsumes scanned implementation inputs"
        );
        (answer, reads)
    }

    #[test]
    fn unimported_runtime_write_rejects_without_field_slot_keys() {
        let project = InlineTestProject::with_language(Language::JavaScript)
            .file("app.js", "function read() { return process.env.PATH; }\n")
            .file("unimported.js", "const marker = 0;\n")
            .build();
        let base = source_workspace(&project);
        let (before, reads) = capture(&base, &project.file("app.js"));
        assert_eq!(before, WorkspaceRuntimeWriteFootprint::Closed);
        assert!(verdict_without_field_slots(&base, &base, &reads.keys()).is_unchanged());
        project
            .file("unimported.js")
            .write("process.env.PATH = 'replacement';\n")
            .unwrap();
        let head = source_workspace(&project);
        let (after, _) = capture(&head, &project.file("app.js"));
        assert_eq!(after, WorkspaceRuntimeWriteFootprint::RuntimeRootWrite);
        let verdict = verdict_without_field_slots(&base, &head, &reads.keys());
        assert!(verdict.changed().is_some(), "{verdict:?}");
    }

    #[test]
    fn repeated_footprint_and_result_hits_record_equal_facts() {
        let project = InlineTestProject::with_language(Language::Python)
            .file("app.py", "def read():\n    return 1\n")
            .file("unimported.py", "marker = 0\n")
            .build();
        let workspace = source_workspace(&project);
        let file = project.file("app.py");
        let oracle = WorkspaceSemanticOracle::new(&workspace);
        let mut budget = SemanticBudget::default();
        let cancel = crate::CancellationToken::default();
        let mut request = SemanticRequest::new(&mut budget, &cancel);
        let (_, first) = capture_query_reads(workspace.analyzer(), || {
            oracle
                .workspace_runtime_write_footprint(&file, &mut request)
                .unwrap()
        });
        let (_, hit) = capture_query_reads(workspace.analyzer(), || {
            oracle
                .workspace_runtime_write_footprint(&file, &mut request)
                .unwrap()
        });
        let (_, result_hit) = capture_query_reads(workspace.analyzer(), || {
            oracle.record_closed_runtime_footprint(&file)
        });
        assert_eq!(first.keys().len(), 1);
        assert_eq!(first.keys(), hit.keys());
        assert_eq!(first.keys(), result_hit.keys());
        assert_eq!(first.digest(), hit.digest());
        assert_eq!(hit.unattributed_reads(), 0);
    }

    #[test]
    fn comment_before_runtime_write_preserves_footprint_digest() {
        let project = InlineTestProject::with_language(Language::JavaScript)
            .file("app.js", "function read() { return process.env.PATH; }\n")
            .file("unimported.js", "process.env.PATH = 'replacement';\n")
            .build();
        let base = source_workspace(&project);
        let (before, reads) = capture(&base, &project.file("app.js"));
        assert_eq!(before, WorkspaceRuntimeWriteFootprint::RuntimeRootWrite);
        project
            .file("unimported.js")
            .write("// comment above the first runtime write\nprocess.env.PATH = 'replacement';\n")
            .unwrap();
        let head = source_workspace(&project);
        let (after, changed_reads) = capture(&head, &project.file("app.js"));
        assert_eq!(before, after);
        assert_eq!(reads.digest(), changed_reads.digest());
        assert!(verdict_without_field_slots(&base, &head, &reads.keys()).is_unchanged());
    }
}
