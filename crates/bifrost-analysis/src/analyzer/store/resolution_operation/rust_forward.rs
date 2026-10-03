//! Demand-driven Rust forward queries sharing one selected context and fact session.

use super::*;
use crate::analyzer::resolution::{FactResolutionOperation, ResolutionCompletionAccumulator};

/// Values returned by this callback are provisional. The enclosing selected
/// operation performs the final authority check before publishing them.
pub(crate) trait SelectedRustForwardQueries {
    /// Certify the producer's reference inventory for one admitted source
    /// fragment, including a fragment with no reference rows. This does not
    /// certify typing or invocation applicability of individual references.
    fn reference_inventory_completion(
        &mut self,
        fragment: BindingFragmentId,
    ) -> Result<ResolutionCompletion>;

    /// Resolve one structured locator using the shared fact session.
    ///
    /// The caller owns the metrics sink and must pass a fresh default value for
    /// every locator. A populated sink is rejected before any fact work starts.
    fn resolve_reference(
        &mut self,
        locator: &SelectedSemanticLocator,
        point_metrics: &mut ResolutionBatchMetrics,
    ) -> Result<
        SelectedResolutionOperationOutcome<SelectedResolutionLocated<SelectedRustReferenceAnswer>>,
    >;
}

struct RustForwardQueries<'query, 'facts, 'store, 'input> {
    selected: &'query SelectedResolutionOperation<'store, 'input>,
    persisted_lexical: &'query SelectedResolutionLexicalSource<'query, 'store>,
    facts: &'query mut FactResolutionOperation<'facts>,
    cancellation: &'query CancellationToken,
    session: &'query ResolutionSession,
    state: RustForwardQueryState,
}

#[derive(Default)]
struct RustForwardQueryState {
    completion: ResolutionCompletionAccumulator,
    stopped: bool,
    unavailable: Option<SelectedResolutionUnavailable>,
}

impl RustForwardQueryState {
    fn cancelled(&mut self) -> ResolutionCompletion {
        self.stopped = true;
        let completion = cancelled_completion();
        self.completion.include(&completion);
        completion
    }

    fn unavailable(&mut self, reason: SelectedResolutionUnavailable) {
        if self.unavailable.is_none() {
            self.unavailable = Some(reason);
        }
    }
}

impl SelectedRustForwardQueries for RustForwardQueries<'_, '_, '_, '_> {
    fn reference_inventory_completion(
        &mut self,
        fragment: BindingFragmentId,
    ) -> Result<ResolutionCompletion> {
        if self.state.stopped
            || self.cancellation.is_cancelled()
            || !self.session.observe_cancellation()
        {
            return Ok(self.state.cancelled());
        }
        let completion = self.persisted_lexical.reference_inventory_completion(
            fragment,
            self.cancellation,
            self.session,
        )?;
        let completion = match self
            .persisted_lexical
            .close_completion(&completion, self.cancellation)?
        {
            Some(completion) => completion,
            None => completion.combine(&self.state.cancelled()),
        };
        self.state.completion.include(&completion);
        if completion.contains_reason(ResolutionIncompleteReason::Cancelled)
            || self.cancellation.is_cancelled()
            || !self.session.observe_cancellation()
        {
            self.state.stopped = true;
            return Ok(completion.combine(&self.state.cancelled()));
        }
        Ok(completion)
    }

    fn resolve_reference(
        &mut self,
        locator: &SelectedSemanticLocator,
        point_metrics: &mut ResolutionBatchMetrics,
    ) -> Result<
        SelectedResolutionOperationOutcome<SelectedResolutionLocated<SelectedRustReferenceAnswer>>,
    > {
        if self.state.stopped
            || self.cancellation.is_cancelled()
            || !self.session.observe_cancellation()
        {
            return Ok(self.cancelled());
        }
        if let Some(reason) = &self.state.unavailable {
            return Ok(SelectedResolutionOperationOutcome::Unavailable(
                reason.clone(),
            ));
        }
        assert_eq!(
            point_metrics,
            &ResolutionBatchMetrics::default(),
            "selected Rust forward point metrics must be fresh and default-valued"
        );
        let reference = match self.selected.ready.lookup_locator_in_session(
            self.persisted_lexical,
            locator,
            self.cancellation,
            self.session,
        )? {
            LocatedSemantic::Found(reference) => reference,
            LocatedSemantic::Missing => {
                return Ok(SelectedResolutionOperationOutcome::Native(
                    SelectedResolutionLocated::Missing,
                ));
            }
            LocatedSemantic::Cancelled => return Ok(self.cancelled()),
        };
        let resolution = self
            .facts
            .resolve_reference_with_metrics(reference, point_metrics)?;
        self.state.completion.include(resolution.completion());
        if self.cancellation.is_cancelled() || !self.session.observe_cancellation() {
            return Ok(self.cancelled());
        }
        let targets = resolution.binding().targets();
        if !(0..targets.len()).all(|_| self.session.scope_step()) {
            return Ok(self.cancelled());
        }
        let targets = targets.to_vec();
        let SelectedRustDefinitionVocabularies {
            units: definitions,
            lexical: lexical_definitions,
            names: definition_names,
        } = match project_rust_source_definitions(
            &self.selected.ready,
            self.selected.mount_table(),
            &targets,
            self.cancellation,
            self.session,
        )? {
            SelectedRustSourceDefinitionProjection::Complete(rows) => {
                match split_projected_rust_definitions(rows) {
                    Some(vocabularies) => vocabularies,
                    None => {
                        let reason = SelectedResolutionUnavailable::MissingDefinitionUnit {
                            storage_language: locator.storage_language().to_owned(),
                            persisted_relative_path: locator.relative_path().to_owned(),
                        };
                        self.state.unavailable(reason.clone());
                        return Ok(SelectedResolutionOperationOutcome::Unavailable(reason));
                    }
                }
            }
            SelectedRustSourceDefinitionProjection::Unavailable => {
                let reason = SelectedResolutionUnavailable::MissingDefinitionUnit {
                    storage_language: locator.storage_language().to_owned(),
                    persisted_relative_path: locator.relative_path().to_owned(),
                };
                self.state.unavailable(reason.clone());
                return Ok(SelectedResolutionOperationOutcome::Unavailable(reason));
            }
            SelectedRustSourceDefinitionProjection::Cancelled => {
                return Ok(self.cancelled());
            }
        };
        if self.cancellation.is_cancelled() || !self.session.observe_cancellation() {
            return Ok(self.cancelled());
        }
        Ok(SelectedResolutionOperationOutcome::Native(
            SelectedResolutionLocated::Found(SelectedRustReferenceAnswer {
                macro_expansion_gaps: Vec::new(),
                enumeration: None,
                inventory_details: Vec::new(),
                named_reasons: super::named_reason_details(
                    &self.selected.ready,
                    resolution.binding().completion(),
                )?,
                boundary_import_names: Vec::new(),
                resolution,
                definitions,
                lexical_definitions,
                definition_names,
                // The reverse-side forward query answers a located reference,
                // not a presentation route, and never reaches the member
                // attribution consumer.
                member_attributions: Vec::new(),
                projection: (),
            }),
        ))
    }
}

impl RustForwardQueries<'_, '_, '_, '_> {
    fn cancelled(
        &mut self,
    ) -> SelectedResolutionOperationOutcome<SelectedResolutionLocated<SelectedRustReferenceAnswer>>
    {
        SelectedResolutionOperationOutcome::Cancelled(self.state.cancelled())
    }
}

impl SelectedResolutionOperation<'_, '_> {
    /// Execute several Rust forward queries through one selected context and
    /// one operation-local fact session. Callback values remain provisional
    /// until selected inventory and overlay authority are revalidated.
    ///
    /// `crate_keys` are the crates that compile `files`, which the caller read
    /// when it built `context`. They bound the mounts this request may bind
    /// into.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn with_rust_forward_queries_in_session<T>(
        mut self,
        context: SelectedResolutionContextSet,
        crate_keys: &[[u8; 32]],
        files: &[&Path],
        cancellation: &CancellationToken,
        context_metrics: &mut SelectedResolutionContextMetrics,
        session: &ResolutionSession,
        run: impl FnOnce(&mut dyn SelectedRustForwardQueries) -> Result<T>,
    ) -> Result<SelectedResolutionOperationOutcome<T>> {
        let operation_cancellation = session.cancellation().unwrap_or(cancellation);
        if operation_cancellation.is_cancelled() || !session.observe_cancellation() {
            return Ok(SelectedResolutionOperationOutcome::Cancelled(
                cancelled_completion(),
            ));
        }
        if !self.ensure_selected_rust_inputs_in_session(operation_cancellation, session)? {
            return Ok(SelectedResolutionOperationOutcome::Cancelled(
                cancelled_completion(),
            ));
        }
        match self.prepare_selected_macro_frontiers_for_files(files, operation_cancellation)? {
            SelectedResolutionStageOutcome::Ready => {}
            SelectedResolutionStageOutcome::Cancelled => {
                return Ok(SelectedResolutionOperationOutcome::Cancelled(
                    cancelled_completion(),
                ));
            }
            SelectedResolutionStageOutcome::Stale(reason) => {
                return Ok(SelectedResolutionOperationOutcome::Stale(reason));
            }
            SelectedResolutionStageOutcome::Unavailable(reason) => {
                return Ok(SelectedResolutionOperationOutcome::Unavailable(reason));
            }
        }
        let context = match self.prepare_context_in_session(
            context,
            operation_cancellation,
            context_metrics,
            session,
        )? {
            SelectedResolutionContextValidationOutcome::Ready(context) => context,
            SelectedResolutionContextValidationOutcome::Cancelled => {
                return Ok(SelectedResolutionOperationOutcome::Cancelled(
                    cancelled_completion(),
                ));
            }
        };
        // The crates that compile the request's own files bound the mounts it
        // may bind into, exactly as the graph route's staged crate does: a
        // reference written in one of these files resolves inside its crate's
        // dependency closure or nowhere, and a gap in a blob outside that
        // closure was never about this request. A file compiled into more than
        // one Cargo target contributes each of its crates, so its scope is the
        // union over them, which is what the caller's context build returned.
        // The narrowing starts here, where the graph stage starts it: after the
        // context has been validated and before the blueprint is collected, so
        // every read the request's own resolution makes is inside it, including
        // the candidate gap boxes the lexical source memoizes per direction.
        let (value, completion, unavailable, stopped) = {
            let _scope = self
                .ready
                .narrow_forward_scope_to_crates(crate_keys, operation_cancellation)?;
            let blueprint = match self.ready.collect_blueprint_in_session(
                context,
                operation_cancellation,
                session,
            )? {
                SelectedFactOperationBlueprintConstruction::Ready(blueprint) => blueprint,
                SelectedFactOperationBlueprintConstruction::Cancelled {
                    cancellation_completion,
                    contextual_reverse_inventory_completion,
                } => {
                    return Ok(SelectedResolutionOperationOutcome::Cancelled(
                        cancellation_completion.combine(&contextual_reverse_inventory_completion),
                    ));
                }
            };
            if matches!(
                self.ready.register_context_in_session(
                    &blueprint,
                    operation_cancellation,
                    session
                )?,
                ContextRegistrationOutcome::Cancelled
            ) {
                return Ok(SelectedResolutionOperationOutcome::Cancelled(
                    cancelled_completion(),
                ));
            }
            let persisted_lexical = self.ready.lexical_source();
            let persisted_typed = self.ready.typed_source();
            let observed_lexical = SeamProfiled::observing(&persisted_lexical);
            let observed_typed = SeamProfiled::observing(&persisted_typed);
            self.ready.with_workspace_forward_fact_operation(
                &blueprint,
                &observed_lexical,
                &observed_typed,
                operation_cancellation,
                session,
                |facts| {
                    let mut queries = RustForwardQueries {
                        selected: &self,
                        persisted_lexical: &persisted_lexical,
                        facts,
                        cancellation: operation_cancellation,
                        session,
                        state: RustForwardQueryState::default(),
                    };
                    let value = run(&mut queries)?;
                    Ok((
                        value,
                        queries.state.completion.finish(),
                        queries.state.unavailable,
                        queries.state.stopped,
                    ))
                },
            )?
        };
        if stopped || operation_cancellation.is_cancelled() || !session.observe_cancellation() {
            return Ok(SelectedResolutionOperationOutcome::Cancelled(
                completion.combine(&cancelled_completion()),
            ));
        }
        if let Some(reason) = unavailable {
            return Ok(SelectedResolutionOperationOutcome::Unavailable(reason));
        }
        // Stamping the final authority is one step. It used to charge one per
        // selected mount plus one, which read the mount count without doing
        // any work proportional to it: `finish` revalidates the selection
        // through its own indexed reads, and nothing here walks the mounts.
        if !session.scope_step() {
            return Ok(SelectedResolutionOperationOutcome::Cancelled(
                completion.combine(&cancelled_completion()),
            ));
        }
        self.ready
            .finish(value, &completion, operation_cancellation)
    }
}
