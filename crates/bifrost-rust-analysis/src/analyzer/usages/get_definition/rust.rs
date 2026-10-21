use brokk_bifrost_analysis::analyzer::QueryScope;
use brokk_bifrost_analysis::analyzer::common::language_for_file;
use brokk_bifrost_analysis::analyzer::usages::reference_site::ResolvedReferenceSite;
use brokk_bifrost_analysis::analyzer::{
    AnalyzerQueryScope, CodeUnit, IAnalyzer, Language, ProjectFile, QueryToken,
};
use brokk_bifrost_analysis::hash::HashMap;
use brokk_bifrost_analysis::{CancellationToken, NavigationOperation, profiling};
use brokk_bifrost_core::analyzer::usages::resolution_session::{
    BoundedResolution, ResolutionSession,
};
use std::sync::Arc;
use tree_sitter::Tree;

use brokk_bifrost_analysis::analyzer::usages::get_definition::*;

#[derive(Default)]
pub(crate) struct RustDefinitionState {
    rust_receiver_type_facts:
        HashMap<ProjectFile, Arc<crate::analyzer::rust::RustReceiverTypeFacts>>,
}

impl RustDefinitionState {
    pub(crate) fn rust_receiver_type_facts(
        &mut self,
        file: &ProjectFile,
        source: &str,
        tree: &Tree,
    ) -> Arc<crate::analyzer::rust::RustReceiverTypeFacts> {
        self.rust_receiver_type_facts
            .entry(file.clone())
            .or_insert_with(|| {
                Arc::new(crate::analyzer::rust::RustReceiverTypeFacts::from_tree(
                    source, tree,
                ))
            })
            .clone()
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn resolve_definition_dispatch<'a: 'selection, 'factory, 'selection, 'borrow>(
    analyzer: &'a dyn brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer,
    _token: brokk_bifrost_core::analyzer::query_token::QueryToken<'_>,
    context: &mut brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionBatchContext<
        'a,
        '_,
    >,
    request: &brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupRequest,
    source: &std::sync::Arc<str>,
    tree: &Option<tree_sitter::Tree>,
    site: &brokk_bifrost_core::analyzer::usages::reference_site::ResolvedReferenceSite,
    _operation: Option<brokk_bifrost_analysis::navigation::NavigationOperation>,
    cancellation: Option<&brokk_bifrost_core::cancellation::CancellationToken>,
    _go_session: Option<
        &brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession,
    >,
    mut rust_definition_batch: Option<
        &mut RustDefinitionBatchOperation<'a, 'factory, 'selection, 'borrow>,
    >,
) -> std::ops::ControlFlow<
    brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionResolution,
    brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionResolution,
> {
    let mut evidence = CallEvidence::default();
    let outcome = {
        let query = brokk_bifrost_analysis::analyzer::languages::BoundedReceiverQuery {
            analyzer,
            file: &request.file,
            source,
            tree: tree.as_ref(),
            site,
            // The budget written for an interactive lookup, which the
            // type route already uses (`resolve_type_batch`, Ruby's
            // type flow). The default's 64 expansions were exceeded by a
            // second field hop through a declared type (issue 693).
            budget: brokk_bifrost_core::analyzer::usages::receiver_analysis::INTERACTIVE_TYPE_LOOKUP_BUDGET,
            cancellation,
        };
        let rust_resolution = match rust_definition_batch.as_mut() {
            Some(batch) => batch.resolve(query),
            None => crate::analyzer::rust::native_points::resolve_rust_definition_bounded(query),
        };
        let rust_outcome = match rust_resolution {
            BoundedResolution::Complete { value, .. } => hold_rust_answer_to_its_proof(value),
            BoundedResolution::Exceeded { limit, .. } => exceeded_budget(
                limit,
                format!(
                    "Rust definition resolution exceeded its {} budget",
                    limit.as_str()
                ),
            ),
            BoundedResolution::Cancelled { .. } => {
                cancelled("Rust definition resolution was cancelled")
            }
        };
        let mut outcome = rust_outcome;
        let rust_receiver_call = tree.as_ref().is_some_and(|tree| {
            crate::analyzer::rust::external_calls::call_path_for_site(tree, site)
                .is_some_and(|callee| callee.kind() == "field_expression")
        });
        // The member in `lock.lock()` is not a lexical reference to its
        // receiver parameter, even though the two identifiers match.
        let has_no_workspace_target = outcome.definitions.is_empty()
            && (rust_receiver_call || outcome.lexical_definition.is_none());
        let has_external_call_shape = tree.as_ref().is_some_and(|tree| {
            crate::analyzer::rust::external_calls::call_path_for_site(tree, site).is_some_and(
                |callee| {
                    matches!(
                        callee.kind(),
                        "field_expression" | "scoped_identifier" | "generic_function"
                    )
                },
            )
        });
        let should_try_model_receiver_fallback = has_no_workspace_target
            && matches!(
                outcome.status,
                DefinitionLookupStatus::NoDefinition
                    | DefinitionLookupStatus::UnresolvableImportBoundary
                    | DefinitionLookupStatus::Incomplete
            )
            && has_external_call_shape;
        let should_try_exact_rust_external_call =
            (rust_receiver_call && has_no_workspace_target) || should_try_model_receiver_fallback;
        let exact = if should_try_exact_rust_external_call {
            tree.as_ref().and_then(|tree| {
                let token = context.token;
                let (operation_factory, selected_operation) = rust_definition_batch
                    .as_mut()
                    .map_or((None, None), |batch| batch.resolver_parts());
                crate::analyzer::rust::external_calls::resolve_exact_rust_external_call_with_operation(
                        analyzer,
                        token,
                        &request.file,
                        source.as_ref(),
                        tree,
                        site,
                        || {
                            if !should_try_model_receiver_fallback {
                                return None;
                            }
                            let callee = crate::analyzer::rust::external_calls::call_path_for_site(
                                tree, site,
                            )?;
                            (callee.kind() == "field_expression").then(|| {
                                context.language_state::<RustDefinitionState>().rust_receiver_type_facts(&request.file, source, tree)
                            })
                        },
                        cancellation,
                        operation_factory,
                        selected_operation,
                    )
            })
        } else {
            None
        };
        if let Some((proof, identity)) = exact {
            outcome = boundary_unchecked(
                format!(
                    "`{}` is a resolver-proven external Rust callable",
                    proof.canonical_callee()
                ),
                UnindexedClaim::external_boundary(identity.owner_fqn(), ClaimSubjectRole::Any),
            );
            let mut reference = outcome.reference.take().unwrap_or_else(|| site.clone());
            reference.text = proof.canonical_callee().to_owned();
            outcome.reference = Some(reference);
            evidence.call_application = proof.call_application();
            evidence.dispatch_extensibility = proof.dispatch_extensibility();
            evidence.exact_external_call = Some(proof);
            evidence.external_callee_identity = Some(identity);
        }
        outcome
    };
    std::ops::ControlFlow::Continue(DefinitionResolution { outcome, evidence })
}

enum RustBatchFactory<'a, 'factory> {
    Owned(crate::analyzer::rust::native_points::RustDefinitionOperationFactory<'a>),
    Borrowed(&'factory crate::analyzer::rust::native_points::RustDefinitionOperationFactory<'a>),
}
impl<'a> std::ops::Deref for RustBatchFactory<'a, '_> {
    type Target = crate::analyzer::rust::native_points::RustDefinitionOperationFactory<'a>;
    fn deref(&self) -> &Self::Target {
        match self {
            Self::Owned(factory) => factory,
            Self::Borrowed(factory) => factory,
        }
    }
}

pub(crate) fn definition_batch_resolver<'a>(
    analyzer: &'a dyn IAnalyzer,
    cancellation: Option<&CancellationToken>,
) -> Option<Box<dyn DefinitionBatchResolver<'a> + 'a>> {
    let cancellation = cancellation.cloned().unwrap_or_default();
    let factory = crate::analyzer::rust::native_points::RustDefinitionOperationFactory::new(
        analyzer,
        &cancellation,
    )?;
    Some(Box::new(RustDefinitionBatchOperation {
        factory: RustBatchFactory::Owned(factory),
        operation: None,
        borrowed_operation: None,
        reuse_disabled: false,
        precomputed: Vec::new(),
        precomputed_index: 0,
    }))
}

impl<'a: 'selection, 'factory, 'selection, 'borrow> DefinitionBatchResolver<'a>
    for RustDefinitionBatchOperation<'a, 'factory, 'selection, 'borrow>
{
    fn precompute(
        &mut self,
        analyzer: &dyn IAnalyzer,
        context: &mut DefinitionBatchContext<'_, '_>,
        requests: &[DefinitionLookupRequest],
        cancellation: Option<&CancellationToken>,
    ) {
        precompute_rust_call_target_batch(analyzer, context, requests, cancellation, self);
    }
    fn resolve_definition_dispatch(
        &mut self,
        analyzer: &'a dyn IAnalyzer,
        token: QueryToken<'_>,
        context: &mut DefinitionBatchContext<'a, '_>,
        request: &DefinitionLookupRequest,
        source: &Arc<str>,
        tree: &Option<Tree>,
        site: &ResolvedReferenceSite,
        operation: Option<NavigationOperation>,
        cancellation: Option<&CancellationToken>,
        go_session: Option<&ResolutionSession>,
    ) -> std::ops::ControlFlow<DefinitionResolution, DefinitionResolution> {
        resolve_definition_dispatch(
            analyzer,
            token,
            context,
            request,
            source,
            tree,
            site,
            operation,
            cancellation,
            go_session,
            Some(self),
        )
    }
}

pub(crate) struct RustDefinitionBatchOperation<'analyzer, 'factory, 'selection, 'borrow> {
    factory: RustBatchFactory<'analyzer, 'factory>,
    operation: Option<
        brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperation<
            'analyzer,
            'selection,
        >,
    >,
    borrowed_operation: Option<
        &'borrow mut brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperation<
            'analyzer,
            'selection,
        >,
    >,
    reuse_disabled: bool,
    precomputed: Vec<Option<BoundedResolution<DefinitionLookupOutcome>>>,
    precomputed_index: usize,
}

impl<'analyzer: 'selection, 'factory, 'selection, 'borrow>
    RustDefinitionBatchOperation<'analyzer, 'factory, 'selection, 'borrow>
{
    fn resolver_parts<'operation>(
        &'operation mut self,
    ) -> (
        Option<&'operation crate::analyzer::rust::native_points::RustDefinitionOperationFactory<'analyzer>>,
        Option<&'operation mut brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperation<'analyzer, 'selection>>,
    ){
        if self.reuse_disabled {
            (None, None)
        } else {
            (
                Some(&self.factory),
                self.borrowed_operation
                    .as_deref_mut()
                    .or(self.operation.as_mut()),
            )
        }
    }

    fn precompute(
        &mut self,
        queries: Vec<brokk_bifrost_analysis::analyzer::languages::BoundedReceiverQuery<'_>>,
        request_indices: &[usize],
        request_count: usize,
        cancellation: &CancellationToken,
    ) {
        if queries.is_empty() {
            return;
        }
        assert_eq!(queries.len(), request_indices.len());
        self.precomputed = std::iter::repeat_with(|| None)
            .take(request_count)
            .collect();
        if self.reuse_disabled {
            return;
        }
        if self.operation.is_none() && self.borrowed_operation.is_none() {
            match self.factory.open(cancellation) {
                Ok(
                    brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperationOpenOutcome::Ready(
                        operation,
                    ),
                ) => self.operation = Some(*operation),
                outcome => {
                    self.reuse_disabled = true;
                    let failure = match outcome {
                        Ok(brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperationOpenOutcome::Unavailable(reason)) => {
                            crate::analyzer::rust::native_points::RustDefinitionOperationOpenFailure::Unavailable(format!("{reason:?}"))
                        }
                        Ok(brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperationOpenOutcome::Stale(reason)) => {
                            crate::analyzer::rust::native_points::RustDefinitionOperationOpenFailure::Stale(format!("{reason:?}"))
                        }
                        Ok(brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperationOpenOutcome::Cancelled) => {
                            crate::analyzer::rust::native_points::RustDefinitionOperationOpenFailure::Cancelled
                        }
                        Ok(brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperationOpenOutcome::Ready(_)) => {
                            unreachable!("ready Rust batch operation was handled above")
                        }
                        Err(error) => {
                            crate::analyzer::rust::native_points::RustDefinitionOperationOpenFailure::StoreError(error.to_string())
                        }
                    };
                    for (request_index, query) in request_indices.iter().copied().zip(queries) {
                        self.precomputed[request_index] = Some(
                            crate::analyzer::rust::native_points::resolve_rust_definition_open_failure_for_batch(
                                query,
                                &failure,
                            ),
                        );
                    }
                    return;
                }
            }
        }
        let results = self.factory.resolve_many(
            self.borrowed_operation
                .as_deref_mut()
                .or(self.operation.as_mut())
                .expect("ready Rust batch operation is retained"),
            &queries,
            cancellation,
        );
        assert_eq!(results.len(), request_indices.len());
        for (request_index, result) in request_indices.iter().copied().zip(results) {
            self.precomputed[request_index] = result;
        }
        if self.precomputed.iter().flatten().any(|result| {
            matches!(
                result,
                BoundedResolution::Complete { value, .. }
                    if value.diagnostics.iter().any(|diagnostic| {
                        matches!(diagnostic.kind.as_str(), "native_stale" | "native_store_error")
                    })
            )
        }) {
            self.operation.take();
            self.borrowed_operation.take();
            self.reuse_disabled = true;
        }
    }

    fn resolve(
        &mut self,
        query: brokk_bifrost_analysis::analyzer::languages::BoundedReceiverQuery<'_>,
    ) -> BoundedResolution<DefinitionLookupOutcome> {
        if self.precomputed_index < self.precomputed.len() {
            let precomputed = self.precomputed[self.precomputed_index].take();
            self.precomputed_index += 1;
            if let Some(precomputed) = precomputed {
                return precomputed;
            }
        }
        self.resolve_unprepared(query)
    }

    fn resolve_unprepared(
        &mut self,
        query: brokk_bifrost_analysis::analyzer::languages::BoundedReceiverQuery<'_>,
    ) -> BoundedResolution<DefinitionLookupOutcome> {
        if self.reuse_disabled {
            return crate::analyzer::rust::native_points::resolve_rust_definition_bounded(query);
        }
        if self.operation.is_none() && self.borrowed_operation.is_none() {
            let cancellation = query.cancellation.cloned().unwrap_or_default();
            let opened = self.factory.open(&cancellation);
            match opened {
                Ok(
                    brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperationOpenOutcome::Ready(
                        operation,
                    ),
                ) => self.operation = Some(*operation),
                outcome => {
                    self.reuse_disabled = true;
                    return crate::analyzer::rust::native_points::resolve_rust_definition_open_failure(
                        query, outcome,
                    );
                }
            }
        }
        let result = self.factory.resolve(
            self.borrowed_operation
                .as_deref_mut()
                .or(self.operation.as_mut())
                .expect("ready Rust batch operation is retained"),
            query,
        );
        if matches!(
            &result,
            BoundedResolution::Complete { value, .. }
                if value.diagnostics.iter().any(|diagnostic| {
                    matches!(diagnostic.kind.as_str(), "native_stale" | "native_store_error")
                })
        ) {
            self.operation.take();
            self.borrowed_operation.take();
            self.reuse_disabled = true;
        }
        result
    }
}

fn precompute_rust_call_target_batch<'analyzer: 'selection, 'selection>(
    analyzer: &dyn IAnalyzer,
    context: &mut DefinitionBatchContext<'_, '_>,
    requests: &[DefinitionLookupRequest],
    cancellation: Option<&CancellationToken>,
    batch: &mut RustDefinitionBatchOperation<'analyzer, '_, 'selection, '_>,
) {
    let Some(first) = requests.first() else {
        return;
    };
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        return;
    }
    let Ok(source) = context.source(&first.file) else {
        return;
    };
    let tree = context.tree(&first.file, Language::Rust, &source);
    let mut request_indices = Vec::with_capacity(requests.len());
    let mut sites = Vec::with_capacity(requests.len());
    for (index, request) in requests.iter().enumerate() {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return;
        }
        if let Ok(site) =
            focused_reference_site(context, request, Language::Rust, &source, tree.as_ref())
        {
            request_indices.push(index);
            sites.push(site);
        }
    }
    if sites.len() < 2 {
        return;
    }
    let queries = request_indices
        .iter()
        .zip(&sites)
        .map(
            |(&index, site)| brokk_bifrost_analysis::analyzer::languages::BoundedReceiverQuery {
                analyzer,
                file: &requests[index].file,
                source: &source,
                tree: tree.as_ref(),
                site,
                budget: brokk_bifrost_core::analyzer::usages::receiver_analysis::INTERACTIVE_TYPE_LOOKUP_BUDGET,
                cancellation,
            },
        )
        .collect();
    let batch_cancellation = cancellation.cloned().unwrap_or_default();
    batch.precompute(
        queries,
        &request_indices,
        requests.len(),
        &batch_cancellation,
    );
}

/// Resolve native call targets on an already captured worker operation.
/// The returned vocabulary contains no semantic artifact or relation handles.
#[allow(clippy::too_many_arguments)]
pub(crate) fn resolve_call_target_batch_in_operation<'a: 'selection, 'selection>(
    analyzer: &'a dyn IAnalyzer,
    requests: Vec<DefinitionLookupRequest>,
    file: ProjectFile,
    source: Arc<str>,
    cancellation: &CancellationToken,
    factory: &crate::analyzer::rust::native_points::RustDefinitionOperationFactory<'a>,
    operation: &mut brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperation<
        'a,
        'selection,
    >,
) -> Vec<CallTargetLookupOutcome> {
    let _timing = profiling::scope("get_definition::resolve_call_target_batch");
    profiling::note_with(|| format!("request_count={}", requests.len()));
    let scope = AnalyzerQueryScope::with_cancellation(analyzer, cancellation);
    let mut context = DefinitionBatchContext::new(analyzer, scope.token());
    context.sources.insert(file, Ok(source));
    record_definition_batch_probe_reads(analyzer, &mut context, &requests);
    let batch = RustDefinitionBatchOperation {
        factory: RustBatchFactory::Borrowed(factory),
        operation: None,
        borrowed_operation: Some(operation),
        reuse_disabled: false,
        precomputed: Vec::new(),
        precomputed_index: 0,
    };
    resolve_call_target_requests(
        analyzer,
        scope.token(),
        &mut context,
        requests,
        Some(cancellation),
        Some(&mut { batch }),
    )
}

pub(crate) fn associated_navigation_targets(
    analyzer: &dyn IAnalyzer,
    candidate: CodeUnit,
    operation: NavigationOperation,
) -> Vec<NavigationTarget> {
    use brokk_bifrost_core::analyzer::structural::resolution::MethodFamilyRelation;
    let mut members = Vec::new();
    if language_for_file(candidate.source()) == Language::Rust
        && candidate.is_class()
        && let Some(provider) = analyzer.member_family_provider()
    {
        let relation = match operation {
            NavigationOperation::Declaration => MethodFamilyRelation::Implements,
            NavigationOperation::Definition => MethodFamilyRelation::ImplementedBy,
        };
        members.extend(
            provider
                .member_family(&candidate, None)
                .edges
                .into_iter()
                .filter(|edge| edge.relation == relation)
                .map(|edge| edge.target),
        );
    }
    if members.is_empty() {
        members.push(candidate);
    }
    members
        .into_iter()
        .map(|code_unit| NavigationTarget {
            code_unit,
            declaration_range: None,
        })
        .collect()
}
