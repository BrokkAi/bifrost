//! Bounded Python definition points shared by navigation and receiver requests.

use super::{PythonNativeOpen, open_python_native_request};
use crate::analyzer::PythonAnalyzer;
use brokk_bifrost_analysis::analyzer::languages::BoundedReceiverQuery;
use brokk_bifrost_analysis::analyzer::native_points::{
    adapt_definition_answer, unavailable_definition,
};
use brokk_bifrost_analysis::analyzer::resolve_analyzer;
use brokk_bifrost_analysis::analyzer::store::resolution_operation::{
    SelectedResolutionLocated, SelectedResolutionOperationOutcome,
    native_units::SelectedNativeDefinitions,
};
use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupOutcome;
use brokk_bifrost_core::analyzer::Language;
use brokk_bifrost_core::analyzer::usages::resolution_session::{
    BoundedResolution, ResolutionSession,
};

/// Selected operation or its explicit opening refusal, retained for one query.
/// Opening failures are answers too; they never trigger legacy recovery.
pub(crate) struct PythonReceiverRequest<'a> {
    opened: PythonNativeOpen<'a>,
}

impl<'a> PythonReceiverRequest<'a> {
    pub(crate) fn open(
        python: &'a PythonAnalyzer,
        cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
    ) -> Self {
        let opened = match open_python_native_request(python, cancellation) {
            Ok(opened) => opened,
            Err(error) => PythonNativeOpen::Unavailable {
                kind: "native_store_error",
                message: error.to_string(),
            },
        };
        Self { opened }
    }

    pub(crate) fn resolve_definition_bounded(
        &mut self,
        query: BoundedReceiverQuery<'_>,
    ) -> BoundedResolution<DefinitionLookupOutcome> {
        // The operation is reusable, but work and sticky stops belong to one
        // query. A warm request must still charge the current query's reads.
        let session = ResolutionSession::bounded(query.budget, query.cancellation);
        let request = match &mut self.opened {
            PythonNativeOpen::Ready(request) => request,
            PythonNativeOpen::Unavailable { kind, message } => {
                return session.finish(unavailable_definition(query.site, kind, message.clone()));
            }
            PythonNativeOpen::Cancelled => {
                return BoundedResolution::Cancelled {
                    work: session.finish(()).work(),
                };
            }
        };
        let result = request.operation.python_definition_at(
            &request.environment,
            query.file,
            query.site.focus_start_byte..query.site.focus_end_byte,
            &session,
        );
        match result {
            Ok(BoundedResolution::Complete { value, work }) => {
                let outcome = match value {
                    SelectedResolutionOperationOutcome::Native(
                        SelectedResolutionLocated::Found(answer),
                    ) => {
                        if matches!(answer.definitions, SelectedNativeDefinitions::Cancelled) {
                            return BoundedResolution::Cancelled { work };
                        }
                        // Definition identity uses binding completion, not
                        // invocation completion or argument application.
                        adapt_definition_answer(query.site, Language::Python, answer)
                    }
                    SelectedResolutionOperationOutcome::Native(
                        SelectedResolutionLocated::Missing,
                    ) => unavailable_definition(
                        query.site,
                        "native_reference_unavailable",
                        "selected Python producer has no reference at this source range".into(),
                    ),
                    SelectedResolutionOperationOutcome::Unavailable(reason) => {
                        unavailable_definition(
                            query.site,
                            "native_unavailable",
                            format!("{reason:?}"),
                        )
                    }
                    SelectedResolutionOperationOutcome::Stale(reason) => {
                        unavailable_definition(query.site, "native_stale", format!("{reason:?}"))
                    }
                    SelectedResolutionOperationOutcome::Cancelled(_) => {
                        return BoundedResolution::Cancelled { work };
                    }
                };
                BoundedResolution::Complete {
                    value: outcome,
                    work,
                }
            }
            Ok(BoundedResolution::Exceeded { limit, work }) => {
                BoundedResolution::Exceeded { limit, work }
            }
            Ok(BoundedResolution::Cancelled { work }) => BoundedResolution::Cancelled { work },
            Err(error) => session.finish(unavailable_definition(
                query.site,
                "native_store_error",
                error.to_string(),
            )),
        }
    }
}

impl brokk_bifrost_analysis::analyzer::languages::ReceiverRequest for PythonReceiverRequest<'_> {
    fn resolve_type(
        &mut self,
        query: brokk_bifrost_analysis::analyzer::languages::BoundedReceiverQuery<'_>,
    ) -> brokk_bifrost_core::analyzer::usages::resolution_session::BoundedResolution<
        brokk_bifrost_analysis::analyzer::usages::get_type::TypeLookupOutcome,
    > {
        // Type lookup retains the structured source/type authority. Only the
        // definition half of this request switches to selected native points.
        brokk_bifrost_analysis::analyzer::languages::StructuralReceiverResolver::resolve_type_bounded(
            &super::super::PythonSupport,
            query,
        )
    }

    fn resolve_definition(
        &mut self,
        query: brokk_bifrost_analysis::analyzer::languages::BoundedReceiverQuery<'_>,
    ) -> brokk_bifrost_core::analyzer::usages::resolution_session::BoundedResolution<
        brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupOutcome,
    > {
        self.resolve_definition_bounded(query)
    }
}

pub(crate) fn resolve_definition_bounded(
    query: BoundedReceiverQuery<'_>,
) -> BoundedResolution<DefinitionLookupOutcome> {
    let Some(python) = resolve_analyzer::<PythonAnalyzer>(query.analyzer) else {
        return ResolutionSession::bounded(query.budget, query.cancellation).finish(
            unavailable_definition(
                query.site,
                "python_analyzer_unavailable",
                "Python analyzer unavailable".into(),
            ),
        );
    };
    let cancellation = query.cancellation.cloned().unwrap_or_default();
    PythonReceiverRequest::open(python, &cancellation).resolve_definition_bounded(query)
}
