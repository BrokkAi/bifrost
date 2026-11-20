//! Go call relations projected from selected inverse and forward operations.

use std::sync::Arc;

use brokk_bifrost_analysis::analyzer::usages::call_relations::{
    CallRelationDiagnosticPayload, CallRelationFailure, LocatedCallRelationDiagnostic,
};

use crate::analyzer::go::GoAnalyzer;

use crate::analyzer::go::selected_reverse::GoSelectedReverseOutcome;

use crate::analyzer::go::selected_reverse::go_selected_inverse_for;

use brokk_bifrost_core::cancellation::CancellationToken;

use brokk_bifrost_analysis::analyzer::structural::reference_edges::EdgeCompleteness;

use brokk_bifrost_analysis::analyzer::structural::reference_edges::EdgeDerivationResult;

use brokk_bifrost_core::analyzer::usages::model::UsageProofAuthority;

use brokk_bifrost_analysis::analyzer::usages::call_relations::CallRelationDiagnostic;

use brokk_bifrost_analysis::analyzer::usages::call_relations::CallRelationDiagnosticCode;

use brokk_bifrost_analysis::analyzer::usages::call_relations::CallRelationLimits;

use brokk_bifrost_analysis::analyzer::usages::call_relations::CallRelationProvider;

use brokk_bifrost_analysis::analyzer::usages::call_relations::{
    CallRelationResult, CallerInventoryCoverage,
};

use brokk_bifrost_analysis::analyzer::usages::call_relations::native_incoming_preflight;

use brokk_bifrost_analysis::analyzer::usages::get_definition::call_sites::CallSiteSyntax;

use brokk_bifrost_core::analyzer::model::{CodeUnit, DispatchExtensibility};

use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;

use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

use brokk_bifrost_core::analyzer::model::ProjectFile;

use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;

use brokk_bifrost_analysis::analyzer::structural::reference_edges::ReferenceEdgeRow;
use brokk_bifrost_analysis::analyzer::usages::native_incoming::{
    IncomingCallProjection, IncomingFile, IncomingFileBudget, IncomingProjectionIssue,
    finish_incoming_sites, project_selected_incoming, structural_incoming_caller,
};

/// Native Go call-relation projection used by Go production dispatch.
pub struct GoNativeCallRelations;

/// Whole-file map of bound method-value call callee spans to their
/// selection's selector spans; `None` when the file's procedure enumeration
/// is unavailable or incomplete. Computed once per file and dispatch batch or
/// session, shared through `CallDispatchLanguageRequest::special_dispatch_memos`.
struct GoBoundMethodValueCallSpans(
    Option<brokk_bifrost_core::hash::HashMap<(usize, usize), (usize, usize)>>,
);

impl CallRelationProvider for GoNativeCallRelations {
    fn proof_authority(&self) -> UsageProofAuthority {
        UsageProofAuthority::Native
    }

    fn incoming(
        &self,
        analyzer: &dyn IAnalyzer,
        target: &CodeUnit,
        limits: CallRelationLimits,
        cancellation: Option<&CancellationToken>,
    ) -> CallRelationResult {
        let cancellation = cancellation.cloned().unwrap_or_default();
        if let Some(result) = native_incoming_preflight(target, limits, &cancellation, || {
            CallRelationDiagnostic::new(
                CallRelationDiagnosticCode::BudgetExhausted,
                CallRelationDiagnosticPayload::GoIncomingBudget {
                    target: target.fq_name().to_string(),
                },
                target.fq_name().to_string(),
            )
        }) {
            return result;
        }
        let Some(go) = resolve_analyzer::<GoAnalyzer>(analyzer) else {
            return unavailable(CallRelationFailure::Unavailable, target);
        };
        let selected = match go_selected_inverse_for(go, target, &cancellation) {
            GoSelectedReverseOutcome::Ready(answer) => answer,
            GoSelectedReverseOutcome::Unavailable(_reason)
            | GoSelectedReverseOutcome::TargetUncovered(_reason) => {
                return unavailable(CallRelationFailure::Unavailable, target);
            }
            GoSelectedReverseOutcome::Stale(_reason) => {
                return unavailable(CallRelationFailure::Stale, target);
            }
            GoSelectedReverseOutcome::Cancelled => {
                return CallRelationResult {
                    caller_inventory: CallerInventoryCoverage::Incomplete,
                    cancelled: true,
                    proof_authority: UsageProofAuthority::Native,
                    ..CallRelationResult::default()
                };
            }
            GoSelectedReverseOutcome::StoreError(_reason) => {
                return unavailable(CallRelationFailure::StoreError, target);
            }
        };
        project_incoming_calls(go, target, selected, limits, &cancellation)
    }

    fn outgoing(
        &self,
        analyzer: &dyn IAnalyzer,
        caller: &CodeUnit,
        limits: CallRelationLimits,
        cancellation: Option<&CancellationToken>,
    ) -> CallRelationResult {
        let cancellation = cancellation.cloned().unwrap_or_default();
        if cancellation.is_cancelled() {
            return CallRelationResult {
                caller_inventory: CallerInventoryCoverage::Incomplete,
                cancelled: true,
                proof_authority: UsageProofAuthority::Native,
                ..CallRelationResult::default()
            };
        }
        let Some(go) = resolve_analyzer::<GoAnalyzer>(analyzer) else {
            return unavailable(CallRelationFailure::Unavailable, caller);
        };
        crate::analyzer::go::native_outgoing::outgoing(
            analyzer, go,
            caller,
            limits,
            brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget::default(),
            &cancellation,
        )
    }

    fn dispatch_special_call_site(
        &self,
        request: brokk_bifrost_analysis::analyzer::usages::call_relations::CallDispatchLanguageRequest<'_>,
    ) -> Option<brokk_bifrost_analysis::analyzer::usages::call_relations::CallDispatchLookup> {
        let root = request.tree.root_node();
        let mut node = root.named_descendant_for_byte_range(
            request.call_span.start_byte,
            request.call_span.end_byte,
        )?;
        let call_node = loop {
            if node.kind() == "call_expression"
                && node.start_byte() == request.call_span.start_byte
                && node.end_byte() == request.call_span.end_byte
            {
                break node;
            }
            node = node.parent()?;
        };
        if call_node
            .parent()
            .is_some_and(|parent| parent.kind() == "go_statement")
        {
            return None;
        }
        let mut function = call_node.child_by_field_name("function")?;
        while function.kind() == "parenthesized_expression" {
            let mut cursor = function.walk();
            function = function.named_children(&mut cursor).next()?;
        }
        if function.kind() != "identifier" {
            return None;
        }
        // The whole-file enumeration runs once per dispatch batch or session;
        // every later identifier call in the same file reuses this memo.
        let memo = request.special_dispatch_memos.get(&root.id()).cloned();
        let memo = match memo {
            Some(memo) => memo,
            None => {
                let computed: Arc<dyn std::any::Any + Send + Sync> =
                    Arc::new(GoBoundMethodValueCallSpans(
                        crate::analyzer::go::semantic::go_bound_method_value_file_call_selectors(
                            request.file,
                            request.tree,
                            request.source,
                            request.cancellation,
                        ),
                    ));
                request
                    .special_dispatch_memos
                    .insert(root.id(), Arc::clone(&computed));
                computed
            }
        };
        let spans = memo
            .downcast_ref::<GoBoundMethodValueCallSpans>()
            .expect("the Go dispatch hook writes its own memo type")
            .0
            .as_ref()?;
        let (sel_start, sel_end) = *spans.get(&(function.start_byte(), function.end_byte()))?;
        let mut current = root.named_descendant_for_byte_range(sel_start, sel_end)?;
        let sel_node = loop {
            if current.kind() == "selector_expression"
                && current.start_byte() == sel_start
                && current.end_byte() == sel_end
            {
                break current;
            }
            current = current.parent()?;
        };
        let field = sel_node.child_by_field_name("field")?;
        let member_text = request.source.get(field.byte_range())?.to_owned();
        let site = brokk_bifrost_core::analyzer::usages::reference_site::ResolvedReferenceSite {
            path: brokk_bifrost_core::path_utils::rel_path_string(request.file),
            text: member_text,
            range: brokk_bifrost_core::analyzer::model::Range {
                start_byte: field.start_byte(),
                end_byte: field.end_byte(),
                start_line: field.start_position().row + 1,
                end_line: field.end_position().row + 1,
            },
            focus_start_byte: field.start_byte(),
            focus_end_byte: field.end_byte(),
        };
        let query = brokk_bifrost_analysis::analyzer::languages::BoundedReceiverQuery {
            analyzer: request.analyzer,
            file: request.file,
            source: request.source,
            tree: Some(request.tree),
            site: &site,
            budget:
                brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget::default(),
            cancellation: request.cancellation,
        };
        let resolution =
            crate::analyzer::usages::get_definition::go::resolve_go_definition_for_special_dispatch(
                query,
            );
        let mut lookup =
            brokk_bifrost_analysis::analyzer::usages::call_relations::dispatch_selected_call(
                request.analyzer,
                request.file,
                resolution,
                request.work,
            );
        crate::analyzer::go::selector_calls::apply_go_typed_selector_target_for_call_node(
            &mut lookup,
            request.analyzer,
            request.token,
            request.file,
            request.source,
            request.tree,
            sel_node,
            call_node,
            request.cancellation,
            request.member_selection,
        );
        Some(lookup)
    }
}

/// Public test-support entry point for comparing the native adapter with the
/// incumbent Go call relation path.
#[cfg(any(test, feature = "test-support"))]
pub fn go_native_incoming_calls(
    analyzer: &dyn IAnalyzer,
    target: &CodeUnit,
    limits: CallRelationLimits,
    cancellation: Option<&CancellationToken>,
) -> CallRelationResult {
    GoNativeCallRelations.incoming(analyzer, target, limits, cancellation)
}

pub(crate) fn project_incoming_calls(
    go: &GoAnalyzer,
    target: &CodeUnit,
    mut selected: EdgeDerivationResult,
    limits: CallRelationLimits,
    cancellation: &CancellationToken,
) -> CallRelationResult {
    let mut result = CallRelationResult {
        proof_authority: UsageProofAuthority::Native,
        caller_inventory: if matches!(selected.completeness, EdgeCompleteness::Complete) {
            CallerInventoryCoverage::Complete
        } else {
            CallerInventoryCoverage::Incomplete
        },
        diagnostics: incomplete_diagnostics(&selected, target),
        ..CallRelationResult::default()
    };
    selected.edges.sort_by(|left, right| {
        (
            left.site.file != *target.source(),
            &left.site.file,
            left.site.range.start_byte,
        )
            .cmp(&(
                right.site.file != *target.source(),
                &right.site.file,
                right.site.range.start_byte,
            ))
    });

    let projected = project_selected_incoming(
        &mut GoIncomingProjection { go, target },
        target,
        selected.edges.iter().map(|edge| (edge, ())),
        limits,
        cancellation,
        &mut result,
    );
    if let Some(sites) = projected.unwrap_or_else(|never| match never {}) {
        finish_incoming_sites(sites, &mut result);
    }
    result.with_diagnostic_limits(limits)
}

struct GoIncomingProjection<'a> {
    go: &'a GoAnalyzer,
    target: &'a CodeUnit,
}

impl IncomingCallProjection for GoIncomingProjection<'_> {
    type Error = std::convert::Infallible;

    fn load_file(
        &mut self,
        file: &ProjectFile,
        budget: &mut IncomingFileBudget<'_>,
        diagnostics: &mut Vec<CallRelationDiagnostic>,
    ) -> Result<IncomingFile, Self::Error> {
        if budget.file_capacity_exhausted() {
            return Ok(IncomingFile::Rejected);
        }
        let Some(source) = self.go.indexed_source(file) else {
            diagnostics.push(diagnostic(
                CallRelationDiagnosticPayload::GoSourceUnavailable.at(file, None),
                self.target.fq_name().to_string(),
                "native_call_source_unavailable",
            ));
            return Ok(IncomingFile::Rejected);
        };
        if !budget.source_fits(source.len()) {
            return Ok(IncomingFile::Rejected);
        }
        if !self
            .go
            .inner
            .source_matches_selected_native_content(file, &source)
        {
            diagnostics.push(diagnostic(
                CallRelationDiagnosticPayload::GoSourceStale.at(file, None),
                self.target.fq_name().to_string(),
                "native_call_source_stale",
            ));
            return Ok(IncomingFile::Rejected);
        }
        let facts = self
            .go
            .structural_fact_providers()
            .into_iter()
            .find_map(|provider| provider.structural_facts(file));
        if facts
            .as_ref()
            .is_some_and(|facts| facts.source() != source.as_str())
        {
            diagnostics.push(diagnostic(
                CallRelationDiagnosticPayload::GoStructuralSourceStale.at(file, None),
                self.target.fq_name().to_string(),
                "native_call_source_stale",
            ));
            return Ok(IncomingFile::Rejected);
        }
        assert!(
            budget.admit_source(source.len()),
            "prechecked source fits the unchanged budget"
        );
        Ok(IncomingFile::Loaded(facts))
    }

    /// Go types satisfy interfaces implicitly, and the store has no record of
    /// where a receiver value converts to an interface type (#8484). So any
    /// concrete method can be called through an interface value, by std or by
    /// a dependency, from a site no reverse row names. An interface's own
    /// method declaration (open dispatch) is named at every call through the
    /// interface, so, like a free function, it keeps the coverage of its
    /// reverse inventory. Missing signature metadata counts as concrete.
    fn unenumerable_dispatch(&mut self, target: &CodeUnit) -> Result<bool, Self::Error> {
        Ok(target.is_function()
            && target.owner_is_type_scope()
            && !self.go.signature_metadata(target).iter().any(|metadata| {
                metadata.dispatch_extensibility() == Some(DispatchExtensibility::Open)
            }))
    }

    fn caller(&self, edge: &ReferenceEdgeRow, syntax: &CallSiteSyntax) -> Option<CodeUnit> {
        structural_incoming_caller(self.go.structural_fact_providers(), edge, syntax)
    }

    fn join_reuse_verdict(
        &self,
        verdict: brokk_bifrost_analysis::analyzer::reuse_verdict::ReuseVerdict,
    ) {
        brokk_bifrost_analysis::analyzer::IAnalyzer::join_reuse_verdict(self.go, verdict);
    }

    fn report_issue(&self, issue: IncomingProjectionIssue<'_>) -> CallRelationDiagnostic {
        match issue {
            IncomingProjectionIssue::FactsUnavailable(file) => diagnostic(
                CallRelationDiagnosticPayload::GoFactsUnavailable.at(file, None),
                "call_source".to_string(),
                "native_call_facts_unavailable",
            ),
            IncomingProjectionIssue::OwnerUnavailable(edge) => diagnostic(
                CallRelationDiagnosticPayload::GoOwnerUnavailable {
                    enclosing: edge.site.enclosing.as_ref().map(Into::into),
                }
                .at(&edge.site.file, Some(edge.site.range)),
                "call_source".to_string(),
                "native_call_owner_unavailable",
            ),
        }
    }
}

fn incomplete_diagnostics(
    selected: &EdgeDerivationResult,
    target: &CodeUnit,
) -> Vec<CallRelationDiagnostic> {
    let EdgeCompleteness::Incomplete { reasons } = &selected.completeness else {
        return Vec::new();
    };
    reasons
        .iter()
        .map(|reason| {
            diagnostic(
                CallRelationDiagnosticPayload::GoInventoryIncomplete {
                    target: target.fq_name().to_string(),
                    reason: reason.into(),
                },
                target.fq_name().to_string(),
                "native_call_inventory_incomplete",
            )
        })
        .collect()
}

fn unavailable(reason: CallRelationFailure, target: &CodeUnit) -> CallRelationResult {
    CallRelationResult {
        caller_inventory: CallerInventoryCoverage::Incomplete,
        proof_authority: UsageProofAuthority::Native,
        diagnostics: vec![diagnostic(
            CallRelationDiagnosticPayload::Failure { reason },
            target.fq_name().to_string(),
            "native_call_unavailable",
        )],
        ..CallRelationResult::default()
    }
}

fn diagnostic(
    message: impl Into<LocatedCallRelationDiagnostic>,
    context: String,
    reason_kind: &str,
) -> CallRelationDiagnostic {
    CallRelationDiagnostic::analysis_failed(message, context, reason_kind.to_owned())
}
