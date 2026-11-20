use super::*;
use crate::analyzer::semantic::{SemanticBudgetDimension, SemanticWork};
use schemars::JsonSchema;
use serde::ser::{SerializeSeq, SerializeStruct};

/// One fixed presentation refusal, with no owned strings or root allocations.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PresentationDiagnostic {
    RowsRefused,
    SourceTextRefused,
    OwnerUnavailable,
}

impl std::fmt::Debug for PresentationDiagnostic {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        struct FixedRoot;
        impl std::fmt::Debug for FixedRoot {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter
                    .debug_struct("CodeQueryExhaustedRoot")
                    .field("path", &".")
                    .field("procedure", &Option::<&str>::None)
                    .field("lane", &"render/site_output/retained_bytes")
                    .field("stage", &Some("result_presentation"))
                    .field("budget", &Option::<CodeQueryExhaustedBudget>::None)
                    .field("charge", &Option::<CodeQueryExhaustedCharge>::None)
                    .field("feedback_iteration", &Option::<usize>::None)
                    .finish()
            }
        }
        let mut diagnostic = formatter.debug_struct("CodeQueryDiagnostic");
        diagnostic
            .field("code", &self.code())
            .field("impact", &CodeQueryDiagnosticImpact::Incomplete)
            .field("incompleteness", &self.incompleteness())
            .field("branch", &(&[] as &[usize]))
            .field("language", &"workspace")
            .field("message", &self.message());
        if *self == Self::OwnerUnavailable {
            diagnostic.field("exhausted_roots", &(&[] as &[FixedRoot]));
        } else {
            diagnostic.field("exhausted_roots", &[FixedRoot]);
        }
        diagnostic.finish()
    }
}

impl PresentationDiagnostic {
    pub const fn code(self) -> CodeQueryDiagnosticCode {
        match self {
            Self::RowsRefused | Self::SourceTextRefused => {
                CodeQueryDiagnosticCode::PresentationRowsRefused
            }
            Self::OwnerUnavailable => CodeQueryDiagnosticCode::PresentationOwnerUnavailable,
        }
    }

    pub const fn incompleteness(self) -> Incompleteness {
        let cause = match self {
            Self::RowsRefused | Self::SourceTextRefused => DiagnosticExecutionCause::Budget,
            Self::OwnerUnavailable => DiagnosticExecutionCause::Provider,
        };
        Incompleteness::Operational(cause)
    }

    pub const fn message(self) -> &'static str {
        match self {
            Self::RowsRefused => "site presentation could not retain the requested payload",
            Self::SourceTextRefused => {
                "site source text could not be admitted for presentation; structural roles and values are retained"
            }
            Self::OwnerUnavailable => "site presentation has no analyzer retention owner",
        }
    }

    fn presentation_label(self) -> &'static str {
        match self {
            Self::RowsRefused | Self::SourceTextRefused => "incomplete [presentation_rows_refused]",
            Self::OwnerUnavailable => "incomplete [presentation_owner_unavailable]",
        }
    }
}

impl Serialize for PresentationDiagnostic {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let has_root = *self != Self::OwnerUnavailable;
        let mut diagnostic =
            serializer.serialize_struct("CodeQueryDiagnostic", 5 + usize::from(has_root))?;
        diagnostic.serialize_field("incompleteness", &self.incompleteness())?;
        diagnostic.serialize_field("code", &self.code())?;
        diagnostic.serialize_field("impact", &CodeQueryDiagnosticImpact::Incomplete)?;
        diagnostic.serialize_field("language", "workspace")?;
        diagnostic.serialize_field("message", self.message())?;
        if has_root {
            #[derive(Serialize)]
            struct FixedRoot {
                path: &'static str,
                lane: &'static str,
                stage: &'static str,
            }
            diagnostic.serialize_field(
                "exhausted_roots",
                &[FixedRoot {
                    path: ".",
                    lane: "render/site_output/retained_bytes",
                    stage: "result_presentation",
                }],
            )?;
        }
        diagnostic.end()
    }
}

/// Legacy semantic diagnostics plus at most one allocation-free presentation
/// refusal. Semantic mutation cannot silently erase a presentation failure.
#[derive(Clone, Default)]
pub struct QueryDiagnostics {
    semantic: Vec<CodeQueryDiagnostic>,
    presentation: Option<PresentationDiagnostic>,
}

impl std::fmt::Debug for QueryDiagnostics {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_list().entries(self.iter()).finish()
    }
}

impl From<Vec<CodeQueryDiagnostic>> for QueryDiagnostics {
    fn from(semantic: Vec<CodeQueryDiagnostic>) -> Self {
        Self {
            semantic,
            presentation: None,
        }
    }
}

impl QueryDiagnostics {
    pub fn len(&self) -> usize {
        self.semantic.len() + usize::from(self.presentation.is_some())
    }

    pub fn is_empty(&self) -> bool {
        self.semantic.is_empty() && self.presentation.is_none()
    }

    /// Append a legacy semantic or host-session diagnostic unchanged.
    pub fn push(&mut self, diagnostic: CodeQueryDiagnostic) {
        self.semantic.push(diagnostic);
    }

    pub fn extend(&mut self, diagnostics: impl IntoIterator<Item = CodeQueryDiagnostic>) {
        self.semantic.extend(diagnostics);
    }

    /// Move another complete carrier after these semantic diagnostics. The
    /// presentation refusal stays a static flag, never a raw owned diagnostic.
    pub(crate) fn append(&mut self, mut other: Self) {
        self.semantic.append(&mut other.semantic);
        if let Some(diagnostic) = other.presentation {
            self.set_presentation(diagnostic);
        }
    }

    /// Keep the first whole-row refusal, upgrading a source-only refusal if
    /// later presentation cannot preserve a complete row.
    pub fn set_presentation(&mut self, diagnostic: PresentationDiagnostic) {
        match self.presentation {
            None | Some(PresentationDiagnostic::SourceTextRefused) => {
                self.presentation = Some(diagnostic);
            }
            Some(
                PresentationDiagnostic::RowsRefused | PresentationDiagnostic::OwnerUnavailable,
            ) => {}
        }
    }

    pub fn iter(&self) -> DiagnosticIter<'_> {
        DiagnosticIter {
            semantic: self.semantic.iter(),
            presentation: self.presentation,
        }
    }

    /// Borrow a semantic-only product; presentation is never a policy input.
    pub fn semantic(&self) -> &[CodeQueryDiagnostic] {
        assert!(
            self.presentation.is_none(),
            "presentation diagnostics cannot enter semantic execution"
        );
        &self.semantic
    }

    pub fn semantic_mut(&mut self) -> &mut Vec<CodeQueryDiagnostic> {
        assert!(
            self.presentation.is_none(),
            "presentation diagnostics cannot enter semantic execution"
        );
        &mut self.semantic
    }

    pub fn into_semantic(self) -> Vec<CodeQueryDiagnostic> {
        assert!(
            self.presentation.is_none(),
            "presentation diagnostics cannot enter semantic execution"
        );
        self.semantic
    }
}

/// Borrowed diagnostics expose values without constructing a raw owned
/// presentation diagnostic. Explicit extraction keeps its static carrier.
#[derive(Clone, Copy)]
pub enum DiagnosticRef<'a> {
    Semantic(&'a CodeQueryDiagnostic),
    Presentation(PresentationDiagnostic),
}

impl std::fmt::Debug for DiagnosticRef<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Semantic(diagnostic) => std::fmt::Debug::fmt(diagnostic, formatter),
            Self::Presentation(diagnostic) => std::fmt::Debug::fmt(diagnostic, formatter),
        }
    }
}

impl<'a> DiagnosticRef<'a> {
    pub fn code(self) -> CodeQueryDiagnosticCode {
        match self {
            Self::Semantic(diagnostic) => diagnostic.code,
            Self::Presentation(diagnostic) => diagnostic.code(),
        }
    }
    pub fn impact(self) -> CodeQueryDiagnosticImpact {
        match self {
            Self::Semantic(diagnostic) => diagnostic.impact,
            Self::Presentation(_) => CodeQueryDiagnosticImpact::Incomplete,
        }
    }
    pub fn incompleteness(self) -> Incompleteness {
        match self {
            Self::Semantic(diagnostic) => diagnostic.incompleteness,
            Self::Presentation(diagnostic) => diagnostic.incompleteness(),
        }
    }
    pub fn language(self) -> &'static str {
        match self {
            Self::Semantic(diagnostic) => diagnostic.language,
            Self::Presentation(_) => "workspace",
        }
    }
    pub fn message(self) -> &'a str {
        match self {
            Self::Semantic(diagnostic) => &diagnostic.message,
            Self::Presentation(diagnostic) => diagnostic.message(),
        }
    }
    pub fn branch(self) -> &'a [usize] {
        match self {
            Self::Semantic(diagnostic) => &diagnostic.branch,
            Self::Presentation(_) => &[],
        }
    }
    pub fn withheld_rows_path(self) -> Option<&'a str> {
        match self {
            Self::Semantic(diagnostic) => diagnostic.withheld_rows_path.as_deref(),
            Self::Presentation(_) => None,
        }
    }
    pub fn step_index(self) -> Option<usize> {
        match self {
            Self::Semantic(diagnostic) => diagnostic.step_index,
            Self::Presentation(_) => None,
        }
    }
    pub fn step_op(self) -> Option<&'a str> {
        match self {
            Self::Semantic(diagnostic) => diagnostic.step_op.as_deref(),
            Self::Presentation(_) => None,
        }
    }
    pub fn no_rows_reason(self) -> Option<CodeQueryStepNoRowsReason> {
        match self {
            Self::Semantic(diagnostic) => diagnostic.no_rows_reason,
            Self::Presentation(_) => None,
        }
    }
    pub fn cause_codes(self) -> &'a [CodeQueryDiagnosticCode] {
        match self {
            Self::Semantic(diagnostic) => &diagnostic.cause_codes,
            Self::Presentation(_) => &[],
        }
    }
    pub fn source(self) -> Option<&'a CodeQuerySourceSpan> {
        match self {
            Self::Semantic(diagnostic) => diagnostic.source.as_ref(),
            Self::Presentation(_) => None,
        }
    }
    pub fn related(self) -> &'a [CodeQueryRelatedSource] {
        match self {
            Self::Semantic(diagnostic) => &diagnostic.related,
            Self::Presentation(_) => &[],
        }
    }
    pub fn presentation_label(self) -> std::borrow::Cow<'static, str> {
        match self {
            Self::Semantic(diagnostic) => std::borrow::Cow::Owned(diagnostic.presentation_label()),
            Self::Presentation(diagnostic) => {
                std::borrow::Cow::Borrowed(diagnostic.presentation_label())
            }
        }
    }
}

impl brokk_bifrost_core::analyzer::reuse_verdict::CarriesReuseVerdict for DiagnosticRef<'_> {
    fn reuse_verdict(&self) -> brokk_bifrost_core::analyzer::reuse_verdict::ReuseVerdict {
        if self.incompleteness().execution_cause().is_some() {
            super::super::EXECUTION_DEPENDENT
        } else {
            brokk_bifrost_core::analyzer::reuse_verdict::ReuseVerdict::Content
        }
    }
}

impl Serialize for DiagnosticRef<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Semantic(diagnostic) => diagnostic.serialize(serializer),
            Self::Presentation(diagnostic) => diagnostic.serialize(serializer),
        }
    }
}

#[derive(Clone)]
#[expect(
    clippy::large_enum_variant,
    reason = "semantic extraction moves its existing diagnostic without a new box allocation"
)]
pub enum DiagnosticHandle {
    Semantic(CodeQueryDiagnostic),
    Presentation(PresentationDiagnostic),
}

impl std::fmt::Debug for DiagnosticHandle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self.as_diagnostic_ref(), formatter)
    }
}

impl DiagnosticHandle {
    pub fn as_diagnostic_ref(&self) -> DiagnosticRef<'_> {
        match self {
            Self::Semantic(diagnostic) => DiagnosticRef::Semantic(diagnostic),
            Self::Presentation(diagnostic) => DiagnosticRef::Presentation(*diagnostic),
        }
    }
}

#[derive(Clone)]
pub struct DiagnosticIter<'a> {
    semantic: std::slice::Iter<'a, CodeQueryDiagnostic>,
    presentation: Option<PresentationDiagnostic>,
}

impl<'a> Iterator for DiagnosticIter<'a> {
    type Item = DiagnosticRef<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.semantic
            .next()
            .map(DiagnosticRef::Semantic)
            .or_else(|| self.presentation.take().map(DiagnosticRef::Presentation))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let length = self.semantic.len() + usize::from(self.presentation.is_some());
        (length, Some(length))
    }
}

impl ExactSizeIterator for DiagnosticIter<'_> {}

impl<'a> IntoIterator for &'a QueryDiagnostics {
    type Item = DiagnosticRef<'a>;
    type IntoIter = DiagnosticIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

pub struct DiagnosticIntoIter {
    semantic: std::vec::IntoIter<CodeQueryDiagnostic>,
    presentation: Option<PresentationDiagnostic>,
}

impl Iterator for DiagnosticIntoIter {
    type Item = DiagnosticHandle;

    fn next(&mut self) -> Option<Self::Item> {
        self.semantic
            .next()
            .map(DiagnosticHandle::Semantic)
            .or_else(|| self.presentation.take().map(DiagnosticHandle::Presentation))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let length = self.semantic.len() + usize::from(self.presentation.is_some());
        (length, Some(length))
    }
}

impl ExactSizeIterator for DiagnosticIntoIter {}

impl IntoIterator for QueryDiagnostics {
    type Item = DiagnosticHandle;
    type IntoIter = DiagnosticIntoIter;

    fn into_iter(self) -> Self::IntoIter {
        DiagnosticIntoIter {
            semantic: self.semantic.into_iter(),
            presentation: self.presentation,
        }
    }
}

impl Serialize for QueryDiagnostics {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.len()))?;
        for diagnostic in self {
            sequence.serialize_element(&diagnostic)?;
        }
        sequence.end()
    }
}

impl JsonSchema for QueryDiagnostics {
    fn inline_schema() -> bool {
        <Vec<CodeQueryDiagnostic>>::inline_schema()
    }
    fn schema_name() -> std::borrow::Cow<'static, str> {
        <Vec<CodeQueryDiagnostic>>::schema_name()
    }
    fn schema_id() -> std::borrow::Cow<'static, str> {
        <Vec<CodeQueryDiagnostic>>::schema_id()
    }
    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        <Vec<CodeQueryDiagnostic>>::json_schema(generator)
    }
}

#[cfg(test)]
mod presentation_diagnostic_carrier_tests {
    use super::*;

    #[test]
    fn static_presentation_diagnostics_keep_the_legacy_array_schema_and_wire_fields() {
        assert!(!std::mem::needs_drop::<PresentationDiagnostic>());
        for (kind, code, cause, message) in [
            (
                PresentationDiagnostic::RowsRefused,
                "presentation_rows_refused",
                DiagnosticExecutionCause::Budget,
                "site presentation could not retain the requested payload",
            ),
            (
                PresentationDiagnostic::SourceTextRefused,
                "presentation_rows_refused",
                DiagnosticExecutionCause::Budget,
                "site source text could not be admitted for presentation; structural roles and values are retained",
            ),
            (
                PresentationDiagnostic::OwnerUnavailable,
                "presentation_owner_unavailable",
                DiagnosticExecutionCause::Provider,
                "site presentation has no analyzer retention owner",
            ),
        ] {
            let mut diagnostics = QueryDiagnostics::default();
            diagnostics.set_presentation(kind);
            assert!(diagnostics.semantic.is_empty());
            assert_eq!(diagnostics.semantic.capacity(), 0);
            let mut expected = serde_json::json!({
                "incompleteness": Incompleteness::Operational(cause),
                "code": code,
                "impact": "incomplete",
                "language": "workspace",
                "message": message,
            });
            if kind != PresentationDiagnostic::OwnerUnavailable {
                expected["exhausted_roots"] = serde_json::json!([{
                    "path": ".",
                    "lane": "render/site_output/retained_bytes",
                    "stage": "result_presentation",
                }]);
            }
            assert_eq!(
                serde_json::to_value(&diagnostics).unwrap(),
                serde_json::json!([expected])
            );
            let borrowed = diagnostics.iter().next().unwrap();
            assert_eq!(borrowed.message(), message);
            assert_eq!(
                borrowed.incompleteness(),
                Incompleteness::Operational(cause)
            );
            assert!(borrowed.source().is_none());
            assert!(borrowed.withheld_rows_path().is_none());
            assert!(borrowed.step_index().is_none() && borrowed.step_op().is_none());
            assert!(borrowed.cause_codes().is_empty());
            assert!(matches!(
                borrowed.presentation_label(),
                std::borrow::Cow::Borrowed(_)
            ));
            let detached = diagnostics.clone().into_iter().next().unwrap();
            drop(diagnostics);
            assert_eq!(detached.as_diagnostic_ref().message(), message);
            assert!(matches!(detached, DiagnosticHandle::Presentation(_)));
        }
        assert_eq!(
            schemars::schema_for!(QueryDiagnostics),
            schemars::schema_for!(Vec<CodeQueryDiagnostic>),
        );
    }

    #[test]
    fn semantic_conversion_preserves_legacy_values_and_refuses_presentation_leakage() {
        let semantic = incomplete_diagnostic(
            CodeQueryDiagnosticCode::HierarchyIncomplete,
            Incompleteness::Content,
            "java",
            "the original semantic gap".to_owned(),
            Vec::new(),
        );
        let raw = vec![semantic];
        let expected_debug = format!("{raw:?}");
        let expected = serde_json::to_value(&raw).unwrap();
        let mut diagnostics = QueryDiagnostics::from(raw);
        assert_eq!(format!("{diagnostics:?}"), expected_debug);
        assert_eq!(serde_json::to_value(&diagnostics).unwrap(), expected);
        assert_eq!(diagnostics.semantic().len(), 1);
        diagnostics.semantic_mut()[0].step_index = Some(2);
        assert_eq!(diagnostics.clone().into_semantic()[0].step_index, Some(2));
        diagnostics.set_presentation(PresentationDiagnostic::SourceTextRefused);
        diagnostics.set_presentation(PresentationDiagnostic::RowsRefused);
        diagnostics.set_presentation(PresentationDiagnostic::SourceTextRefused);
        assert_eq!(diagnostics.len(), 2);
        assert_eq!(diagnostics.iter().count(), 2);
        assert_eq!(
            diagnostics.iter().nth(1).unwrap().message(),
            PresentationDiagnostic::RowsRefused.message()
        );
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                diagnostics.clone().into_semantic()
            }))
            .is_err()
        );
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| { diagnostics.semantic() }))
                .is_err()
        );
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                diagnostics.semantic_mut().clear();
            }))
            .is_err()
        );
        assert_eq!(
            diagnostics.iter().next().unwrap().code(),
            CodeQueryDiagnosticCode::HierarchyIncomplete
        );
    }
}

macro_rules! saturating_add_work {
    ($left:ident, $right:ident; [$($field:ident),* $(,)?]; [$($flag:ident),* $(,)?] $(; [$($peak:ident),* $(,)?])?) => {
        Self {
            $($field: $left.$field.saturating_add($right.$field),)*
            $($flag: $left.$flag || $right.$flag,)*
            $($($peak: $left.$peak.component_max($right.$peak),)*)?
        }
    };
}

macro_rules! saturating_sub_work {
    ($left:ident, $right:ident; [$($field:ident),* $(,)?]; [$($flag:ident),* $(,)?] $(; [$($peak:ident),* $(,)?])?) => {
        Self {
            $($field: $left.$field.saturating_sub($right.$field),)*
            $($flag: $left.$flag && !$right.$flag,)*
            $($($peak: $left.$peak,)*)?
        }
    };
}

/// Declare one labeled CodeQuery diagnostic vocabulary once.
///
/// The variant list, each variant's wire label, the complete label inventory,
/// and the `as_str` projection all come from the single table below. A new
/// variant therefore cannot reach the wire without also reaching `LABELS`,
/// which is the inventory the Python client's parity test mirrors (#2898).
macro_rules! code_query_labeled_enum {
    (
        $(#[$meta:meta])*
        $name:ident {
            $($variant:ident => $label:literal,)+
        }
    ) => {
        $(#[$meta])*
        pub enum $name {
            $($variant,)+
        }

        impl $name {
            /// Every label this vocabulary publishes, in declaration order.
            pub const LABELS: &'static [&'static str] = &[$($label,)+];

            /// The `snake_case` label this variant serializes as.
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $label,)+
                }
            }
        }
    };
}

code_query_labeled_enum! {
    #[derive(
        Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
    )]
    #[serde(rename_all = "snake_case")]
    CodeQueryDiagnosticCode {
        PolicyDeclaredProvenSubset => "policy_declared_proven_subset",
        InvalidPlan => "invalid_plan",
        Cancelled => "cancelled",
        UnsupportedStructuralFeature => "unsupported_structural_feature",
        QualifyingTypeUnresolved => "qualifying_type_unresolved",
        StructuralRoleCoverageIncomplete => "structural_role_coverage_incomplete",
        MissingStructuralAdapter => "missing_structural_adapter",
        RecoveredSyntaxIncomplete => "recovered_syntax_incomplete",
        UnsupportedImportAnalysis => "unsupported_import_analysis",
        DynamicImportTarget => "dynamic_import_target",
        HierarchyIncomplete => "hierarchy_incomplete",
        SemanticResultsOmitted => "semantic_results_omitted",
        SemanticWorkspaceRequired => "semantic_workspace_required",
        NoEnclosingProcedure => "no_enclosing_procedure",
        SemanticCapabilityUnsupported => "semantic_capability_unsupported",
        SemanticAnalysisPartial => "semantic_analysis_partial",
        CallBindingDispatchPartial => "call_binding_dispatch_partial",
        CallBindingSelectorRejected => "call_binding_selector_rejected",
        SemanticBudgetExhausted => "semantic_budget_exhausted",
        SemanticProviderFailed => "semantic_provider_failed",
        SemanticPackAcquisitionPending => "semantic_pack_acquisition_pending",
        SemanticPackActivationFailed => "semantic_pack_activation_failed",
        WorkspaceSemanticModelsNotLoaded => "workspace_semantic_models_not_loaded",
        UnresolvedProtocolReference => "unresolved_protocol_reference",
        TypestateRegistrationStale => "typestate_registration_stale",
        TypestateHandleStale => "typestate_handle_stale",
        TypestateRootMismatch => "typestate_root_mismatch",
        TypestateCapabilityUnsupported => "typestate_capability_unsupported",
        TypestateAnalysisPartial => "typestate_analysis_partial",
        TypestateProviderFailed => "typestate_provider_failed",
        TypestateSolverBudgetExhausted => "typestate_solver_budget_exhausted",
        TypestateFindingBudgetExhausted => "typestate_finding_budget_exhausted",
        TypestateWitnessTruncated => "typestate_witness_truncated",
        UnresolvedValueFlowPlanReference => "unresolved_value_flow_plan_reference",
        ValueFlowRegistrationStale => "value_flow_registration_stale",
        ValueFlowHandleStale => "value_flow_handle_stale",
        ValueFlowRootMismatch => "value_flow_root_mismatch",
        ValueFlowCapabilityUnsupported => "value_flow_capability_unsupported",
        ValueFlowAnalysisPartial => "value_flow_analysis_partial",
        ValueFlowProviderFailed => "value_flow_provider_failed",
        ValueFlowSolverBudgetExhausted => "value_flow_solver_budget_exhausted",
        ValueFlowWitnessTruncated => "value_flow_witness_truncated",
        TypeFlowWitnessTruncated => "type_flow_witness_truncated",
        TypeFlowWitnessUnavailable => "type_flow_witness_unavailable",
        DerivedCacheRebuilt => "derived_cache_rebuilt",
        UnresolvedTaintResultReference => "unresolved_taint_result_reference",
        TaintRegistrationStale => "taint_registration_stale",
        TaintHandleStale => "taint_handle_stale",
        TaintRootMismatch => "taint_root_mismatch",
        TaintPlanReportMismatch => "taint_plan_report_mismatch",
        TaintProjectionFailed => "taint_projection_failed",
        TaintFindingTruncated => "taint_finding_truncated",
        ReceiverAnalysisPartial => "receiver_analysis_partial",
        ReceiverAnalysisFailed => "receiver_analysis_failed",
        CallRelationBudgetExhausted => "call_relation_budget_exhausted",
        CallRelationParseFailed => "call_relation_parse_failed",
        CallRelationCandidatesOmitted => "call_relation_candidates_omitted",
        CallRelationTargetsAmbiguous => "call_relation_targets_ambiguous",
        CallRelationCandidateLimit => "call_relation_candidate_limit",
        CallRelationAnalysisFailed => "call_relation_analysis_failed",
        PresentationRowsRefused => "presentation_rows_refused",
        PresentationOwnerUnavailable => "presentation_owner_unavailable",
        RenderedCapturesTruncated => "rendered_captures_truncated",
        ReferenceSourceBytesTruncated => "reference_source_bytes_truncated",
        ReferenceCandidateFilesTruncated => "reference_candidate_files_truncated",
        ReferenceCandidatesOmitted => "reference_candidates_omitted",
        ReferenceTargetsAmbiguous => "reference_targets_ambiguous",
        ReferenceCallsiteLimit => "reference_callsite_limit",
        ReferenceAnalysisFailed => "reference_analysis_failed",
        ReferenceKindUndecided => "reference_kind_undecided",
        StepProducedNoRows => "step_produced_no_rows",
        EnclosingPatternUndecided => "enclosing_pattern_undecided",
        IdenticalCapturesOpen => "identical_captures_open",
        RowPredicateUndecided => "row_predicate_undecided",
        MemberFormUndecided => "member_form_undecided",
        UsesParserUnsupported => "uses_parser_unsupported",
        UsesCandidateLimit => "uses_candidate_limit",
        UsesTargetsAmbiguous => "uses_targets_ambiguous",
        UsesCandidateUnavailable => "uses_candidate_unavailable",
UsesCandidateIncomplete => "uses_candidate_incomplete",
UsesCandidateUnresolved => "uses_candidate_unresolved",
UsesReferenceProjectionMissing => "uses_reference_projection_missing",
UsesDefinitionProjectionMissing => "uses_definition_projection_missing",
UsesInverseUnconfirmed => "uses_inverse_unconfirmed",
UsesIndexedSourceUnavailable => "uses_indexed_source_unavailable",
UsesTargetRangeUnavailable => "uses_target_range_unavailable",
        ExecutionBudgetExhausted => "execution_budget_exhausted",
        PipelineBudgetExhausted => "pipeline_budget_exhausted",
        ImportGraphBudgetExhausted => "import_graph_budget_exhausted",
        OccurrenceRoleUnsupported => "occurrence_role_unsupported",
        OccurrenceResolutionIncomplete => "occurrence_resolution_incomplete",
        OccurrenceRowBudgetExhausted => "occurrence_row_budget_exhausted",
        EnvironmentAxisUnsupported => "environment_axis_unsupported",
        MaterializationAxisUnsupported => "materialization_axis_unsupported",
        MaterializationDerivationIncomplete => "materialization_derivation_incomplete",
        MaterializationRowBudgetExhausted => "materialization_row_budget_exhausted",
        EnvironmentDerivationIncomplete => "environment_derivation_incomplete",
        EnvironmentBoundedWorkLimit => "environment_bounded_work_limit",
        EnvironmentRowBudgetExhausted => "environment_row_budget_exhausted",
        ResolutionTraceIncomplete => "resolution_trace_incomplete",
        PythonHierarchyDerivationIncomplete => "python_hierarchy_derivation_incomplete",
        EdgeAxisUnsupported => "edge_axis_unsupported",
        EdgeDerivationIncomplete => "edge_derivation_incomplete",
        FlowStateAxisUnsupported => "flow_state_axis_unsupported",
        FlowStateDerivationIncomplete => "flow_state_derivation_incomplete",
        RewriteDomainUnsupported => "rewrite_domain_unsupported",
        RewritePathDerivationIncomplete => "rewrite_path_derivation_incomplete",
        ControlRelationDerivationIncomplete => "control_relation_derivation_incomplete",
        BranchRelationDerivationIncomplete => "branch_relation_derivation_incomplete",
        LoopRelationDerivationIncomplete => "loop_relation_derivation_incomplete",
        FailureHandlerDerivationIncomplete => "failure_handler_derivation_incomplete",
        StatementReachabilityDerivationIncomplete => "statement_reachability_derivation_incomplete",
        PendingCleanupFlowDerivationIncomplete => "pending_cleanup_flow_derivation_incomplete",
        ControlRelationExitPartitionPartial => "control_relation_exit_partition_partial",
        TopologyDerivationIncomplete => "topology_derivation_incomplete",
        TopologyOwnershipAmbiguous => "topology_ownership_ambiguous",
        IdentityAxisUnsupported => "identity_axis_unsupported",
        PathDerivationIncomplete => "path_derivation_incomplete",
        EffectDerivationIncomplete => "effect_derivation_incomplete",
        ResultContractDerivationIncomplete => "result_contract_derivation_incomplete",
        ResultObligationDerivationIncomplete => "result_obligation_derivation_incomplete",
        EffectBudgetExhausted => "effect_budget_exhausted",
        CallShapeCoverageIncomplete => "call_shape_coverage_incomplete",
        JsxProjectionIncomplete => "jsx_projection_incomplete",
        CrossDomainBindingUnproven => "cross_domain_binding_unproven",
        CrossDomainKeyUnsupported => "cross_domain_key_unsupported",
        CrossDomainDocumentIncomplete => "cross_domain_document_incomplete",
        CrossDomainCorrelationAmbiguous => "cross_domain_correlation_ambiguous",
        ResultLimitReached => "result_limit_reached",
        BroadQuery => "broad_query",
    }
}

impl CodeQueryDiagnosticCode {
    /// Codes whose meaning is inherently operational, independent of content.
    /// Partial content/operational outcomes use the diagnostic's explicit
    /// Incompleteness instead of blanket classification by code.
    pub const fn is_execution_state(self) -> bool {
        self.inherent_execution_cause().is_some()
    }
    pub const fn inherent_execution_cause(self) -> Option<DiagnosticExecutionCause> {
        match self {
            Self::Cancelled => Some(DiagnosticExecutionCause::Cancelled),
            Self::SemanticBudgetExhausted
            | Self::TypestateSolverBudgetExhausted
            | Self::TypestateFindingBudgetExhausted
            | Self::TypestateWitnessTruncated
            | Self::ValueFlowSolverBudgetExhausted
            | Self::ValueFlowWitnessTruncated
            | Self::TypeFlowWitnessTruncated
            | Self::TaintFindingTruncated
            | Self::CallRelationBudgetExhausted
            | Self::CallRelationCandidateLimit
            | Self::PresentationRowsRefused
            | Self::RenderedCapturesTruncated
            | Self::ReferenceSourceBytesTruncated
            | Self::ReferenceCandidateFilesTruncated
            | Self::ReferenceCallsiteLimit
            | Self::UsesCandidateLimit
            | Self::ExecutionBudgetExhausted
            | Self::PipelineBudgetExhausted
            | Self::ImportGraphBudgetExhausted
            | Self::OccurrenceRowBudgetExhausted
            | Self::MaterializationRowBudgetExhausted
            | Self::EnvironmentRowBudgetExhausted
            | Self::EffectBudgetExhausted => Some(DiagnosticExecutionCause::Budget),
            Self::PresentationOwnerUnavailable
            | Self::SemanticProviderFailed
            | Self::SemanticPackAcquisitionPending
            | Self::SemanticPackActivationFailed
            | Self::UnresolvedProtocolReference
            | Self::TypestateProviderFailed
            | Self::UnresolvedValueFlowPlanReference
            | Self::ValueFlowProviderFailed
            | Self::UnresolvedTaintResultReference
            | Self::TaintPlanReportMismatch
            | Self::ReceiverAnalysisFailed
            | Self::CallRelationAnalysisFailed
            | Self::ReferenceAnalysisFailed => Some(DiagnosticExecutionCause::Provider),
            Self::TypestateRegistrationStale
            | Self::TypestateHandleStale
            | Self::TypestateRootMismatch
            | Self::ValueFlowRegistrationStale
            | Self::ValueFlowHandleStale
            | Self::ValueFlowRootMismatch
            | Self::TaintRegistrationStale
            | Self::TaintHandleStale
            | Self::TaintRootMismatch => Some(DiagnosticExecutionCause::Snapshot),
            _ => None,
        }
    }

    pub(crate) fn from_execution_reason(
        family: Self,
        reason: &str,
    ) -> (
        Self,
        Option<brokk_bifrost_analysis::analyzer::read_ledger::DerivationExecutionCause>,
    ) {
        (
            family,
            brokk_bifrost_analysis::analyzer::read_ledger::DerivationExecutionCause::from_reason(
                reason,
            ),
        )
    }
}

code_query_labeled_enum! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
    #[serde(rename_all = "snake_case")]
    CodeQueryDiagnosticImpact {
        Advisory => "advisory",
        DeclaredNonExhaustive => "declared_non_exhaustive",
        Incomplete => "incomplete",
        Invalid => "invalid",
    }
}

/// Why a producer could not close a partial result. Content gaps are stable
/// under their recorded reads; operational stops cannot authorize unit reuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Incompleteness {
    Content,
    /// A terminal result cap, whose replay requires a recorded grant.
    ConfiguredCap,
    Operational(DiagnosticExecutionCause),
}

pub use brokk_bifrost_analysis::analyzer::read_ledger::DerivationExecutionCause as DiagnosticExecutionCause;

impl Incompleteness {
    pub(crate) fn combine(self, other: Self) -> Self {
        match self {
            Self::Operational(_) => self,
            Self::Content => other,
            Self::ConfiguredCap => match other {
                Self::Operational(_) => other,
                _ => self,
            },
        }
    }

    pub(crate) fn from_execution_reason(reason: &str) -> Self {
        match DiagnosticExecutionCause::from_reason(reason) {
            Some(cause) => Self::Operational(cause),
            None => Self::Content,
        }
    }

    /// The producer's cause, also used by reuse admission and timing output.
    pub const fn execution_cause(self) -> Option<DiagnosticExecutionCause> {
        match self {
            Self::Content | Self::ConfiguredCap => None,
            Self::Operational(cause) => Some(cause),
        }
    }
}

#[derive(Debug, Clone)]
pub enum UsesOmissionEvidence {
    Unavailable {
        inventory_evidence:
            Option<crate::analyzer::store::resolution_operation::ReferenceInventoryCompleteness>,
    },
    Incomplete {
        evidence: Option<crate::analyzer::usages::get_definition::DefinitionLookupEvidence>,
    },
    Unresolved {
        status: crate::analyzer::usages::get_definition::DefinitionLookupStatus,
    },
    ReferenceProjectionMissing,
    DefinitionProjectionMissing,
    InverseUnconfirmed {
        target: CodeUnit,
        range: (usize, usize),
    },
    IndexedSourceUnavailable,
    TargetRangeUnavailable,
}

#[derive(Debug, Clone)]
pub struct UsesOmissionSite {
    pub range: Option<(usize, usize)>,
    pub evidence: UsesOmissionEvidence,
}

#[derive(Clone, Serialize, JsonSchema)]
pub struct CodeQueryDiagnostic {
    /// A native non-UTF-8 call site was refused. Such sites have no report
    /// location and are excluded from the exact rendered omission count.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub has_non_utf8_refusal: bool,
    /// Query-local call-shape keys. Never written to a unit product.
    #[serde(skip)]
    #[schemars(skip)]
    pub refusal_sites: std::collections::BTreeSet<String>,
    #[serde(skip)]
    #[schemars(skip)]
    pub uses_omissions: Vec<UsesOmissionSite>,
    /// Internal attribution used when promoting call ambiguity impact. It is
    /// not part of the public wire representation or rendered evidence.
    #[serde(skip)]
    #[schemars(skip)]
    pub call_relation_facts: Option<
        Box<brokk_bifrost_analysis::analyzer::usages::call_relations::CallRelationDiagnosticFacts>,
    >,
    /// Producer-owned admission provenance. Missing provenance rejects replay.
    pub incompleteness: Incompleteness,
    pub code: CodeQueryDiagnosticCode,
    pub impact: CodeQueryDiagnosticImpact,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[schemars(default)]
    pub branch: Vec<usize>,
    pub language: &'static str,
    pub message: String,
    /// Exact source site responsible for this diagnostic, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<CodeQuerySourceSpan>,
    /// Complete attribution of the evidence that left this result open.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub related: Vec<CodeQueryRelatedSource>,
    /// Every root or file whose exhausted work produced this diagnostic.
    ///
    /// A budget diagnostic that says only that some budget ran out cannot be
    /// acted on: attributing one required an instrumented build (#3194). The
    /// list carries the complete attribution, and the message renders it one
    /// line per entry up to the prose bound a policy report allows. Empty for
    /// every diagnostic that is not about exhausted work.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exhausted_roots: Vec<CodeQueryExhaustedRoot>,
    /// The one workspace-relative file every row this diagnostic withheld
    /// lies in, when the producer knows it (#5451).
    ///
    /// An incomplete diagnostic means its step left rows out or open. When
    /// this is set, every such row is a row of this file, spelled as the
    /// row's own `path`, so a reader may confine the gap to it. The executor
    /// clears it once a later operator is not row-local, because that
    /// operator's rows are no longer the ones withheld. Absent means the
    /// withheld rows may lie anywhere.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub withheld_rows_path: Option<String>,
    /// Zero-based index of the authored step this diagnostic belongs to,
    /// within the `steps` array of the plan or branch that owns the step.
    /// Absent on request-level diagnostics.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step_index: Option<usize>,
    /// Canonical op label of the authored step at `step_index`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step_op: Option<String>,
    /// Why the step produced no rows. Set only on `step_produced_no_rows`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_rows_reason: Option<CodeQueryStepNoRowsReason>,
    /// Codes of the step's own incomplete diagnostics that left it without
    /// rows, in first-seen order. Set only for the `incomplete` reason.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(default)]
    pub cause_codes: Vec<CodeQueryDiagnosticCode>,
}

/// Why an authored step turned a non-empty input into no rows.
#[cfg_attr(feature = "query-result-fixtures", derive(Default))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CodeQueryStepNoRowsReason {
    /// The step itself reported incomplete work.
    Incomplete,
    /// The step's relation or lookup produced no rows, including after the
    /// step's own inline conditions.
    #[cfg_attr(feature = "query-result-fixtures", default)]
    NoMatchingRows,
    /// A standalone row-selecting step (`filter`, `identical_captures`,
    /// `resolved_call`, `resolved_value`, `call_argument`) rejected all of its
    /// input rows.
    AllInputsFiltered,
}

impl CodeQueryDiagnostic {
    /// Preserve the producer's typed admission metadata. A presentation code
    /// cannot decide whether a mixed outcome is content or execution-dependent.
    pub const fn new(diagnostic: Self) -> Self {
        diagnostic
    }

    /// Drop `step_produced_no_rows` advisories and clear step attribution on
    /// the remaining diagnostics so policy consumers keep whole and unit-sliced
    /// runs identical.
    pub fn strip_step_attribution(diagnostics: &mut Vec<Self>) {
        diagnostics.retain_mut(|diagnostic| {
            if diagnostic.code == CodeQueryDiagnosticCode::StepProducedNoRows {
                return false;
            }
            diagnostic.step_index = None;
            diagnostic.step_op = None;
            diagnostic.no_rows_reason = None;
            diagnostic.cause_codes.clear();
            true
        });
    }
}

/// An execution-state diagnostic is execution dependent: the query marks
/// every one it returns (`QueryExecutionState::diagnostic`).
impl brokk_bifrost_core::analyzer::reuse_verdict::CarriesReuseVerdict for CodeQueryDiagnostic {
    fn reuse_verdict(&self) -> brokk_bifrost_core::analyzer::reuse_verdict::ReuseVerdict {
        if self.incompleteness.execution_cause().is_some() {
            super::super::EXECUTION_DEPENDENT
        } else {
            brokk_bifrost_core::analyzer::reuse_verdict::ReuseVerdict::Content
        }
    }
}

/// `step_index` and `step_op` say where a diagnostic was seen, not what it
/// says, so they stay out of identity: a diagnostic one capability raises in
/// several steps is still one diagnostic when results are deduplicated, and
/// the first one seen keeps its attribution.
impl PartialEq for CodeQueryDiagnostic {
    fn eq(&self, other: &Self) -> bool {
        let Self {
            has_non_utf8_refusal,
            refusal_sites: _,
            call_relation_facts: _,
            incompleteness: _,
            uses_omissions: _,
            code,
            impact,
            branch,
            language,
            message,
            source,
            related,
            exhausted_roots,
            withheld_rows_path,
            step_index: _,
            step_op: _,
            no_rows_reason,
            cause_codes,
        } = self;
        has_non_utf8_refusal == &other.has_non_utf8_refusal
            && code == &other.code
            && impact == &other.impact
            && branch == &other.branch
            && language == &other.language
            && message == &other.message
            && source == &other.source
            && related == &other.related
            && exhausted_roots == &other.exhausted_roots
            && withheld_rows_path == &other.withheld_rows_path
            && no_rows_reason == &other.no_rows_reason
            && cause_codes == &other.cause_codes
    }
}
impl Eq for CodeQueryDiagnostic {}
impl std::hash::Hash for CodeQueryDiagnostic {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        let Self {
            has_non_utf8_refusal,
            refusal_sites: _,
            call_relation_facts: _,
            incompleteness: _,
            uses_omissions: _,
            code,
            impact,
            branch,
            language,
            message,
            source,
            related,
            exhausted_roots,
            withheld_rows_path,
            step_index: _,
            step_op: _,
            no_rows_reason,
            cause_codes,
        } = self;
        std::hash::Hash::hash(has_non_utf8_refusal, state);
        std::hash::Hash::hash(code, state);
        std::hash::Hash::hash(impact, state);
        std::hash::Hash::hash(branch, state);
        std::hash::Hash::hash(language, state);
        std::hash::Hash::hash(message, state);
        std::hash::Hash::hash(source, state);
        std::hash::Hash::hash(related, state);
        std::hash::Hash::hash(exhausted_roots, state);
        std::hash::Hash::hash(withheld_rows_path, state);
        std::hash::Hash::hash(no_rows_reason, state);
        std::hash::Hash::hash(cause_codes, state);
    }
}

impl std::fmt::Debug for CodeQueryDiagnostic {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut diagnostic = formatter.debug_struct("CodeQueryDiagnostic");
        diagnostic
            .field("code", &self.code)
            .field("impact", &self.impact)
            .field("branch", &self.branch)
            .field("language", &self.language)
            .field("message", &self.message);
        // Selector prose embeds Debug output. Keep absent optional source
        // out of that prose while retaining complete attributed source spans.
        if self.source.is_some() {
            diagnostic.field("source", &self.source);
        }
        if !self.related.is_empty() {
            diagnostic.field("related", &self.related);
        }
        if self.has_non_utf8_refusal {
            diagnostic.field("has_non_utf8_refusal", &true);
        }
        diagnostic.field("exhausted_roots", &self.exhausted_roots);
        if self.withheld_rows_path.is_some() {
            diagnostic.field("withheld_rows_path", &self.withheld_rows_path);
        }
        if self.step_index.is_some() {
            diagnostic.field("step_index", &self.step_index);
        }
        if self.step_op.is_some() {
            diagnostic.field("step_op", &self.step_op);
        }
        if self.no_rows_reason.is_some() {
            diagnostic.field("no_rows_reason", &self.no_rows_reason);
        }
        if !self.cause_codes.is_empty() {
            diagnostic.field("cause_codes", &self.cause_codes);
        }
        diagnostic.finish()
    }
}

/// An exact workspace-relative source span shared by query diagnostics and evidence.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct CodeQuerySourceSpan {
    pub path: String,
    pub range: CodeQueryRange,
    pub start_byte: usize,
    pub end_byte: usize,
}

/// One source that explains a diagnostic's incompleteness.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct CodeQueryRelatedSource {
    pub source: CodeQuerySourceSpan,
    pub label: String,
}

/// One root or file whose work stopped against a named limit.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct CodeQueryExhaustedRoot {
    /// The workspace-relative path of the file the work belonged to.
    pub path: String,
    /// The qualified name of the procedure that was the analysis root.
    /// Absent when the exhausted work is file-scoped rather than per root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub procedure: Option<String>,
    /// The exhausted lane, `<budget>/<dimension>`, for example
    /// `solver/reached_states`, `semantic/nested_entries`, or
    /// `semantic/retained_bytes`.
    pub lane: String,
    /// The stage of the analysis that charged the lane, for example
    /// `plan_refinement` or `value_flow_solve`. Absent when the emitting
    /// analysis has one stage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stage: Option<String>,
    /// The consumed counter and the tested allowance, when recorded at admission.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget: Option<CodeQueryExhaustedBudget>,
    /// The charge that did not fit, and the limit it was checked against.
    /// Absent when the producing code records the stop without a charge.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub charge: Option<CodeQueryExhaustedCharge>,
    /// The feedback iteration whose plan produced the stop, counting from
    /// zero. Absent for an analysis without feedback iterations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub feedback_iteration: Option<usize>,
}

/// Usage observed at a refusing admission, in that admission's budget scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct CodeQueryExhaustedBudget {
    pub consumed: usize,
    pub limit: usize,
}

/// The exact charge one lane refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct CodeQueryExhaustedCharge {
    pub attempted: usize,
    pub limit: usize,
}

impl CodeQueryExhaustedRoot {
    /// Cancellation shares the root-attribution wire, but refuses no budget.
    pub fn is_budget_refusal(&self) -> bool {
        self.lane != "solver/cancelled"
    }

    /// The one-line rendering the diagnostic message carries.
    pub fn render(&self) -> String {
        let mut line = self.path.clone();
        if let Some(procedure) = &self.procedure {
            line.push_str(&format!(" {procedure}"));
        }
        line.push_str(&format!(" lane {}", self.lane));
        if let Some(stage) = &self.stage {
            line.push_str(&format!(" stage {stage}"));
        }
        if let Some(budget) = self.budget {
            line.push_str(&format!(
                " consumed {} limit {}",
                budget.consumed, budget.limit
            ));
        }
        match self.charge {
            Some(charge) => line.push_str(&format!(
                " charged {} limit {}",
                charge.attempted, charge.limit
            )),
            None if self.budget.is_none() => line.push_str(" charge unrecorded"),
            None => {}
        }
        if let Some(iteration) = self.feedback_iteration {
            line.push_str(&format!(" iteration {iteration}"));
        }
        line
    }
}

/// Prose bound for one diagnostic message that lists entries. A policy report
/// validates its diagnostic prose against `MAX_REPORT_PROSE_BYTES` (4 KiB) and
/// drops a longer one, so a rendered list stops short of that. An exhausted-work
/// message keeps the complete attribution in `exhausted_roots`.
pub const MAX_DIAGNOSTIC_LIST_MESSAGE_BYTES: usize = 3_584;

/// Render one exhausted-work diagnostic message: the reason, then one line
/// per attributed entry. The result is bounded by `max_bytes` provided the
/// reason/count header plus an elision line fits within that bound. Product
/// callers use short fixed reasons and `MAX_DIAGNOSTIC_LIST_MESSAGE_BYTES`
/// so a policy report keeps the prose it validates (`MAX_REPORT_PROSE_BYTES`).
/// Entries the bound cuts stay in `exhausted_roots`.
pub fn render_exhausted_roots(
    reason: &str,
    roots: &[CodeQueryExhaustedRoot],
    max_bytes: usize,
) -> String {
    let noun = if roots.len() == 1 { "root" } else { "roots" };
    let mut message = format!("{reason} in {} {noun}", roots.len());
    for (index, root) in roots.iter().enumerate() {
        let line = format!("\n- {}", root.render());
        let remaining = roots.len() - index;
        let elision = format!("\n- [{remaining} more in exhausted_roots]");
        if message.len() + line.len() + elision.len() > max_bytes {
            message.push_str(&elision);
            break;
        }
        message.push_str(&line);
    }
    message
}

/// Read one diagnostic back, resolving its language label to the one static
/// spelling this crate emits.
///
/// Written by hand because the label is a `&'static str`: a derived reader
/// would demand that every input outlive the program. A diagnostic names the
/// language whose analysis produced it, or one of the two whole-execution
/// labels, so a label that is neither is a row this build did not write -- an
/// error, never a label invented at load time. (`Box::leak` would answer any
/// string at the cost of leaking one allocation per corrupt row.)
impl<'de> Deserialize<'de> for CodeQueryDiagnostic {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            #[serde(default)]
            has_non_utf8_refusal: bool,
            incompleteness: Incompleteness,
            code: CodeQueryDiagnosticCode,
            impact: CodeQueryDiagnosticImpact,
            #[serde(default)]
            branch: Vec<usize>,
            language: String,
            message: String,
            #[serde(default)]
            source: Option<CodeQuerySourceSpan>,
            #[serde(default)]
            related: Vec<CodeQueryRelatedSource>,
            #[serde(default)]
            exhausted_roots: Vec<CodeQueryExhaustedRoot>,
            #[serde(default)]
            withheld_rows_path: Option<String>,
            #[serde(default)]
            step_index: Option<usize>,
            #[serde(default)]
            step_op: Option<String>,
            #[serde(default)]
            no_rows_reason: Option<CodeQueryStepNoRowsReason>,
            #[serde(default)]
            cause_codes: Vec<CodeQueryDiagnosticCode>,
        }

        let wire = Wire::deserialize(deserializer)?;
        let language = static_language_label(&wire.language).ok_or_else(|| {
            serde::de::Error::custom(format!(
                "unknown code query diagnostic language `{}`",
                wire.language
            ))
        })?;
        Ok(Self {
            has_non_utf8_refusal: wire.has_non_utf8_refusal,
            refusal_sites: Default::default(),
            call_relation_facts: None,
            uses_omissions: Vec::new(),
            incompleteness: wire.incompleteness,
            code: wire.code,
            impact: wire.impact,
            branch: wire.branch,
            language,
            message: wire.message,
            source: wire.source,
            related: wire.related,
            exhausted_roots: wire.exhausted_roots,
            withheld_rows_path: wire.withheld_rows_path,
            step_index: wire.step_index,
            step_op: wire.step_op,
            no_rows_reason: wire.no_rows_reason,
            cause_codes: wire.cause_codes,
        })
    }
}

/// The whole-execution language labels, which name no single language.
const EXECUTION_SCOPE_LABELS: [&str; 2] = ["workspace", "all"];

fn static_language_label(label: &str) -> Option<&'static str> {
    if let Some(language) = Language::from_config_label(label)
        && language.config_label() == label
    {
        return Some(language.config_label());
    }
    EXECUTION_SCOPE_LABELS
        .into_iter()
        .find(|known| *known == label)
}

impl CodeQueryDiagnostic {
    /// Build the shared, unstyled diagnostic label used by text transports.
    #[doc(hidden)]
    pub fn presentation_label(&self) -> String {
        let kind = format!("{} [{}]", self.impact.as_str(), self.code.as_str());
        if self.branch.is_empty() {
            kind
        } else {
            format!("{kind} [branch {}]", format_branch_path(&self.branch))
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodeQueryExecutionLimits {
    pub max_scanned_files: usize,
    pub max_scanned_source_bytes: usize,
    pub max_fact_nodes: usize,
    pub max_call_answers: usize,
    /// Operational physical work allowance; excluded from content admission.
    pub max_call_scanned_files: usize,
    pub max_call_scanned_source_bytes: usize,
    pub max_pipeline_rows: usize,
    pub semantic: CodeQuerySemanticLimits,
    pub typestate: CodeQueryTypestateLimits,
    pub value_flow: CodeQueryValueFlowLimits,
    pub taint: CodeQueryTaintLimits,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodeQueryTaintLimits {
    pub max_findings: usize,
    pub max_projected_bytes: usize,
    pub max_origins_per_finding: usize,
    pub max_witnesses_per_finding: usize,
    pub max_steps_per_witness: usize,
    pub max_witness_bytes: usize,
}

impl CodeQueryTaintLimits {
    pub fn is_valid(self) -> bool {
        self.max_findings > 0
            && self.max_findings <= 50_000
            && self.max_projected_bytes > 0
            && self.max_projected_bytes <= 64 * 1024 * 1024
            && self.max_origins_per_finding > 0
            && self.max_origins_per_finding <= 50_000
            && self.max_witnesses_per_finding > 0
            && self.max_witnesses_per_finding <= 50_000
            && self.max_steps_per_witness > 0
            && self.max_steps_per_witness <= 16_384
            && self.max_witness_bytes > 0
            && self.max_witness_bytes <= 16 * 1024 * 1024
    }

    pub const fn projection_limits(self) -> CodeQueryTaintProjectionLimits {
        CodeQueryTaintProjectionLimits::new(
            self.max_origins_per_finding,
            self.max_witnesses_per_finding,
            self.max_steps_per_witness,
            self.max_witness_bytes,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodeQueryValueFlowLimits {
    pub solver_work: brokk_bifrost_flow::dataflow::SolverWork,
    pub max_retained_relations: usize,
    pub max_retained_bytes: usize,
    pub max_endpoints: usize,
    pub max_witnesses: usize,
    pub max_witness_steps: usize,
    pub max_witness_expansions: usize,
    pub max_witness_bytes: usize,
    pub max_total_witness_steps: usize,
    pub max_total_witness_expansions: usize,
    pub max_total_witness_bytes: usize,
}

impl CodeQueryValueFlowLimits {
    pub fn is_valid(self) -> bool {
        let hard_solver = brokk_bifrost_flow::dataflow::SolverWork::default_limits();
        let solver_valid = brokk_bifrost_flow::dataflow::SolverBudgetDimension::ALL
            .into_iter()
            .all(|dimension| {
                let value = self.solver_work.get(dimension);
                value > 0 && value <= hard_solver.get(dimension)
            });
        solver_valid
            && self.max_retained_relations > 0
            && self.max_retained_relations <= u32::MAX as usize
            && self.max_retained_bytes > 0
            && self.max_retained_bytes <= 64 * 1024 * 1024
            && self.max_endpoints > 0
            && self.max_endpoints <= 50_000
            && self.max_witnesses > 0
            && self.max_witnesses <= 50_000
            && self.max_witness_steps > 0
            && self.max_witness_steps <= 16_384
            && self.max_witness_expansions > 0
            && self.max_witness_expansions <= 65_536
            && self.max_witness_bytes > 0
            && self.max_witness_bytes <= 16 * 1024 * 1024
            && self.max_total_witness_steps > 0
            && self.max_total_witness_steps <= 1_000_000
            && self.max_total_witness_expansions > 0
            && self.max_total_witness_expansions <= 4_000_000
            && self.max_total_witness_bytes > 0
            && self.max_total_witness_bytes <= 64 * 1024 * 1024
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodeQueryTypestateLimits {
    pub solver_work: brokk_bifrost_flow::dataflow::SolverWork,
    pub max_reached_rows: usize,
    pub max_candidates: usize,
    pub max_witness_steps: usize,
    pub max_witness_expansions: usize,
    pub max_total_witness_expansions: usize,
    pub max_witness_bytes: usize,
}

impl CodeQueryTypestateLimits {
    pub fn is_valid(self) -> bool {
        let hard_solver = brokk_bifrost_flow::dataflow::SolverWork::default_limits();
        let solver_valid = brokk_bifrost_flow::dataflow::SolverBudgetDimension::ALL
            .into_iter()
            .all(|dimension| {
                let value = self.solver_work.get(dimension);
                value > 0 && value <= hard_solver.get(dimension)
            });
        solver_valid
            && self.max_reached_rows > 0
            && self.max_reached_rows
                <= brokk_bifrost_flow::typestate::MAX_TYPESTATE_FINDING_REACHED_ROWS
            && self.max_candidates > 0
            && self.max_candidates
                <= brokk_bifrost_flow::typestate::MAX_TYPESTATE_FINDING_CANDIDATES
            && self.max_witness_steps > 0
            && self.max_witness_steps <= brokk_bifrost_flow::typestate::MAX_TYPESTATE_WITNESS_STEPS
            && self.max_witness_expansions > 0
            && self.max_witness_expansions
                <= brokk_bifrost_flow::typestate::MAX_TYPESTATE_WITNESS_EXPANSIONS
            && self.max_total_witness_expansions > 0
            && self.max_total_witness_expansions
                <= brokk_bifrost_flow::typestate::MAX_TYPESTATE_FINDING_WITNESS_EXPANSIONS
            && self.max_witness_bytes > 0
            && self.max_witness_bytes
                <= brokk_bifrost_flow::typestate::MAX_TYPESTATE_FINDING_WITNESS_BYTES
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct CodeQuerySemanticLimits {
    pub max_materialized_files: usize,
    pub max_source_bytes: usize,
    pub max_rows_per_dimension: usize,
    pub max_retained_bytes: usize,

    /// Per-dimension row capacities, for a caller that has them.
    ///
    /// `None` is the ordinary case: one uniform `max_rows_per_dimension`
    /// bounds every row lane, and the executor derives a memory-shaped
    /// estimate for each homogeneous retained-row lane from
    /// `max_retained_bytes` on top of it, because a caller that supplies one
    /// number for fourteen lanes of very different density has not priced any
    /// of them. `nested_entries` keeps the uniform bound for heterogeneous
    /// retained collections. Traversal visits are work telemetry and do not
    /// consume this resident row grant.
    ///
    /// `Some` says the caller has: it carries its own multi-dimensional
    /// ledger and knows exactly how much of each lane is left. Those
    /// remainders differ by orders of magnitude -- one whole-workspace bind
    /// that drains `nested_entries` leaves `procedures` almost untouched --
    /// and collapsing them to one scalar caps every dimension at the most
    /// depleted lane (#2523). When the table is present it is authoritative:
    /// it replaces the scalar and every applicable byte-shaped estimate. The
    /// real memory bound is unaffected either way, because it is measured
    /// rather than estimated: `SemanticQueryState::materialize` charges each
    /// artifact's own retained bytes against `max_retained_bytes`.
    ///
    /// The table's `SourceBytes` and `OwnedTextBytes` entries are never read.
    /// Those two lanes are not row dimensions; `max_source_bytes` and
    /// `max_retained_bytes` are their limits.
    pub rows_per_dimension: Option<CodeQuerySemanticRowLimits>,
}

impl CodeQuerySemanticLimits {
    pub fn all_positive(self) -> bool {
        self.max_materialized_files > 0
            && self.max_source_bytes > 0
            && self.max_retained_bytes > 0
            && CodeQuerySemanticRowLimits::ROW_DIMENSIONS
                .into_iter()
                .all(|dimension| self.rows(dimension) > 0)
    }

    /// This query's row capacity for one dimension: the caller's own entry
    /// when it published a per-dimension table, and the uniform scalar
    /// otherwise.
    pub fn rows(self, dimension: SemanticBudgetDimension) -> usize {
        match self.rows_per_dimension {
            Some(rows) => rows.get(dimension),
            None => self.max_rows_per_dimension,
        }
    }
}

/// One row capacity per semantic row dimension.
///
/// Built only through [`CodeQuerySemanticRowLimits::from_rows`], which fills
/// every row dimension from the caller's own ledger and leaves the two byte
/// lanes at `usize::MAX` so that a stray read of them cannot silently narrow
/// `max_source_bytes` or `max_retained_bytes`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct CodeQuerySemanticRowLimits(SemanticWork);

impl CodeQuerySemanticRowLimits {
    /// Every semantic dimension that counts rows, which is every dimension
    /// except the two that count bytes.
    pub const ROW_DIMENSIONS: [SemanticBudgetDimension; 14] = {
        let mut dimensions = [SemanticBudgetDimension::Procedures; 14];
        let mut source = 0;
        let mut target = 0;
        while source < SemanticBudgetDimension::ALL.len() {
            let dimension = SemanticBudgetDimension::ALL[source];
            if !matches!(
                dimension,
                SemanticBudgetDimension::SourceBytes | SemanticBudgetDimension::OwnedTextBytes
            ) {
                dimensions[target] = dimension;
                target += 1;
            }
            source += 1;
        }
        assert!(target == dimensions.len());
        dimensions
    };

    pub fn from_rows(rows: impl Fn(SemanticBudgetDimension) -> usize) -> Self {
        use SemanticBudgetDimension as Dimension;
        Self(SemanticWork {
            source_bytes: usize::MAX,
            procedures: rows(Dimension::Procedures),
            blocks: rows(Dimension::Blocks),
            program_points: rows(Dimension::ProgramPoints),
            values: rows(Dimension::Values),
            allocations: rows(Dimension::Allocations),
            call_sites: rows(Dimension::CallSites),
            memory_locations: rows(Dimension::MemoryLocations),
            captures: rows(Dimension::Captures),
            source_mappings: rows(Dimension::SourceMappings),
            evidence: rows(Dimension::Evidence),
            gaps: rows(Dimension::Gaps),
            events: rows(Dimension::Events),
            control_edges: rows(Dimension::ControlEdges),
            nested_entries: rows(Dimension::NestedEntries),
            owned_text_bytes: usize::MAX,
        })
    }

    pub const fn get(self, dimension: SemanticBudgetDimension) -> usize {
        self.0.get(dimension)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CodeQueryExecutionWork {
    pub scanned_files: u64,
    pub scanned_source_bytes: u64,
    pub fact_nodes: u64,
    pub pipeline_rows: u64,
    pub examined_references: u64,
    pub semantic: CodeQuerySemanticWork,
}

impl CodeQueryExecutionWork {
    pub const fn saturating_add(self, other: Self) -> Self {
        Self {
            scanned_files: self.scanned_files.saturating_add(other.scanned_files),
            scanned_source_bytes: self
                .scanned_source_bytes
                .saturating_add(other.scanned_source_bytes),
            fact_nodes: self.fact_nodes.saturating_add(other.fact_nodes),
            pipeline_rows: self.pipeline_rows.saturating_add(other.pipeline_rows),
            examined_references: self
                .examined_references
                .saturating_add(other.examined_references),
            semantic: self.semantic.saturating_add(other.semantic),
        }
    }
}

/// Every budgeted lane an execution charged that `CodeQueryExecutionWork`
/// does not publish, plus the per-step output counts.
///
/// A merge of per-seed executions can only claim to equal one whole execution
/// while no cumulative cap was reached, and a cap the merge cannot see is a
/// truncation the sliced run cannot detect. `CodeQueryExecutionWork` is the
/// caller-facing measurement and its shape is pinned by consumers, so the
/// three budgeted lanes it drops and the per-step counts it never had live
/// here, beside it, rather than changing it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeQueryBudgetedWork {
    /// Admission counters exclude observational caller scan telemetry.
    #[serde(default)]
    pub admission: CodeQueryAdmissionWork,
    /// Provenance trace steps charged against `max_pipeline_rows`.
    pub provenance_steps: u64,
    /// Files resolved by import traversal, charged against
    /// `max_scanned_files`.
    pub import_files_resolved: u64,
    /// Import edges resolved, charged against `max_pipeline_rows`.
    pub import_edges_resolved: u64,
    /// Rows each plan operator emitted, indexed by its physical plan node.
    ///
    /// `max_step_outputs` is enforced per step and has no counter of its own,
    /// so a merge that sums lanes must sum these separately to see a per-step
    /// truncation. Two executions of the same query lower to the same plan and
    /// therefore index identically; a node that is not a pipeline step
    /// contributes zero.
    ///
    /// `None` means the execution stopped before it counted any step (it was
    /// cancelled before it started, or its plan was invalid): the counts are
    /// unknown, which is not the same as empty or zero. A merge with an
    /// unknown side is unknown, so no per-step cap can be decided from it, and
    /// the execution that produced it always carries its own typed
    /// incompleteness. Only a counted execution is ever stored: a stored row
    /// holds the array, and serializing `None` is an error.
    #[serde(with = "counted_step_outputs")]
    pub step_outputs: Option<Vec<u64>>,
    /// The number of distinct sites the plan's anchor seeds selected, before
    /// any later step filtered them.
    ///
    /// Only the anchor seed leaves count: every operand of a union, operand
    /// zero of an intersect, except or correlate, and the sources of a call
    /// reachability relation. A seed on the other side of those operators holds
    /// exclusions or sinks, not candidates, and counting it would show
    /// candidates a rule could never report. A site counts once however many
    /// seed leaves or retried branches reach it; the key is the site's file
    /// and its position, never the full row, so one site that carries several
    /// binding or role rows still counts once.
    ///
    /// An incremental run that executes call reachability sources as separate
    /// queries reports the sum only when every reachability operator is on the
    /// anchor spine (the root source and its sources); otherwise it reports
    /// `None`, because the sum could include an excluded operand or count a
    /// shared site twice.
    ///
    /// `None` is "not measured": the execution stopped before it counted, or
    /// a stored product predates the counter. It is never read as zero. A sum
    /// with an unmeasured side is unmeasured, so a total never reports fewer
    /// candidates than were seen, and a real zero (an evaluated scope with no
    /// anchor site) stays distinguishable from an absent measurement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub candidate_sites: Option<u64>,
}

/// Work admitted from recorded content reads and call answers.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeQueryAdmissionWork {
    pub scanned_files: u64,
    pub scanned_source_bytes: u64,
    pub fact_nodes: u64,
    pub pipeline_rows: u64,
    pub call_answers: u64,
}

impl CodeQueryAdmissionWork {
    pub fn saturating_add(self, other: Self) -> Self {
        Self {
            scanned_files: self.scanned_files.saturating_add(other.scanned_files),
            scanned_source_bytes: self
                .scanned_source_bytes
                .saturating_add(other.scanned_source_bytes),
            fact_nodes: self.fact_nodes.saturating_add(other.fact_nodes),
            pipeline_rows: self.pipeline_rows.saturating_add(other.pipeline_rows),
            call_answers: self.call_answers.saturating_add(other.call_answers),
        }
    }
}

/// The stored shape of [`CodeQueryBudgetedWork::step_outputs`]: the plain
/// array a counted execution always had. An execution that never counted its
/// steps has nothing to store, so serializing it fails instead of writing a
/// value that reads back as an empty count.
mod counted_step_outputs {
    use serde::{Deserialize, Deserializer, Serialize, Serializer, ser::Error};

    pub fn serialize<S: Serializer>(
        step_outputs: &Option<Vec<u64>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match step_outputs {
            Some(counts) => counts.serialize(serializer),
            None => Err(S::Error::custom(
                "an execution that never counted its steps has no stored per-step counts",
            )),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Vec<u64>>, D::Error> {
        Vec::<u64>::deserialize(deserializer).map(Some)
    }
}

/// The identity of a sum: nothing executed, so no step was counted and none
/// stopped.
impl Default for CodeQueryBudgetedWork {
    fn default() -> Self {
        Self {
            admission: CodeQueryAdmissionWork::default(),
            provenance_steps: 0,
            import_files_resolved: 0,
            import_edges_resolved: 0,
            step_outputs: Some(Vec::new()),
            candidate_sites: Some(0),
        }
    }
}

impl CodeQueryBudgetedWork {
    /// Sum every lane of two executions of the same query.
    ///
    /// Sums over-count whatever two units both reached, so a rule that widens
    /// when a sum reaches its cap widens more often than strictly necessary,
    /// never less. The per-step counts of a sum with an unknown side are
    /// unknown.
    pub fn saturating_add(&self, other: &Self) -> Self {
        let step_outputs = match (&self.step_outputs, &other.step_outputs) {
            (Some(left), Some(right)) => {
                assert_eq!(
                    left.len(),
                    right.len(),
                    "per-step output counts of one query's executions have one entry per plan node"
                );
                Some(
                    left.iter()
                        .zip(right)
                        .map(|(left, right)| left.saturating_add(*right))
                        .collect(),
                )
            }
            _ => None,
        };
        Self {
            admission: self.admission.saturating_add(other.admission),
            provenance_steps: self.provenance_steps.saturating_add(other.provenance_steps),
            import_files_resolved: self
                .import_files_resolved
                .saturating_add(other.import_files_resolved),
            import_edges_resolved: self
                .import_edges_resolved
                .saturating_add(other.import_edges_resolved),
            step_outputs,
            candidate_sites: self
                .candidate_sites
                .zip(other.candidate_sites)
                .map(|(left, right)| left.saturating_add(right)),
        }
    }

    /// The largest number of rows any one step emitted, or `None` when the
    /// execution never counted its steps.
    pub fn max_step_outputs(&self) -> Option<u64> {
        self.step_outputs
            .as_ref()
            .map(|counts| counts.iter().copied().max().unwrap_or(0))
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CodeQuerySemanticWork {
    pub materialization_attempts: u64,
    pub unique_materialized_files: u64,
    pub request_cache_hits: u64,
    pub source_bytes: u64,
    pub procedures: u64,
    pub blocks: u64,
    pub program_points: u64,
    pub values: u64,
    pub allocations: u64,
    pub call_sites: u64,
    pub memory_locations: u64,
    pub captures: u64,
    pub source_mappings: u64,
    pub evidence: u64,
    pub gaps: u64,
    pub events: u64,
    pub control_edges: u64,
    pub nested_entries: u64,
    pub retained_bytes: u64,
    /// Admitted plus worked per lane; held-and-scanned bytes can count twice.
    /// This cumulative telemetry is not a bound.
    pub cumulative: crate::analyzer::semantic::SemanticWork,
    /// Largest live resident census per lane.
    pub resident_peaks: crate::analyzer::semantic::SemanticWork,
    /// Largest work balance of any one root or prepass per lane.
    pub root_work_peaks: crate::analyzer::semantic::SemanticWork,
    /// The `nested_entries` lane of `resident_peaks`.
    pub resident_nested_entries_peak: u64,
    /// The retained-artifact byte peak, also reported as `retained_bytes`.
    pub resident_retained_bytes_peak: u64,
    pub traversal_steps: u64,
    pub budget_exhausted: bool,
    #[serde(skip_serializing_if = "CodeQueryTypestateWork::is_empty")]
    pub typestate: CodeQueryTypestateWork,
    #[serde(skip_serializing_if = "CodeQueryValueFlowWork::is_empty")]
    pub value_flow: CodeQueryValueFlowWork,
    #[serde(skip_serializing_if = "CodeQueryTypeFlowWork::is_empty")]
    pub type_flow: CodeQueryTypeFlowWork,
    #[serde(skip_serializing_if = "CodeQueryEffectWork::is_empty")]
    pub effects: CodeQueryEffectWork,
}

impl CodeQuerySemanticWork {
    pub(crate) const fn saturating_add(self, other: Self) -> Self {
        let left = self;
        let mut result = saturating_add_work!(left, other; [materialization_attempts, unique_materialized_files, request_cache_hits, source_bytes, procedures, blocks, program_points, values, allocations, call_sites, memory_locations, captures, source_mappings, evidence, gaps, events, control_edges, nested_entries, retained_bytes, cumulative, resident_nested_entries_peak, resident_retained_bytes_peak, traversal_steps, typestate, value_flow, type_flow, effects]; [budget_exhausted]; [resident_peaks, root_work_peaks]);
        result.resident_nested_entries_peak =
            if left.resident_nested_entries_peak > other.resident_nested_entries_peak {
                left.resident_nested_entries_peak
            } else {
                other.resident_nested_entries_peak
            };
        result.resident_retained_bytes_peak =
            if left.resident_retained_bytes_peak > other.resident_retained_bytes_peak {
                left.resident_retained_bytes_peak
            } else {
                other.resident_retained_bytes_peak
            };
        result
    }

    pub(crate) const fn saturating_sub(self, earlier: Self) -> Self {
        let left = self;
        let mut result = saturating_sub_work!(left, earlier; [materialization_attempts, unique_materialized_files, request_cache_hits, source_bytes, procedures, blocks, program_points, values, allocations, call_sites, memory_locations, captures, source_mappings, evidence, gaps, events, control_edges, nested_entries, retained_bytes, cumulative, resident_nested_entries_peak, resident_retained_bytes_peak, traversal_steps, typestate, value_flow, type_flow, effects]; [budget_exhausted]; [resident_peaks, root_work_peaks]);
        result.resident_nested_entries_peak = left.resident_nested_entries_peak;
        result.resident_retained_bytes_peak = left.resident_retained_bytes_peak;
        result
    }
}

/// Invocation-local declared-effect work. Source acquisitions count fact-provider
/// requests on a query-local miss, not disk reads or source parsing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CodeQueryEffectWork {
    pub acquisitions: u64,
    pub source_acquisitions: u64,
    pub source_bytes: u64,
    pub request_hits: u64,
    pub acquired_procedures: u64,
    pub acquired_edges: u64,
    pub scc_node_visits: u64,
    pub scc_edge_visits: u64,
    /// Components used by propagation, including singleton fallback components
    /// when the bounded SCC pass cannot complete.
    pub scc_components: u64,
    pub propagation_rounds: u64,
    pub propagation_node_visits: u64,
    pub propagation_edge_visits: u64,
    pub inherited_effect_candidates: u64,
    pub coverage_rounds: u64,
    pub coverage_edge_visits: u64,
    pub projected_rows: u64,
}

impl CodeQueryEffectWork {
    pub const fn is_empty(&self) -> bool {
        self.acquisitions == 0
            && self.source_acquisitions == 0
            && self.source_bytes == 0
            && self.request_hits == 0
            && self.acquired_procedures == 0
            && self.acquired_edges == 0
            && self.scc_node_visits == 0
            && self.scc_edge_visits == 0
            && self.scc_components == 0
            && self.propagation_rounds == 0
            && self.propagation_node_visits == 0
            && self.propagation_edge_visits == 0
            && self.inherited_effect_candidates == 0
            && self.coverage_rounds == 0
            && self.coverage_edge_visits == 0
            && self.projected_rows == 0
    }

    pub(crate) const fn saturating_add(self, other: Self) -> Self {
        let left = self;
        saturating_add_work!(left, other; [acquisitions, source_acquisitions, source_bytes, request_hits, acquired_procedures, acquired_edges, scc_node_visits, scc_edge_visits, scc_components, propagation_rounds, propagation_node_visits, propagation_edge_visits, inherited_effect_candidates, coverage_rounds, coverage_edge_visits, projected_rows]; [])
    }

    pub(crate) const fn saturating_sub(self, other: Self) -> Self {
        let left = self;
        saturating_sub_work!(left, other; [acquisitions, source_acquisitions, source_bytes, request_hits, acquired_procedures, acquired_edges, scc_node_visits, scc_edge_visits, scc_components, propagation_rounds, propagation_node_visits, propagation_edge_visits, inherited_effect_candidates, coverage_rounds, coverage_edge_visits, projected_rows]; [])
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CodeQueryTypestateWork {
    pub solves: u64,
    pub cache_hits: u64,
    pub summary_hits: u64,
    pub summary_misses: u64,
    pub summary_rejections: u64,
    pub summary_evictions: u64,
    pub summary_recomputations: u64,
    pub reached_rows: u64,
    pub findings: u64,
    pub omitted_findings: u64,
    pub witnesses: u64,
    pub omitted_witnesses: u64,
    pub witness_steps: u64,
    pub witness_bytes: u64,
    pub fixed_point_solves: u64,
    pub cancelled_solves: u64,
    pub budget_exhausted_solves: u64,
    pub failed_solves: u64,
    pub finding_budget_exhausted: bool,
}

impl CodeQueryTypestateWork {
    pub const fn is_empty(&self) -> bool {
        self.solves == 0
            && self.cache_hits == 0
            && self.summary_hits == 0
            && self.summary_misses == 0
            && self.summary_rejections == 0
            && self.summary_evictions == 0
            && self.summary_recomputations == 0
            && self.reached_rows == 0
            && self.findings == 0
            && self.omitted_findings == 0
            && self.witnesses == 0
            && self.omitted_witnesses == 0
            && self.witness_steps == 0
            && self.witness_bytes == 0
            && self.fixed_point_solves == 0
            && self.cancelled_solves == 0
            && self.budget_exhausted_solves == 0
            && self.failed_solves == 0
            && !self.finding_budget_exhausted
    }

    pub(crate) const fn saturating_sub(self, earlier: Self) -> Self {
        Self {
            solves: self.solves.saturating_sub(earlier.solves),
            cache_hits: self.cache_hits.saturating_sub(earlier.cache_hits),
            summary_hits: self.summary_hits.saturating_sub(earlier.summary_hits),
            summary_misses: self.summary_misses.saturating_sub(earlier.summary_misses),
            summary_rejections: self
                .summary_rejections
                .saturating_sub(earlier.summary_rejections),
            summary_evictions: self
                .summary_evictions
                .saturating_sub(earlier.summary_evictions),
            summary_recomputations: self
                .summary_recomputations
                .saturating_sub(earlier.summary_recomputations),
            reached_rows: self.reached_rows.saturating_sub(earlier.reached_rows),
            findings: self.findings.saturating_sub(earlier.findings),
            omitted_findings: self
                .omitted_findings
                .saturating_sub(earlier.omitted_findings),
            witnesses: self.witnesses.saturating_sub(earlier.witnesses),
            omitted_witnesses: self
                .omitted_witnesses
                .saturating_sub(earlier.omitted_witnesses),
            witness_steps: self.witness_steps.saturating_sub(earlier.witness_steps),
            witness_bytes: self.witness_bytes.saturating_sub(earlier.witness_bytes),
            fixed_point_solves: self
                .fixed_point_solves
                .saturating_sub(earlier.fixed_point_solves),
            cancelled_solves: self
                .cancelled_solves
                .saturating_sub(earlier.cancelled_solves),
            budget_exhausted_solves: self
                .budget_exhausted_solves
                .saturating_sub(earlier.budget_exhausted_solves),
            failed_solves: self.failed_solves.saturating_sub(earlier.failed_solves),
            finding_budget_exhausted: self.finding_budget_exhausted
                && !earlier.finding_budget_exhausted,
        }
    }

    pub(crate) const fn saturating_add(self, other: Self) -> Self {
        let left = self;
        saturating_add_work!(left, other; [solves, cache_hits, summary_hits, summary_misses, summary_rejections, summary_evictions, summary_recomputations, reached_rows, findings, omitted_findings, witnesses, omitted_witnesses, witness_steps, witness_bytes, fixed_point_solves, cancelled_solves, budget_exhausted_solves, failed_solves]; [finding_budget_exhausted])
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CodeQueryValueFlowWork {
    pub solves: u64,
    pub cache_hits: u64,
    pub reached_rows: u64,
    pub meetings: u64,
    pub sink_outcomes: u64,
    pub omitted_endpoints: u64,
    pub witnesses: u64,
    pub omitted_witnesses: u64,
    pub witness_expansions: u64,
    pub witness_steps: u64,
    pub witness_bytes: u64,
    pub fixed_point_solves: u64,
    pub cancelled_solves: u64,
    pub budget_exhausted_solves: u64,
    pub failed_solves: u64,
    pub endpoint_truncated: bool,
    pub witness_truncated: bool,
}

impl CodeQueryValueFlowWork {
    pub const fn is_empty(&self) -> bool {
        self.solves == 0
            && self.cache_hits == 0
            && self.reached_rows == 0
            && self.meetings == 0
            && self.sink_outcomes == 0
            && self.omitted_endpoints == 0
            && self.witnesses == 0
            && self.omitted_witnesses == 0
            && self.witness_expansions == 0
            && self.witness_steps == 0
            && self.witness_bytes == 0
            && self.fixed_point_solves == 0
            && self.cancelled_solves == 0
            && self.budget_exhausted_solves == 0
            && self.failed_solves == 0
            && !self.endpoint_truncated
            && !self.witness_truncated
    }

    pub(crate) const fn saturating_sub(self, earlier: Self) -> Self {
        let left = self;
        saturating_sub_work!(left, earlier; [solves, cache_hits, reached_rows, meetings, sink_outcomes, omitted_endpoints, witnesses, omitted_witnesses, witness_expansions, witness_steps, witness_bytes, fixed_point_solves, cancelled_solves, budget_exhausted_solves, failed_solves]; [endpoint_truncated, witness_truncated])
    }

    pub(crate) const fn saturating_add(self, other: Self) -> Self {
        let left = self;
        saturating_add_work!(left, other; [solves, cache_hits, reached_rows, meetings, sink_outcomes, omitted_endpoints, witnesses, omitted_witnesses, witness_expansions, witness_steps, witness_bytes, fixed_point_solves, cancelled_solves, budget_exhausted_solves, failed_solves]; [endpoint_truncated, witness_truncated])
    }
}

/// Work the class-set type-flow executor charged to one query: one solver run
/// per distinct input procedure at most, with the rows each step projected.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CodeQueryTypeFlowWork {
    /// Root products reused from this policy run, independent of query-local hits.
    #[serde(skip_serializing_if = "is_zero_u64")]
    pub root_memo_hits: u64,
    /// Solver work attributed to shared products; never charged to completeness.
    #[serde(skip_serializing_if = "brokk_bifrost_flow::dataflow::SolverWork::is_empty")]
    pub root_memo_solver_work: brokk_bifrost_flow::dataflow::SolverWork,
    /// Semantic work attributed to shared products; never replayed as query work.
    #[serde(skip_serializing_if = "SemanticWork::is_empty")]
    pub root_memo_semantic_work: SemanticWork,
    /// Fresh whole-workspace field-slot indexes built by this query.
    pub field_slot_builds: u64,
    /// Ready indexes reused through the workspace's in-memory acquisition path.
    /// Query-local reuse does not reacquire the index and is not counted here.
    pub field_slot_memory_hits: u64,
    /// Complete durable indexes loaded and accepted for this query.
    pub field_slot_persistence_hits: u64,
    /// Durable lookups for which no matching index was present.
    pub field_slot_persistence_misses: u64,
    /// Durable rows found but rejected by exact validation or replay admission.
    pub field_slot_persistence_rejections: u64,
    /// Fresh indexes inserted into the durable store by this query.
    pub field_slot_publications: u64,
    /// Complete finding-free root projections loaded and accepted from the
    /// durable store by this query.
    pub root_result_persistence_hits: u64,
    /// Durable root-projection lookups for which no exact key was present.
    pub root_result_persistence_misses: u64,
    /// Durable root-projection rows found but rejected by validation or
    /// hydration limits.
    pub root_result_persistence_rejections: u64,
    /// Operational failures while reading or writing durable root projections.
    pub root_result_store_failures: u64,
    /// Fresh finding-free root projections inserted into the durable store by
    /// this query.
    pub root_result_publications: u64,
    pub solves: u64,
    pub cache_hits: u64,
    pub snapshot_cache_hits: u64,
    pub snapshot_cache_misses: u64,
    pub dispatch_cache_hits: u64,
    pub dispatch_cache_misses: u64,
    pub binding_cache_hits: u64,
    pub binding_cache_misses: u64,
    pub summary_cache_hits: u64,
    pub summary_cache_misses: u64,
    /// Exact Zero-entry root relations restored from reusable summaries.
    pub root_summary_cache_hits: u64,
    /// Restored root relations rejected because they did not carry a Meeting
    /// for every sink in the current plan.
    pub root_summary_observation_rejections: u64,
    pub published_summaries: u64,
    /// Independently bounded solver runs performed across all input roots.
    /// A source-refined root may contribute both an exploratory and a refined
    /// solve while `solves` remains the number of distinct root transactions.
    pub solver_attempts: u64,
    #[serde(
        skip_serializing_if = "brokk_bifrost_flow::type_flow::TypeFlowSummaryProfile::is_empty"
    )]
    pub summary_profile: brokk_bifrost_flow::type_flow::TypeFlowSummaryProfile,
    pub class_set_rows: u64,
    pub finding_rows: u64,
    pub witnesses: u64,
    pub omitted_witnesses: u64,
    pub witness_expansions: u64,
    pub witness_steps: u64,
    pub witness_bytes: u64,
    pub witness_truncated: bool,
    pub incomplete_roots: u64,
    pub failed_solves: u64,
}

impl CodeQueryTypeFlowWork {
    pub const fn is_empty(&self) -> bool {
        self.root_memo_hits == 0
            && self.root_memo_solver_work.is_empty()
            && self.root_memo_semantic_work.is_empty()
            && self.field_slot_builds == 0
            && self.field_slot_memory_hits == 0
            && self.field_slot_persistence_hits == 0
            && self.field_slot_persistence_misses == 0
            && self.field_slot_persistence_rejections == 0
            && self.field_slot_publications == 0
            && self.root_result_persistence_hits == 0
            && self.root_result_persistence_misses == 0
            && self.root_result_persistence_rejections == 0
            && self.root_result_store_failures == 0
            && self.root_result_publications == 0
            && self.solves == 0
            && self.cache_hits == 0
            && self.snapshot_cache_hits == 0
            && self.snapshot_cache_misses == 0
            && self.dispatch_cache_hits == 0
            && self.dispatch_cache_misses == 0
            && self.binding_cache_hits == 0
            && self.binding_cache_misses == 0
            && self.summary_cache_hits == 0
            && self.summary_cache_misses == 0
            && self.root_summary_cache_hits == 0
            && self.root_summary_observation_rejections == 0
            && self.published_summaries == 0
            && self.solver_attempts == 0
            && self.summary_profile.is_empty()
            && self.class_set_rows == 0
            && self.finding_rows == 0
            && self.witnesses == 0
            && self.omitted_witnesses == 0
            && self.witness_expansions == 0
            && self.witness_steps == 0
            && self.witness_bytes == 0
            && !self.witness_truncated
            && self.incomplete_roots == 0
            && self.failed_solves == 0
    }

    pub(crate) const fn saturating_sub(self, earlier: Self) -> Self {
        let left = self;
        saturating_sub_work!(left, earlier; [root_memo_hits, root_memo_solver_work, root_memo_semantic_work, field_slot_builds, field_slot_memory_hits, field_slot_persistence_hits, field_slot_persistence_misses, field_slot_persistence_rejections, field_slot_publications, root_result_persistence_hits, root_result_persistence_misses, root_result_persistence_rejections, root_result_store_failures, root_result_publications, solves, cache_hits, snapshot_cache_hits, snapshot_cache_misses, dispatch_cache_hits, dispatch_cache_misses, binding_cache_hits, binding_cache_misses, summary_cache_hits, summary_cache_misses, root_summary_cache_hits, root_summary_observation_rejections, published_summaries, solver_attempts, summary_profile, class_set_rows, finding_rows, witnesses, omitted_witnesses, witness_expansions, witness_steps, witness_bytes, incomplete_roots, failed_solves]; [witness_truncated])
    }

    pub(crate) const fn saturating_add(self, other: Self) -> Self {
        let left = self;
        saturating_add_work!(left, other; [root_memo_hits, root_memo_solver_work, root_memo_semantic_work, field_slot_builds, field_slot_memory_hits, field_slot_persistence_hits, field_slot_persistence_misses, field_slot_persistence_rejections, field_slot_publications, root_result_persistence_hits, root_result_persistence_misses, root_result_persistence_rejections, root_result_store_failures, root_result_publications, solves, cache_hits, snapshot_cache_hits, snapshot_cache_misses, dispatch_cache_hits, dispatch_cache_misses, binding_cache_hits, binding_cache_misses, summary_cache_hits, summary_cache_misses, root_summary_cache_hits, root_summary_observation_rejections, published_summaries, solver_attempts, summary_profile, class_set_rows, finding_rows, witnesses, omitted_witnesses, witness_expansions, witness_steps, witness_bytes, incomplete_roots, failed_solves]; [witness_truncated])
    }
}

impl Default for CodeQueryExecutionLimits {
    fn default() -> Self {
        Self {
            max_scanned_files: MAX_SCANNED_FILES,
            max_scanned_source_bytes: MAX_SCANNED_SOURCE_BYTES,
            max_fact_nodes: MAX_FACT_NODES,
            max_call_answers: MAX_CALL_ANSWERS,
            max_call_scanned_files: MAX_CALL_SCANNED_FILES,
            max_call_scanned_source_bytes: MAX_CALL_SCANNED_SOURCE_BYTES,
            max_pipeline_rows: MAX_PIPELINE_ROWS,
            semantic: CodeQuerySemanticLimits::default(),
            typestate: CodeQueryTypestateLimits::default(),
            value_flow: CodeQueryValueFlowLimits::default(),
            taint: CodeQueryTaintLimits::default(),
        }
    }
}

impl Default for CodeQuerySemanticLimits {
    fn default() -> Self {
        Self {
            max_materialized_files: MAX_SEMANTIC_MATERIALIZED_FILES,
            max_source_bytes: MAX_SEMANTIC_SOURCE_BYTES,
            max_rows_per_dimension: MAX_SEMANTIC_ROWS_PER_DIMENSION,
            max_retained_bytes: MAX_SEMANTIC_RETAINED_BYTES,

            rows_per_dimension: None,
        }
    }
}

impl Default for CodeQueryTypestateLimits {
    fn default() -> Self {
        Self {
            solver_work: brokk_bifrost_flow::dataflow::SolverWork::default_limits(),
            max_reached_rows: brokk_bifrost_flow::typestate::MAX_TYPESTATE_FINDING_REACHED_ROWS,
            max_candidates: brokk_bifrost_flow::typestate::MAX_TYPESTATE_FINDING_CANDIDATES,
            max_witness_steps: brokk_bifrost_flow::typestate::MAX_TYPESTATE_WITNESS_STEPS,
            max_witness_expansions: brokk_bifrost_flow::typestate::MAX_TYPESTATE_WITNESS_EXPANSIONS,
            max_total_witness_expansions:
                brokk_bifrost_flow::typestate::MAX_TYPESTATE_FINDING_WITNESS_EXPANSIONS,
            max_witness_bytes: brokk_bifrost_flow::typestate::MAX_TYPESTATE_FINDING_WITNESS_BYTES,
        }
    }
}

impl Default for CodeQueryValueFlowLimits {
    fn default() -> Self {
        Self {
            solver_work: brokk_bifrost_flow::dataflow::SolverWork::default_limits(),
            max_retained_relations: 262_144,
            max_retained_bytes: 16 * 1024 * 1024,
            max_endpoints: 50_000,
            max_witnesses: 4_096,
            max_witness_steps: 4_096,
            max_witness_expansions: 16_384,
            max_witness_bytes: 4 * 1024 * 1024,
            max_total_witness_steps: 262_144,
            max_total_witness_expansions: 1_048_576,
            max_total_witness_bytes: 16 * 1024 * 1024,
        }
    }
}

impl Default for CodeQueryTaintLimits {
    fn default() -> Self {
        Self {
            max_findings: 50_000,
            max_projected_bytes: 64 * 1024 * 1024,
            max_origins_per_finding: 4_096,
            max_witnesses_per_finding: 4_096,
            max_steps_per_witness: 4_096,
            max_witness_bytes: 4 * 1024 * 1024,
        }
    }
}

fn is_zero_u64(value: &u64) -> bool {
    *value == 0
}

#[cfg(test)]
mod type_flow_summary_profile_tests {
    use super::CodeQueryTypeFlowWork;

    #[test]
    fn profile_work_serializes_typed_summary_rejections() {
        let empty = serde_json::to_value(CodeQueryTypeFlowWork::default())
            .expect("empty type-flow work serializes");
        assert!(empty.get("summary_profile").is_none());

        let legacy: CodeQueryTypeFlowWork = serde_json::from_value(serde_json::json!({
            "solves": 1
        }))
        .expect("a legacy profile without summary attribution deserializes");
        assert!(legacy.summary_profile.is_empty());
        assert_eq!(legacy.field_slot_memory_hits, 0);
        assert_eq!(legacy.field_slot_persistence_hits, 0);
        assert_eq!(legacy.field_slot_persistence_misses, 0);
        assert_eq!(legacy.field_slot_persistence_rejections, 0);
        assert_eq!(legacy.field_slot_publications, 0);
        assert_eq!(legacy.root_result_persistence_hits, 0);
        assert_eq!(legacy.root_result_persistence_misses, 0);
        assert_eq!(legacy.root_result_persistence_rejections, 0);
        assert_eq!(legacy.root_result_store_failures, 0);
        assert_eq!(legacy.root_result_publications, 0);
        assert_eq!(legacy.root_summary_cache_hits, 0);
        assert_eq!(legacy.root_summary_observation_rejections, 0);
        assert_eq!(legacy.solver_attempts, 0);

        let mut work = CodeQueryTypeFlowWork::default();
        work.summary_profile.lookup_relation = 3;
        let json = serde_json::to_value(work).expect("type-flow work serializes");
        assert_eq!(json["summary_profile"]["lookup_relation"], 3);
    }

    #[test]
    fn field_slot_persistence_work_round_trips_and_composes() {
        let cold = CodeQueryTypeFlowWork {
            field_slot_builds: 1,
            field_slot_persistence_misses: 1,
            field_slot_publications: 1,
            ..CodeQueryTypeFlowWork::default()
        };
        let warm = CodeQueryTypeFlowWork {
            field_slot_memory_hits: 2,
            field_slot_persistence_hits: 1,
            field_slot_persistence_rejections: 1,
            ..CodeQueryTypeFlowWork::default()
        };

        let combined = cold.saturating_add(warm);
        assert!(!combined.is_empty());
        assert_eq!(combined.saturating_sub(cold), warm);

        let json = serde_json::to_value(combined).expect("field-slot work serializes");
        assert_eq!(json["field_slot_memory_hits"], 2);
        assert_eq!(json["field_slot_persistence_hits"], 1);
        assert_eq!(json["field_slot_persistence_misses"], 1);
        assert_eq!(json["field_slot_persistence_rejections"], 1);
        assert_eq!(json["field_slot_publications"], 1);
        assert_eq!(
            serde_json::from_value::<CodeQueryTypeFlowWork>(json)
                .expect("field-slot work deserializes"),
            combined
        );
    }

    #[test]
    fn root_summary_work_round_trips_and_composes() {
        let accepted = CodeQueryTypeFlowWork {
            summary_cache_hits: 1,
            root_summary_cache_hits: 1,
            ..CodeQueryTypeFlowWork::default()
        };
        let rejected = CodeQueryTypeFlowWork {
            summary_cache_hits: 1,
            root_summary_cache_hits: 1,
            root_summary_observation_rejections: 1,
            ..CodeQueryTypeFlowWork::default()
        };
        let combined = accepted.saturating_add(rejected);
        assert_eq!(combined.saturating_sub(accepted), rejected);
        let json = serde_json::to_value(combined).expect("root summary work serializes");
        assert_eq!(json["root_summary_cache_hits"], 2);
        assert_eq!(json["root_summary_observation_rejections"], 1);
        assert_eq!(
            serde_json::from_value::<CodeQueryTypeFlowWork>(json)
                .expect("root summary work deserializes"),
            combined
        );
    }

    #[test]
    fn root_result_persistence_work_round_trips_and_composes() {
        let lookup = CodeQueryTypeFlowWork {
            root_result_persistence_hits: 2,
            root_result_persistence_misses: 3,
            root_result_persistence_rejections: 5,
            root_result_store_failures: 7,
            root_result_publications: 11,
            ..CodeQueryTypeFlowWork::default()
        };
        let more = CodeQueryTypeFlowWork {
            root_result_persistence_hits: 13,
            root_result_persistence_misses: 17,
            root_result_persistence_rejections: 19,
            root_result_store_failures: 23,
            root_result_publications: 29,
            ..CodeQueryTypeFlowWork::default()
        };

        let combined = lookup.saturating_add(more);
        assert!(!combined.is_empty());
        assert_eq!(combined.saturating_sub(lookup), more);

        let json = serde_json::to_value(combined).expect("root-result work serializes");
        assert_eq!(json["root_result_persistence_hits"], 15);
        assert_eq!(json["root_result_persistence_misses"], 20);
        assert_eq!(json["root_result_persistence_rejections"], 24);
        assert_eq!(json["root_result_store_failures"], 30);
        assert_eq!(json["root_result_publications"], 40);
        assert_eq!(
            serde_json::from_value::<CodeQueryTypeFlowWork>(json)
                .expect("root-result work deserializes"),
            combined
        );

        let saturated = CodeQueryTypeFlowWork {
            root_result_persistence_hits: u64::MAX,
            root_result_persistence_misses: u64::MAX,
            root_result_persistence_rejections: u64::MAX,
            root_result_store_failures: u64::MAX,
            root_result_publications: u64::MAX,
            ..CodeQueryTypeFlowWork::default()
        }
        .saturating_add(CodeQueryTypeFlowWork {
            root_result_persistence_hits: 1,
            root_result_persistence_misses: 1,
            root_result_persistence_rejections: 1,
            root_result_store_failures: 1,
            root_result_publications: 1,
            ..CodeQueryTypeFlowWork::default()
        });
        assert_eq!(saturated.root_result_persistence_hits, u64::MAX);
        assert_eq!(saturated.root_result_persistence_misses, u64::MAX);
        assert_eq!(saturated.root_result_persistence_rejections, u64::MAX);
        assert_eq!(saturated.root_result_store_failures, u64::MAX);
        assert_eq!(saturated.root_result_publications, u64::MAX);
        assert_eq!(
            CodeQueryTypeFlowWork::default().saturating_sub(saturated),
            CodeQueryTypeFlowWork::default()
        );
    }
}

#[cfg(test)]
mod budgeted_work_storage_tests {
    use super::CodeQueryBudgetedWork;

    fn with_candidates(candidate_sites: Option<u64>) -> CodeQueryBudgetedWork {
        CodeQueryBudgetedWork {
            candidate_sites,
            ..CodeQueryBudgetedWork::default()
        }
    }

    // A total is only as measured as its least measured part: an unmeasured
    // unit makes the sum unmeasured, so a warm run that reads one unit stored
    // before the counter existed reports no count rather than a short one
    // (#12581). A measured zero is a count, and sums as one.
    #[test]
    fn candidate_sites_sum_only_when_every_part_was_measured() {
        let sum = |parts: &[Option<u64>]| {
            parts
                .iter()
                .map(|part| with_candidates(*part))
                .fold(CodeQueryBudgetedWork::default(), |total, part| {
                    total.saturating_add(&part)
                })
                .candidate_sites
        };
        assert_eq!(sum(&[]), Some(0), "nothing executed is a measured zero");
        assert_eq!(sum(&[Some(0)]), Some(0));
        assert_eq!(sum(&[Some(2), Some(0), Some(5)]), Some(7));
        assert_eq!(sum(&[Some(2), None, Some(5)]), None);
        assert_eq!(sum(&[Some(u64::MAX), Some(1)]), Some(u64::MAX));
    }

    // A row stored before the counter has no such field, and a row never
    // stores an unmeasured one; both read back as unmeasured, never as zero.
    #[test]
    fn candidate_sites_survive_storage_without_becoming_zero() {
        let measured = serde_json::to_value(with_candidates(Some(0))).expect("serializes");
        assert_eq!(measured["candidate_sites"], 0);
        let read: CodeQueryBudgetedWork = serde_json::from_value(measured).expect("deserializes");
        assert_eq!(read.candidate_sites, Some(0));

        let mut stored = serde_json::to_value(with_candidates(Some(4))).expect("serializes");
        stored
            .as_object_mut()
            .expect("an object")
            .remove("candidate_sites");
        let old: CodeQueryBudgetedWork = serde_json::from_value(stored).expect("deserializes");
        assert_eq!(old.candidate_sites, None);
        let unmeasured = serde_json::to_value(with_candidates(None)).expect("serializes");
        assert!(unmeasured.get("candidate_sites").is_none(), "{unmeasured}");
    }

    // Stored rows hold only counted executions: the counts are the same plain
    // array they always were, and an uncounted execution refuses to serialize,
    // so it can never reach a row that reads back as an empty count (#11709).
    #[test]
    fn only_counted_step_outputs_serialize() {
        let counted = CodeQueryBudgetedWork {
            step_outputs: Some(vec![2, 0, 5]),
            ..CodeQueryBudgetedWork::default()
        };
        let stored = serde_json::to_value(&counted).expect("counted work serializes");
        assert_eq!(stored["step_outputs"], serde_json::json!([2, 0, 5]));
        let read: CodeQueryBudgetedWork =
            serde_json::from_value(stored).expect("a stored row deserializes");
        assert_eq!(read, counted);

        let uncounted = CodeQueryBudgetedWork {
            step_outputs: None,
            ..CodeQueryBudgetedWork::default()
        };
        let error = serde_json::to_value(&uncounted).expect_err("uncounted work never serializes");
        assert!(
            error.to_string().contains(
                "an execution that never counted its steps has no stored per-step counts"
            ),
            "{error}"
        );
    }
}
