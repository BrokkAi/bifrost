//! Stable inputs for Output diagnostics. Evaluation captures them while the
//! provider is live; projection renders them, so a replayed Output renders the
//! same text without the provider.

use super::*;
use brokk_bifrost_flow::taint::compose::IncompleteCause;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OutputDiagnosticLocation {
    path: String,
    span: Option<[u64; 2]>,
    region: Option<[u64; 4]>,
}

impl OutputDiagnosticLocation {
    /// Accept exactly the locations `policy_location` can rebuild: a decoded
    /// row that passes here must never reach its `expect`.
    fn validate(&self) -> Result<(), ()> {
        let path = WorkspaceRelativePath::new(&self.path).map_err(|_| ())?;
        match (self.span, self.region) {
            (None, None) => Ok(()),
            (Some([start, end]), None) if start <= end => Ok(()),
            (Some([start, end]), Some([start_line, start_column, end_line, end_column]))
                if start <= end =>
            {
                PolicySourceLocation::span_from_coordinates(
                    path,
                    start,
                    end,
                    start_line,
                    start_column,
                    end_line,
                    end_column,
                )
                .map(|_| ())
                .map_err(|_| ())
            }
            _ => Err(()),
        }
    }
    fn capture(location: &PolicySourceLocation) -> Self {
        Self {
            path: location.path().to_owned(),
            span: location.byte_span().map(|span| [span.start(), span.end()]),
            region: location.region().map(|region| {
                [
                    region.start_line(),
                    region.start_column(),
                    region.end_line(),
                    region.end_column(),
                ]
            }),
        }
    }

    fn policy_location(&self) -> PolicySourceLocation {
        let path = WorkspaceRelativePath::new(self.path.as_str()).expect("captured relative path");
        match (self.span, self.region) {
            (Some([start, end]), Some([start_line, start_column, end_line, end_column])) => {
                PolicySourceLocation::span_from_coordinates(
                    path,
                    start,
                    end,
                    start_line,
                    start_column,
                    end_line,
                    end_column,
                )
                .expect("captured diagnostic coordinates")
            }
            (None, None) | (Some(_), None) => PolicySourceLocation::artifact(path),
            _ => unreachable!("display region requires a byte span"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum CompositionText {
    // The producer's detail is verbatim evidence, never a rendered diagnostic.
    Object {
        site: String,
        procedure: String,
    },
    ExecutionRoots,
    Execution {
        procedure: String,
    },
    Dispatch {
        call: String,
        procedure: String,
    },
    ModelOutputStorage {
        call: String,
        procedure: String,
    },
    Callers {
        procedure: String,
    },
    Model {
        call: String,
        procedure: String,
    },
    UnknownSummaryEffects {
        call: String,
        procedure: String,
        summary_path: String,
        summary: String,
        target: String,
    },
    Interior {
        procedure: String,
    },
    PartialFlows {
        procedure: String,
        outcome: String,
    },
    Open {
        procedure: String,
    },
    MissingCaptureBinding {
        procedure: String,
        slot: String,
    },
    UnplacedTransfer {
        procedure: String,
        carrier: String,
    },
    Endpoints {
        procedure: String,
    },
    StoreInventory {
        procedure: String,
    },
    SemanticBudget,
    CompositionBudget {
        lane: String,
    },
    Cancelled,
    ProcedureCause {
        label: String,
        path: String,
        procedure: String,
        status: String,
    },
    CallSiteEvidence(CallSiteEvidenceText),
    ModeledOutput {
        path: String,
    },
}

impl CompositionText {
    pub(super) fn render(&self, detail: &str) -> String {
        match self {
            Self::Object { site, procedure } => {
                format!("object composition at {site} in {procedure} is incomplete: {detail}")
            }
            Self::ExecutionRoots => {
                format!("taint composition execution-root inventory is incomplete: {detail}")
            }
            Self::Execution { procedure } => {
                format!("execution composition of {procedure} is incomplete: {detail}")
            }
            Self::Dispatch { call, procedure } => format!(
                "taint composition could not resolve the dispatch of call {call} in {procedure}: {detail}"
            ),
            Self::ModelOutputStorage { call, procedure } => format!(
                "taint composition could not prove a model output's receiver or argument storage at call {call} in {procedure}"
            ),
            Self::Callers { procedure } => format!(
                "taint composition could not enumerate the callers of {procedure}: {detail}"
            ),
            Self::Model { call, procedure } => format!(
                "taint composition model of call {call} in {procedure} is incomplete: {detail}"
            ),
            Self::UnknownSummaryEffects {
                call,
                procedure,
                summary_path,
                summary,
                target,
            } => format!(
                "taint composition call {call} in {procedure} retains unknown effects of selected partial summary {summary} in {summary_path} for its {target} target"
            ),
            Self::Interior { procedure } => {
                format!("taint composition interior flows of {procedure} are incomplete: {detail}")
            }
            Self::PartialFlows { procedure, outcome } => {
                format!("taint composition partial flows of {procedure} are {outcome}")
            }
            Self::Open { procedure } => {
                format!("taint composition found {procedure} open: {detail}")
            }
            Self::MissingCaptureBinding { procedure, slot } => {
                format!("taint composition found no capture binding for {slot} in {procedure}")
            }
            Self::UnplacedTransfer { procedure, carrier } => format!(
                "taint composition could not place sanitizer or transform carrier {carrier} in {procedure}"
            ),
            Self::Endpoints { procedure } => format!(
                "taint composition matched the policy endpoints of {procedure} incompletely: {detail}"
            ),
            Self::StoreInventory { procedure } => format!(
                "taint composition selected the store writes of {procedure} incompletely: {detail}"
            ),
            // A unit stopped by a discovery refusal carries where it stopped
            // (operation, lane and limit); a soft stop has no detail.
            Self::SemanticBudget if detail.is_empty() => {
                "taint composition exhausted its semantic proof budget".to_owned()
            }
            Self::SemanticBudget => {
                format!("taint composition exhausted its semantic proof budget: {detail}")
            }
            Self::CompositionBudget { lane } => {
                format!("taint composition exhausted its {lane} lane")
            }
            Self::Cancelled => {
                "taint composition was cancelled before reaching a fixed point".to_owned()
            }
            Self::ProcedureCause {
                label,
                path,
                procedure,
                status,
            } => {
                format!("taint discovery is incomplete: {label} for {path}:{procedure} is {status}")
            }
            Self::CallSiteEvidence(evidence) => {
                format!("taint discovery is incomplete: {evidence}")
            }
            Self::ModeledOutput { path } => format!(
                "taint discovery is incomplete: a modeled output at {path} has unresolved receiver or argument storage"
            ),
        }
    }
}

/// The call-site evidence of an incomplete call. Both engines print it; a
/// call outside Rust appends it to its generic cause (#4823).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CallSiteEvidenceText {
    pub(super) callee: Option<String>,
    pub(super) path: String,
    pub(super) start: u64,
    pub(super) end: u64,
    pub(super) status: String,
    pub(super) resolver_complete: bool,
    pub(super) boundary_status: String,
    pub(super) gap: Option<String>,
}

impl std::fmt::Display for CallSiteEvidenceText {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "call `{}` at {} bytes {}..{} has snapshot input status {}; {}; resolver boundary status: {}; call semantic gap: {}",
            self.callee
                .as_deref()
                .unwrap_or("<unavailable from call shape>"),
            self.path,
            self.start,
            self.end,
            self.status,
            if self.resolver_complete {
                "the resolver edge is complete"
            } else {
                "the resolver left the call incomplete"
            },
            self.boundary_status,
            self.gap
                .as_deref()
                .unwrap_or("no call-site semantic-gap row"),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum SanitizerDeclineReason {
    GuardEvidence { detail: String },
    Admission { detail: String },
}

impl SanitizerDeclineReason {
    fn detail(&self) -> &str {
        match self {
            Self::GuardEvidence { detail } | Self::Admission { detail } => detail,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum OutputDiagnosticRecord {
    Incompleteness {
        kind: CompositionText,
        cause: IncompleteCause,
        family: String,
        primary: Option<OutputDiagnosticLocation>,
        detail: String,
    },
    Finding {
        kind: CompositionText,
        cause: IncompleteCause,
        family: String,
        primary: Option<OutputDiagnosticLocation>,
        detail: String,
    },
    ConditionalSanitizerDecline {
        site: OutputDiagnosticLocation,
        sanitizer: String,
        reason: SanitizerDeclineReason,
    },
    ProviderRefusal {
        site: OutputDiagnosticLocation,
        reason: RefusalReason,
        run_incomplete: bool,
        /// Whether the semantic input alone decides the refusal. It lives only
        /// in this record: publication reads it, and the rendered text does not.
        cause: IncompleteCause,
    },
}

impl OutputDiagnosticRecord {
    /// A record's cause identity is independent of its presentation detail,
    /// except for a semantic budget stop, which names where it stopped.
    pub(super) fn typed_identity(&self) -> Vec<u8> {
        match self {
            Self::Incompleteness {
                kind,
                cause,
                family,
                primary,
                detail,
            } => {
                // A semantic budget stop is the one cause whose detail is part
                // of what it says: where the unit stopped. Its detail is
                // deterministic (operation, lane, dimension and limit).
                let detail = matches!(kind, CompositionText::SemanticBudget).then_some(detail);
                serde_json::to_vec(&(0, kind, cause, family, primary, detail))
                    .expect("typed diagnostic")
            }
            Self::Finding {
                kind,
                cause,
                family,
                primary,
                ..
            } => serde_json::to_vec(&(1, kind, cause, family, primary)).expect("typed diagnostic"),
            Self::ConditionalSanitizerDecline {
                site,
                sanitizer,
                reason,
            } => serde_json::to_vec(&(2, site, sanitizer, reason)).expect("typed diagnostic"),
            Self::ProviderRefusal {
                site,
                reason,
                run_incomplete,
                cause,
            } => serde_json::to_vec(&(3, site, reason, run_incomplete, cause))
                .expect("typed diagnostic"),
        }
    }

    /// What the report shows of a record: its typed identity without a
    /// refusal's cause, which publication reads and the rendered text does not
    /// show. A unit reused from an earlier run can hold a refusal as content
    /// while a unit computed now holds the same row as operational; the report
    /// lists that row once, as a run that reuses nothing does.
    pub(super) fn render_identity(&self) -> Vec<u8> {
        match self {
            Self::ProviderRefusal {
                site,
                reason,
                run_incomplete,
                cause: _,
            } => serde_json::to_vec(&(3, site, reason, run_incomplete)).expect("typed diagnostic"),
            Self::Incompleteness { .. }
            | Self::Finding { .. }
            | Self::ConditionalSanitizerDecline { .. } => self.typed_identity(),
        }
    }

    pub(super) fn validate(&self) -> Result<(), ()> {
        match self {
            Self::Incompleteness { primary, .. } | Self::Finding { primary, .. } => {
                if let Some(primary) = primary {
                    primary.validate()?;
                }
            }
            Self::ConditionalSanitizerDecline { site, .. } => site.validate()?,
            Self::ProviderRefusal { site, .. } => {
                site.validate()?;
                if site.span.is_none() {
                    return Err(());
                }
            }
        }
        Ok(())
    }
    /// Give a semantic budget stop that names no location the anchor of the unit
    /// it stopped, so each unit's stop stays its own record and says where it
    /// stopped. Any other record, and a stop that already has a location, is left
    /// as it is.
    pub(super) fn locate_semantic_budget_stop(&mut self, anchor: &PolicySourceLocation) {
        if let Self::Incompleteness {
            kind: CompositionText::SemanticBudget,
            primary: primary @ None,
            ..
        }
        | Self::Finding {
            kind: CompositionText::SemanticBudget,
            primary: primary @ None,
            ..
        } = self
        {
            *primary = Some(OutputDiagnosticLocation::capture(anchor));
        }
    }

    /// A cause that keeps the run incomplete.
    pub(super) fn incompleteness(
        kind: CompositionText,
        cause: IncompleteCause,
        family: String,
        primary: Option<&PolicySourceLocation>,
        detail: String,
    ) -> Self {
        Self::Incompleteness {
            kind,
            cause,
            family,
            primary: primary.map(OutputDiagnosticLocation::capture),
            detail,
        }
    }

    /// A cause that leaves one finding partial in a complete run.
    pub(super) fn finding(
        kind: CompositionText,
        cause: IncompleteCause,
        family: String,
        primary: Option<&PolicySourceLocation>,
        detail: String,
    ) -> Self {
        Self::Finding {
            kind,
            cause,
            family,
            primary: primary.map(OutputDiagnosticLocation::capture),
            detail,
        }
    }

    pub(super) fn sanitizer_decline(
        location: &PolicySourceLocation,
        decline: &SanitizerDecline,
    ) -> Self {
        let reason = if decline.target.is_some() {
            SanitizerDeclineReason::Admission {
                detail: decline.reason.clone(),
            }
        } else {
            SanitizerDeclineReason::GuardEvidence {
                detail: decline.reason.clone(),
            }
        };
        Self::ConditionalSanitizerDecline {
            site: OutputDiagnosticLocation::capture(location),
            sanitizer: decline.sanitizer.to_string(),
            reason,
        }
    }

    pub(super) fn provider_refusal(
        path: String,
        span: [u64; 2],
        reason: RefusalReason,
        run_incomplete: bool,
        cause: IncompleteCause,
    ) -> Self {
        Self::ProviderRefusal {
            site: OutputDiagnosticLocation {
                path,
                span: Some(span),
                region: None,
            },
            reason,
            run_incomplete,
            cause,
        }
    }
}

pub(super) fn render(record: &OutputDiagnosticRecord) -> PolicyDiagnostic {
    match record {
        OutputDiagnosticRecord::Incompleteness {
            kind,
            family,
            primary,
            detail,
            ..
        }
        | OutputDiagnosticRecord::Finding {
            kind,
            family,
            primary,
            detail,
            ..
        } => {
            let impact = if matches!(record, OutputDiagnosticRecord::Finding { .. }) {
                PolicyDiagnosticImpact::FindingPartial
            } else {
                PolicyDiagnosticImpact::RunIncomplete
            };
            let code = if matches!(kind, CompositionText::SemanticBudget) {
                PolicyDiagnosticCode::CodeQuery {
                    code: CodeQueryDiagnosticCode::SemanticBudgetExhausted,
                }
            } else {
                PolicyDiagnosticCode::EvaluationFailure
            };
            PolicyDiagnostic::try_new_in_family(
                code,
                PolicyDiagnosticSeverity::Warning,
                impact,
                family.clone(),
                super::super::finding::bounded_report_prose(kind.render(detail)),
                primary
                    .as_ref()
                    .map(OutputDiagnosticLocation::policy_location),
                Vec::new(),
            )
            .expect("captured bounded diagnostic")
        }
        OutputDiagnosticRecord::ConditionalSanitizerDecline {
            site,
            sanitizer,
            reason,
        } => {
            let display_site = site.region.map_or_else(
                || site.path.clone(),
                |region| format!("{}:{}", site.path, region[0]),
            );
            PolicyDiagnostic::try_new_in_family(
                PolicyDiagnosticCode::EvaluationFailure,
                PolicyDiagnosticSeverity::Note,
                PolicyDiagnosticImpact::Advisory,
                "taint/conditional_sanitizer_decline",
                super::super::finding::bounded_report_prose(format!(
                    "sanitizer {sanitizer} declined at {display_site}: {}",
                    reason.detail()
                )),
                Some(site.policy_location()),
                Vec::new(),
            )
            .expect("bounded sanitizer decline")
        }
        OutputDiagnosticRecord::ProviderRefusal {
            site,
            reason,
            run_incomplete,
            cause: _,
        } => {
            let site_text = format!(
                "{}:{}..{}",
                site.path.replace('\\', "/"),
                site.span.expect("refusal selector range")[0],
                site.span.expect("refusal selector range")[1]
            );
            let message = match reason {
                RefusalReason::AmbiguousCallSite(ranges) => format!(
                    "taint semantic binding refused one site: the selector row at {site_text} identifies {} distinct semantic call sites {ranges:?}, so it names no single call",
                    ranges.len()
                ),
                RefusalReason::NoSemanticCallSite => format!(
                    "taint semantic binding refused one site: the selector row at {site_text} does not identify a semantic call site"
                ),
                RefusalReason::NoValueObservation => format!(
                    "taint semantic binding refused one site: the matched source row at {site_text} produced no point-sensitive value observation"
                ),
                RefusalReason::UnidentifiedFormal { name, detail } => format!(
                    "taint semantic binding refused one site: the port `(argument :name \"{name}\")` at {site_text} does not identify one actual there: {detail}"
                ),
                RefusalReason::MissingOperand {
                    port,
                    arguments,
                    lowering_gap,
                } => format!(
                    "taint semantic binding refused one site: the port `{port}` at {site_text} names no operand of the selected call, which has {arguments} argument(s); {}",
                    if *lowering_gap {
                        "the call's lowering leaves an unanswered gap at this site"
                    } else {
                        "the call's lowering records no unanswered operand gap"
                    }
                ),
            };
            PolicyDiagnostic::new_bounded(
                PolicyDiagnosticCode::EvaluationFailure,
                PolicyDiagnosticSeverity::Warning,
                if *run_incomplete {
                    PolicyDiagnosticImpact::RunIncomplete
                } else {
                    PolicyDiagnosticImpact::Advisory
                },
                message,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#9947: zero-column stored location passed validation then panicked during render"
    )]
    fn zero_column_stored_location_is_corrupt() {
        let mut location = OutputDiagnosticLocation {
            path: "src/main.rs".to_owned(),
            span: Some([2, 7]),
            region: Some([1, 3, 1, 8]),
        };
        assert!(location.validate().is_ok());
        location.region = Some([1, 0, 1, 1]);
        assert!(location.validate().is_err());
        let record = OutputDiagnosticRecord::ProviderRefusal {
            site: location,
            reason: RefusalReason::NoSemanticCallSite,
            run_incomplete: true,
            cause: IncompleteCause::Content,
        };
        assert!(matches!(
            record.validate().map_err(|_| UnitDecodeError::Corrupt),
            Err(UnitDecodeError::Corrupt)
        ));
    }

    #[test]
    fn output_diagnostic_round_trip_and_render() {
        let location = OutputDiagnosticLocation {
            path: "src/main.rs".to_owned(),
            span: Some([2, 7]),
            region: Some([1, 3, 1, 8]),
        };
        let records = [
            OutputDiagnosticRecord::Incompleteness {
                kind: CompositionText::ExecutionRoots,
                cause: IncompleteCause::Content,
                family: "taint_analysis/partial_discovery".to_owned(),
                primary: None,
                detail: "inventory open".to_owned(),
            },
            OutputDiagnosticRecord::Finding {
                kind: CompositionText::SemanticBudget,
                cause: IncompleteCause::Operational(
                    brokk_bifrost_flow::taint::compose::OperationalCause::Budget(
                        BudgetLane::Semantic,
                    ),
                ),
                family: "taint_analysis/semantic_budget".to_owned(),
                primary: Some(location.clone()),
                detail: String::new(),
            },
            OutputDiagnosticRecord::ConditionalSanitizerDecline {
                site: location.clone(),
                sanitizer: "safe".to_owned(),
                reason: SanitizerDeclineReason::GuardEvidence {
                    detail: "guard open".to_owned(),
                },
            },
            OutputDiagnosticRecord::ProviderRefusal {
                site: location,
                reason: RefusalReason::NoSemanticCallSite,
                run_incomplete: true,
                cause: IncompleteCause::Content,
            },
        ];
        for record in records {
            let encoded = serde_json::to_vec(&record).unwrap();
            let decoded: OutputDiagnosticRecord = serde_json::from_slice(&encoded).unwrap();
            assert_eq!(record, decoded);
            assert_eq!(
                serde_json::to_value(render(&record)).unwrap(),
                serde_json::to_value(render(&decoded)).unwrap()
            );
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#9947: provider refusal with a byte span failed Output decode"
    )]
    fn provider_refusal_span_only_round_trips() {
        let record = OutputDiagnosticRecord::provider_refusal(
            "src/main.rs".to_owned(),
            [2, 7],
            RefusalReason::NoSemanticCallSite,
            true,
            IncompleteCause::Content,
        );
        let encoded = serde_json::to_vec(&record).unwrap();
        let decoded: OutputDiagnosticRecord = serde_json::from_slice(&encoded).unwrap();
        decoded.validate().unwrap();
        assert_eq!(record, decoded);
        let _ = render(&decoded);
    }

    fn artifact(path: &str) -> PolicySourceLocation {
        PolicySourceLocation::artifact(
            brokk_bifrost_analysis::analyzer::semantic::WorkspaceRelativePath::new(path).unwrap(),
        )
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#10403: the soft semantic stops of several units collapsed into one unanchored record"
    )]
    fn a_soft_semantic_stop_takes_the_anchor_of_its_unit() {
        use brokk_bifrost_flow::taint::compose::{BudgetLane, IncompleteCause, OperationalCause};
        let stop = || {
            OutputDiagnosticRecord::incompleteness(
                CompositionText::SemanticBudget,
                IncompleteCause::Operational(OperationalCause::Budget(BudgetLane::Semantic)),
                "taint_analysis/semantic_budget".to_owned(),
                None,
                String::new(),
            )
        };
        let located = |file: &str| {
            let mut record = stop();
            record.locate_semantic_budget_stop(&artifact(file));
            record
        };
        // Two soft stops with no location are one record, which is the defect.
        assert_eq!(stop().typed_identity(), stop().typed_identity());
        // Located at their units, they are two records, and each names its file.
        assert_ne!(
            located("src/a.rs").typed_identity(),
            located("src/b.rs").typed_identity()
        );
        for file in ["src/a.rs", "src/b.rs"] {
            let rendered = serde_json::to_string(&render(&located(file))).unwrap();
            assert!(rendered.contains(file), "{rendered}");
        }
        // The location survives the encoded form a stored unit uses.
        let record = located("src/a.rs");
        let decoded: OutputDiagnosticRecord =
            serde_json::from_slice(&serde_json::to_vec(&record).unwrap()).unwrap();
        decoded.validate().unwrap();
        assert_eq!(record, decoded);
        // A stop that has a location, and every other record, keep theirs.
        let mut kept = located("src/a.rs");
        kept.locate_semantic_budget_stop(&artifact("src/b.rs"));
        assert_eq!(kept, located("src/a.rs"));
        let mut other = OutputDiagnosticRecord::incompleteness(
            CompositionText::Open {
                procedure: "src/a.rs".to_owned(),
            },
            IncompleteCause::Operational(OperationalCause::Budget(BudgetLane::Semantic)),
            "taint_analysis/semantic_budget".to_owned(),
            None,
            String::new(),
        );
        let before = other.clone();
        other.locate_semantic_budget_stop(&artifact("src/b.rs"));
        assert_eq!(other, before);
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#10403: the stops of several units collapsed into one record that named no anchor"
    )]
    fn semantic_budget_stops_keep_their_detail_in_the_record_identity() {
        use brokk_bifrost_flow::taint::compose::{BudgetLane, IncompleteCause, OperationalCause};
        let record = |kind: CompositionText, detail: &str| {
            OutputDiagnosticRecord::incompleteness(
                kind,
                IncompleteCause::Operational(OperationalCause::Budget(BudgetLane::Semantic)),
                "taint_analysis/semantic_budget".to_owned(),
                None,
                detail.to_owned(),
            )
        };
        let evidence = "taint value-flow discovery exceeded the shared semantic budget: semantic resident `rows` (`evidence`) limit 9";
        let values = "taint call dispatch exceeded the shared semantic budget: semantic resident `rows` (`values`) limit 9";
        // Two stops in different lanes are two records.
        assert_ne!(
            record(CompositionText::SemanticBudget, evidence).typed_identity(),
            record(CompositionText::SemanticBudget, values).typed_identity()
        );
        // A soft stop has no detail and keeps the identity it always had.
        assert_eq!(
            record(CompositionText::SemanticBudget, "").typed_identity(),
            record(CompositionText::SemanticBudget, "").typed_identity()
        );
        // Every other cause keeps an identity that ignores its presentation detail.
        let open = |detail: &str| {
            record(
                CompositionText::Open {
                    procedure: "src/a.rs".to_owned(),
                },
                detail,
            )
        };
        assert_eq!(open("one").typed_identity(), open("two").typed_identity());
    }

    /// Two refusals that differ only in cause are different facts: publication
    /// reads the cause, so a run must not merge them, while the rendered text
    /// of both stays byte-identical so a warm report equals the cold one.
    #[test]
    fn provider_refusals_differing_only_in_cause_are_distinct_and_render_alike() {
        let refusal = |cause| {
            OutputDiagnosticRecord::provider_refusal(
                "src/main.rs".to_owned(),
                [2, 7],
                RefusalReason::NoValueObservation,
                true,
                cause,
            )
        };
        let content = refusal(IncompleteCause::Content);
        let operational = refusal(IncompleteCause::Operational(
            brokk_bifrost_flow::taint::compose::OperationalCause::Provider,
        ));
        assert_ne!(content.typed_identity(), operational.typed_identity());
        assert_eq!(
            serde_json::to_value(render(&content)).unwrap(),
            serde_json::to_value(render(&operational)).unwrap()
        );
    }

    /// A row written before the record carried a cause must not decode: its
    /// refusal would read as having no cause at all.
    #[test]
    fn provider_refusal_without_a_cause_is_corrupt() {
        let current = serde_json::to_value(OutputDiagnosticRecord::provider_refusal(
            "src/main.rs".to_owned(),
            [2, 7],
            RefusalReason::NoValueObservation,
            true,
            IncompleteCause::Content,
        ))
        .unwrap();
        let mut stored = current.clone();
        stored["provider_refusal"]
            .as_object_mut()
            .expect("an externally tagged record")
            .remove("cause")
            .expect("the record carries its cause");
        assert!(serde_json::from_value::<OutputDiagnosticRecord>(current).is_ok());
        assert!(serde_json::from_value::<OutputDiagnosticRecord>(stored).is_err());
    }

    #[test]
    fn output_diagnostic_text_matches_existing_templates() {
        let cases = [
            (
                CompositionText::ExecutionRoots,
                "no roots",
                "taint composition execution-root inventory is incomplete: no roots",
            ),
            (
                CompositionText::Open {
                    procedure: "src/main.rs".to_owned(),
                },
                "unknown",
                "taint composition found src/main.rs open: unknown",
            ),
            (
                CompositionText::SemanticBudget,
                "",
                "taint composition exhausted its semantic proof budget",
            ),
            (
                CompositionText::SemanticBudget,
                "taint value-flow discovery exceeded the shared semantic budget: semantic resident `rows` (`evidence`) limit 7",
                "taint composition exhausted its semantic proof budget: taint value-flow discovery exceeded the shared semantic budget: semantic resident `rows` (`evidence`) limit 7",
            ),
        ];
        for (kind, detail, expected) in cases {
            assert_eq!(kind.render(detail), expected);
        }
    }
}
