//! Demand-driven receiver/value analysis contracts.
//!
//! This module owns the shared object-sensitive vocabulary for issue #394. It
//! deliberately does not walk any language ASTs; language-specific providers
//! implement the trait and return these bounded outcomes.

#![allow(dead_code)]

use crate::analyzer::{CodeUnit, Language, ProjectFile, Range};

pub(crate) const DEFAULT_RECEIVER_CONTEXT_DEPTH: usize = 1;
pub(crate) const DEFAULT_RECEIVER_MAX_TARGETS: usize = 4;
pub(crate) const DEFAULT_RECEIVER_MAX_SUMMARY_EXPANSIONS: usize = 64;
pub(crate) const DEFAULT_RECEIVER_MAX_SCOPE_NODES: usize = 20_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ReceiverAnalysisOutcome<T> {
    Precise(Vec<T>),
    Ambiguous(Vec<T>),
    Unknown,
    Unsupported { reason: &'static str },
    ExceededBudget { limit: &'static str },
}

impl<T> ReceiverAnalysisOutcome<T> {
    pub(crate) fn is_precise(&self) -> bool {
        matches!(self, Self::Precise(_))
    }

    pub(crate) fn is_terminal_for_graph(&self) -> bool {
        matches!(
            self,
            Self::Ambiguous(_) | Self::Unsupported { .. } | Self::ExceededBudget { .. }
        )
    }

    pub(crate) fn into_precise(self) -> Option<Vec<T>> {
        match self {
            Self::Precise(values) => Some(values),
            Self::Ambiguous(_)
            | Self::Unknown
            | Self::Unsupported { .. }
            | Self::ExceededBudget { .. } => None,
        }
    }
}

impl<T> ReceiverAnalysisOutcome<T>
where
    T: Eq,
{
    pub(crate) fn bounded_precise(
        values: impl IntoIterator<Item = T>,
        budget: ReceiverAnalysisBudget,
    ) -> Self {
        let mut unique = Vec::new();
        for value in values {
            if unique.contains(&value) {
                continue;
            }
            unique.push(value);
            if unique.len() > budget.max_targets {
                return Self::Ambiguous(unique);
            }
        }
        if unique.is_empty() {
            Self::Unknown
        } else {
            Self::Precise(unique)
        }
    }

    pub(crate) fn single_precise_or_ambiguous(
        values: impl IntoIterator<Item = T>,
        budget: ReceiverAnalysisBudget,
    ) -> Self {
        let mut unique = Vec::new();
        for value in values {
            if unique.contains(&value) {
                continue;
            }
            unique.push(value);
            if unique.len() > budget.max_targets {
                return Self::Ambiguous(unique);
            }
        }
        match unique.len() {
            0 => Self::Unknown,
            1 => Self::Precise(unique),
            _ => Self::Ambiguous(unique),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum ReceiverValue {
    AllocationSite {
        ty: CodeUnit,
        file: ProjectFile,
        range: Range,
    },
    InstanceType(CodeUnit),
    ClassOrStaticObject(CodeUnit),
    ModuleOrExportObject(CodeUnit),
    CurrentReceiver(CodeUnit),
    FactoryReturn {
        factory: CodeUnit,
        value: Box<ReceiverValue>,
    },
}

impl ReceiverValue {
    pub(crate) fn owner(&self) -> &CodeUnit {
        match self {
            ReceiverValue::AllocationSite { ty, .. }
            | ReceiverValue::InstanceType(ty)
            | ReceiverValue::ClassOrStaticObject(ty)
            | ReceiverValue::ModuleOrExportObject(ty)
            | ReceiverValue::CurrentReceiver(ty) => ty,
            ReceiverValue::FactoryReturn { value, .. } => value.owner(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct ReceiverAnalysisBudget {
    pub(crate) context_depth: usize,
    pub(crate) max_targets: usize,
    pub(crate) max_summary_expansions: usize,
    pub(crate) max_scope_nodes: usize,
}

impl Default for ReceiverAnalysisBudget {
    fn default() -> Self {
        Self {
            context_depth: DEFAULT_RECEIVER_CONTEXT_DEPTH,
            max_targets: DEFAULT_RECEIVER_MAX_TARGETS,
            max_summary_expansions: DEFAULT_RECEIVER_MAX_SUMMARY_EXPANSIONS,
            max_scope_nodes: DEFAULT_RECEIVER_MAX_SCOPE_NODES,
        }
    }
}

impl ReceiverAnalysisBudget {
    pub(crate) fn tiny() -> Self {
        Self {
            context_depth: 0,
            max_targets: 1,
            max_summary_expansions: 1,
            max_scope_nodes: 1,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ReceiverContext<'a> {
    pub(crate) enclosing_unit: Option<&'a CodeUnit>,
    pub(crate) byte: usize,
    pub(crate) context_depth: usize,
}

impl<'a> ReceiverContext<'a> {
    pub(crate) fn new(enclosing_unit: Option<&'a CodeUnit>, byte: usize) -> Self {
        Self {
            enclosing_unit,
            byte,
            context_depth: DEFAULT_RECEIVER_CONTEXT_DEPTH,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ReceiverAnalysisQuery<'a> {
    pub(crate) language: Language,
    pub(crate) file: &'a ProjectFile,
    pub(crate) receiver_text: &'a str,
    pub(crate) receiver_range: Option<Range>,
    pub(crate) member_name: Option<&'a str>,
    pub(crate) context: ReceiverContext<'a>,
    pub(crate) budget: ReceiverAnalysisBudget,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ReceiverSummaryQuery<'a> {
    pub(crate) language: Language,
    pub(crate) file: &'a ProjectFile,
    pub(crate) call_text: &'a str,
    pub(crate) call_range: Option<Range>,
    pub(crate) callee: Option<&'a CodeUnit>,
    pub(crate) context: ReceiverContext<'a>,
    pub(crate) budget: ReceiverAnalysisBudget,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct ReceiverAnalysisCacheKey {
    pub(crate) language: Language,
    pub(crate) file: ProjectFile,
    pub(crate) start_byte: usize,
    pub(crate) end_byte: usize,
    pub(crate) expression: String,
    pub(crate) member_name: Option<String>,
    pub(crate) context_depth: usize,
    pub(crate) max_targets: usize,
}

impl ReceiverAnalysisCacheKey {
    pub(crate) fn for_receiver(query: &ReceiverAnalysisQuery<'_>) -> Self {
        let (start_byte, end_byte) = query
            .receiver_range
            .map(|range| (range.start_byte, range.end_byte))
            .unwrap_or((query.context.byte, query.context.byte));
        Self {
            language: query.language,
            file: query.file.clone(),
            start_byte,
            end_byte,
            expression: query.receiver_text.to_string(),
            member_name: query.member_name.map(str::to_string),
            context_depth: query.context.context_depth,
            max_targets: query.budget.max_targets,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ReceiverAnalysisBudgetTracker {
    budget: ReceiverAnalysisBudget,
    summary_expansions: usize,
    scope_nodes: usize,
}

impl ReceiverAnalysisBudgetTracker {
    pub(crate) fn new(budget: ReceiverAnalysisBudget) -> Self {
        Self {
            budget,
            summary_expansions: 0,
            scope_nodes: 0,
        }
    }

    pub(crate) fn record_summary_expansion(&mut self) -> Result<(), ReceiverBudgetLimit> {
        self.summary_expansions += 1;
        if self.summary_expansions > self.budget.max_summary_expansions {
            Err(ReceiverBudgetLimit::SummaryExpansions)
        } else {
            Ok(())
        }
    }

    pub(crate) fn record_scope_node(&mut self) -> Result<(), ReceiverBudgetLimit> {
        self.scope_nodes += 1;
        if self.scope_nodes > self.budget.max_scope_nodes {
            Err(ReceiverBudgetLimit::ScopeNodes)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum ReceiverBudgetLimit {
    SummaryExpansions,
    ScopeNodes,
}

impl ReceiverBudgetLimit {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            ReceiverBudgetLimit::SummaryExpansions => "summary_expansions",
            ReceiverBudgetLimit::ScopeNodes => "scope_nodes",
        }
    }

    pub(crate) fn exceeded<T>(self) -> ReceiverAnalysisOutcome<T> {
        ReceiverAnalysisOutcome::ExceededBudget {
            limit: self.as_str(),
        }
    }
}

pub(crate) trait ReceiverFactProvider {
    fn resolve_receiver(
        &self,
        query: ReceiverAnalysisQuery<'_>,
    ) -> ReceiverAnalysisOutcome<ReceiverValue>;

    fn summarize_call_result(
        &self,
        query: ReceiverSummaryQuery<'_>,
    ) -> ReceiverAnalysisOutcome<ReceiverValue>;
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct NoopReceiverFactProvider;

impl ReceiverFactProvider for NoopReceiverFactProvider {
    fn resolve_receiver(
        &self,
        _query: ReceiverAnalysisQuery<'_>,
    ) -> ReceiverAnalysisOutcome<ReceiverValue> {
        ReceiverAnalysisOutcome::Unknown
    }

    fn summarize_call_result(
        &self,
        _query: ReceiverSummaryQuery<'_>,
    ) -> ReceiverAnalysisOutcome<ReceiverValue> {
        ReceiverAnalysisOutcome::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::CodeUnitType;
    use std::path::Path;

    fn file() -> ProjectFile {
        ProjectFile::new(
            Path::new("/tmp/bifrost-receiver-analysis"),
            "src/service.ts",
        )
    }

    fn class(name: &str) -> CodeUnit {
        CodeUnit::new(file(), CodeUnitType::Class, "", name)
    }

    fn query<'a>(
        file: &'a ProjectFile,
        receiver_text: &'a str,
        budget: ReceiverAnalysisBudget,
    ) -> ReceiverAnalysisQuery<'a> {
        ReceiverAnalysisQuery {
            language: Language::TypeScript,
            file,
            receiver_text,
            receiver_range: Some(Range {
                start_byte: 10,
                end_byte: 10 + receiver_text.len(),
                start_line: 2,
                end_line: 2,
            }),
            member_name: Some("run"),
            context: ReceiverContext::new(None, 10),
            budget,
        }
    }

    #[test]
    fn bounded_precise_returns_precise_under_target_cap() {
        let service = ReceiverValue::InstanceType(class("Service"));
        let outcome = ReceiverAnalysisOutcome::bounded_precise(
            [service.clone(), service.clone()],
            ReceiverAnalysisBudget::default(),
        );

        assert_eq!(outcome, ReceiverAnalysisOutcome::Precise(vec![service]));
    }

    #[test]
    fn bounded_precise_returns_ambiguous_over_target_cap() {
        let budget = ReceiverAnalysisBudget {
            max_targets: 1,
            ..ReceiverAnalysisBudget::default()
        };
        let outcome = ReceiverAnalysisOutcome::bounded_precise(
            [
                ReceiverValue::InstanceType(class("Service")),
                ReceiverValue::InstanceType(class("Other")),
            ],
            budget,
        );

        assert!(
            matches!(outcome, ReceiverAnalysisOutcome::Ambiguous(ref values) if values.len() == 2)
        );
        assert!(outcome.is_terminal_for_graph());
    }

    #[test]
    fn bounded_precise_returns_unknown_for_empty_values() {
        let outcome = ReceiverAnalysisOutcome::<ReceiverValue>::bounded_precise(
            [],
            ReceiverAnalysisBudget::default(),
        );

        assert_eq!(outcome, ReceiverAnalysisOutcome::Unknown);
    }

    #[test]
    fn single_precise_or_ambiguous_requires_exactly_one_target() {
        let outcome = ReceiverAnalysisOutcome::single_precise_or_ambiguous(
            [
                ReceiverValue::InstanceType(class("Service")),
                ReceiverValue::InstanceType(class("Other")),
            ],
            ReceiverAnalysisBudget::default(),
        );

        assert!(matches!(
            outcome,
            ReceiverAnalysisOutcome::Ambiguous(ref values) if values.len() == 2
        ));
    }

    #[test]
    fn unsupported_is_terminal_for_graph() {
        let outcome: ReceiverAnalysisOutcome<ReceiverValue> =
            ReceiverAnalysisOutcome::Unsupported {
                reason: "language receiver model not implemented",
            };

        assert!(outcome.is_terminal_for_graph());
        assert!(!outcome.is_precise());
        assert_eq!(outcome.into_precise(), None);
    }

    #[test]
    fn budget_tracker_reports_summary_expansion_limit() {
        let mut tracker = ReceiverAnalysisBudgetTracker::new(ReceiverAnalysisBudget::tiny());

        assert!(tracker.record_summary_expansion().is_ok());
        let limit = tracker.record_summary_expansion().unwrap_err();
        assert_eq!(limit, ReceiverBudgetLimit::SummaryExpansions);
        assert_eq!(
            limit.exceeded::<ReceiverValue>(),
            ReceiverAnalysisOutcome::ExceededBudget {
                limit: "summary_expansions"
            }
        );
    }

    #[test]
    fn budget_tracker_reports_scope_node_limit() {
        let mut tracker = ReceiverAnalysisBudgetTracker::new(ReceiverAnalysisBudget::tiny());

        assert!(tracker.record_scope_node().is_ok());
        let limit = tracker.record_scope_node().unwrap_err();
        assert_eq!(limit, ReceiverBudgetLimit::ScopeNodes);
        assert_eq!(
            limit.exceeded::<ReceiverValue>(),
            ReceiverAnalysisOutcome::ExceededBudget {
                limit: "scope_nodes"
            }
        );
    }

    #[test]
    fn exceeded_budget_is_terminal_for_graph() {
        let outcome: ReceiverAnalysisOutcome<ReceiverValue> =
            ReceiverAnalysisOutcome::ExceededBudget {
                limit: "scope_nodes",
            };

        assert!(outcome.is_terminal_for_graph());
        assert!(!outcome.is_precise());
        assert_eq!(outcome.into_precise(), None);
    }

    #[test]
    fn cache_key_owns_query_identity_without_source_text() {
        let file = file();
        let budget = ReceiverAnalysisBudget::default();
        let query = query(&file, "service", budget);
        let key = ReceiverAnalysisCacheKey::for_receiver(&query);

        assert_eq!(key.language, Language::TypeScript);
        assert_eq!(key.file, file);
        assert_eq!(key.start_byte, 10);
        assert_eq!(key.end_byte, 17);
        assert_eq!(key.expression, "service");
        assert_eq!(key.member_name.as_deref(), Some("run"));
        assert_eq!(key.context_depth, DEFAULT_RECEIVER_CONTEXT_DEPTH);
        assert_eq!(key.max_targets, DEFAULT_RECEIVER_MAX_TARGETS);
    }

    #[test]
    fn noop_provider_preserves_existing_unknown_behavior() {
        let file = file();
        let provider = NoopReceiverFactProvider;
        let budget = ReceiverAnalysisBudget::default();

        assert_eq!(
            provider.resolve_receiver(query(&file, "service", budget)),
            ReceiverAnalysisOutcome::Unknown
        );

        let summary_query = ReceiverSummaryQuery {
            language: Language::TypeScript,
            file: &file,
            call_text: "makeService()",
            call_range: None,
            callee: None,
            context: ReceiverContext::new(None, 0),
            budget,
        };
        assert_eq!(
            provider.summarize_call_result(summary_query),
            ReceiverAnalysisOutcome::Unknown
        );
    }
}
