use serde::Serialize;

use super::plan::{
    PhysicalQueryNodeId, PhysicalQueryOperator, PhysicalQueryPlan, PhysicalQueryPlanExplain,
};

/// Structured observations from one physical query-plan execution.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct QueryExecutionProfile {
    pub(crate) plan: PhysicalQueryPlanExplain,
    pub(crate) operators: Vec<QueryOperatorProfile>,
    pub(crate) peak_concurrency: usize,
}

impl QueryExecutionProfile {
    pub(crate) fn sequential(plan: &PhysicalQueryPlan) -> Self {
        Self {
            plan: plan.explain(),
            operators: Vec::new(),
            peak_concurrency: 1,
        }
    }

    pub(crate) fn record(&mut self, observation: QueryOperatorProfile) {
        self.operators.push(observation);
    }
}

/// Whether this operator ran, was bypassed by a dependency, or observed
/// cancellation while doing its own work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum QueryOperatorDisposition {
    Completed,
    Skipped,
    Cancelled,
}

/// One physical-operator invocation observation.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct QueryOperatorProfile {
    pub(crate) node: PhysicalQueryNodeId,
    /// Ordered set-branch slots from the root to this invocation. This keeps
    /// repeated executions of one shared DAG node independently attributable.
    pub(crate) branch: Vec<usize>,
    pub(crate) operator: PhysicalQueryOperator,
    pub(crate) disposition: QueryOperatorDisposition,
    pub(crate) elapsed_ns: u64,
    pub(crate) input_rows: usize,
    /// Rows forwarded to the parent. A skipped operator can forward a
    /// dependency's valid cancellation-safe partial rows without producing
    /// rows of its own; `disposition` distinguishes that case.
    pub(crate) output_rows: usize,
    /// This operator clipped or incompletely produced its own output.
    pub(crate) operator_truncated: bool,
    /// The aggregated execution result propagated upward was incomplete.
    pub(crate) result_truncated: bool,
    /// The aggregated execution result propagated upward was cancelled.
    pub(crate) result_cancelled: bool,
}
