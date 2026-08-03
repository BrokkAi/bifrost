use serde::Serialize;
use std::time::Duration;

/// Observed production phase costs for one retained compatible taint batch.
///
/// These measurements describe the work that produced the immutable retained
/// plan/report pair. They are diagnostic observations only: no policy decision,
/// completeness result, or cache behavior depends on them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct ProductionTaintPhaseMetrics {
    plan_discovery_and_summary_binding_ns: u64,
    batch_planning_ns: u64,
    propagation_ns: u64,
    finding_and_witness_reconstruction_ns: u64,
    standalone_projection_ns: u64,
    policy_projection_ns: u64,
    compatible_policy_count: usize,
    propagation_solves: usize,
}

impl ProductionTaintPhaseMetrics {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        plan_discovery_and_summary_binding: Duration,
        batch_planning: Duration,
        propagation: Duration,
        finding_and_witness_reconstruction: Duration,
        standalone_projection: Duration,
        policy_projection: Duration,
        compatible_policy_count: usize,
        propagation_solves: usize,
    ) -> Self {
        Self {
            plan_discovery_and_summary_binding_ns: duration_ns(plan_discovery_and_summary_binding),
            batch_planning_ns: duration_ns(batch_planning),
            propagation_ns: duration_ns(propagation),
            finding_and_witness_reconstruction_ns: duration_ns(finding_and_witness_reconstruction),
            standalone_projection_ns: duration_ns(standalone_projection),
            policy_projection_ns: duration_ns(policy_projection),
            compatible_policy_count,
            propagation_solves,
        }
    }

    pub const fn plan_discovery_and_summary_binding_ns(&self) -> u64 {
        self.plan_discovery_and_summary_binding_ns
    }

    pub const fn batch_planning_ns(&self) -> u64 {
        self.batch_planning_ns
    }

    pub const fn propagation_ns(&self) -> u64 {
        self.propagation_ns
    }

    pub const fn finding_and_witness_reconstruction_ns(&self) -> u64 {
        self.finding_and_witness_reconstruction_ns
    }

    pub const fn standalone_projection_ns(&self) -> u64 {
        self.standalone_projection_ns
    }

    pub const fn policy_projection_ns(&self) -> u64 {
        self.policy_projection_ns
    }

    pub const fn compatible_policy_count(&self) -> usize {
        self.compatible_policy_count
    }

    pub const fn propagation_solves(&self) -> usize {
        self.propagation_solves
    }
}

fn duration_ns(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}
