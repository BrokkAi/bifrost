//! Direction selection for bounded data-flow queries.
//!
//! The planner is deliberately independent from any particular data-flow
//! domain.  Clients describe the work they expect in each direction and the
//! capabilities their result requires; the planner only selects an already
//! supported solver.

use std::{error::Error, fmt};

use crate::analyzer::semantic::SemanticWork;

use super::budget::SolverWork;

/// Direction requested by a data-flow query.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DataflowDirectionRequest {
    /// Select the direction using the configured heuristic.
    #[default]
    Auto,
    /// Always use forward propagation.
    Forward,
    /// Always use backward propagation.
    Backward,
}

/// Direction selected for a data-flow query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DataflowDirection {
    Forward,
    Backward,
}

impl DataflowDirectionRequest {
    /// Return the concrete direction for an explicit request.
    pub const fn explicit_direction(self) -> Option<DataflowDirection> {
        match self {
            Self::Auto => None,
            Self::Forward => Some(DataflowDirection::Forward),
            Self::Backward => Some(DataflowDirection::Backward),
        }
    }
}

/// The default hysteresis applied by an automatic direction selection.
pub const DEFAULT_MINIMUM_BACKWARD_SAVINGS_PERCENT: u8 = 20;

/// Per-query direction selection controls.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DataflowQueryPlanConfig {
    pub direction: DataflowDirectionRequest,
    pub minimum_backward_savings_percent: u8,
}

impl DataflowQueryPlanConfig {
    /// Construct a configuration using the default savings threshold.
    pub const fn new(direction: DataflowDirectionRequest) -> Self {
        Self {
            direction,
            minimum_backward_savings_percent: DEFAULT_MINIMUM_BACKWARD_SAVINGS_PERCENT,
        }
    }

    /// Construct a configuration with an explicit savings threshold.
    ///
    /// Values over 100 are rejected by [`plan_dataflow_direction`].  Keeping
    /// construction infallible lets configuration remain a small owned value
    /// in [`DataflowRequest`](super::DataflowRequest), while the planner still
    /// reports malformed input as a typed error.
    pub const fn with_minimum_backward_savings_percent(
        mut self,
        minimum_backward_savings_percent: u8,
    ) -> Self {
        self.minimum_backward_savings_percent = minimum_backward_savings_percent;
        self
    }

    /// Return this configuration with a different direction request.
    pub const fn with_direction(mut self, direction: DataflowDirectionRequest) -> Self {
        self.direction = direction;
        self
    }

    pub const fn direction(self) -> DataflowDirectionRequest {
        self.direction
    }

    pub const fn minimum_backward_savings_percent(self) -> u8 {
        self.minimum_backward_savings_percent
    }
}

impl Default for DataflowQueryPlanConfig {
    fn default() -> Self {
        Self::new(DataflowDirectionRequest::Auto)
    }
}

/// A capability that may be required by a query result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DataflowDirectionCapability {
    /// The direction can solve over a bounded immutable ICFG snapshot.
    BoundedSnapshot,
    /// The direction models the reverse semantic relation completely.
    CompleteReverseSemantics,
    /// The direction can produce reusable procedure summaries.
    ReusableSummaries,
    /// The direction can produce normalized path witnesses.
    NormalizedWitnesses,
}

impl DataflowDirectionCapability {
    pub const fn name(self) -> &'static str {
        match self {
            Self::BoundedSnapshot => "bounded_snapshot",
            Self::CompleteReverseSemantics => "complete_reverse_semantics",
            Self::ReusableSummaries => "reusable_summaries",
            Self::NormalizedWitnesses => "normalized_witnesses",
        }
    }
}

impl fmt::Display for DataflowDirectionCapability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())
    }
}

/// Capabilities available to each propagation direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DataflowDirectionCapabilities {
    pub forward_bounded_snapshot: bool,
    pub backward_bounded_snapshot: bool,
    pub backward_reverse_semantics_complete: bool,
    pub forward_reusable_summaries: bool,
    pub backward_reusable_summaries: bool,
    pub forward_normalized_witnesses: bool,
    pub backward_normalized_witnesses: bool,
}

impl DataflowDirectionCapabilities {
    /// Capabilities currently implemented by the flow engine.  Backward
    /// summary and normalized-witness production remain intentionally absent.
    pub const fn current() -> Self {
        Self {
            forward_bounded_snapshot: true,
            backward_bounded_snapshot: true,
            backward_reverse_semantics_complete: false,
            forward_reusable_summaries: true,
            backward_reusable_summaries: false,
            forward_normalized_witnesses: true,
            backward_normalized_witnesses: false,
        }
    }

    /// Capabilities useful for tests and callers that provide all result
    /// implementations themselves.
    pub const fn all_supported() -> Self {
        Self {
            forward_bounded_snapshot: true,
            backward_bounded_snapshot: true,
            backward_reverse_semantics_complete: true,
            forward_reusable_summaries: true,
            backward_reusable_summaries: true,
            forward_normalized_witnesses: true,
            backward_normalized_witnesses: true,
        }
    }

    /// Capabilities for a bounded snapshot solve in either direction.
    pub const fn bounded_snapshot() -> Self {
        Self {
            forward_bounded_snapshot: true,
            backward_bounded_snapshot: true,
            backward_reverse_semantics_complete: true,
            forward_reusable_summaries: false,
            backward_reusable_summaries: false,
            forward_normalized_witnesses: false,
            backward_normalized_witnesses: false,
        }
    }

    pub const fn supports(
        self,
        direction: DataflowDirection,
        requirements: DataflowDirectionRequirements,
    ) -> bool {
        self.missing_capability(direction, requirements).is_none()
    }

    /// Return the first missing capability in stable requirement order.
    pub const fn missing_capability(
        self,
        direction: DataflowDirection,
        requirements: DataflowDirectionRequirements,
    ) -> Option<DataflowDirectionCapability> {
        let bounded_snapshot = match direction {
            DataflowDirection::Forward => self.forward_bounded_snapshot,
            DataflowDirection::Backward => self.backward_bounded_snapshot,
        };
        if requirements.bounded_snapshot && !bounded_snapshot {
            return Some(DataflowDirectionCapability::BoundedSnapshot);
        }

        if matches!(direction, DataflowDirection::Backward)
            && requirements.complete_reverse_semantics
            && !self.backward_reverse_semantics_complete
        {
            return Some(DataflowDirectionCapability::CompleteReverseSemantics);
        }

        let reusable_summaries = match direction {
            DataflowDirection::Forward => self.forward_reusable_summaries,
            DataflowDirection::Backward => self.backward_reusable_summaries,
        };
        if requirements.reusable_summaries && !reusable_summaries {
            return Some(DataflowDirectionCapability::ReusableSummaries);
        }

        let normalized_witnesses = match direction {
            DataflowDirection::Forward => self.forward_normalized_witnesses,
            DataflowDirection::Backward => self.backward_normalized_witnesses,
        };
        if requirements.normalized_witnesses && !normalized_witnesses {
            return Some(DataflowDirectionCapability::NormalizedWitnesses);
        }

        None
    }
}

impl Default for DataflowDirectionCapabilities {
    fn default() -> Self {
        Self::current()
    }
}

/// Result capabilities required by a query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct DataflowDirectionRequirements {
    pub bounded_snapshot: bool,
    pub complete_reverse_semantics: bool,
    pub reusable_summaries: bool,
    pub normalized_witnesses: bool,
}

impl DataflowDirectionRequirements {
    pub const fn none() -> Self {
        Self {
            bounded_snapshot: false,
            complete_reverse_semantics: false,
            reusable_summaries: false,
            normalized_witnesses: false,
        }
    }

    pub const fn bounded_snapshot() -> Self {
        Self {
            bounded_snapshot: true,
            ..Self::none()
        }
    }

    pub const fn with_bounded_snapshot(mut self, required: bool) -> Self {
        self.bounded_snapshot = required;
        self
    }

    pub const fn with_complete_reverse_semantics(mut self, required: bool) -> Self {
        self.complete_reverse_semantics = required;
        self
    }

    pub const fn with_reusable_summaries(mut self, required: bool) -> Self {
        self.reusable_summaries = required;
        self
    }

    pub const fn with_normalized_witnesses(mut self, required: bool) -> Self {
        self.normalized_witnesses = required;
        self
    }
}

/// Direction-neutral estimate of the work in each propagation direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct DataflowDirectionEstimate {
    pub forward_nodes: usize,
    pub forward_edges: usize,
    pub forward_transfer_fanout: usize,
    pub backward_nodes: usize,
    pub backward_edges: usize,
    pub backward_transfer_fanout: usize,
    pub bound_sources: usize,
    pub bound_sinks: usize,
}

impl DataflowDirectionEstimate {
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        forward_nodes: usize,
        forward_edges: usize,
        forward_transfer_fanout: usize,
        backward_nodes: usize,
        backward_edges: usize,
        backward_transfer_fanout: usize,
        bound_sources: usize,
        bound_sinks: usize,
    ) -> Self {
        Self {
            forward_nodes,
            forward_edges,
            forward_transfer_fanout,
            backward_nodes,
            backward_edges,
            backward_transfer_fanout,
            bound_sources,
            bound_sinks,
        }
    }

    /// Conservative forward work estimate using saturating arithmetic.
    pub const fn forward_cost(self) -> usize {
        self.forward_nodes
            .saturating_add(self.forward_edges)
            .saturating_add(self.forward_transfer_fanout)
            .saturating_add(self.bound_sources)
    }

    /// Conservative backward work estimate using saturating arithmetic.
    pub const fn backward_cost(self) -> usize {
        self.backward_nodes
            .saturating_add(self.backward_edges)
            .saturating_add(self.backward_transfer_fanout)
            .saturating_add(self.bound_sinks)
    }

    pub const fn cost(self, direction: DataflowDirection) -> usize {
        match direction {
            DataflowDirection::Forward => self.forward_cost(),
            DataflowDirection::Backward => self.backward_cost(),
        }
    }
}

/// Why the planner selected a direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DataflowDirectionSelectionReason {
    ExplicitForward,
    ExplicitBackward,
    AutoBackwardSavings,
    AutoForwardTie,
    AutoForwardInsufficientSavings,
    AutoForwardMissingBackwardCapability(DataflowDirectionCapability),
    AutoBackwardMissingForwardCapability(DataflowDirectionCapability),
}

impl DataflowDirectionSelectionReason {
    /// Stable machine-readable reason code for logs and persisted diagnostics.
    pub const fn code(self) -> &'static str {
        match self {
            Self::ExplicitForward => "explicit_forward",
            Self::ExplicitBackward => "explicit_backward",
            Self::AutoBackwardSavings => "auto_backward_savings",
            Self::AutoForwardTie => "auto_forward_tie",
            Self::AutoForwardInsufficientSavings => "auto_forward_insufficient_savings",
            Self::AutoForwardMissingBackwardCapability(_) => {
                "auto_forward_missing_backward_capability"
            }
            Self::AutoBackwardMissingForwardCapability(_) => {
                "auto_backward_missing_forward_capability"
            }
        }
    }

    pub const fn capability(self) -> Option<DataflowDirectionCapability> {
        match self {
            Self::AutoForwardMissingBackwardCapability(capability)
            | Self::AutoBackwardMissingForwardCapability(capability) => Some(capability),
            _ => None,
        }
    }
}

impl fmt::Display for DataflowDirectionSelectionReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

/// The complete, direction-independent output of planning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DataflowDirectionPlan {
    request: DataflowDirectionRequest,
    direction: DataflowDirection,
    reason: DataflowDirectionSelectionReason,
    estimate: DataflowDirectionEstimate,
    capabilities: DataflowDirectionCapabilities,
    requirements: DataflowDirectionRequirements,
}

impl DataflowDirectionPlan {
    pub const fn request(self) -> DataflowDirectionRequest {
        self.request
    }

    pub const fn direction(self) -> DataflowDirection {
        self.direction
    }

    pub const fn selected_direction(self) -> DataflowDirection {
        self.direction
    }

    pub const fn reason(self) -> DataflowDirectionSelectionReason {
        self.reason
    }

    pub const fn estimate(self) -> DataflowDirectionEstimate {
        self.estimate
    }

    pub const fn capabilities(self) -> DataflowDirectionCapabilities {
        self.capabilities
    }

    pub const fn requirements(self) -> DataflowDirectionRequirements {
        self.requirements
    }

    pub const fn estimated_forward_cost(self) -> usize {
        self.estimate.forward_cost()
    }

    pub const fn estimated_backward_cost(self) -> usize {
        self.estimate.backward_cost()
    }

    /// Pair this pre-propagation decision with the work charged by its run.
    pub const fn record_work(
        self,
        snapshot_work: SemanticWork,
        propagation_work: SolverWork,
    ) -> DataflowDirectionExecutionMetrics {
        DataflowDirectionExecutionMetrics {
            plan: self,
            snapshot_work,
            propagation_work,
        }
    }
}

/// Observable estimates and actual charges for one planned data-flow run.
///
/// Snapshot construction is reported separately because it is shared by both
/// candidate directions and should not distort propagation comparisons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataflowDirectionExecutionMetrics {
    plan: DataflowDirectionPlan,
    snapshot_work: SemanticWork,
    propagation_work: SolverWork,
}

impl DataflowDirectionExecutionMetrics {
    pub const fn plan(self) -> DataflowDirectionPlan {
        self.plan
    }

    pub const fn direction(self) -> DataflowDirection {
        self.plan.direction()
    }

    pub const fn reason(self) -> DataflowDirectionSelectionReason {
        self.plan.reason()
    }

    pub const fn snapshot_work(self) -> SemanticWork {
        self.snapshot_work
    }

    pub const fn propagation_work(self) -> SolverWork {
        self.propagation_work
    }
}

/// Failure to honor a direction request or to validate its configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DataflowDirectionPlanningError {
    InvalidMinimumBackwardSavingsPercent {
        percent: u8,
    },
    UnsupportedDirection {
        requested: DataflowDirectionRequest,
        direction: DataflowDirection,
        missing: DataflowDirectionCapability,
    },
    NoSupportedDirection {
        missing_forward: DataflowDirectionCapability,
        missing_backward: DataflowDirectionCapability,
    },
}

impl DataflowDirectionPlanningError {
    pub const fn requested(self) -> Option<DataflowDirectionRequest> {
        match self {
            Self::UnsupportedDirection { requested, .. } => Some(requested),
            Self::InvalidMinimumBackwardSavingsPercent { .. }
            | Self::NoSupportedDirection { .. } => None,
        }
    }

    pub const fn missing_capability(self) -> Option<DataflowDirectionCapability> {
        match self {
            Self::UnsupportedDirection { missing, .. } => Some(missing),
            Self::InvalidMinimumBackwardSavingsPercent { .. } => None,
            Self::NoSupportedDirection { .. } => None,
        }
    }
}

impl fmt::Display for DataflowDirectionPlanningError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMinimumBackwardSavingsPercent { percent } => write!(
                formatter,
                "minimum backward savings percent must be at most 100, got {percent}"
            ),
            Self::UnsupportedDirection {
                requested,
                direction,
                missing,
            } => write!(
                formatter,
                "requested {requested:?} direction {direction:?} requires unsupported {missing}"
            ),
            Self::NoSupportedDirection {
                missing_forward,
                missing_backward,
            } => write!(
                formatter,
                "neither direction is supported: forward lacks {missing_forward}, backward lacks {missing_backward}"
            ),
        }
    }
}

impl Error for DataflowDirectionPlanningError {}

/// Select a propagation direction from a query configuration, work estimate,
/// and direction-specific capability requirements.
pub const fn plan_dataflow_direction(
    config: DataflowQueryPlanConfig,
    estimate: DataflowDirectionEstimate,
    capabilities: DataflowDirectionCapabilities,
    requirements: DataflowDirectionRequirements,
) -> Result<DataflowDirectionPlan, DataflowDirectionPlanningError> {
    if config.minimum_backward_savings_percent > 100 {
        return Err(
            DataflowDirectionPlanningError::InvalidMinimumBackwardSavingsPercent {
                percent: config.minimum_backward_savings_percent,
            },
        );
    }

    let forward_missing = capabilities.missing_capability(DataflowDirection::Forward, requirements);
    let backward_missing =
        capabilities.missing_capability(DataflowDirection::Backward, requirements);

    let plan = match config.direction {
        DataflowDirectionRequest::Forward => {
            if let Some(missing) = forward_missing {
                return Err(DataflowDirectionPlanningError::UnsupportedDirection {
                    requested: config.direction,
                    direction: DataflowDirection::Forward,
                    missing,
                });
            }
            (
                DataflowDirection::Forward,
                DataflowDirectionSelectionReason::ExplicitForward,
            )
        }
        DataflowDirectionRequest::Backward => {
            if let Some(missing) = backward_missing {
                return Err(DataflowDirectionPlanningError::UnsupportedDirection {
                    requested: config.direction,
                    direction: DataflowDirection::Backward,
                    missing,
                });
            }
            (
                DataflowDirection::Backward,
                DataflowDirectionSelectionReason::ExplicitBackward,
            )
        }
        DataflowDirectionRequest::Auto => match (forward_missing, backward_missing) {
            (Some(missing_forward), Some(missing_backward)) => {
                return Err(DataflowDirectionPlanningError::NoSupportedDirection {
                    missing_forward,
                    missing_backward,
                });
            }
            (Some(missing), None) => (
                DataflowDirection::Backward,
                DataflowDirectionSelectionReason::AutoBackwardMissingForwardCapability(missing),
            ),
            (None, Some(missing)) => (
                DataflowDirection::Forward,
                DataflowDirectionSelectionReason::AutoForwardMissingBackwardCapability(missing),
            ),
            (None, None) => {
                let forward_cost = estimate.forward_cost();
                let backward_cost = estimate.backward_cost();
                if forward_cost == backward_cost {
                    (
                        DataflowDirection::Forward,
                        DataflowDirectionSelectionReason::AutoForwardTie,
                    )
                } else if backward_cost < forward_cost
                    && (backward_cost as u128) * 100
                        <= (forward_cost as u128)
                            * (100 - config.minimum_backward_savings_percent) as u128
                {
                    (
                        DataflowDirection::Backward,
                        DataflowDirectionSelectionReason::AutoBackwardSavings,
                    )
                } else {
                    (
                        DataflowDirection::Forward,
                        DataflowDirectionSelectionReason::AutoForwardInsufficientSavings,
                    )
                }
            }
        },
    };

    Ok(DataflowDirectionPlan {
        request: config.direction,
        direction: plan.0,
        reason: plan.1,
        estimate,
        capabilities,
        requirements,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const REQUIREMENTS: DataflowDirectionRequirements = DataflowDirectionRequirements::none();
    const CAPABILITIES: DataflowDirectionCapabilities =
        DataflowDirectionCapabilities::all_supported();

    fn estimate(forward: usize, backward: usize) -> DataflowDirectionEstimate {
        DataflowDirectionEstimate::new(forward, 0, 0, backward, 0, 0, 0, 0)
    }

    #[test]
    fn auto_defaults_to_forward_for_ties_and_selects_at_threshold() {
        let tie = plan_dataflow_direction(
            DataflowQueryPlanConfig::default(),
            estimate(100, 100),
            CAPABILITIES,
            REQUIREMENTS,
        )
        .unwrap();
        assert_eq!(tie.direction(), DataflowDirection::Forward);
        assert_eq!(
            tie.reason(),
            DataflowDirectionSelectionReason::AutoForwardTie
        );

        let threshold = plan_dataflow_direction(
            DataflowQueryPlanConfig::default(),
            estimate(100, 80),
            CAPABILITIES,
            REQUIREMENTS,
        )
        .unwrap();
        assert_eq!(threshold.direction(), DataflowDirection::Backward);
        assert_eq!(
            threshold.reason(),
            DataflowDirectionSelectionReason::AutoBackwardSavings
        );
    }

    #[test]
    fn zero_cost_tie_still_prefers_forward() {
        let plan = plan_dataflow_direction(
            DataflowQueryPlanConfig::default(),
            DataflowDirectionEstimate::default(),
            CAPABILITIES,
            REQUIREMENTS,
        )
        .unwrap();
        assert_eq!(plan.direction(), DataflowDirection::Forward);
    }

    #[test]
    fn estimate_costs_saturate_without_wrapping() {
        let estimate = DataflowDirectionEstimate::new(
            usize::MAX,
            usize::MAX,
            usize::MAX,
            usize::MAX - 1,
            1,
            1,
            0,
            0,
        );
        assert_eq!(estimate.forward_cost(), usize::MAX);
        assert_eq!(estimate.backward_cost(), usize::MAX);
    }

    #[test]
    fn bound_observations_contribute_to_their_directional_cost() {
        let estimate = DataflowDirectionEstimate::new(100, 0, 0, 100, 0, 0, 100, 0);
        let plan = plan_dataflow_direction(
            DataflowQueryPlanConfig::default(),
            estimate,
            CAPABILITIES,
            REQUIREMENTS,
        )
        .unwrap();

        assert_eq!(estimate.forward_cost(), 200);
        assert_eq!(estimate.backward_cost(), 100);
        assert_eq!(plan.direction(), DataflowDirection::Backward);
    }

    #[test]
    fn explicit_directions_are_deterministic() {
        let forward = plan_dataflow_direction(
            DataflowQueryPlanConfig::new(DataflowDirectionRequest::Forward),
            estimate(1000, 1),
            CAPABILITIES,
            REQUIREMENTS,
        )
        .unwrap();
        assert_eq!(forward.direction(), DataflowDirection::Forward);
        assert_eq!(
            forward.reason(),
            DataflowDirectionSelectionReason::ExplicitForward
        );

        let backward = plan_dataflow_direction(
            DataflowQueryPlanConfig::new(DataflowDirectionRequest::Backward),
            estimate(1, 1000),
            CAPABILITIES,
            REQUIREMENTS,
        )
        .unwrap();
        assert_eq!(backward.direction(), DataflowDirection::Backward);
        assert_eq!(
            backward.reason(),
            DataflowDirectionSelectionReason::ExplicitBackward
        );
    }

    #[test]
    fn explicit_backward_reports_the_missing_capability() {
        let requirements = DataflowDirectionRequirements::none().with_reusable_summaries(true);
        let capabilities = DataflowDirectionCapabilities::current();
        let error = plan_dataflow_direction(
            DataflowQueryPlanConfig::new(DataflowDirectionRequest::Backward),
            estimate(1, 1),
            capabilities,
            requirements,
        )
        .unwrap_err();
        assert_eq!(
            error,
            DataflowDirectionPlanningError::UnsupportedDirection {
                requested: DataflowDirectionRequest::Backward,
                direction: DataflowDirection::Backward,
                missing: DataflowDirectionCapability::ReusableSummaries,
            }
        );
    }

    #[test]
    fn auto_falls_forward_for_each_missing_backward_capability() {
        for (requirements, missing) in [
            (
                DataflowDirectionRequirements::none().with_bounded_snapshot(true),
                DataflowDirectionCapability::BoundedSnapshot,
            ),
            (
                DataflowDirectionRequirements::none().with_reusable_summaries(true),
                DataflowDirectionCapability::ReusableSummaries,
            ),
            (
                DataflowDirectionRequirements::none().with_normalized_witnesses(true),
                DataflowDirectionCapability::NormalizedWitnesses,
            ),
            (
                DataflowDirectionRequirements::none().with_complete_reverse_semantics(true),
                DataflowDirectionCapability::CompleteReverseSemantics,
            ),
        ] {
            let capabilities = DataflowDirectionCapabilities {
                backward_bounded_snapshot: missing != DataflowDirectionCapability::BoundedSnapshot,
                backward_reverse_semantics_complete: missing
                    != DataflowDirectionCapability::CompleteReverseSemantics,
                backward_reusable_summaries: missing
                    != DataflowDirectionCapability::ReusableSummaries,
                backward_normalized_witnesses: missing
                    != DataflowDirectionCapability::NormalizedWitnesses,
                ..CAPABILITIES
            };
            let plan = plan_dataflow_direction(
                DataflowQueryPlanConfig::default(),
                estimate(1000, 1),
                capabilities,
                requirements,
            )
            .unwrap();
            assert_eq!(plan.direction(), DataflowDirection::Forward);
            assert_eq!(
                plan.reason(),
                DataflowDirectionSelectionReason::AutoForwardMissingBackwardCapability(missing)
            );
        }
    }

    #[test]
    fn incomplete_reverse_semantics_gates_auto_and_explicit_backward() {
        let requirements =
            DataflowDirectionRequirements::none().with_complete_reverse_semantics(true);
        let capabilities = DataflowDirectionCapabilities::current();
        let auto = plan_dataflow_direction(
            DataflowQueryPlanConfig::default(),
            estimate(10_000, 1),
            capabilities,
            requirements,
        )
        .unwrap();
        assert_eq!(auto.direction(), DataflowDirection::Forward);
        assert_eq!(
            auto.reason(),
            DataflowDirectionSelectionReason::AutoForwardMissingBackwardCapability(
                DataflowDirectionCapability::CompleteReverseSemantics
            )
        );

        let explicit = plan_dataflow_direction(
            DataflowQueryPlanConfig::new(DataflowDirectionRequest::Backward),
            estimate(10_000, 1),
            capabilities,
            requirements,
        )
        .unwrap_err();
        assert_eq!(
            explicit,
            DataflowDirectionPlanningError::UnsupportedDirection {
                requested: DataflowDirectionRequest::Backward,
                direction: DataflowDirection::Backward,
                missing: DataflowDirectionCapability::CompleteReverseSemantics,
            }
        );
    }

    #[test]
    fn invalid_threshold_is_typed() {
        let error = plan_dataflow_direction(
            DataflowQueryPlanConfig::default().with_minimum_backward_savings_percent(101),
            estimate(100, 1),
            CAPABILITIES,
            REQUIREMENTS,
        )
        .unwrap_err();
        assert_eq!(
            error,
            DataflowDirectionPlanningError::InvalidMinimumBackwardSavingsPercent { percent: 101 }
        );
    }

    #[test]
    fn execution_metrics_keep_snapshot_and_propagation_work_separate() {
        let plan = plan_dataflow_direction(
            DataflowQueryPlanConfig::default(),
            estimate(100, 10),
            CAPABILITIES,
            REQUIREMENTS,
        )
        .unwrap();
        let snapshot_work = SemanticWork {
            control_edges: 7,
            ..SemanticWork::default()
        };
        let propagation_work = SolverWork {
            propagated_outputs: 13,
            ..SolverWork::default()
        };
        let metrics = plan.record_work(snapshot_work, propagation_work);

        assert_eq!(metrics.direction(), DataflowDirection::Backward);
        assert_eq!(metrics.snapshot_work(), snapshot_work);
        assert_eq!(metrics.propagation_work(), propagation_work);
    }
}
