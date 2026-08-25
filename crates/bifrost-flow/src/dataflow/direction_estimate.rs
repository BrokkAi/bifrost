//! Reachability estimates for direction planning over one ICFG snapshot.
//!
//! The planner compares the bounded work reachable from the query's source
//! and demand endpoints.  This module deliberately only measures topology;
//! callers supply the directional transfer fan-out and logical endpoint
//! counts because those values belong to the data-flow domain rather than the
//! graph itself.

use std::collections::{HashSet, VecDeque};

use crate::analyzer::semantic::{IcfgEdgeId, IcfgNodeId, IcfgSnapshot, ProgramPointHandle};

use super::budget::DataflowRequest;
use super::direction::{
    DataflowDirectionCapabilities, DataflowDirectionEstimate, DataflowDirectionPlan,
    DataflowDirectionPlanningError, DataflowDirectionRequirements, plan_dataflow_direction,
};

/// Estimate the two directional reachable slices in one immutable snapshot.
///
/// `forward_seed_nodes` are traversed through successor edges and
/// `backward_demand_nodes` through predecessor edges.  Nodes and edges are
/// counted once even when several endpoints reach the same part of the
/// snapshot.  The endpoint counts are passed separately because a caller may
/// bind multiple logical sources or sinks to one snapshot node.
///
/// Invalid endpoint IDs are not part of the snapshot slice and therefore do
/// not contribute reachable nodes or edges.  The caller-provided endpoint
/// counts are retained as-is so the planner can still account for those
/// logical bindings.  Traversal is iterative and follows the snapshot's
/// stable adjacency order; the result is consequently independent of hash
/// iteration order.
pub fn estimate_snapshot_reachable_slices(
    snapshot: &IcfgSnapshot,
    forward_seed_nodes: &[IcfgNodeId],
    backward_demand_nodes: &[IcfgNodeId],
    forward_transfer_fanout: usize,
    backward_transfer_fanout: usize,
    bound_sources: usize,
    bound_sinks: usize,
) -> DataflowDirectionEstimate {
    let forward = reachable_slice(snapshot, forward_seed_nodes, Traversal::Forward);
    let backward = reachable_slice(snapshot, backward_demand_nodes, Traversal::Backward);

    DataflowDirectionEstimate::new(
        forward.nodes,
        forward.edges,
        forward_transfer_fanout,
        backward.nodes,
        backward.edges,
        backward_transfer_fanout,
        bound_sources,
        bound_sinks,
    )
}

/// Bind semantic program points to every context-specific node in a snapshot.
///
/// A point can occur in several bounded call contexts. The returned dense IDs
/// include every such occurrence once, in stable snapshot order.
pub fn snapshot_node_ids_for_points(
    snapshot: &IcfgSnapshot,
    points: &[&ProgramPointHandle],
) -> Vec<IcfgNodeId> {
    snapshot
        .nodes()
        .iter()
        .enumerate()
        .filter(|(_, node)| points.iter().any(|point| node.point() == *point))
        .map(|(index, _)| {
            IcfgNodeId::new(u32::try_from(index).expect("validated snapshot node IDs fit in u32"))
        })
        .collect()
}

/// Estimate and plan one snapshot-compatible query from its request controls.
///
/// This is the common planning step for domain clients: omitted configuration
/// on [`DataflowRequest`] uses `Auto`, while tests and advanced callers can
/// force a supported direction through the same request. Bounded-snapshot and
/// complete-reverse-semantics requirements are always applied by this entry
/// point, so omitting a requirement cannot enable an incomplete backward run.
#[allow(clippy::too_many_arguments)]
pub fn plan_snapshot_dataflow_direction(
    request: &DataflowRequest<'_>,
    snapshot: &IcfgSnapshot,
    forward_seed_nodes: &[IcfgNodeId],
    backward_demand_nodes: &[IcfgNodeId],
    forward_transfer_fanout: usize,
    backward_transfer_fanout: usize,
    bound_sources: usize,
    bound_sinks: usize,
    capabilities: DataflowDirectionCapabilities,
    requirements: DataflowDirectionRequirements,
) -> Result<DataflowDirectionPlan, DataflowDirectionPlanningError> {
    let requirements = requirements
        .with_bounded_snapshot(true)
        .with_complete_reverse_semantics(true);
    let estimate = estimate_snapshot_reachable_slices(
        snapshot,
        forward_seed_nodes,
        backward_demand_nodes,
        forward_transfer_fanout,
        backward_transfer_fanout,
        bound_sources,
        bound_sinks,
    );
    plan_dataflow_direction(
        request.query_plan_config(),
        estimate,
        capabilities,
        requirements,
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ReachableSlice {
    nodes: usize,
    edges: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Traversal {
    Forward,
    Backward,
}

fn reachable_slice(
    snapshot: &IcfgSnapshot,
    endpoints: &[IcfgNodeId],
    traversal: Traversal,
) -> ReachableSlice {
    let mut seen_nodes = HashSet::with_capacity(endpoints.len());
    let mut seen_edges = HashSet::<IcfgEdgeId>::new();
    let mut pending = VecDeque::with_capacity(endpoints.len());

    for &endpoint in endpoints {
        if snapshot.node(endpoint).is_some() && seen_nodes.insert(endpoint) {
            pending.push_back(endpoint);
        }
    }

    while let Some(node) = pending.pop_front() {
        match traversal {
            Traversal::Forward => {
                for (edge_id, edge) in snapshot.successor_edges(node) {
                    if seen_edges.insert(edge_id) && seen_nodes.insert(edge.target) {
                        pending.push_back(edge.target);
                    }
                }
            }
            Traversal::Backward => {
                for (edge_id, edge) in snapshot.predecessor_edges(node) {
                    if seen_edges.insert(edge_id) && seen_nodes.insert(edge.source) {
                        pending.push_back(edge.source);
                    }
                }
            }
        }
    }

    ReachableSlice {
        // Set cardinalities cannot overflow: each set contains at most one
        // entry per snapshot ID.  Keeping these as cardinalities also avoids
        // any arithmetic that could turn a bounded estimate into a wrapped
        // value on unusual platforms.
        nodes: seen_nodes.len(),
        edges: seen_edges.len(),
    }
}
