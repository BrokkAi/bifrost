use serde::Serialize;

use super::plan::{
    PhysicalQueryNodeId, PhysicalQueryOperator, PhysicalQueryPlan, PhysicalQueryPlanExplain,
};

/// Structured observations from one physical query-plan execution.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct QueryExecutionProfile {
    pub(crate) format: &'static str,
    pub(crate) plan: PhysicalQueryPlanExplain,
    pub(crate) operators: Vec<QueryOperatorProfile>,
    pub(crate) peak_concurrency: usize,
    pub(crate) planning_ns: u64,
    pub(crate) execution_ns: u64,
    pub(crate) rendering_ns: u64,
    pub(crate) total_elapsed_ns: u64,
    /// Budget-accounted work performed while physical operators executed.
    pub(crate) execution_work: QueryOperatorWorkProfile,
    /// Budget-accounted source hydration performed after physical execution
    /// while retaining evidence and rendering public rows.
    pub(crate) rendering_work: QueryOperatorWorkProfile,
    /// Total budget-accounted request work (`execution_work + rendering_work`).
    pub(crate) work: QueryOperatorWorkProfile,
    pub(crate) cache: QueryCacheProfile,
}

impl QueryExecutionProfile {
    pub(crate) fn sequential(plan: &PhysicalQueryPlan, planning_ns: u64) -> Self {
        Self {
            format: "bifrost_code_query_execution_profile/v2",
            plan: plan.explain(),
            operators: Vec::new(),
            peak_concurrency: 1,
            planning_ns,
            execution_ns: 0,
            rendering_ns: 0,
            total_elapsed_ns: 0,
            execution_work: QueryOperatorWorkProfile::default(),
            rendering_work: QueryOperatorWorkProfile::default(),
            work: QueryOperatorWorkProfile::default(),
            cache: QueryCacheProfile::default(),
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

/// A reason an operator did not consume all work available to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum QueryOperatorTermination {
    CancellationBeforeWork,
    CancellationDuringWork,
    DependencyCancelled,
    DependencyPipelineHalted,
    TerminalCap,
    ResultLimit,
    ExecutionBudget,
    PipelineBudget,
    ImportGraphBudget,
    AnalysisLimit,
    UnsupportedAnalysis,
    AnalysisIncomplete,
}

/// Budget-accounted query work plus exact observational graph-build work
/// attributed to one operator invocation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub(crate) struct QueryOperatorWorkProfile {
    pub(crate) scanned_files: u64,
    pub(crate) scanned_source_bytes: u64,
    pub(crate) fact_nodes: u64,
    pub(crate) pipeline_rows: u64,
    pub(crate) examined_references: u64,
    pub(crate) provenance_steps: u64,
    pub(crate) import_files_resolved: u64,
    pub(crate) import_edges_resolved: u64,
}

impl QueryOperatorWorkProfile {
    #[cfg(test)]
    pub(crate) fn saturating_add(self, other: Self) -> Self {
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
            provenance_steps: self.provenance_steps.saturating_add(other.provenance_steps),
            import_files_resolved: self
                .import_files_resolved
                .saturating_add(other.import_files_resolved),
            import_edges_resolved: self
                .import_edges_resolved
                .saturating_add(other.import_edges_resolved),
        }
    }

    pub(crate) fn saturating_sub(self, earlier: Self) -> Self {
        Self {
            scanned_files: self.scanned_files.saturating_sub(earlier.scanned_files),
            scanned_source_bytes: self
                .scanned_source_bytes
                .saturating_sub(earlier.scanned_source_bytes),
            fact_nodes: self.fact_nodes.saturating_sub(earlier.fact_nodes),
            pipeline_rows: self.pipeline_rows.saturating_sub(earlier.pipeline_rows),
            examined_references: self
                .examined_references
                .saturating_sub(earlier.examined_references),
            provenance_steps: self
                .provenance_steps
                .saturating_sub(earlier.provenance_steps),
            import_files_resolved: self
                .import_files_resolved
                .saturating_sub(earlier.import_files_resolved),
            import_edges_resolved: self
                .import_edges_resolved
                .saturating_sub(earlier.import_edges_resolved),
        }
    }
}

/// Completeness-sensitive counters for one cache layer.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub(crate) struct QueryCacheLayerProfile {
    pub(crate) lookups: u64,
    pub(crate) hits: u64,
    pub(crate) misses: u64,
    pub(crate) builds: u64,
    pub(crate) waits: u64,
    pub(crate) wait_ns: u64,
    pub(crate) complete_hits: u64,
    pub(crate) incomplete_hits: u64,
    pub(crate) complete_builds: u64,
    pub(crate) incomplete_builds: u64,
    pub(crate) unknown_outcomes: u64,
    /// Cached payload items made available to the consumer before
    /// relation-specific filtering and projection. This can exceed emitted
    /// rows; `relation_expansions` records post-filter expansions separately.
    pub(crate) replayed_items: u64,
}

/// Exact outcomes for structural-facts lookups performed by seed scans.
/// Other analyzer subsystems can consult the same provider internally, so the
/// field name deliberately scopes these counters to the observable seed path.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub(crate) struct QuerySeedStructuralFactsCacheProfile {
    pub(crate) lookups: u64,
    pub(crate) memory_hits: u64,
    pub(crate) persisted_hydrations: u64,
    pub(crate) extractions: u64,
    pub(crate) unavailable: u64,
    pub(crate) unknown_outcomes: u64,
    pub(crate) replayed_files: u64,
}

impl QuerySeedStructuralFactsCacheProfile {
    pub(crate) fn record_memory_hit(&mut self, available: bool) {
        self.lookups = self.lookups.saturating_add(1);
        self.memory_hits = self.memory_hits.saturating_add(1);
        self.replayed_files = self.replayed_files.saturating_add(u64::from(available));
    }

    pub(crate) fn record_persisted_hydration(&mut self) {
        self.lookups = self.lookups.saturating_add(1);
        self.persisted_hydrations = self.persisted_hydrations.saturating_add(1);
    }

    pub(crate) fn record_extraction(&mut self) {
        self.lookups = self.lookups.saturating_add(1);
        self.extractions = self.extractions.saturating_add(1);
    }

    pub(crate) fn record_unavailable(&mut self) {
        self.lookups = self.lookups.saturating_add(1);
        self.unavailable = self.unavailable.saturating_add(1);
    }

    pub(crate) fn record_unknown(&mut self) {
        self.lookups = self.lookups.saturating_add(1);
        self.unknown_outcomes = self.unknown_outcomes.saturating_add(1);
    }

    pub(crate) fn saturating_sub(self, earlier: Self) -> Self {
        Self {
            lookups: self.lookups.saturating_sub(earlier.lookups),
            memory_hits: self.memory_hits.saturating_sub(earlier.memory_hits),
            persisted_hydrations: self
                .persisted_hydrations
                .saturating_sub(earlier.persisted_hydrations),
            extractions: self.extractions.saturating_sub(earlier.extractions),
            unavailable: self.unavailable.saturating_sub(earlier.unavailable),
            unknown_outcomes: self
                .unknown_outcomes
                .saturating_sub(earlier.unknown_outcomes),
            replayed_files: self.replayed_files.saturating_sub(earlier.replayed_files),
        }
    }
}

impl QueryCacheLayerProfile {
    pub(crate) fn record_hit(&mut self, complete: Option<bool>, replayed_items: usize) {
        self.lookups = self.lookups.saturating_add(1);
        self.hits = self.hits.saturating_add(1);
        self.replayed_items = self
            .replayed_items
            .saturating_add(u64::try_from(replayed_items).unwrap_or(u64::MAX));
        match complete {
            Some(true) => self.complete_hits = self.complete_hits.saturating_add(1),
            Some(false) => self.incomplete_hits = self.incomplete_hits.saturating_add(1),
            None => self.unknown_outcomes = self.unknown_outcomes.saturating_add(1),
        }
    }

    pub(crate) fn record_miss(&mut self) {
        self.lookups = self.lookups.saturating_add(1);
        self.misses = self.misses.saturating_add(1);
    }

    pub(crate) fn record_build(&mut self, complete: Option<bool>) {
        self.builds = self.builds.saturating_add(1);
        match complete {
            Some(true) => self.complete_builds = self.complete_builds.saturating_add(1),
            Some(false) => self.incomplete_builds = self.incomplete_builds.saturating_add(1),
            None => self.unknown_outcomes = self.unknown_outcomes.saturating_add(1),
        }
    }

    pub(crate) fn saturating_sub(self, earlier: Self) -> Self {
        Self {
            lookups: self.lookups.saturating_sub(earlier.lookups),
            hits: self.hits.saturating_sub(earlier.hits),
            misses: self.misses.saturating_sub(earlier.misses),
            builds: self.builds.saturating_sub(earlier.builds),
            waits: self.waits.saturating_sub(earlier.waits),
            wait_ns: self.wait_ns.saturating_sub(earlier.wait_ns),
            complete_hits: self.complete_hits.saturating_sub(earlier.complete_hits),
            incomplete_hits: self.incomplete_hits.saturating_sub(earlier.incomplete_hits),
            complete_builds: self.complete_builds.saturating_sub(earlier.complete_builds),
            incomplete_builds: self
                .incomplete_builds
                .saturating_sub(earlier.incomplete_builds),
            unknown_outcomes: self
                .unknown_outcomes
                .saturating_sub(earlier.unknown_outcomes),
            replayed_items: self.replayed_items.saturating_sub(earlier.replayed_items),
        }
    }
}

/// Cache observations are split by lifecycle because a bounded request-local
/// result is not equivalent to a complete generation-keyed derived layer.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub(crate) struct QueryCacheProfile {
    pub(crate) seed_result: QueryCacheLayerProfile,
    pub(crate) seed_structural_facts: QuerySeedStructuralFactsCacheProfile,
    pub(crate) inbound_reference: QueryCacheLayerProfile,
    pub(crate) outbound_reference: QueryCacheLayerProfile,
    pub(crate) incoming_call: QueryCacheLayerProfile,
    pub(crate) outgoing_call: QueryCacheLayerProfile,
    pub(crate) import_forward: QueryCacheLayerProfile,
    pub(crate) import_reverse: QueryCacheLayerProfile,
}

impl QueryCacheProfile {
    pub(crate) fn saturating_sub(self, earlier: Self) -> Self {
        Self {
            seed_result: self.seed_result.saturating_sub(earlier.seed_result),
            seed_structural_facts: self
                .seed_structural_facts
                .saturating_sub(earlier.seed_structural_facts),
            inbound_reference: self
                .inbound_reference
                .saturating_sub(earlier.inbound_reference),
            outbound_reference: self
                .outbound_reference
                .saturating_sub(earlier.outbound_reference),
            incoming_call: self.incoming_call.saturating_sub(earlier.incoming_call),
            outgoing_call: self.outgoing_call.saturating_sub(earlier.outgoing_call),
            import_forward: self.import_forward.saturating_sub(earlier.import_forward),
            import_reverse: self.import_reverse.saturating_sub(earlier.import_reverse),
        }
    }
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
    /// Operator-local wall time, excluding inline dependency execution.
    pub(crate) elapsed_ns: u64,
    /// Inclusive wall time from invocation entry through its returned value.
    pub(crate) total_elapsed_ns: u64,
    /// Wall time spent synchronously executing dependency subtrees.
    pub(crate) dependency_execution_ns: u64,
    /// Idle time waiting for an already-running scheduled dependency. The
    /// serial executor has no such lifecycle, so this remains zero until M4;
    /// M3 same-key materialization waits belong to the cache `wait_ns` fields.
    pub(crate) dependency_wait_ns: u64,
    /// Time spent attaching branch provenance/diagnostics and combining sets.
    pub(crate) merge_ns: u64,
    /// Ready-queue/enqueue/dequeue overhead. There is no scheduler in M2.
    pub(crate) scheduling_overhead_ns: u64,
    pub(crate) input_rows: usize,
    /// Input rows actually visited by this operator. This can be smaller than
    /// `input_rows` after cancellation or an early output cap.
    pub(crate) rows_visited: usize,
    /// Relation expansions produced after relation-specific filtering and
    /// projection, before the generic output de-duplication pass.
    pub(crate) relation_expansions: usize,
    /// Exact discarded-row count for row-to-row operators. Expansion
    /// operators report `None` rather than a misleading zero.
    pub(crate) rows_discarded: Option<usize>,
    /// Lower bound from temporary Vec/HashMap/HashSet inline capacities. Heap
    /// payloads owned by strings, paths, traces, and nested vectors are omitted.
    pub(crate) temporary_capacity_bytes_lower_bound: u64,
    pub(crate) work: QueryOperatorWorkProfile,
    pub(crate) cache: QueryCacheProfile,
    pub(crate) terminations: Vec<QueryOperatorTermination>,
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
