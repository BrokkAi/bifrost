use serde::Serialize;

use super::super::query::CodeQuery;
use super::super::search::CodeQueryResult;
use super::plan::{
    CodeQueryExplain, CodeQueryPhysicalOperator, PhysicalQueryNodeId, PhysicalQueryOperator,
    PhysicalQueryPlan, PhysicalQueryPlanExplain,
};
use super::scheduler::SchedulerRunProfile;

/// Structured observations from one physical query-plan execution.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct QueryExecutionProfile {
    pub(crate) format: &'static str,
    pub(crate) plan: PhysicalQueryPlanExplain,
    pub(crate) operators: Vec<QueryOperatorProfile>,
    pub(crate) peak_concurrency: usize,
    pub(crate) scheduler: SchedulerRunProfile,
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
            format: "bifrost_code_query_execution_profile/v4",
            plan: plan.explain(),
            operators: Vec::new(),
            peak_concurrency: 1,
            scheduler: SchedulerRunProfile::default(),
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

    pub(crate) fn record_scheduler_run(&mut self, run: SchedulerRunProfile) {
        self.peak_concurrency = self.peak_concurrency.max(run.peak_concurrency);
        self.scheduler = self.scheduler.saturating_add(run);
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
    pub(crate) fn saturating_add(self, other: Self) -> Self {
        Self {
            lookups: self.lookups.saturating_add(other.lookups),
            memory_hits: self.memory_hits.saturating_add(other.memory_hits),
            persisted_hydrations: self
                .persisted_hydrations
                .saturating_add(other.persisted_hydrations),
            extractions: self.extractions.saturating_add(other.extractions),
            unavailable: self.unavailable.saturating_add(other.unavailable),
            unknown_outcomes: self.unknown_outcomes.saturating_add(other.unknown_outcomes),
            replayed_files: self.replayed_files.saturating_add(other.replayed_files),
        }
    }

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
    pub(crate) fn saturating_add(self, other: Self) -> Self {
        Self {
            lookups: self.lookups.saturating_add(other.lookups),
            hits: self.hits.saturating_add(other.hits),
            misses: self.misses.saturating_add(other.misses),
            builds: self.builds.saturating_add(other.builds),
            waits: self.waits.saturating_add(other.waits),
            wait_ns: self.wait_ns.saturating_add(other.wait_ns),
            complete_hits: self.complete_hits.saturating_add(other.complete_hits),
            incomplete_hits: self.incomplete_hits.saturating_add(other.incomplete_hits),
            complete_builds: self.complete_builds.saturating_add(other.complete_builds),
            incomplete_builds: self
                .incomplete_builds
                .saturating_add(other.incomplete_builds),
            unknown_outcomes: self.unknown_outcomes.saturating_add(other.unknown_outcomes),
            replayed_items: self.replayed_items.saturating_add(other.replayed_items),
        }
    }

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
    pub(crate) fn saturating_add(self, other: Self) -> Self {
        Self {
            seed_result: self.seed_result.saturating_add(other.seed_result),
            seed_structural_facts: self
                .seed_structural_facts
                .saturating_add(other.seed_structural_facts),
            inbound_reference: self
                .inbound_reference
                .saturating_add(other.inbound_reference),
            outbound_reference: self
                .outbound_reference
                .saturating_add(other.outbound_reference),
            incoming_call: self.incoming_call.saturating_add(other.incoming_call),
            outgoing_call: self.outgoing_call.saturating_add(other.outgoing_call),
            import_forward: self.import_forward.saturating_add(other.import_forward),
            import_reverse: self.import_reverse.saturating_add(other.import_reverse),
        }
    }

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

const PUBLIC_PROFILE_FORMAT: &str = "bifrost_code_query_profile/v1";

/// Stable, versioned result and observations from one profiled query execution.
///
/// The ordinary query result is nested unchanged. Every other field is an
/// explicit projection so internal profiler evolution does not silently alter
/// the supported serialized contract.
#[derive(Debug, Serialize)]
pub struct CodeQueryProfile {
    pub format: &'static str,
    pub result: CodeQueryResult,
    pub explain: CodeQueryExplain,
    pub timings_ns: CodeQueryProfileTimings,
    pub work: CodeQueryProfileWork,
    pub cache_layers: Vec<CodeQueryProfileCacheLayer>,
    pub scheduling: CodeQueryProfileScheduling,
    pub operators: Vec<CodeQueryOperatorObservation>,
}

impl CodeQueryProfile {
    pub(crate) fn from_internal(
        query: &CodeQuery,
        result: CodeQueryResult,
        profile: QueryExecutionProfile,
    ) -> Self {
        let explain = CodeQueryExplain::from_internal_profile(query, &profile.plan);
        let bounded_dispatch = (profile.scheduler.tasks_enqueued > 0)
            .then(|| CodeQueryBoundedDispatchProfile::from_internal(profile.scheduler));

        Self {
            format: PUBLIC_PROFILE_FORMAT,
            result,
            explain,
            timings_ns: CodeQueryProfileTimings {
                planning: profile.planning_ns,
                execution: profile.execution_ns,
                rendering: profile.rendering_ns,
                total: profile.total_elapsed_ns,
            },
            work: CodeQueryProfileWork::from_internal(profile.work),
            cache_layers: CodeQueryProfileCacheLayer::from_internal(profile.cache),
            scheduling: CodeQueryProfileScheduling {
                peak_concurrency: profile.peak_concurrency,
                bounded_dispatch,
            },
            operators: profile
                .operators
                .into_iter()
                .map(CodeQueryOperatorObservation::from_internal)
                .collect(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct CodeQueryProfileTimings {
    pub planning: u64,
    pub execution: u64,
    pub rendering: u64,
    pub total: u64,
}

/// Budget-accounted work. These counters can saturate at `u64::MAX`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct CodeQueryProfileWork {
    pub scanned_files: u64,
    pub scanned_source_bytes: u64,
    pub fact_nodes: u64,
    pub pipeline_rows: u64,
    pub examined_references: u64,
    pub provenance_steps: u64,
    pub import_files_resolved: u64,
    pub import_edges_resolved: u64,
}

impl CodeQueryProfileWork {
    fn from_internal(work: QueryOperatorWorkProfile) -> Self {
        Self {
            scanned_files: work.scanned_files,
            scanned_source_bytes: work.scanned_source_bytes,
            fact_nodes: work.fact_nodes,
            pipeline_rows: work.pipeline_rows,
            examined_references: work.examined_references,
            provenance_steps: work.provenance_steps,
            import_files_resolved: work.import_files_resolved,
            import_edges_resolved: work.import_edges_resolved,
        }
    }
}

/// Deterministically ordered, semantically named cache-layer observations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "layer", rename_all = "snake_case")]
pub enum CodeQueryProfileCacheLayer {
    SeedResult {
        metrics: CodeQueryProfileCacheCounters,
    },
    SeedStructuralFacts {
        metrics: CodeQueryStructuralFactsCacheCounters,
    },
    InboundReference {
        metrics: CodeQueryProfileCacheCounters,
    },
    OutboundReference {
        metrics: CodeQueryProfileCacheCounters,
    },
    IncomingCall {
        metrics: CodeQueryProfileCacheCounters,
    },
    OutgoingCall {
        metrics: CodeQueryProfileCacheCounters,
    },
    ImportForward {
        metrics: CodeQueryProfileCacheCounters,
    },
    ImportReverse {
        metrics: CodeQueryProfileCacheCounters,
    },
}

impl CodeQueryProfileCacheLayer {
    fn from_internal(profile: QueryCacheProfile) -> Vec<Self> {
        vec![
            Self::SeedResult {
                metrics: CodeQueryProfileCacheCounters::from_internal(profile.seed_result),
            },
            Self::SeedStructuralFacts {
                metrics: CodeQueryStructuralFactsCacheCounters::from_internal(
                    profile.seed_structural_facts,
                ),
            },
            Self::InboundReference {
                metrics: CodeQueryProfileCacheCounters::from_internal(profile.inbound_reference),
            },
            Self::OutboundReference {
                metrics: CodeQueryProfileCacheCounters::from_internal(profile.outbound_reference),
            },
            Self::IncomingCall {
                metrics: CodeQueryProfileCacheCounters::from_internal(profile.incoming_call),
            },
            Self::OutgoingCall {
                metrics: CodeQueryProfileCacheCounters::from_internal(profile.outgoing_call),
            },
            Self::ImportForward {
                metrics: CodeQueryProfileCacheCounters::from_internal(profile.import_forward),
            },
            Self::ImportReverse {
                metrics: CodeQueryProfileCacheCounters::from_internal(profile.import_reverse),
            },
        ]
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct CodeQueryProfileCacheCounters {
    pub kind: CodeQueryCacheMetricsKind,
    pub lookups: u64,
    pub hits: u64,
    pub misses: u64,
    pub builds: u64,
    pub waits: u64,
    pub wait_ns: u64,
    pub complete_hits: u64,
    pub incomplete_hits: u64,
    pub complete_builds: u64,
    pub incomplete_builds: u64,
    pub unknown_outcomes: u64,
    pub replayed_items: u64,
}

impl CodeQueryProfileCacheCounters {
    fn from_internal(counters: QueryCacheLayerProfile) -> Self {
        Self {
            kind: CodeQueryCacheMetricsKind::CompleteValue,
            lookups: counters.lookups,
            hits: counters.hits,
            misses: counters.misses,
            builds: counters.builds,
            waits: counters.waits,
            wait_ns: counters.wait_ns,
            complete_hits: counters.complete_hits,
            incomplete_hits: counters.incomplete_hits,
            complete_builds: counters.complete_builds,
            incomplete_builds: counters.incomplete_builds,
            unknown_outcomes: counters.unknown_outcomes,
            replayed_items: counters.replayed_items,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct CodeQueryStructuralFactsCacheCounters {
    pub kind: CodeQueryCacheMetricsKind,
    pub lookups: u64,
    pub memory_hits: u64,
    pub persisted_hydrations: u64,
    pub extractions: u64,
    pub unavailable: u64,
    pub unknown_outcomes: u64,
    pub replayed_files: u64,
}

impl Default for CodeQueryStructuralFactsCacheCounters {
    fn default() -> Self {
        Self {
            kind: CodeQueryCacheMetricsKind::StructuralFacts,
            lookups: 0,
            memory_hits: 0,
            persisted_hydrations: 0,
            extractions: 0,
            unavailable: 0,
            unknown_outcomes: 0,
            replayed_files: 0,
        }
    }
}

impl CodeQueryStructuralFactsCacheCounters {
    fn from_internal(counters: QuerySeedStructuralFactsCacheProfile) -> Self {
        Self {
            kind: CodeQueryCacheMetricsKind::StructuralFacts,
            lookups: counters.lookups,
            memory_hits: counters.memory_hits,
            persisted_hydrations: counters.persisted_hydrations,
            extractions: counters.extractions,
            unavailable: counters.unavailable,
            unknown_outcomes: counters.unknown_outcomes,
            replayed_files: counters.replayed_files,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeQueryCacheMetricsKind {
    #[default]
    CompleteValue,
    StructuralFacts,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CodeQueryProfileScheduling {
    pub peak_concurrency: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bounded_dispatch: Option<CodeQueryBoundedDispatchProfile>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct CodeQueryBoundedDispatchProfile {
    pub worker_limit: usize,
    pub workers_spawned: usize,
    pub tasks_enqueued: usize,
    pub tasks_started: usize,
    pub tasks_completed: usize,
    pub tasks_observed_cancelled_before_start: usize,
    pub queue_wait_ns: u64,
    pub budget_wait_ns: u64,
    pub coordinator_wait_ns: u64,
    pub dispatch_overhead_ns: u64,
    pub peak_concurrency: usize,
}

impl CodeQueryBoundedDispatchProfile {
    fn from_internal(profile: SchedulerRunProfile) -> Self {
        Self {
            worker_limit: profile.worker_limit,
            workers_spawned: profile.workers_spawned,
            tasks_enqueued: profile.tasks_enqueued,
            tasks_started: profile.tasks_started,
            tasks_completed: profile.tasks_completed,
            tasks_observed_cancelled_before_start: profile.tasks_observed_cancelled_before_start,
            queue_wait_ns: profile.queue_wait_ns,
            budget_wait_ns: profile.budget_wait_ns,
            coordinator_wait_ns: profile.coordinator_wait_ns,
            dispatch_overhead_ns: profile.dispatch_overhead_ns,
            peak_concurrency: profile.peak_concurrency,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CodeQueryOperatorObservation {
    pub node: u32,
    pub branch: Vec<usize>,
    pub operator: CodeQueryPhysicalOperator,
    pub disposition: CodeQueryOperatorDisposition,
    pub timings_ns: CodeQueryOperatorTimings,
    pub input_rows: usize,
    pub rows_visited: usize,
    pub relation_expansions: usize,
    pub rows_discarded: Option<usize>,
    pub output_rows: usize,
    pub temporary_capacity_bytes_lower_bound: u64,
    pub work: CodeQueryProfileWork,
    pub cache_layers: Vec<CodeQueryProfileCacheLayer>,
    pub terminations: Vec<CodeQueryOperatorTermination>,
    pub operator_truncated: bool,
    pub result_truncated: bool,
    pub result_cancelled: bool,
}

impl CodeQueryOperatorObservation {
    fn from_internal(observation: QueryOperatorProfile) -> Self {
        Self {
            node: observation.node.get(),
            branch: observation.branch,
            operator: CodeQueryPhysicalOperator::from_internal(observation.operator),
            disposition: CodeQueryOperatorDisposition::from_internal(observation.disposition),
            timings_ns: CodeQueryOperatorTimings {
                elapsed: observation.elapsed_ns,
                total: observation.total_elapsed_ns,
                dependency_execution: observation.dependency_execution_ns,
                dependency_wait: observation.dependency_wait_ns,
                merge: observation.merge_ns,
                scheduling_overhead: observation.scheduling_overhead_ns,
            },
            input_rows: observation.input_rows,
            rows_visited: observation.rows_visited,
            relation_expansions: observation.relation_expansions,
            rows_discarded: observation.rows_discarded,
            output_rows: observation.output_rows,
            temporary_capacity_bytes_lower_bound: observation.temporary_capacity_bytes_lower_bound,
            work: CodeQueryProfileWork::from_internal(observation.work),
            cache_layers: CodeQueryProfileCacheLayer::from_internal(observation.cache),
            terminations: observation
                .terminations
                .into_iter()
                .map(CodeQueryOperatorTermination::from_internal)
                .collect(),
            operator_truncated: observation.operator_truncated,
            result_truncated: observation.result_truncated,
            result_cancelled: observation.result_cancelled,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct CodeQueryOperatorTimings {
    pub elapsed: u64,
    pub total: u64,
    pub dependency_execution: u64,
    pub dependency_wait: u64,
    pub merge: u64,
    pub scheduling_overhead: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeQueryOperatorDisposition {
    Completed,
    Skipped,
    Cancelled,
}

impl CodeQueryOperatorDisposition {
    const fn from_internal(disposition: QueryOperatorDisposition) -> Self {
        match disposition {
            QueryOperatorDisposition::Completed => Self::Completed,
            QueryOperatorDisposition::Skipped => Self::Skipped,
            QueryOperatorDisposition::Cancelled => Self::Cancelled,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeQueryOperatorTermination {
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

impl CodeQueryOperatorTermination {
    const fn from_internal(termination: QueryOperatorTermination) -> Self {
        match termination {
            QueryOperatorTermination::CancellationBeforeWork => Self::CancellationBeforeWork,
            QueryOperatorTermination::CancellationDuringWork => Self::CancellationDuringWork,
            QueryOperatorTermination::DependencyCancelled => Self::DependencyCancelled,
            QueryOperatorTermination::DependencyPipelineHalted => Self::DependencyPipelineHalted,
            QueryOperatorTermination::TerminalCap => Self::TerminalCap,
            QueryOperatorTermination::ResultLimit => Self::ResultLimit,
            QueryOperatorTermination::ExecutionBudget => Self::ExecutionBudget,
            QueryOperatorTermination::PipelineBudget => Self::PipelineBudget,
            QueryOperatorTermination::ImportGraphBudget => Self::ImportGraphBudget,
            QueryOperatorTermination::AnalysisLimit => Self::AnalysisLimit,
            QueryOperatorTermination::UnsupportedAnalysis => Self::UnsupportedAnalysis,
            QueryOperatorTermination::AnalysisIncomplete => Self::AnalysisIncomplete,
        }
    }
}

#[cfg(test)]
mod public_contract_tests {
    use serde_json::{Value, json};

    use super::*;
    use crate::analyzer::structural::execution::plan::{LogicalQueryOperator, LogicalQueryPlan};
    use crate::analyzer::structural::query::SCHEMA_VERSION;

    fn union_query() -> CodeQuery {
        CodeQuery::from_json(&json!({
            "schema_version": SCHEMA_VERSION,
            "execution_mode": "profile",
            "union": [
                { "match": { "name": "First" } },
                { "match": { "name": "Second" } }
            ],
            "limit": 20,
            "result_detail": "compact"
        }))
        .expect("profile query should parse")
    }

    fn result() -> CodeQueryResult {
        CodeQueryResult {
            results: Vec::new(),
            truncated: true,
            diagnostics: Vec::new(),
        }
    }

    #[test]
    fn public_profile_projects_stable_metrics_and_omits_internal_evidence() {
        let query = union_query();
        let logical = LogicalQueryPlan::lower(&query).expect("query should lower");
        let LogicalQueryOperator::Limit { input: union, .. } =
            logical.node(logical.root()).operator()
        else {
            panic!("root should be a limit");
        };
        let parallel_union = *union;
        let physical = PhysicalQueryPlan::select_with_parallel_union(logical, Some(parallel_union));
        let union_node = physical.node(physical.root()).dependencies()[0];
        let union_operator = physical.node(union_node).operator();
        let mut profile = QueryExecutionProfile::sequential(&physical, 11);
        profile.execution_ns = 22;
        profile.rendering_ns = 33;
        profile.total_elapsed_ns = 66;
        profile.work = QueryOperatorWorkProfile {
            scanned_files: 1,
            scanned_source_bytes: 2,
            fact_nodes: 3,
            pipeline_rows: 4,
            examined_references: 5,
            provenance_steps: 6,
            import_files_resolved: 7,
            import_edges_resolved: 8,
        };
        profile.cache.seed_result = QueryCacheLayerProfile {
            lookups: 2,
            hits: 1,
            complete_hits: 1,
            replayed_items: 3,
            ..QueryCacheLayerProfile::default()
        };
        profile.cache.seed_structural_facts = QuerySeedStructuralFactsCacheProfile {
            lookups: 2,
            memory_hits: 1,
            extractions: 1,
            replayed_files: 2,
            ..QuerySeedStructuralFactsCacheProfile::default()
        };
        profile.record_scheduler_run(SchedulerRunProfile {
            worker_limit: 2,
            workers_spawned: 2,
            tasks_enqueued: 2,
            tasks_started: 2,
            tasks_completed: 2,
            tasks_observed_cancelled_before_start: 1,
            queue_wait_ns: 41,
            worker_task_elapsed_ns: 999,
            budget_wait_ns: 42,
            coordinator_wait_ns: 43,
            dispatch_overhead_ns: 44,
            peak_concurrency: 2,
        });
        profile.record(QueryOperatorProfile {
            node: union_node,
            branch: vec![1],
            operator: union_operator,
            disposition: QueryOperatorDisposition::Cancelled,
            elapsed_ns: 12,
            total_elapsed_ns: 20,
            dependency_execution_ns: 3,
            dependency_wait_ns: 4,
            merge_ns: 5,
            scheduling_overhead_ns: 6,
            input_rows: 7,
            rows_visited: 8,
            relation_expansions: 9,
            rows_discarded: Some(10),
            temporary_capacity_bytes_lower_bound: 11,
            work: QueryOperatorWorkProfile {
                scanned_files: 8,
                scanned_source_bytes: 7,
                fact_nodes: 6,
                pipeline_rows: 5,
                examined_references: 4,
                provenance_steps: 3,
                import_files_resolved: 2,
                import_edges_resolved: 1,
            },
            cache: QueryCacheProfile {
                seed_result: QueryCacheLayerProfile {
                    lookups: 1,
                    misses: 1,
                    ..QueryCacheLayerProfile::default()
                },
                ..QueryCacheProfile::default()
            },
            terminations: vec![
                QueryOperatorTermination::CancellationDuringWork,
                QueryOperatorTermination::ResultLimit,
            ],
            output_rows: 12,
            operator_truncated: true,
            result_truncated: true,
            result_cancelled: true,
        });

        let public = CodeQueryProfile::from_internal(&query, result(), profile);
        let value = serde_json::to_value(&public).expect("public profile should serialize");

        assert_eq!(value["format"], "bifrost_code_query_profile/v1");
        assert_eq!(value["result"], json!({ "results": [], "truncated": true }));
        assert_eq!(
            value["explain"]["scheduling"],
            json!({
                "policy": "auto",
                "selected": "parallel",
                "max_concurrency": 2
            })
        );
        assert_eq!(
            value["timings_ns"],
            json!({
                "planning": 11,
                "execution": 22,
                "rendering": 33,
                "total": 66
            })
        );
        assert_eq!(
            value["work"],
            json!({
                "scanned_files": 1,
                "scanned_source_bytes": 2,
                "fact_nodes": 3,
                "pipeline_rows": 4,
                "examined_references": 5,
                "provenance_steps": 6,
                "import_files_resolved": 7,
                "import_edges_resolved": 8
            })
        );
        assert_eq!(
            cache_layer_names(&value["cache_layers"]),
            [
                "seed_result",
                "seed_structural_facts",
                "inbound_reference",
                "outbound_reference",
                "incoming_call",
                "outgoing_call",
                "import_forward",
                "import_reverse",
            ]
        );
        assert_eq!(
            value["cache_layers"][0],
            json!({
                "layer": "seed_result",
                "metrics": {
                    "kind": "complete_value",
                    "lookups": 2,
                    "hits": 1,
                    "misses": 0,
                    "builds": 0,
                    "waits": 0,
                    "wait_ns": 0,
                    "complete_hits": 1,
                    "incomplete_hits": 0,
                    "complete_builds": 0,
                    "incomplete_builds": 0,
                    "unknown_outcomes": 0,
                    "replayed_items": 3
                }
            })
        );
        assert_eq!(
            value["cache_layers"][1]["metrics"]["kind"],
            "structural_facts"
        );
        assert_eq!(
            value["scheduling"],
            json!({
                "peak_concurrency": 2,
                "bounded_dispatch": {
                    "worker_limit": 2,
                    "workers_spawned": 2,
                    "tasks_enqueued": 2,
                    "tasks_started": 2,
                    "tasks_completed": 2,
                    "tasks_observed_cancelled_before_start": 1,
                    "queue_wait_ns": 41,
                    "budget_wait_ns": 42,
                    "coordinator_wait_ns": 43,
                    "dispatch_overhead_ns": 44,
                    "peak_concurrency": 2
                }
            })
        );
        assert_eq!(
            value["operators"][0]["timings_ns"],
            json!({
                "elapsed": 12,
                "total": 20,
                "dependency_execution": 3,
                "dependency_wait": 4,
                "merge": 5,
                "scheduling_overhead": 6
            })
        );
        assert_eq!(value["operators"][0]["node"], union_node.get());
        assert_eq!(value["operators"][0]["branch"], json!([1]));
        assert_eq!(value["operators"][0]["operator"], "parallel_union");
        assert_eq!(value["operators"][0]["disposition"], "cancelled");
        assert_eq!(
            value["operators"][0]["temporary_capacity_bytes_lower_bound"],
            11
        );
        assert_eq!(
            value["operators"][0]["terminations"],
            json!(["cancellation_during_work", "result_limit"])
        );
        assert_eq!(value["operators"][0]["operator_truncated"], true);
        assert_eq!(value["operators"][0]["result_truncated"], true);
        assert_eq!(value["operators"][0]["result_cancelled"], true);
        assert_eq!(
            cache_layer_names(&value["operators"][0]["cache_layers"]),
            cache_layer_names(&value["cache_layers"])
        );

        let serialized = serde_json::to_string(&public).expect("public profile should serialize");
        for internal_field in [
            "bifrost_code_query_execution_profile/v4",
            "execution_work",
            "rendering_work",
            "worker_task_elapsed_ns",
            "final_in_authored_suffix",
            "derived_layer_request",
            "projection_filter_fingerprint",
            "representation_version",
        ] {
            assert!(!serialized.contains(internal_field));
        }
    }

    #[test]
    fn public_profile_omits_bounded_dispatch_when_scheduler_did_not_run() {
        let query = union_query();
        let physical = PhysicalQueryPlan::select_with_parallel_union(
            LogicalQueryPlan::lower(&query).expect("query should lower"),
            None,
        );
        let profile = QueryExecutionProfile::sequential(&physical, 0);

        let value =
            serde_json::to_value(CodeQueryProfile::from_internal(&query, result(), profile))
                .expect("public profile should serialize");

        assert_eq!(value["scheduling"], json!({ "peak_concurrency": 1 }));
    }

    fn cache_layer_names(value: &Value) -> Vec<&str> {
        value
            .as_array()
            .expect("cache layers should be an array")
            .iter()
            .map(|layer| {
                layer["layer"]
                    .as_str()
                    .expect("cache layer should have a string tag")
            })
            .collect()
    }
}
