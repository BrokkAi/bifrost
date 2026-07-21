use std::fmt;

use serde::Serialize;

use crate::hash::HashMap;

use super::super::query::{
    CodeQuery, CodeQueryPlan, CodeQueryPlanSource, CodeQuerySeed, QueryError, QueryStep,
    QueryValueKind, SetOperator,
};
use super::derived::DerivedLayerRequest;

/// A dense, plan-local identifier for one logical operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub(crate) struct LogicalQueryNodeId(u32);

impl LogicalQueryNodeId {
    pub(crate) const fn get(self) -> u32 {
        self.0
    }

    const fn index(self) -> usize {
        self.0 as usize
    }

    fn from_index(index: usize) -> Self {
        Self(u32::try_from(index).expect("validated CodeQuery plans fit in u32 node IDs"))
    }
}

/// One operation in the storage-neutral logical query DAG.
#[derive(Debug, Clone)]
pub(crate) enum LogicalQueryOperator {
    Seed(Box<CodeQuerySeed>),
    Step {
        input: LogicalQueryNodeId,
        step: QueryStep,
        /// Whether this step ended its authored pipeline suffix before lowering.
        /// The sequential executor needs this to preserve partial-row behavior on
        /// cancellation after splitting a suffix into individual DAG nodes.
        final_in_authored_suffix: bool,
    },
    Set {
        op: SetOperator,
        inputs: Box<[LogicalQueryNodeId]>,
    },
    Limit {
        input: LogicalQueryNodeId,
        count: usize,
    },
}

impl LogicalQueryOperator {
    fn dependencies(&self) -> &[LogicalQueryNodeId] {
        match self {
            Self::Seed(_) => &[],
            Self::Step { input, .. } | Self::Limit { input, .. } => std::slice::from_ref(input),
            Self::Set { inputs, .. } => inputs,
        }
    }
}

/// An arena entry in a [`LogicalQueryPlan`].
#[derive(Debug, Clone)]
pub(crate) struct LogicalQueryNode {
    operator: LogicalQueryOperator,
    output_kind: QueryValueKind,
}

impl LogicalQueryNode {
    pub(crate) fn operator(&self) -> &LogicalQueryOperator {
        &self.operator
    }

    pub(crate) const fn output_kind(&self) -> QueryValueKind {
        self.output_kind
    }
}

/// A logical query DAG stored in dependency-first arena order.
#[derive(Debug, Clone)]
pub(crate) struct LogicalQueryPlan {
    nodes: Vec<LogicalQueryNode>,
    root: LogicalQueryNodeId,
}

impl LogicalQueryPlan {
    /// Validate the authored semantic plan and lower it into a shared logical DAG.
    pub(crate) fn lower(query: &CodeQuery) -> Result<Self, QueryError> {
        let validated_output = query.validate_steps()?;
        let mut builder = LogicalQueryPlanBuilder::default();
        let (input, output_kind) = builder.lower_authored_plan(&query.plan);
        debug_assert_eq!(output_kind, validated_output);

        let root = builder.push_node(
            LogicalQueryOperator::Limit {
                input,
                count: query.limit,
            },
            output_kind,
        );
        let plan = Self {
            nodes: builder.nodes,
            root,
        };
        plan.validate_dependency_order()
            .map_err(|error| QueryError {
                path: "plan".to_owned(),
                message: error.to_string(),
            })?;
        Ok(plan)
    }

    pub(crate) fn node(&self, id: LogicalQueryNodeId) -> &LogicalQueryNode {
        &self.nodes[id.index()]
    }

    pub(crate) const fn root(&self) -> LogicalQueryNodeId {
        self.root
    }

    fn validate_dependency_order(&self) -> Result<(), LogicalPlanValidationError> {
        if self.root.index() >= self.nodes.len() {
            return Err(LogicalPlanValidationError::MissingRoot {
                root: self.root,
                node_count: self.nodes.len(),
            });
        }

        for (consumer_index, node) in self.nodes.iter().enumerate() {
            let consumer = LogicalQueryNodeId::from_index(consumer_index);
            for &dependency in node.operator.dependencies() {
                if dependency.index() >= consumer_index {
                    return Err(LogicalPlanValidationError::DependencyNotBeforeConsumer {
                        consumer,
                        dependency,
                    });
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum LogicalPlanValidationError {
    MissingRoot {
        root: LogicalQueryNodeId,
        node_count: usize,
    },
    DependencyNotBeforeConsumer {
        consumer: LogicalQueryNodeId,
        dependency: LogicalQueryNodeId,
    },
}

impl fmt::Display for LogicalPlanValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingRoot { root, node_count } => write!(
                formatter,
                "logical root {} is outside the {node_count}-node arena",
                root.get()
            ),
            Self::DependencyNotBeforeConsumer {
                consumer,
                dependency,
            } => write!(
                formatter,
                "logical node {} depends on node {}, which does not precede it",
                consumer.get(),
                dependency.get()
            ),
        }
    }
}

#[derive(Default)]
struct LogicalQueryPlanBuilder {
    nodes: Vec<LogicalQueryNode>,
    interned_seeds: HashMap<String, LogicalQueryNodeId>,
}

impl LogicalQueryPlanBuilder {
    fn lower_authored_plan(
        &mut self,
        plan: &CodeQueryPlan,
    ) -> (LogicalQueryNodeId, QueryValueKind) {
        // Authored plan depth is validated and capped at MAX_QUERY_PLAN_DEPTH before this
        // bounded recursive lowering begins.
        let (mut input, mut output_kind) = match &plan.source {
            CodeQueryPlanSource::Seed(seed) => {
                let key = seed.canonical_cache_key();
                if let Some(&existing) = self.interned_seeds.get(&key) {
                    (existing, QueryValueKind::StructuralMatch)
                } else {
                    let id = self.push_node(
                        LogicalQueryOperator::Seed(seed.clone()),
                        QueryValueKind::StructuralMatch,
                    );
                    self.interned_seeds.insert(key, id);
                    (id, QueryValueKind::StructuralMatch)
                }
            }
            CodeQueryPlanSource::Set { op, branches } => {
                let lowered = branches
                    .iter()
                    .map(|branch| self.lower_authored_plan(branch))
                    .collect::<Vec<_>>();
                let output_kind = lowered
                    .first()
                    .expect("validated set operations contain at least two branches")
                    .1;
                let inputs = lowered
                    .into_iter()
                    .map(|(input, branch_kind)| {
                        debug_assert_eq!(branch_kind, output_kind);
                        input
                    })
                    .collect::<Box<[_]>>();
                let id = self.push_node(LogicalQueryOperator::Set { op: *op, inputs }, output_kind);
                (id, output_kind)
            }
        };

        for (step_index, step) in plan.steps.iter().enumerate() {
            let step_output = step
                .output_kind(output_kind)
                .expect("typed query steps were validated before lowering");
            input = self.push_node(
                LogicalQueryOperator::Step {
                    input,
                    step: step.clone(),
                    final_in_authored_suffix: step_index + 1 == plan.steps.len(),
                },
                step_output,
            );
            output_kind = step_output;
        }
        (input, output_kind)
    }

    fn push_node(
        &mut self,
        operator: LogicalQueryOperator,
        output_kind: QueryValueKind,
    ) -> LogicalQueryNodeId {
        let id = LogicalQueryNodeId::from_index(self.nodes.len());
        debug_assert!(
            operator
                .dependencies()
                .iter()
                .all(|dependency| dependency.index() < id.index()),
            "logical dependencies must precede their consumer"
        );
        self.nodes.push(LogicalQueryNode {
            operator,
            output_kind,
        });
        id
    }
}

/// A dense, plan-local identifier for one physical operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub(crate) struct PhysicalQueryNodeId(u32);

impl PhysicalQueryNodeId {
    const fn index(self) -> usize {
        self.0 as usize
    }

    const fn from_logical(id: LogicalQueryNodeId) -> Self {
        Self(id.get())
    }
}

/// The concrete Milestone-1 implementation selected for one logical operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PhysicalQueryOperator {
    SeedScan,
    PipelineStep,
    SequentialUnion,
    ParallelUnion,
    SequentialIntersection,
    SequentialExcept,
    Limit,
}

/// An arena entry in a [`PhysicalQueryPlan`].
#[derive(Debug, Clone)]
pub(crate) struct PhysicalQueryNode {
    logical_node: LogicalQueryNodeId,
    operator: PhysicalQueryOperator,
    dependencies: Box<[PhysicalQueryNodeId]>,
    derived_layer_request: Option<DerivedLayerRequest>,
}

impl PhysicalQueryNode {
    pub(crate) const fn logical_node(&self) -> LogicalQueryNodeId {
        self.logical_node
    }

    pub(crate) const fn operator(&self) -> PhysicalQueryOperator {
        self.operator
    }

    pub(crate) fn dependencies(&self) -> &[PhysicalQueryNodeId] {
        &self.dependencies
    }

    pub(crate) const fn derived_layer_request(&self) -> Option<DerivedLayerRequest> {
        self.derived_layer_request
    }
}

/// A one-to-one physical implementation of a logical query DAG.
#[derive(Debug, Clone)]
pub(crate) struct PhysicalQueryPlan {
    logical: LogicalQueryPlan,
    nodes: Vec<PhysicalQueryNode>,
    root: PhysicalQueryNodeId,
}

impl PhysicalQueryPlan {
    #[cfg(test)]
    pub(crate) fn select(logical: LogicalQueryPlan) -> Self {
        Self::select_with_parallel_union(logical, None)
    }

    pub(crate) fn select_with_parallel_union(
        logical: LogicalQueryPlan,
        parallel_union: Option<LogicalQueryNodeId>,
    ) -> Self {
        logical
            .validate_dependency_order()
            .expect("logical plan lowering establishes dependency order");

        let nodes = logical
            .nodes
            .iter()
            .enumerate()
            .map(|(index, node)| {
                let logical_node = LogicalQueryNodeId::from_index(index);
                let operator = match node.operator() {
                    LogicalQueryOperator::Seed(_) => PhysicalQueryOperator::SeedScan,
                    LogicalQueryOperator::Step { .. } => PhysicalQueryOperator::PipelineStep,
                    LogicalQueryOperator::Set { op, .. } => match op {
                        SetOperator::Union if parallel_union == Some(logical_node) => {
                            PhysicalQueryOperator::ParallelUnion
                        }
                        SetOperator::Union => PhysicalQueryOperator::SequentialUnion,
                        SetOperator::Intersect => PhysicalQueryOperator::SequentialIntersection,
                        SetOperator::Except => PhysicalQueryOperator::SequentialExcept,
                    },
                    LogicalQueryOperator::Limit { .. } => PhysicalQueryOperator::Limit,
                };
                let dependencies = node
                    .operator()
                    .dependencies()
                    .iter()
                    .copied()
                    .map(PhysicalQueryNodeId::from_logical)
                    .collect();
                let derived_layer_request = match node.operator() {
                    LogicalQueryOperator::Step {
                        step: QueryStep::ImportersOf,
                        ..
                    } => Some(DerivedLayerRequest::complete_direct_import_topology()),
                    _ => None,
                };
                PhysicalQueryNode {
                    logical_node,
                    operator,
                    dependencies,
                    derived_layer_request,
                }
            })
            .collect();
        let root = PhysicalQueryNodeId::from_logical(logical.root);
        Self {
            logical,
            nodes,
            root,
        }
    }

    pub(crate) const fn root(&self) -> PhysicalQueryNodeId {
        self.root
    }

    pub(crate) fn node(&self, id: PhysicalQueryNodeId) -> &PhysicalQueryNode {
        &self.nodes[id.index()]
    }

    pub(crate) fn logical_node(&self, id: PhysicalQueryNodeId) -> &LogicalQueryNode {
        self.logical.node(self.node(id).logical_node())
    }

    pub(crate) fn explain(&self) -> PhysicalQueryPlanExplain {
        PhysicalQueryPlanExplain {
            root: self.root,
            nodes: self
                .nodes
                .iter()
                .enumerate()
                .map(|(index, node)| PhysicalQueryNodeExplain {
                    physical_node: PhysicalQueryNodeId(
                        u32::try_from(index)
                            .expect("physical plan is one-to-one with a u32 logical arena"),
                    ),
                    logical_node: node.logical_node(),
                    operator: node.operator(),
                    logical_operator: LogicalQueryOperatorExplain::from_operator(
                        self.logical.node(node.logical_node()).operator(),
                    ),
                    output_kind: self.logical.node(node.logical_node()).output_kind().label(),
                    dependencies: node.dependencies().to_vec(),
                    derived_layer_request: node.derived_layer_request(),
                })
                .collect(),
        }
    }
}

/// An owned, deterministic, serializable explanation of a selected physical plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct PhysicalQueryPlanExplain {
    root: PhysicalQueryNodeId,
    nodes: Vec<PhysicalQueryNodeExplain>,
}

/// One stable arena entry in a [`PhysicalQueryPlanExplain`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct PhysicalQueryNodeExplain {
    physical_node: PhysicalQueryNodeId,
    logical_node: LogicalQueryNodeId,
    operator: PhysicalQueryOperator,
    logical_operator: LogicalQueryOperatorExplain,
    output_kind: &'static str,
    dependencies: Vec<PhysicalQueryNodeId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    derived_layer_request: Option<DerivedLayerRequest>,
}

/// The complete semantic payload of one logical operator in an explain node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum LogicalQueryOperatorExplain {
    Seed {
        seed: serde_json::Value,
    },
    Step {
        step: serde_json::Value,
        final_in_authored_suffix: bool,
    },
    Set {
        op: &'static str,
    },
    Limit {
        count: usize,
    },
}

impl LogicalQueryOperatorExplain {
    fn from_operator(operator: &LogicalQueryOperator) -> Self {
        match operator {
            LogicalQueryOperator::Seed(seed) => Self::Seed {
                seed: seed.to_canonical_json(),
            },
            LogicalQueryOperator::Step {
                step,
                final_in_authored_suffix,
                ..
            } => Self::Step {
                step: step.to_canonical_json(),
                final_in_authored_suffix: *final_in_authored_suffix,
            },
            LogicalQueryOperator::Set { op, .. } => Self::Set { op: op.label() },
            LogicalQueryOperator::Limit { count, .. } => Self::Limit { count: *count },
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::analyzer::structural::query::{
        CallTraversalFilter, CodeQueryResultDetail, Pattern, SCHEMA_VERSION, StringPredicate,
    };

    fn seed(name: &str) -> CodeQuerySeed {
        CodeQuerySeed {
            where_globs: Vec::new(),
            languages: Vec::new(),
            root: Pattern {
                name: Some(StringPredicate::Exact(name.to_owned())),
                ..Pattern::default()
            },
            inside: None,
            not_inside: None,
        }
    }

    fn branch(seed: CodeQuerySeed, steps: Vec<QueryStep>) -> CodeQueryPlan {
        CodeQueryPlan {
            source: CodeQueryPlanSource::Seed(Box::new(seed)),
            steps,
        }
    }

    fn query(plan: CodeQueryPlan) -> CodeQuery {
        CodeQuery {
            schema_version: SCHEMA_VERSION,
            plan,
            limit: 20,
            result_detail: CodeQueryResultDetail::Compact,
        }
    }

    fn explain(query: &CodeQuery) -> PhysicalQueryPlanExplain {
        PhysicalQueryPlan::select(LogicalQueryPlan::lower(query).expect("query should lower"))
            .explain()
    }

    #[test]
    fn identical_seeds_share_one_logical_dag_node() {
        let shared = seed("Widget");
        let logical = LogicalQueryPlan::lower(&query(CodeQueryPlan {
            source: CodeQueryPlanSource::Set {
                op: SetOperator::Union,
                branches: vec![
                    branch(shared.clone(), Vec::new()),
                    branch(shared, Vec::new()),
                ],
            },
            steps: Vec::new(),
        }))
        .expect("query should lower");

        assert_eq!(logical.nodes.len(), 3);
        let LogicalQueryOperator::Limit { input, count } = logical.node(logical.root).operator()
        else {
            panic!("root should be an explicit limit");
        };
        assert_eq!(*count, 20);
        let LogicalQueryOperator::Set { inputs, .. } = logical.node(*input).operator() else {
            panic!("limit should depend on the union");
        };
        assert_eq!(inputs.len(), 2);
        assert_eq!(inputs[0], inputs[1]);
        assert!(matches!(
            logical.node(inputs[0]).operator(),
            LogicalQueryOperator::Seed(_)
        ));
    }

    #[test]
    fn logical_arena_is_dependency_postorder() {
        let logical = LogicalQueryPlan::lower(&query(CodeQueryPlan {
            source: CodeQueryPlanSource::Set {
                op: SetOperator::Union,
                branches: vec![
                    branch(seed("First"), vec![QueryStep::EnclosingDecl]),
                    branch(seed("Second"), vec![QueryStep::EnclosingDecl]),
                ],
            },
            steps: vec![QueryStep::FileOf],
        }))
        .expect("query should lower");

        logical
            .validate_dependency_order()
            .expect("every dependency should precede its consumer");
        for (consumer, node) in logical.nodes.iter().enumerate() {
            assert!(
                node.operator()
                    .dependencies()
                    .iter()
                    .all(|dependency| dependency.index() < consumer),
                "node {consumer} is not in dependency postorder"
            );
        }
        assert_eq!(logical.root.index(), logical.nodes.len() - 1);
    }

    #[test]
    fn physical_selection_uses_sequential_union() {
        let logical = LogicalQueryPlan::lower(&query(CodeQueryPlan {
            source: CodeQueryPlanSource::Set {
                op: SetOperator::Union,
                branches: vec![
                    branch(seed("First"), Vec::new()),
                    branch(seed("Second"), Vec::new()),
                ],
            },
            steps: vec![QueryStep::EnclosingDecl, QueryStep::FileOf],
        }))
        .expect("query should lower");
        let physical = PhysicalQueryPlan::select(logical);

        let root = physical.node(physical.root());
        assert_eq!(root.operator(), PhysicalQueryOperator::Limit);
        let file_step_id = root.dependencies()[0];
        let enclosing_step_id = physical.node(file_step_id).dependencies()[0];
        let union_id = physical.node(enclosing_step_id).dependencies()[0];
        assert_eq!(
            physical.node(union_id).operator(),
            PhysicalQueryOperator::SequentialUnion
        );
        assert_eq!(
            serde_json::to_value(physical.explain()).expect("explain should serialize"),
            json!({
                "root": 5,
                "nodes": [
                    {
                        "physical_node": 0,
                        "logical_node": 0,
                        "operator": "seed_scan",
                        "logical_operator": {
                            "kind": "seed",
                            "seed": { "match": { "name": "First" } }
                        },
                        "output_kind": "structural_match",
                        "dependencies": []
                    },
                    {
                        "physical_node": 1,
                        "logical_node": 1,
                        "operator": "seed_scan",
                        "logical_operator": {
                            "kind": "seed",
                            "seed": { "match": { "name": "Second" } }
                        },
                        "output_kind": "structural_match",
                        "dependencies": []
                    },
                    {
                        "physical_node": 2,
                        "logical_node": 2,
                        "operator": "sequential_union",
                        "logical_operator": { "kind": "set", "op": "union" },
                        "output_kind": "structural_match",
                        "dependencies": [0, 1]
                    },
                    {
                        "physical_node": 3,
                        "logical_node": 3,
                        "operator": "pipeline_step",
                        "logical_operator": {
                            "kind": "step",
                            "step": { "op": "enclosing_decl" },
                            "final_in_authored_suffix": false
                        },
                        "output_kind": "declaration",
                        "dependencies": [2]
                    },
                    {
                        "physical_node": 4,
                        "logical_node": 4,
                        "operator": "pipeline_step",
                        "logical_operator": {
                            "kind": "step",
                            "step": { "op": "file_of" },
                            "final_in_authored_suffix": true
                        },
                        "output_kind": "file",
                        "dependencies": [3]
                    },
                    {
                        "physical_node": 5,
                        "logical_node": 5,
                        "operator": "limit",
                        "logical_operator": { "kind": "limit", "count": 20 },
                        "output_kind": "file",
                        "dependencies": [4]
                    }
                ]
            })
        );
    }

    #[test]
    fn physical_selection_can_choose_parallel_union_independently() {
        let logical = LogicalQueryPlan::lower(&query(CodeQueryPlan {
            source: CodeQueryPlanSource::Set {
                op: SetOperator::Union,
                branches: vec![
                    branch(seed("First"), Vec::new()),
                    branch(seed("Second"), Vec::new()),
                ],
            },
            steps: Vec::new(),
        }))
        .expect("query should lower");
        let LogicalQueryOperator::Limit { input: union, .. } =
            logical.node(logical.root()).operator()
        else {
            panic!("root should be a limit");
        };
        let union = *union;
        let physical = PhysicalQueryPlan::select_with_parallel_union(logical.clone(), Some(union));

        assert_eq!(
            physical
                .node(PhysicalQueryNodeId::from_logical(union))
                .operator(),
            PhysicalQueryOperator::ParallelUnion
        );
        let sequential = PhysicalQueryPlan::select(logical);
        assert_eq!(
            sequential
                .node(PhysicalQueryNodeId::from_logical(union))
                .operator(),
            PhysicalQueryOperator::SequentialUnion
        );
    }

    #[test]
    fn only_complete_reverse_import_traversal_requests_a_derived_layer() {
        let logical = LogicalQueryPlan::lower(&query(branch(
            seed("AnyDeclaration"),
            vec![
                QueryStep::FileOf,
                QueryStep::ImportersOf,
                QueryStep::ImportsOf,
            ],
        )))
        .expect("query should lower");
        let physical = PhysicalQueryPlan::select(logical);

        let importer_node = physical
            .nodes
            .iter()
            .find(|node| {
                matches!(
                    physical.logical.node(node.logical_node()).operator(),
                    LogicalQueryOperator::Step {
                        step: QueryStep::ImportersOf,
                        ..
                    }
                )
            })
            .expect("physical plan should contain importers_of");
        let request = importer_node
            .derived_layer_request()
            .expect("reverse imports require the complete direct import topology");
        assert_eq!(
            request,
            DerivedLayerRequest::complete_direct_import_topology()
        );

        let imports_node = physical
            .nodes
            .iter()
            .find(|node| {
                matches!(
                    physical.logical.node(node.logical_node()).operator(),
                    LogicalQueryOperator::Step {
                        step: QueryStep::ImportsOf,
                        ..
                    }
                )
            })
            .expect("physical plan should contain imports_of");
        assert_eq!(imports_node.derived_layer_request(), None);
    }

    #[test]
    fn derived_layer_request_is_visible_in_physical_explain() {
        let physical = PhysicalQueryPlan::select(
            LogicalQueryPlan::lower(&query(branch(
                seed("AnyDeclaration"),
                vec![QueryStep::FileOf, QueryStep::ImportersOf],
            )))
            .expect("query should lower"),
        );
        let explained = serde_json::to_value(physical.explain()).expect("explain should serialize");
        let importer_node = explained["nodes"]
            .as_array()
            .expect("explain nodes should be an array")
            .iter()
            .find(|node| node["logical_operator"]["step"]["op"] == "importers_of")
            .expect("explain should contain importers_of");
        assert_eq!(
            importer_node["derived_layer_request"],
            serde_json::to_value(DerivedLayerRequest::complete_direct_import_topology())
                .expect("request should serialize")
        );
        assert!(
            explained["nodes"]
                .as_array()
                .expect("explain nodes should be an array")
                .iter()
                .filter(|node| node["logical_operator"]["step"]["op"] != "importers_of")
                .all(|node| node.get("derived_layer_request").is_none()),
            "unannotated operators should not gain a null derived-layer field"
        );
    }

    #[test]
    fn semantically_distinct_same_topology_queries_have_distinct_explains() {
        let baseline = query(branch(
            seed("Callable"),
            vec![
                QueryStep::EnclosingDecl,
                QueryStep::Callers(CallTraversalFilter::default()),
            ],
        ));
        let different_seed = query(branch(
            seed("OtherCallable"),
            vec![
                QueryStep::EnclosingDecl,
                QueryStep::Callers(CallTraversalFilter::default()),
            ],
        ));
        let different_step = query(branch(
            seed("Callable"),
            vec![
                QueryStep::EnclosingDecl,
                QueryStep::Callers(CallTraversalFilter {
                    depth: std::num::NonZeroUsize::new(2).expect("two is non-zero"),
                    proof: None,
                }),
            ],
        ));
        let mut different_limit = baseline.clone();
        different_limit.limit = 21;

        let baseline = explain(&baseline);
        assert_ne!(baseline, explain(&different_seed));
        assert_ne!(baseline, explain(&different_step));
        assert_ne!(baseline, explain(&different_limit));
    }

    #[test]
    fn json_and_rql_frontends_select_the_same_physical_plan() {
        let json_query = CodeQuery::from_json(&json!({
            "union": [
                {
                    "match": { "kind": "class", "name": "Legacy" },
                    "steps": [{ "op": "enclosing_decl" }]
                },
                {
                    "match": { "kind": "class", "name": "Replacement" },
                    "steps": [{ "op": "enclosing_decl" }]
                }
            ],
            "steps": [{ "op": "file_of" }],
            "limit": 20
        }))
        .expect("JSON query should parse");
        let rql_query = CodeQuery::from_sexp(
            r#"(limit 20
              (file-of
                (union
                  (enclosing-decl (class :name "Legacy"))
                  (enclosing-decl (class :name "Replacement")))))"#,
        )
        .expect("RQL query should parse");

        assert_eq!(explain(&json_query), explain(&rql_query));
    }
}
