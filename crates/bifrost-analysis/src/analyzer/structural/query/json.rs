use super::ir::{
    BindingFilter, BindingSeed, CallInputSelector, CandidateFilter, CodeQuery, CodeQueryPlan,
    CodeQueryPlanSource, CodeQuerySeed, EdgeFilter, HierarchyTraversal, OccurrenceFilter,
    OccurrenceSeed, Pattern, QueryStep, ScopeFilter, ScopeSeed, StringPredicate,
    UNATTRIBUTED_TIER_LABEL,
};
use super::schema::{
    CallTraversalCompleteness, reference_kind_label, usage_proof_label, usage_surface_label,
};
use crate::analyzer::structural::kinds::{NormalizedKind, Role};
use serde_json::{Map, Value, json};

impl CodeQuery {
    /// The canonical JSON form of this query. Used by `--print-json` style
    /// debugging and by tests asserting that both frontends parse to the same
    /// query (`parse(json).to_canonical_json() == parse(sexp).to_canonical_json()`).
    pub fn to_canonical_json(&self) -> Value {
        let Value::Object(mut object) = self.to_canonical_query_plan_json() else {
            unreachable!("canonical query plans are JSON objects");
        };
        object.insert("limit".to_string(), json!(self.limit));
        object.insert(
            "result_detail".to_string(),
            json!(self.result_detail.label()),
        );
        object.insert(
            "execution_mode".to_string(),
            json!(self.execution_mode.label()),
        );
        Value::Object(object)
    }

    /// Canonical typed query-plan meaning without execution/output controls.
    ///
    /// Policy selectors use this projection because policy evaluation owns its
    /// result budget and detail level independently of the authored selector.
    pub fn to_canonical_query_plan_json(&self) -> Value {
        let mut object = plan_to_json(&self.plan);
        object.insert("schema_version".to_string(), json!(self.schema_version));
        Value::Object(object)
    }
}

fn plan_to_json(plan: &CodeQueryPlan) -> Map<String, Value> {
    let mut object = match &plan.source {
        CodeQueryPlanSource::Seed(seed) => seed_to_json(seed),
        CodeQueryPlanSource::Occurrences(seed) => occurrence_seed_to_json(seed),
        CodeQueryPlanSource::Scopes(seed) => scope_seed_to_json(seed),
        CodeQueryPlanSource::Bindings(seed) => binding_seed_to_json(seed),
        CodeQueryPlanSource::Set { op, branches } => {
            let mut object = Map::new();
            object.insert(
                op.label().to_string(),
                Value::Array(
                    branches
                        .iter()
                        .map(|branch| Value::Object(plan_to_json(branch)))
                        .collect(),
                ),
            );
            object
        }
    };
    if !plan.steps.is_empty() {
        object.insert(
            "steps".to_string(),
            Value::Array(plan.steps.iter().map(query_step_to_json).collect()),
        );
    }
    object
}

pub(super) fn seed_to_json(seed: &CodeQuerySeed) -> Map<String, Value> {
    let mut object = Map::new();
    if !seed.where_globs.is_empty() {
        object.insert(
            "where".to_string(),
            Value::Array(
                seed.where_globs
                    .iter()
                    .map(|glob| Value::String(glob.as_str().to_string()))
                    .collect(),
            ),
        );
    }
    if !seed.languages.is_empty() {
        object.insert(
            "languages".to_string(),
            Value::Array(
                seed.languages
                    .iter()
                    .map(|language| Value::String(language.config_label().to_string()))
                    .collect(),
            ),
        );
    }
    object.insert("match".to_string(), pattern_to_json(&seed.root));
    if let Some(pattern) = &seed.inside {
        object.insert("inside".to_string(), pattern_to_json(pattern));
    }
    if let Some(pattern) = &seed.inside_decl {
        object.insert("inside_decl".to_string(), pattern_to_json(pattern));
    }
    if let Some(pattern) = &seed.not_inside {
        object.insert("not_inside".to_string(), pattern_to_json(pattern));
    }
    object
}

pub(super) fn occurrence_filter_to_json(filter: &OccurrenceFilter) -> Map<String, Value> {
    let mut object = Map::new();
    if !filter.classes.is_empty() {
        object.insert(
            "class".to_string(),
            Value::Array(
                filter
                    .classes
                    .iter()
                    .map(|class| json!(class.label()))
                    .collect(),
            ),
        );
    }
    if !filter.roles.is_empty() {
        object.insert(
            "role".to_string(),
            Value::Array(
                filter
                    .roles
                    .iter()
                    .map(|role| json!(role.label()))
                    .collect(),
            ),
        );
    }
    if !filter.namespaces.is_empty() {
        object.insert(
            "namespace".to_string(),
            Value::Array(
                filter
                    .namespaces
                    .iter()
                    .map(|namespace| json!(namespace.label()))
                    .collect(),
            ),
        );
    }
    object
}

fn occurrence_seed_to_json(seed: &OccurrenceSeed) -> Map<String, Value> {
    let mut object = Map::new();
    if !seed.where_globs.is_empty() {
        object.insert(
            "where".to_string(),
            Value::Array(
                seed.where_globs
                    .iter()
                    .map(|glob| Value::String(glob.as_str().to_string()))
                    .collect(),
            ),
        );
    }
    if !seed.languages.is_empty() {
        object.insert(
            "languages".to_string(),
            Value::Array(
                seed.languages
                    .iter()
                    .map(|language| Value::String(language.config_label().to_string()))
                    .collect(),
            ),
        );
    }
    object.insert(
        "occurrences".to_string(),
        Value::Object(occurrence_filter_to_json(&seed.filter)),
    );
    object
}

impl OccurrenceSeed {
    pub(crate) fn to_canonical_json(&self) -> Value {
        Value::Object(occurrence_seed_to_json(self))
    }

    pub(crate) fn canonical_cache_key(&self) -> String {
        serde_json::to_string(&self.to_canonical_json())
            .expect("canonical occurrence seed is serializable")
    }
}

pub(super) fn scope_filter_to_json(filter: &ScopeFilter) -> Map<String, Value> {
    let mut object = Map::new();
    if !filter.kinds.is_empty() {
        object.insert(
            "kind".to_string(),
            Value::Array(
                filter
                    .kinds
                    .iter()
                    .map(|kind| json!(kind.label()))
                    .collect(),
            ),
        );
    }
    object
}

pub(super) fn binding_filter_to_json(filter: &BindingFilter) -> Map<String, Value> {
    let mut object = Map::new();
    if !filter.kinds.is_empty() {
        object.insert(
            "kind".to_string(),
            Value::Array(
                filter
                    .kinds
                    .iter()
                    .map(|kind| json!(kind.label()))
                    .collect(),
            ),
        );
    }
    if !filter.names.is_empty() {
        object.insert(
            "name".to_string(),
            Value::Array(filter.names.iter().map(|name| json!(name)).collect()),
        );
    }
    if !filter.hoisting.is_empty() {
        object.insert(
            "hoisting".to_string(),
            Value::Array(
                filter
                    .hoisting
                    .iter()
                    .map(|class| json!(class.label()))
                    .collect(),
            ),
        );
    }
    object
}

pub(super) fn edge_filter_to_json(filter: &EdgeFilter) -> Map<String, Value> {
    let mut object = Map::new();
    if !filter.reference_kinds.is_empty() {
        object.insert(
            "reference_kinds".to_string(),
            Value::Array(
                filter
                    .reference_kinds
                    .iter()
                    .map(|kind| json!(reference_kind_label(*kind)))
                    .collect(),
            ),
        );
    }
    if let Some(proof) = filter.proof {
        object.insert("proof".to_string(), json!(usage_proof_label(proof)));
    }
    if let Some(surface) = filter.surface {
        object.insert("surface".to_string(), json!(usage_surface_label(surface)));
    }
    if !filter.usage_kinds.is_empty() {
        object.insert(
            "usage".to_string(),
            Value::Array(
                filter
                    .usage_kinds
                    .iter()
                    .map(|kind| json!(kind.wire_label()))
                    .collect(),
            ),
        );
    }
    if !filter.relations.is_empty() {
        object.insert(
            "relation".to_string(),
            Value::Array(
                filter
                    .relations
                    .iter()
                    .map(|relation| json!(relation.label()))
                    .collect(),
            ),
        );
    }
    if !filter.site_classes.is_empty() {
        object.insert(
            "site_class".to_string(),
            Value::Array(
                filter
                    .site_classes
                    .iter()
                    .map(|class| json!(class.label()))
                    .collect(),
            ),
        );
    }
    object
}

pub(super) fn candidate_filter_to_json(filter: &CandidateFilter) -> Map<String, Value> {
    let mut object = Map::new();
    if !filter.tiers.is_empty() || filter.unattributed_tier {
        // `unattributed` renders first because the registry lists it first, so
        // one canonical JSON exists for one authored filter whatever the order
        // the author spelled the labels in.
        let mut tiers: Vec<Value> = Vec::new();
        if filter.unattributed_tier {
            tiers.push(json!(UNATTRIBUTED_TIER_LABEL));
        }
        tiers.extend(filter.tiers.iter().map(|tier| json!(tier.label())));
        object.insert("tier".to_string(), Value::Array(tiers));
    }
    if !filter.outcomes.is_empty() || !filter.rejection_reasons.is_empty() {
        let mut outcomes: Vec<Value> = filter
            .outcomes
            .iter()
            .map(|outcome| json!(outcome.label()))
            .collect();
        outcomes.extend(
            filter
                .rejection_reasons
                .iter()
                .map(|reason| json!(reason.label())),
        );
        object.insert("outcome".to_string(), Value::Array(outcomes));
    }
    if !filter.boundaries.is_empty() {
        object.insert(
            "boundary".to_string(),
            Value::Array(
                filter
                    .boundaries
                    .iter()
                    .map(|status| json!(status.label()))
                    .collect(),
            ),
        );
    }
    object
}

fn scope_seed_to_json(seed: &ScopeSeed) -> Map<String, Value> {
    let mut object = environment_seed_scope_json(&seed.where_globs, &seed.languages);
    object.insert(
        "scopes".to_string(),
        Value::Object(scope_filter_to_json(&seed.filter)),
    );
    object
}

fn binding_seed_to_json(seed: &BindingSeed) -> Map<String, Value> {
    let mut object = environment_seed_scope_json(&seed.where_globs, &seed.languages);
    object.insert(
        "bindings".to_string(),
        Value::Object(binding_filter_to_json(&seed.filter)),
    );
    object
}

/// The `where`/`languages` prefix every non-structural seed renders identically.
fn environment_seed_scope_json(
    where_globs: &[glob::Pattern],
    languages: &[crate::analyzer::Language],
) -> Map<String, Value> {
    let mut object = Map::new();
    if !where_globs.is_empty() {
        object.insert(
            "where".to_string(),
            Value::Array(
                where_globs
                    .iter()
                    .map(|glob| Value::String(glob.as_str().to_string()))
                    .collect(),
            ),
        );
    }
    if !languages.is_empty() {
        object.insert(
            "languages".to_string(),
            Value::Array(
                languages
                    .iter()
                    .map(|language| Value::String(language.config_label().to_string()))
                    .collect(),
            ),
        );
    }
    object
}

impl ScopeSeed {
    pub(crate) fn to_canonical_json(&self) -> Value {
        Value::Object(scope_seed_to_json(self))
    }

    pub(crate) fn canonical_cache_key(&self) -> String {
        serde_json::to_string(&self.to_canonical_json())
            .expect("canonical scope seed is serializable")
    }
}

impl BindingSeed {
    pub(crate) fn to_canonical_json(&self) -> Value {
        Value::Object(binding_seed_to_json(self))
    }

    pub(crate) fn canonical_cache_key(&self) -> String {
        serde_json::to_string(&self.to_canonical_json())
            .expect("canonical binding seed is serializable")
    }
}

impl CodeQuerySeed {
    pub(crate) fn to_canonical_json(&self) -> Value {
        Value::Object(seed_to_json(self))
    }

    pub(crate) fn canonical_cache_key(&self) -> String {
        serde_json::to_string(&self.to_canonical_json())
            .expect("canonical CodeQuery seed is serializable")
    }
}

fn query_step_to_json(step: &QueryStep) -> Value {
    let mut object = Map::new();
    object.insert("op".to_string(), json!(step.label()));
    match step {
        QueryStep::Supertypes(HierarchyTraversal::Depth(depth))
        | QueryStep::Subtypes(HierarchyTraversal::Depth(depth)) => {
            object.insert("depth".to_string(), json!(depth.get()));
        }
        QueryStep::Supertypes(HierarchyTraversal::Transitive)
        | QueryStep::Subtypes(HierarchyTraversal::Transitive) => {
            object.insert("transitive".to_string(), Value::Bool(true));
        }
        QueryStep::Supertypes(HierarchyTraversal::Direct)
        | QueryStep::Subtypes(HierarchyTraversal::Direct)
        | QueryStep::EnclosingDecl
        | QueryStep::ProcedureOf
        | QueryStep::CfgEntry
        | QueryStep::CfgExits
        | QueryStep::CfgSuccessorEdges
        | QueryStep::CfgPredecessorEdges
        | QueryStep::CfgEdgeSource
        | QueryStep::CfgEdgeTarget
        | QueryStep::FileOf
        | QueryStep::ImportsOf
        | QueryStep::ImportersOf
        | QueryStep::Members
        | QueryStep::Owner
        | QueryStep::OccurrenceTarget
        | QueryStep::ScopeOf
        | QueryStep::ScopeAncestors
        | QueryStep::BindingOccurrence
        | QueryStep::CandidateTarget
        | QueryStep::EdgeTarget => {}
        QueryStep::EdgesOf(filter) | QueryStep::EdgesFrom(filter) => {
            object.extend(edge_filter_to_json(filter));
        }
        QueryStep::OccurrencesOf(filter) | QueryStep::OccurrencesIn(filter) => {
            object.extend(occurrence_filter_to_json(filter));
        }
        QueryStep::BindingsIn(filter) => {
            object.extend(binding_filter_to_json(filter));
        }
        QueryStep::CandidatesOf(filter) => {
            object.extend(candidate_filter_to_json(filter));
        }
        QueryStep::ReachingBinding(options) => {
            if options.include_shadowed {
                object.insert("include_shadowed".to_string(), Value::Bool(true));
            }
        }
        QueryStep::Typestate(traversal) => {
            object.insert(
                "protocol_ref".to_string(),
                json!(traversal.protocol_ref.to_string()),
            );
        }
        QueryStep::ValueFlow(traversal) => {
            object.insert(
                "plan_ref".to_string(),
                json!(traversal.plan_ref.to_string()),
            );
        }
        QueryStep::Taint(traversal) => {
            object.insert(
                "taint_ref".to_string(),
                json!(traversal.taint_ref.to_string()),
            );
        }
        QueryStep::Witness(traversal) => {
            if let Some(max_steps) = traversal.max_steps {
                object.insert("max_steps".to_string(), json!(max_steps));
            }
            if let Some(max_bytes) = traversal.max_bytes {
                object.insert("max_bytes".to_string(), json!(max_bytes));
            }
        }
        QueryStep::ReferencesOf(filter) | QueryStep::UsedBy(filter) | QueryStep::Uses(filter) => {
            if !filter.reference_kinds.is_empty() {
                object.insert(
                    "reference_kinds".to_string(),
                    Value::Array(
                        filter
                            .reference_kinds
                            .iter()
                            .map(|kind| json!(reference_kind_label(*kind)))
                            .collect(),
                    ),
                );
            }
            if let Some(proof) = filter.proof {
                object.insert("proof".to_string(), json!(usage_proof_label(proof)));
            }
            if filter.surface != Default::default() {
                object.insert(
                    "surface".to_string(),
                    json!(usage_surface_label(filter.surface)),
                );
            }
        }
        QueryStep::Callers(filter) | QueryStep::Callees(filter) => {
            if filter.depth.get() != 1 {
                object.insert("depth".to_string(), json!(filter.depth.get()));
            }
            if let Some(proof) = filter.proof {
                object.insert("proof".to_string(), json!(usage_proof_label(proof)));
            }
            if filter.completeness != CallTraversalCompleteness::Exhaustive {
                object.insert(
                    "completeness".to_string(),
                    json!(filter.completeness.label()),
                );
            }
        }
        QueryStep::CallSitesTo(filter) | QueryStep::CallSitesFrom(filter) => {
            if let Some(proof) = filter.proof {
                object.insert("proof".to_string(), json!(usage_proof_label(proof)));
            }
        }
        QueryStep::CallInput(selector) => match selector {
            CallInputSelector::Receiver => {
                object.insert("receiver".to_string(), Value::Bool(true));
            }
            CallInputSelector::ParameterIndex(index) => {
                object.insert("parameter_index".to_string(), json!(index));
            }
            CallInputSelector::ParameterName(name) => {
                object.insert("parameter_name".to_string(), json!(name));
            }
        },
        QueryStep::ReceiverTargets(filter)
        | QueryStep::PointsTo(filter)
        | QueryStep::MemberTargets(filter) => {
            if let Some(capture) = &filter.capture {
                object.insert("capture".to_string(), json!(capture));
            }
        }
    }
    Value::Object(object)
}

impl QueryStep {
    pub(crate) fn to_canonical_json(&self) -> Value {
        query_step_to_json(self)
    }
}

fn kind_list_to_json(kinds: &[NormalizedKind]) -> Value {
    if kinds.len() == 1 {
        json!(kinds[0].label())
    } else {
        Value::Array(kinds.iter().map(|kind| json!(kind.label())).collect())
    }
}

fn pattern_to_json(pattern: &Pattern) -> Value {
    let mut object = Map::new();
    if !pattern.kinds.is_empty() {
        object.insert("kind".to_string(), kind_list_to_json(&pattern.kinds));
    }
    if !pattern.not_kinds.is_empty() {
        object.insert(
            "not_kind".to_string(),
            kind_list_to_json(&pattern.not_kinds),
        );
    }
    if let Some(predicate) = &pattern.name {
        object.insert("name".to_string(), string_predicate_to_json(predicate));
    }
    if let Some(predicate) = &pattern.text {
        object.insert("text".to_string(), string_predicate_to_json(predicate));
    }
    if let Some(capture) = &pattern.capture {
        object.insert("capture".to_string(), json!(capture));
    }
    if let Some(sub) = &pattern.has {
        object.insert("has".to_string(), pattern_to_json(sub));
    }
    if let Some(sub) = &pattern.not_has {
        object.insert("not_has".to_string(), pattern_to_json(sub));
    }
    for &role in Role::single_target_roles() {
        if let Some(sub) = pattern.single_role_pattern(role) {
            object.insert(role.label().to_string(), pattern_to_json(sub));
        }
    }
    for &role in Role::list_target_roles() {
        let patterns = pattern.list_role_patterns(role);
        if !patterns.is_empty() {
            object.insert(
                role.label().to_string(),
                Value::Array(patterns.iter().map(pattern_to_json).collect()),
            );
        }
    }
    if !pattern.kwargs.is_empty() {
        let mut kwargs = Map::new();
        for (keyword, sub) in &pattern.kwargs {
            kwargs.insert(keyword.clone(), pattern_to_json(sub));
        }
        object.insert(Role::Kwarg.label().to_string(), Value::Object(kwargs));
    }
    Value::Object(object)
}

fn string_predicate_to_json(predicate: &StringPredicate) -> Value {
    match predicate {
        StringPredicate::Exact(text) => json!(text),
        StringPredicate::Regex(regex) => json!({ "regex": regex.as_str() }),
    }
}
