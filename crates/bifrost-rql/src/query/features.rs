use super::ir::{
    CodeQuery, CodeQueryPlan, CodeQueryPlanSource, CodeQuerySeed, Pattern, QueryPathScope,
    SetOperator,
};
use super::schema::QueryStepOp;
use brokk_bifrost_core::analyzer::Language;
use brokk_bifrost_core::analyzer::structural::kinds::{NormalizedKind, Role};

/// A typed source relation used by a code query.
///
/// Set operators and cross-domain operators are plan composition, so their
/// child sources are reported individually rather than as source operations of
/// their own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QuerySourceOperation {
    Match,
    Occurrences,
    Scopes,
    Bindings,
    Paths,
    GenerationSites,
    Exports,
    ConfigurationFacts,
    DependencyEvidence,
}

/// A typed composition operation in a query plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryCompositionOperation {
    Set(SetOperator),
    Correlate,
    RequireBoth,
}

impl QueryCompositionOperation {
    pub fn label(self) -> &'static str {
        match self {
            Self::Set(operation) => operation.label(),
            Self::Correlate => "correlate",
            Self::RequireBoth => "require_both",
        }
    }
}

/// The typed scope of one composition operation in a query plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryCompositionScope {
    pub operation: QueryCompositionOperation,
    /// Indices through the ordered child plans; a root composition has an empty path.
    pub plan_path: Vec<usize>,
}

/// The typed scope of one leaf source in a query plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuerySourceScope {
    pub operation: QuerySourceOperation,
    /// Indices through the ordered child plans; a root leaf has an empty path.
    pub plan_path: Vec<usize>,
    pub languages: Option<Vec<Language>>,
    pub where_globs: QueryPathScope,
}

/// The ordered step operations authored by one query plan node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryStepScope {
    /// Indices through the ordered child plans; a root plan has an empty path.
    pub plan_path: Vec<usize>,
    pub operations: Vec<QueryStepOp>,
}

/// The bounded, query-local dependency description of a typed code query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryStaticDependencies {
    pub schema_version: u64,
    pub source_operations: Vec<QuerySourceOperation>,
    pub source_scopes: Vec<QuerySourceScope>,
    pub composition_scopes: Vec<QueryCompositionScope>,
    pub step_operations: Vec<QueryStepOp>,
    pub step_scopes: Vec<QueryStepScope>,
    /// One entry per distinct language-bearing source scope, in plan order.
    /// `Some(vec![vec![]])` records an actual unscoped source and means all
    /// analyzer languages. `None` means that no source in the query has a
    /// programming-language axis, as with configuration facts or dependency
    /// evidence.
    pub language_scopes: Option<Vec<Vec<Language>>>,
    pub may_use_semantic_packs: bool,
}

impl CodeQuery {
    /// Return the typed source and step operations used by this query.
    ///
    /// The walk follows authored plan order and uses an explicit stack so
    /// nested plans remain bounded by the request's plan tree. It reports only
    /// typed IR facts; selector strings and canonical JSON are not part of
    /// this dependency description.
    pub fn static_dependencies(&self) -> QueryStaticDependencies {
        let mut dependencies = QueryStaticDependencies {
            schema_version: self.schema_version,
            source_operations: Vec::new(),
            source_scopes: Vec::new(),
            composition_scopes: Vec::new(),
            step_operations: Vec::new(),
            step_scopes: Vec::new(),
            language_scopes: None,
            may_use_semantic_packs: self.may_use_semantic_packs(),
        };
        let mut pending: Vec<(&CodeQueryPlan, Vec<usize>)> = vec![(&self.plan, Vec::new())];

        while let Some((plan, plan_path)) = pending.pop() {
            match &plan.source {
                CodeQueryPlanSource::Seed(seed) => record_source(
                    &mut dependencies,
                    QuerySourceOperation::Match,
                    &plan_path,
                    Some(&seed.languages),
                    &seed.where_globs,
                ),
                CodeQueryPlanSource::Occurrences(seed) => record_source(
                    &mut dependencies,
                    QuerySourceOperation::Occurrences,
                    &plan_path,
                    Some(&seed.languages),
                    &seed.where_globs,
                ),
                CodeQueryPlanSource::Scopes(seed) => record_source(
                    &mut dependencies,
                    QuerySourceOperation::Scopes,
                    &plan_path,
                    Some(&seed.languages),
                    &seed.where_globs,
                ),
                CodeQueryPlanSource::Bindings(seed) => record_source(
                    &mut dependencies,
                    QuerySourceOperation::Bindings,
                    &plan_path,
                    Some(&seed.languages),
                    &seed.where_globs,
                ),
                CodeQueryPlanSource::Paths(seed) => record_source(
                    &mut dependencies,
                    QuerySourceOperation::Paths,
                    &plan_path,
                    Some(&seed.languages),
                    &seed.where_globs,
                ),
                CodeQueryPlanSource::GenerationSites(seed) => record_source(
                    &mut dependencies,
                    QuerySourceOperation::GenerationSites,
                    &plan_path,
                    Some(&seed.languages),
                    &seed.where_globs,
                ),
                CodeQueryPlanSource::Exports(seed) => record_source(
                    &mut dependencies,
                    QuerySourceOperation::Exports,
                    &plan_path,
                    Some(&seed.languages),
                    &seed.where_globs,
                ),
                CodeQueryPlanSource::ConfigurationFacts(seed) => record_source(
                    &mut dependencies,
                    QuerySourceOperation::ConfigurationFacts,
                    &plan_path,
                    None,
                    &seed.where_globs,
                ),
                CodeQueryPlanSource::DependencyEvidence(seed) => record_source(
                    &mut dependencies,
                    QuerySourceOperation::DependencyEvidence,
                    &plan_path,
                    None,
                    &seed.where_globs,
                ),
                CodeQueryPlanSource::Set { op, .. } => {
                    dependencies.composition_scopes.push(QueryCompositionScope {
                        operation: QueryCompositionOperation::Set(*op),
                        plan_path: plan_path.clone(),
                    });
                    for (index, child) in plan.source.child_plans().into_iter().enumerate().rev() {
                        let mut child_path = plan_path.clone();
                        child_path.push(index);
                        pending.push((child, child_path));
                    }
                }
                CodeQueryPlanSource::Correlate(_) => {
                    dependencies.composition_scopes.push(QueryCompositionScope {
                        operation: QueryCompositionOperation::Correlate,
                        plan_path: plan_path.clone(),
                    });
                    for (index, child) in plan.source.child_plans().into_iter().enumerate().rev() {
                        let mut child_path = plan_path.clone();
                        child_path.push(index);
                        pending.push((child, child_path));
                    }
                }
                CodeQueryPlanSource::RequireBoth(_) => {
                    dependencies.composition_scopes.push(QueryCompositionScope {
                        operation: QueryCompositionOperation::RequireBoth,
                        plan_path: plan_path.clone(),
                    });
                    for (index, child) in plan.source.child_plans().into_iter().enumerate().rev() {
                        let mut child_path = plan_path.clone();
                        child_path.push(index);
                        pending.push((child, child_path));
                    }
                }
            }

            let operations = plan.steps.iter().map(|step| step.op()).collect::<Vec<_>>();
            for &operation in &operations {
                push_unique(&mut dependencies.step_operations, operation);
            }
            dependencies.step_scopes.push(QueryStepScope {
                plan_path,
                operations,
            });
        }

        dependencies
    }
}

fn record_source(
    dependencies: &mut QueryStaticDependencies,
    operation: QuerySourceOperation,
    plan_path: &[usize],
    languages: Option<&[Language]>,
    where_globs: &QueryPathScope,
) {
    let languages = languages.map(normalize_languages);
    push_unique(&mut dependencies.source_operations, operation);
    dependencies.source_scopes.push(QuerySourceScope {
        operation,
        plan_path: plan_path.to_vec(),
        languages: languages.clone(),
        where_globs: where_globs.clone(),
    });
    if let Some(languages) = languages {
        let scopes = dependencies.language_scopes.get_or_insert_with(Vec::new);
        push_unique(scopes, languages);
    }
}

fn normalize_languages(languages: &[Language]) -> Vec<Language> {
    let mut languages = languages.to_vec();
    languages.sort_unstable();
    languages.dedup();
    languages
}

fn push_unique<T: PartialEq>(values: &mut Vec<T>, value: T) {
    if !values.contains(&value) {
        values.push(value);
    }
}

impl CodeQuerySeed {
    pub fn referenced_kinds(&self) -> Vec<NormalizedKind> {
        let mut kinds = Vec::new();
        collect_referenced_kinds(&self.root, &mut kinds);
        if let Some(pattern) = &self.inside {
            collect_referenced_kinds(pattern, &mut kinds);
        }
        if let Some(pattern) = &self.inside_decl {
            collect_referenced_kinds(pattern, &mut kinds);
        }
        if let Some(pattern) = &self.not_inside {
            collect_referenced_kinds(pattern, &mut kinds);
        }
        kinds.sort_unstable();
        kinds.dedup();
        kinds
    }

    pub fn used_roles(&self) -> Vec<Role> {
        let mut roles = Vec::new();
        collect_used_roles(&self.root, &mut roles);
        if let Some(pattern) = &self.inside {
            collect_used_roles(pattern, &mut roles);
        }
        if let Some(pattern) = &self.inside_decl {
            collect_used_roles(pattern, &mut roles);
        }
        if let Some(pattern) = &self.not_inside {
            collect_used_roles(pattern, &mut roles);
        }
        roles.sort_unstable();
        roles.dedup();
        roles
    }
}

fn collect_referenced_kinds(pattern: &Pattern, out: &mut Vec<NormalizedKind>) {
    walk_patterns(pattern, |pattern, _| {
        out.extend(pattern.kinds.iter().copied());
        out.extend(pattern.not_kinds.iter().copied());
    });
}

fn collect_used_roles(pattern: &Pattern, out: &mut Vec<Role>) {
    walk_patterns(pattern, |_, role| {
        if let Some(role) = role {
            out.push(role);
        }
    });
}

fn walk_patterns(pattern: &Pattern, mut visit: impl FnMut(&Pattern, Option<Role>)) {
    let mut pending = vec![(pattern, None)];
    while let Some((pattern, role)) = pending.pop() {
        visit(pattern, role);
        if let Some(child) = &pattern.has {
            pending.push((child, None));
        }
        if let Some(child) = &pattern.not_has {
            pending.push((child, None));
        }
        if let Some(child) = &pattern.local_value {
            pending.push((child, None));
        }
        for &role in Role::single_target_roles() {
            if let Some(child) = pattern.single_role_pattern(role) {
                pending.push((child, Some(role)));
            }
        }
        for &role in Role::list_target_roles() {
            for child in pattern.list_role_patterns(role) {
                pending.push((child, Some(role)));
            }
        }
        for (_, child) in &pattern.kwargs {
            pending.push((child, Some(Role::Kwarg)));
        }
    }
}
