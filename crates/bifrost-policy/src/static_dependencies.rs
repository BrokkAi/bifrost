//! Source-owned static dependencies for one parsed RQLP document.
//!
//! This module records typed authoring facts only. It does not load selector
//! files, activate semantic packs, inspect a workspace, or claim support,
//! proof, completeness, or profile coverage.

use std::ops::Range;

use brokk_bifrost_analysis::analyzer::semantic::WorkspaceRelativePath;
use brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelProvenance;
use brokk_bifrost_rql::query::{
    CallIdentity, CodeQuery, CodeQueryPlan, QueryCompositionOperation, QuerySourceOperation,
    QueryStaticDependencies, QueryStep, QueryStepOp, ResolvedCallIdentityKind,
    ResolvedCallReceiverType,
};

use super::definition::{
    CatalogRef, EndpointId, EndpointPredicate, EndpointRef, EndpointSetDocument,
    EndpointSetFileRef, EndpointSetKind, FLOW_SET_SEGMENTS, MatchEndpointSetRef, PolicyAnalysis,
    PolicyAnalysisType, PolicySelector, ReceiverTypeConstraintKind, RelationalAssertionPlan,
    ResolvedPolicyLocator, ResolvedPolicyLocatorKind, ResolvedPolicyLocatorRole, RowBindingSource,
    TAINT_SET_SEGMENTS, TaintEndpointSet, TaintEntryId, TaintPolicySpec, TaintSetSegments,
    TypestateEventTrigger, TypestatePolicySpec, TypestateTerminalTrigger,
    relational_binding_selector_path,
};
use super::source::{ParsedRqlpDocument, PolicySourceIdentity};

/// Version of the source-only typed dependency descriptor.
pub const STATIC_DEPENDENCY_EXPORT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StaticDependencyDocument {
    Policy { analysis: PolicyAnalysisType },
    Endpoint,
    EndpointSet { kind: EndpointSetKind },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StaticSelectorSource {
    Inline {
        schema_version: u64,
    },
    File {
        authored_schema_version: Option<u32>,
        analysis_schema_version: Option<u32>,
        path: WorkspaceRelativePath,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticLocatorReference {
    pub role: ResolvedPolicyLocatorRole,
    pub value: String,
    pub source_range: Option<Range<usize>>,
    pub resolution: Option<StaticLocatorResolution>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticLocatorResolution {
    pub kind: ResolvedPolicyLocatorKind,
    pub identity: String,
    pub constraint: Option<ReceiverTypeConstraintKind>,
    pub provenance: Option<SemanticModelProvenance>,
}

/// One selector occurrence and its query-local typed dependency record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticSelectorDependency {
    pub path: String,
    pub source: StaticSelectorSource,
    pub query: Option<QueryStaticDependencies>,
    pub locators: Vec<StaticLocatorReference>,
}

/// Direct typed requirements of the policy/query API. These are separate from
/// [`RawDependencyRef`], which remains an unresolved external closure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectQueryApiRequirement {
    Analysis(PolicyAnalysisType),
    SourceOperation(QuerySourceOperation),
    CompositionOperation(QueryCompositionOperation),
    StepOperation(QueryStepOp),
}

/// One typed source reference which remains external to this report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RawDependencyRef {
    SelectorFile {
        path: WorkspaceRelativePath,
        authored_schema_version: Option<u32>,
        analysis_schema_version: Option<u32>,
    },
    EndpointFile {
        reference: EndpointSetFileRef,
    },
    CatalogSet {
        reference: CatalogRef,
    },
    MatchSet {
        reference: MatchEndpointSetRef,
    },
    CatalogEndpoint {
        catalog: CatalogRef,
        entry_id: TaintEntryId,
    },
    MatchEndpoint {
        endpoint_id: EndpointId,
    },
    Locator {
        reference: Box<StaticLocatorReference>,
    },
}

/// Complete source-only dependency descriptor for one parsed RQLP document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyStaticDependencyReport {
    pub schema_version: u32,
    pub source: PolicySourceIdentity,
    pub document: StaticDependencyDocument,
    pub selectors: Vec<StaticSelectorDependency>,
    pub direct_query_api_requirements: Vec<DirectQueryApiRequirement>,
    pub unresolved_external_closure: Vec<RawDependencyRef>,
}

/// Export typed dependencies from an already parsed source document.
pub fn export_static_dependencies(parsed: &ParsedRqlpDocument) -> PolicyStaticDependencyReport {
    let document = match parsed.document() {
        super::definition::RqlpDocument::Policy { definition } => {
            StaticDependencyDocument::Policy {
                analysis: definition.analysis.analysis_type(),
            }
        }
        super::definition::RqlpDocument::Endpoint { .. } => StaticDependencyDocument::Endpoint,
        super::definition::RqlpDocument::EndpointSet { definition } => {
            StaticDependencyDocument::EndpointSet {
                kind: definition.kind,
            }
        }
    };
    let mut collector = Collector::default();
    match parsed.document() {
        super::definition::RqlpDocument::Policy { definition } => {
            collector
                .direct_query_api_requirements
                .push(DirectQueryApiRequirement::Analysis(
                    definition.analysis.analysis_type(),
                ));
            collect_policy_analysis(&mut collector, &definition.analysis);
        }
        super::definition::RqlpDocument::Endpoint { definition } => {
            collector.collect_selector("/selector", &definition.selector);
        }
        super::definition::RqlpDocument::EndpointSet { definition } => {
            collect_endpoint_set_document(&mut collector, definition);
        }
    }
    PolicyStaticDependencyReport {
        schema_version: STATIC_DEPENDENCY_EXPORT_SCHEMA_VERSION,
        source: parsed.identity().clone(),
        document,
        selectors: collector.selectors,
        direct_query_api_requirements: collector.direct_query_api_requirements,
        unresolved_external_closure: collector.unresolved_external_closure,
    }
}

impl ParsedRqlpDocument {
    pub fn static_dependency_export(&self) -> PolicyStaticDependencyReport {
        export_static_dependencies(self)
    }
}

#[derive(Default)]
struct Collector {
    selectors: Vec<StaticSelectorDependency>,
    direct_query_api_requirements: Vec<DirectQueryApiRequirement>,
    unresolved_external_closure: Vec<RawDependencyRef>,
}

impl Collector {
    fn collect_selector(&mut self, path: &str, selector: &PolicySelector) {
        let (source, query, locators) = match selector {
            PolicySelector::Inline {
                schema,
                query,
                resolved_locators,
            } => {
                let dependencies = query.static_dependencies();
                let mut locators = Vec::new();
                collect_query_locators(query, &mut locators);
                for resolved in resolved_locators {
                    push_unique(&mut locators, static_locator_from_policy(resolved));
                }
                self.record_query_requirements(&dependencies);
                (
                    StaticSelectorSource::Inline {
                        schema_version: u64::from(schema.version),
                    },
                    Some(dependencies),
                    locators,
                )
            }
            PolicySelector::File {
                authored_schema_version,
                analysis_schema_version,
                path,
            } => {
                self.push_dependency(RawDependencyRef::SelectorFile {
                    path: path.clone(),
                    authored_schema_version: *authored_schema_version,
                    analysis_schema_version: *analysis_schema_version,
                });
                (
                    StaticSelectorSource::File {
                        authored_schema_version: *authored_schema_version,
                        analysis_schema_version: *analysis_schema_version,
                        path: path.clone(),
                    },
                    None,
                    Vec::new(),
                )
            }
        };
        for locator in &locators {
            if locator.resolution.is_none() {
                self.push_dependency(RawDependencyRef::Locator {
                    reference: Box::new(locator.clone()),
                });
            }
        }
        self.selectors.push(StaticSelectorDependency {
            path: path.to_owned(),
            source,
            query,
            locators,
        });
    }

    fn record_query_requirements(&mut self, dependencies: &QueryStaticDependencies) {
        for operation in &dependencies.source_operations {
            push_unique(
                &mut self.direct_query_api_requirements,
                DirectQueryApiRequirement::SourceOperation(*operation),
            );
        }
        for scope in &dependencies.composition_scopes {
            push_unique(
                &mut self.direct_query_api_requirements,
                DirectQueryApiRequirement::CompositionOperation(scope.operation),
            );
        }
        for operation in &dependencies.step_operations {
            push_unique(
                &mut self.direct_query_api_requirements,
                DirectQueryApiRequirement::StepOperation(*operation),
            );
        }
    }

    fn push_dependency(&mut self, dependency: RawDependencyRef) {
        push_unique(&mut self.unresolved_external_closure, dependency);
    }

    fn collect_endpoint_set_refs<'a, T>(
        &mut self,
        set: &TaintEndpointSet<T>,
        entries: impl Iterator<Item = (&'a TaintEntryId, &'a PolicySelector)>,
        path: &str,
    ) {
        for reference in &set.include_sets {
            self.push_dependency(RawDependencyRef::CatalogSet {
                reference: reference.clone(),
            });
        }
        for reference in &set.include_matches {
            self.push_dependency(RawDependencyRef::MatchSet {
                reference: reference.clone(),
            });
        }
        for reference in &set.include_files {
            self.push_dependency(RawDependencyRef::EndpointFile {
                reference: reference.clone(),
            });
        }
        for (id, selector) in entries {
            self.collect_selector(
                &format!(
                    "{path}/entries/{}/selector",
                    json_pointer_segment(id.as_str())
                ),
                selector,
            );
        }
    }

    fn collect_endpoint_predicate(&mut self, predicate: &EndpointPredicate) {
        let endpoints = match predicate {
            EndpointPredicate::Exact { endpoints } => endpoints,
            // Category predicates carry category IDs, not endpoint references.
            EndpointPredicate::Categories { .. } => return,
        };
        for endpoint in endpoints {
            match endpoint {
                EndpointRef::Local { .. } => {}
                EndpointRef::Catalog { catalog, entry_id } => {
                    self.push_dependency(RawDependencyRef::CatalogEndpoint {
                        catalog: catalog.clone(),
                        entry_id: entry_id.clone(),
                    });
                }
                EndpointRef::MatchEndpoint { endpoint_id } => {
                    self.push_dependency(RawDependencyRef::MatchEndpoint {
                        endpoint_id: endpoint_id.clone(),
                    });
                }
            }
        }
    }
}

fn collect_policy_analysis(collector: &mut Collector, analysis: &PolicyAnalysis) {
    match analysis {
        PolicyAnalysis::Match { spec } => {
            collector.collect_selector("/analysis/selector", &spec.selector)
        }
        PolicyAnalysis::Assertion { spec } => {
            collector.collect_selector("/analysis/subject", &spec.subject);
            if let Some(plan) = &spec.relational {
                collect_relational_plan(collector, plan);
            }
        }
        PolicyAnalysis::Taint { spec } => collect_taint_policy(collector, spec, TAINT_SET_SEGMENTS),
        PolicyAnalysis::Flow { spec } => collect_taint_policy(collector, spec, FLOW_SET_SEGMENTS),
        PolicyAnalysis::Typestate { spec } => collect_typestate_policy(collector, spec),
    }
}

fn collect_relational_plan(collector: &mut Collector, plan: &RelationalAssertionPlan) {
    for binding in &plan.bindings {
        let RowBindingSource::Query(selector) = &binding.source;
        collector.collect_selector(&relational_binding_selector_path(&binding.name), selector);
    }
}

fn collect_taint_policy(
    collector: &mut Collector,
    spec: &TaintPolicySpec,
    segments: TaintSetSegments,
) {
    collector.collect_endpoint_set_refs(
        &spec.sources,
        spec.sources
            .entries
            .iter()
            .map(|entry| (&entry.id, &entry.selector)),
        &format!("/analysis/{}", segments.sources),
    );
    collector.collect_endpoint_set_refs(
        &spec.sinks,
        spec.sinks
            .entries
            .iter()
            .map(|entry| (&entry.id, &entry.selector)),
        &format!("/analysis/{}", segments.sinks),
    );
    collector.collect_endpoint_set_refs(
        &spec.sanitizers,
        spec.sanitizers
            .entries
            .iter()
            .map(|entry| (&entry.id, &entry.selector)),
        &format!("/analysis/{}", segments.sanitizers),
    );
    collector.collect_endpoint_set_refs(
        &spec.entry_points,
        spec.entry_points
            .entries
            .iter()
            .map(|entry| (&entry.id, &entry.selector)),
        &format!("/analysis/{}", segments.entry_points),
    );
    collector.collect_endpoint_set_refs(
        &spec.transforms,
        spec.transforms
            .entries
            .iter()
            .map(|entry| (&entry.id, &entry.selector)),
        &format!("/analysis/{}", segments.transforms),
    );
    collector.collect_endpoint_set_refs(
        &spec.external_models,
        spec.external_models
            .entries
            .iter()
            .map(|entry| (&entry.id, &entry.selector)),
        &format!("/analysis/{}", segments.external_models),
    );
    for reference in &spec.store_include_files {
        collector.push_dependency(RawDependencyRef::EndpointFile {
            reference: reference.clone(),
        });
    }
    for entry in &spec.store_writes {
        collector.collect_selector(
            &format!(
                "/analysis/{}/entries/{}/selector",
                segments.stores,
                json_pointer_segment(entry.id.as_str())
            ),
            &entry.selector,
        );
    }
    for entry in &spec.store_reads {
        collector.collect_selector(
            &format!(
                "/analysis/{}/entries/{}/selector",
                segments.stores,
                json_pointer_segment(entry.id.as_str())
            ),
            &entry.selector,
        );
    }
    for combination in &spec.finding_combinations {
        collector.collect_endpoint_predicate(&combination.source);
        collector.collect_endpoint_predicate(&combination.sink);
    }
}

fn collect_typestate_policy(collector: &mut Collector, spec: &TypestatePolicySpec) {
    for reference in &spec.subjects.include_matches {
        collector.push_dependency(RawDependencyRef::MatchSet {
            reference: reference.clone(),
        });
    }
    for subject in &spec.subjects.entries {
        collector.collect_selector(
            &format!(
                "/analysis/subjects/entries/{}/selector",
                json_pointer_segment(subject.id.as_str())
            ),
            &subject.selector,
        );
    }
    for event in &spec.automaton.events {
        if let Some(predicate) = &event.applies_to_subjects {
            collector.collect_endpoint_predicate(predicate);
        }
        match &event.trigger {
            TypestateEventTrigger::Calls { selector, .. } => collector.collect_selector(
                &format!(
                    "/analysis/automaton/events/{}/calls/selector",
                    json_pointer_segment(event.id.as_str())
                ),
                selector,
            ),
            TypestateEventTrigger::MatchEndpoints { set, .. } => {
                collector.push_dependency(RawDependencyRef::MatchSet {
                    reference: set.clone(),
                })
            }
            TypestateEventTrigger::SemanticEvent { .. } => {}
        }
    }
    for expectation in &spec.automaton.terminal_expectations {
        if let Some(predicate) = &expectation.applies_to_subjects {
            collector.collect_endpoint_predicate(predicate);
        }
        if let TypestateTerminalTrigger::MatchEndpoints { set, .. } = &expectation.trigger {
            collector.push_dependency(RawDependencyRef::MatchSet {
                reference: set.clone(),
            });
        }
    }
}

fn collect_endpoint_set_document(collector: &mut Collector, document: &EndpointSetDocument) {
    match document.kind {
        EndpointSetKind::Sources => collector.collect_endpoint_set_refs(
            &document.spec.sources,
            document
                .spec
                .sources
                .entries
                .iter()
                .map(|entry| (&entry.id, &entry.selector)),
            "/set",
        ),
        EndpointSetKind::Sinks => collector.collect_endpoint_set_refs(
            &document.spec.sinks,
            document
                .spec
                .sinks
                .entries
                .iter()
                .map(|entry| (&entry.id, &entry.selector)),
            "/set",
        ),
        EndpointSetKind::Sanitizers => collector.collect_endpoint_set_refs(
            &document.spec.sanitizers,
            document
                .spec
                .sanitizers
                .entries
                .iter()
                .map(|entry| (&entry.id, &entry.selector)),
            "/set",
        ),
        EndpointSetKind::EntryPoints => collector.collect_endpoint_set_refs(
            &document.spec.entry_points,
            document
                .spec
                .entry_points
                .entries
                .iter()
                .map(|entry| (&entry.id, &entry.selector)),
            "/set",
        ),
        EndpointSetKind::Transforms => collector.collect_endpoint_set_refs(
            &document.spec.transforms,
            document
                .spec
                .transforms
                .entries
                .iter()
                .map(|entry| (&entry.id, &entry.selector)),
            "/set",
        ),
        EndpointSetKind::ExternalModels => collector.collect_endpoint_set_refs(
            &document.spec.external_models,
            document
                .spec
                .external_models
                .entries
                .iter()
                .map(|entry| (&entry.id, &entry.selector)),
            "/set",
        ),
        EndpointSetKind::Stores => {
            for reference in &document.spec.store_include_files {
                collector.push_dependency(RawDependencyRef::EndpointFile {
                    reference: reference.clone(),
                });
            }
            for entry in &document.spec.store_writes {
                collector.collect_selector(
                    &format!(
                        "/set/store-write/{}/selector",
                        json_pointer_segment(entry.id.as_str())
                    ),
                    &entry.selector,
                );
            }
            for entry in &document.spec.store_reads {
                collector.collect_selector(
                    &format!(
                        "/set/store-read/{}/selector",
                        json_pointer_segment(entry.id.as_str())
                    ),
                    &entry.selector,
                );
            }
        }
        EndpointSetKind::Origins => collect_endpoint_set_refs_for_flow(
            collector,
            &document.spec.sources,
            document
                .spec
                .sources
                .entries
                .iter()
                .map(|entry| (&entry.id, &entry.selector)),
        ),
        EndpointSetKind::Observations => collect_endpoint_set_refs_for_flow(
            collector,
            &document.spec.sinks,
            document
                .spec
                .sinks
                .entries
                .iter()
                .map(|entry| (&entry.id, &entry.selector)),
        ),
        EndpointSetKind::Kills => collect_endpoint_set_refs_for_flow(
            collector,
            &document.spec.sanitizers,
            document
                .spec
                .sanitizers
                .entries
                .iter()
                .map(|entry| (&entry.id, &entry.selector)),
        ),
        EndpointSetKind::FlowTransforms => collect_endpoint_set_refs_for_flow(
            collector,
            &document.spec.transforms,
            document
                .spec
                .transforms
                .entries
                .iter()
                .map(|entry| (&entry.id, &entry.selector)),
        ),
    }
}

fn collect_endpoint_set_refs_for_flow<'a, T>(
    collector: &mut Collector,
    set: &TaintEndpointSet<T>,
    entries: impl Iterator<Item = (&'a TaintEntryId, &'a PolicySelector)>,
) {
    collector.collect_endpoint_set_refs(set, entries, "/set");
}

fn collect_query_locators(query: &CodeQuery, locators: &mut Vec<StaticLocatorReference>) {
    let mut pending: Vec<&CodeQueryPlan> = vec![&query.plan];
    while let Some(plan) = pending.pop() {
        for step in &plan.steps {
            match step {
                QueryStep::ResolvedCall(filter) => {
                    collect_call_identity(
                        &filter.resolves_to,
                        ResolvedPolicyLocatorRole::Callable,
                        locators,
                    );
                    if let Some(receiver) = &filter.receiver_type {
                        collect_receiver_identity(receiver, locators);
                    }
                }
                QueryStep::ResolvedValue(filter) => {
                    collect_call_identity(
                        &filter.resolves_to,
                        ResolvedPolicyLocatorRole::Value,
                        locators,
                    );
                }
                _ => {}
            }
        }
        pending.extend(plan.source.child_plans().into_iter().rev());
    }
}

fn collect_receiver_identity(
    receiver: &ResolvedCallReceiverType,
    locators: &mut Vec<StaticLocatorReference>,
) {
    collect_call_identity(
        receiver.root(),
        ResolvedPolicyLocatorRole::ReceiverType,
        locators,
    );
}

fn collect_call_identity(
    identity: &CallIdentity,
    role: ResolvedPolicyLocatorRole,
    locators: &mut Vec<StaticLocatorReference>,
) {
    let CallIdentity::Qualified {
        value,
        source_range,
        resolved,
    } = identity
    else {
        return;
    };
    push_unique(
        locators,
        StaticLocatorReference {
            role,
            value: value.clone(),
            source_range: source_range.clone(),
            resolution: resolved.as_ref().map(|resolved| StaticLocatorResolution {
                kind: match resolved.kind {
                    ResolvedCallIdentityKind::WorkspaceDeclaration => {
                        ResolvedPolicyLocatorKind::WorkspaceDeclaration
                    }
                    ResolvedCallIdentityKind::ActiveSemanticModel => {
                        ResolvedPolicyLocatorKind::ActiveSemanticModel
                    }
                },
                identity: resolved.identity.clone(),
                constraint: None,
                provenance: None,
            }),
        },
    );
}

fn static_locator_from_policy(locator: &ResolvedPolicyLocator) -> StaticLocatorReference {
    StaticLocatorReference {
        role: locator.role,
        value: locator.identity.clone(),
        source_range: None,
        resolution: Some(StaticLocatorResolution {
            kind: locator.kind,
            identity: locator.identity.clone(),
            constraint: Some(locator.constraint),
            provenance: locator.provenance.clone(),
        }),
    }
}

fn json_pointer_segment(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}

fn push_unique<T: PartialEq>(values: &mut Vec<T>, value: T) {
    if !values.contains(&value) {
        values.push(value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PolicySourceIdentity, parse_rqlp_source};

    #[test]
    fn inline_match_exports_typed_query_dependencies() {
        let parsed = parse_rqlp_source(
            r#"(policy :id "test.match" :name "Match" :message "M" :severity warning
                :analysis (analysis :type match :selector (rql (call))))"#,
            PolicySourceIdentity::new("test.match.rqlp"),
        )
        .expect("inline match source");

        let report = export_static_dependencies(&parsed);
        assert_eq!(
            report.schema_version,
            STATIC_DEPENDENCY_EXPORT_SCHEMA_VERSION
        );
        assert_eq!(
            report.document,
            StaticDependencyDocument::Policy {
                analysis: PolicyAnalysisType::Match,
            }
        );
        assert_eq!(report.selectors.len(), 1);
        assert_eq!(report.selectors[0].path, "/analysis/selector");
        let query = report.selectors[0]
            .query
            .as_ref()
            .expect("inline selector query");
        assert!(
            query
                .source_operations
                .contains(&QuerySourceOperation::Match)
        );
        assert!(report.direct_query_api_requirements.contains(
            &DirectQueryApiRequirement::SourceOperation(QuerySourceOperation::Match)
        ));
    }

    #[test]
    fn file_and_endpoint_imports_remain_typed_external_closure() {
        let policy = parse_rqlp_source(
            r#"(policy :id "test.file" :name "File" :message "M" :severity warning
                :analysis (analysis :type match
                  :selector (rql-file :path "queries/rule.rql")))"#,
            PolicySourceIdentity::new("test.file.rqlp"),
        )
        .expect("file selector source");
        let policy_report = export_static_dependencies(&policy);
        assert!(
            policy_report
                .unresolved_external_closure
                .iter()
                .any(|dependency| {
                    matches!(
                        dependency,
                        RawDependencyRef::SelectorFile { path, .. }
                            if path.as_str() == "queries/rule.rql"
                    )
                })
        );

        let endpoint_set = parse_rqlp_source(
            r#"(endpoint-set-document
                :schema-version 1
                :kind sources
                :set (endpoint-set :include-files [
                    (endpoint-set-file :path "nested.rqlp")]))"#,
            PolicySourceIdentity::new("test.sources.rqlp"),
        )
        .expect("endpoint-set import source");
        let endpoint_report = export_static_dependencies(&endpoint_set);
        assert!(
            endpoint_report
                .unresolved_external_closure
                .iter()
                .any(|dependency| {
                    matches!(
                        dependency,
                        RawDependencyRef::EndpointFile { reference }
                            if reference.path.as_str() == "nested.rqlp"
                    )
                })
        );
    }

    fn inline_selector() -> PolicySelector {
        let parsed = parse_rqlp_source(
            r#"(policy :id "test.selector" :name "Selector" :message "M" :severity warning
                :analysis (analysis :type match :selector (rql (call))))"#,
            PolicySourceIdentity::new("test.selector.rqlp"),
        )
        .expect("selector source");
        let crate::RqlpDocument::Policy { definition } = parsed.document() else {
            panic!("policy")
        };
        let PolicyAnalysis::Match { spec } = &definition.analysis else {
            panic!("match")
        };
        spec.selector.clone()
    }

    #[test]
    fn resolved_locator_provenance_does_not_become_unresolved_closure() {
        let mut selector = inline_selector();
        let PolicySelector::Inline {
            resolved_locators, ..
        } = &mut selector
        else {
            panic!("inline")
        };
        resolved_locators.push(ResolvedPolicyLocator {
            role: ResolvedPolicyLocatorRole::Callable,
            kind: ResolvedPolicyLocatorKind::WorkspaceDeclaration,
            identity: "decl.exact".to_owned(),
            constraint: ReceiverTypeConstraintKind::Exact,
            provenance: None,
        });
        let mut collector = Collector::default();
        collector.collect_selector("/selector", &selector);
        assert_eq!(collector.selectors[0].locators.len(), 1);
        assert!(collector.selectors[0].locators[0].resolution.is_some());
        assert!(collector.unresolved_external_closure.is_empty());
    }

    #[test]
    fn store_selector_occurrences_keep_independent_entry_paths() {
        let parsed = parse_rqlp_source(
            r#"(endpoint-set-document :schema-version 1 :kind sources
                :set (endpoint-set :include-files [(endpoint-set-file :path "nested.rqlp")]))"#,
            PolicySourceIdentity::new("test.store.rqlp"),
        )
        .expect("set source");
        let crate::RqlpDocument::EndpointSet { definition } = parsed.document() else {
            panic!("set")
        };
        let mut document = (**definition).clone();
        document.kind = EndpointSetKind::Stores;
        for id in ["first", "second"] {
            document.spec.store_writes.push(crate::TaintStoreWriteSpec {
                id: TaintEntryId::new(id).expect("entry ID"),
                selector: inline_selector(),
                store: crate::TaintStoreName::new("storage").expect("store name"),
                key: None,
                instance: None,
                input: crate::PolicyPort::MatchedValue,
            });
        }
        let mut collector = Collector::default();
        collect_endpoint_set_document(&mut collector, &document);
        assert_eq!(
            collector
                .selectors
                .iter()
                .map(|record| record.path.as_str())
                .collect::<Vec<_>>(),
            [
                "/set/store-write/first/selector",
                "/set/store-write/second/selector"
            ]
        );
    }

    #[test]
    fn category_predicate_has_no_endpoint_reference_axis() {
        let predicate = EndpointPredicate::Categories {
            predicate: crate::CategoryPredicate::Any {
                categories: Vec::new(),
            },
        };
        let mut collector = Collector::default();
        collector.collect_endpoint_predicate(&predicate);
        assert!(collector.unresolved_external_closure.is_empty());
        assert!(collector.selectors.is_empty());
    }
}
