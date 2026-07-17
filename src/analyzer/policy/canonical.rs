//! Deterministic JSON projections of parsed RQLP authoring documents.
//!
//! Normalized authored JSON preserves file, catalog, and directory references.
//! A second, fallible projection is available only for a closed inline/local
//! document. Neither projection computes or claims a final loaded-policy hash;
//! dependencies remain the workspace loader's responsibility.

use std::{cmp::Ordering, collections::HashSet, fmt};

use serde_json::{Map, Value, json};

use super::definition::*;
use super::source::ParsedRqlpDocument;

impl ParsedRqlpDocument {
    /// Project this parser-validated, closed inline/local document into
    /// canonical semantic JSON.
    pub fn to_inline_local_canonical_semantic_json(
        &self,
    ) -> Result<Value, InlineLocalSemanticProjectionError> {
        self.document().to_inline_local_canonical_semantic_json()
    }
}

impl RqlpDocument {
    /// Project this parsed document into deterministic normalized authoring
    /// JSON without resolving any workspace or catalog dependency. This is a
    /// non-validating debug/authoring projection and is never a semantic-hash
    /// input; callers that construct the public authoring graph directly can
    /// therefore serialize incomplete or invalid values here.
    pub fn to_normalized_authored_json(&self) -> Value {
        match self {
            Self::Policy { definition } => policy_definition_to_json(definition),
            Self::Endpoint { definition } => endpoint_definition_to_json(definition),
        }
    }

    /// Project a closed, fully inline/local document into canonical semantic
    /// JSON. This deliberately returns an error while any workspace selector,
    /// catalog, endpoint-set, or cross-document precedence dependency remains.
    ///
    /// This projection is semantic content only. It neither computes nor
    /// claims a final loaded-policy semantic hash; that identity remains the
    /// responsibility of the workspace loader after composition.
    pub(crate) fn to_inline_local_canonical_semantic_json(
        &self,
    ) -> Result<Value, InlineLocalSemanticProjectionError> {
        ensure_inline_local_document(self)?;
        let mut value = self.to_normalized_authored_json();
        remove_inline_selector_source_tags(&mut value);
        Ok(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InlineLocalSemanticProjectionError {
    FileSelector { path: String },
    CatalogReference { name: String, version: u32 },
    MatchDirectory { path: String },
    ExactEndpointSet { endpoint_ids: Vec<String> },
    MatchEndpointReference { endpoint_id: String },
    DanglingLocalEndpointReference { entry_id: String },
    DanglingSelectorReference { path: String },
    EndpointSupersedes { endpoint_id: String },
    EndpointPredicateRequiresComposition,
}

impl fmt::Display for InlineLocalSemanticProjectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FileSelector { path } => {
                write!(formatter, "RQL file selector `{path}` has not been loaded")
            }
            Self::CatalogReference { name, version } => {
                write!(
                    formatter,
                    "catalog `{name}` version {version} has not been composed"
                )
            }
            Self::MatchDirectory { path } => {
                write!(formatter, "endpoint directory `{path}` has not been loaded")
            }
            Self::ExactEndpointSet { endpoint_ids } => write!(
                formatter,
                "exact endpoint set [{}] has not been resolved",
                endpoint_ids.join(", ")
            ),
            Self::MatchEndpointReference { endpoint_id } => write!(
                formatter,
                "match endpoint `{endpoint_id}` has not been resolved"
            ),
            Self::DanglingLocalEndpointReference { entry_id } => write!(
                formatter,
                "local endpoint `{entry_id}` is not declared by this policy"
            ),
            Self::DanglingSelectorReference { path } => {
                write!(
                    formatter,
                    "selector evidence reference `{path}` is not declared"
                )
            }
            Self::EndpointSupersedes { endpoint_id } => write!(
                formatter,
                "superseded endpoint `{endpoint_id}` has not been resolved"
            ),
            Self::EndpointPredicateRequiresComposition => formatter.write_str(
                "endpoint predicates require loaded endpoint identities and composition",
            ),
        }
    }
}

impl std::error::Error for InlineLocalSemanticProjectionError {}

fn ensure_inline_local_document(
    document: &RqlpDocument,
) -> Result<(), InlineLocalSemanticProjectionError> {
    match document {
        RqlpDocument::Policy { definition } => ensure_inline_local_policy(definition),
        RqlpDocument::Endpoint { definition } => {
            ensure_inline_selector(&definition.selector)?;
            if let Some(endpoint_id) = definition.supersedes.first() {
                return Err(InlineLocalSemanticProjectionError::EndpointSupersedes {
                    endpoint_id: endpoint_id.to_string(),
                });
            }
            Ok(())
        }
    }
}

fn ensure_inline_local_policy(
    definition: &PolicyDefinition,
) -> Result<(), InlineLocalSemanticProjectionError> {
    let selector_paths = policy_selector_paths(definition);
    let local_endpoint_ids = match &definition.analysis {
        PolicyAnalysis::Match { spec } => {
            ensure_inline_selector(&spec.selector)?;
            HashSet::new()
        }
        PolicyAnalysis::Taint { spec } => {
            let local_endpoint_ids = taint_local_endpoint_ids(spec);
            ensure_inline_local_taint(spec, &local_endpoint_ids)?;
            local_endpoint_ids
        }
        PolicyAnalysis::Typestate { spec } => {
            let local_endpoint_ids = spec
                .subjects
                .entries
                .iter()
                .map(|subject| subject.id.as_str())
                .collect::<HashSet<_>>();
            ensure_inline_local_typestate(spec, &local_endpoint_ids)?;
            local_endpoint_ids
        }
    };

    if let Some(classification) = &definition.classification
        && let Some(cvss) = &classification.cvss
    {
        for rule in &cvss.metric_rules {
            for reference in rule.evidence_refs() {
                match reference {
                    PolicyEvidenceRef::PolicySelf => {}
                    PolicyEvidenceRef::Endpoint { endpoint } => {
                        ensure_local_endpoint_ref(endpoint, &local_endpoint_ids)?;
                    }
                    PolicyEvidenceRef::Selector { path }
                        if !selector_paths.contains(path.as_str()) =>
                    {
                        return Err(
                            InlineLocalSemanticProjectionError::DanglingSelectorReference {
                                path: path.to_string(),
                            },
                        );
                    }
                    PolicyEvidenceRef::Selector { .. } => {}
                }
            }
        }
    }
    Ok(())
}

fn policy_selector_paths(definition: &PolicyDefinition) -> HashSet<String> {
    let mut paths = HashSet::new();
    match &definition.analysis {
        PolicyAnalysis::Match { .. } => {
            paths.insert("/analysis/selector".to_string());
        }
        PolicyAnalysis::Taint { spec } => {
            extend_taint_selector_paths(&mut paths, "sources", &spec.sources.entries);
            extend_taint_selector_paths(&mut paths, "sinks", &spec.sinks.entries);
            extend_taint_selector_paths(&mut paths, "sanitizers", &spec.sanitizers.entries);
            extend_taint_selector_paths(&mut paths, "transforms", &spec.transforms.entries);
            extend_taint_selector_paths(
                &mut paths,
                "external_models",
                &spec.external_models.entries,
            );
        }
        PolicyAnalysis::Typestate { spec } => {
            paths.extend(spec.subjects.entries.iter().map(|subject| {
                format!(
                    "/analysis/subjects/entries/{}/selector",
                    json_pointer_segment(subject.id.as_str())
                )
            }));
            paths.extend(
                spec.automaton
                    .events
                    .iter()
                    .filter(|event| matches!(event.trigger, TypestateEventTrigger::Calls { .. }))
                    .map(|event| {
                        format!(
                            "/analysis/automaton/events/{}/calls/selector",
                            json_pointer_segment(event.id.as_str())
                        )
                    }),
            );
        }
    }
    paths
}

fn extend_taint_selector_paths<T: TaintSelectorEntry>(
    paths: &mut HashSet<String>,
    set_name: &str,
    entries: &[T],
) {
    paths.extend(entries.iter().map(|entry| {
        format!(
            "/analysis/{set_name}/entries/{}/selector",
            json_pointer_segment(entry.entry_id().as_str())
        )
    }));
}

trait TaintSelectorEntry {
    fn entry_id(&self) -> &TaintEntryId;
}

macro_rules! impl_taint_selector_entry {
    ($($type:ty),+ $(,)?) => {
        $(
            impl TaintSelectorEntry for $type {
                fn entry_id(&self) -> &TaintEntryId {
                    &self.id
                }
            }
        )+
    };
}

impl_taint_selector_entry!(
    TaintSourceSpec,
    TaintSinkSpec,
    TaintSanitizerSpec,
    TaintTransformSpec,
    TaintExternalModelSpec,
);

fn json_pointer_segment(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}

fn ensure_inline_local_taint(
    spec: &TaintPolicySpec,
    local_endpoint_ids: &HashSet<&str>,
) -> Result<(), InlineLocalSemanticProjectionError> {
    ensure_local_endpoint_set(&spec.sources)?;
    ensure_local_endpoint_set(&spec.sinks)?;
    ensure_local_endpoint_set(&spec.sanitizers)?;
    ensure_local_endpoint_set(&spec.transforms)?;
    ensure_local_endpoint_set(&spec.external_models)?;

    for source in &spec.sources.entries {
        ensure_inline_selector(&source.selector)?;
    }
    for sink in &spec.sinks.entries {
        ensure_inline_selector(&sink.selector)?;
    }
    for sanitizer in &spec.sanitizers.entries {
        ensure_inline_selector(&sanitizer.selector)?;
    }
    for transform in &spec.transforms.entries {
        ensure_inline_selector(&transform.selector)?;
    }
    for model in &spec.external_models.entries {
        ensure_inline_selector(&model.selector)?;
    }
    for combination in &spec.finding_combinations {
        ensure_local_endpoint_predicate(&combination.source, local_endpoint_ids)?;
        ensure_local_endpoint_predicate(&combination.sink, local_endpoint_ids)?;
    }
    Ok(())
}

fn ensure_inline_local_typestate(
    spec: &TypestatePolicySpec,
    local_endpoint_ids: &HashSet<&str>,
) -> Result<(), InlineLocalSemanticProjectionError> {
    for reference in &spec.subjects.include_matches {
        ensure_resolved_match_endpoint_set(reference)?;
    }
    for subject in &spec.subjects.entries {
        ensure_inline_selector(&subject.selector)?;
    }
    for event in &spec.automaton.events {
        match &event.trigger {
            TypestateEventTrigger::Calls { selector, .. } => ensure_inline_selector(selector)?,
            TypestateEventTrigger::MatchEndpoints { set, .. } => {
                ensure_resolved_match_endpoint_set(set)?
            }
            TypestateEventTrigger::SemanticEvent { .. } => {}
        }
        if let Some(predicate) = &event.applies_to_subjects {
            ensure_local_endpoint_predicate(predicate, local_endpoint_ids)?;
        }
    }
    for expectation in &spec.automaton.terminal_expectations {
        if let TypestateTerminalTrigger::MatchEndpoints { set, .. } = &expectation.trigger {
            ensure_resolved_match_endpoint_set(set)?;
        }
        if let Some(predicate) = &expectation.applies_to_subjects {
            ensure_local_endpoint_predicate(predicate, local_endpoint_ids)?;
        }
    }
    Ok(())
}

fn ensure_local_endpoint_set<T>(
    set: &TaintEndpointSet<T>,
) -> Result<(), InlineLocalSemanticProjectionError> {
    if let Some(reference) = set.include_sets.first() {
        return Err(InlineLocalSemanticProjectionError::CatalogReference {
            name: reference.name.to_string(),
            version: reference.version,
        });
    }
    if let Some(reference) = set.include_matches.first() {
        ensure_resolved_match_endpoint_set(reference)?;
    }
    Ok(())
}

fn ensure_resolved_match_endpoint_set(
    reference: &MatchEndpointSetRef,
) -> Result<(), InlineLocalSemanticProjectionError> {
    match reference {
        MatchEndpointSetRef::Directory { reference } => {
            Err(InlineLocalSemanticProjectionError::MatchDirectory {
                path: reference.path.as_str().to_string(),
            })
        }
        MatchEndpointSetRef::Exact { endpoint_ids } => {
            Err(InlineLocalSemanticProjectionError::ExactEndpointSet {
                endpoint_ids: endpoint_ids.iter().map(ToString::to_string).collect(),
            })
        }
    }
}

fn ensure_local_endpoint_predicate(
    predicate: &EndpointPredicate,
    local_endpoint_ids: &HashSet<&str>,
) -> Result<(), InlineLocalSemanticProjectionError> {
    match predicate {
        EndpointPredicate::Exact { endpoints } => {
            for endpoint in endpoints {
                ensure_local_endpoint_ref(endpoint, local_endpoint_ids)?;
            }
        }
        EndpointPredicate::Categories { .. } => {}
    }
    Err(InlineLocalSemanticProjectionError::EndpointPredicateRequiresComposition)
}

fn ensure_local_endpoint_ref(
    reference: &EndpointRef,
    local_endpoint_ids: &HashSet<&str>,
) -> Result<(), InlineLocalSemanticProjectionError> {
    match reference {
        EndpointRef::Local { entry_id } if local_endpoint_ids.contains(entry_id.as_str()) => Ok(()),
        EndpointRef::Local { entry_id } => Err(
            InlineLocalSemanticProjectionError::DanglingLocalEndpointReference {
                entry_id: entry_id.to_string(),
            },
        ),
        EndpointRef::Catalog { catalog, .. } => {
            Err(InlineLocalSemanticProjectionError::CatalogReference {
                name: catalog.name.to_string(),
                version: catalog.version,
            })
        }
        EndpointRef::MatchEndpoint { endpoint_id } => {
            Err(InlineLocalSemanticProjectionError::MatchEndpointReference {
                endpoint_id: endpoint_id.to_string(),
            })
        }
    }
}

fn taint_local_endpoint_ids(spec: &TaintPolicySpec) -> HashSet<&str> {
    spec.sources
        .entries
        .iter()
        .map(|entry| entry.id.as_str())
        .chain(spec.sinks.entries.iter().map(|entry| entry.id.as_str()))
        .chain(
            spec.sanitizers
                .entries
                .iter()
                .map(|entry| entry.id.as_str()),
        )
        .chain(
            spec.transforms
                .entries
                .iter()
                .map(|entry| entry.id.as_str()),
        )
        .chain(
            spec.external_models
                .entries
                .iter()
                .map(|entry| entry.id.as_str()),
        )
        .collect()
}

fn ensure_inline_selector(
    selector: &PolicySelector,
) -> Result<(), InlineLocalSemanticProjectionError> {
    match selector {
        PolicySelector::Inline { .. } => Ok(()),
        PolicySelector::File { path, .. } => {
            Err(InlineLocalSemanticProjectionError::FileSelector {
                path: path.as_str().to_string(),
            })
        }
    }
}

fn remove_inline_selector_source_tags(value: &mut Value) {
    match value {
        Value::Array(values) => {
            for value in values {
                remove_inline_selector_source_tags(value);
            }
        }
        Value::Object(object) => {
            let is_inline_selector = object.len() == 3
                && object.get("type").and_then(Value::as_str) == Some("inline")
                && object.contains_key("schema_version")
                && object.contains_key("query");
            if is_inline_selector {
                object.remove("type");
            }
            for value in object.values_mut() {
                remove_inline_selector_source_tags(value);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

fn policy_definition_to_json(definition: &PolicyDefinition) -> Value {
    let mut object = Map::new();
    insert(&mut object, "type", json!("policy"));
    insert(
        &mut object,
        "schema_version",
        json!(definition.schema_version.version),
    );
    insert(&mut object, "id", json!(definition.metadata.id.as_str()));
    insert(&mut object, "name", json!(definition.metadata.name));
    insert(
        &mut object,
        "message",
        policy_message_to_json(&definition.metadata.message),
    );
    insert(
        &mut object,
        "severity",
        policy_severity_to_json(&definition.metadata.severity),
    );
    insert_option(
        &mut object,
        "description",
        definition
            .metadata
            .description
            .as_ref()
            .map(|value| json!(value)),
    );
    insert_option(
        &mut object,
        "help_uri",
        definition
            .metadata
            .help_uri
            .as_ref()
            .map(|value| json!(value)),
    );
    insert(
        &mut object,
        "tags",
        string_set(definition.metadata.tags.iter().map(String::as_str)),
    );
    insert(
        &mut object,
        "analysis",
        policy_analysis_to_json(&definition.analysis),
    );
    insert_option(
        &mut object,
        "classification",
        definition
            .classification
            .as_ref()
            .map(classification_to_json),
    );
    insert(
        &mut object,
        "report",
        report_options_to_json(&definition.report),
    );
    Value::Object(object)
}

fn endpoint_definition_to_json(definition: &MatchEndpointDefinition) -> Value {
    let mut object = Map::new();
    insert(&mut object, "type", json!("endpoint"));
    insert(
        &mut object,
        "schema_version",
        json!(definition.schema_version.version),
    );
    insert(&mut object, "id", json!(definition.id.as_str()));
    insert(&mut object, "name", json!(definition.name));
    insert(&mut object, "display_name", json!(definition.display_name));
    insert_option(
        &mut object,
        "description",
        definition.description.as_ref().map(|value| json!(value)),
    );
    insert_option(
        &mut object,
        "help_uri",
        definition.help_uri.as_ref().map(|value| json!(value)),
    );
    insert(
        &mut object,
        "role",
        json!(endpoint_role_label(definition.role)),
    );
    insert(
        &mut object,
        "categories",
        id_set(definition.categories.iter().map(PolicyCategoryId::as_str)),
    );
    insert(
        &mut object,
        "selector",
        selector_to_json(&definition.selector),
    );
    insert(
        &mut object,
        "binding",
        endpoint_binding_to_json(&definition.binding),
    );
    insert_option(
        &mut object,
        "taint",
        definition.taint.as_ref().map(endpoint_taint_to_json),
    );
    insert(
        &mut object,
        "supersedes",
        id_set(definition.supersedes.iter().map(EndpointId::as_str)),
    );
    Value::Object(object)
}

fn policy_analysis_to_json(analysis: &PolicyAnalysis) -> Value {
    match analysis {
        PolicyAnalysis::Match { spec } => {
            let mut object = tagged("match");
            insert(&mut object, "selector", selector_to_json(&spec.selector));
            Value::Object(object)
        }
        PolicyAnalysis::Taint { spec } => {
            let mut object = tagged("taint");
            insert(&mut object, "mode", json!(may_mode_label(spec.mode)));
            insert(
                &mut object,
                "sources",
                endpoint_set_to_json(
                    &spec.sources,
                    |left, right| left.id.cmp(&right.id),
                    taint_source_to_json,
                ),
            );
            insert(
                &mut object,
                "sinks",
                endpoint_set_to_json(
                    &spec.sinks,
                    |left, right| left.id.cmp(&right.id),
                    taint_sink_to_json,
                ),
            );
            insert(
                &mut object,
                "sanitizers",
                endpoint_set_to_json(
                    &spec.sanitizers,
                    |left, right| left.id.cmp(&right.id),
                    taint_sanitizer_to_json,
                ),
            );
            insert(
                &mut object,
                "transforms",
                endpoint_set_to_json(
                    &spec.transforms,
                    |left, right| left.id.cmp(&right.id),
                    taint_transform_to_json,
                ),
            );
            insert(
                &mut object,
                "external_models",
                endpoint_set_to_json(
                    &spec.external_models,
                    |left, right| left.id.cmp(&right.id),
                    taint_external_model_to_json,
                ),
            );
            insert(
                &mut object,
                "finding_combinations",
                sorted_typed_values(
                    spec.finding_combinations.iter(),
                    |left, right| left.id.cmp(&right.id),
                    finding_combination_to_json,
                ),
            );
            Value::Object(object)
        }
        PolicyAnalysis::Typestate { spec } => {
            let mut object = tagged("typestate");
            insert(&mut object, "mode", json!(may_mode_label(spec.mode)));
            insert(
                &mut object,
                "subjects",
                typestate_subject_set_to_json(&spec.subjects),
            );
            insert(
                &mut object,
                "uncertainty",
                typestate_uncertainty_to_json(&spec.uncertainty),
            );
            insert(
                &mut object,
                "automaton",
                typestate_automaton_to_json(&spec.automaton),
            );
            Value::Object(object)
        }
    }
}

fn policy_message_to_json(message: &PolicyMessageSpec) -> Value {
    match message {
        PolicyMessageSpec::Static { text } => json!({ "type": "static", "text": text }),
        PolicyMessageSpec::Generated { relation } => json!({
            "type": "generated",
            "relation": generated_relation_label(*relation),
        }),
    }
}

fn policy_severity_to_json(severity: &PolicySeveritySpec) -> Value {
    match severity {
        PolicySeveritySpec::Fixed { level } => {
            json!({ "type": "fixed", "level": policy_level_label(*level) })
        }
        PolicySeveritySpec::Unrated => json!({ "type": "unrated" }),
        PolicySeveritySpec::Cvss { when_unscored } => json!({
            "type": "cvss",
            "when_unscored": finding_severity_label(*when_unscored),
        }),
    }
}

fn selector_to_json(selector: &PolicySelector) -> Value {
    match selector {
        PolicySelector::Inline { schema, query } => {
            json!({
                "type": "inline",
                "schema_version": schema.version,
                "query": query.to_canonical_query_plan_json(),
            })
        }
        PolicySelector::File {
            authored_schema_version,
            path,
        } => {
            let mut object = tagged("file");
            insert_option(
                &mut object,
                "authored_schema_version",
                authored_schema_version.map(|version| json!(version)),
            );
            insert(&mut object, "path", json!(path.as_str()));
            Value::Object(object)
        }
    }
}

fn endpoint_binding_to_json(binding: &PolicyEndpointBinding) -> Value {
    match binding {
        PolicyEndpointBinding::MatchedValue => Value::Object(tagged("matched_value")),
        PolicyEndpointBinding::Receiver => Value::Object(tagged("receiver")),
        PolicyEndpointBinding::ReturnValue => Value::Object(tagged("return_value")),
        PolicyEndpointBinding::ArgumentIndex { index } => {
            json!({ "type": "argument_index", "index": index })
        }
        PolicyEndpointBinding::ArgumentName { name } => {
            json!({ "type": "argument_name", "name": name })
        }
    }
}

fn endpoint_taint_to_json(taint: &EndpointTaintSemantics) -> Value {
    match taint {
        EndpointTaintSemantics::Source { labels, evidence } => {
            let mut object = tagged("source");
            insert(
                &mut object,
                "labels",
                id_set(labels.iter().map(TaintLabel::as_str)),
            );
            insert_option(
                &mut object,
                "evidence",
                evidence.as_ref().map(taint_source_evidence_to_json),
            );
            Value::Object(object)
        }
        EndpointTaintSemantics::Sink {
            accepts,
            tags,
            impacts,
        } => {
            let mut object = tagged("sink");
            insert(
                &mut object,
                "accepts",
                id_set(accepts.iter().map(TaintLabel::as_str)),
            );
            insert(
                &mut object,
                "tags",
                id_set(tags.iter().map(TaintTag::as_str)),
            );
            insert(
                &mut object,
                "impacts",
                id_set(impacts.iter().map(TaintImpact::as_str)),
            );
            Value::Object(object)
        }
    }
}

fn report_options_to_json(report: &PolicyReportOptions) -> Value {
    json!({
        "witness": {
            "max_steps": report.witness.max_steps,
            "max_bytes": report.witness.max_bytes,
        },
        "witnesses_per_finding": report.witnesses_per_finding,
        "origins_per_finding": report.origins_per_finding,
    })
}

fn endpoint_set_to_json<T>(
    set: &TaintEndpointSet<T>,
    compare_entries: fn(&T, &T) -> Ordering,
    entry_to_json: fn(&T) -> Value,
) -> Value {
    json!({
        "include_sets": sorted_typed_values(
            set.include_sets.iter(),
            compare_catalog_refs,
            catalog_ref_to_json,
        ),
        "include_matches": sorted_typed_values(
            set.include_matches.iter(),
            compare_match_endpoint_set_refs,
            match_endpoint_set_ref_to_json,
        ),
        "entries": sorted_typed_values(set.entries.iter(), compare_entries, entry_to_json),
    })
}

fn catalog_ref_to_json(reference: &CatalogRef) -> Value {
    let mut object = Map::new();
    insert(&mut object, "name", json!(reference.name.as_str()));
    insert(&mut object, "version", json!(reference.version));
    insert_option(
        &mut object,
        "sha256",
        reference.sha256.map(|hash| json!(hash.to_string())),
    );
    Value::Object(object)
}

fn match_endpoint_set_ref_to_json(reference: &MatchEndpointSetRef) -> Value {
    match reference {
        MatchEndpointSetRef::Directory { reference } => {
            json!({ "type": "directory", "reference": match_directory_ref_to_json(reference) })
        }
        MatchEndpointSetRef::Exact { endpoint_ids } => json!({
            "type": "exact",
            "endpoint_ids": id_set(endpoint_ids.iter().map(EndpointId::as_str)),
        }),
    }
}

fn match_directory_ref_to_json(reference: &MatchDirectoryRef) -> Value {
    let mut object = Map::new();
    insert(&mut object, "path", json!(reference.path.as_str()));
    insert(
        &mut object,
        "scope",
        json!(directory_scope_label(reference.scope)),
    );
    insert(
        &mut object,
        "categories",
        category_predicate_to_json(&reference.categories),
    );
    insert_option(
        &mut object,
        "manifest_sha256",
        reference
            .manifest_sha256
            .map(|hash| json!(hash.to_string())),
    );
    Value::Object(object)
}

fn category_predicate_to_json(predicate: &CategoryPredicate) -> Value {
    match predicate {
        CategoryPredicate::Any { categories } => json!({
            "type": "any",
            "categories": id_set(categories.iter().map(PolicyCategoryId::as_str)),
        }),
        CategoryPredicate::All { categories } => json!({
            "type": "all",
            "categories": id_set(categories.iter().map(PolicyCategoryId::as_str)),
        }),
    }
}

fn finding_combination_to_json(combination: &FindingCombinationSpec) -> Value {
    let mut object = Map::new();
    insert(&mut object, "id", json!(combination.id.as_str()));
    insert(
        &mut object,
        "source",
        endpoint_predicate_to_json(&combination.source),
    );
    insert(
        &mut object,
        "sink",
        endpoint_predicate_to_json(&combination.sink),
    );
    insert(&mut object, "message", json!(combination.message));
    insert_option(
        &mut object,
        "severity",
        combination.severity.as_ref().map(policy_severity_to_json),
    );
    insert(
        &mut object,
        "add_classifications",
        sorted_typed_values(
            combination.add_classifications.iter(),
            compare_taxonomy_classifications,
            taxonomy_classification_to_json,
        ),
    );
    insert(
        &mut object,
        "supersedes",
        id_set(
            combination
                .supersedes
                .iter()
                .map(FindingCombinationId::as_str),
        ),
    );
    Value::Object(object)
}

fn endpoint_predicate_to_json(predicate: &EndpointPredicate) -> Value {
    match predicate {
        EndpointPredicate::Categories { predicate } => json!({
            "type": "categories",
            "predicate": category_predicate_to_json(predicate),
        }),
        EndpointPredicate::Exact { endpoints } => json!({
            "type": "exact",
            "endpoints": sorted_typed_values(
                endpoints.iter(),
                compare_endpoint_refs,
                endpoint_ref_to_json,
            ),
        }),
    }
}

fn endpoint_ref_to_json(reference: &EndpointRef) -> Value {
    match reference {
        EndpointRef::Local { entry_id } => {
            json!({ "type": "local", "entry_id": entry_id.as_str() })
        }
        EndpointRef::Catalog { catalog, entry_id } => json!({
            "type": "catalog",
            "catalog": catalog_ref_to_json(catalog),
            "entry_id": entry_id.as_str(),
        }),
        EndpointRef::MatchEndpoint { endpoint_id } => json!({
            "type": "match_endpoint",
            "endpoint_id": endpoint_id.as_str(),
        }),
    }
}

fn policy_port_to_json(port: &PolicyPort) -> Value {
    match port {
        PolicyPort::MatchedValue => Value::Object(tagged("matched_value")),
        PolicyPort::Receiver => Value::Object(tagged("receiver")),
        PolicyPort::ReturnValue => Value::Object(tagged("return_value")),
        PolicyPort::ArgumentIndex { index } => {
            json!({ "type": "argument_index", "index": index })
        }
        PolicyPort::ArgumentName { name } => {
            json!({ "type": "argument_name", "name": name })
        }
    }
}

fn taint_source_to_json(source: &TaintSourceSpec) -> Value {
    let mut object = Map::new();
    insert(&mut object, "id", json!(source.id.as_str()));
    insert(&mut object, "display_name", json!(source.display_name));
    insert(
        &mut object,
        "categories",
        id_set(source.categories.iter().map(PolicyCategoryId::as_str)),
    );
    insert(&mut object, "selector", selector_to_json(&source.selector));
    insert(&mut object, "bind", policy_port_to_json(&source.bind));
    insert(
        &mut object,
        "labels",
        id_set(source.labels.iter().map(TaintLabel::as_str)),
    );
    insert_option(
        &mut object,
        "evidence",
        source.evidence.as_ref().map(taint_source_evidence_to_json),
    );
    Value::Object(object)
}

fn taint_source_evidence_to_json(evidence: &TaintSourceEvidence) -> Value {
    let mut object = Map::new();
    insert_option(
        &mut object,
        "trust_boundary",
        evidence
            .trust_boundary
            .map(|value| json!(taint_trust_boundary_label(value))),
    );
    insert_option(
        &mut object,
        "system_entry",
        evidence
            .system_entry
            .map(|value| json!(taint_system_entry_label(value))),
    );
    Value::Object(object)
}

fn taint_sink_to_json(sink: &TaintSinkSpec) -> Value {
    json!({
        "id": sink.id.as_str(),
        "display_name": sink.display_name,
        "categories": id_set(sink.categories.iter().map(PolicyCategoryId::as_str)),
        "selector": selector_to_json(&sink.selector),
        "dangerous_operand": policy_port_to_json(&sink.dangerous_operand),
        "accepts": id_set(sink.accepts.iter().map(TaintLabel::as_str)),
        "tags": id_set(sink.tags.iter().map(TaintTag::as_str)),
        "impacts": id_set(sink.impacts.iter().map(TaintImpact::as_str)),
    })
}

fn taint_sanitizer_to_json(sanitizer: &TaintSanitizerSpec) -> Value {
    json!({
        "id": sanitizer.id.as_str(),
        "selector": selector_to_json(&sanitizer.selector),
        "input": policy_port_to_json(&sanitizer.input),
        "output": policy_port_to_json(&sanitizer.output),
        "removes": id_set(sanitizer.removes.iter().map(TaintLabel::as_str)),
    })
}

fn taint_transform_to_json(transform: &TaintTransformSpec) -> Value {
    json!({
        "id": transform.id.as_str(),
        "selector": selector_to_json(&transform.selector),
        "input": policy_port_to_json(&transform.input),
        "output": policy_port_to_json(&transform.output),
        "removes": id_set(transform.removes.iter().map(TaintLabel::as_str)),
        "adds": id_set(transform.adds.iter().map(TaintLabel::as_str)),
    })
}

fn taint_external_model_to_json(model: &TaintExternalModelSpec) -> Value {
    json!({
        "id": model.id.as_str(),
        "selector": selector_to_json(&model.selector),
        "transfers": sorted_values(model.transfers.iter().map(taint_transfer_to_json)),
    })
}

fn taint_transfer_to_json(transfer: &TaintTransferSpec) -> Value {
    json!({
        "from": policy_port_to_json(&transfer.from),
        "to": policy_port_to_json(&transfer.to),
        "labels": id_set(transfer.labels.iter().map(TaintLabel::as_str)),
        "effect": taint_transfer_effect_to_json(&transfer.effect),
    })
}

fn taint_transfer_effect_to_json(effect: &TaintTransferEffect) -> Value {
    match effect {
        TaintTransferEffect::Propagate => Value::Object(tagged("propagate")),
        TaintTransferEffect::Sanitize { removes } => json!({
            "type": "sanitize",
            "removes": id_set(removes.iter().map(TaintLabel::as_str)),
        }),
        TaintTransferEffect::Transform { removes, adds } => json!({
            "type": "transform",
            "removes": id_set(removes.iter().map(TaintLabel::as_str)),
            "adds": id_set(adds.iter().map(TaintLabel::as_str)),
        }),
    }
}

fn typestate_subject_set_to_json(subjects: &TypestateSubjectSet) -> Value {
    json!({
        "include_matches": sorted_typed_values(
            subjects.include_matches.iter(),
            compare_match_endpoint_set_refs,
            match_endpoint_set_ref_to_json,
        ),
        "entries": sorted_typed_values(
            subjects.entries.iter(),
            |left, right| left.id.cmp(&right.id),
            typestate_subject_to_json,
        ),
    })
}

fn typestate_subject_to_json(subject: &TypestateSubjectSpec) -> Value {
    json!({
        "id": subject.id.as_str(),
        "selector": selector_to_json(&subject.selector),
        "subject": typestate_seed_binding_to_json(&subject.subject),
    })
}

fn typestate_seed_binding_to_json(binding: &TypestateSeedBinding) -> Value {
    match binding {
        TypestateSeedBinding::MatchedValue => Value::Object(tagged("matched_value")),
        TypestateSeedBinding::Receiver => Value::Object(tagged("receiver")),
        TypestateSeedBinding::ReturnValue => Value::Object(tagged("return_value")),
        TypestateSeedBinding::ArgumentIndex { index } => {
            json!({ "type": "argument_index", "index": index })
        }
        TypestateSeedBinding::ArgumentName { name } => {
            json!({ "type": "argument_name", "name": name })
        }
    }
}

fn typestate_uncertainty_to_json(uncertainty: &TypestateUncertaintySpec) -> Value {
    json!({
        "unknown_call": inconclusive_policy_label(uncertainty.unknown_call),
        "escape": inconclusive_policy_label(uncertainty.escape),
    })
}

fn typestate_automaton_to_json(automaton: &TypestateAutomatonSpec) -> Value {
    json!({
        "states": id_set(automaton.states.iter().map(TypestateStateId::as_str)),
        "initial": automaton.initial.as_str(),
        "accepting_states": id_set(
            automaton.accepting_states.iter().map(TypestateStateId::as_str),
        ),
        "error_states": id_set(automaton.error_states.iter().map(TypestateStateId::as_str)),
        "events": sorted_typed_values(
            automaton.events.iter(),
            |left, right| left.id.cmp(&right.id),
            typestate_event_to_json,
        ),
        "transitions": sorted_typed_values(
            automaton.transitions.iter(),
            compare_typestate_transitions,
            typestate_transition_to_json,
        ),
        "terminal_expectations": sorted_typed_values(
            automaton
                .terminal_expectations
                .iter(),
            |left, right| left.id.cmp(&right.id),
            typestate_terminal_expectation_to_json,
        ),
    })
}

fn typestate_event_to_json(event: &TypestateEventSpec) -> Value {
    let mut object = Map::new();
    insert(&mut object, "id", json!(event.id.as_str()));
    insert(
        &mut object,
        "trigger",
        typestate_event_trigger_to_json(&event.trigger),
    );
    insert_option(
        &mut object,
        "applies_to_subjects",
        event
            .applies_to_subjects
            .as_ref()
            .map(endpoint_predicate_to_json),
    );
    insert(
        &mut object,
        "supersedes",
        id_set(event.supersedes.iter().map(TypestateEventId::as_str)),
    );
    Value::Object(object)
}

fn typestate_event_trigger_to_json(trigger: &TypestateEventTrigger) -> Value {
    match trigger {
        TypestateEventTrigger::Calls {
            selector,
            subject,
            phase,
        } => json!({
            "type": "calls",
            "selector": selector_to_json(selector),
            "subject": typestate_call_binding_to_json(subject),
            "phase": endpoint_observation_phase_label(*phase),
        }),
        TypestateEventTrigger::MatchEndpoints { set, role, phase } => json!({
            "type": "match_endpoints",
            "set": match_endpoint_set_ref_to_json(set),
            "role": endpoint_role_label(*role),
            "phase": endpoint_observation_phase_label(*phase),
        }),
        TypestateEventTrigger::SemanticEvent { event } => json!({
            "type": "semantic_event",
            "event": policy_semantic_event_to_json(*event),
        }),
    }
}

fn typestate_call_binding_to_json(binding: &TypestateCallBinding) -> Value {
    match binding {
        TypestateCallBinding::Receiver => Value::Object(tagged("receiver")),
        TypestateCallBinding::ReturnValue => Value::Object(tagged("return_value")),
        TypestateCallBinding::ArgumentIndex { index } => {
            json!({ "type": "argument_index", "index": index })
        }
        TypestateCallBinding::ArgumentName { name } => {
            json!({ "type": "argument_name", "name": name })
        }
    }
}

fn policy_semantic_event_to_json(event: PolicySemanticEvent) -> Value {
    match event {
        PolicySemanticEvent::NormalProcedureExit { scope } => json!({
            "type": "normal_procedure_exit",
            "scope": typestate_exit_scope_label(scope),
        }),
        PolicySemanticEvent::ExceptionalProcedureExit { scope } => json!({
            "type": "exceptional_procedure_exit",
            "scope": typestate_exit_scope_label(scope),
        }),
    }
}

fn typestate_transition_to_json(transition: &TypestateTransitionSpec) -> Value {
    json!({
        "from": transition.from.as_str(),
        "on": transition.on.as_str(),
        "to": transition.to.as_str(),
    })
}

fn typestate_terminal_expectation_to_json(expectation: &TypestateTerminalExpectationSpec) -> Value {
    let mut object = Map::new();
    insert(&mut object, "id", json!(expectation.id.as_str()));
    insert(
        &mut object,
        "trigger",
        typestate_terminal_trigger_to_json(&expectation.trigger),
    );
    insert_option(
        &mut object,
        "applies_to_subjects",
        expectation
            .applies_to_subjects
            .as_ref()
            .map(endpoint_predicate_to_json),
    );
    insert(
        &mut object,
        "expected_states",
        id_set(
            expectation
                .expected_states
                .iter()
                .map(TypestateStateId::as_str),
        ),
    );
    insert(
        &mut object,
        "supersedes",
        id_set(
            expectation
                .supersedes
                .iter()
                .map(TypestateExpectationId::as_str),
        ),
    );
    Value::Object(object)
}

fn typestate_terminal_trigger_to_json(trigger: &TypestateTerminalTrigger) -> Value {
    match trigger {
        TypestateTerminalTrigger::MatchEndpoints { set, role, phase } => json!({
            "type": "match_endpoints",
            "set": match_endpoint_set_ref_to_json(set),
            "role": endpoint_role_label(*role),
            "phase": endpoint_observation_phase_label(*phase),
        }),
        TypestateTerminalTrigger::SemanticEvent { event } => json!({
            "type": "semantic_event",
            "event": policy_semantic_event_to_json(*event),
        }),
    }
}

fn classification_to_json(classification: &PolicyClassificationSpec) -> Value {
    let mut object = Map::new();
    insert(
        &mut object,
        "fallback",
        taxonomy_classification_to_json(&classification.fallback),
    );
    // Refinements are intentionally ordered: later evaluation applies them in
    // authored order and canonical authoring JSON must preserve that contract.
    insert(
        &mut object,
        "refinements",
        Value::Array(
            classification
                .refinements
                .iter()
                .map(classification_refinement_to_json)
                .collect(),
        ),
    );
    insert_option(
        &mut object,
        "cvss",
        classification.cvss.as_ref().map(cvss_policy_to_json),
    );
    Value::Object(object)
}

fn classification_refinement_to_json(refinement: &ClassificationRefinementSpec) -> Value {
    json!({
        "when": classification_predicate_to_json(&refinement.when),
        "add": sorted_typed_values(
            refinement.add.iter(),
            compare_taxonomy_classifications,
            taxonomy_classification_to_json,
        ),
    })
}

fn taxonomy_classification_to_json(classification: &TaxonomyClassificationSpec) -> Value {
    let mut object = Map::new();
    insert(&mut object, "taxonomy", json!(classification.taxonomy));
    insert(&mut object, "identifier", json!(classification.identifier));
    insert_option(
        &mut object,
        "name",
        classification.name.as_ref().map(|value| json!(value)),
    );
    Value::Object(object)
}

fn classification_predicate_to_json(predicate: &ClassificationPredicate) -> Value {
    match predicate {
        ClassificationPredicate::All { predicates } => json!({
            "type": "all",
            "predicates": sorted_values(predicates.iter().map(classification_predicate_to_json)),
        }),
        ClassificationPredicate::Any { predicates } => json!({
            "type": "any",
            "predicates": sorted_values(predicates.iter().map(classification_predicate_to_json)),
        }),
        ClassificationPredicate::AnalysisType { analysis_type } => json!({
            "type": "analysis_type",
            "analysis_type": policy_analysis_type_label(*analysis_type),
        }),
        ClassificationPredicate::SourceCategories { quantifier, values } => json!({
            "type": "source_categories",
            "quantifier": any_or_all_label(*quantifier),
            "values": id_set(values.iter().map(PolicyCategoryId::as_str)),
        }),
        ClassificationPredicate::SinkCategories { quantifier, values } => json!({
            "type": "sink_categories",
            "quantifier": any_or_all_label(*quantifier),
            "values": id_set(values.iter().map(PolicyCategoryId::as_str)),
        }),
        ClassificationPredicate::SourceLabels { quantifier, values } => json!({
            "type": "source_labels",
            "quantifier": any_or_all_label(*quantifier),
            "values": id_set(values.iter().map(TaintLabel::as_str)),
        }),
        ClassificationPredicate::SinkTags { quantifier, values } => json!({
            "type": "sink_tags",
            "quantifier": any_or_all_label(*quantifier),
            "values": id_set(values.iter().map(TaintTag::as_str)),
        }),
        ClassificationPredicate::SinkImpacts { quantifier, values } => json!({
            "type": "sink_impacts",
            "quantifier": any_or_all_label(*quantifier),
            "values": id_set(values.iter().map(TaintImpact::as_str)),
        }),
        ClassificationPredicate::FindingCombination { id } => json!({
            "type": "finding_combination",
            "id": id.as_str(),
        }),
        ClassificationPredicate::TypestateExpectation { id } => json!({
            "type": "typestate_expectation",
            "id": id.as_str(),
        }),
    }
}

fn cvss_policy_to_json(cvss: &CvssPolicySpec) -> Value {
    json!({
        "version": cvss.version.wire_label(),
        "emit": cvss_emit_policy_label(cvss.emit),
        // Rule precedence is intentionally authored order.
        "metric_rules": cvss
            .metric_rules
            .iter()
            .map(cvss_metric_rule_to_json)
            .collect::<Vec<_>>(),
    })
}

fn cvss_metric_rule_to_json(rule: &CvssMetricRule) -> Value {
    json!({
        "metric": rule.metric().first_label(),
        "value": rule.value().first_label(),
        "when": cvss_evidence_predicate_to_json(rule.when()),
        "basis": policy_cvss_basis_label(rule.basis()),
        "scope": cvss_evidence_scope_to_json(rule.scope()),
        "evidence_refs": sorted_typed_values(
            rule.evidence_refs().iter(),
            compare_policy_evidence_refs,
            policy_evidence_ref_to_json,
        ),
        "rationale": rule.rationale(),
        "assumptions": string_set(rule.assumptions().iter().map(String::as_str)),
    })
}

fn cvss_evidence_predicate_to_json(predicate: &CvssEvidencePredicate) -> Value {
    match predicate {
        CvssEvidencePredicate::All { predicates } => json!({
            "type": "all",
            "predicates": sorted_values(predicates.iter().map(cvss_evidence_predicate_to_json)),
        }),
        CvssEvidencePredicate::Any { predicates } => json!({
            "type": "any",
            "predicates": sorted_values(predicates.iter().map(cvss_evidence_predicate_to_json)),
        }),
        CvssEvidencePredicate::AnalysisType { analysis_type } => json!({
            "type": "analysis_type",
            "analysis_type": policy_analysis_type_label(*analysis_type),
        }),
        CvssEvidencePredicate::SourceEvidence { evidence } => json!({
            "type": "source_evidence",
            "evidence": taint_source_evidence_to_json(evidence),
        }),
        CvssEvidencePredicate::SourceCategories { quantifier, values } => json!({
            "type": "source_categories",
            "quantifier": any_or_all_label(*quantifier),
            "values": id_set(values.iter().map(PolicyCategoryId::as_str)),
        }),
        CvssEvidencePredicate::SinkCategories { quantifier, values } => json!({
            "type": "sink_categories",
            "quantifier": any_or_all_label(*quantifier),
            "values": id_set(values.iter().map(PolicyCategoryId::as_str)),
        }),
        CvssEvidencePredicate::SourceLabels { quantifier, values } => json!({
            "type": "source_labels",
            "quantifier": any_or_all_label(*quantifier),
            "values": id_set(values.iter().map(TaintLabel::as_str)),
        }),
        CvssEvidencePredicate::SinkTags { quantifier, values } => json!({
            "type": "sink_tags",
            "quantifier": any_or_all_label(*quantifier),
            "values": id_set(values.iter().map(TaintTag::as_str)),
        }),
        CvssEvidencePredicate::SinkImpacts { quantifier, values } => json!({
            "type": "sink_impacts",
            "quantifier": any_or_all_label(*quantifier),
            "values": id_set(values.iter().map(TaintImpact::as_str)),
        }),
    }
}

fn cvss_evidence_scope_to_json(scope: CvssEvidenceScope) -> Value {
    match scope {
        CvssEvidenceScope::Global => Value::Object(tagged("global")),
        CvssEvidenceScope::System { system } => json!({
            "type": "system",
            "system": cvss_system_scope_label(system),
        }),
    }
}

fn policy_evidence_ref_to_json(reference: &PolicyEvidenceRef) -> Value {
    match reference {
        PolicyEvidenceRef::PolicySelf => Value::Object(tagged("policy_self")),
        PolicyEvidenceRef::Endpoint { endpoint } => json!({
            "type": "endpoint",
            "endpoint": endpoint_ref_to_json(endpoint),
        }),
        PolicyEvidenceRef::Selector { path } => json!({
            "type": "selector",
            "path": path.as_str(),
        }),
    }
}

fn tagged(label: &str) -> Map<String, Value> {
    let mut object = Map::new();
    insert(&mut object, "type", json!(label));
    object
}

fn insert(object: &mut Map<String, Value>, key: &str, value: Value) {
    object.insert(key.to_string(), value);
}

fn insert_option(object: &mut Map<String, Value>, key: &str, value: Option<Value>) {
    if let Some(value) = value {
        insert(object, key, value);
    }
}

fn id_set<'a>(values: impl Iterator<Item = &'a str>) -> Value {
    string_set(values)
}

fn string_set<'a>(values: impl Iterator<Item = &'a str>) -> Value {
    let mut values = values.map(str::to_string).collect::<Vec<_>>();
    values.sort_unstable();
    values.dedup();
    Value::Array(values.into_iter().map(Value::String).collect())
}

fn sorted_typed_values<'a, T: 'a>(
    values: impl Iterator<Item = &'a T>,
    mut compare: impl FnMut(&T, &T) -> Ordering,
    encode: impl Fn(&T) -> Value,
) -> Value {
    let mut values = values
        .map(|value| {
            let encoded = encode(value);
            let tie_breaker = serde_json::to_string(&encoded)
                .expect("serializing a serde_json::Value cannot fail");
            (value, encoded, tie_breaker)
        })
        .collect::<Vec<_>>();
    values.sort_unstable_by(|left, right| {
        compare(left.0, right.0).then_with(|| left.2.cmp(&right.2))
    });
    let mut encoded = values
        .into_iter()
        .map(|(_, encoded, _)| encoded)
        .collect::<Vec<_>>();
    encoded.dedup();
    Value::Array(encoded)
}

fn sorted_values(values: impl Iterator<Item = Value>) -> Value {
    let mut values = values.collect::<Vec<_>>();
    values.sort_unstable_by_key(|value| {
        serde_json::to_string(value).expect("serializing a serde_json::Value cannot fail")
    });
    values.dedup();
    Value::Array(values)
}

fn compare_catalog_refs(left: &CatalogRef, right: &CatalogRef) -> Ordering {
    left.name
        .cmp(&right.name)
        .then_with(|| left.version.cmp(&right.version))
        .then_with(|| left.sha256.cmp(&right.sha256))
}

fn compare_match_endpoint_set_refs(
    left: &MatchEndpointSetRef,
    right: &MatchEndpointSetRef,
) -> Ordering {
    match (left, right) {
        (
            MatchEndpointSetRef::Directory { reference: left },
            MatchEndpointSetRef::Directory { reference: right },
        ) => compare_match_directory_refs(left, right),
        (MatchEndpointSetRef::Directory { .. }, MatchEndpointSetRef::Exact { .. }) => {
            Ordering::Less
        }
        (MatchEndpointSetRef::Exact { .. }, MatchEndpointSetRef::Directory { .. }) => {
            Ordering::Greater
        }
        (
            MatchEndpointSetRef::Exact { endpoint_ids: left },
            MatchEndpointSetRef::Exact {
                endpoint_ids: right,
            },
        ) => sorted_identifier_refs(left.iter().map(EndpointId::as_str)).cmp(
            &sorted_identifier_refs(right.iter().map(EndpointId::as_str)),
        ),
    }
}

fn compare_match_directory_refs(left: &MatchDirectoryRef, right: &MatchDirectoryRef) -> Ordering {
    left.path
        .cmp(&right.path)
        .then_with(|| directory_scope_label(left.scope).cmp(directory_scope_label(right.scope)))
        .then_with(|| compare_category_predicates(&left.categories, &right.categories))
        .then_with(|| left.manifest_sha256.cmp(&right.manifest_sha256))
}

fn compare_category_predicates(left: &CategoryPredicate, right: &CategoryPredicate) -> Ordering {
    let (left_kind, left_categories) = match left {
        CategoryPredicate::Any { categories } => (0_u8, categories),
        CategoryPredicate::All { categories } => (1_u8, categories),
    };
    let (right_kind, right_categories) = match right {
        CategoryPredicate::Any { categories } => (0_u8, categories),
        CategoryPredicate::All { categories } => (1_u8, categories),
    };
    left_kind.cmp(&right_kind).then_with(|| {
        sorted_identifier_refs(left_categories.iter().map(PolicyCategoryId::as_str)).cmp(
            &sorted_identifier_refs(right_categories.iter().map(PolicyCategoryId::as_str)),
        )
    })
}

fn compare_endpoint_refs(left: &EndpointRef, right: &EndpointRef) -> Ordering {
    match (left, right) {
        (EndpointRef::Local { entry_id: left }, EndpointRef::Local { entry_id: right }) => {
            left.cmp(right)
        }
        (EndpointRef::Local { .. }, _) => Ordering::Less,
        (_, EndpointRef::Local { .. }) => Ordering::Greater,
        (
            EndpointRef::Catalog {
                catalog: left_catalog,
                entry_id: left_entry,
            },
            EndpointRef::Catalog {
                catalog: right_catalog,
                entry_id: right_entry,
            },
        ) => compare_catalog_refs(left_catalog, right_catalog)
            .then_with(|| left_entry.cmp(right_entry)),
        (EndpointRef::Catalog { .. }, EndpointRef::MatchEndpoint { .. }) => Ordering::Less,
        (EndpointRef::MatchEndpoint { .. }, EndpointRef::Catalog { .. }) => Ordering::Greater,
        (
            EndpointRef::MatchEndpoint { endpoint_id: left },
            EndpointRef::MatchEndpoint { endpoint_id: right },
        ) => left.cmp(right),
    }
}

fn compare_taxonomy_classifications(
    left: &TaxonomyClassificationSpec,
    right: &TaxonomyClassificationSpec,
) -> Ordering {
    left.taxonomy
        .cmp(&right.taxonomy)
        .then_with(|| left.identifier.cmp(&right.identifier))
        .then_with(|| left.name.cmp(&right.name))
}

fn compare_typestate_transitions(
    left: &TypestateTransitionSpec,
    right: &TypestateTransitionSpec,
) -> Ordering {
    left.from
        .cmp(&right.from)
        .then_with(|| left.on.cmp(&right.on))
        .then_with(|| left.to.cmp(&right.to))
}

fn compare_policy_evidence_refs(left: &PolicyEvidenceRef, right: &PolicyEvidenceRef) -> Ordering {
    match (left, right) {
        (PolicyEvidenceRef::PolicySelf, PolicyEvidenceRef::PolicySelf) => Ordering::Equal,
        (PolicyEvidenceRef::PolicySelf, _) => Ordering::Less,
        (_, PolicyEvidenceRef::PolicySelf) => Ordering::Greater,
        (
            PolicyEvidenceRef::Endpoint { endpoint: left },
            PolicyEvidenceRef::Endpoint { endpoint: right },
        ) => compare_endpoint_refs(left, right),
        (PolicyEvidenceRef::Endpoint { .. }, PolicyEvidenceRef::Selector { .. }) => Ordering::Less,
        (PolicyEvidenceRef::Selector { .. }, PolicyEvidenceRef::Endpoint { .. }) => {
            Ordering::Greater
        }
        (
            PolicyEvidenceRef::Selector { path: left },
            PolicyEvidenceRef::Selector { path: right },
        ) => left.cmp(right),
    }
}

fn sorted_identifier_refs<'a>(values: impl Iterator<Item = &'a str>) -> Vec<&'a str> {
    let mut values = values.collect::<Vec<_>>();
    values.sort_unstable();
    values.dedup();
    values
}

const fn generated_relation_label(value: GeneratedRelation) -> &'static str {
    match value {
        GeneratedRelation::CanReach => "can_reach",
    }
}

const fn policy_level_label(value: PolicyLevel) -> &'static str {
    match value {
        PolicyLevel::Note => "note",
        PolicyLevel::Warning => "warning",
        PolicyLevel::Error => "error",
    }
}

const fn finding_severity_label(value: FindingSeverity) -> &'static str {
    match value {
        FindingSeverity::Unrated => "unrated",
        FindingSeverity::Note => "note",
        FindingSeverity::Warning => "warning",
        FindingSeverity::Error => "error",
    }
}

const fn policy_analysis_type_label(value: PolicyAnalysisType) -> &'static str {
    match value {
        PolicyAnalysisType::Match => "match",
        PolicyAnalysisType::Taint => "taint",
        PolicyAnalysisType::Typestate => "typestate",
    }
}

const fn endpoint_role_label(value: EndpointRole) -> &'static str {
    match value {
        EndpointRole::Source => "source",
        EndpointRole::Sink => "sink",
    }
}

const fn directory_scope_label(value: DirectoryScope) -> &'static str {
    match value {
        DirectoryScope::Direct => "direct",
        DirectoryScope::Recursive => "recursive",
    }
}

const fn may_mode_label(value: MayMode) -> &'static str {
    match value {
        MayMode::May => "may",
    }
}

const fn taint_trust_boundary_label(value: TaintTrustBoundary) -> &'static str {
    match value {
        TaintTrustBoundary::External => "external",
        TaintTrustBoundary::Internal => "internal",
        TaintTrustBoundary::SameTrustZone => "same_trust_zone",
    }
}

const fn taint_system_entry_label(value: TaintSystemEntry) -> &'static str {
    match value {
        TaintSystemEntry::VulnerableSystemNetworkStack => "vulnerable_system_network_stack",
        TaintSystemEntry::DownloadedArtifact => "downloaded_artifact",
        TaintSystemEntry::LocalInput => "local_input",
        TaintSystemEntry::AdjacentNetwork => "adjacent_network",
        TaintSystemEntry::Physical => "physical",
    }
}

const fn inconclusive_policy_label(value: InconclusivePolicy) -> &'static str {
    match value {
        InconclusivePolicy::Inconclusive => "inconclusive",
    }
}

const fn typestate_exit_scope_label(value: TypestateExitScope) -> &'static str {
    match value {
        TypestateExitScope::AnalysisRoot => "analysis_root",
    }
}

const fn endpoint_observation_phase_label(value: EndpointObservationPhase) -> &'static str {
    match value {
        EndpointObservationPhase::AtMatch => "at_match",
        EndpointObservationPhase::BeforeCall => "before_call",
        EndpointObservationPhase::AfterNormalReturn => "after_normal_return",
        EndpointObservationPhase::AfterExceptionalReturn => "after_exceptional_return",
    }
}

const fn any_or_all_label(value: AnyOrAll) -> &'static str {
    match value {
        AnyOrAll::Any => "any",
        AnyOrAll::All => "all",
    }
}

const fn cvss_emit_policy_label(value: CvssEmitPolicy) -> &'static str {
    match value {
        CvssEmitPolicy::WhenBaseComplete => "when_base_complete",
    }
}

const fn policy_cvss_basis_label(value: PolicyCvssBasis) -> &'static str {
    match value {
        PolicyCvssBasis::PolicyAssertion => "policy_assertion",
    }
}

const fn cvss_system_scope_label(value: CvssSystemScope) -> &'static str {
    match value {
        CvssSystemScope::VulnerableSystem => "vulnerable_system",
        CvssSystemScope::SubsequentSystem => "subsequent_system",
    }
}

#[cfg(test)]
mod tests {
    use crate::analyzer::semantic::WorkspaceRelativePath;
    use crate::analyzer::structural::CodeQuery;
    use crate::schema_version::{SchemaVersionOrigin, SchemaVersionResolution};
    use serde_json::json;

    use super::*;

    fn schema(version: u32) -> SchemaVersionResolution {
        SchemaVersionResolution {
            version,
            origin: SchemaVersionOrigin::ImplicitCompatible,
        }
    }

    fn inline_selector() -> PolicySelector {
        PolicySelector::Inline {
            schema: schema(2),
            query: CodeQuery::from_sexp("(call :callee (name \"eval\"))").unwrap(),
        }
    }

    fn metadata() -> PolicyMetadata {
        PolicyMetadata {
            id: PolicyId::new("bifrost.security.example").unwrap(),
            name: "Example".to_string(),
            message: PolicyMessageSpec::Static {
                text: "Example finding".to_string(),
            },
            severity: PolicySeveritySpec::Fixed {
                level: PolicyLevel::Warning,
            },
            description: None,
            help_uri: None,
            tags: vec![
                "security".to_string(),
                "audit".to_string(),
                "security".to_string(),
            ],
        }
    }

    #[test]
    fn match_projection_flattens_metadata_materializes_defaults_and_strips_query_controls() {
        let document = RqlpDocument::Policy {
            definition: Box::new(PolicyDefinition {
                schema_version: schema(1),
                metadata: metadata(),
                analysis: PolicyAnalysis::Match {
                    spec: MatchPolicySpec {
                        selector: inline_selector(),
                    },
                },
                classification: None,
                report: PolicyReportOptions::default(),
            }),
        };

        let actual = document.to_normalized_authored_json();
        assert_eq!(
            actual,
            json!({
                "type": "policy",
                "schema_version": 1,
                "id": "bifrost.security.example",
                "name": "Example",
                "message": { "type": "static", "text": "Example finding" },
                "severity": { "type": "fixed", "level": "warning" },
                "tags": ["audit", "security"],
                "analysis": {
                    "type": "match",
                    "selector": {
                        "type": "inline",
                        "schema_version": 2,
                        "query": {
                            "schema_version": 2,
                            "match": { "kind": "call", "callee": { "name": "eval" } },
                        },
                    },
                },
                "report": {
                    "witness": { "max_steps": 64, "max_bytes": 16384 },
                    "witnesses_per_finding": 8,
                    "origins_per_finding": 8,
                },
            })
        );
        assert!(actual.pointer("/analysis/selector/query/limit").is_none());
        assert!(
            actual
                .pointer("/analysis/selector/query/result_detail")
                .is_none()
        );

        let semantic = document.to_inline_local_canonical_semantic_json().unwrap();
        assert_eq!(
            semantic.pointer("/analysis/selector/schema_version"),
            Some(&json!(2))
        );
        assert!(semantic.pointer("/analysis/selector/type").is_none());
    }

    #[test]
    fn endpoint_projection_keeps_unresolved_file_selector_and_normalizes_sets() {
        let document = RqlpDocument::Endpoint {
            definition: Box::new(MatchEndpointDefinition {
                schema_version: schema(1),
                id: EndpointId::new("bifrost.sources.request").unwrap(),
                name: "Request value".to_string(),
                display_name: "user-controlled I/O".to_string(),
                description: None,
                help_uri: Some("https://example.invalid/source".to_string()),
                role: EndpointRole::Source,
                categories: vec![
                    PolicyCategoryId::new("io.user").unwrap(),
                    PolicyCategoryId::new("io.user").unwrap(),
                ],
                selector: PolicySelector::File {
                    authored_schema_version: Some(2),
                    path: WorkspaceRelativePath::new("queries/request.rql").unwrap(),
                },
                binding: PolicyEndpointBinding::ArgumentIndex { index: 0 },
                taint: Some(EndpointTaintSemantics::Source {
                    labels: vec![TaintLabel::new("user-input").unwrap()],
                    evidence: Some(TaintSourceEvidence {
                        trust_boundary: Some(TaintTrustBoundary::External),
                        system_entry: None,
                    }),
                }),
                supersedes: vec![],
            }),
        };

        assert_eq!(
            document.to_normalized_authored_json(),
            json!({
                "type": "endpoint",
                "schema_version": 1,
                "id": "bifrost.sources.request",
                "name": "Request value",
                "display_name": "user-controlled I/O",
                "help_uri": "https://example.invalid/source",
                "role": "source",
                "categories": ["io.user"],
                "selector": {
                    "type": "file",
                    "authored_schema_version": 2,
                    "path": "queries/request.rql",
                },
                "binding": { "type": "argument_index", "index": 0 },
                "taint": {
                    "type": "source",
                    "labels": ["user-input"],
                    "evidence": { "trust_boundary": "external" },
                },
                "supersedes": [],
            })
        );
        assert!(matches!(
            document.to_inline_local_canonical_semantic_json(),
            Err(InlineLocalSemanticProjectionError::FileSelector { path })
                if path == "queries/request.rql"
        ));
    }

    #[test]
    fn taint_projection_covers_generated_message_composition_and_data_bearing_ports() {
        let mut metadata = metadata();
        metadata.message = PolicyMessageSpec::Generated {
            relation: GeneratedRelation::CanReach,
        };
        metadata.severity = PolicySeveritySpec::Cvss {
            when_unscored: FindingSeverity::Warning,
        };
        let document = RqlpDocument::Policy {
            definition: Box::new(PolicyDefinition {
                schema_version: schema(1),
                metadata,
                analysis: PolicyAnalysis::Taint {
                    spec: TaintPolicySpec {
                        mode: MayMode::May,
                        sources: TaintEndpointSet {
                            include_sets: vec![],
                            include_matches: vec![MatchEndpointSetRef::Exact {
                                endpoint_ids: vec![
                                    EndpointId::new("bifrost.sources.request").unwrap(),
                                ],
                            }],
                            entries: vec![],
                        },
                        sinks: TaintEndpointSet::default(),
                        sanitizers: TaintEndpointSet::default(),
                        transforms: TaintEndpointSet::default(),
                        external_models: TaintEndpointSet::default(),
                        finding_combinations: vec![],
                    },
                },
                classification: None,
                report: PolicyReportOptions::default(),
            }),
        };

        let actual = document.to_normalized_authored_json();
        assert_eq!(
            actual.pointer("/message"),
            Some(&json!({ "type": "generated", "relation": "can_reach" }))
        );
        assert_eq!(
            actual.pointer("/analysis"),
            Some(&json!({
                "type": "taint",
                "mode": "may",
                "sources": {
                    "include_sets": [],
                    "include_matches": [{
                        "type": "exact",
                        "endpoint_ids": ["bifrost.sources.request"],
                    }],
                    "entries": [],
                },
                "sinks": { "include_sets": [], "include_matches": [], "entries": [] },
                "sanitizers": { "include_sets": [], "include_matches": [], "entries": [] },
                "transforms": { "include_sets": [], "include_matches": [], "entries": [] },
                "external_models": { "include_sets": [], "include_matches": [], "entries": [] },
                "finding_combinations": [],
            }))
        );
        assert_eq!(
            policy_port_to_json(&PolicyPort::ReturnValue),
            json!({ "type": "return_value" })
        );
        assert!(matches!(
            document.to_inline_local_canonical_semantic_json(),
            Err(InlineLocalSemanticProjectionError::ExactEndpointSet { endpoint_ids })
                if endpoint_ids == ["bifrost.sources.request"]
        ));

        let mut dangling = document.clone();
        let RqlpDocument::Policy { definition } = &mut dangling else {
            unreachable!()
        };
        let PolicyAnalysis::Taint { spec } = &mut definition.analysis else {
            unreachable!()
        };
        spec.sources.include_matches.clear();
        spec.finding_combinations.push(FindingCombinationSpec {
            id: FindingCombinationId::new("dangling").unwrap(),
            source: EndpointPredicate::Exact {
                endpoints: vec![EndpointRef::Local {
                    entry_id: TaintEntryId::new("missing-source").unwrap(),
                }],
            },
            sink: EndpointPredicate::Categories {
                predicate: CategoryPredicate::All {
                    categories: vec![PolicyCategoryId::new("sink").unwrap()],
                },
            },
            message: "Dangling".to_string(),
            severity: None,
            add_classifications: vec![],
            supersedes: vec![],
        });
        assert!(matches!(
            dangling.to_inline_local_canonical_semantic_json(),
            Err(InlineLocalSemanticProjectionError::DanglingLocalEndpointReference {
                entry_id
            }) if entry_id == "missing-source"
        ));
    }

    #[test]
    fn typestate_projection_normalizes_transitions_and_keeps_terminal_shapes() {
        let open = TypestateStateId::new("open").unwrap();
        let closed = TypestateStateId::new("closed").unwrap();
        let close = TypestateEventId::new("close").unwrap();
        let document = RqlpDocument::Policy {
            definition: Box::new(PolicyDefinition {
                schema_version: schema(1),
                metadata: metadata(),
                analysis: PolicyAnalysis::Typestate {
                    spec: TypestatePolicySpec {
                        mode: MayMode::May,
                        subjects: TypestateSubjectSet::default(),
                        uncertainty: TypestateUncertaintySpec {
                            unknown_call: InconclusivePolicy::Inconclusive,
                            escape: InconclusivePolicy::Inconclusive,
                        },
                        automaton: TypestateAutomatonSpec {
                            states: vec![closed.clone(), open.clone()],
                            initial: open.clone(),
                            accepting_states: vec![closed.clone()],
                            error_states: vec![],
                            events: vec![],
                            transitions: vec![
                                TypestateTransitionSpec {
                                    from: open.clone(),
                                    on: close.clone(),
                                    to: closed.clone(),
                                },
                                TypestateTransitionSpec {
                                    from: closed.clone(),
                                    on: close,
                                    to: closed.clone(),
                                },
                            ],
                            terminal_expectations: vec![TypestateTerminalExpectationSpec {
                                id: TypestateExpectationId::new("closed-at-exit").unwrap(),
                                trigger: TypestateTerminalTrigger::SemanticEvent {
                                    event: PolicySemanticEvent::NormalProcedureExit {
                                        scope: TypestateExitScope::AnalysisRoot,
                                    },
                                },
                                applies_to_subjects: None,
                                expected_states: vec![closed],
                                supersedes: vec![],
                            }],
                        },
                    },
                },
                classification: None,
                report: PolicyReportOptions::default(),
            }),
        };

        let actual = document.to_normalized_authored_json();
        assert_eq!(
            actual.pointer("/analysis"),
            Some(&json!({
                "type": "typestate",
                "mode": "may",
                "subjects": { "include_matches": [], "entries": [] },
                "uncertainty": {
                    "unknown_call": "inconclusive",
                    "escape": "inconclusive",
                },
                "automaton": {
                    "states": ["closed", "open"],
                    "initial": "open",
                    "accepting_states": ["closed"],
                    "error_states": [],
                    "events": [],
                    "transitions": [
                        { "from": "closed", "on": "close", "to": "closed" },
                        { "from": "open", "on": "close", "to": "closed" },
                    ],
                    "terminal_expectations": [{
                        "id": "closed-at-exit",
                        "trigger": {
                            "type": "semantic_event",
                            "event": {
                                "type": "normal_procedure_exit",
                                "scope": "analysis_root",
                            },
                        },
                        "expected_states": ["closed"],
                        "supersedes": [],
                    }],
                },
            }))
        );

        let mut dangling = document.clone();
        let RqlpDocument::Policy { definition } = &mut dangling else {
            unreachable!()
        };
        let PolicyAnalysis::Typestate { spec } = &mut definition.analysis else {
            unreachable!()
        };
        spec.automaton.terminal_expectations[0].applies_to_subjects =
            Some(EndpointPredicate::Exact {
                endpoints: vec![EndpointRef::Local {
                    entry_id: TaintEntryId::new("missing-subject").unwrap(),
                }],
            });
        assert!(matches!(
            dangling.to_inline_local_canonical_semantic_json(),
            Err(InlineLocalSemanticProjectionError::DanglingLocalEndpointReference {
                entry_id
            }) if entry_id == "missing-subject"
        ));
    }

    #[test]
    fn classification_and_cvss_projection_use_ordered_rules_and_first_labels() {
        let metric = CvssMetric::Base {
            metric: CvssBaseMetric::Av,
        };
        let value = CvssMetricValue::try_new(metric, CvssMetricValueToken::N).unwrap();
        let classification = PolicyClassificationSpec {
            fallback: TaxonomyClassificationSpec {
                taxonomy: "CWE".to_string(),
                identifier: "CWE-20".to_string(),
                name: None,
            },
            refinements: vec![ClassificationRefinementSpec {
                when: ClassificationPredicate::AnalysisType {
                    analysis_type: PolicyAnalysisType::Taint,
                },
                add: vec![TaxonomyClassificationSpec {
                    taxonomy: "CWE".to_string(),
                    identifier: "CWE-74".to_string(),
                    name: Some("Injection".to_string()),
                }],
            }],
            cvss: Some(CvssPolicySpec {
                version: CvssVersion::V4_0,
                emit: CvssEmitPolicy::WhenBaseComplete,
                metric_rules: vec![
                    CvssMetricRule::try_new(
                        CvssBaseMetric::Av,
                        value,
                        CvssEvidencePredicate::AnalysisType {
                            analysis_type: PolicyAnalysisType::Taint,
                        },
                        PolicyCvssBasis::PolicyAssertion,
                        CvssEvidenceScope::System {
                            system: CvssSystemScope::VulnerableSystem,
                        },
                        vec![PolicyEvidenceRef::PolicySelf],
                        "Network-reachable input".to_string(),
                        vec!["deployed".to_string()],
                    )
                    .unwrap(),
                ],
            }),
        };

        assert_eq!(
            classification_to_json(&classification),
            json!({
                "fallback": { "taxonomy": "CWE", "identifier": "CWE-20" },
                "refinements": [{
                    "when": { "type": "analysis_type", "analysis_type": "taint" },
                    "add": [{
                        "taxonomy": "CWE",
                        "identifier": "CWE-74",
                        "name": "Injection",
                    }],
                }],
                "cvss": {
                    "version": "4.0",
                    "emit": "when_base_complete",
                    "metric_rules": [{
                        "metric": "AV",
                        "value": "N",
                        "when": { "type": "analysis_type", "analysis_type": "taint" },
                        "basis": "policy_assertion",
                        "scope": { "type": "system", "system": "vulnerable_system" },
                        "evidence_refs": [{ "type": "policy_self" }],
                        "rationale": "Network-reachable input",
                        "assumptions": ["deployed"],
                    }],
                },
            })
        );
    }

    #[test]
    fn normalized_projection_excludes_version_origin_and_tags_unit_sum_variants() {
        let query = CodeQuery::from_sexp("(call)").unwrap();
        let inferred = PolicySelector::Inline {
            schema: schema(2),
            query: query.clone(),
        };
        let explicit = PolicySelector::Inline {
            schema: SchemaVersionResolution {
                version: 2,
                origin: SchemaVersionOrigin::Explicit,
            },
            query,
        };
        assert_eq!(selector_to_json(&inferred), selector_to_json(&explicit));
        assert_eq!(
            policy_severity_to_json(&PolicySeveritySpec::Unrated),
            json!({ "type": "unrated" })
        );
        assert_eq!(
            taint_transfer_effect_to_json(&TaintTransferEffect::Propagate),
            json!({ "type": "propagate" })
        );
        assert_eq!(
            cvss_evidence_scope_to_json(CvssEvidenceScope::Global),
            json!({ "type": "global" })
        );
    }

    #[test]
    fn semantic_guard_rejects_a_forged_dangling_selector_evidence_reference() {
        let value = CvssMetricValue::try_new(
            CvssMetric::Base {
                metric: CvssBaseMetric::Av,
            },
            CvssMetricValueToken::N,
        )
        .unwrap();
        let definition = PolicyDefinition {
            schema_version: schema(1),
            metadata: metadata(),
            analysis: PolicyAnalysis::Match {
                spec: MatchPolicySpec {
                    selector: inline_selector(),
                },
            },
            classification: Some(PolicyClassificationSpec {
                fallback: TaxonomyClassificationSpec {
                    taxonomy: "Bifrost".to_string(),
                    identifier: "example".to_string(),
                    name: None,
                },
                refinements: Vec::new(),
                cvss: Some(CvssPolicySpec {
                    version: CvssVersion::V4_0,
                    emit: CvssEmitPolicy::WhenBaseComplete,
                    metric_rules: vec![
                        CvssMetricRule::try_new(
                            CvssBaseMetric::Av,
                            value,
                            CvssEvidencePredicate::AnalysisType {
                                analysis_type: PolicyAnalysisType::Match,
                            },
                            PolicyCvssBasis::PolicyAssertion,
                            CvssEvidenceScope::System {
                                system: CvssSystemScope::VulnerableSystem,
                            },
                            vec![PolicyEvidenceRef::Selector {
                                path: PolicySelectorPath::new("/analysis/missing").unwrap(),
                            }],
                            "Network path".to_string(),
                            Vec::new(),
                        )
                        .unwrap(),
                    ],
                }),
            }),
            report: PolicyReportOptions::default(),
        };

        assert_eq!(
            ensure_inline_local_policy(&definition),
            Err(
                InlineLocalSemanticProjectionError::DanglingSelectorReference {
                    path: "/analysis/missing".to_string(),
                }
            )
        );
    }

    #[test]
    fn typed_sets_sort_by_stable_identity_before_json_field_order() {
        let values = [
            TaxonomyClassificationSpec {
                taxonomy: "z-taxonomy".to_string(),
                identifier: "a-id".to_string(),
                name: None,
            },
            TaxonomyClassificationSpec {
                taxonomy: "a-taxonomy".to_string(),
                identifier: "z-id".to_string(),
                name: None,
            },
            TaxonomyClassificationSpec {
                taxonomy: "a-taxonomy".to_string(),
                identifier: "z-id".to_string(),
                name: None,
            },
        ];
        assert_eq!(
            sorted_typed_values(
                values.iter(),
                compare_taxonomy_classifications,
                taxonomy_classification_to_json,
            ),
            json!([
                { "taxonomy": "a-taxonomy", "identifier": "z-id" },
                { "taxonomy": "z-taxonomy", "identifier": "a-id" },
            ])
        );
    }
}
