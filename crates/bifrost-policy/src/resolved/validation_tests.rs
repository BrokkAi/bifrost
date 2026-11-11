use std::fs;
use std::sync::Arc;

use super::*;
use crate::SchemaVersionOrigin;
use crate::catalog::{CatalogRegistryLimits, TaintCatalogDefinition, TaintCatalogRegistry};
use crate::registry::{PolicyRegistry, PolicyRegistryLimits};
use brokk_bifrost_rql::SCHEMA_VERSION as RQL_SCHEMA_VERSION;
use tempfile::TempDir;

fn loaded_typestate_policy() -> (LoadedPolicy, &'static str) {
    let root = TempDir::new().unwrap();
    fs::create_dir(root.path().join("endpoints")).unwrap();
    fs::write(
        root.path().join("endpoints/acquire.rqlp"),
        r#"(endpoint
      :id "test.acquire" :name "Acquire" :display-name "resource"
      :role source :categories [resource.acquire]
      :selector (rql (name "open_resource")) :binding return-value
      :supersedes [])"#,
    )
    .unwrap();
    fs::write(
        root.path().join("endpoints/close.rqlp"),
        r#"(endpoint
      :id "test.close" :name "Close" :display-name "close"
      :role sink :categories [resource.close]
      :selector (rql (name "close_resource")) :binding receiver
      :supersedes [])"#,
    )
    .unwrap();
    let source = r#"(policy
      :id "test.lifecycle" :name "Lifecycle"
      :message "resource is open" :severity error
      :analysis (analysis :type typestate :mode may
        :subjects (subject-set :include-matches [
          (match-directory :path "endpoints" :scope recursive
            :categories (all [resource.acquire]))])
        :uncertainty (uncertainty :escape inconclusive)
        :automaton (automaton
          :states [open closed violated] :initial open
          :accepting-states [closed] :error-states [violated]
          :events [(event :id close
            :matches (match-directory :path "endpoints" :scope recursive
              :role sink :phase after-normal-return
              :categories (all [resource.close])) :supersedes [])]
          :transitions [(transition :from open :on close :to closed)]
          :terminal-expectations [(terminal-expectation :id close-terminal
            :matches (match-directory :path "endpoints" :scope recursive
              :role sink :phase after-normal-return
              :categories (all [resource.close]))
            :expected-states [closed] :supersedes [])])))"#;
    fs::write(root.path().join("policy.rqlp"), source).unwrap();
    let catalogs = Arc::new(TaintCatalogRegistry::new_without_workspace(
        CatalogRegistryLimits::default(),
    ));
    let mut registry = PolicyRegistry::new_for_workspace(
        root.path().to_path_buf(),
        catalogs,
        PolicyRegistryLimits::default(),
    )
    .unwrap();
    (
        registry.load_policy_path("policy.rqlp").unwrap().clone(),
        source,
    )
}

fn loaded_endpoint_set_policy() -> (LoadedPolicy, &'static str) {
    let root = TempDir::new().unwrap();
    fs::write(
        root.path().join("shared.rqlp"),
        r#"(endpoint-set-document
      :schema-version 1 :kind sources :language java :rql-schema-version 1
      :set (endpoint-set :entries [
        (source :id shared :display-name "shared" :categories [input.user]
          :selector (rql :schema-version 1 (language java (call :callee (name "source"))))
          :bind return-value :labels [untrusted])]))"#,
    )
    .unwrap();
    let source = r#"(policy :schema-version 1 :id "test.import" :name "Import"
      :message "imported source" :severity warning
      :analysis (analysis :type taint :mode may
        :sources (endpoint-set :include-files [(endpoint-set-file :path "shared.rqlp")])
        :sinks (endpoint-set :entries [
          (sink :id output :display-name "output" :categories [data.sensitive]
            :selector (rql :schema-version 1 (language java (call :callee (name "sink"))))
            :dangerous-operand (argument :index 0) :accepts [untrusted])])))"#;
    fs::write(root.path().join("policy.rqlp"), source).unwrap();
    let catalogs = Arc::new(TaintCatalogRegistry::new_without_workspace(
        CatalogRegistryLimits::default(),
    ));
    let mut registry = PolicyRegistry::new_for_workspace(
        root.path().to_path_buf(),
        catalogs,
        PolicyRegistryLimits::default(),
    )
    .unwrap();
    (
        registry.load_policy_path("policy.rqlp").unwrap().clone(),
        source,
    )
}

fn loaded_catalog_policy(
    two: bool,
    evidence: Option<TaintSourceEvidence>,
) -> (LoadedPolicy, TaintCatalogHash, &'static str) {
    let selector = |name: &str| PolicySelector::Inline {
        schema: SchemaVersionResolution {
            version: RQL_SCHEMA_VERSION as u32,
            origin: SchemaVersionOrigin::Explicit,
        },
        query: CodeQuery::from_sexp(&format!("(name \"{name}\")")).unwrap(),
        resolved_locators: Vec::new(),
    };
    let mut catalogs =
        TaintCatalogRegistry::new_without_workspace(CatalogRegistryLimits::default());
    let definition = TaintCatalogDefinition {
        schema_version: POLICY_DOCUMENT_SCHEMA_VERSION,
        name: PolicyId::new("test.catalog").unwrap(),
        version: 2,
        categories: vec![PolicyCategoryId::new("input.user").unwrap()],
        sources: vec![TaintSourceSpec {
            id: TaintEntryId::new("request").unwrap(),
            display_name: "request".into(),
            categories: vec![PolicyCategoryId::new("input.user").unwrap()],
            selector: selector("request"),
            bind: PolicyPort::ReturnValue,
            labels: vec![TaintLabel::new("untrusted").unwrap()],
            threat_model: None,
            evidence,
        }],
        sinks: vec![TaintSinkSpec {
            id: TaintEntryId::new("store").unwrap(),
            display_name: "store".into(),
            categories: vec![PolicyCategoryId::new("input.user").unwrap()],
            selector: selector("store"),
            dangerous_operand: PolicyPort::MatchedValue,
            accepts: vec![TaintLabel::new("untrusted").unwrap()],
            tags: Vec::new(),
            impacts: Vec::new(),
        }],
        sanitizers: Vec::new(),
        transforms: Vec::new(),
        external_models: Vec::new(),
    };
    let hash = catalogs.register(definition.clone()).unwrap();
    if two {
        let mut second = definition;
        second.name = PolicyId::new("test.other").unwrap();
        catalogs.register(second).unwrap();
    }
    let mut policies =
        PolicyRegistry::new_without_workspace(Arc::new(catalogs), PolicyRegistryLimits::default());
    let source = if two {
        r#"(policy
      :id "test.catalog-policy" :name "Catalog policy"
      :message (generated-message :relation can-reach)
      :severity warning
      :analysis (analysis :type taint :mode may
        :sources (endpoint-set :include-sets [
          (catalog :name "test.catalog" :version 2)
          (catalog :name "test.other" :version 2)])
        :sinks (endpoint-set :include-sets [
          (catalog :name "test.catalog" :version 2)
          (catalog :name "test.other" :version 2)])))"#
    } else {
        r#"(policy
      :id "test.catalog-policy" :name "Catalog policy"
      :message (generated-message :relation can-reach)
      :severity warning
      :analysis (analysis :type taint :mode may
        :sources (endpoint-set :include-sets [(catalog :name "test.catalog" :version 2)])
        :sinks (endpoint-set :include-sets [(catalog :name "test.catalog" :version 2)])))"#
    };
    let loaded = policies
        .register_policy_bytes(
            PolicySourceIdentity::new("catalog-policy"),
            source.as_bytes(),
        )
        .unwrap();
    (loaded.clone(), hash, source)
}

#[test]
fn catalog_dependency_keeps_registered_version() {
    let (loaded, hash, _) = loaded_catalog_policy(false, None);
    assert_eq!(loaded.catalogs().len(), 1);
    assert_eq!(loaded.catalogs()[0].version, 2);
    assert_eq!(loaded.catalogs()[0].semantic_hash, hash);
    let constructed =
        ResolvedCatalogIdentity::try_new(PolicyId::new("test.catalog").unwrap(), 2, hash).unwrap();
    assert_eq!(constructed, loaded.catalogs()[0]);
}

fn revalidate(loaded: LoadedPolicy, source: &str) -> Result<LoadedPolicy, LoadedModelError> {
    LoadedPolicy::try_new(
        loaded.definition,
        loaded.source,
        source.as_bytes(),
        loaded.schema_resolution,
        loaded.resolved_selectors,
        loaded.catalogs,
        loaded.endpoint_dependencies,
        loaded.match_directory_manifests,
        loaded.endpoint_set_dependencies,
        loaded.precedence_manifest,
        loaded.resolved_taint,
        loaded.resolved_without_flow,
        loaded.resolved_typestate,
    )
}

#[test]
fn resolved_source_requires_provenance() {
    let (mut loaded, _, source) = loaded_catalog_policy(false, None);
    loaded.resolved_taint.as_mut().unwrap().sources[0]
        .origins
        .clear();
    assert!(matches!(
        revalidate(loaded, source),
        Err(LoadedModelError::InvalidResolvedModel { .. })
    ));
}

#[test]
fn duplicate_dependency_provenance_is_rejected() {
    let (mut loaded, _, source) = loaded_catalog_policy(false, None);
    let identity = loaded.resolved_taint.as_ref().unwrap().sources[0]
        .identity
        .clone();
    let dependency = loaded
        .endpoint_dependencies
        .iter_mut()
        .find(|dependency| dependency.identity == identity)
        .unwrap();
    let first = dependency.origins[0].clone();
    dependency.origins.push(first.clone());
    loaded.resolved_taint.as_mut().unwrap().sources[0]
        .origins
        .push(first);
    assert!(matches!(
        revalidate(loaded, source),
        Err(LoadedModelError::InvalidResolvedModel { .. })
    ));
}

#[test]
fn catalog_manifest_order_does_not_change_loading() {
    let (mut loaded, _, source) = loaded_catalog_policy(true, None);
    assert_eq!(loaded.catalogs.len(), 2);
    loaded.resolved_taint.as_mut().unwrap().catalogs.reverse();
    assert!(revalidate(loaded, source).is_ok());
}

#[test]
fn catalog_manifest_must_retain_every_catalog() {
    let (mut loaded, _, source) = loaded_catalog_policy(true, None);
    loaded.resolved_taint.as_mut().unwrap().catalogs.pop();
    assert!(matches!(
        revalidate(loaded, source),
        Err(LoadedModelError::InvalidResolvedModel { .. })
    ));
}

#[test]
fn source_categories_must_match_the_dependency() {
    let (mut loaded, _, source) = loaded_catalog_policy(false, None);
    loaded.resolved_taint.as_mut().unwrap().sources[0]
        .definition
        .categories[0] = PolicyCategoryId::new("input.other").unwrap();
    assert!(matches!(
        revalidate(loaded, source),
        Err(LoadedModelError::InvalidResolvedModel { .. })
    ));
}

#[test]
fn composed_endpoint_rejects_role_taint_mismatch() {
    let (loaded, _, _) = loaded_catalog_policy(false, None);
    let dependency = loaded
        .endpoint_dependencies
        .iter()
        .find(|dependency| {
            matches!(
                dependency.model.taint,
                Some(EndpointTaintSemantics::Source { .. })
            )
        })
        .unwrap();
    let selector = loaded
        .resolved_selectors
        .iter()
        .find(|selector| selector.path == dependency.selector_path)
        .unwrap();
    let mut model = dependency.model.clone();
    model.role = EndpointRole::Sink;
    assert!(matches!(
        ResolvedEndpointDependency::from_composed_model(
            dependency.identity.clone(),
            dependency.definition_schema.clone(),
            selector,
            model,
            dependency.origins.clone(),
        ),
        Err(LoadedModelError::InvalidResolvedModel { .. })
    ));
}

#[test]
fn source_evidence_accepts_either_fact() {
    let trust = TaintSourceEvidence {
        trust_boundary: Some(TaintTrustBoundary::External),
        system_entry: None,
    };
    let system = TaintSourceEvidence {
        trust_boundary: None,
        system_entry: Some(TaintSystemEntry::LocalInput),
    };
    assert!(
        loaded_catalog_policy(false, Some(trust))
            .0
            .resolved_taint
            .is_some()
    );
    assert!(
        loaded_catalog_policy(false, Some(system))
            .0
            .resolved_taint
            .is_some()
    );
}

#[test]
fn authored_catalog_pin_must_match_registered_hash() {
    let (mut loaded, hash, source) = loaded_catalog_policy(false, None);
    let PolicyAnalysis::Taint { spec } = &mut loaded.definition.analysis else {
        panic!("expected taint policy");
    };
    for reference in spec
        .sources
        .include_sets
        .iter_mut()
        .chain(spec.sinks.include_sets.iter_mut())
    {
        let CatalogRef::Named { sha256, .. } = reference else {
            panic!("expected named catalog");
        };
        *sha256 = Some(hash);
    }
    assert!(revalidate(loaded.clone(), source).is_ok());
    let PolicyAnalysis::Taint { spec } = &mut loaded.definition.analysis else {
        unreachable!()
    };
    let CatalogRef::Named { sha256, .. } = &mut spec.sources.include_sets[0] else {
        unreachable!()
    };
    *sha256 = Some(TaintCatalogHash::from_bytes([0; 32]));
    assert!(matches!(
        revalidate(loaded, source),
        Err(LoadedModelError::InvalidResolvedModel { .. })
    ));
}

fn loaded_local_store_policy() -> (LoadedPolicy, &'static str) {
    let source = r#"(policy
      :id "test.store-closure" :name "Store closure"
      :message "stored input" :severity warning
      :analysis (analysis :type taint :mode may
        :sources (endpoint-set :entries [
          (source :id raw :display-name "raw" :categories [input.user]
            :selector (rql (name "read")) :bind return-value
            :labels [untrusted])])
        :sinks (endpoint-set :entries [
          (sink :id output :display-name "output" :categories [data.sensitive]
            :selector (rql (name "put"))
            :dangerous-operand (argument :index 0) :accepts [untrusted])])
        :stores (endpoint-set :entries [
          (store-write :id cache-write :selector (rql (name "put"))
            :store primary :instance receiver :input (argument :index 0))
          (store-read :id cache-read :selector (rql (name "get"))
            :store primary :instance receiver :output return-value)])))"#;
    let catalogs = Arc::new(TaintCatalogRegistry::new_without_workspace(
        CatalogRegistryLimits::default(),
    ));
    let mut registry =
        PolicyRegistry::new_without_workspace(catalogs, PolicyRegistryLimits::default());
    let loaded = registry
        .register_policy_bytes(
            PolicySourceIdentity::new("store-closure.rqlp"),
            source.as_bytes(),
        )
        .unwrap();
    (loaded.clone(), source)
}

#[test]
fn first_source_and_store_read_selectors_remain_in_closure() {
    let (loaded, _) = loaded_local_store_policy();
    let paths = loaded
        .resolved_selectors()
        .iter()
        .map(|selector| selector.path.as_str())
        .collect::<Vec<_>>();
    assert!(
        paths
            .iter()
            .any(|path| path.ends_with("/sources/entries/raw/selector"))
    );
    assert!(
        paths
            .iter()
            .any(|path| path.ends_with("/stores/entries/cache-read/selector"))
    );
}

#[test]
fn missing_resolved_store_read_reports_model_closure() {
    let (mut loaded, source) = loaded_local_store_policy();
    loaded.resolved_taint.as_mut().unwrap().store_reads.clear();
    assert!(matches!(
        revalidate(loaded, source),
        Err(LoadedModelError::InvalidResolvedModel { .. })
    ));
}

#[test]
fn missing_source_dependency_reports_model_closure() {
    let (mut loaded, source) = loaded_local_store_policy();
    let source_identity = loaded.resolved_taint.as_ref().unwrap().sources[0]
        .identity
        .clone();
    loaded
        .endpoint_dependencies
        .retain(|dependency| dependency.identity != source_identity);
    assert!(matches!(
        revalidate(loaded, source),
        Err(LoadedModelError::InvalidResolvedModel { .. })
    ));
}

#[test]
fn endpoint_terminal_loads_with_resolved_dependency() {
    let (loaded, _) = loaded_typestate_policy();
    let spec = loaded.resolved_typestate.unwrap();
    let ResolvedTypestateTerminalTrigger::MatchEndpoints { endpoints, .. } =
        &spec.automaton.terminal_expectations[0].trigger
    else {
        panic!("expected endpoint terminal");
    };
    assert_eq!(endpoints.len(), 1);
    assert!(
        spec.endpoint_dependencies
            .iter()
            .any(|dependency| dependency.identity == endpoints[0])
    );
}

fn rehash_typestate(loaded: &mut LoadedPolicy) {
    let spec = loaded.resolved_typestate.as_mut().unwrap();
    spec.authoring_projection_hash = TypestateAuthoringProjectionHash::from_spec(spec).unwrap();
}

#[test]
fn endpoint_terminal_cannot_have_an_empty_match_set() {
    let (mut loaded, source) = loaded_typestate_policy();
    let trigger = &mut loaded
        .resolved_typestate
        .as_mut()
        .unwrap()
        .automaton
        .terminal_expectations[0]
        .trigger;
    let ResolvedTypestateTerminalTrigger::MatchEndpoints { endpoints, .. } = trigger else {
        panic!("expected endpoint terminal");
    };
    endpoints.clear();
    rehash_typestate(&mut loaded);
    assert!(matches!(
        revalidate(loaded, source),
        Err(LoadedModelError::InvalidResolvedModel { .. })
    ));
}

#[test]
fn terminal_variant_must_match_authored_trigger() {
    let (mut loaded, source) = loaded_typestate_policy();
    loaded
        .resolved_typestate
        .as_mut()
        .unwrap()
        .automaton
        .terminal_expectations[0]
        .trigger = ResolvedTypestateTerminalTrigger::SemanticEvent {
        event: PolicySemanticEvent::NormalProcedureExit {
            scope: TypestateExitScope::AnalysisRoot,
        },
    };
    rehash_typestate(&mut loaded);
    assert!(matches!(
        revalidate(loaded, source),
        Err(LoadedModelError::InvalidResolvedModel { .. })
    ));
}

#[test]
fn typestate_dependency_manifest_requires_exact_hashes() {
    let (mut loaded, source) = loaded_typestate_policy();
    assert!(
        loaded
            .resolved_typestate
            .as_ref()
            .unwrap()
            .endpoint_dependencies
            .len()
            >= 2
    );
    loaded
        .resolved_typestate
        .as_mut()
        .unwrap()
        .endpoint_dependencies[1]
        .semantic_hash = EndpointSemanticHash::from_bytes([7; 32]);
    rehash_typestate(&mut loaded);
    assert!(matches!(
        revalidate(loaded, source),
        Err(LoadedModelError::InvalidResolvedModel { .. })
    ));
}

#[test]
fn typestate_match_manifest_requires_every_hash() {
    let (mut loaded, source) = loaded_typestate_policy();
    let spec = loaded.resolved_typestate.as_mut().unwrap();
    assert!(spec.match_manifests.len() >= 2);
    let mut hashes = spec
        .match_manifests
        .iter()
        .map(|manifest| manifest.semantic_hash)
        .collect::<Vec<_>>();
    hashes.sort();
    hashes.dedup();
    assert!(
        hashes.len() >= 2,
        "fixture must have distinct manifest hashes"
    );
    let last = *hashes.last().unwrap();
    for manifest in &mut spec.match_manifests {
        if manifest.semantic_hash == last {
            manifest.semantic_hash = MatchSetManifestHash::from_bytes([255; 32]);
        }
    }
    rehash_typestate(&mut loaded);
    assert!(matches!(
        revalidate(loaded, source),
        Err(LoadedModelError::InvalidResolvedModel { .. })
    ));
}

#[test]
fn precedence_edge_cannot_leave_event_domain() {
    let (mut loaded, source) = loaded_typestate_policy();
    let unknown = TypestateEventId::new("missing-event").unwrap();
    let PolicyAnalysis::Typestate { spec } = &mut loaded.definition.analysis else {
        panic!("expected typestate policy");
    };
    spec.automaton.events[0].supersedes.push(unknown.clone());
    let event = &mut loaded.resolved_typestate.as_mut().unwrap().automaton.events[0];
    event.supersedes.push(unknown.clone());
    loaded
        .precedence_manifest
        .edges
        .push(ResolvedPrecedenceEdge::TypestateEvent {
            dominant: event.id.clone(),
            dominated: unknown,
        });
    rehash_typestate(&mut loaded);
    assert!(matches!(
        revalidate(loaded, source),
        Err(LoadedModelError::InvalidResolvedModel { .. })
    ));
}

#[test]
fn endpoint_set_origin_requires_manifest_membership() {
    let (mut loaded, source) = loaded_endpoint_set_policy();
    assert_eq!(loaded.endpoint_set_dependencies.len(), 1);
    assert!(!loaded.endpoint_set_dependencies[0].entries.is_empty());
    loaded.endpoint_set_dependencies[0].entries.clear();
    assert!(matches!(
        revalidate(loaded, source),
        Err(LoadedModelError::InvalidResolvedModel { .. })
    ));
}

#[test]
fn external_model_transfer_list_cannot_gain_or_lose_entries() {
    let source = r#"(policy :schema-version 1
      :id "test.transfer-closure" :name "Transfer closure"
      :message "flow" :severity warning
      :analysis (analysis :type taint :mode may
        :sources (endpoint-set :entries [
          (source :id input :display-name "input" :categories [input.user]
            :selector (rql :schema-version 1 (name "source"))
            :bind return-value :labels [untrusted])])
        :sinks (endpoint-set :entries [
          (sink :id output :display-name "output" :categories [data.sensitive]
            :selector (rql :schema-version 1 (name "sink"))
            :dangerous-operand (argument :index 0) :accepts [untrusted])])
        :external-models (endpoint-set :entries [
          (external-model :id bridge
            :selector (rql :schema-version 1 (name "bridge"))
            :transfers [
              (transfer :from (argument :index 0) :to return-value
                :labels [untrusted] :effect propagate)
              (transfer :from (argument :index 1) :to return-value
                :labels [untrusted] :effect propagate)])])))"#;
    let catalogs = Arc::new(TaintCatalogRegistry::new_without_workspace(
        CatalogRegistryLimits::default(),
    ));
    let mut registry =
        PolicyRegistry::new_without_workspace(catalogs, PolicyRegistryLimits::default());
    let loaded = registry
        .register_policy_bytes(
            PolicySourceIdentity::new("transfer-closure.rqlp"),
            source.as_bytes(),
        )
        .unwrap()
        .clone();
    let mut missing = loaded.clone();
    let transfers = &mut missing.resolved_taint.as_mut().unwrap().external_models[0]
        .definition
        .transfers;
    assert_eq!(transfers.len(), 2);
    transfers.pop();
    assert!(matches!(
        revalidate(missing, source),
        Err(LoadedModelError::InvalidResolvedModel { .. })
    ));
    let mut extra = loaded;
    extra.resolved_taint.as_mut().unwrap().external_models[0]
        .definition
        .transfers
        .push(TaintTransferSpec {
            from: PolicyPort::ArgumentIndex { index: 2 },
            to: PolicyPort::ReturnValue,
            labels: vec![TaintLabel::new("untrusted").unwrap()],
            effect: TaintTransferEffect::Propagate,
        });
    assert!(matches!(
        revalidate(extra, source),
        Err(LoadedModelError::InvalidResolvedModel { .. })
    ));
}

#[test]
fn inline_selector_cannot_disappear_from_loaded_policy() {
    let source = r#"(policy :id "test.selector" :name "Selector"
        :message "found" :severity warning
        :analysis (analysis :type match :selector (rql (name "x"))))"#;
    let identity = PolicySourceIdentity::new("selector.rqlp");
    let parsed = crate::source::parse_rqlp_source(source, identity.clone()).unwrap();
    let resolution = parsed.schema_resolution();
    let RqlpDocument::Policy { definition } = parsed.into_document() else {
        panic!("expected policy");
    };
    let error = LoadedPolicy::try_new(
        *definition,
        identity,
        source.as_bytes(),
        resolution,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        PolicyPrecedenceManifest::default(),
        None,
        None,
        None,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        LoadedModelError::MissingSelectorPath { .. }
    ));
}
