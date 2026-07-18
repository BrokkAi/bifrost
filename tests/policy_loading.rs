use std::fs;
use std::path::Path;
use std::sync::Arc;

use brokk_bifrost::analyzer::structural::CodeQuery;
use brokk_bifrost::policy::{
    CatalogRegistryLimits, PolicyCategoryId, PolicyId, PolicyPort, PolicyRegistry,
    PolicyRegistryError, PolicyRegistryLimits, PolicySelector, PolicySourceIdentity,
    ResolvedEndpointIdentity, SchemaVersionOrigin, SchemaVersionResolution, SelectorOrigin,
    TaintCatalogDefinition, TaintCatalogRegistry, TaintEntryId, TaintLabel, TaintSanitizerSpec,
    TaintSinkSpec, TaintSourceSpec,
};
use tempfile::TempDir;

fn catalogs() -> Arc<TaintCatalogRegistry> {
    Arc::new(TaintCatalogRegistry::new_without_workspace(
        CatalogRegistryLimits::default(),
    ))
}

fn registry_without_workspace() -> PolicyRegistry {
    PolicyRegistry::new_without_workspace(catalogs(), PolicyRegistryLimits::default())
}

fn registry_for(root: &Path) -> PolicyRegistry {
    PolicyRegistry::new_for_workspace(
        root.to_path_buf(),
        catalogs(),
        PolicyRegistryLimits::default(),
    )
    .unwrap()
}

fn endpoint(
    id: &str,
    role: &str,
    display_name: &str,
    categories: &[&str],
    query_name: &str,
    taint: &str,
) -> String {
    format!(
        r#"(endpoint
          :id "{id}"
          :name "{display_name}"
          :display-name "{display_name}"
          :role {role}
          :categories [{}]
          :selector (rql (call :callee (name "{query_name}")))
          :binding return-value
          {taint}
          :supersedes [])"#,
        categories.join(" ")
    )
}

fn source_endpoint(id: &str, display_name: &str, category: &str, query_name: &str) -> String {
    endpoint(
        id,
        "source",
        display_name,
        &[category],
        query_name,
        ":taint (source-semantics :labels [untrusted])",
    )
}

fn sink_endpoint(id: &str, display_name: &str, category: &str, query_name: &str) -> String {
    endpoint(
        id,
        "sink",
        display_name,
        &[category],
        query_name,
        ":taint (sink-semantics :accepts [untrusted])",
    )
}

fn directory_policy(directory: &str) -> String {
    format!(
        r#"(policy
          :id "test.directory-policy"
          :name "Directory policy"
          :message (generated-message :relation can-reach)
          :severity warning
          :analysis (analysis
            :type taint
            :mode may
            :sources (endpoint-set :include-matches [
              (match-directory :path "{directory}" :scope recursive
                :categories (all [selected.source]))])
            :sinks (endpoint-set :include-matches [
              (match-directory :path "{directory}" :scope recursive
                :categories (all [selected.sink]))])))"#
    )
}

#[test]
fn context_free_registry_loads_inline_documents_and_rejects_workspace_references() {
    let mut registry = registry_without_workspace();
    let endpoint = source_endpoint("test.endpoint", "embedded source", "input.user", "input");
    let loaded_endpoint = registry
        .register_endpoint_bytes(
            PolicySourceIdentity::new("embedded:endpoint"),
            endpoint.as_bytes(),
        )
        .unwrap();
    assert_eq!(loaded_endpoint.definition().id.as_str(), "test.endpoint");

    let policy = r#"(policy
      :id "test.inline"
      :name "Inline"
      :message "Inline match"
      :severity warning
      :analysis (analysis :type match :selector (rql (name "target"))))"#;
    let loaded = registry
        .register_policy_bytes(
            PolicySourceIdentity::new("embedded:policy"),
            policy.as_bytes(),
        )
        .unwrap();
    assert_eq!(loaded.resolved_selectors().len(), 1);
    assert_eq!(
        loaded.schema_resolution().origin,
        SchemaVersionOrigin::ImplicitCompatible
    );

    let referenced = r#"(policy
      :id "test.file"
      :name "File"
      :message "File match"
      :severity warning
      :analysis (analysis :type match :selector (rql-file :path "queries/a.rql")))"#;
    let error = registry
        .register_policy_bytes(
            PolicySourceIdentity::new("embedded:file-policy"),
            referenced.as_bytes(),
        )
        .unwrap_err();
    assert!(
        error.to_string().contains("requires a workspace root"),
        "{error}"
    );
}

#[test]
fn embedding_source_labels_are_bounded_and_duplicate_ids_are_transactional() {
    let mut registry = registry_without_workspace();
    let policy = r#"(policy :id "test.duplicate" :name "Duplicate" :message "M"
      :severity warning :analysis (analysis :type match :selector (rql (call))))"#;
    let error = registry
        .register_policy_bytes(PolicySourceIdentity::new(""), policy.as_bytes())
        .unwrap_err();
    assert!(matches!(
        error,
        PolicyRegistryError::InvalidSourceIdentity(_)
    ));

    registry
        .register_policy_bytes(PolicySourceIdentity::new("first"), policy.as_bytes())
        .unwrap();
    let error = registry
        .register_policy_bytes(PolicySourceIdentity::new("second"), policy.as_bytes())
        .unwrap_err();
    assert!(matches!(
        error,
        PolicyRegistryError::DuplicatePolicyId { .. }
    ));
    assert_eq!(registry.policies().len(), 1);
}

#[test]
fn public_path_and_byte_boundaries_reject_invalid_documents_transactionally() {
    let temp = TempDir::new().unwrap();
    let policy = r#"(policy :id "test.path" :name "Path" :message "M"
      :severity warning :analysis (analysis :type match :selector (rql (call))))"#;
    fs::write(temp.path().join("wrong.txt"), policy).unwrap();
    fs::create_dir(temp.path().join("directory.rqlp")).unwrap();
    fs::write(temp.path().join("invalid.rqlp"), [0xff, 0xfe]).unwrap();
    let mut registry = registry_for(temp.path());

    for path in [
        "wrong.txt",
        "../escape.rqlp",
        "directory.rqlp",
        "invalid.rqlp",
    ] {
        assert!(registry.load_policy_path(path).is_err(), "accepted {path}");
        assert_eq!(registry.policies().len(), 0);
    }
    assert!(
        registry
            .load_policy_path(temp.path().join("wrong.txt"))
            .is_err()
    );
    assert_eq!(registry.policies().len(), 0);

    let error = registry
        .register_policy_bytes(PolicySourceIdentity::new("invalid:utf8"), &[0xff])
        .unwrap_err();
    assert!(matches!(error, PolicyRegistryError::InvalidUtf8 { .. }));
    let oversized = vec![b' '; 256 * 1024 + 1];
    let error = registry
        .register_policy_bytes(PolicySourceIdentity::new("oversized"), &oversized)
        .unwrap_err();
    assert!(matches!(error, PolicyRegistryError::SourceTooLarge { .. }));
    assert_eq!(registry.policies().len(), 0);
}

#[test]
fn explicit_and_compatible_omitted_versions_share_semantics_not_source_identity() {
    let omitted = r#"(policy
      :id "test.versioned"
      :name "Versioned"
      :message "M"
      :severity warning
      :analysis (analysis :type match :selector (rql (name "target"))))"#;
    let explicit = r#"(policy
      :schema-version 1
      :id "test.versioned"
      :name "Versioned"
      :message "M"
      :severity warning
      :analysis (analysis :type match
        :selector (rql :schema-version 2 (name "target"))))"#;
    let mut omitted_registry = registry_without_workspace();
    let omitted = omitted_registry
        .register_policy_bytes(PolicySourceIdentity::new("omitted"), omitted.as_bytes())
        .unwrap();
    let mut explicit_registry = registry_without_workspace();
    let explicit = explicit_registry
        .register_policy_bytes(PolicySourceIdentity::new("explicit"), explicit.as_bytes())
        .unwrap();
    assert_eq!(omitted.semantic_hash(), explicit.semantic_hash());
    assert_ne!(omitted.source_hash(), explicit.source_hash());
    assert_eq!(
        omitted.schema_resolution().origin,
        SchemaVersionOrigin::ImplicitCompatible
    );
    assert_eq!(
        explicit.schema_resolution().origin,
        SchemaVersionOrigin::Explicit
    );
}

#[test]
fn endpoint_and_registry_limits_fail_before_partial_insertion() {
    let limits = PolicyRegistryLimits::default()
        .with_max_endpoints(1)
        .unwrap();
    let mut registry = PolicyRegistry::new_without_workspace(catalogs(), limits);
    let first = source_endpoint("test.first", "first", "input.one", "one");
    let second = source_endpoint("test.second", "second", "input.two", "two");
    registry
        .register_endpoint_bytes(PolicySourceIdentity::new("first"), first.as_bytes())
        .unwrap();
    let error = registry
        .register_endpoint_bytes(PolicySourceIdentity::new("second"), second.as_bytes())
        .unwrap_err();
    assert!(matches!(
        error,
        PolicyRegistryError::EndpointLimitExceeded { .. }
    ));
    assert_eq!(registry.endpoints().len(), 1);
}

#[test]
fn auxiliary_models_consume_endpoint_slots_transactionally() {
    let limits = PolicyRegistryLimits::default()
        .with_max_endpoints(2)
        .unwrap();
    let mut registry = PolicyRegistry::new_without_workspace(catalogs(), limits);
    let policy = r#"(policy
      :id "test.auxiliary-slots"
      :name "Auxiliary slots"
      :message (generated-message :relation can-reach)
      :severity warning
      :analysis (analysis
        :type taint :mode may
        :sources (endpoint-set :entries [
          (source :id request :display-name "request" :categories [input.user]
            :selector (rql (name "request")) :bind return-value
            :labels [untrusted])])
        :sinks (endpoint-set :entries [
          (sink :id store :display-name "store" :categories [data.sensitive]
            :selector (rql (name "store")) :dangerous-operand matched-value
            :accepts [untrusted])])
        :sanitizers (endpoint-set :entries [
          (sanitizer :id clean :selector (rql (name "clean"))
            :input (argument :index 0) :output return-value
            :removes [untrusted])])))"#;
    let error = registry
        .register_policy_bytes(
            PolicySourceIdentity::new("auxiliary-slots"),
            policy.as_bytes(),
        )
        .unwrap_err();
    assert!(matches!(
        error,
        PolicyRegistryError::EndpointLimitExceeded {
            attempted: 3,
            maximum: 2
        }
    ));
    assert_eq!(registry.policies().len(), 0);

    for id in ["test.after-first", "test.after-second"] {
        let endpoint = source_endpoint(id, id, "input.after", id);
        registry
            .register_endpoint_bytes(PolicySourceIdentity::new(id), endpoint.as_bytes())
            .unwrap();
    }
    assert_eq!(registry.endpoints().len(), 2);
}

#[test]
fn catalog_expansion_consumes_retained_bytes_transactionally() {
    let selector = |name: &str| PolicySelector::Inline {
        schema: SchemaVersionResolution {
            version: 2,
            origin: SchemaVersionOrigin::Explicit,
        },
        query: CodeQuery::from_sexp(&format!("(name \"{name}\")")).unwrap(),
    };
    let mut catalog_registry =
        TaintCatalogRegistry::new_without_workspace(CatalogRegistryLimits::default());
    catalog_registry
        .register(TaintCatalogDefinition {
            schema_version: 1,
            name: PolicyId::new("test.retained-catalog").unwrap(),
            version: 1,
            sources: vec![TaintSourceSpec {
                id: TaintEntryId::new("request").unwrap(),
                display_name: "request".to_string(),
                categories: vec![PolicyCategoryId::new("input.user").unwrap()],
                selector: selector("request"),
                bind: PolicyPort::ReturnValue,
                labels: vec![TaintLabel::new("untrusted").unwrap()],
                evidence: None,
            }],
            sinks: vec![TaintSinkSpec {
                id: TaintEntryId::new("store").unwrap(),
                display_name: "store".to_string(),
                categories: vec![PolicyCategoryId::new("data.sensitive").unwrap()],
                selector: selector("store"),
                dangerous_operand: PolicyPort::MatchedValue,
                accepts: vec![TaintLabel::new("untrusted").unwrap()],
                tags: Vec::new(),
                impacts: Vec::new(),
            }],
            sanitizers: vec![TaintSanitizerSpec {
                id: TaintEntryId::new("clean").unwrap(),
                selector: selector("clean"),
                input: PolicyPort::ArgumentIndex { index: 0 },
                output: PolicyPort::ReturnValue,
                removes: vec![TaintLabel::new("untrusted").unwrap()],
            }],
            transforms: Vec::new(),
            external_models: Vec::new(),
        })
        .unwrap();
    let policy = |id: &str| {
        format!(
            r#"(policy
              :id "{id}"
              :name "Catalog retention"
              :message (generated-message :relation can-reach)
              :severity warning
              :analysis (analysis
                :type taint :mode may
                :sources (endpoint-set :include-sets [
                  (catalog :name "test.retained-catalog" :version 1)])
                :sinks (endpoint-set :include-sets [
                  (catalog :name "test.retained-catalog" :version 1)])
                :sanitizers (endpoint-set :include-sets [
                  (catalog :name "test.retained-catalog" :version 1)])))"#
        )
    };
    let first = policy("test.catalog-retention-a");
    let second = policy("test.catalog-retention-b");
    let catalog_bytes = catalog_registry
        .iter()
        .next()
        .unwrap()
        .canonical_json()
        .len();
    let limits = PolicyRegistryLimits::default()
        .with_max_retained_source_and_selector_bytes(first.len() + catalog_bytes + second.len())
        .unwrap();
    let mut registry = PolicyRegistry::new_without_workspace(Arc::new(catalog_registry), limits);
    registry
        .register_policy_bytes(
            PolicySourceIdentity::new("catalog-retention-a"),
            first.as_bytes(),
        )
        .unwrap();
    let error = registry
        .register_policy_bytes(
            PolicySourceIdentity::new("catalog-retention-b"),
            second.as_bytes(),
        )
        .unwrap_err();
    assert!(matches!(
        error,
        PolicyRegistryError::RetainedByteLimitExceeded { .. }
    ));
    assert_eq!(registry.policies().len(), 1);

    let smaller = r#"(policy :id "test.after-retention" :name "After" :message "M"
      :severity warning :analysis (analysis :type match :selector (rql (name "x"))))"#;
    registry
        .register_policy_bytes(
            PolicySourceIdentity::new("after-retention"),
            smaller.as_bytes(),
        )
        .unwrap();
    assert_eq!(registry.policies().len(), 2);
}

#[test]
fn exact_endpoints_use_only_the_pre_registered_index_and_remain_one_set() {
    let mut registry = registry_without_workspace();
    let source = source_endpoint("test.source", "request input", "input.user", "request");
    let sink = sink_endpoint("test.sink", "sensitive output", "data.pii", "store");
    registry
        .register_endpoint_bytes(PolicySourceIdentity::new("source"), source.as_bytes())
        .unwrap();
    registry
        .register_endpoint_bytes(PolicySourceIdentity::new("sink"), sink.as_bytes())
        .unwrap();
    let policy = r#"(policy
      :id "test.exact"
      :name "Exact"
      :message (generated-message :relation can-reach)
      :severity warning
      :analysis (analysis
        :type taint
        :mode may
        :sources (endpoint-set :include-matches [
          (match-endpoints :ids [test.source])])
        :sinks (endpoint-set :include-matches [
          (match-endpoints :ids [test.sink])])))"#;
    let loaded = registry
        .register_policy_bytes(PolicySourceIdentity::new("exact"), policy.as_bytes())
        .unwrap();
    let spec = loaded.resolved_taint().unwrap();
    assert_eq!(spec.sources.len(), 1);
    assert_eq!(spec.sinks.len(), 1);
    assert_eq!(loaded.endpoint_dependencies().len(), 2);
    assert_eq!(registry.endpoints().len(), 2);
    assert_eq!(registry.policies().len(), 1);
}

#[test]
fn directory_selection_hashes_only_selected_endpoint_meaning() {
    let temp = TempDir::new().unwrap();
    fs::create_dir(temp.path().join("endpoints")).unwrap();
    fs::write(
        temp.path().join("endpoints/source.rqlp"),
        source_endpoint("test.source", "selected input", "selected.source", "input"),
    )
    .unwrap();
    fs::write(
        temp.path().join("endpoints/sink.rqlp"),
        sink_endpoint("test.sink", "selected sink", "selected.sink", "sink"),
    )
    .unwrap();
    fs::write(
        temp.path().join("endpoints/unselected.rqlp"),
        source_endpoint("test.unselected", "other", "other.source", "other"),
    )
    .unwrap();
    fs::write(
        temp.path().join("policy.rqlp"),
        directory_policy("endpoints"),
    )
    .unwrap();

    let mut first = registry_for(temp.path());
    let first_policy = first.load_policy_path("policy.rqlp").unwrap();
    let first_hash = first_policy.semantic_hash();
    assert_eq!(first_policy.endpoint_dependencies().len(), 2);
    assert_eq!(first_policy.match_directory_manifests().len(), 2);

    fs::write(
        temp.path().join("endpoints/unselected.rqlp"),
        source_endpoint(
            "test.unselected",
            "changed but still other",
            "other.source",
            "changed_other",
        ),
    )
    .unwrap();
    let mut second = registry_for(temp.path());
    let second_hash = second
        .load_policy_path("policy.rqlp")
        .unwrap()
        .semantic_hash();
    assert_eq!(first_hash, second_hash);

    fs::write(
        temp.path().join("endpoints/source.rqlp"),
        source_endpoint(
            "test.source",
            "changed selected input",
            "selected.source",
            "input",
        ),
    )
    .unwrap();
    let mut third = registry_for(temp.path());
    let third_policy = third.load_policy_path("policy.rqlp").unwrap();
    assert_ne!(first_hash, third_policy.semantic_hash());
    assert_eq!(
        first_policy.endpoint_dependencies()[0].analysis_projection_hash(),
        third_policy.endpoint_dependencies()[0].analysis_projection_hash(),
        "display-only edits must not change endpoint analysis identity"
    );
}

#[test]
fn directory_manifest_pins_and_candidate_limits_are_transactional() {
    let temp = TempDir::new().unwrap();
    fs::create_dir(temp.path().join("endpoints")).unwrap();
    fs::write(
        temp.path().join("endpoints/source.rqlp"),
        source_endpoint("test.source", "input", "selected.source", "input"),
    )
    .unwrap();
    fs::write(
        temp.path().join("endpoints/sink.rqlp"),
        sink_endpoint("test.sink", "sink", "selected.sink", "sink"),
    )
    .unwrap();
    let wrong_pin = "0".repeat(64);
    let pinned = directory_policy("endpoints").replace(
        ":scope recursive\n                :categories",
        &format!(
            ":scope recursive\n                :manifest-sha256 \"{wrong_pin}\"\n                :categories"
        ),
    );
    fs::write(temp.path().join("policy.rqlp"), pinned).unwrap();

    let mut registry = registry_for(temp.path());
    let error = registry.load_policy_path("policy.rqlp").unwrap_err();
    assert!(matches!(
        error,
        PolicyRegistryError::MatchDirectoryManifestMismatch { .. }
    ));
    assert_eq!(registry.policies().len(), 0);

    fs::write(
        temp.path().join("policy.rqlp"),
        directory_policy("endpoints"),
    )
    .unwrap();
    let limits = PolicyRegistryLimits::default()
        .with_max_match_directory_candidates(1)
        .unwrap();
    let mut limited =
        PolicyRegistry::new_for_workspace(temp.path().to_path_buf(), catalogs(), limits).unwrap();
    assert!(limited.load_policy_path("policy.rqlp").is_err());
    assert_eq!(limited.policies().len(), 0);
}

#[test]
fn three_sources_and_four_sinks_remain_one_setwise_policy() {
    let sources = (1..=3)
        .map(|index| {
            format!(
                r#"(source :id "s{index}" :display-name "source {index}"
                  :categories [input.user]
                  :selector (rql (name "source{index}"))
                  :bind return-value :labels [untrusted])"#
            )
        })
        .collect::<Vec<_>>()
        .join(" ");
    let sinks = (1..=4)
        .map(|index| {
            format!(
                r#"(sink :id "k{index}" :display-name "sink {index}"
                  :categories [output.sensitive]
                  :selector (rql (name "sink{index}"))
                  :dangerous-operand matched-value :accepts [untrusted])"#
            )
        })
        .collect::<Vec<_>>()
        .join(" ");
    let policy = format!(
        r#"(policy
          :id "test.setwise"
          :name "Setwise"
          :message (generated-message :relation can-reach)
          :severity warning
          :analysis (analysis
            :type taint :mode may
            :sources (endpoint-set :entries [{sources}])
            :sinks (endpoint-set :entries [{sinks}])))"#
    );
    let mut registry = registry_without_workspace();
    let loaded = registry
        .register_policy_bytes(PolicySourceIdentity::new("setwise"), policy.as_bytes())
        .unwrap();
    let spec = loaded.resolved_taint().unwrap();
    assert_eq!(spec.sources.len(), 3);
    assert_eq!(spec.sinks.len(), 4);
    assert_eq!(loaded.endpoint_dependencies().len(), 7);
}

#[test]
fn referenced_rql_retains_both_pin_provenance_and_effective_origin() {
    let temp = TempDir::new().unwrap();
    fs::create_dir(temp.path().join("queries")).unwrap();
    fs::write(
        temp.path().join("queries/explicit.rql"),
        "(rql :schema-version 2 (name \"target\"))",
    )
    .unwrap();
    let policy = r#"(policy
      :id "test.referenced"
      :name "Referenced"
      :message "Referenced"
      :severity warning
      :analysis (analysis :type match
        :selector (rql-file :schema-version 2 :path "queries/explicit.rql")))"#;
    let mut registry = registry_for(temp.path());
    let loaded = registry
        .register_policy_bytes(
            PolicySourceIdentity::new("embedded:referenced"),
            policy.as_bytes(),
        )
        .unwrap();
    let selector = &loaded.resolved_selectors()[0];
    assert_eq!(
        selector.schema_resolution.origin,
        SchemaVersionOrigin::ReferencedDocumentExplicit
    );
    let SelectorOrigin::ReferencedFile {
        wrapper_authored_schema_version,
        document_authored_schema_version,
        ..
    } = &selector.origin
    else {
        panic!("expected referenced selector provenance")
    };
    assert_eq!(*wrapper_authored_schema_version, Some(2));
    assert_eq!(*document_authored_schema_version, Some(2));
}

#[test]
fn typestate_reuses_directory_endpoints_without_creating_endpoint_runs() {
    let temp = TempDir::new().unwrap();
    fs::create_dir(temp.path().join("endpoints")).unwrap();
    fs::write(
        temp.path().join("endpoints/acquire.rqlp"),
        r#"(endpoint
          :id "test.resource-acquire"
          :name "Acquire"
          :display-name "resource"
          :role source
          :categories [resource.acquire]
          :selector (rql (name "open_resource"))
          :binding return-value
          :supersedes [])"#,
    )
    .unwrap();
    fs::write(
        temp.path().join("endpoints/close.rqlp"),
        r#"(endpoint
          :id "test.resource-close"
          :name "Close"
          :display-name "close"
          :role sink
          :categories [resource.close]
          :selector (rql (name "close_resource"))
          :binding receiver
          :supersedes [])"#,
    )
    .unwrap();
    fs::write(
        temp.path().join("policy.rqlp"),
        r#"(policy
          :id "test.resource-lifecycle"
          :name "Resource lifecycle"
          :message "Resource is not closed"
          :severity error
          :analysis (analysis
            :type typestate
            :mode may
            :subjects (subject-set :include-matches [
              (match-directory :path "endpoints" :scope recursive
                :categories (all [resource.acquire]))])
            :uncertainty (uncertainty
              :unknown-call inconclusive :escape inconclusive)
            :automaton (automaton
              :states [open closed violated]
              :initial open
              :accepting-states [closed]
              :error-states [violated]
              :events [
                (event :id close
                  :matches (match-directory :path "endpoints" :scope recursive
                    :role sink :phase after-normal-return
                    :categories (all [resource.close]))
                  :supersedes [])]
              :transitions [(transition :from open :on close :to closed)]
              :terminal-expectations [
                (terminal-expectation :id normal-exit
                  :on (normal-procedure-exit :scope analysis-root)
                  :expected-states [closed] :supersedes [])])))"#,
    )
    .unwrap();

    let mut registry = registry_for(temp.path());
    let loaded = registry.load_policy_path("policy.rqlp").unwrap();
    let spec = loaded.resolved_typestate().unwrap();
    assert_eq!(spec.subjects.len(), 1);
    assert_eq!(spec.endpoint_dependencies.len(), 2);
    assert_eq!(loaded.endpoint_dependencies().len(), 2);
    assert_eq!(registry.endpoints().len(), 0);
    assert_eq!(registry.policies().len(), 1);
}

#[test]
fn policy_iterators_are_stably_sorted() {
    let mut registry = registry_without_workspace();
    for id in ["test.z", "test.a", "test.m"] {
        let source = format!(
            r#"(policy :id "{id}" :name "{id}" :message "M" :severity warning
              :analysis (analysis :type match :selector (rql (name "x"))))"#
        );
        registry
            .register_policy_bytes(PolicySourceIdentity::new(id), source.as_bytes())
            .unwrap();
    }
    let ids = registry
        .policies()
        .map(|policy| policy.definition().metadata.id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(ids, ["test.a", "test.m", "test.z"]);
}

#[test]
fn registered_catalog_sources_and_sinks_become_closed_policy_dependencies() {
    let selector = |name: &str| PolicySelector::Inline {
        schema: SchemaVersionResolution {
            version: 2,
            origin: SchemaVersionOrigin::Explicit,
        },
        query: CodeQuery::from_sexp(&format!("(name \"{name}\")")).unwrap(),
    };
    let mut catalog_registry =
        TaintCatalogRegistry::new_without_workspace(CatalogRegistryLimits::default());
    catalog_registry
        .register(TaintCatalogDefinition {
            schema_version: 1,
            name: PolicyId::new("test.catalog").unwrap(),
            version: 1,
            sources: vec![TaintSourceSpec {
                id: TaintEntryId::new("request").unwrap(),
                display_name: "request input".to_string(),
                categories: vec![PolicyCategoryId::new("input.user").unwrap()],
                selector: selector("request"),
                bind: PolicyPort::ReturnValue,
                labels: vec![TaintLabel::new("untrusted").unwrap()],
                evidence: None,
            }],
            sinks: vec![TaintSinkSpec {
                id: TaintEntryId::new("store").unwrap(),
                display_name: "sensitive store".to_string(),
                categories: vec![PolicyCategoryId::new("data.sensitive").unwrap()],
                selector: selector("store"),
                dangerous_operand: PolicyPort::MatchedValue,
                accepts: vec![TaintLabel::new("untrusted").unwrap()],
                tags: Vec::new(),
                impacts: Vec::new(),
            }],
            sanitizers: Vec::new(),
            transforms: Vec::new(),
            external_models: Vec::new(),
        })
        .unwrap();
    let mut registry = PolicyRegistry::new_without_workspace(
        Arc::new(catalog_registry),
        PolicyRegistryLimits::default(),
    );
    let policy = r#"(policy
      :id "test.catalog-policy"
      :name "Catalog policy"
      :message (generated-message :relation can-reach)
      :severity warning
      :analysis (analysis
        :type taint :mode may
        :sources (endpoint-set :include-sets [
          (catalog :name "test.catalog" :version 1)])
        :sinks (endpoint-set :include-sets [
          (catalog :name "test.catalog" :version 1)])))"#;
    let loaded = registry
        .register_policy_bytes(
            PolicySourceIdentity::new("catalog-policy"),
            policy.as_bytes(),
        )
        .unwrap();
    assert_eq!(loaded.catalogs().len(), 1);
    assert_eq!(loaded.endpoint_dependencies().len(), 2);
    assert!(loaded.resolved_selectors().iter().all(|selector| {
        selector
            .path
            .as_str()
            .starts_with("/dependencies/catalogs/")
    }));
}

#[test]
fn same_named_catalog_auxiliaries_retain_qualified_identity_and_selector_paths() {
    let selector = |name: &str| PolicySelector::Inline {
        schema: SchemaVersionResolution {
            version: 2,
            origin: SchemaVersionOrigin::Explicit,
        },
        query: CodeQuery::from_sexp(&format!("(name \"{name}\")")).unwrap(),
    };
    let sanitizer = |name: &str| TaintSanitizerSpec {
        id: TaintEntryId::new("clean").unwrap(),
        selector: selector(name),
        input: PolicyPort::ArgumentIndex { index: 0 },
        output: PolicyPort::ReturnValue,
        removes: vec![TaintLabel::new("untrusted").unwrap()],
    };
    let mut catalog_registry =
        TaintCatalogRegistry::new_without_workspace(CatalogRegistryLimits::default());
    catalog_registry
        .register(TaintCatalogDefinition {
            schema_version: 1,
            name: PolicyId::new("test.catalog-a").unwrap(),
            version: 1,
            sources: vec![TaintSourceSpec {
                id: TaintEntryId::new("request").unwrap(),
                display_name: "request input".to_string(),
                categories: vec![PolicyCategoryId::new("input.user").unwrap()],
                selector: selector("request"),
                bind: PolicyPort::ReturnValue,
                labels: vec![TaintLabel::new("untrusted").unwrap()],
                evidence: None,
            }],
            sinks: Vec::new(),
            sanitizers: vec![sanitizer("clean-a")],
            transforms: Vec::new(),
            external_models: Vec::new(),
        })
        .unwrap();
    catalog_registry
        .register(TaintCatalogDefinition {
            schema_version: 1,
            name: PolicyId::new("test.catalog-b").unwrap(),
            version: 1,
            sources: Vec::new(),
            sinks: vec![TaintSinkSpec {
                id: TaintEntryId::new("store").unwrap(),
                display_name: "sensitive store".to_string(),
                categories: vec![PolicyCategoryId::new("data.sensitive").unwrap()],
                selector: selector("store"),
                dangerous_operand: PolicyPort::MatchedValue,
                accepts: vec![TaintLabel::new("untrusted").unwrap()],
                tags: Vec::new(),
                impacts: Vec::new(),
            }],
            sanitizers: vec![sanitizer("clean-b")],
            transforms: Vec::new(),
            external_models: Vec::new(),
        })
        .unwrap();
    let mut registry = PolicyRegistry::new_without_workspace(
        Arc::new(catalog_registry),
        PolicyRegistryLimits::default(),
    );
    let policy = r#"(policy
      :id "test.catalog-auxiliaries"
      :name "Catalog auxiliaries"
      :message (generated-message :relation can-reach)
      :severity warning
      :analysis (analysis
        :type taint :mode may
        :sources (endpoint-set :include-sets [
          (catalog :name "test.catalog-a" :version 1)])
        :sinks (endpoint-set :include-sets [
          (catalog :name "test.catalog-b" :version 1)])
        :sanitizers (endpoint-set :include-sets [
          (catalog :name "test.catalog-a" :version 1)
          (catalog :name "test.catalog-b" :version 1)])))"#;
    let loaded = registry
        .register_policy_bytes(
            PolicySourceIdentity::new("catalog-auxiliaries"),
            policy.as_bytes(),
        )
        .unwrap();

    let sanitizers = &loaded.resolved_taint().unwrap().sanitizers;
    assert_eq!(sanitizers.len(), 2);
    let identities = sanitizers
        .iter()
        .map(|entry| match &entry.identity {
            ResolvedEndpointIdentity::Catalog { catalog, entry_id } => {
                (catalog.name.as_str(), entry_id.as_str())
            }
            identity => panic!("expected catalog auxiliary identity, got {identity:?}"),
        })
        .collect::<Vec<_>>();
    assert_eq!(
        identities,
        [("test.catalog-a", "clean"), ("test.catalog-b", "clean")]
    );
    assert_eq!(
        sanitizers
            .iter()
            .map(|entry| entry.selector_path.as_str())
            .collect::<Vec<_>>(),
        [
            "/dependencies/catalogs/test.catalog-a@1/clean/selector",
            "/dependencies/catalogs/test.catalog-b@1/clean/selector",
        ]
    );
    assert!(sanitizers.iter().all(|entry| entry.origins.len() == 1));
    assert!(loaded.resolved_selectors().iter().any(|selector| {
        selector.path.as_str() == "/dependencies/catalogs/test.catalog-a@1/clean/selector"
            && matches!(selector.origin, SelectorOrigin::Catalog { .. })
    }));
    assert!(loaded.resolved_selectors().iter().any(|selector| {
        selector.path.as_str() == "/dependencies/catalogs/test.catalog-b@1/clean/selector"
            && matches!(selector.origin, SelectorOrigin::Catalog { .. })
    }));
    let canonical = loaded.to_canonical_semantic_json();
    let canonical_sanitizers = canonical["analysis"]["sanitizers"]
        .as_array()
        .expect("resolved taint canonical projection contains sanitizers");
    assert_eq!(canonical_sanitizers.len(), 2);
    assert_ne!(
        canonical_sanitizers[0]["identity"],
        canonical_sanitizers[1]["identity"]
    );
}
