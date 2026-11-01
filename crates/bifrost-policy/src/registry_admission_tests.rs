use std::sync::Arc;

use crate::*;

fn registry(limits: PolicyRegistryLimits) -> PolicyRegistry {
    PolicyRegistry::new_without_workspace(
        Arc::new(TaintCatalogRegistry::new_without_workspace(
            CatalogRegistryLimits::default(),
        )),
        limits,
    )
}

fn policy(id: usize) -> String {
    format!(
        r#"(policy :id "test.p{id}" :name "Inline" :message "Match" :severity warning
        :analysis (analysis :type match :selector (rql (name "target"))))"#
    )
}

#[test]
fn endpoint_limit_accepts_its_hard_ceiling_and_rejects_invalid_requests() {
    assert!(
        PolicyRegistryLimits::default()
            .with_max_endpoints(MAX_REGISTERED_ENDPOINTS)
            .is_ok()
    );
    assert!(
        PolicyRegistryLimits::default()
            .with_max_endpoints(MAX_REGISTERED_ENDPOINTS + 1)
            .is_err()
    );
    assert!(
        PolicyRegistryLimits::default()
            .with_max_endpoints(0)
            .is_err()
    );
}

#[test]
fn policy_count_admits_the_last_slot_transactionally() {
    let mut registry = registry(PolicyRegistryLimits::default());
    for id in 0..MAX_REGISTERED_POLICIES {
        registry
            .register_policy_bytes(
                PolicySourceIdentity::new(format!("test:{id}")),
                policy(id).as_bytes(),
            )
            .unwrap();
    }
    assert!(matches!(
        registry.register_policy_bytes(
            PolicySourceIdentity::new("test:overflow"),
            policy(MAX_REGISTERED_POLICIES).as_bytes()
        ),
        Err(PolicyRegistryError::PolicyLimitExceeded { .. })
    ));
}

#[test]
fn source_byte_ceiling_is_inclusive() {
    let mut source = policy(0);
    source.extend(std::iter::repeat_n(
        ' ',
        MAX_RQLP_SOURCE_BYTES - source.len(),
    ));
    let mut registry = registry(PolicyRegistryLimits::default());
    registry
        .register_policy_bytes(PolicySourceIdentity::new("test:exact"), source.as_bytes())
        .unwrap();
    source.push(' ');
    assert!(matches!(
        registry.register_policy_bytes(PolicySourceIdentity::new("test:over"), source.as_bytes()),
        Err(PolicyRegistryError::SourceTooLarge { .. })
    ));
}

#[test]
fn deferred_source_keeps_exact_bytes_and_charges_them() {
    let source = policy(0);
    let mut generous = registry(PolicyRegistryLimits::default());
    let loaded = generous
        .register_policy_bytes_deferred(
            PolicySourceIdentity::new("test:deferred"),
            source.as_bytes(),
        )
        .unwrap();
    assert_eq!(
        loaded.source_hash(),
        PolicySourceHash::from_source_bytes(source.as_bytes())
    );
    let mut bounded = registry(
        PolicyRegistryLimits::default()
            .with_max_retained_source_and_selector_bytes(source.len() - 1)
            .unwrap(),
    );
    assert!(matches!(
        bounded.register_policy_bytes_deferred(
            PolicySourceIdentity::new("test:deferred"),
            source.as_bytes()
        ),
        Err(PolicyRegistryError::RetainedByteLimitExceeded { .. })
    ));
}

#[test]
fn endpoint_slots_accumulate_across_registrations() {
    let mut bounded = registry(
        PolicyRegistryLimits::default()
            .with_max_endpoints(2)
            .unwrap(),
    );
    for id in 0..3 {
        let source = format!(
            r#"(endpoint :id "test.e{id}" :name "Source" :display-name "Source"
            :role source :categories [input.user] :selector (rql (call :callee (name "input")))
            :binding return-value :taint (source-semantics :labels [untrusted]) :supersedes [])"#
        );
        let result = bounded.register_endpoint_bytes(
            PolicySourceIdentity::new(format!("test:{id}")),
            source.as_bytes(),
        );
        if id < 2 {
            let loaded = result.unwrap();
            assert_eq!(
                loaded.source_hash(),
                PolicySourceHash::from_source_bytes(source.as_bytes())
            );
        } else {
            assert!(matches!(
                result,
                Err(PolicyRegistryError::EndpointLimitExceeded { .. })
            ));
        }
    }
}

const STORE: &str = r#"(endpoint-set-document :schema-version 1 :kind stores
  :set (endpoint-set :entries [
    (store-write :id put :selector (rql (language java (call :callee (name "put"))))
      :store accounts :key (argument :index 0) :input (argument :index 1))
    (store-read :id get :selector (rql (language java (call :callee (name "get"))))
      :store accounts :key (argument :index 0) :output return-value)]))"#;

fn imported_policy(id: &str, references: &str) -> String {
    format!(
        r#"(policy :schema-version 1 :id "{id}" :name "Imports"
      :message "flow" :severity warning
      :analysis (analysis :type taint :mode may
        :sources (endpoint-set :entries [(source :id source :display-name "input"
          :categories [input.user] :selector (rql (language java (call :callee (name "source"))))
          :bind return-value :labels [untrusted])])
        :sinks (endpoint-set :entries [(sink :id sink :display-name "output"
          :categories [output.sensitive] :selector (rql (language java (call :callee (name "sink"))))
          :dangerous-operand (argument :index 0) :accepts [untrusted])])
        :stores (endpoint-set :include-files [{references}])) )"#
    )
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "c07008dd0dac: fitting cache replacement was charged before releasing the old entry"
)]
fn cache_replacement_obeys_the_resulting_retained_budget() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("db.rqlp");
    let reference = r#"(endpoint-set-file :path "db.rqlp")"#;
    let first = imported_policy("first", reference);
    let second = imported_policy("other", reference);
    // Each policy keeps a typed copy; the registry keeps one parsed cache copy.
    let maximum = first.len() + second.len() + 3 * STORE.len();
    for extra in [0, 1] {
        // An extra document byte adds two retained bytes. Leave one byte of
        // room in the refusal case to exceed the retained limit by exactly one.
        let maximum = maximum + extra;
        std::fs::write(&path, STORE).unwrap();
        let mut registry = PolicyRegistry::new_for_workspace(
            temp.path().to_path_buf(),
            Arc::new(TaintCatalogRegistry::new_without_workspace(
                CatalogRegistryLimits::default(),
            )),
            PolicyRegistryLimits::default()
                .with_max_retained_source_and_selector_bytes(maximum)
                .unwrap(),
        )
        .unwrap();
        registry
            .register_policy_bytes("first.rqlp".into(), first.as_bytes())
            .unwrap();
        let changed = STORE.replace("name \"put\"", "name \"set\"") + &" ".repeat(extra);
        assert_ne!(changed, STORE);
        std::fs::write(&path, changed).unwrap();
        let result = registry.register_policy_bytes("other.rqlp".into(), second.as_bytes());
        if extra == 0 {
            result.unwrap();
        } else {
            match result.unwrap_err() {
                PolicyRegistryError::RetainedByteLimitExceeded {
                    attempted,
                    maximum: limit,
                } => {
                    assert_eq!(limit, maximum);
                    assert_eq!(attempted, maximum + 1);
                }
                error => panic!("unexpected replacement diagnostic: {error:?}"),
            }
        }
    }
    let padded = format!("{STORE}{}", " ".repeat(10_000));
    std::fs::write(&path, &padded).unwrap();
    let mut registry = PolicyRegistry::new_for_workspace(
        temp.path().to_path_buf(),
        Arc::new(TaintCatalogRegistry::new_without_workspace(
            CatalogRegistryLimits::default(),
        )),
        PolicyRegistryLimits::default()
            .with_max_retained_source_and_selector_bytes(first.len() + 2 * padded.len())
            .unwrap(),
    )
    .unwrap();
    registry
        .register_policy_bytes("first.rqlp".into(), first.as_bytes())
        .unwrap();
    std::fs::write(&path, STORE).unwrap();
    registry
        .register_policy_bytes("other.rqlp".into(), second.as_bytes())
        .unwrap();
}
fn workspace_registry(root: &std::path::Path, limits: PolicyRegistryLimits) -> PolicyRegistry {
    PolicyRegistry::new_for_workspace(
        root.to_path_buf(),
        Arc::new(TaintCatalogRegistry::new_without_workspace(
            CatalogRegistryLimits::default(),
        )),
        limits,
    )
    .unwrap()
}

#[test]
fn endpoint_set_limits_report_the_exhausted_dimension() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(temp.path().join("db.rqlp"), STORE).unwrap();
    std::fs::write(
        temp.path().join("other.rqlp"),
        STORE
            .replace(":id put", ":id put-other")
            .replace(":id get", ":id get-other"),
    )
    .unwrap();
    std::fs::write(temp.path().join("wrapper.rqlp"), r#"(endpoint-set-document :kind stores :set (endpoint-set :include-files [(endpoint-set-file :path "db.rqlp")]))"#).unwrap();
    let single = r#"(endpoint-set-file :path "db.rqlp")"#;
    let siblings = r#"(endpoint-set-file :path "db.rqlp") (endpoint-set-file :path "other.rqlp")"#;
    let nested = r#"(endpoint-set-file :path "wrapper.rqlp")"#;
    // The closure has two inline endpoints plus two imported stores; each sibling is depth one.
    let cases = [
        (
            single,
            PolicyRegistryLimits::default()
                .with_max_endpoint_set_files(1)
                .unwrap(),
            None,
        ),
        (
            siblings,
            PolicyRegistryLimits::default()
                .with_max_endpoint_set_files(1)
                .unwrap(),
            Some("endpoint-set-file-limit"),
        ),
        (
            siblings,
            PolicyRegistryLimits::default()
                .with_max_endpoint_set_depth(1)
                .unwrap(),
            None,
        ),
        (
            nested,
            PolicyRegistryLimits::default()
                .with_max_endpoint_set_depth(1)
                .unwrap(),
            Some("endpoint-set-depth-limit"),
        ),
        (
            single,
            PolicyRegistryLimits::default()
                .with_max_endpoint_set_entries(4)
                .unwrap(),
            None,
        ),
        (
            single,
            PolicyRegistryLimits::default()
                .with_max_endpoint_set_entries(3)
                .unwrap(),
            Some("endpoint-set-entry-limit"),
        ),
    ];
    for (references, limits, expected) in cases {
        let mut registry = workspace_registry(temp.path(), limits);
        let source = imported_policy("test", references);
        let result = registry.register_policy_bytes("p.rqlp".into(), source.as_bytes());
        if let Some(expected) = expected {
            match result.unwrap_err() {
                PolicyRegistryError::EndpointSetImport { error, .. } => {
                    assert_eq!(error.diagnostic.code, expected)
                }
                error => panic!("unexpected import failure: {error:?}"),
            }
            assert_eq!(registry.policies().len(), 0);
        } else {
            result.unwrap();
        }
    }
}

#[test]
fn one_call_can_read_and_write_a_store_with_distinct_ports() {
    let temp = tempfile::tempdir().unwrap();
    let source = imported_policy("test", r#"(endpoint-set-file :path "db.rqlp")"#);
    let paired = STORE
        .replace("name \"put\"", "name \"access\"")
        .replace("name \"get\"", "name \"access\"");
    std::fs::write(temp.path().join("db.rqlp"), &paired).unwrap();
    let mut registry = workspace_registry(temp.path(), PolicyRegistryLimits::default());
    let loaded = registry
        .register_policy_bytes("p.rqlp".into(), source.as_bytes())
        .unwrap();
    assert_eq!(loaded.resolved_taint().unwrap().store_reads.len(), 1);
    assert_eq!(loaded.resolved_taint().unwrap().store_writes.len(), 1);
    let conflict = paired
        .replace("store-read :id get", "store-write :id get")
        .replace(":output return-value", ":input (argument :index 0)");
    std::fs::write(temp.path().join("db.rqlp"), conflict).unwrap();
    let mut registry = workspace_registry(temp.path(), PolicyRegistryLimits::default());
    match registry
        .register_policy_bytes("p.rqlp".into(), source.as_bytes())
        .unwrap_err()
    {
        PolicyRegistryError::EndpointSetImport { error, .. } => {
            assert_eq!(error.diagnostic.code, "endpoint-set-store-conflict")
        }
        error => panic!("unexpected store failure: {error:?}"),
    }
}

#[test]
fn referenced_selector_bytes_are_charged_at_the_exact_boundary() {
    let temp = tempfile::tempdir().unwrap();
    let query = "(rql :schema-version 1 (name \"target\"))";
    std::fs::write(temp.path().join("query.rql"), query).unwrap();
    let source = policy(0).replace("(rql (name \"target\"))", "(rql-file :path \"query.rql\")");
    let maximum = source.len() + query.len();
    let mut exact = workspace_registry(
        temp.path(),
        PolicyRegistryLimits::default()
            .with_max_retained_source_and_selector_bytes(maximum)
            .unwrap(),
    );
    exact
        .register_policy_bytes("p.rqlp".into(), source.as_bytes())
        .unwrap();
    let mut short = workspace_registry(
        temp.path(),
        PolicyRegistryLimits::default()
            .with_max_retained_source_and_selector_bytes(maximum - 1)
            .unwrap(),
    );
    assert!(matches!(
        short.register_policy_bytes("p.rqlp".into(), source.as_bytes()),
        Err(PolicyRegistryError::RetainedByteLimitExceeded { .. })
    ));
    assert_eq!(short.policies().len(), 0);
}

fn source_document(id: &str) -> String {
    format!(
        r#"(endpoint :id "{id}" :name "Input" :display-name "Input" :role source
      :categories [input.user] :selector (rql (call :callee (name "input")))
      :binding return-value :taint (source-semantics :labels [untrusted]))"#
    )
}

fn directory_import_policy(references: &str) -> String {
    format!(
        r#"(policy :id "test.directory" :name "Directory" :message "Flow" :severity warning
      :analysis (analysis :type taint :mode may
        :sources (endpoint-set :include-matches [{references}])
        :sinks (endpoint-set :entries [(sink :id output :display-name "Output"
          :categories [output.sensitive] :selector (rql (call :callee (name "sink")))
          :dangerous-operand (argument :index 0) :accepts [untrusted])])) )"#
    )
}

#[test]
fn directory_candidate_budget_ignores_other_entries_and_classifies_missing_paths() {
    let temp = tempfile::tempdir().unwrap();
    let directory = temp.path().join("endpoints");
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(directory.join("one.rqlp"), source_document("test.one")).unwrap();
    for name in ["ignored.txt", "another.txt"] {
        std::fs::write(directory.join(name), "ignored").unwrap();
    }
    let source = directory_import_policy(
        r#"(match-directory :path "endpoints" :scope direct :categories (all [input.user]))"#,
    );
    let limits = PolicyRegistryLimits::default()
        .with_max_match_directory_candidates(1)
        .unwrap();
    workspace_registry(temp.path(), limits)
        .register_policy_bytes("p.rqlp".into(), source.as_bytes())
        .unwrap();
    std::fs::write(directory.join("two.rqlp"), source_document("test.two")).unwrap();
    let mut registry = workspace_registry(temp.path(), limits);
    match registry
        .register_policy_bytes("p.rqlp".into(), source.as_bytes())
        .unwrap_err()
    {
        PolicyRegistryError::MatchDirectoryLimits { message } => {
            assert!(message.contains("`.rqlp` candidates"), "{message}")
        }
        error => panic!("unexpected directory failure: {error:?}"),
    }
    assert_eq!(registry.policies().len(), 0);
    let missing = directory_import_policy(
        r#"(match-directory :path "missing" :scope direct :categories (all [input.user]))"#,
    );
    assert!(matches!(
        workspace_registry(temp.path(), limits)
            .register_policy_bytes("p.rqlp".into(), missing.as_bytes()),
        Err(PolicyRegistryError::Directory { .. })
    ));
}

#[test]
fn direct_and_recursive_selections_preserve_both_authored_origins() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(temp.path().join("endpoints/nested/deeper")).unwrap();
    std::fs::write(
        temp.path().join("endpoints/root.rqlp"),
        source_document("test.root"),
    )
    .unwrap();
    std::fs::write(
        temp.path().join("endpoints/nested/deeper/child.rqlp"),
        source_document("test.child"),
    )
    .unwrap();
    let direct =
        r#"(match-directory :path "endpoints" :scope direct :categories (all [input.user]))"#;
    let recursive =
        r#"(match-directory :path "endpoints" :scope recursive :categories (all [input.user]))"#;
    for references in [
        format!("{direct} {recursive}"),
        format!("{recursive} {direct}"),
    ] {
        let source = directory_import_policy(&references);
        let mut registry = workspace_registry(temp.path(), PolicyRegistryLimits::default());
        let loaded = registry
            .register_policy_bytes("p.rqlp".into(), source.as_bytes())
            .unwrap();
        assert_eq!(loaded.resolved_taint().unwrap().sources.len(), 2);
        let origins: std::collections::HashSet<_> = loaded
            .endpoint_dependencies()
            .iter()
            .flat_map(|dependency| &dependency.origins)
            .filter_map(|origin| match origin {
                EndpointOrigin::MatchDirectory { path, source }
                    if source.as_str() == "endpoints/root.rqlp" =>
                {
                    Some(path.as_str())
                }
                _ => None,
            })
            .collect();
        assert_eq!(
            origins,
            std::collections::HashSet::from([
                "/analysis/sources/include-matches/0",
                "/analysis/sources/include-matches/1"
            ])
        );
    }
}

#[test]
fn directory_transient_budget_includes_unselected_referenced_selectors() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(temp.path().join("endpoints")).unwrap();
    let query = format!(
        "(rql :schema-version 1 (call :callee (name \"input\"))){}",
        " ".repeat(10_000)
    );
    std::fs::write(temp.path().join("large.rql"), &query).unwrap();
    let one = source_document("test.one")
        .replace("input.user", "selected.input")
        .replace(
            "(rql (call :callee (name \"input\")))",
            "(rql-file :path \"large.rql\")",
        );
    let two = source_document("test.two")
        .replace("input.user", "ignored.input")
        .replace(
            "(rql (call :callee (name \"input\")))",
            "(rql-file :path \"large.rql\")",
        );
    std::fs::write(temp.path().join("endpoints/one.rqlp"), &one).unwrap();
    std::fs::write(temp.path().join("endpoints/two.rqlp"), &two).unwrap();
    let source = directory_import_policy(
        r#"(match-directory :path "endpoints" :scope direct :categories (all [selected.input]))"#,
    );
    let sufficient = source.len() + one.len() + two.len() + 2 * query.len();
    let mut generous = workspace_registry(
        temp.path(),
        PolicyRegistryLimits::default()
            .with_max_retained_source_and_selector_bytes(sufficient)
            .unwrap(),
    );
    assert_eq!(
        generous
            .register_policy_bytes("p.rqlp".into(), source.as_bytes())
            .unwrap()
            .resolved_taint()
            .unwrap()
            .sources
            .len(),
        1
    );
    // This fits both endpoint documents and either referenced-query copy, but not both.
    let maximum = source.len() + one.len() + two.len() + query.len();
    let mut bounded = workspace_registry(
        temp.path(),
        PolicyRegistryLimits::default()
            .with_max_retained_source_and_selector_bytes(maximum)
            .unwrap(),
    );
    assert!(matches!(
        bounded.register_policy_bytes("p.rqlp".into(), source.as_bytes()),
        Err(PolicyRegistryError::RetainedByteLimitExceeded { .. })
    ));
    assert_eq!(bounded.policies().len(), 0);
}

#[test]
fn workspace_loading_requires_analyzer_for_qualified_locators() {
    let temp = tempfile::tempdir().unwrap();
    let step = r#"(resolved-call :resolves-to "Widget.create" :proof exact
        (call-bindings (call-shape (call :callee "create"))))"#;
    let qualified_policy = policy(0).replace("(name \"target\")", step);
    let qualified_endpoint =
        source_document("test.qualified").replace("(call :callee (name \"input\"))", step);
    std::fs::write(temp.path().join("qualified-policy.rqlp"), &qualified_policy).unwrap();
    std::fs::write(
        temp.path().join("qualified-endpoint.rqlp"),
        &qualified_endpoint,
    )
    .unwrap();
    std::fs::write(temp.path().join("plain-policy.rqlp"), policy(0)).unwrap();
    std::fs::write(
        temp.path().join("plain-endpoint.rqlp"),
        source_document("test.qualified"),
    )
    .unwrap();
    let mut policy_registry = workspace_registry(temp.path(), PolicyRegistryLimits::default());
    match policy_registry
        .load_policy_path("qualified-policy.rqlp")
        .unwrap_err()
    {
        PolicyRegistryError::Source(error) => {
            assert_eq!(error.diagnostic.code, "qualified-call-locator-incomplete")
        }
        error => panic!("unexpected policy diagnostic: {error:?}"),
    }
    assert_eq!(policy_registry.policies().len(), 0);
    policy_registry
        .load_policy_path("plain-policy.rqlp")
        .unwrap();
    let mut deferred = registry(PolicyRegistryLimits::default());
    deferred
        .register_policy_bytes_deferred("built-in.rqlp".into(), qualified_policy.as_bytes())
        .unwrap();
    let mut endpoint_registry = workspace_registry(temp.path(), PolicyRegistryLimits::default());
    match endpoint_registry
        .load_endpoint_path("qualified-endpoint.rqlp")
        .unwrap_err()
    {
        PolicyRegistryError::Source(error) => {
            assert_eq!(error.diagnostic.code, "qualified-call-locator-incomplete")
        }
        error => panic!("unexpected endpoint diagnostic: {error:?}"),
    }
    assert_eq!(endpoint_registry.endpoints().len(), 0);
    endpoint_registry
        .load_endpoint_path("plain-endpoint.rqlp")
        .unwrap();
}

fn terminal_policy(events: &str, transitions: &str, terminal: &str) -> String {
    format!(
        r#"(policy :id "test.terminals" :name "Terminals" :message "Resource open" :severity warning
      :analysis (analysis :type typestate :mode may
        :subjects (subject-set :entries [(subject :id resource
          :selector (rql (call :callee (name "open"))) :subject return-value)])
        :uncertainty (uncertainty :escape inconclusive)
        :automaton (automaton :states [open closed violated] :initial open
          :accepting-states [open closed] :error-states [violated]
          :events [{events}] :transitions [{transitions}] :terminal-expectations [{terminal}])))"#
    )
}

const TERMINAL: &str = r#"(terminal-expectation :id final-use
    :matches (match-endpoints :ids [test.shared] :role sink :phase after-normal-return)
    :expected-states [closed])"#;
const SHARED_SINK: &str = r#"(endpoint :id "test.shared" :name "Close" :display-name "Close"
    :role sink :categories [resource.close] :selector (rql (call :callee (name "close")))
    :binding receiver :supersedes [])"#;

#[test]
fn terminal_only_endpoint_matches_publish_their_dependency() {
    let mut registry = registry(PolicyRegistryLimits::default());
    registry
        .register_endpoint_bytes("shared.rqlp".into(), SHARED_SINK.as_bytes())
        .unwrap();
    let event = r#"(event :id noop :calls (calls :selector (rql (call :callee (name "noop"))) :subject receiver :phase after-normal-return))"#;
    let source = terminal_policy(event, "(transition :from open :on noop :to open)", TERMINAL);
    let loaded = registry
        .register_policy_bytes("p.rqlp".into(), source.as_bytes())
        .unwrap();
    assert!(loaded.endpoint_dependencies().iter().any(|dependency| dependency.origins.iter().any(|origin| matches!(origin,
        EndpointOrigin::ExactMatch { path, source } if source.as_str()=="shared.rqlp" && path.as_str()=="/analysis/automaton/terminal-expectations/final-use/on"))));
}

#[test]
fn shared_imported_match_endpoint_retains_each_document_origin() {
    let temp = tempfile::tempdir().unwrap();
    let document = r#"(endpoint-set-document :kind sources :set (endpoint-set :include-matches [(match-endpoints :ids [test.shared])]))"#;
    for name in ["left.rqlp", "right.rqlp"] {
        std::fs::write(temp.path().join(name), document).unwrap();
    }
    for references in [
        r#"(endpoint-set-file :path "left.rqlp") (endpoint-set-file :path "right.rqlp")"#,
        r#"(endpoint-set-file :path "right.rqlp") (endpoint-set-file :path "left.rqlp")"#,
    ] {
        let mut registry = workspace_registry(temp.path(), PolicyRegistryLimits::default());
        registry
            .register_endpoint_bytes(
                "shared.rqlp".into(),
                source_document("test.shared").as_bytes(),
            )
            .unwrap();
        let source = imported_policy("test", "").replace(
            ":sources (endpoint-set :entries",
            &format!(":sources (endpoint-set :include-files [{references}] :entries"),
        );
        let loaded = registry
            .register_policy_bytes("p.rqlp".into(), source.as_bytes())
            .unwrap();
        let documents: std::collections::HashSet<_> = loaded
            .endpoint_dependencies()
            .iter()
            .flat_map(|dependency| &dependency.origins)
            .filter_map(|origin| match origin {
                EndpointOrigin::EndpointSetFile { source, .. } => Some(source.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(
            documents,
            std::collections::HashSet::from(["left.rqlp", "right.rqlp"])
        );
    }
}

#[test]
fn imported_set_identity_tracks_resolved_queries_and_entry_names() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("db.rqlp");
    let query = "(rql :schema-version 1 (language java (call :callee (name \"put\"))))";
    std::fs::write(temp.path().join("put.rql"), query).unwrap();
    let referenced = STORE.replace(
        "(rql (language java (call :callee (name \"put\"))))",
        "(rql-file :path \"put.rql\")",
    );
    let source = imported_policy("test", r#"(endpoint-set-file :path "db.rqlp")"#);
    let mut hashes = Vec::new();
    for document in [
        STORE.to_string(),
        referenced.clone(),
        referenced.replace(":id put", ":id put-renamed"),
    ] {
        std::fs::write(&path, document).unwrap();
        let mut registry = workspace_registry(temp.path(), PolicyRegistryLimits::default());
        hashes.push(
            registry
                .register_policy_bytes("p.rqlp".into(), source.as_bytes())
                .unwrap()
                .endpoint_set_dependencies()[0]
                .semantic_hash,
        );
    }
    assert_eq!(hashes[0], hashes[1]);
    assert_ne!(hashes[1], hashes[2]);
    std::fs::write(&path, referenced).unwrap();
    std::fs::write(
        temp.path().join("put.rql"),
        query.replace("name \"put\"", "name \"write\""),
    )
    .unwrap();
    let mut registry = workspace_registry(temp.path(), PolicyRegistryLimits::default());
    let changed = registry
        .register_policy_bytes("p.rqlp".into(), source.as_bytes())
        .unwrap()
        .endpoint_set_dependencies()[0]
        .semantic_hash;
    assert_ne!(hashes[1], changed);
}

#[test]
fn missing_selection_diagnostic_highlights_the_authored_reference() {
    let temp = tempfile::tempdir().unwrap();
    let prefix = r#"(policy :id "test.selection" :name "Selection" :message "Selected" :severity warning
      :analysis (analysis :type assertion
        (bind :name earlier :query (rql (enclosing-decl (function :name "control"))))
        (bind :name selected :query "#;
    let reference = r#"(declaration-selection-file :path "missing.rqlp" :language python)"#;
    let source = format!("{prefix}{reference})))");
    let mut registry = workspace_registry(temp.path(), PolicyRegistryLimits::default());
    match registry
        .register_policy_bytes("p.rqlp".into(), source.as_bytes())
        .unwrap_err()
    {
        PolicyRegistryError::DeclarationSelectionImport { error, .. } => {
            assert_eq!(error.diagnostic.code, "declaration-selection-unavailable");
            assert_eq!(
                error.diagnostic.range,
                prefix.len()..prefix.len() + reference.len()
            );
        }
        error => panic!("unexpected selection diagnostic: {error:?}"),
    }
    assert_eq!(registry.policies().len(), 0);
    std::fs::write(temp.path().join("missing.rqlp"), r#"(declaration-selection-document :schema-version 1 :language python :declarations [(rql (enclosing-decl (function :name "control")))])"#).unwrap();
    registry
        .register_policy_bytes("p.rqlp".into(), source.as_bytes())
        .unwrap();
}

#[test]
fn catalog_and_match_selectors_preserve_resolved_locator_evidence() {
    use brokk_bifrost_analysis::analyzer::{AnalyzerConfig, Language};
    let project = crate::inline_project::InlineTestProject::with_language(Language::Java)
        .file(
            "Widget.java",
            "class Widget { int create(int value) { return value; } }",
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let analyzer = workspace.analyzer();
    let step = r#"(resolved-call :resolves-to "Widget.create" :proof exact :receiver-type "Widget"
        (call-bindings (call-shape (call :callee "create"))))"#;
    let query = format!("(rql :schema-version 1 (language java {step}))");
    let inline = imported_policy("template", "").replace(
        "(rql (language java (call :callee (name \"source\"))))",
        &query,
    );
    let parsed = parse_rqlp_source(&inline, "template.rqlp".into()).unwrap();
    let RqlpDocument::Policy { definition } = parsed.document() else {
        panic!("expected policy")
    };
    let PolicyAnalysis::Taint { spec } = &definition.analysis else {
        panic!("expected taint")
    };
    let source = spec.sources.entries[0].clone();
    let mut catalogs =
        TaintCatalogRegistry::new_without_workspace(CatalogRegistryLimits::default());
    catalogs
        .register(TaintCatalogDefinition {
            schema_version: 1,
            name: PolicyId::new("test.catalog").unwrap(),
            version: 1,
            categories: source.categories.clone(),
            sources: vec![source],
            sinks: Vec::new(),
            sanitizers: Vec::new(),
            transforms: Vec::new(),
            external_models: Vec::new(),
        })
        .unwrap();
    let mut registry =
        PolicyRegistry::new_without_workspace(Arc::new(catalogs), PolicyRegistryLimits::default());
    let policy = r#"(policy :id "test.catalog-policy" :name "Catalog" :message "Flow" :severity warning
      :analysis (analysis :type taint :mode may
        :sources (endpoint-set :include-sets [(catalog :name "test.catalog" :version 1)])
        :sinks (endpoint-set :entries [(sink :id output :display-name "Output"
          :categories [output.sensitive] :selector (rql (call :callee (name "sink")))
          :dangerous-operand (argument :index 0) :accepts [untrusted])])) )"#;
    let loaded = registry
        .register_policy_bytes_with_analyzer(
            "catalog-policy.rqlp".into(),
            policy.as_bytes(),
            analyzer,
        )
        .unwrap();
    let selected = loaded
        .resolved_selectors()
        .iter()
        .find(|selector| matches!(selector.origin, SelectorOrigin::Catalog { .. }))
        .unwrap();
    assert!(
        selected
            .resolved_locators
            .iter()
            .any(|locator| locator.role == ResolvedPolicyLocatorRole::Callable)
    );
    assert!(
        selected
            .resolved_locators
            .iter()
            .any(|locator| locator.role == ResolvedPolicyLocatorRole::ReceiverType)
    );
    assert!(selected.resolved_locators.iter().all(|locator| locator.kind
        == ResolvedPolicyLocatorKind::WorkspaceDeclaration
        && !locator.identity.is_empty()));
    let endpoint =
        source_document("test.qualified").replace("(rql (call :callee (name \"input\")))", &query);
    let expected = registry
        .register_endpoint_bytes_with_analyzer(
            "qualified.rqlp".into(),
            endpoint.as_bytes(),
            analyzer,
        )
        .unwrap()
        .resolved_selector()
        .resolved_locators
        .clone();
    assert_eq!(expected.len(), 2);
    let matched = policy
        .replace("test.catalog-policy", "test.match-policy")
        .replace(
            "(catalog :name \"test.catalog\" :version 1)",
            "(match-endpoints :ids [test.qualified])",
        )
        .replace(":include-sets", ":include-matches");
    let loaded = registry
        .register_policy_bytes_with_analyzer(
            "matched-policy.rqlp".into(),
            matched.as_bytes(),
            analyzer,
        )
        .unwrap();
    let selected = loaded
        .resolved_selectors()
        .iter()
        .find(|selector| {
            selector.path.as_str() == "/dependencies/match-endpoints/test.qualified/selector"
        })
        .unwrap();
    assert_eq!(selected.resolved_locators, expected);
}

#[test]
fn exact_endpoint_selection_admits_multiple_candidates() {
    let mut registry = registry(PolicyRegistryLimits::default());
    for id in ["test.one", "test.two"] {
        registry
            .register_endpoint_bytes(
                PolicySourceIdentity::new(format!("{id}.rqlp")),
                source_document(id).as_bytes(),
            )
            .unwrap();
    }
    let source = directory_import_policy("(match-endpoints :ids [test.one test.two])");
    let loaded = registry
        .register_policy_bytes("p.rqlp".into(), source.as_bytes())
        .unwrap();
    assert_eq!(loaded.resolved_taint().unwrap().sources.len(), 2);
}

#[test]
fn endpoint_origin_ceiling_counts_imported_and_authored_references() {
    let temp = tempfile::tempdir().unwrap();
    let document = r#"(endpoint-set-document :kind sources :set (endpoint-set :include-matches [(match-endpoints :ids [test.shared])]))"#;
    let mut leaves = Vec::new();
    // Each leaf authors one match reference. Four wrappers respect the
    // parser's 64-reference cap and keep the file closure below 256 files.
    for index in 0..251 {
        let name = format!("set{index}.rqlp");
        std::fs::write(temp.path().join(&name), document).unwrap();
        leaves.push(format!("(endpoint-set-file :path \"{name}\")"));
    }
    let mut files = String::new();
    for (index, chunk) in leaves.chunks(64).enumerate() {
        let name = format!("wrapper{index}.rqlp");
        std::fs::write(
            temp.path().join(&name),
            format!(
                "(endpoint-set-document :kind sources :set (endpoint-set :include-files [{}]))",
                chunk.join(" ")
            ),
        )
        .unwrap();
        files.push_str(&format!("(endpoint-set-file :path \"{name}\")"));
    }
    // 251 leaf match positions plus five root positions reach the 256-origin
    // merge ceiling in composition/common.rs; a sixth root position exceeds it.
    for count in [5, 6] {
        let mut registry = workspace_registry(temp.path(), PolicyRegistryLimits::default());
        registry
            .register_endpoint_bytes(
                "shared.rqlp".into(),
                source_document("test.shared").as_bytes(),
            )
            .unwrap();
        for index in 0..5 {
            let id = format!("test.other{index}");
            registry
                .register_endpoint_bytes(
                    PolicySourceIdentity::new(format!("{id}.rqlp")),
                    source_document(&id).as_bytes(),
                )
                .unwrap();
        }
        let references: String = (0..count)
            .map(|index| {
                if index == 0 {
                    "(match-endpoints :ids [test.shared])".to_string()
                } else {
                    format!(
                        "(match-endpoints :ids [test.shared test.other{}])",
                        index - 1
                    )
                }
            })
            .collect();
        let source = directory_import_policy(&references).replace(
            ":sources (endpoint-set :include-matches",
            &format!(":sources (endpoint-set :include-files [{files}] :include-matches"),
        );
        let result = registry.register_policy_bytes("p.rqlp".into(), source.as_bytes());
        if count == 5 {
            result.unwrap();
        } else {
            assert!(
                matches!(
                    result,
                    Err(PolicyRegistryError::EndpointOriginLimitExceeded {
                        found: 257,
                        maximum: 256,
                        ..
                    })
                ),
                "{result:?}"
            );
            assert_eq!(registry.policies().len(), 0);
        }
    }
}
