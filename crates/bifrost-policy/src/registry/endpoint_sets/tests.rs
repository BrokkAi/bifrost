use super::*;
use crate::catalog::CatalogRegistryLimits;

const STORE: &str = r#"(endpoint-set-document :schema-version 1 :kind stores
  :set (endpoint-set :entries [
    (store-write :id put :selector (rql (language java (call :callee (name "put"))))
      :store accounts :key (argument :index 0) :input (argument :index 1))
    (store-read :id get :selector (rql (language java (call :callee (name "get"))))
      :store accounts :key (argument :index 0) :output return-value)]))"#;

fn policy(id: &str, references: &str) -> String {
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

fn reference(path: &str) -> String {
    format!(r#"(endpoint-set-file :path "{path}")"#)
}

fn registry(root: &Path) -> PolicyRegistry {
    PolicyRegistry::new_for_workspace(
        root.to_path_buf(),
        Arc::new(TaintCatalogRegistry::new_without_workspace(
            CatalogRegistryLimits::default(),
        )),
        PolicyRegistryLimits::default(),
    )
    .unwrap()
}

#[test]
fn two_policies_reuse_typed_store_document_and_preserve_provenance() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(temp.path().join("library/stores")).unwrap();
    std::fs::write(temp.path().join("library/stores/db.rqlp"), STORE).unwrap();
    let mut registry = registry(temp.path());
    for id in ["first", "second"] {
        let loaded = registry
            .register_policy_bytes(
                PolicySourceIdentity::new(format!("policies/{id}.rqlp")),
                policy(id, &reference("library/stores/db.rqlp")).as_bytes(),
            )
            .unwrap();
        let stores = loaded.resolved_taint().unwrap();
        assert_eq!(stores.store_writes.len(), 1);
        assert_eq!(stores.store_reads.len(), 1);
        assert_eq!(
            loaded.endpoint_set_dependencies()[0].source.as_str(),
            "library/stores/db.rqlp"
        );
        assert!(stores.store_writes[0].origins.iter().any(|origin| matches!(origin, EndpointOrigin::EndpointSetFile {source, ..} if source.as_str() == "library/stores/db.rqlp")));
    }
    assert_eq!(registry.endpoint_set_parse_count(), 1);
    assert_eq!(registry.endpoint_set_cache_hits(), 1);
}

#[test]
fn imported_match_sets_retain_both_endpoint_and_shared_document_provenance() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(
        temp.path().join("sources.rqlp"),
        r#"(endpoint-set-document :kind sources
      :set (endpoint-set :include-matches [(match-endpoints :ids [shared.input])]))"#,
    )
    .unwrap();
    let mut registry = registry(temp.path());
    registry
        .register_endpoint_bytes(
            "input.rqlp".into(),
            br#"(endpoint :id shared.input
      :name "Input" :display-name "Input" :role source :categories [input.user]
      :selector (rql (language java (call :callee (name "source"))))
      :binding return-value :taint (source-semantics :labels [untrusted]))"#,
        )
        .unwrap();
    let source = policy("test", "").replace(":sources (endpoint-set :entries", ":sources (endpoint-set :include-files [(endpoint-set-file :path \"sources.rqlp\")] :entries");
    let loaded = registry
        .register_policy_bytes("p.rqlp".into(), source.as_bytes())
        .unwrap();
    let endpoint = loaded
        .endpoint_dependencies()
        .iter()
        .find(|entry| {
            matches!(
                entry.identity,
                ResolvedEndpointIdentity::MatchEndpoint { .. }
            )
        })
        .unwrap();
    assert!(endpoint.origins.iter().any(|origin| matches!(origin, EndpointOrigin::EndpointSetFile {source, ..} if source.as_str() == "sources.rqlp")));
    assert!(endpoint.origins.iter().any(|origin| matches!(origin, EndpointOrigin::ExactMatch {source, ..} if source.as_str() == "input.rqlp")));
    assert_eq!(loaded.endpoint_set_dependencies()[0].entries.len(), 1);
}

#[test]
fn changed_dependency_invalidates_parser_reuse_and_semantic_identity() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("db.rqlp");
    std::fs::write(&path, STORE).unwrap();
    let mut first = registry(temp.path());
    let source = policy("same", &reference("db.rqlp"));
    let before = first
        .register_policy_bytes("p.rqlp".into(), source.as_bytes())
        .unwrap()
        .semantic_hash();
    std::fs::write(&path, STORE.replace(":store accounts", ":store users")).unwrap();
    let mut second = registry(temp.path());
    let after = second
        .register_policy_bytes("p.rqlp".into(), source.as_bytes())
        .unwrap()
        .semantic_hash();
    assert_ne!(before, after);
    first
        .register_policy_bytes(
            "q.rqlp".into(),
            policy("other", &reference("db.rqlp")).as_bytes(),
        )
        .unwrap();
    assert_eq!(first.endpoint_set_parse_count(), 2);
}

#[test]
fn replacing_cached_document_releases_its_retained_byte_reservation() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("db.rqlp");
    std::fs::write(&path, STORE).unwrap();
    let mut registry = registry(temp.path());
    registry
        .register_policy_bytes(
            "first.rqlp".into(),
            policy("first", &reference("db.rqlp")).as_bytes(),
        )
        .unwrap();
    let before = registry.retained_source_and_selector_bytes;
    let changed = STORE.replace(":store accounts", ":store users");
    std::fs::write(path, &changed).unwrap();
    let second = policy("second", &reference("db.rqlp"));
    registry
        .register_policy_bytes("second.rqlp".into(), second.as_bytes())
        .unwrap();
    assert_eq!(
        registry.retained_source_and_selector_bytes,
        before + second.len() + 2 * changed.len() - STORE.len()
    );
    assert_eq!(registry.endpoint_set_cache.len(), 1);
}

#[test]
fn whitespace_and_repeated_imports_preserve_semantics() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(temp.path().join("db.rqlp"), STORE).unwrap();
    let source = policy("same", &reference("db.rqlp"));
    let before = registry(temp.path())
        .register_policy_bytes("p.rqlp".into(), source.as_bytes())
        .unwrap()
        .semantic_hash();
    std::fs::write(temp.path().join("db.rqlp"), format!("; comment\n{STORE}\n")).unwrap();
    let after = registry(temp.path())
        .register_policy_bytes("p.rqlp".into(), source.as_bytes())
        .unwrap()
        .semantic_hash();
    assert_eq!(before, after);
}

#[test]
fn nested_diamond_imports_are_unique_and_order_independent() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(temp.path().join("db.rqlp"), STORE).unwrap();
    let wrapper = r#"(endpoint-set-document :kind stores :set (endpoint-set :include-files [(endpoint-set-file :path "db.rqlp")]))"#;
    for path in ["left.rqlp", "right.rqlp"] {
        std::fs::write(temp.path().join(path), wrapper).unwrap();
    }
    let mut hashes = Vec::new();
    for paths in [["left.rqlp", "right.rqlp"], ["right.rqlp", "left.rqlp"]] {
        let refs = paths.map(reference).join(" ");
        let mut registry = registry(temp.path());
        let loaded = registry
            .register_policy_bytes("p.rqlp".into(), policy("test", &refs).as_bytes())
            .unwrap();
        assert_eq!(loaded.resolved_taint().unwrap().store_writes.len(), 1);
        assert_eq!(loaded.resolved_taint().unwrap().store_reads.len(), 1);
        assert_eq!(loaded.endpoint_set_dependencies().len(), 3);
        hashes.push(loaded.semantic_hash());
    }
    assert_eq!(hashes[0], hashes[1]);
}

#[test]
fn duplicate_ids_in_distinct_documents_fail_regardless_of_import_order() {
    let temp = tempfile::tempdir().unwrap();
    for path in ["left.rqlp", "right.rqlp"] {
        std::fs::write(temp.path().join(path), STORE).unwrap();
    }
    for paths in [["left.rqlp", "right.rqlp"], ["right.rqlp", "left.rqlp"]] {
        let refs = paths.map(reference).join(" ");
        let error = registry(temp.path())
            .register_policy_bytes("p.rqlp".into(), policy("test", &refs).as_bytes())
            .unwrap_err();
        assert!(
            error.to_string().contains("duplicate endpoint entry ID"),
            "{error:?}"
        );
    }
}

#[test]
fn nested_depth_and_file_limits_abort_before_registration() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(temp.path().join("db.rqlp"), STORE).unwrap();
    std::fs::write(temp.path().join("wrapper.rqlp"), r#"(endpoint-set-document :kind stores :set (endpoint-set :include-files [(endpoint-set-file :path "db.rqlp")]))"#).unwrap();
    for limits in [
        PolicyRegistryLimits::default()
            .with_max_endpoint_set_depth(1)
            .unwrap(),
        PolicyRegistryLimits::default()
            .with_max_endpoint_set_files(1)
            .unwrap(),
    ] {
        let mut registry = registry(temp.path());
        registry.limits = limits;
        assert!(
            registry
                .register_policy_bytes(
                    "p.rqlp".into(),
                    policy("test", &reference("wrapper.rqlp")).as_bytes()
                )
                .is_err()
        );
        assert_eq!(registry.policies().len(), 0);
        assert_eq!(registry.endpoint_set_parse_count(), 0);
    }
}

#[test]
fn referenced_rql_keeps_its_shared_document_context_and_provenance() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(temp.path().join("library")).unwrap();
    std::fs::write(
        temp.path().join("library/put.rql"),
        r#"(rql :schema-version 1 (language java (call :callee (name "put"))))"#,
    )
    .unwrap();
    let store = STORE.replace(
        r#"(rql (language java (call :callee (name "put"))))"#,
        r#"(rql-file :path "library/put.rql")"#,
    );
    std::fs::write(temp.path().join("library/db.rqlp"), store).unwrap();
    let mut registry = registry(temp.path());
    let loaded = registry
        .register_policy_bytes(
            "policies/p.rqlp".into(),
            policy("test", &reference("library/db.rqlp")).as_bytes(),
        )
        .unwrap();
    assert!(loaded.resolved_selectors().iter().any(|selector| matches!(&selector.origin, SelectorOrigin::ReferencedFile {reference, ..} if reference.as_str() == "library/put.rql")));
}

#[test]
fn a_correct_semantic_pin_loads_and_a_changed_dependency_fails_the_pin() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(temp.path().join("db.rqlp"), STORE).unwrap();
    let mut first = registry(temp.path());
    let hash = first
        .register_policy_bytes(
            "p.rqlp".into(),
            policy("test", &reference("db.rqlp")).as_bytes(),
        )
        .unwrap()
        .endpoint_set_dependencies()[0]
        .semantic_hash;
    let pinned = policy(
        "test",
        &format!(r#"(endpoint-set-file :path "db.rqlp" :sha256 "{hash}")"#),
    );
    registry(temp.path())
        .register_policy_bytes("p.rqlp".into(), pinned.as_bytes())
        .unwrap();
    std::fs::write(
        temp.path().join("db.rqlp"),
        STORE.replace(":store accounts", ":store users"),
    )
    .unwrap();
    assert!(
        registry(temp.path())
            .register_policy_bytes("p.rqlp".into(), pinned.as_bytes())
            .is_err()
    );
}

#[test]
fn wrong_kind_missing_cycles_and_hash_mismatches_fail_transactionally() {
    let temp = tempfile::tempdir().unwrap();
    let cycle = r#"(endpoint-set-document :kind stores :set (endpoint-set :include-files [(endpoint-set-file :path "db.rqlp")]))"#;
    let cases = [
        ("", reference("missing.rqlp"), "unavailable"),
        (
            r#"(endpoint-set-document :kind sanitizers :set (endpoint-set))"#,
            reference("db.rqlp"),
            "wrong-kind",
        ),
        (cycle, reference("db.rqlp"), "cycle"),
        (
            STORE,
            format!(
                r#"(endpoint-set-file :path "db.rqlp" :sha256 "{}")"#,
                "0".repeat(64)
            ),
            "hash-mismatch",
        ),
    ];
    for (document, reference, expected) in cases {
        std::fs::write(temp.path().join("db.rqlp"), document).unwrap();
        let mut registry = registry(temp.path());
        let error = registry
            .register_policy_bytes("p.rqlp".into(), policy("test", &reference).as_bytes())
            .unwrap_err();
        let PolicyRegistryError::EndpointSetImport { error, .. } = error else {
            panic!("expected ranged import error: {error:?}")
        };
        assert!(error.diagnostic.code.contains(expected), "{error:?}");
        assert!(!error.diagnostic.range.is_empty());
        assert_eq!(registry.policies().len(), 0);
        assert_eq!(registry.endpoint_set_parse_count(), 0);
    }
}

#[test]
fn cancellation_and_entry_budget_never_register_a_partial_policy() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(temp.path().join("db.rqlp"), STORE).unwrap();
    let mut registry = registry(temp.path());
    registry.limits = registry.limits.with_max_endpoint_set_entries(3).unwrap();
    assert!(
        registry
            .register_policy_bytes(
                "p.rqlp".into(),
                policy("test", &reference("db.rqlp")).as_bytes()
            )
            .is_err()
    );
    assert_eq!(registry.policies().len(), 0);
    let token = CancellationToken::new();
    token.cancel();
    registry.set_cancellation(Some(token));
    assert!(matches!(
        registry.register_policy_bytes(
            "p.rqlp".into(),
            policy("test", &reference("db.rqlp")).as_bytes()
        ),
        Err(PolicyRegistryError::Cancelled)
    ));
    assert_eq!(registry.policies().len(), 0);
}

#[test]
fn exhausted_import_bytes_and_mid_closure_cancellation_do_not_commit_cache() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(temp.path().join("db.rqlp"), STORE).unwrap();
    let source = policy("test", &reference("db.rqlp"));
    let mut bounded = registry(temp.path());
    bounded.limits = bounded
        .limits
        .with_max_retained_source_and_selector_bytes(source.len() + STORE.len() - 1)
        .unwrap();
    assert!(
        bounded
            .register_policy_bytes("p.rqlp".into(), source.as_bytes())
            .is_err()
    );
    assert_eq!(bounded.policies().len(), 0);
    assert_eq!(bounded.endpoint_set_parse_count(), 0);
    assert!(bounded.endpoint_set_cache.is_empty());

    let mut cancelled = registry(temp.path());
    cancelled.set_cancellation(Some(CancellationToken::timeout_after_checks_for_test(3)));
    assert!(matches!(
        cancelled.register_policy_bytes("p.rqlp".into(), source.as_bytes()),
        Err(PolicyRegistryError::Cancelled)
    ));
    assert_eq!(cancelled.policies().len(), 0);
    assert_eq!(cancelled.endpoint_set_parse_count(), 0);
    assert!(cancelled.endpoint_set_cache.is_empty());
}

#[test]
fn portable_import_paths_reject_traversal_absolute_and_windows_prefixes() {
    for path in [
        "../db.rqlp",
        "/db.rqlp",
        "C:/db.rqlp",
        "C:db.rqlp",
        "//host/share/db.rqlp",
        "lib/../db.rqlp",
    ] {
        let source = policy("test", &reference(path));
        assert!(
            crate::parse_rqlp_source(&source, "p.rqlp".into()).is_err(),
            "accepted {path}"
        );
    }
}

#[cfg(unix)]
#[test]
fn imported_symlink_cannot_escape_workspace() {
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("db.rqlp"), STORE).unwrap();
    std::os::unix::fs::symlink(outside.path().join("db.rqlp"), root.path().join("db.rqlp"))
        .unwrap();
    assert!(
        registry(root.path())
            .register_policy_bytes(
                "p.rqlp".into(),
                policy("test", &reference("db.rqlp")).as_bytes()
            )
            .is_err()
    );
}
