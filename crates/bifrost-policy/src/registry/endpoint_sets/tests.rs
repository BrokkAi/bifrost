use super::*;
use brokk_bifrost_test_macros::hardwon;

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
    crate::test_registry_for_workspace(root)
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
fn value_type_barrier_imports_preserve_proofs_provenance_and_identity() {
    let temp = tempfile::tempdir().unwrap();
    let leaf = r#"(endpoint-set-document :kind barriers :set (endpoint-set :entries [
      (barrier :id boolean :value-type (intrinsic bool))]))"#;
    let parent = r#"(endpoint-set-document :kind barriers :set (endpoint-set
      :include-files [(endpoint-set-file :path "boolean.rqlp")]
      :entries [(barrier :id fieldless :value-type (enum :fieldless true))]))"#;
    std::fs::write(temp.path().join("boolean.rqlp"), leaf).unwrap();
    std::fs::write(temp.path().join("types.rqlp"), parent).unwrap();
    let source = policy("barrier-import", &reference("types.rqlp")).replace(":stores", ":barriers");
    let mut first_registry = registry(temp.path());
    let loaded = first_registry
        .register_policy_bytes("policy.rqlp".into(), source.as_bytes())
        .unwrap();
    let barriers = &loaded.resolved_taint().unwrap().barriers;
    assert_eq!(barriers.len(), 2);
    assert_eq!(barriers[0].value_type, ValueTypePredicate::IntrinsicBool);
    assert_eq!(barriers[1].value_type, ValueTypePredicate::FieldlessEnum);
    assert_eq!(loaded.endpoint_set_dependencies().len(), 2);
    assert!(barriers[0].origins.iter().any(|origin| matches!(origin,
        EndpointOrigin::EndpointSetFile { source, .. } if source.as_str() == "boolean.rqlp"
    )));
    assert!(
        loaded
            .resolved_selectors()
            .iter()
            .all(|selector| !selector.path.as_str().starts_with("/analysis/barriers/"))
    );
    let first_hash = loaded.semantic_hash();
    std::fs::write(
        temp.path().join("boolean.rqlp"),
        leaf.replace("(intrinsic bool)", "(enum :fieldless true)"),
    )
    .unwrap();
    let mut changed_registry = registry(temp.path());
    let changed = changed_registry
        .register_policy_bytes("policy.rqlp".into(), source.as_bytes())
        .unwrap();
    assert_ne!(
        first_hash,
        changed.semantic_hash(),
        "imported type predicates change policy meaning"
    );

    std::fs::write(
        temp.path().join("boolean.rqlp"),
        leaf.replace(":id boolean", ":id source"),
    )
    .unwrap();
    let duplicate = registry(temp.path())
        .register_policy_bytes("policy.rqlp".into(), source.as_bytes())
        .unwrap_err();
    assert!(
        duplicate
            .to_string()
            .contains("duplicate endpoint entry ID `source`"),
        "{duplicate}"
    );
    std::fs::write(
        temp.path().join("types.rqlp"),
        "(endpoint-set-document :kind sanitizers :set (endpoint-set))",
    )
    .unwrap();
    let wrong_kind = registry(temp.path())
        .register_policy_bytes("policy.rqlp".into(), source.as_bytes())
        .unwrap_err();
    assert!(
        wrong_kind.to_string().contains("expected barriers"),
        "{wrong_kind}"
    );

    let empty = policy("barrier-empty", "");
    let explicit_empty = empty.replace(":stores", ":barriers");
    let original_hash = registry(temp.path())
        .register_policy_bytes("empty.rqlp".into(), empty.as_bytes())
        .unwrap()
        .semantic_hash();
    let empty_hash = registry(temp.path())
        .register_policy_bytes("empty.rqlp".into(), explicit_empty.as_bytes())
        .unwrap()
        .semantic_hash();
    assert_eq!(
        original_hash, empty_hash,
        "empty barriers preserve pre-barrier policy hashes"
    );
}

#[test]
#[hardwon("#7150: positional policy atoms had no hover metadata")]
fn value_type_barrier_vocabulary_formats_hovers_and_rejects_unproven_syntax() {
    use crate::source::{parse_rqlp_source, rqlp_source_help_at};
    let document = r#"(endpoint-set-document :kind barriers :set (endpoint-set :entries [
      (barrier :id boolean :value-type (intrinsic bool))
      (barrier :id status :value-type (enum :fieldless true))]))"#;
    let parsed = parse_rqlp_source(document, "barriers.rqlp".into()).unwrap();
    let formatted = crate::format::format_rqlp_source(document).unwrap();
    let reparsed = parse_rqlp_source(&formatted, "barriers.rqlp".into()).unwrap();
    assert_eq!(
        parsed.document().to_normalized_authored_json(),
        reparsed.document().to_normalized_authored_json()
    );
    let hover = rqlp_source_help_at(document, document.find(":value-type").unwrap() + 2).unwrap();
    assert!(
        hover.signature.contains("intrinsic bool|numeric"),
        "{hover:?}"
    );
    let intrinsic = rqlp_source_help_at(document, document.find("intrinsic").unwrap() + 2).unwrap();
    assert_eq!(intrinsic.signature, "(intrinsic bool|numeric)");
    let boolean_offset = document.find("intrinsic bool").unwrap() + "intrinsic ".len();
    let boolean = rqlp_source_help_at(document, boolean_offset + 1).unwrap();
    assert!(boolean.description.contains("Boolean"), "{boolean:?}");
    let numeric = document.replace("intrinsic bool", "intrinsic numeric");
    let parsed_numeric = parse_rqlp_source(&numeric, "numeric.rqlp".into()).unwrap();
    assert!(
        parsed_numeric
            .document()
            .to_normalized_authored_json()
            .to_string()
            .contains("numeric")
    );
    let numeric_hover =
        rqlp_source_help_at(&numeric, numeric.find("numeric").unwrap() + 2).unwrap();
    assert!(
        numeric_hover.description.contains("Integer"),
        "{numeric_hover:?}"
    );
    for (old, new, rejected) in [
        ("intrinsic bool", "intrinsic i32", "i32"),
        ("fieldless true", "fieldless false", "false"),
        (":id boolean", ":input return-value :id boolean", ":input"),
        (":id status", ":id boolean", "boolean"),
    ] {
        let invalid = document.replace(old, new);
        let error = parse_rqlp_source(&invalid, "barriers.rqlp".into()).unwrap_err();
        assert_eq!(
            &invalid[error.diagnostic.range.clone()],
            rejected,
            "{error:?}"
        );
    }
}

#[test]
fn wildcard_identity_tracks_only_contributing_catalogs() {
    use crate::catalog::TaintCatalogDefinition;

    let temp = tempfile::tempdir().unwrap();
    let sinks = r#"(endpoint-set :include-sets [
      (catalog :any-registered true :categories (any [sql-injection]))])"#;
    std::fs::write(
        temp.path().join("sinks.rqlp"),
        format!("(endpoint-set-document :kind sinks :set {sinks})"),
    )
    .unwrap();
    let executable_hash = |set: &str, matched_name: &str, unmatched_name: &str| {
        let mut catalogs =
            TaintCatalogRegistry::new_without_workspace(CatalogRegistryLimits::default());
        for (name, category, display_name) in [
            ("test.sql", "sql-injection", matched_name),
            ("test.path", "path-injection", unmatched_name),
        ] {
            let category = PolicyCategoryId::new(category).unwrap();
            catalogs
                .register(TaintCatalogDefinition {
                    schema_version: 1,
                    name: PolicyId::new(name).unwrap(),
                    version: 1,
                    categories: vec![category.clone()],
                    sources: Vec::new(),
                    sinks: vec![TaintSinkSpec {
                        id: TaintEntryId::new("sink").unwrap(),
                        display_name: display_name.into(),
                        categories: vec![category],
                        selector: crate::test_support::inline_match_selector("sink"),
                        dangerous_operand: PolicyPort::ArgumentIndex { index: 0 },
                        accepts: vec![TaintLabel::new("untrusted").unwrap()],
                        tags: Vec::new(),
                        impacts: Vec::new(),
                    }],
                    sanitizers: Vec::new(),
                    transforms: Vec::new(),
                    external_models: Vec::new(),
                })
                .unwrap();
        }
        let mut registry = PolicyRegistry::new_for_workspace(
            temp.path().to_path_buf(),
            Arc::new(catalogs),
            PolicyRegistryLimits::default(),
        )
        .unwrap();
        let source = format!(
            r#"(policy :id "test.wildcard" :name "Wildcard" :message "flow" :severity warning
              :analysis (analysis :type taint :mode may
                :sources (endpoint-set :entries [(source :id raw :display-name "raw"
                  :categories [input.user] :selector (rql (language rust (call :callee (name "source"))))
                  :bind return-value :labels [untrusted])])
                :sinks {set}))"#
        );
        let loaded = registry
            .register_policy_bytes("policy.rqlp".into(), source.as_bytes())
            .unwrap();
        assert_eq!(loaded.catalogs().len(), 1);
        assert_eq!(loaded.catalogs()[0].name.as_str(), "test.sql");
        loaded.semantic_hash()
    };
    for set in [
        sinks,
        r#"(endpoint-set :include-files [(endpoint-set-file :path "sinks.rqlp")])"#,
    ] {
        let baseline = executable_hash(set, "SQL", "Path");
        assert_eq!(baseline, executable_hash(set, "SQL", "Changed path"));
        assert_ne!(baseline, executable_hash(set, "Changed SQL", "Path"));
    }
}

#[test]
fn conditional_sanitizer_files_are_hashed_and_validate_loaded_call_arity() {
    let temp = tempfile::tempdir().unwrap();
    let entry = r#"(sanitizer :id guard :selector (rql-file :path "guard.rql")
      :when (result true) :sanitizes (argument :index 0)
      :requires [(receiver :result-of (rql-file :path "clean.rql"))]
      :removes [untrusted])"#;
    std::fs::write(
        temp.path().join("sanitizers.rqlp"),
        format!("(endpoint-set-document :kind sanitizers :set (endpoint-set :entries [{entry}]))"),
    )
    .unwrap();
    for set in [
        format!("(endpoint-set :entries [{entry}])"),
        r#"(endpoint-set :include-files [(endpoint-set-file :path "sanitizers.rqlp")])"#.to_owned(),
    ] {
        let source = policy("guard", "").replace(":stores", &format!(":sanitizers {set} :stores"));
        std::fs::write(
            temp.path().join("guard.rql"),
            "(rql :schema-version 1 (call (arity 1)))",
        )
        .unwrap();
        std::fs::write(
            temp.path().join("clean.rql"),
            r#"(rql :schema-version 1 (call :callee (name "clean")))"#,
        )
        .unwrap();
        let before = registry(temp.path())
            .register_policy_bytes("policy.rqlp".into(), source.as_bytes())
            .unwrap()
            .semantic_hash();
        std::fs::write(
            temp.path().join("clean.rql"),
            r#"(rql :schema-version 1 (call :callee (name "other")))"#,
        )
        .unwrap();
        let after = registry(temp.path())
            .register_policy_bytes("policy.rqlp".into(), source.as_bytes())
            .unwrap()
            .semantic_hash();
        assert_ne!(
            before, after,
            "the result-of selector contents affect identity"
        );
        std::fs::write(
            temp.path().join("guard.rql"),
            "(rql :schema-version 1 (call (arity 0)))",
        )
        .unwrap();
        let error = registry(temp.path())
            .register_policy_bytes("policy.rqlp".into(), source.as_bytes())
            .unwrap_err();
        assert!(error.to_string().contains("argument index 0"), "{error}");
    }
}
