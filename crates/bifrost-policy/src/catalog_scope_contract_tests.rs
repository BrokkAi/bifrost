use crate::*;

fn catalog(name: &str, count: usize) -> TaintCatalogDefinition {
    TaintCatalogDefinition {
        schema_version: 1,
        name: PolicyId::new(name).unwrap(),
        version: 1,
        categories: vec![PolicyCategoryId::new("input.user").unwrap()],
        sources: (0..count)
            .map(|i| {
                crate::test_support::taint_source_spec(
                    &format!("s{i}"),
                    "Input",
                    "input",
                    "untrusted",
                )
            })
            .collect(),
        sinks: vec![],
        sanitizers: vec![],
        transforms: vec![],
        external_models: vec![],
    }
}

#[test]
fn catalog_source_labels_preserve_printable_provenance_and_reject_controls() {
    for size in [256, 257, 1024] {
        assert!(CatalogSourceIdentity::new("a".repeat(size)).is_ok());
    }
    assert_eq!(
        CatalogSourceIdentity::new("a".repeat(1025)),
        Err(CatalogSourceIdentityError::TooLong)
    );
    for label in ["catalog\nforged.json", "catalog\0.json"] {
        assert_eq!(
            CatalogSourceIdentity::new(label),
            Err(CatalogSourceIdentityError::ControlCharacter)
        );
    }
}

#[test]
fn catalog_identity_limit_admits_hard_maximum_and_reports_attempted_value() {
    assert!(
        CatalogRegistryLimits::default()
            .with_max_identities(1024)
            .is_ok()
    );
    let error = CatalogRegistryLimits::default()
        .with_max_identities(1025)
        .unwrap_err()
        .to_string();
    assert!(error.contains("1025"), "{error}");
    assert!(error.contains("1024"), "{error}");
}

#[test]
fn catalog_versions_coexist_without_identity_collision() {
    let mut registry = TaintCatalogRegistry::new_without_workspace(Default::default());
    registry.register(catalog("test.input", 1)).unwrap();
    let mut second = catalog("test.input", 2);
    second.version = 2;
    registry.register(second).unwrap();
    assert_eq!(registry.len(), 2);
    assert_eq!(
        registry
            .iter()
            .map(|c| c.identity().version)
            .collect::<std::collections::HashSet<_>>(),
        [1, 2].into_iter().collect()
    );
}

#[test]
fn catalog_json_byte_limit_and_path_diagnostics() {
    let mut registry = TaintCatalogRegistry::new_without_workspace(Default::default());
    registry.register(catalog("test.input", 1)).unwrap();
    let mut bytes = registry.iter().next().unwrap().canonical_json().to_vec();
    bytes.resize(MAX_CATALOG_JSON_BYTES, b' ');
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("MixedCase")).unwrap();
    std::fs::write(root.path().join("MixedCase/Other.json"), &bytes).unwrap();
    let mut workspace =
        TaintCatalogRegistry::new_for_workspace(root.path().to_path_buf(), Default::default())
            .unwrap();
    workspace
        .register_json_path("MixedCase/Other.json")
        .unwrap();
    registry
        .register_json_bytes(CatalogSourceIdentity::new("input.json").unwrap(), &bytes)
        .unwrap();
    bytes.push(b' ');
    assert!(matches!(
        registry.register_json_bytes(CatalogSourceIdentity::new("input.json").unwrap(), &bytes),
        Err(CatalogRegistryError::JsonTooLarge { .. })
    ));
    std::fs::write(root.path().join("MixedCase/Other.json"), b"{").unwrap();
    let error = workspace
        .register_json_path("MixedCase/Other.json")
        .unwrap_err();
    match error {
        CatalogRegistryError::InvalidJson { source, .. } => {
            assert_eq!(source.as_str(), "MixedCase/Other.json")
        }
        other => panic!("{other}"),
    }
}

#[test]
fn catalog_cumulative_entries_admit_exact_capacity() {
    let mut registry = TaintCatalogRegistry::new_without_workspace(Default::default());
    for i in 0..16 {
        registry
            .register(catalog(&format!("test.c{i}"), 4096))
            .unwrap();
    }
    assert!(matches!(
        registry.register(catalog("test.overflow", 1)),
        Err(CatalogRegistryError::RegistryEntryLimit { .. })
    ));
    assert_eq!(registry.len(), 16);
}

#[test]
fn catalog_deep_unknown_field_reports_the_wire_error() {
    let bytes = format!("{{\"unknown\":{}0{}}}", "[".repeat(70), "]".repeat(70));
    let mut registry = TaintCatalogRegistry::new_without_workspace(Default::default());
    let error = registry
        .register_json_bytes(
            CatalogSourceIdentity::new("deep.json").unwrap(),
            bytes.as_bytes(),
        )
        .unwrap_err()
        .to_string();
    assert!(error.contains("unknown field"), "{error}");
}

#[test]
fn scope_distinct_policy_selectors_are_valid_and_exclusions_are_existential() {
    let doc = parse_policy_scope_document(r#"{"schema_version":1,"scopes":[{"path":"tests","reason":"first","exclude_roots":true,"policy_ids":["test.first"]},{"path":"tests","reason":"second","exclude_roots":true,"policy_ids":["test.second"]}]}"#).unwrap();
    assert_eq!(doc.scopes().len(), 2);
    assert!(doc.excludes_root("tests/a.py", &PolicyId::new("test.first").unwrap(), &[]));
    let empty = parse_policy_scope_document(r#"{"schema_version":1,"scopes":[]}"#).unwrap();
    assert!(!empty.excludes_root("tests/a.py", &PolicyId::new("test.first").unwrap(), &[]));
}

#[test]
fn scope_count_limit_admits_exact_capacity() {
    let scopes: Vec<_> = (0..257)
        .map(|i| serde_json::json!({"path":format!("p{i}"),"reason":"accepted"}))
        .collect();
    let source = |items: &[serde_json::Value]| {
        serde_json::json!({"schema_version":1,"scopes":items}).to_string()
    };
    assert!(parse_policy_scope_document(&source(&scopes[..256])).is_ok());
    assert!(matches!(
        parse_policy_scope_document(&source(&scopes)),
        Err(PolicyScopeDocumentError::Validation(
            PolicyScopeValidationError::TooManyScopes { .. }
        ))
    ));
}

#[test]
fn scope_json_errors_preserve_line_and_column() {
    let error =
        parse_policy_scope_document("{\n  \"schema_version\": 1,\n  \"scopes\": !\n}").unwrap_err();
    assert!(
        matches!(
            error,
            PolicyScopeDocumentError::JsonDecode {
                line: 3,
                column: 13,
                ..
            }
        ),
        "{error}"
    );
}

#[test]
fn external_model_only_catalog_is_nonempty() {
    let mut definition = catalog("test.external", 0);
    definition.external_models.push(TaintExternalModelSpec {
        categories: vec![],
        id: TaintEntryId::new("transfer").unwrap(),
        selector: crate::test_support::inline_match_selector("transfer"),
        transfers: vec![TaintTransferSpec {
            from: PolicyPort::ArgumentIndex { index: 0 },
            to: PolicyPort::ReturnValue,
            labels: vec![TaintLabel::new("untrusted").unwrap()],
            effect: TaintTransferEffect::Propagate,
        }],
    });
    let mut registry = TaintCatalogRegistry::new_without_workspace(Default::default());
    registry.register(definition).unwrap();
    assert_eq!(registry.len(), 1);
}

#[test]
fn catalog_canonical_byte_admission_counts_payloads() {
    let mut registry = TaintCatalogRegistry::new_without_workspace(Default::default());
    let mut total = 0;
    for i in 0..16 {
        let mut definition = catalog(&format!("test.c{i:02}"), 2048);
        for source in &mut definition.sources {
            source.display_name = "x".repeat(4096);
        }
        let mut isolated = TaintCatalogRegistry::new_without_workspace(Default::default());
        isolated.register(definition.clone()).unwrap();
        let bytes = isolated.iter().next().unwrap().canonical_json().len();
        if total + bytes > MAX_CATALOG_RETAINED_CANONICAL_BYTES {
            assert!(matches!(
                registry.register(definition),
                Err(CatalogRegistryError::RegistryCanonicalByteLimit { .. })
            ));
            assert_eq!(registry.len(), i);
            return;
        }
        registry.register(definition).unwrap();
        total += bytes;
    }
    panic!("fixture never crossed canonical byte capacity");
}
