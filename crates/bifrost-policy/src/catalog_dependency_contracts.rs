use crate::*;

fn catalog_manifest(hash: &str) -> String {
    format!(
        r#"{{"schema_version":2,"id":"test.dependencies","version":"1.0.0","name":"Dependencies","description":"Test fixture","policies":[],"catalogs":[{{"path":"catalog.json","semantic_hash":"{hash}"}}]}}"#
    )
}

#[test]
fn embedded_catalog_requires_lowercase_content_identity() {
    let lower = "a".repeat(64);
    BuiltInPolicyCatalog::from_embedded_packs(vec![EmbeddedPolicyPack::new(catalog_manifest(
        &lower,
    ))])
    .unwrap();
    let error = BuiltInPolicyCatalog::from_embedded_packs(vec![EmbeddedPolicyPack::new(
        catalog_manifest(&lower.to_uppercase()),
    )])
    .unwrap_err();
    assert_eq!(error.code(), "built-in-policy-catalog-invalid");
}

#[test]
fn embedded_inventory_rejects_unlisted_sources() {
    let error = BuiltInPolicyCatalog::from_embedded_packs(vec![
        EmbeddedPolicyPack::new(catalog_manifest(&"a".repeat(64)))
            .with_source("extra.rqlp", "unlisted"),
    ])
    .unwrap_err();
    assert_eq!(error.code(), "built-in-policy-catalog-invalid");
    assert!(error.to_string().contains("paths do not exactly match"));
}

#[test]
fn source_identity_preserves_final_newline() {
    assert_ne!(
        PolicySourceHash::from_source_bytes(b"policy"),
        PolicySourceHash::from_source_bytes(b"policy\n")
    );
}

#[test]
fn selection_exclusions_are_unique_and_deterministic() {
    let catalog = BuiltInPolicyCatalog::without_rules().unwrap();
    let a = BuiltInPolicySelectionRecord::new(&catalog, &[], &["z".into(), "a".into(), "z".into()]);
    let b = BuiltInPolicySelectionRecord::new(&catalog, &[], &["a".into(), "z".into()]);
    assert_eq!(a, b);
}

#[test]
fn catalog_authored_identity_distinguishes_references() {
    let source = |name: &str| {
        format!(
            r#"(policy :id "test.catalog" :name "Catalog" :message (generated-message :relation can-reach) :severity warning :analysis (analysis :type taint :mode may :sources (endpoint-set :include-sets [(catalog :name "{name}" :version 1)]) :sinks (endpoint-set)))"#
        )
    };
    let identity = |text: String| {
        policy_source_identity(PolicySourceIdentity::new("test.rqlp"), text.as_bytes()).unwrap()
    };
    let a = identity(source("test.first"));
    let b = identity(source("test.second"));
    assert_ne!(a.authored_hash, b.authored_hash);
}

#[test]
fn flow_and_entry_point_sets_reject_direct_catalog_imports() {
    for (analysis, group) in [("flow", "origins"), ("taint", "entry-points")] {
        let empty = if analysis == "flow" {
            ":observations (endpoint-set)"
        } else {
            ":sources (endpoint-set) :sinks (endpoint-set)"
        };
        let source = format!(
            r#"(policy :id "test.catalog" :name "Catalog" :message (generated-message :relation can-reach) :severity warning :analysis (analysis :type {analysis} :mode may {empty} :{group} (endpoint-set :include-sets [(catalog :name "test.inputs" :version 1)])))"#
        );
        let error = parse_rqlp_source(&source, PolicySourceIdentity::new("test.rqlp")).unwrap_err();
        assert_eq!(error.diagnostic.code, "field-not-allowed");
        assert!(error.diagnostic.message.contains(":include-sets"));
    }
}
