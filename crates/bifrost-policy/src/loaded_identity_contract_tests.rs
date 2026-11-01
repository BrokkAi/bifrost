use std::sync::Arc;

use serde_json::json;

use crate::{PolicyRegistry, PolicySourceIdentity, TaintCatalogRegistry};

fn registry() -> PolicyRegistry {
    PolicyRegistry::new_without_workspace(
        Arc::new(TaintCatalogRegistry::new_without_workspace(
            Default::default(),
        )),
        Default::default(),
    )
}

fn load(text: &str) -> crate::LoadedPolicy {
    registry()
        .register_policy_bytes(
            PolicySourceIdentity::new("test-only:canonical"),
            text.as_bytes(),
        )
        .unwrap()
        .clone()
}

fn policy(stores: &str) -> String {
    format!(
        r#"(policy :id "test.canonical" :name "Canonical" :message "M" :severity warning
      :analysis (analysis :type taint :mode may
        :sources (endpoint-set :entries [(source :id raw :display-name "Raw" :categories [input.user]
          :selector (rql (call)) :bind return-value :labels [untrusted])])
        :sinks (endpoint-set :entries [(sink :id sink :display-name "Sink" :categories [data.sensitive]
          :selector (rql (call)) :dangerous-operand (argument :index 0) :accepts [untrusted])])
        {stores}))"#
    )
}

#[test]
fn loaded_stores_preserve_independent_ports_and_identity() {
    let write = r#"(store-write :id put :selector (rql (call :callee (name "put")))
      :store session :key (argument :index 0) :instance receiver :input (argument :index 1))"#;
    let read = r#"(store-read :id get :selector (rql (call :callee (name "get")))
      :store session :key (argument :index 0) :instance receiver :output return-value)"#;
    for entries in [
        write.to_string(),
        read.to_string(),
        format!("{write} {read}"),
    ] {
        let text = policy(&format!(":stores (endpoint-set :entries [{entries}])"));
        let loaded = load(&text);
        let value = loaded.to_canonical_semantic_json();
        let stores = &value["analysis"]["stores"];
        assert!(stores.is_object(), "{value:#}");
        for (kind, port, expected) in [
            (
                "writes",
                "input",
                json!({"type":"argument_index","index":1}),
            ),
            ("reads", "output", json!({"type":"return_value"})),
        ] {
            for entry in stores[kind].as_array().unwrap() {
                assert_eq!(
                    entry["definition"]["key"],
                    json!({"type":"argument_index","index":0})
                );
                assert_eq!(entry["definition"]["instance"], json!({"type":"receiver"}));
                assert_eq!(entry["definition"][port], expected);
            }
        }
        let changed = load(&text.replace(":key (argument :index 0)", ":key (argument :index 2)"));
        assert_ne!(loaded.semantic_hash(), changed.semantic_hash());
        assert_ne!(value, changed.to_canonical_semantic_json());
        assert_eq!(
            loaded.semantic_hash(),
            load(&format!("\n{text}\n")).semantic_hash()
        );
    }
}

#[test]
fn endpoint_analysis_identity_tracks_binding_but_ignores_display_metadata() {
    let text = r#"(endpoint :id "test.source" :name "Source" :display-name "Source" :role source
      :categories [input.user] :selector (rql (call)) :binding (argument :index 0)
      :taint (source-semantics :labels [untrusted]) :supersedes [])"#;
    let endpoint = |text: &str| {
        registry()
            .register_endpoint_bytes(
                PolicySourceIdentity::new("test-only:endpoint"),
                text.as_bytes(),
            )
            .unwrap()
            .clone()
    };
    let first = endpoint(text);
    let second = endpoint(&text.replace(":index 0", ":index 1"));
    assert_ne!(
        first.analysis_projection_hash(),
        second.analysis_projection_hash()
    );
    assert_eq!(
        first.to_canonical_semantic_json()["binding"],
        json!({"type":"argument_index","index":0})
    );
    let renamed = endpoint(&text.replace(":display-name \"Source\"", ":display-name \"Renamed\""));
    assert_eq!(
        first.analysis_projection_hash(),
        renamed.analysis_projection_hash()
    );
    assert_ne!(first.semantic_hash(), renamed.semantic_hash());
}

#[test]
fn directory_manifests_publish_complete_selected_endpoint_identities() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::create_dir(temp.path().join("endpoints")).unwrap();
    for id in ["alpha", "beta"] {
        std::fs::write(
            temp.path().join(format!("endpoints/{id}.rqlp")),
            format!(
                r#"
          (endpoint :id "test.{id}" :name "{id}" :display-name "{id}" :role source
            :categories [input.user] :selector (rql (call :callee (name "{id}")))
            :binding return-value :taint (source-semantics :labels [untrusted]))"#
            ),
        )
        .unwrap();
    }
    let make_registry = || {
        PolicyRegistry::new_for_workspace(
            temp.path().to_path_buf(),
            Arc::new(TaintCatalogRegistry::new_without_workspace(
                Default::default(),
            )),
            Default::default(),
        )
        .unwrap()
    };
    let text = policy("").replace(":sources (endpoint-set :entries [", ":sources (endpoint-set :include-matches [(match-directory :path \"endpoints\" :scope recursive :categories (all [input.user]))] :entries [");
    let loaded = make_registry()
        .register_policy_bytes("policy.rqlp".into(), text.as_bytes())
        .unwrap()
        .clone();
    let value = loaded.to_canonical_semantic_json();
    assert_public_projection("directory", value.clone());
    let manifests = value["match_manifests"].as_array().unwrap();
    assert_eq!(manifests.len(), 1);
    let selected = manifests[0]["selected"].as_array().unwrap();
    assert_eq!(selected.len(), 2);
    assert_eq!(manifests[0]["role"], "source");
    let mut endpoints = make_registry();
    for entry in selected {
        let id = entry["identity"]["endpoint_id"].as_str().unwrap();
        let endpoint = endpoints
            .load_endpoint_path(format!(
                "endpoints/{}.rqlp",
                id.strip_prefix("test.").unwrap()
            ))
            .unwrap();
        assert_eq!(entry["semantic_hash"], endpoint.semantic_hash().to_string());
        assert_eq!(
            entry["analysis_projection_hash"],
            endpoint.analysis_projection_hash().to_string()
        );
        assert_ne!(entry["semantic_hash"], entry["analysis_projection_hash"]);
    }
    assert_eq!(
        value,
        make_registry()
            .register_policy_bytes("policy.rqlp".into(), text.as_bytes())
            .unwrap()
            .to_canonical_semantic_json()
    );
}

#[test]
fn imported_set_content_is_published_and_changes_policy_identity() {
    let temp = tempfile::tempdir().unwrap();
    let document = |id: &str, index: u32| {
        format!(
            r#"(endpoint-set-document :kind stores
      :set (endpoint-set :entries [(store-write :id {id} :selector (rql (call))
        :store {id} :key (argument :index {index}) :input return-value)]))"#
        )
    };
    for id in ["alpha", "beta"] {
        std::fs::write(temp.path().join(format!("{id}.rqlp")), document(id, 0)).unwrap();
    }
    let make_registry = || {
        PolicyRegistry::new_for_workspace(
            temp.path().to_path_buf(),
            Arc::new(TaintCatalogRegistry::new_without_workspace(
                Default::default(),
            )),
            Default::default(),
        )
        .unwrap()
    };
    let text = policy(
        ":stores (endpoint-set :include-files [(endpoint-set-file :path \"alpha.rqlp\") (endpoint-set-file :path \"beta.rqlp\")])",
    );
    let load = || {
        make_registry()
            .register_policy_bytes("policy.rqlp".into(), text.as_bytes())
            .unwrap()
            .clone()
    };
    let first = load();
    assert_public_projection("imports", first.to_canonical_semantic_json());
    let mut expected = first
        .endpoint_set_dependencies()
        .iter()
        .map(|dependency| dependency.semantic_hash.to_string())
        .collect::<Vec<_>>();
    expected.sort();
    expected.dedup();
    assert_eq!(
        first.to_canonical_semantic_json()["endpoint_set_dependencies"],
        json!(expected)
    );
    for id in ["alpha", "beta"] {
        std::fs::write(temp.path().join(format!("{id}.rqlp")), document(id, 1)).unwrap();
        assert_ne!(first.semantic_hash(), load().semantic_hash());
        std::fs::write(temp.path().join(format!("{id}.rqlp")), document(id, 0)).unwrap();
    }
}

#[test]
fn loaded_catalog_closure_is_public_and_order_independent() {
    use crate::{
        PolicyCategoryId, PolicyId, PolicyPort, PolicySelector, SchemaVersionOrigin,
        SchemaVersionResolution, TaintCatalogDefinition, TaintEntryId, TaintLabel, TaintSourceSpec,
    };
    let mut catalogs = TaintCatalogRegistry::new_without_workspace(Default::default());
    for name in ["test.zeta", "test.alpha"] {
        catalogs
            .register(TaintCatalogDefinition {
                schema_version: 1,
                name: PolicyId::new(name).unwrap(),
                version: 1,
                categories: vec![PolicyCategoryId::new("input.user").unwrap()],
                sources: vec![TaintSourceSpec {
                    id: TaintEntryId::new("input").unwrap(),
                    display_name: name.into(),
                    categories: vec![PolicyCategoryId::new("input.user").unwrap()],
                    selector: PolicySelector::Inline {
                        schema: SchemaVersionResolution {
                            version: 1,
                            origin: SchemaVersionOrigin::Explicit,
                        },
                        query: brokk_bifrost_rql::CodeQuery::from_sexp("(call)").unwrap(),
                        resolved_locators: vec![],
                    },
                    bind: PolicyPort::ReturnValue,
                    labels: vec![TaintLabel::new("untrusted").unwrap()],
                    threat_model: None,
                    evidence: Some(crate::TaintSourceEvidence {
                        trust_boundary: Some(crate::TaintTrustBoundary::External),
                        system_entry: Some(crate::TaintSystemEntry::LocalInput),
                    }),
                }],
                sinks: vec![],
                sanitizers: vec![],
                transforms: vec![],
                external_models: vec![],
            })
            .unwrap();
    }
    let catalogs = Arc::new(catalogs);
    let a = "(catalog :name \"test.alpha\" :version 1)";
    let z = "(catalog :name \"test.zeta\" :version 1)";
    let load = |refs: &str| {
        let text = policy("").replace(
            ":sources (endpoint-set :entries [",
            &format!(":sources (endpoint-set :include-sets [{refs}] :entries ["),
        );
        PolicyRegistry::new_without_workspace(catalogs.clone(), Default::default())
            .register_policy_bytes("policy.rqlp".into(), text.as_bytes())
            .unwrap()
            .clone()
    };
    let first = load(&format!("{a} {z}"));
    let second = load(&format!("{z} {a}"));
    let value = first.to_canonical_semantic_json();
    assert_public_projection("catalogs", value.clone());
    let expected = first
        .catalogs()
        .iter()
        .map(|catalog| {
            json!({"name":catalog.name.as_str(),
        "version":catalog.version,"semantic_hash":catalog.semantic_hash.to_string()})
        })
        .collect::<Vec<_>>();
    assert_eq!(value["resolved_catalogs"], json!(expected));
    assert_eq!(value, second.to_canonical_semantic_json());
    assert_eq!(first.semantic_hash(), second.semantic_hash());
    assert_ne!(first.semantic_hash(), load(a).semantic_hash());
}

#[test]
fn single_barrier_preserves_its_authored_predicate() {
    let text = policy(
        ":barriers (endpoint-set :entries [(barrier :id scalar :value-type (intrinsic bool))])",
    );
    let first = load(&text);
    let value = first.to_canonical_semantic_json();
    assert_eq!(
        value["analysis"]["barriers"],
        json!([{"id":"scalar","value_type":{"type":"intrinsic","kind":"bool"}}])
    );
    assert_ne!(
        first.semantic_hash(),
        load(&text.replace("intrinsic bool", "intrinsic numeric")).semantic_hash()
    );
}

#[test]
fn loaded_auxiliaries_preserve_requirements_and_added_labels() {
    let text = policy(
        r#":sanitizers (endpoint-set :entries [(sanitizer :id guard
      :selector (rql (call)) :when (result true) :sanitizes receiver
      :requires [(argument :index 1 :equals true)] :removes [untrusted])])
      :transforms (endpoint-set :entries [(transform :id encode :selector (rql (call))
        :input (argument :index 0) :output return-value :removes [raw] :adds [escaped])])"#,
    );
    let first = load(&text);
    let value = first.to_canonical_semantic_json();
    assert_eq!(
        value["analysis"]["transforms"][0]["definition"]["adds"],
        json!(["escaped"])
    );
    assert!(
        value["analysis"]["sanitizers"][0]["definition"]["requires"]
            .as_array()
            .is_some_and(|items| !items.is_empty()),
        "{value:#}"
    );
    for changed in [
        text.replace(":equals true", ":equals false"),
        text.replace(":adds [escaped]", ":adds [encoded]"),
    ] {
        assert_ne!(first.semantic_hash(), load(&changed).semantic_hash());
    }
}

fn assert_public_projection(name: &str, mut value: serde_json::Value) {
    // Digests have independent identity oracles; the snapshot pins the public
    // document shape without freezing implementation-specific digest values.
    let mut stack = vec![&mut value];
    while let Some(value) = stack.pop() {
        match value {
            serde_json::Value::Object(object) => {
                for (key, value) in object {
                    if key.ends_with("hash") {
                        *value = json!("<digest>");
                    } else if key == "endpoint_set_dependencies" {
                        for hash in value.as_array_mut().unwrap() {
                            *hash = json!("<digest>");
                        }
                    } else {
                        stack.push(value);
                    }
                }
            }
            serde_json::Value::Array(values) => stack.extend(values),
            _ => {}
        }
    }
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/loaded-canonical")
        .join(format!("{name}.json"));
    let actual = format!("{}\n", serde_json::to_string_pretty(&value).unwrap());
    if std::env::var_os("BIFROST_BLESS").as_deref() == Some(std::ffi::OsStr::new("1")) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &actual).unwrap();
    }
    assert_eq!(std::fs::read_to_string(path).unwrap(), actual);
}
