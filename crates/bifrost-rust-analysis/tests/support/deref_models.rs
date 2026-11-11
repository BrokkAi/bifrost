// Test-only trimmed generated declarations and separate reviewed summaries.
use brokk_bifrost_analysis::analyzer::semantic_model::*;
use brokk_bifrost_core::cancellation::CancellationToken;
pub fn activate(
    analyzer: &dyn brokk_bifrost_analysis::analyzer::IAnalyzer,
    summary: Option<bool>,
    certified: bool,
) -> (SemanticPackCatalog, SemanticModelActivationRequest) {
    let models = models(summary, certified);
    let catalog = SemanticPackCatalog::open_ephemeral(Default::default()).unwrap();
    for model in models {
        let mut source: AuthoredSemanticModelPack = serde_json::from_value(model.clone()).unwrap();
        if source.pack_id == "bifrost.rust-stdlib" {
            // Only a producer can set extraction authority; authored JSON
            // cannot carry it, including this explicit test-only source.
            source.extraction = Some(ArtifactExtraction::source_set(
                ArtifactExtractionKind::RustdocJsonSet,
                &"a".repeat(64),
            ));
        }
        let pack = compile_pack(&source, &CompilerOptions::default())
            .unwrap_or_else(|errors| panic!("deref fixture compilation: {errors:?}"));
        catalog
            .register_session_pack(
                &pack,
                &SessionPackSource {
                    kind: SessionPackSourceKind::Embedded,
                    source_id: model["pack_id"].as_str().unwrap().to_owned(),
                },
            )
            .unwrap();
    }
    let request = SemanticModelActivationRequest {
        approximate_standard_libraries: vec![],
        bifrost_version: semver::Version::parse(env!("CARGO_PKG_VERSION")).unwrap(),
        evidence: vec![SemanticModelActivationEvidence {
            language: "rust".into(),
            ecosystem: "cargo".into(),
            package: Some(CatalogCoordinate {
                name: "std".into(),
                version: None,
            }),
            module: None,
            toolchain: None,
            target: None,
            configuration: None,
            artifact_sha256: Some(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            ),
        }],
        controls: ["bifrost.rust-stdlib", "test.std-deref-companion"]
            .into_iter()
            .map(|pack_id| SemanticModelActivationControl {
                scope: SemanticModelControlScope::Workspace,
                action: SemanticModelControlAction::Enable,
                selector: SemanticModelPackSelector {
                    pack_id: pack_id.into(),
                    version: None,
                    manifest_digest: None,
                },
            })
            .collect(),
        limits: SemanticModelRuntimeLimits::default(),
    };
    assert!(matches!(
        acquire_active_semantic_models(
            analyzer,
            &catalog,
            None,
            &request,
            &CancellationToken::default()
        ),
        SemanticModelRuntimeOutcome::Ready { .. }
    ));
    (catalog, request)
}
// Shared source fixtures also exercise toolchain-keyed companion activation.
pub fn models(summary: Option<bool>, certified: bool) -> Vec<serde_json::Value> {
    let mut string = rust_type("alloc.string.String", "struct");
    string["aliases"] = serde_json::json!(["std.string.String"]);
    string["implemented_traits_complete"] = true.into();
    string["implemented_traits"] = serde_json::json!([{
        "trait_type": {"kind":"named", "name":"core.ops.Deref"},
        "associated_types": [{"name":"Target", "type":{"kind":"named", "name":"str"}}]
    }]);
    let deref_id = "member.fixture.string-deref.trait.core-deref";
    let deref_symbol = format!("alloc.string.String.deref#{deref_id}");
    let deref = serde_json::json!({
        "id":deref_id,"owner":string["id"],"name":"deref","member_kind":"method",
        "visibility":"public","is_static":false,"callable_family_complete":certified,
        "implemented_trait":{"kind":"named","name":"core.ops.Deref"},
        "self_form":{"kind":"shared"},
        "signature":{"parameters":[],"returns":{"kind":"by_ref","element":{"kind":"named","name":"str"}}},
        "receiver":{"pointer":false},
        "locator":{"kind":"artifact","path":"alloc.json","symbol":deref_symbol}
    });
    let contains = serde_json::json!({
        "id":"member.fixture.str-contains","owner":"type.fixture.core-primitive-str",
        "name":"contains","member_kind":"method","visibility":"public","is_static":false,
        "callable_family_complete":true,"self_form":{"kind":"shared"},
        "signature":{"parameters":[{"name":"pattern","type":{"kind":"named","name":"str"}}],
            "returns":{"kind":"named","name":"bool"}},
        "receiver":{"pointer":false},
        "locator":{"kind":"artifact","path":"core.json","symbol":"core.primitive.str.contains"}
    });
    let mut declarations = serde_json::json!({
        "schema_version":22,"pack_id":"bifrost.rust-stdlib","version":"0.0.0",
        "producer":{"name":"test-only-rustdoc","version":"0.0.0"},
        "language":"rust","ecosystem":"cargo","compatibility":{"toolchains":[]},
        "provenance":{"source":"explicitly test-only trimmed std Deref declarations"},
        "license":"NOASSERTION","completeness":"complete",
        "safety":{"generated_code_only":true,"review_required":false},
        "shards":[{"id":"test.declarations","activation":[{"targets":[],"configurations":[]}],
            "payload":{"kind":"declaration_facts","types":[
                rust_type("alloc","module"), rust_type("alloc.string","module"), string,
                rust_type("std","module"), rust_type("std.string","module"),
                rust_type("core","module"), rust_type("core.ops","module"), rust_type("core.ops.Deref","trait"),
                rust_type("core.primitive","module"),rust_type("core.primitive.str","struct")
            ],"members":[deref,contains],"relations":[]}}]
    });
    let mut companion = serde_json::json!({
        "schema_version":22,"pack_id":"test.std-deref-companion","version":"0.0.0",
        "producer":{"name":"test-only-deref-summaries","version":"0.0.0"},
        "language":"rust","ecosystem":"cargo","compatibility":{"toolchains":[]},
        "provenance":{"source":"explicitly test-only reviewed Deref summary"},
        "license":"NOASSERTION","completeness":"complete",
        "safety":{"generated_code_only":false,"review_required":true},
        "shards":[{"id":"test.summaries","activation":[{"targets":[],"configurations":[]}],
            "payload":{"kind":"procedure_summaries","summaries":[{
                "id":"test.string-deref","target":{"path":"alloc.json","symbol":deref_symbol,"has_receiver":true,"parameter_count":0},
                "completeness":if summary==Some(true) {"complete"}else{"partial"},
                "ordinary_heap_unchanged":summary==Some(true),"no_concurrency_effects":summary==Some(true),
                "transfers":[{"input":{"kind":"receiver"},"exit_kind":"normal","output":{"kind":"normal_return"},
                    "value_transfer":{"kind":{"kind":"conversion","preservation":"identity"},"operation":{"kind":"none"}}}],
                "effects":[]
            }]}}]
    });
    let mut pathbuf = rust_type("std.path.PathBuf", "struct");
    pathbuf["implemented_traits_complete"] = true.into();
    pathbuf["implemented_traits"] = serde_json::json!([{
        "trait_type":{"kind":"named","name":"core.ops.Deref"},
        "associated_types":[{"name":"Target","type":{"kind":"named","name":"std.path.Path"}}]
    }]);
    let payload = &mut declarations["shards"][0]["payload"];
    payload["types"].as_array_mut().unwrap().extend([
        rust_type("std.path", "module"),
        rust_type("std.path.Path", "struct"),
        pathbuf,
    ]);
    let mut path_deref = payload["members"][0].clone();
    path_deref["id"] = "member.fixture.pathbuf-deref.trait.core-deref".into();
    path_deref["owner"] = "type.fixture.std-path-pathbuf".into();
    path_deref["callable_family_complete"] = true.into();
    path_deref["signature"]["returns"]["element"]["name"] = "std.path.Path".into();
    path_deref["locator"]["path"] = "std.json".into();
    path_deref["locator"]["symbol"] =
        "std.path.PathBuf.deref#member.fixture.pathbuf-deref.trait.core-deref".into();
    let mut prefix = payload["members"][1].clone();
    prefix["id"] = "member.fixture.path-starts-with".into();
    prefix["owner"] = "type.fixture.std-path-path".into();
    prefix["name"] = "starts_with".into();
    prefix["locator"]["path"] = "std.json".into();
    prefix["locator"]["symbol"] = "std.path.Path.starts_with".into();
    payload["members"]
        .as_array_mut()
        .unwrap()
        .extend([path_deref.clone(), prefix]);
    let mut mutable_target = payload["members"][1].clone();
    mutable_target["id"] = "member.fixture.str-mutate".into();
    mutable_target["name"] = "mutate".into();
    mutable_target["self_form"]["kind"] = "mutable".into();
    mutable_target["signature"]["parameters"] = serde_json::json!([]);
    mutable_target["signature"]["returns"] = serde_json::Value::Null;
    mutable_target["locator"]["symbol"] = "core.primitive.str.mutate".into();
    payload["members"]
        .as_array_mut()
        .unwrap()
        .push(mutable_target);
    let mut path_summary = companion["shards"][0]["payload"]["summaries"][0].clone();
    path_summary["id"] = "test.pathbuf-deref".into();
    path_summary["target"]["path"] = path_deref["locator"]["path"].clone();
    path_summary["target"]["symbol"] = path_deref["locator"]["symbol"].clone();
    companion["shards"][0]["payload"]["summaries"]
        .as_array_mut()
        .unwrap()
        .push(path_summary);
    let mut as_str = declarations["shards"][0]["payload"]["members"][0].clone();
    as_str["id"] = "member.fixture.string-as-str".into();
    as_str["name"] = "as_str".into();
    as_str["callable_family_complete"] = true.into();
    as_str.as_object_mut().unwrap().remove("implemented_trait");
    as_str["locator"]["symbol"] = "alloc.string.String.as_str".into();
    declarations["shards"][0]["payload"]["members"]
        .as_array_mut()
        .unwrap()
        .push(as_str);
    let mut view_summary = companion["shards"][0]["payload"]["summaries"][0].clone();
    view_summary["id"] = "test.string-as-str".into();
    view_summary["target"]["symbol"] = "alloc.string.String.as_str".into();
    companion["shards"][0]["payload"]["summaries"]
        .as_array_mut()
        .unwrap()
        .push(view_summary);
    std::iter::once(declarations).chain(summary.map(|_| companion)).collect()
}

fn rust_type(name: &str, type_kind: &str) -> serde_json::Value {
    serde_json::json!({
        "id": format!(
            "type.fixture.{}",
            name.replace('.', "-").to_ascii_lowercase()
        ),
        "name": name,
        "type_kind": type_kind,
        "visibility": "public",
        "locator": {
            "kind": "artifact",
            "path": "library/std/src/lib.rs",
            "symbol": name
        }
    })
}
