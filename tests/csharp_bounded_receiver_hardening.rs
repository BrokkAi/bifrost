mod common;

use brokk_bifrost::analyzer::structural::{CodeQuery, execute_workspace};
use brokk_bifrost::{
    AnalyzerConfig, CSharpAnalyzer, CodeUnit, CodeUnitType, IAnalyzer, Language, WorkspaceAnalyzer,
};
use common::InlineTestProject;
use serde_json::{Value, json};

fn member_function(analyzer: &CSharpAnalyzer, owner: &str, name: &str) -> CodeUnit {
    let declarations = analyzer.get_all_declarations();
    declarations
        .iter()
        .find(|unit| {
            unit.kind() == CodeUnitType::Function
                && unit.identifier() == name
                && analyzer
                    .parent_of(unit)
                    .is_some_and(|parent| parent.fq_name() == owner)
        })
        .cloned()
        .unwrap_or_else(|| panic!("missing {owner}.{name} in {declarations:#?}"))
}

fn member(analyzer: &CSharpAnalyzer, owner: &str, name: &str) -> CodeUnit {
    let declarations = analyzer.get_all_declarations();
    declarations
        .iter()
        .find(|unit| {
            unit.identifier() == name
                && analyzer
                    .parent_of(unit)
                    .is_some_and(|parent| parent.fq_name() == owner)
        })
        .cloned()
        .unwrap_or_else(|| panic!("missing {owner}.{name} in {declarations:#?}"))
}

#[test]
fn csharp_return_and_member_metadata_preserve_structured_nominal_types() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "Metadata.cs",
            r#"
namespace Demo.Models;
public class Product {}
public class Box<T> {}

public class Factory<TFactory>
{
    public Product Value { get; }
    public Box<Product> Create() => null;
    public TFactory GenericValue;
}
"#,
        )
        .build();
    let analyzer = CSharpAnalyzer::from_project(project.project().clone());

    for (member_name, expected_name, expected_generic_arguments) in [
        ("Value", "Product", None),
        ("Create", "Box`1", Some(1)),
        ("GenericValue", "TFactory", None),
    ] {
        let declaration = member(&analyzer, "Demo.Models.Factory`1", member_name);
        let metadata = analyzer
            .signature_metadata(&declaration)
            .into_iter()
            .next()
            .unwrap_or_else(|| panic!("metadata for {member_name}"));
        let identity = metadata
            .return_type_identity()
            .unwrap_or_else(|| panic!("structured return type for {member_name}: {metadata:#?}"));
        let name = identity
            .nominal_name()
            .unwrap_or_else(|| panic!("nominal type for {member_name}: {identity:#?}"));

        assert_eq!(name.path(), [expected_name], "{member_name}: {metadata:#?}");
        assert_eq!(
            name.lexical_scope(),
            ["Demo", "Models", "Factory`1"],
            "{member_name}: {metadata:#?}"
        );
        assert_eq!(
            identity.generic_argument_count(),
            expected_generic_arguments,
            "{member_name}: {metadata:#?}"
        );
    }

    let owner = analyzer
        .get_all_declarations()
        .into_iter()
        .find(|unit| unit.fq_name() == "Demo.Models.Factory`1")
        .expect("generic owner");
    let owner_metadata = analyzer
        .signature_metadata(&owner)
        .into_iter()
        .next()
        .expect("owner metadata");
    assert_eq!(owner_metadata.type_parameters(), ["TFactory"]);
}

#[test]
fn csharp_extension_receiver_metadata_is_structured_exact_and_serializable() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "Extensions.cs",
            r#"
namespace Demo;

public struct Service {}

public static class ServiceExtensions
{
    public static void Extend([ReceiverMarker] this ref Demo.Service value) {}
    public static void Ordinary(Demo.Service value) {}
}

public class Caller
{
    public void Call()
    {
        var service = new Service();
        service.Extend();
    }
}
"#,
        )
        .build();
    let analyzer = CSharpAnalyzer::from_project(project.project().clone());
    let extension = member_function(&analyzer, "Demo.ServiceExtensions", "Extend");
    let ordinary = member_function(&analyzer, "Demo.ServiceExtensions", "Ordinary");

    let extension_metadata = analyzer
        .signature_metadata(&extension)
        .into_iter()
        .next()
        .expect("extension signature metadata");
    assert_eq!(
        extension_metadata.extension_receiver_type(),
        Some("Demo.Service")
    );
    let receiver_identity = extension_metadata
        .extension_receiver_type_identity()
        .expect("structured extension receiver type");
    let receiver_name = receiver_identity
        .nominal_name()
        .expect("nominal extension receiver type");
    assert_eq!(receiver_name.path(), ["Demo", "Service"]);
    assert_eq!(receiver_name.lexical_scope(), ["Demo", "ServiceExtensions"]);
    assert!(
        analyzer
            .signature_metadata(&ordinary)
            .into_iter()
            .all(|metadata| metadata.extension_receiver_type().is_none()
                && metadata.extension_receiver_type_identity().is_none())
    );

    let encoded = serde_json::to_value(&extension_metadata).expect("serialize metadata");
    assert_eq!(encoded["extension_receiver_type"], "Demo.Service");
    assert!(
        encoded["extension_receiver_type_identity"].is_object(),
        "{encoded}"
    );
    let decoded: brokk_bifrost::analyzer::SignatureMetadata =
        serde_json::from_value(encoded.clone()).expect("deserialize metadata");
    assert_eq!(decoded, extension_metadata);

    let mut legacy = encoded;
    legacy
        .as_object_mut()
        .expect("metadata object")
        .remove("extension_receiver_type");
    legacy
        .as_object_mut()
        .expect("metadata object")
        .remove("extension_receiver_type_identity");
    let legacy: brokk_bifrost::analyzer::SignatureMetadata =
        serde_json::from_value(legacy).expect("deserialize legacy metadata");
    assert_eq!(legacy.extension_receiver_type(), None);
    assert_eq!(legacy.extension_receiver_type_identity(), None);

    let workspace = WorkspaceAnalyzer::build(project.project_dyn(), AnalyzerConfig::default());
    let query = CodeQuery::from_json(&json!({
        "languages": ["csharp"],
        "match": {
            "kind": "call",
            "callee": { "name": "Extend" },
            "receiver": { "name": "service" }
        },
        "steps": [{ "op": "member_targets" }]
    }))
    .expect("extension receiver query");
    let result = execute_workspace(&workspace, &query);
    let value: Value = serde_json::to_value(&result).expect("serialize query result");

    assert_eq!(value["results"][0]["outcome"], "precise", "{value}");
    assert_eq!(
        value["results"][0]["member_targets"][0]["fq_name"], "Demo.ServiceExtensions.Extend",
        "{value}"
    );
}
