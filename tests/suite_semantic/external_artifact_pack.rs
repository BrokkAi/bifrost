use brokk_bifrost::analyzer::semantic_model::{
    ActivationSelector, ArtifactProducerLimits, ArtifactProductionRequest, AuthoredPayload,
    Compatibility, CompilerOptions, Completeness, ExternalArtifactKind,
    ExternalArtifactPackProducer, NameSelector, Provenance, Safety, compile_pack,
};
use brokk_bifrost::analyzer::{CSharpAssemblyPackProducer, Language, Project, TestProject};

const DLL: &[u8] = include_bytes!("../fixtures/csharp-external/ExternalLibrary.dll");

fn request(path: std::path::PathBuf) -> ArtifactProductionRequest {
    ArtifactProductionRequest {
        path,
        artifact_kind: ExternalArtifactKind::DotNetAssembly,
        pack_id: "fixture.external-library".to_owned(),
        pack_version: "1.0.0".to_owned(),
        ecosystem: "nuget".to_owned(),
        compatibility: Compatibility {
            bifrost: ">=0.8.0, <1.0.0".to_owned(),
            toolchains: Vec::new(),
        },
        activation: vec![ActivationSelector {
            package: Some(NameSelector {
                name: "fixture:external-library".to_owned(),
                version: Some("1.0.0".to_owned()),
            }),
            module: None,
            toolchain: None,
            targets: Vec::new(),
            configurations: Vec::new(),
            artifact_sha256: None,
        }],
        provenance: Provenance {
            source: "checked-in fixture".to_owned(),
            revision: None,
        },
        license: "MIT".to_owned(),
        safety: Safety {
            generated_code_only: false,
            review_required: false,
        },
    }
}

#[test]
fn csharp_repeated_production_is_byte_identical_and_external() {
    let temp = tempfile::tempdir().unwrap();
    let project_root = temp.path().join("workspace");
    std::fs::create_dir(&project_root).unwrap();
    let source = project_root.join("Probe.cs");
    let assembly = temp.path().join("ExternalLibrary.dll");
    std::fs::write(&source, "class Probe {}\n").unwrap();
    std::fs::write(&assembly, DLL).unwrap();
    let project = TestProject::new(&project_root, Language::CSharp);
    let files_before = project.all_files().unwrap();

    let first = CSharpAssemblyPackProducer.produce_exact_artifact(
        &request(assembly.clone()),
        &ArtifactProducerLimits::default(),
    );
    let second = CSharpAssemblyPackProducer
        .produce_exact_artifact(&request(assembly), &ArtifactProducerLimits::default());

    assert_eq!(first.completeness, Completeness::Complete);
    assert!(first.diagnostics.is_empty(), "{:?}", first.diagnostics);
    let first_pack = first.pack.as_ref().expect("first C# pack");
    let second_pack = second.pack.as_ref().expect("second C# pack");
    assert_eq!(
        compile_pack(first_pack, &CompilerOptions::default()).unwrap(),
        compile_pack(second_pack, &CompilerOptions::default()).unwrap()
    );
    let AuthoredPayload::DeclarationFacts { types, members, .. } = &first_pack.shards[0].payload
    else {
        panic!("producer must emit declarations");
    };
    assert!(types.iter().any(|fact| fact.name == "Fixture.Api.Client`1"));
    assert!(members.iter().any(|fact| fact.name == "Convert"));
    assert_eq!(project.all_files().unwrap(), files_before);
    assert!(
        files_before
            .iter()
            .all(|file| file.abs_path() != temp.path().join("ExternalLibrary.dll"))
    );
}
