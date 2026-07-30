use brokk_bifrost::analyzer::semantic_model::{
    ActivationSelector, ArtifactProducerLimits, ArtifactProductionRequest, AuthoredPayload,
    Compatibility, CompilerOptions, Completeness, ExternalArtifactKind,
    ExternalArtifactPackProducer, NameSelector, Provenance, Safety, compile_pack,
};
use brokk_bifrost::analyzer::{
    CSharpAssemblyPackProducer, JavaJarPackProducer, Language, Project, TestProject,
};
use std::io::Write;
use std::process::Command;
use zip::write::SimpleFileOptions;

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

#[test]
fn java_source_and_class_share_declaration_ids() {
    if !jdk_tool_available("javac") || !jdk_tool_available("jar") {
        eprintln!("skipping Java pack integration: javac and jar are required");
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let source_root = temp.path().join("src/fixture");
    let classes = temp.path().join("classes");
    std::fs::create_dir_all(&source_root).unwrap();
    std::fs::create_dir(&classes).unwrap();
    let source = "package fixture; public class Api<T> { public Api() {} public <U> U map(U value) { return value; } }\n";
    let source_file = source_root.join("Api.java");
    std::fs::write(&source_file, source).unwrap();
    let source_jar = temp.path().join("fixture-sources.jar");
    let mut zip = zip::ZipWriter::new(std::fs::File::create(&source_jar).unwrap());
    zip.start_file("fixture/Api.java", SimpleFileOptions::default())
        .unwrap();
    zip.write_all(source.as_bytes()).unwrap();
    zip.finish().unwrap();
    run_jdk(
        Command::new("javac")
            .arg("-parameters")
            .arg("-d")
            .arg(&classes)
            .arg(&source_file),
    );
    let class_jar = temp.path().join("fixture.jar");
    run_jdk(
        Command::new("jar")
            .current_dir(&classes)
            .arg("cf")
            .arg(&class_jar)
            .arg("."),
    );

    let source_production = JavaJarPackProducer.produce_exact_artifact(
        &java_request(source_jar, ExternalArtifactKind::JavaSourceJar),
        &ArtifactProducerLimits::default(),
    );
    let class_production = JavaJarPackProducer.produce_exact_artifact(
        &java_request(class_jar, ExternalArtifactKind::JavaClassJar),
        &ArtifactProducerLimits::default(),
    );
    assert!(
        source_production.diagnostics.is_empty(),
        "{:?}",
        source_production.diagnostics
    );
    assert!(
        class_production.diagnostics.is_empty(),
        "{:?}",
        class_production.diagnostics
    );
    let source_pack = source_production.pack.as_ref().unwrap();
    let class_pack = class_production.pack.as_ref().unwrap();
    let AuthoredPayload::DeclarationFacts {
        types: source_types,
        members: source_members,
        ..
    } = &source_pack.shards[0].payload
    else {
        panic!("source producer must emit declarations");
    };
    let AuthoredPayload::DeclarationFacts {
        types: class_types,
        members: class_members,
        ..
    } = &class_pack.shards[0].payload
    else {
        panic!("class producer must emit declarations");
    };
    let source_type = source_types
        .iter()
        .find(|fact| fact.name == "fixture.Api")
        .unwrap();
    let class_type = class_types
        .iter()
        .find(|fact| fact.name == "fixture.Api")
        .unwrap();
    assert_eq!(source_type.id, class_type.id);
    let source_method = source_members
        .iter()
        .find(|fact| fact.owner == source_type.id && fact.name == "map")
        .unwrap();
    let class_method = class_members
        .iter()
        .find(|fact| fact.owner == class_type.id && fact.name == "map")
        .unwrap();
    assert_eq!(source_method.id, class_method.id);
}

fn java_request(
    path: std::path::PathBuf,
    artifact_kind: ExternalArtifactKind,
) -> ArtifactProductionRequest {
    let mut request = request(path);
    request.artifact_kind = artifact_kind;
    request.pack_id = "fixture.java-api".to_owned();
    request.ecosystem = "maven".to_owned();
    request.activation[0].package.as_mut().unwrap().name = "fixture:java-api".to_owned();
    request
}

fn jdk_tool_available(tool: &str) -> bool {
    Command::new(tool)
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success())
}

fn run_jdk(command: &mut Command) {
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "JDK command failed: {command:?}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
