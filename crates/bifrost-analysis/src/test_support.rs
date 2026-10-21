//! Shared test fixtures used across crate unit tests. Each fixture
//! materializes a `TempDir` workspace, builds a `WorkspaceAnalyzer` over
//! it, and exposes both for assertions. Test-only.

#[cfg(test)]
pub(crate) use brokk_bifrost_core::test_support::write_file;

/// Engine fixture shared with surface regression tests in the tools crate.
pub const RUST_CFG_DECORATED_MACROS_SOURCE: &str =
    include_str!("../fixtures/rust_cfg_decorated_macros.rs");

/// Build fixed non-source inputs for read-ledger verification tests.
#[cfg(any(test, feature = "test-support"))]
pub fn read_ledger_test_inputs() -> crate::analyzer::HeadInputs {
    use crate::analyzer::semantic::ids::StableDigest;

    crate::analyzer::HeadInputs {
        models: StableDigest::sha256("models"),
        policy_semantic_hash: StableDigest::sha256("policy-semantic"),
        policy_source: StableDigest::sha256("policy-source"),
        configuration: StableDigest::sha256("configuration"),
        epoch: StableDigest::sha256("epoch"),
    }
}

/// Run a fixture command and include its output if it fails.
pub fn run_command_success(command: &mut std::process::Command) {
    let output = command
        .output()
        .unwrap_or_else(|error| panic!("failed to run fixture command {command:?}: {error}"));
    assert!(
        output.status.success(),
        "fixture command failed: {command:?}\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Build the shared request shape for a Maven source-jar fixture.
#[allow(clippy::too_many_arguments)] // These are the fixture-specific values in one Maven source-jar request.
pub fn jvm_source_jar_request(
    path: PathBuf,
    artifact_kind: crate::analyzer::semantic_model::ExternalArtifactKind,
    pack_id: &str,
    language: &str,
    package: &str,
    version: &str,
    targets: Vec<String>,
    provenance: crate::analyzer::semantic_model::Provenance,
) -> crate::analyzer::semantic_model::ArtifactProductionRequest {
    use crate::analyzer::semantic_model::{
        ActivationSelector, ArtifactProductionRequest, Compatibility, NameSelector, Safety,
        VersionConstraint,
    };

    ArtifactProductionRequest {
        path,
        artifact_kind,
        pack_id: pack_id.to_owned(),
        pack_version: version.to_owned(),
        ecosystem: "maven".to_owned(),
        compatibility: Compatibility {
            bifrost: None,
            toolchains: vec![VersionConstraint {
                name: language.to_owned(),
                requirement: format!("={version}"),
            }],
        },
        activation: vec![ActivationSelector {
            package: Some(NameSelector {
                name: package.to_owned(),
                version: Some(format!("={version}")),
            }),
            module: None,
            toolchain: Some(NameSelector {
                name: language.to_owned(),
                version: Some(format!("={version}")),
            }),
            targets,
            configurations: Vec::new(),
            artifact_sha256: None,
        }],
        provenance,
        license: "Apache-2.0".to_owned(),
        safety: Safety {
            generated_code_only: false,
            review_required: false,
        },
    }
}

/// Build a `.gem` archive with an inner gzipped tar of declaration files.
pub fn ruby_gem_archive(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut compressed = Vec::new();
    {
        let encoder =
            flate2::write::GzEncoder::new(&mut compressed, flate2::Compression::default());
        let mut data = tar::Builder::new(encoder);
        for (path, bytes) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            data.append_data(&mut header, path, *bytes).unwrap();
        }
        data.into_inner().unwrap().finish().unwrap();
    }

    let mut gem = Vec::new();
    {
        let mut outer = tar::Builder::new(&mut gem);
        let mut header = tar::Header::new_gnu();
        header.set_size(compressed.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        outer
            .append_data(&mut header, "data.tar.gz", compressed.as_slice())
            .unwrap();
        outer.finish().unwrap();
    }
    gem
}

#[cfg(any(test, feature = "test-support"))]
#[path = "../../../test-support/git.rs"]
#[doc(hidden)]
pub mod shared_git;

#[cfg(any(test, feature = "test-support"))]
#[path = "../../../test-support/zip.rs"]
pub(crate) mod zip_helpers;

#[cfg(any(test, feature = "test-support"))]
use crate::analyzer::semantic::SemanticArtifact;
#[cfg(any(test, feature = "test-support"))]
use crate::analyzer::semantic::{
    ProcedureSemantics, SemanticCallSite, TransferKind, TransferOperation, ValueFlowKind, ValueId,
};
#[cfg(any(test, feature = "test-support"))]
use crate::analyzer::{AnalyzerConfig, Language, ProjectFile, TestProject, WorkspaceAnalyzer};
#[cfg(any(test, feature = "test-support"))]
use crate::analyzer::{FilesystemProject, Project};
#[cfg(any(test, feature = "test-support"))]
#[cfg(any(test, feature = "test-support"))]
use std::fs;
use std::path::{Path, PathBuf};
#[cfg(any(test, feature = "test-support"))]
use std::sync::Arc;
#[cfg(any(test, feature = "test-support"))]
use tempfile::TempDir;

/// Returns the source, target, and call site for each call-backed transfer of
/// the requested kind in a procedure.
#[cfg(any(test, feature = "test-support"))]
pub fn call_backed_transfer_sites(
    procedure: &ProcedureSemantics,
    kind: TransferKind,
) -> Vec<(ValueId, ValueId, &SemanticCallSite)> {
    procedure
        .points()
        .iter()
        .flat_map(|point| &point.events)
        .filter_map(|event| {
            let crate::analyzer::semantic::SemanticEffect::ValueFlow {
                kind: ValueFlowKind::Transfer(transfer),
                source,
                target,
            } = &event.effect
            else {
                return None;
            };
            if transfer.kind != kind {
                return None;
            }
            let TransferOperation::CallSite(call_site) = transfer.operation else {
                return None;
            };
            Some((
                *source,
                *target,
                procedure
                    .call_site(call_site)
                    .expect("a transfer names a call site of its own procedure"),
            ))
        })
        .collect()
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn discovery_declaring(
    language: &str,
    modules: &[&str],
    mut artifacts_for_module: impl FnMut(
        &str,
    ) -> Vec<
        crate::analyzer::semantic_model::ResolvedDependencyArtifact,
    >,
) -> crate::analyzer::semantic_model::DependencyDiscoveryOutcome {
    use crate::analyzer::semantic_model::{
        CatalogCoordinate, DependencyDiscoveryOutcome, ResolvedDependency,
        SemanticModelActivationEvidence,
    };

    DependencyDiscoveryOutcome::complete(
        modules
            .iter()
            .map(|module| ResolvedDependency {
                id: format!("test:distribution:{module}"),
                evidence: SemanticModelActivationEvidence {
                    language: language.to_owned(),
                    ecosystem: "test".to_owned(),
                    package: None,
                    module: Some(CatalogCoordinate {
                        name: (*module).to_owned(),
                        version: None,
                    }),
                    toolchain: None,
                    target: None,
                    configuration: None,
                    artifact_sha256: None,
                },
                provenance: Vec::new(),
                artifacts: artifacts_for_module(module),
                scope: crate::analyzer::topology::DependencyScope::Unknown,
                declared_by: None,
            })
            .collect(),
    )
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn incomplete_discovery_declaring(
    language: &str,
    modules: &[&str],
    artifacts_for_module: impl FnMut(
        &str,
    )
        -> Vec<crate::analyzer::semantic_model::ResolvedDependencyArtifact>,
) -> crate::analyzer::semantic_model::DependencyDiscoveryOutcome {
    let mut outcome = discovery_declaring(language, modules, artifacts_for_module);
    outcome.complete = false;
    outcome
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn activate_rust_declaration_pack(
    analyzer: &dyn crate::analyzer::IAnalyzer,
    pack_id: &str,
    pack_json: &serde_json::Value,
) {
    use crate::analyzer::semantic_model::{
        CatalogCoordinate, CatalogOptions, CompilerOptions, SemanticModelActivationControl,
        SemanticModelActivationEvidence, SemanticModelActivationRequest,
        SemanticModelControlAction, SemanticModelControlScope, SemanticModelPackSelector,
        SemanticModelRuntimeLimits, SemanticModelRuntimeOutcome, SemanticPackCatalog,
        SessionPackSource, SessionPackSourceKind, SourceFormat,
        acquire_active_semantic_models_with_evidence, compile_source,
    };

    let pack = compile_source(
        SourceFormat::Json,
        &serde_json::to_vec(pack_json).expect("serialize the Rust declaration fixture"),
        &CompilerOptions::default(),
    )
    .unwrap_or_else(|diagnostics| {
        panic!("Rust declaration fixture must compile: {diagnostics:#?}")
    });
    let catalog =
        SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).expect("ephemeral catalog");
    catalog
        .register_session_pack(
            &pack,
            &SessionPackSource {
                kind: SessionPackSourceKind::Embedded,
                source_id: pack_id.to_owned(),
            },
        )
        .expect("register the Rust declaration fixture");
    let request = SemanticModelActivationRequest {
        bifrost_version: semver::Version::parse(env!("CARGO_PKG_VERSION")).expect("crate version"),
        evidence: vec![SemanticModelActivationEvidence {
            language: "rust".to_owned(),
            ecosystem: "cargo".to_owned(),
            package: Some(CatalogCoordinate {
                name: "std".to_owned(),
                version: None,
            }),
            module: None,
            toolchain: None,
            target: None,
            configuration: None,
            artifact_sha256: None,
        }],
        controls: vec![SemanticModelActivationControl {
            scope: SemanticModelControlScope::Workspace,
            action: SemanticModelControlAction::Enable,
            selector: SemanticModelPackSelector {
                pack_id: pack_id.to_owned(),
                version: None,
                manifest_digest: None,
            },
        }],
        limits: SemanticModelRuntimeLimits::default(),
    };
    let SemanticModelRuntimeOutcome::Ready { .. } = acquire_active_semantic_models_with_evidence(
        analyzer,
        &catalog,
        None,
        &request,
        None,
        &crate::CancellationToken::new(),
    ) else {
        panic!("Rust declaration fixture must activate");
    };
}

#[cfg(any(test, feature = "test-support"))]
#[allow(clippy::too_many_arguments)]
pub fn semantic_artifact_key_fixture(
    mount: &str,
    path: &str,
    language: crate::analyzer::semantic::SemanticLanguage,
    revision: crate::analyzer::semantic::SourceRevision,
    adapter_name: &str,
    adapter: &str,
    ir: &str,
    configuration: &str,
    dependencies: &str,
) -> crate::analyzer::semantic::SemanticArtifactKey {
    use crate::analyzer::semantic::{
        AdapterSemanticsVersion, ConfigurationFingerprint, DependencyFingerprint,
        SemanticIrVersion, StableDigest, WorkspaceMountId, WorkspaceRelativePath,
    };

    let digest = |label: &str| StableDigest::sha256(label);
    crate::analyzer::semantic::SemanticArtifactKey::new(
        WorkspaceMountId::from_digest(digest(mount)),
        WorkspaceRelativePath::new(path).expect("fixture path is portable"),
        language,
        revision,
        AdapterSemanticsVersion::new(adapter_name, digest(adapter))
            .expect("fixture adapter has a name"),
        SemanticIrVersion::from_digest(digest(ir)),
        ConfigurationFingerprint::from_digest(digest(configuration)),
        DependencyFingerprint::from_digest(digest(dependencies)),
    )
}

#[cfg(any(test, feature = "test-support"))]
pub fn minimal_semantic_procedure(
    id: crate::analyzer::semantic::ProcedureId,
    locator: crate::analyzer::semantic::SemanticLocator,
    kind: crate::analyzer::semantic::ProcedureKind,
) -> crate::analyzer::semantic::ProcedureSemanticsParts {
    use crate::analyzer::semantic::{
        BasicBlock, BlockId, ControlEdge, ControlEdgeKind, Evidence, EvidenceCompleteness,
        EvidenceId, ProgramPoint, ProgramPointId, ProofStatus, SemanticEffect, SemanticEvent,
        SourceMapping, SourceMappingId, SourceMappingKind,
    };

    let source = SourceMappingId::new(0);
    let evidence = EvidenceId::new(0);
    let mut parts = crate::analyzer::semantic::ProcedureSemanticsParts::new(
        id,
        locator.clone(),
        kind,
        source,
        evidence,
    );
    parts.source_mappings.push(SourceMapping {
        id: source,
        locator,
        kind: SourceMappingKind::Exact,
        ast_identity: None,
    });
    parts.evidence_rows.push(Evidence {
        id: evidence,
        proof: ProofStatus::Proven,
        completeness: EvidenceCompleteness::Complete,
        sources: vec![source].into_boxed_slice(),
    });

    let entry = ProgramPointId::new(0);
    let normal_exit = ProgramPointId::new(1);
    let exceptional_exit = ProgramPointId::new(2);
    parts.blocks.push(BasicBlock {
        id: BlockId::new(0),
        points: vec![entry, normal_exit, exceptional_exit].into_boxed_slice(),
        source,
        evidence,
    });
    parts.points.extend([
        ProgramPoint {
            id: entry,
            block: BlockId::new(0),
            events: vec![SemanticEvent::new(SemanticEffect::Entry, source, evidence)]
                .into_boxed_slice(),
            source,
            evidence,
        },
        ProgramPoint {
            id: normal_exit,
            block: BlockId::new(0),
            events: vec![SemanticEvent::new(
                SemanticEffect::NormalExit,
                source,
                evidence,
            )]
            .into_boxed_slice(),
            source,
            evidence,
        },
        ProgramPoint {
            id: exceptional_exit,
            block: BlockId::new(0),
            events: vec![SemanticEvent::new(
                SemanticEffect::ExceptionalExit,
                source,
                evidence,
            )]
            .into_boxed_slice(),
            source,
            evidence,
        },
    ]);
    parts.control_edges.extend([
        ControlEdge {
            source_point: entry,
            target_point: normal_exit,
            kind: ControlEdgeKind::Normal,
            source,
            evidence,
        },
        ControlEdge {
            source_point: entry,
            target_point: exceptional_exit,
            kind: ControlEdgeKind::Exceptional,
            source,
            evidence,
        },
    ]);
    parts
}

#[cfg(any(test, feature = "test-support"))]
pub fn write_fixture_files(root: &Path, files: &[(&str, &str)]) {
    for (path, contents) in files {
        let full = root.join(path);
        fs::create_dir_all(full.parent().expect("fixture file has a parent"))
            .expect("create fixture parent directory");
        fs::write(full, contents).expect("write fixture file");
    }
}

#[cfg(any(test, feature = "test-support"))]
pub fn hermetic_jvm_config() -> AnalyzerConfig {
    use crate::analyzer::JvmDependencyDiscoveryMode;

    let mut config = AnalyzerConfig::default();
    config.jvm.dependency_discovery.mode = JvmDependencyDiscoveryMode::Disabled;
    config.jvm.standard_library_discovery.discover_java_home = false;
    config
}

#[cfg(any(test, feature = "test-support"))]
pub fn artifact_production_request(
    path: PathBuf,
    artifact_kind: crate::analyzer::semantic_model::ExternalArtifactKind,
    pack_id: &str,
    ecosystem: &str,
    package_name: &str,
    provenance_source: &str,
) -> crate::analyzer::semantic_model::ArtifactProductionRequest {
    use crate::analyzer::semantic_model::{
        ActivationSelector, ArtifactProductionRequest, Compatibility, NameSelector, Provenance,
        Safety,
    };

    ArtifactProductionRequest {
        path,
        artifact_kind,
        pack_id: pack_id.to_owned(),
        pack_version: "1.0.0".to_owned(),
        ecosystem: ecosystem.to_owned(),
        compatibility: Compatibility {
            bifrost: None,
            toolchains: Vec::new(),
        },
        activation: vec![ActivationSelector {
            package: Some(NameSelector {
                name: package_name.to_owned(),
                version: Some("1.0.0".to_owned()),
            }),
            module: None,
            toolchain: None,
            targets: Vec::new(),
            configurations: Vec::new(),
            artifact_sha256: None,
        }],
        provenance: Provenance {
            source: provenance_source.to_owned(),
            revision: None,
        },
        license: "MIT".to_owned(),
        safety: Safety {
            generated_code_only: false,
            review_required: false,
        },
    }
}

#[cfg(any(test, feature = "test-support"))]
pub fn configuration_facts(
    path: &Path,
    source: &str,
) -> brokk_bifrost_core::analyzer::configuration::ConfigurationDocumentFacts {
    use crate::analyzer::configuration::{
        ConfigurationIngestionOutcome, ingest_configuration_document,
    };

    match ingest_configuration_document(path, source.as_bytes()) {
        ConfigurationIngestionOutcome::Facts(facts) => *facts,
        other => panic!("expected configuration facts, got {other:?}"),
    }
}

/// Asserts that one parser-limited properties line has the expected evidence.
#[cfg(any(test, feature = "test-support"))]
pub fn assert_properties_parser_limit(
    source: &str,
    document: &brokk_bifrost_core::analyzer::configuration::ConfigurationDocumentFacts,
    expected_evidence: &str,
) {
    use brokk_bifrost_core::analyzer::configuration::{
        ConfigurationCompleteness, ConfigurationRecoveryReason,
    };

    let ConfigurationCompleteness::Incomplete { recoveries } = document.completeness() else {
        panic!("{source:?} must be incomplete: {document:#?}");
    };
    assert_eq!(recoveries.len(), 1, "{source:?}: {document:#?}");
    assert_eq!(
        recoveries[0].reason(),
        ConfigurationRecoveryReason::ParserLimit,
        "{source:?}"
    );
    let evidence = recoveries[0].evidence();
    assert_eq!(
        &source[evidence.start_byte()..evidence.end_byte()],
        expected_evidence,
        "{source:?}"
    );
}

/// Returns the scalar kind, panicking if the fact is not a scalar.
#[cfg(any(test, feature = "test-support"))]
pub fn configuration_scalar_kind(
    fact: &brokk_bifrost_core::analyzer::configuration::ConfigurationFact,
) -> brokk_bifrost_core::analyzer::configuration::ConfigurationScalarKind {
    use brokk_bifrost_core::analyzer::configuration::ConfigurationNodeKind;

    match fact.kind() {
        ConfigurationNodeKind::Scalar { scalar_kind } => *scalar_kind,
        other => panic!("expected a scalar, got {other:?}"),
    }
}

/// Asserts that two selected facts retain the same configuration stable ID.
#[cfg(any(test, feature = "test-support"))]
pub fn assert_same_configuration_stable_id(
    before: brokk_bifrost_core::analyzer::configuration::ConfigurationStableId,
    after: brokk_bifrost_core::analyzer::configuration::ConfigurationStableId,
) {
    assert_eq!(before, after);
}

#[cfg(any(test, feature = "test-support"))]
pub fn configuration_recovery_ranges(
    document: &brokk_bifrost_core::analyzer::configuration::ConfigurationDocumentFacts,
) -> Vec<(
    brokk_bifrost_core::analyzer::configuration::ConfigurationRecoveryReason,
    std::ops::Range<usize>,
)> {
    use brokk_bifrost_core::analyzer::configuration::ConfigurationCompleteness;

    match document.completeness() {
        ConfigurationCompleteness::Complete => Vec::new(),
        ConfigurationCompleteness::Incomplete { recoveries } => recoveries
            .iter()
            .map(|recovery| {
                (
                    recovery.reason(),
                    recovery.evidence().start_byte()..recovery.evidence().end_byte(),
                )
            })
            .collect(),
    }
}

#[cfg(any(test, feature = "test-support"))]
pub fn configuration_scalar_ranges(
    document: &brokk_bifrost_core::analyzer::configuration::ConfigurationDocumentFacts,
) -> Vec<(
    brokk_bifrost_core::analyzer::configuration::ConfigurationScalarKind,
    std::ops::Range<usize>,
)> {
    use brokk_bifrost_core::analyzer::configuration::ConfigurationNodeKind;

    document
        .facts()
        .iter()
        .filter_map(|fact| match fact.kind() {
            ConfigurationNodeKind::Scalar { scalar_kind } => Some((
                *scalar_kind,
                fact.evidence().start_byte()..fact.evidence().end_byte(),
            )),
            _ => None,
        })
        .collect()
}

#[cfg(any(test, feature = "test-support"))]
pub fn configuration_scalar_evidence<'source>(
    document: &brokk_bifrost_core::analyzer::configuration::ConfigurationDocumentFacts,
    source: &'source str,
) -> Vec<(
    brokk_bifrost_core::analyzer::configuration::ConfigurationScalarKind,
    &'source str,
)> {
    configuration_scalar_ranges(document)
        .into_iter()
        .map(|(kind, range)| (kind, &source[range]))
        .collect()
}

#[cfg(any(test, feature = "test-support"))]
pub fn properties_members<'source>(
    source: &'source str,
    document: &brokk_bifrost_core::analyzer::configuration::ConfigurationDocumentFacts,
) -> Vec<(String, usize, &'source str, &'source str)> {
    use brokk_bifrost_core::analyzer::configuration::{
        ConfigurationFactId, ConfigurationFormat, ConfigurationMemberRole, ConfigurationNodeKind,
        ConfigurationRouteSelector, ConfigurationScalarKind,
    };
    use std::collections::HashSet;

    let mut seen = HashSet::new();
    document
        .facts()
        .iter()
        .enumerate()
        .filter_map(|(index, fact)| {
            let ConfigurationNodeKind::Member { role, key, value } = fact.kind() else {
                return None;
            };
            assert_eq!(*role, ConfigurationMemberRole::Property, "{fact:#?}");
            assert_eq!(fact.parent().map(|parent| parent.index()), Some(1));
            let [segment] = fact.route().segments() else {
                panic!("{fact:#?}");
            };
            let ConfigurationRouteSelector::Key { name, occurrence } = segment.selector() else {
                panic!("{fact:#?}");
            };
            assert_eq!(name, key.text());
            assert_eq!(segment.evidence(), key.evidence());
            assert!(seen.insert(fact.stable_id(ConfigurationFormat::Properties)));
            let value = document
                .fact(value.expect("every property has a value"))
                .unwrap();
            assert_eq!(value.parent(), ConfigurationFactId::new(index));
            assert!(matches!(
                value.kind(),
                ConfigurationNodeKind::Scalar {
                    scalar_kind: ConfigurationScalarKind::String
                }
            ));
            assert_eq!(value.route(), fact.route());
            Some((
                key.text().to_owned(),
                *occurrence,
                &source[key.evidence().start_byte()..key.evidence().end_byte()],
                &source[value.evidence().start_byte()..value.evidence().end_byte()],
            ))
        })
        .collect()
}

#[cfg(any(test, feature = "test-support"))]
pub fn complete_semantic_capabilities(
    additional: &[crate::analyzer::semantic::SemanticCapability],
) -> crate::analyzer::semantic::SemanticCapabilities {
    use crate::analyzer::semantic::{SemanticCapabilities, SemanticCapability};

    let mut builder = SemanticCapabilities::builder();
    for capability in [
        SemanticCapability::Procedures,
        SemanticCapability::EntryBoundary,
        SemanticCapability::NormalExitBoundary,
        SemanticCapability::ExceptionalExitBoundary,
        SemanticCapability::BasicBlocks,
        SemanticCapability::ProgramPoints,
        SemanticCapability::NormalControlFlow,
        SemanticCapability::ExceptionalControlFlow,
    ]
    .into_iter()
    .chain(additional.iter().copied())
    {
        builder = builder.complete(capability);
    }
    builder.build()
}

#[cfg(any(test, feature = "test-support"))]
pub fn named_file_function_locator(
    key: &crate::analyzer::semantic::SemanticArtifactKey,
    file_name: &str,
    name: &str,
    anchor: crate::analyzer::semantic::SourceAnchor,
    role: crate::analyzer::semantic::SemanticRole,
) -> crate::analyzer::semantic::SemanticLocator {
    use crate::analyzer::semantic::{
        DeclarationLocator, DeclarationSegment, DeclarationSegmentKind, SemanticLocator,
    };

    let declaration = DeclarationLocator::new(vec![
        DeclarationSegment::named(
            DeclarationSegmentKind::File,
            file_name,
            source_anchor(0, 1, 0),
            0,
        )
        .expect("named file segment"),
        DeclarationSegment::named(DeclarationSegmentKind::Function, name, anchor, 0)
            .expect("named function segment"),
    ])
    .expect("non-empty declaration");
    SemanticLocator::new(
        key.mount(),
        key.path().clone(),
        key.language(),
        declaration,
        role,
        anchor,
    )
}

#[cfg(any(test, feature = "test-support"))]
pub struct ComposerPackageMetadata<'a> {
    pub name: &'a str,
    pub version: &'a str,
    pub reference: String,
    pub autoload: &'a str,
}

#[cfg(any(test, feature = "test-support"))]
pub fn composer_fixture_metadata(packages: &[ComposerPackageMetadata<'_>]) -> (String, String) {
    let mut locked = Vec::new();
    let mut installed = Vec::new();
    for package in packages {
        locked.push(format!(
            r#"{{"name":"{}","version":"{}","type":"library","dist":{{"type":"path","url":"file:///{}","reference":"{}"}},"autoload":{}}}"#,
            package.name, package.version, package.name, package.reference, package.autoload
        ));
        installed.push(format!(
            r#"{{"name":"{}","version":"{}","type":"library","install-path":"../{}","autoload":{}}}"#,
            package.name, package.version, package.name, package.autoload
        ));
    }
    (
        format!(
            r#"{{"content-hash":"fixture","packages":[{}],"packages-dev":[]}}"#,
            locked.join(",")
        ),
        format!(r#"{{"packages":[{}],"dev":false}}"#, installed.join(",")),
    )
}

#[cfg(any(test, feature = "test-support"))]
pub fn assert_no_optional_claim_pack_v2_digests(
    compiled: &crate::analyzer::semantic_model::CompiledSemanticModelPack,
) {
    assert_eq!(
        compiled.manifest.semantic_sha256,
        "c95c929e580da66b273670232922084f7bf76495fdd609e0338e1cb832538932"
    );
    assert_eq!(
        compiled.manifest.content_sha256,
        "bbddac2ff793463700951d9a2b5377facb90741a779e029468b50df07e985b53"
    );
    assert_eq!(
        compiled.shards[0].descriptor.semantic_sha256,
        "9db53e8ae41538e727785153a35935b000fae2efd916b0dfa85a226aafbe00a2"
    );
    assert_eq!(
        compiled.shards[0].descriptor.content_sha256,
        "5db9b5f2535724a7c173425fe1b6b07ceeccdb7e09c45736ab2f73a85328eec9"
    );
}

#[cfg(any(test, feature = "test-support"))]
pub fn runtime_contract_profile_support()
-> crate::analyzer::semantic_model::csmi::CsmiVocabularySupport {
    use crate::analyzer::semantic_model::csmi::{
        CSMI_RUNTIME_CONTRACTS_PROFILE_SCHEMA, CSMI_RUNTIME_CONTRACTS_PROFILE_VERSION,
        CSMI_RUNTIME_VALUES_PROFILE_ID, CsmiVocabularySupport,
    };

    CsmiVocabularySupport::support(
        CSMI_RUNTIME_VALUES_PROFILE_ID,
        CSMI_RUNTIME_CONTRACTS_PROFILE_VERSION,
        CSMI_RUNTIME_CONTRACTS_PROFILE_SCHEMA,
    )
}

#[cfg(any(test, feature = "test-support"))]
pub fn compile_semantic_pack_fixture(
    source: &str,
) -> crate::analyzer::semantic_model::CompiledSemanticModelPack {
    use crate::analyzer::semantic_model::{CompilerOptions, SourceFormat, compile_source};

    compile_source(
        SourceFormat::Json,
        source.as_bytes(),
        &CompilerOptions::default(),
    )
    .unwrap_or_else(|diagnostics| panic!("fixture pack must compile: {diagnostics:#?}"))
}

#[cfg(any(test, feature = "test-support"))]
pub fn install_pre_shipped_semantic_pack(
    catalog: &crate::analyzer::semantic_model::SemanticPackCatalog,
    pack: &crate::analyzer::semantic_model::CompiledSemanticModelPack,
    source_id: &str,
) {
    use crate::analyzer::semantic_model::{DurablePackSource, DurablePackSourceKind};

    catalog
        .install(
            pack,
            &DurablePackSource {
                kind: DurablePackSourceKind::PreShipped,
                source_id: source_id.to_owned(),
            },
        )
        .expect("install fixture pack");
}

#[cfg(any(test, feature = "test-support"))]
pub fn build_pre_shipped_semantic_pack_catalog(directory: &Path, source: &str, source_id: &str) {
    use crate::analyzer::semantic_model::{CatalogOpenMode, CatalogOptions, SemanticPackCatalog};

    let pack = compile_semantic_pack_fixture(source);
    let catalog = SemanticPackCatalog::open(
        directory,
        CatalogOpenMode::ReadWrite,
        CatalogOptions::default(),
    )
    .expect("open catalog for install");
    install_pre_shipped_semantic_pack(&catalog, &pack, source_id);
}

#[cfg(any(test, feature = "test-support"))]
pub fn go_semantic_model_activation_request(
    module: Option<crate::analyzer::semantic_model::CatalogCoordinate>,
) -> crate::analyzer::semantic_model::SemanticModelActivationRequest {
    use crate::analyzer::semantic_model::{
        SemanticModelActivationEvidence, SemanticModelActivationRequest, SemanticModelRuntimeLimits,
    };
    use semver::Version;

    SemanticModelActivationRequest {
        bifrost_version: Version::parse(env!("CARGO_PKG_VERSION")).expect("crate version"),
        evidence: vec![SemanticModelActivationEvidence {
            language: "go".to_owned(),
            ecosystem: "go".to_owned(),
            package: None,
            module,
            toolchain: None,
            target: None,
            configuration: None,
            artifact_sha256: None,
        }],
        controls: Vec::new(),
        limits: SemanticModelRuntimeLimits::default(),
    }
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn resolved_reference_site(
    path: String,
    text: String,
    range: crate::analyzer::Range,
) -> crate::analyzer::usages::reference_site::ResolvedReferenceSite {
    crate::analyzer::usages::reference_site::ResolvedReferenceSite {
        path,
        text,
        range,
        focus_start_byte: range.start_byte,
        focus_end_byte: range.end_byte,
    }
}

#[cfg(any(test, feature = "test-support"))]
pub fn source_anchor(
    start_byte: u32,
    end_byte: u32,
    occurrence: u32,
) -> crate::analyzer::semantic::SourceAnchor {
    use crate::analyzer::semantic::{SourceAnchor, SourcePosition, SourceSpan};

    SourceAnchor::new(
        SourceSpan::new(
            SourcePosition::new(start_byte, 0, start_byte),
            SourcePosition::new(end_byte, 0, end_byte),
        )
        .expect("fixture source span should be ordered"),
        occurrence,
    )
}

#[cfg(any(test, feature = "test-support"))]
pub fn rel_paths(files: &[ProjectFile]) -> Vec<String> {
    files
        .iter()
        .map(crate::path_utils::rel_path_string)
        .collect()
}

pub fn external_route_candidates(
    trace: &crate::analyzer::usages::get_definition::ResolutionTraceResult,
) -> Vec<&crate::analyzer::usages::get_definition::TraceCandidate> {
    trace
        .candidates
        .iter()
        .filter(|row| {
            matches!(
                row.candidate,
                crate::analyzer::usages::get_definition::TraceCandidateRef::ExternalRoute { .. }
            )
        })
        .collect()
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn java_analyzer(root: &Path) -> crate::analyzer::JavaAnalyzer {
    use crate::analyzer::JavaAnalyzer;

    JavaAnalyzer::from_project(TestProject::new(root.to_path_buf(), Language::Java))
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn procedure_named<'artifact>(
    artifact: &'artifact SemanticArtifact,
    name: &str,
) -> &'artifact ProcedureSemantics {
    artifact
        .procedures()
        .iter()
        .find(|procedure| {
            procedure
                .locator()
                .declaration()
                .segments()
                .last()
                .and_then(|segment| segment.name())
                == Some(name)
        })
        .unwrap_or_else(|| panic!("missing procedure {name}"))
}

#[cfg(unix)]
pub fn create_fifo(path: &Path) {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let path = CString::new(path.as_os_str().as_bytes()).expect("FIFO path has no NUL bytes");
    // SAFETY: `path` is a live NUL-terminated string and mkfifo retains neither
    // the pointer nor any Rust-owned memory.
    let result = unsafe { libc::mkfifo(path.as_ptr(), 0o600) };
    assert_eq!(
        result,
        0,
        "mkfifo failed: {}",
        std::io::Error::last_os_error()
    );
}

#[cfg(any(test, feature = "test-support"))]
pub fn write_zip(path: &Path, entries: &[(&str, &str)]) {
    let mut writer = zip::ZipWriter::new(std::fs::File::create(path).expect("create ZIP fixture"));
    for (entry_name, source) in entries {
        writer
            .start_file(*entry_name, zip::write::SimpleFileOptions::default())
            .expect("start ZIP fixture entry");
        std::io::Write::write_all(&mut writer, source.as_bytes()).expect("write ZIP fixture entry");
    }
    writer.finish().expect("finish ZIP fixture");
}

#[cfg(any(test, feature = "test-support"))]
pub fn fixture_marker(source: &str, needle: &str) -> usize {
    source
        .find(needle)
        .unwrap_or_else(|| panic!("fixture does not contain {needle:?}"))
}

#[cfg(any(test, feature = "test-support"))]
pub fn token_range(source: &str, marker: &str, token: &str) -> (usize, usize) {
    let marker_start = fixture_marker(source, marker);
    let token_start = fixture_marker(marker, token);
    let start = marker_start + token_start;
    (start, start + token.len())
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn parse_fixture_tree(source: &str, language: tree_sitter::Language) -> tree_sitter::Tree {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&language)
        .expect("fixture grammar loads");
    parser.parse(source, None).expect("fixture source parses")
}

#[cfg(any(test, feature = "test-support"))]
pub fn activation_evidence(
    language: &str,
    ecosystem: &str,
    package: &str,
) -> crate::analyzer::semantic_model::SemanticModelActivationEvidence {
    use crate::analyzer::semantic_model::{CatalogCoordinate, SemanticModelActivationEvidence};

    SemanticModelActivationEvidence {
        language: language.to_owned(),
        ecosystem: ecosystem.to_owned(),
        package: Some(CatalogCoordinate {
            name: package.to_owned(),
            version: None,
        }),
        module: None,
        toolchain: None,
        target: None,
        configuration: None,
        artifact_sha256: None,
    }
}

#[cfg(any(test, feature = "test-support"))]
pub fn unscoped_activation_evidence(
    language: &str,
    ecosystem: &str,
) -> crate::analyzer::semantic_model::SemanticModelActivationEvidence {
    use crate::analyzer::semantic_model::SemanticModelActivationEvidence;

    SemanticModelActivationEvidence {
        language: language.to_owned(),
        ecosystem: ecosystem.to_owned(),
        package: None,
        module: None,
        toolchain: None,
        target: None,
        configuration: None,
        artifact_sha256: None,
    }
}

#[cfg(any(test, feature = "test-support"))]
pub const NESTED_CALLABLE_BRANCH_CASES: &[(Language, &str, &str)] = &[
    (
        Language::JavaScript,
        "sample.js",
        "function f(x) { if (x === 1) { return function () { return x; }; } else { return function () { return x; }; } }",
    ),
    (
        Language::JavaScript,
        "sample.js",
        "function f(x) { if (x === 1) { return function* () { yield x; }; } else { return function* () { yield x; }; } }",
    ),
    (
        Language::JavaScript,
        "sample.js",
        "function f(x) { if (x === 1) { return { m() { return x; } }; } else { return { m() { return x; } }; } }",
    ),
    (
        Language::JavaScript,
        "sample.js",
        "function f(x) { if (x === 1) { return class { m() { return x; } }; } else { return class { m() { return x; } }; } }",
    ),
    (
        Language::JavaScript,
        "sample.js",
        "function f(x) { if (x === 1) { return (a) => a + x; } else { return (a) => a + x; } }",
    ),
    (
        Language::TypeScript,
        "sample.ts",
        "function f(x: number) { if (x === 1) { return function (a: number) { return a + x; }; } else { return function (a: number) { return a + x; }; } }",
    ),
    (
        Language::TypeScript,
        "sample.ts",
        "function f(x: number) { if (x === 1) { return (a: number) => a + x; } else { return (a: number) => a + x; } }",
    ),
    (
        Language::Python,
        "sample.py",
        "def f(x):\n    if x is None:\n        class A:\n            pass\n        return A\n    else:\n        class A:\n            pass\n        return A\n",
    ),
    (
        Language::Python,
        "sample.py",
        "def f(x, d):\n    if x is None:\n        @d\n        def g():\n            return x\n        return g\n    else:\n        @d\n        def g():\n            return x\n        return g\n",
    ),
    (
        Language::Python,
        "sample.py",
        "def f(x):\n    if x is None:\n        return lambda a: a + x\n    else:\n        return lambda a: a + x\n",
    ),
    (
        Language::Java,
        "Sample.java",
        "class Sample { java.util.function.IntUnaryOperator f(int x) { if (x == 1) return a -> a + x; else return a -> a + x; } }",
    ),
    (
        Language::Java,
        "Sample.java",
        "class Sample { Object f(int x) { if (x == 1) { record R(int a) {} return new R(x); } else { record R(int a) {} return new R(x); } } }",
    ),
];

#[cfg(any(test, feature = "test-support"))]
pub fn write_jdk_release(home: &Path, java_version: &str) -> PathBuf {
    write_jdk_release_contents(home, format!("JAVA_VERSION=\"{java_version}\"\n"))
}

#[cfg(any(test, feature = "test-support"))]
pub fn write_jdk_release_with_implementor(
    home: &Path,
    java_version: &str,
    implementor: &str,
) -> PathBuf {
    write_jdk_release_contents(
        home,
        format!("JAVA_VERSION=\"{java_version}\"\nIMPLEMENTOR=\"{implementor}\"\n"),
    )
}

#[cfg(any(test, feature = "test-support"))]
fn write_jdk_release_contents(home: &Path, release_contents: String) -> PathBuf {
    std::fs::create_dir_all(home).expect("create fake JDK home");
    std::fs::write(home.join("release"), release_contents).expect("write JDK release file");
    home.to_path_buf()
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn commit_all(repo: &git2::Repository, message: &str) -> git2::Oid {
    let signature = git2::Signature::now("Tester", "tester@example.com").expect("signature");
    shared_git::commit_all_with_deletions(repo, message, &signature)
}

/// Inspect persisted rows without changing an ephemeral fixture into a disk-backed one.
#[cfg(any(test, feature = "test-support"))]
pub fn store_read_connection(
    store: &crate::analyzer::store::AnalyzerStore,
) -> impl std::ops::Deref<Target = rusqlite::Connection> + '_ {
    store.read_conn().expect("open the analyzer store reader")
}

#[cfg(any(test, feature = "test-support"))]
pub fn cache_row_count(root: &Path, table: &str) -> i64 {
    let connection = rusqlite::Connection::open(crate::analyzer::store::analyzer_db_path(root))
        .expect("open the shared analyzer cache");
    cache_row_count_for_connection(&connection, table)
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn cache_row_count_for_connection(connection: &rusqlite::Connection, table: &str) -> i64 {
    connection
        .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .expect("count cache rows")
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn block_shared_analyzer_cache(root: &Path) -> PathBuf {
    let path = crate::analyzer::store::analyzer_db_path(root);
    fs::create_dir_all(&path).expect("block the cache path");
    path
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn assert_shared_analyzer_cache_error(error: &str, path: &Path) {
    assert!(
        error.contains(&path.display().to_string()),
        "the error must name the cache it could not open: {error}"
    );
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn mixed_language_rust_workspace() -> (TempDir, WorkspaceAnalyzer) {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canonical root");
    for (relative_path, source) in [
        (
            "Cargo.toml",
            "[package]\nname = \"mixed\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        ),
        (
            "src/lib.rs",
            "pub fn target() -> usize { 1 }\npub fn caller() -> usize { target() }\n",
        ),
        ("include/widget.h", "struct Widget { int value; };\n"),
        ("scripts/build.py", "def helper():\n    return 1\n"),
    ] {
        ProjectFile::new(root.clone(), relative_path)
            .write(source)
            .expect("write mixed-language fixture");
    }
    let project =
        TestProject::from_root_with_inferred_languages(&root).expect("infer fixture languages");
    let workspace =
        WorkspaceAnalyzer::build_ephemeral_footgun(Arc::new(project), AnalyzerConfig::default())
            .expect("mixed-language workspace");
    (temp, workspace)
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn synthetic_oid(byte: u8) -> git2::Oid {
    git2::Oid::from_bytes(&[byte; 20]).expect("twenty bytes is a valid object id")
}

/// Owns a `TempDir` workspace and the analyzer built over it.
#[cfg(any(test, feature = "test-support"))]
pub struct AnalyzerFixture {
    _temp: TempDir,
    #[doc(hidden)]
    pub analyzer: WorkspaceAnalyzer,
    #[allow(dead_code)]
    #[doc(hidden)]
    pub test_project: Option<TestProject>,
}

#[cfg(any(test, feature = "test-support"))]
impl AnalyzerFixture {
    /// Build a fixture from `(relative_path, file_contents)` pairs.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn new(files: &[(&str, &str)]) -> Self {
        let temp = TempDir::new().expect("tempdir");
        for (rel, content) in files {
            let abs = temp.path().join(rel);
            if let Some(parent) = abs.parent() {
                fs::create_dir_all(parent).expect("mkdir");
            }
            fs::write(&abs, content).expect("write");
        }
        let project: Arc<dyn Project> =
            Arc::new(FilesystemProject::new(temp.path().to_path_buf()).expect("project"));
        let analyzer =
            WorkspaceAnalyzer::build_ephemeral_footgun(project, AnalyzerConfig::default())
                .expect("ephemeral workspace should build");
        Self {
            _temp: temp,
            analyzer,
            test_project: None,
        }
    }

    pub fn new_for_language(language: Language, files: &[(&str, &str)]) -> Self {
        let temp = TempDir::new().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        for (rel, content) in files {
            ProjectFile::new(root.clone(), rel)
                .write(content)
                .unwrap_or_else(|err| panic!("failed to write {rel}: {err}"));
        }
        let project = TestProject::new(root, language);
        let analyzer = WorkspaceAnalyzer::build_ephemeral_footgun(
            Arc::new(project.clone()),
            AnalyzerConfig::default(),
        )
        .expect("ephemeral workspace should build");
        Self {
            _temp: temp,
            analyzer,
            test_project: Some(project),
        }
    }

    #[allow(dead_code)]
    #[doc(hidden)]
    pub fn test_project(&self) -> &TestProject {
        self.test_project
            .as_ref()
            .expect("fixture was not built with TestProject")
    }

    pub fn analyzer(&self) -> &WorkspaceAnalyzer {
        &self.analyzer
    }

    pub fn project_root(&self) -> PathBuf {
        self.analyzer.analyzer().project().root().to_path_buf()
    }
}
