use std::path::Path;

use rustdoc_types::Crate as RustdocCrate;
use serde::Deserialize;

use crate::CancellationToken;
use crate::analyzer::RustDependencyApiEvidence;
use crate::analyzer::semantic_model::{
    DependencyPackDiagnostic, DependencyPackDiagnosticSeverity, DependencyPackLimits,
    ProducerDiagnostic, ProducerDiagnosticSeverity, read_exact_artifact_while,
};

const CARGO_METADATA_FORMAT_VERSION: u32 = 1;
const MINIMUM_LOCKFILE_VERSION: u32 = 3;
const MAXIMUM_LOCKFILE_VERSION: u32 = 4;

#[derive(Debug, Deserialize)]
struct CargoMetadata {
    version: u32,
    #[serde(default)]
    packages: Vec<CargoMetadataPackage>,
    resolve: Option<CargoMetadataResolve>,
}

#[derive(Debug, Deserialize)]
struct CargoMetadataPackage {
    id: String,
    name: String,
    version: String,
    source: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CargoMetadataResolve {
    #[serde(default)]
    nodes: Vec<CargoMetadataNode>,
}

#[derive(Debug, Deserialize)]
struct CargoMetadataNode {
    id: String,
    #[serde(default)]
    features: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct CargoLockfile {
    version: u32,
    #[serde(default, rename = "package")]
    packages: Vec<CargoLockPackage>,
}

#[derive(Debug, Deserialize)]
struct CargoLockPackage {
    name: String,
    version: String,
    source: Option<String>,
    checksum: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RustdocVersionEnvelope {
    format_version: u32,
}

#[derive(Debug)]
struct DecodedRustdocArtifact {
    package_id: String,
    crate_name: String,
    enabled_features: Vec<String>,
    toolchain: String,
    document: RustdocCrate,
}

#[derive(Debug)]
struct DecodedRustDependencyEvidence {
    metadata: CargoMetadata,
    lockfile: CargoLockfile,
    artifacts: Vec<DecodedRustdocArtifact>,
}

fn decode_rust_dependency_evidence(
    evidence: &RustDependencyApiEvidence,
    limits: &DependencyPackLimits,
    cancellation: Option<&CancellationToken>,
) -> Result<DecodedRustDependencyEvidence, DependencyPackDiagnostic> {
    require_non_empty("target", &evidence.target)?;
    require_non_empty("configuration", &evidence.configuration)?;
    if evidence.selected_targets.is_empty() {
        return Err(diagnostic(
            "rust.evidence.selected_targets",
            None,
            "Rust dependency evidence must select at least one Cargo target",
        ));
    }
    if evidence.packages.is_empty() {
        return Err(diagnostic(
            "rust.evidence.artifacts",
            None,
            "Rust dependency evidence must bind at least one rustdoc JSON artifact",
        ));
    }

    let metadata_artifact = read_evidence_file(&evidence.metadata_path, limits, cancellation)?;
    let metadata: CargoMetadata =
        serde_json::from_slice(metadata_artifact.bytes()).map_err(|error| {
            diagnostic(
                "rust.metadata.invalid_json",
                Some(&evidence.metadata_path),
                format!("could not decode Cargo metadata JSON: {error}"),
            )
        })?;
    if metadata.version != CARGO_METADATA_FORMAT_VERSION {
        return Err(diagnostic(
            "rust.metadata.unsupported_version",
            Some(&evidence.metadata_path),
            format!(
                "Cargo metadata format {} is unsupported; expected {}",
                metadata.version, CARGO_METADATA_FORMAT_VERSION
            ),
        ));
    }

    let lockfile_artifact = read_evidence_file(&evidence.lockfile_path, limits, cancellation)?;
    let lockfile: CargoLockfile = toml::from_str(
        std::str::from_utf8(lockfile_artifact.bytes()).map_err(|error| {
            diagnostic(
                "rust.lockfile.invalid_utf8",
                Some(&evidence.lockfile_path),
                format!("Cargo.lock is not UTF-8: {error}"),
            )
        })?,
    )
    .map_err(|error| {
        diagnostic(
            "rust.lockfile.invalid_toml",
            Some(&evidence.lockfile_path),
            format!("could not decode Cargo.lock: {error}"),
        )
    })?;
    if !(MINIMUM_LOCKFILE_VERSION..=MAXIMUM_LOCKFILE_VERSION).contains(&lockfile.version) {
        return Err(diagnostic(
            "rust.lockfile.unsupported_version",
            Some(&evidence.lockfile_path),
            format!(
                "Cargo.lock version {} is unsupported; expected {} through {}",
                lockfile.version, MINIMUM_LOCKFILE_VERSION, MAXIMUM_LOCKFILE_VERSION
            ),
        ));
    }

    let mut artifacts = Vec::with_capacity(evidence.packages.len());
    for binding in &evidence.packages {
        if is_cancelled(cancellation) {
            return Err(cancelled_diagnostic(Some(&binding.rustdoc_json_path)));
        }
        require_non_empty("package_id", &binding.package_id)?;
        require_non_empty("crate_name", &binding.crate_name)?;
        require_non_empty("rustdoc_toolchain", &binding.rustdoc_toolchain)?;
        if binding.rustdoc_format_version != rustdoc_types::FORMAT_VERSION {
            return Err(diagnostic(
                "rust.rustdoc.unsupported_expected_version",
                Some(&binding.rustdoc_json_path),
                format!(
                    "configured rustdoc format {} is unsupported; this producer accepts {}",
                    binding.rustdoc_format_version,
                    rustdoc_types::FORMAT_VERSION
                ),
            ));
        }

        let artifact = read_evidence_file(&binding.rustdoc_json_path, limits, cancellation)?;
        let envelope: RustdocVersionEnvelope =
            serde_json::from_slice(artifact.bytes()).map_err(|error| {
                diagnostic(
                    "rust.rustdoc.invalid_json",
                    Some(&binding.rustdoc_json_path),
                    format!("could not read rustdoc JSON version: {error}"),
                )
            })?;
        if envelope.format_version != rustdoc_types::FORMAT_VERSION {
            return Err(diagnostic(
                "rust.rustdoc.unsupported_version",
                Some(&binding.rustdoc_json_path),
                format!(
                    "rustdoc JSON format {} is unsupported; this producer accepts {}",
                    envelope.format_version,
                    rustdoc_types::FORMAT_VERSION
                ),
            ));
        }
        let document: RustdocCrate = serde_json::from_slice(artifact.bytes()).map_err(|error| {
            diagnostic(
                "rust.rustdoc.invalid_json",
                Some(&binding.rustdoc_json_path),
                format!(
                    "could not decode rustdoc JSON format {}: {error}",
                    envelope.format_version
                ),
            )
        })?;
        if document.target.triple != evidence.target {
            return Err(diagnostic(
                "rust.rustdoc.target_mismatch",
                Some(&binding.rustdoc_json_path),
                format!(
                    "rustdoc target {} does not match selected target {}",
                    document.target.triple, evidence.target
                ),
            ));
        }

        let mut enabled_features = binding.enabled_features.clone();
        enabled_features.sort();
        enabled_features.dedup();
        artifacts.push(DecodedRustdocArtifact {
            package_id: binding.package_id.clone(),
            crate_name: binding.crate_name.clone(),
            enabled_features,
            toolchain: binding.rustdoc_toolchain.clone(),
            document,
        });
    }

    Ok(DecodedRustDependencyEvidence {
        metadata,
        lockfile,
        artifacts,
    })
}

fn read_evidence_file(
    path: &Path,
    limits: &DependencyPackLimits,
    cancellation: Option<&CancellationToken>,
) -> Result<crate::analyzer::semantic_model::ExactArtifact, DependencyPackDiagnostic> {
    read_exact_artifact_while(path, &limits.producer, || is_cancelled(cancellation))
        .map_err(|producer| producer_diagnostic(path, producer))
}

fn producer_diagnostic(path: &Path, producer: ProducerDiagnostic) -> DependencyPackDiagnostic {
    DependencyPackDiagnostic {
        severity: match producer.severity {
            ProducerDiagnosticSeverity::Warning => DependencyPackDiagnosticSeverity::Warning,
            ProducerDiagnosticSeverity::Error => DependencyPackDiagnosticSeverity::Error,
        },
        code: producer.code,
        dependency_id: None,
        location: Some(path.to_string_lossy().into_owned()),
        message: producer.message,
    }
}

fn require_non_empty(field: &str, value: &str) -> Result<(), DependencyPackDiagnostic> {
    if value.trim().is_empty() {
        return Err(diagnostic(
            "rust.evidence.empty_field",
            None,
            format!("Rust dependency evidence field {field} must not be empty"),
        ));
    }
    Ok(())
}

fn is_cancelled(cancellation: Option<&CancellationToken>) -> bool {
    cancellation.is_some_and(CancellationToken::is_cancelled)
}

fn cancelled_diagnostic(path: Option<&Path>) -> DependencyPackDiagnostic {
    diagnostic(
        "rust.evidence.cancelled",
        path,
        "Rust dependency evidence decoding was cancelled",
    )
}

fn diagnostic(
    code: &str,
    path: Option<&Path>,
    message: impl Into<String>,
) -> DependencyPackDiagnostic {
    DependencyPackDiagnostic {
        severity: DependencyPackDiagnosticSeverity::Error,
        code: code.to_owned(),
        dependency_id: None,
        location: path.map(|value| value.to_string_lossy().into_owned()),
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::fs;

    use rustdoc_types::{Crate as RustdocCrate, Id, Target};
    use serde_json::json;
    use tempfile::TempDir;

    use super::*;
    use crate::analyzer::{RustPackageApiArtifact, RustSelectedTarget};

    const PACKAGE_ID: &str = "registry+https://github.com/rust-lang/crates.io-index#widget@1.2.3";
    const TARGET: &str = "x86_64-unknown-linux-gnu";

    #[test]
    fn exact_evidence_decodes_supported_metadata_lockfile_and_rustdoc() {
        let fixture = EvidenceFixture::new();
        let decoded = decode_rust_dependency_evidence(
            &fixture.evidence,
            &DependencyPackLimits::default(),
            None,
        )
        .unwrap();

        assert_eq!(decoded.metadata.version, CARGO_METADATA_FORMAT_VERSION);
        assert_eq!(decoded.metadata.packages.len(), 1);
        assert_eq!(decoded.metadata.packages[0].id, PACKAGE_ID);
        assert_eq!(decoded.metadata.packages[0].name, "widget");
        assert_eq!(decoded.metadata.packages[0].version, "1.2.3");
        assert_eq!(
            decoded.metadata.packages[0].source.as_deref(),
            Some("registry+https://github.com/rust-lang/crates.io-index")
        );
        assert_eq!(decoded.metadata.resolve.as_ref().unwrap().nodes.len(), 1);
        assert_eq!(
            decoded.metadata.resolve.as_ref().unwrap().nodes[0].id,
            PACKAGE_ID
        );
        assert_eq!(
            decoded.metadata.resolve.as_ref().unwrap().nodes[0].features,
            ["derive"]
        );
        assert_eq!(decoded.lockfile.version, MAXIMUM_LOCKFILE_VERSION);
        assert_eq!(decoded.lockfile.packages.len(), 1);
        assert_eq!(decoded.lockfile.packages[0].name, "widget");
        assert_eq!(decoded.lockfile.packages[0].version, "1.2.3");
        assert_eq!(
            decoded.lockfile.packages[0].source.as_deref(),
            Some("registry+https://github.com/rust-lang/crates.io-index")
        );
        assert_eq!(
            decoded.lockfile.packages[0].checksum.as_deref(),
            Some("abc123")
        );
        assert_eq!(decoded.artifacts.len(), 1);
        assert_eq!(decoded.artifacts[0].package_id, PACKAGE_ID);
        assert_eq!(decoded.artifacts[0].crate_name, "widget");
        assert_eq!(decoded.artifacts[0].enabled_features, ["derive"]);
        assert_eq!(decoded.artifacts[0].toolchain, "nightly-2026-07-14");
        assert_eq!(decoded.artifacts[0].document.target.triple, TARGET);
    }

    #[test]
    fn unsupported_rustdoc_version_fails_before_full_decode() {
        let fixture = EvidenceFixture::new();
        fs::write(
            &fixture.rustdoc_path,
            serde_json::to_vec(&json!({ "format_version": rustdoc_types::FORMAT_VERSION + 1 }))
                .unwrap(),
        )
        .unwrap();

        let diagnostic = decode_rust_dependency_evidence(
            &fixture.evidence,
            &DependencyPackLimits::default(),
            None,
        )
        .unwrap_err();

        assert_eq!(diagnostic.code, "rust.rustdoc.unsupported_version");
    }

    #[test]
    fn rustdoc_target_must_match_selected_target() {
        let fixture = EvidenceFixture::new();
        fixture.write_rustdoc("aarch64-apple-darwin");

        let diagnostic = decode_rust_dependency_evidence(
            &fixture.evidence,
            &DependencyPackLimits::default(),
            None,
        )
        .unwrap_err();

        assert_eq!(diagnostic.code, "rust.rustdoc.target_mismatch");
    }

    #[test]
    fn cancellation_stops_before_decoding_evidence() {
        let fixture = EvidenceFixture::new();
        let cancellation = CancellationToken::new();
        cancellation.cancel();

        let diagnostic = decode_rust_dependency_evidence(
            &fixture.evidence,
            &DependencyPackLimits::default(),
            Some(&cancellation),
        )
        .unwrap_err();

        assert_eq!(diagnostic.code, "artifact.cancelled");
    }

    struct EvidenceFixture {
        _root: TempDir,
        rustdoc_path: std::path::PathBuf,
        evidence: RustDependencyApiEvidence,
    }

    impl EvidenceFixture {
        fn new() -> Self {
            let root = tempfile::tempdir().unwrap();
            let metadata_path = root.path().join("metadata.json");
            let lockfile_path = root.path().join("Cargo.lock");
            let rustdoc_path = root.path().join("widget.json");
            fs::write(
                &metadata_path,
                serde_json::to_vec(&json!({
                    "version": CARGO_METADATA_FORMAT_VERSION,
                    "packages": [{
                        "id": PACKAGE_ID,
                        "name": "widget",
                        "version": "1.2.3",
                        "source": "registry+https://github.com/rust-lang/crates.io-index"
                    }],
                    "resolve": {
                        "nodes": [{
                            "id": PACKAGE_ID,
                            "features": ["derive"]
                        }]
                    }
                }))
                .unwrap(),
            )
            .unwrap();
            fs::write(
                &lockfile_path,
                "version = 4\n\n[[package]]\nname = \"widget\"\nversion = \"1.2.3\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"abc123\"\n",
            )
            .unwrap();
            let evidence = RustDependencyApiEvidence {
                metadata_path,
                lockfile_path,
                target: TARGET.to_owned(),
                configuration: "library".to_owned(),
                selected_targets: vec![RustSelectedTarget {
                    package_id: "path+file:///workspace#consumer@0.1.0".to_owned(),
                    target_name: "consumer".to_owned(),
                    target_kind: "lib".to_owned(),
                }],
                packages: vec![RustPackageApiArtifact {
                    package_id: PACKAGE_ID.to_owned(),
                    crate_name: "widget".to_owned(),
                    enabled_features: vec!["derive".to_owned()],
                    rustdoc_json_path: rustdoc_path.clone(),
                    rustdoc_toolchain: "nightly-2026-07-14".to_owned(),
                    rustdoc_format_version: rustdoc_types::FORMAT_VERSION,
                }],
            };
            let fixture = Self {
                _root: root,
                rustdoc_path,
                evidence,
            };
            fixture.write_rustdoc(TARGET);
            fixture
        }

        fn write_rustdoc(&self, target: &str) {
            let document = RustdocCrate {
                root: Id(0),
                crate_version: Some("1.2.3".to_owned()),
                includes_private: false,
                index: HashMap::new(),
                paths: HashMap::new(),
                external_crates: HashMap::new(),
                target: Target {
                    triple: target.to_owned(),
                    target_features: Vec::new(),
                },
                format_version: rustdoc_types::FORMAT_VERSION,
            };
            fs::write(&self.rustdoc_path, serde_json::to_vec(&document).unwrap()).unwrap();
        }
    }
}
