//! The canonical codec of a JVM external selection's answer digest.
//!
//! An answer digest is compared at head by read verification, so it must be a
//! canonical encoding, not `Debug` output: every field is hashed under its own
//! name, every sequence is count-prefixed, and every enum is written through an
//! exhaustive `match` with an explicit tag. Each struct is destructured without
//! `..`, so adding a field to a covered type fails to compile until this codec
//! either hashes it or excludes it here with a stated reason.
//!
//! The codec version lives in the two domain literals. Change the version
//! suffix when the encoding changes (a field added, removed or reordered, a tag
//! renumbered): digests then differ, and replay fails closed on the change.
//!
//! Ordering. A sequence is hashed in the order the selection produced it when
//! that order is part of the answer (search roots, resolution probes, the
//! dependency list that catalog expectations index positionally). A sequence
//! that is a set by meaning is sorted first. Both orders compare path and name
//! bytes as `OsStr::as_encoded_bytes`, which is UTF-8 on Unix and WTF-8 on
//! Windows, so equal names order equally on every platform and never by
//! UTF-16 code units or the platform's `PathBuf` comparison.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;
use brokk_bifrost_semantic::analyzer::semantic_model::dependency::{
    DependencyArtifactRole, DependencyProvenance, ResolvedDependency, ResolvedDependencyArtifact,
    ResolvedDependencyArtifactInput,
};
use brokk_bifrost_semantic::analyzer::semantic_model::model::{
    RustArtifactApproximation, RustArtifactMismatchKind,
};
use brokk_bifrost_semantic::analyzer::semantic_model::producer::ExternalArtifactKind;
use brokk_bifrost_semantic::analyzer::semantic_model::runtime::SemanticModelActivationEvidence;
use brokk_bifrost_semantic::analyzer::semantic_model::{ArtifactSourceIdentity, CatalogCoordinate};

/// Codec version 4 of the dependencies answer. Version 1 hashed `Debug` output;
/// version 2 hashed only the last selection failure, version 3 hashes every
/// failure in the order selection met them, and version 4 hashes typed
/// unresolved-coordinate failures.
pub(crate) const DEPENDENCIES_ANSWER_DOMAIN: &[u8] =
    b"bifrost-external-selection-answer:dependencies:v4";
/// Codec version 2 of the JDK answer. Version 1 hashed `Debug` output of the
/// artifact kind and left most of each dependency out.
pub(crate) const JDK_ANSWER_DOMAIN: &[u8] = b"bifrost-external-selection-answer:jdk:v2";

pub(crate) fn flag(hash: &mut CanonicalHasher, name: &str, value: bool) {
    hash.field(name, &[u8::from(value)]);
}

pub(crate) fn text(hash: &mut CanonicalHasher, name: &str, value: &str) {
    hash.field(name, value.as_bytes());
}

fn optional_bytes(hash: &mut CanonicalHasher, name: &str, value: Option<&[u8]>) {
    flag(hash, name, value.is_some());
    if let Some(value) = value {
        hash.field(name, value);
    }
}

pub(crate) fn optional_text(hash: &mut CanonicalHasher, name: &str, value: Option<&str>) {
    optional_bytes(hash, name, value.map(str::as_bytes));
}

pub(crate) fn path(hash: &mut CanonicalHasher, name: &str, value: &Path) {
    hash.field(name, value.as_os_str().as_encoded_bytes());
}

pub(crate) fn optional_os(hash: &mut CanonicalHasher, name: &str, value: &Option<OsString>) {
    optional_bytes(hash, name, value.as_deref().map(|v| v.as_encoded_bytes()));
}

/// Paths in the order the selection produced them.
pub(crate) fn paths(hash: &mut CanonicalHasher, name: &str, values: &[PathBuf]) {
    hash.sequence(name, values, |hash, value| path(hash, "path", value));
}

/// Paths as a set: sorted by encoded bytes, never by `PathBuf` order.
pub(crate) fn sorted_paths(hash: &mut CanonicalHasher, name: &str, values: &[PathBuf]) {
    let mut sorted: Vec<&PathBuf> = values.iter().collect();
    sorted.sort_unstable_by(|a, b| {
        a.as_os_str()
            .as_encoded_bytes()
            .cmp(b.as_os_str().as_encoded_bytes())
    });
    hash.sequence(name, &sorted, |hash, value| path(hash, "path", value));
}

pub(crate) fn artifact_kind(hash: &mut CanonicalHasher, name: &str, kind: ExternalArtifactKind) {
    // An exhaustive match: a new kind fails to compile here until it has a tag.
    let tag = match kind {
        ExternalArtifactKind::NpmPackageManifest => "npm_package_manifest",
        ExternalArtifactKind::TypeScriptDeclarationFile => "type_script_declaration_file",
        ExternalArtifactKind::JavaSourceJar => "java_source_jar",
        ExternalArtifactKind::JavaClassJar => "java_class_jar",
        ExternalArtifactKind::ScalaSourceJar => "scala_source_jar",
        ExternalArtifactKind::KotlinSourceJar => "kotlin_source_jar",
        ExternalArtifactKind::JdkSourceZip => "jdk_source_zip",
        ExternalArtifactKind::JdkJmodSet => "jdk_jmod_set",
        ExternalArtifactKind::DotNetAssembly => "dot_net_assembly",
        ExternalArtifactKind::RustdocJson => "rustdoc_json",
        ExternalArtifactKind::RustdocJsonSet => "rustdoc_json_set",
        ExternalArtifactKind::TypeScriptLibrarySet => "type_script_library_set",
        ExternalArtifactKind::GoSourceSet => "go_source_set",
        ExternalArtifactKind::PythonStub => "python_stub",
        ExternalArtifactKind::PythonSource => "python_source",
        ExternalArtifactKind::RubyGemArchive => "ruby_gem_archive",
        ExternalArtifactKind::ComposerPackageSourceSet => "composer_package_source_set",
        ExternalArtifactKind::PhpDeclarationStub => "php_declaration_stub",
        ExternalArtifactKind::CppHeaderSourceSet => "cpp_header_source_set",
    };
    text(hash, name, tag);
}

pub(crate) fn artifact_role(hash: &mut CanonicalHasher, name: &str, role: DependencyArtifactRole) {
    let tag = match role {
        DependencyArtifactRole::Metadata => "metadata",
        DependencyArtifactRole::Declarations => "declarations",
        DependencyArtifactRole::Binary => "binary",
        DependencyArtifactRole::Sources => "sources",
        DependencyArtifactRole::Reference => "reference",
        DependencyArtifactRole::Runtime => "runtime",
    };
    text(hash, name, tag);
}

fn coordinate(hash: &mut CanonicalHasher, name: &str, value: &Option<CatalogCoordinate>) {
    flag(hash, name, value.is_some());
    if let Some(CatalogCoordinate { name, version }) = value {
        text(hash, "coordinate_name", name);
        // A semver `Version` displays canonically, including pre-release and
        // build metadata.
        optional_text(
            hash,
            "coordinate_version",
            version.as_ref().map(ToString::to_string).as_deref(),
        );
    }
}

fn evidence(hash: &mut CanonicalHasher, value: &SemanticModelActivationEvidence) {
    let SemanticModelActivationEvidence {
        language,
        ecosystem,
        package,
        module,
        toolchain,
        target,
        configuration,
        artifact_sha256,
    } = value;
    text(hash, "language", language);
    text(hash, "ecosystem", ecosystem);
    coordinate(hash, "package", package);
    coordinate(hash, "module", module);
    coordinate(hash, "toolchain", toolchain);
    optional_text(hash, "target", target.as_deref());
    optional_text(hash, "configuration", configuration.as_deref());
    optional_text(hash, "artifact_sha256", artifact_sha256.as_deref());
}

fn rust_approximation(hash: &mut CanonicalHasher, value: &Option<RustArtifactApproximation>) {
    flag(hash, "rust_artifact_approximation", value.is_some());
    let Some(RustArtifactApproximation {
        built_from_version,
        built_from_features,
        built_from_cfgs,
        target,
        format_version,
        toolchain,
        docsrs_build,
        original_sha256,
        produced_sha256,
        activation_version_requirement,
        mismatch_kinds,
        selection_rule_id,
        selection_rule_version,
    }) = value
    else {
        return;
    };
    text(hash, "built_from_version", built_from_version);
    hash.sequence("built_from_features", built_from_features, |hash, value| {
        text(hash, "feature", value)
    });
    hash.sequence("built_from_cfgs", built_from_cfgs, |hash, value| {
        text(hash, "cfg", value)
    });
    text(hash, "approximation_target", target);
    hash.field("format_version", &format_version.to_be_bytes());
    text(hash, "approximation_toolchain", toolchain);
    flag(hash, "docsrs_build", *docsrs_build);
    text(hash, "original_sha256", original_sha256);
    text(hash, "produced_sha256", produced_sha256);
    text(
        hash,
        "activation_version_requirement",
        activation_version_requirement,
    );
    hash.sequence("mismatch_kinds", mismatch_kinds, |hash, kind| {
        text(
            hash,
            "mismatch_kind",
            match kind {
                RustArtifactMismatchKind::VersionNearby => "version_nearby",
                RustArtifactMismatchKind::FeatureSuperset => "feature_superset",
                RustArtifactMismatchKind::FormatConverted => "format_converted",
            },
        )
    });
    text(hash, "selection_rule_id", selection_rule_id);
    hash.field(
        "selection_rule_version",
        &selection_rule_version.to_be_bytes(),
    );
}

fn source_identity(hash: &mut CanonicalHasher, value: &Option<ArtifactSourceIdentity>) {
    optional_text(
        hash,
        "source_identity",
        value.as_ref().map(ArtifactSourceIdentity::as_str),
    );
}

fn resolved_artifact(hash: &mut CanonicalHasher, value: &ResolvedDependencyArtifact) {
    let ResolvedDependencyArtifact {
        role,
        kind,
        rust_artifact_approximation,
        module,
        input,
        expected_sha256,
        source_identity: identity,
    } = value;
    artifact_role(hash, "role", *role);
    artifact_kind(hash, "kind", *kind);
    rust_approximation(hash, rust_artifact_approximation);
    optional_text(hash, "module", module.as_deref());
    match input {
        ResolvedDependencyArtifactInput::File(file) => {
            text(hash, "input", "file");
            path(hash, "file", file);
        }
        ResolvedDependencyArtifactInput::SourceSet {
            root,
            relative_paths,
        } => {
            text(hash, "input", "source_set");
            path(hash, "root", root);
            // A source set is the set of files under its root.
            sorted_paths(hash, "relative_paths", relative_paths);
        }
    }
    optional_text(hash, "expected_sha256", expected_sha256.as_deref());
    source_identity(hash, identity);
}

/// One resolved dependency, every field. `provenance` and `artifacts` keep the
/// resolver's order: provenance is documented as ordered evidence, and the
/// artifact order is the order production reads and keys them in.
pub(crate) fn resolved_dependency(hash: &mut CanonicalHasher, value: &ResolvedDependency) {
    let ResolvedDependency {
        id,
        evidence: activation_evidence,
        provenance,
        artifacts,
        scope,
        declared_by,
    } = value;
    text(hash, "id", id);
    evidence(hash, activation_evidence);
    hash.sequence("provenance", provenance, |hash, value| {
        let DependencyProvenance { key, value } = value;
        text(hash, "key", key);
        text(hash, "value", value);
    });
    hash.sequence("artifacts", artifacts, resolved_artifact);
    // The scope does not feed the generated-production key, but it is part of
    // the resolved answer a policy can read, so it is part of this digest.
    text(hash, "scope", scope.label());
    optional_text(hash, "declared_by", declared_by.as_deref());
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_analysis::analyzer::topology::DependencyScope;
    use semver::Version;

    fn digest(dependency: &ResolvedDependency) -> [u8; 32] {
        let mut hash = CanonicalHasher::new(b"selection-codec-test");
        resolved_dependency(&mut hash, dependency);
        hash.finish()
    }

    fn coordinate(name: &str, major: u64) -> Option<CatalogCoordinate> {
        Some(CatalogCoordinate {
            name: name.to_owned(),
            version: Some(Version::new(major, 0, 0)),
        })
    }

    /// Every optional field is present and every sequence has two elements, so
    /// each mutation below changes a value the baseline actually encodes.
    fn baseline() -> ResolvedDependency {
        ResolvedDependency {
            id: "dep".into(),
            evidence: SemanticModelActivationEvidence {
                language: "java".into(),
                ecosystem: "maven".into(),
                package: coordinate("package", 1),
                module: coordinate("module", 1),
                toolchain: coordinate("toolchain", 1),
                target: Some("target".into()),
                configuration: Some("configuration".into()),
                artifact_sha256: Some("a".repeat(64)),
            },
            provenance: vec![
                DependencyProvenance {
                    key: "k1".into(),
                    value: "v1".into(),
                },
                DependencyProvenance {
                    key: "k2".into(),
                    value: "v2".into(),
                },
            ],
            artifacts: vec![
                ResolvedDependencyArtifact {
                    role: DependencyArtifactRole::Binary,
                    kind: ExternalArtifactKind::JavaClassJar,
                    rust_artifact_approximation: Some(RustArtifactApproximation {
                        built_from_version: "1.0.0".into(),
                        built_from_features: vec!["f".into()],
                        built_from_cfgs: vec!["c".into()],
                        target: "t".into(),
                        format_version: 1,
                        toolchain: "tc".into(),
                        docsrs_build: false,
                        original_sha256: "b".repeat(64),
                        produced_sha256: "c".repeat(64),
                        activation_version_requirement: "^1".into(),
                        mismatch_kinds: vec![RustArtifactMismatchKind::VersionNearby],
                        selection_rule_id: "rule".into(),
                        selection_rule_version: 1,
                    }),
                    module: Some("m".into()),
                    input: ResolvedDependencyArtifactInput::File(PathBuf::from("a.jar")),
                    expected_sha256: Some("d".repeat(64)),
                    source_identity: Some(ArtifactSourceIdentity::from_digest("e".repeat(64))),
                },
                ResolvedDependencyArtifact {
                    role: DependencyArtifactRole::Sources,
                    kind: ExternalArtifactKind::JavaSourceJar,
                    rust_artifact_approximation: None,
                    module: None,
                    input: ResolvedDependencyArtifactInput::SourceSet {
                        root: PathBuf::from("root"),
                        relative_paths: vec![PathBuf::from("x"), PathBuf::from("y")],
                    },
                    expected_sha256: None,
                    source_identity: None,
                },
            ],
            scope: DependencyScope::Compile,
            declared_by: Some("declarer".into()),
        }
    }

    /// Each mutation changes exactly one field of one covered struct. The
    /// codec destructures every struct without `..`, so a new field fails to
    /// compile there; this test proves that each existing field reaches the
    /// digest, and that no two single-field changes collide.
    #[test]
    fn every_field_of_a_resolved_dependency_reaches_the_digest() {
        type Mutation = (&'static str, fn(&mut ResolvedDependency));
        let mutations: &[Mutation] = &[
            ("id", |d| d.id = "other".into()),
            ("evidence.language", |d| {
                d.evidence.language = "kotlin".into()
            }),
            ("evidence.ecosystem", |d| {
                d.evidence.ecosystem = "gradle".into()
            }),
            ("evidence.package.name", |d| {
                d.evidence.package = coordinate("other", 1)
            }),
            ("evidence.package.version", |d| {
                d.evidence.package = coordinate("package", 2)
            }),
            ("evidence.package.absent", |d| d.evidence.package = None),
            ("evidence.module", |d| d.evidence.module = None),
            ("evidence.toolchain", |d| d.evidence.toolchain = None),
            ("evidence.target", |d| d.evidence.target = None),
            ("evidence.configuration", |d| {
                d.evidence.configuration = None
            }),
            ("evidence.artifact_sha256", |d| {
                d.evidence.artifact_sha256 = None
            }),
            ("provenance.key", |d| d.provenance[0].key = "kx".into()),
            ("provenance.value", |d| d.provenance[0].value = "vx".into()),
            ("provenance.order", |d| d.provenance.reverse()),
            ("provenance.len", |d| {
                d.provenance.pop();
            }),
            ("artifacts.order", |d| d.artifacts.reverse()),
            ("artifacts.len", |d| {
                d.artifacts.pop();
            }),
            ("artifact.role", |d| {
                d.artifacts[0].role = DependencyArtifactRole::Runtime
            }),
            ("artifact.kind", |d| {
                d.artifacts[0].kind = ExternalArtifactKind::KotlinSourceJar
            }),
            ("artifact.approximation.absent", |d| {
                d.artifacts[0].rust_artifact_approximation = None
            }),
            ("approximation.built_from_version", |d| {
                approximation(d).built_from_version = "2.0.0".into()
            }),
            ("approximation.built_from_features", |d| {
                approximation(d).built_from_features.clear()
            }),
            ("approximation.built_from_cfgs", |d| {
                approximation(d).built_from_cfgs.clear()
            }),
            ("approximation.target", |d| {
                approximation(d).target = "u".into()
            }),
            ("approximation.format_version", |d| {
                approximation(d).format_version = 2
            }),
            ("approximation.toolchain", |d| {
                approximation(d).toolchain = "tc2".into()
            }),
            ("approximation.docsrs_build", |d| {
                approximation(d).docsrs_build = true
            }),
            ("approximation.original_sha256", |d| {
                approximation(d).original_sha256 = "f".repeat(64)
            }),
            ("approximation.produced_sha256", |d| {
                approximation(d).produced_sha256 = "f".repeat(64)
            }),
            ("approximation.activation_version_requirement", |d| {
                approximation(d).activation_version_requirement = "^2".into()
            }),
            ("approximation.mismatch_kinds", |d| {
                approximation(d).mismatch_kinds = vec![RustArtifactMismatchKind::FormatConverted]
            }),
            ("approximation.selection_rule_id", |d| {
                approximation(d).selection_rule_id = "rule2".into()
            }),
            ("approximation.selection_rule_version", |d| {
                approximation(d).selection_rule_version = 2
            }),
            ("artifact.module", |d| d.artifacts[0].module = None),
            ("artifact.input.file", |d| {
                d.artifacts[0].input = ResolvedDependencyArtifactInput::File(PathBuf::from("b.jar"))
            }),
            ("artifact.input.variant", |d| {
                d.artifacts[0].input = ResolvedDependencyArtifactInput::SourceSet {
                    root: PathBuf::from("a.jar"),
                    relative_paths: Vec::new(),
                }
            }),
            ("artifact.input.root", |d| {
                d.artifacts[1].input = ResolvedDependencyArtifactInput::SourceSet {
                    root: PathBuf::from("root2"),
                    relative_paths: vec![PathBuf::from("x"), PathBuf::from("y")],
                }
            }),
            ("artifact.input.relative_paths", |d| {
                d.artifacts[1].input = ResolvedDependencyArtifactInput::SourceSet {
                    root: PathBuf::from("root"),
                    relative_paths: vec![PathBuf::from("x"), PathBuf::from("z")],
                }
            }),
            ("artifact.expected_sha256", |d| {
                d.artifacts[0].expected_sha256 = None
            }),
            ("artifact.source_identity", |d| {
                d.artifacts[0].source_identity =
                    Some(ArtifactSourceIdentity::from_digest("f".repeat(64)))
            }),
            ("scope", |d| d.scope = DependencyScope::Test),
            ("declared_by", |d| d.declared_by = None),
        ];

        fn approximation(d: &mut ResolvedDependency) -> &mut RustArtifactApproximation {
            d.artifacts[0]
                .rust_artifact_approximation
                .as_mut()
                .expect("baseline carries an approximation")
        }

        let base = digest(&baseline());
        assert_eq!(base, digest(&baseline()));
        let mut seen = std::collections::HashMap::new();
        for (name, mutate) in mutations {
            let mut changed = baseline();
            mutate(&mut changed);
            let changed = digest(&changed);
            assert_ne!(base, changed, "{name} does not reach the digest");
            if let Some(other) = seen.insert(changed, *name) {
                panic!("{name} and {other} give the same digest");
            }
        }
    }

    /// A source set is the set of files under its root, so the listing order
    /// is not part of the answer.
    #[test]
    fn source_set_relative_paths_hash_as_a_set() {
        let mut reordered = baseline();
        reordered.artifacts[1].input = ResolvedDependencyArtifactInput::SourceSet {
            root: PathBuf::from("root"),
            relative_paths: vec![PathBuf::from("y"), PathBuf::from("x")],
        };
        assert_eq!(digest(&baseline()), digest(&reordered));
    }

    /// Paths order by encoded bytes, so a name above U+007F sorts after ASCII
    /// on every platform, never by UTF-16 code unit.
    #[test]
    fn sorted_paths_order_by_encoded_bytes() {
        let names = [
            PathBuf::from("b"),
            PathBuf::from("\u{10000}"),
            PathBuf::from("\u{ffff}"),
            PathBuf::from("a"),
        ];
        let mut expected = CanonicalHasher::new(b"order");
        paths(
            &mut expected,
            "p",
            &[
                PathBuf::from("a"),
                PathBuf::from("b"),
                PathBuf::from("\u{ffff}"),
                PathBuf::from("\u{10000}"),
            ],
        );
        let mut actual = CanonicalHasher::new(b"order");
        sorted_paths(&mut actual, "p", &names);
        assert_eq!(expected.finish(), actual.finish());
    }
}
