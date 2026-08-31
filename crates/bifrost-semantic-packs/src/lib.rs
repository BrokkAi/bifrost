//! Optional Bifrost-curated semantic packs and their distribution lifecycle.
//!
//! Generic pack artifacts, catalogs, activation, and analyzer overlays remain in
//! `brokk-bifrost-analysis`. This downstream crate owns only Bifrost's prebuilt
//! content and product distribution policy. Analyzer consumers can omit it and
//! register their own packs.

#[cfg(feature = "download")]
pub mod download;
#[cfg(any(feature = "release-tooling", feature = "download"))]
pub mod release_bundle;
#[cfg(feature = "release-tooling")]
pub mod summary_foundry;

use std::error::Error;
use std::fmt::{self, Display, Formatter};

use brokk_bifrost_analysis::analyzer::semantic_model::{
    ArtifactError, CatalogError, CompiledSemanticModelPack, CompiledShardArtifact, DecodeLimits,
    SemanticPackCatalog, SessionPackSource, SessionPackSourceKind, decode_manifest,
    decode_shard_for_manifest,
};

/// One immutable compiled pack embedded in a Bifrost distribution.
///
/// Construction does not decode or globally register content.
/// [`EmbeddedPackRegistry::register_all`] validates and registers the content
/// when a driver opts into Bifrost's bundled packs.
#[derive(Debug, Clone, Copy)]
pub struct EmbeddedSemanticPack<'a> {
    source_id: &'a str,
    manifest_bytes: &'a [u8],
    shard_bytes: &'a [&'a [u8]],
}

impl<'a> EmbeddedSemanticPack<'a> {
    pub const fn new(
        source_id: &'a str,
        manifest_bytes: &'a [u8],
        shard_bytes: &'a [&'a [u8]],
    ) -> Self {
        Self {
            source_id,
            manifest_bytes,
            shard_bytes,
        }
    }

    pub fn source_id(&self) -> &'a str {
        self.source_id
    }

    pub fn decode(
        &self,
        limits: &DecodeLimits,
    ) -> Result<CompiledSemanticModelPack, EmbeddedPackError> {
        if self.source_id.is_empty() {
            return Err(EmbeddedPackError::EmptySourceId);
        }
        let manifest = decode_manifest(self.manifest_bytes, limits)?;
        if manifest.shards.len() != self.shard_bytes.len() {
            return Err(EmbeddedPackError::ShardCount {
                declared: manifest.shards.len(),
                embedded: self.shard_bytes.len(),
            });
        }

        let mut shards = Vec::with_capacity(manifest.shards.len());
        for (descriptor, bytes) in manifest.shards.iter().zip(self.shard_bytes) {
            decode_shard_for_manifest(&manifest, descriptor, bytes, limits)?;
            shards.push(CompiledShardArtifact {
                descriptor: descriptor.clone(),
                bytes: bytes.to_vec(),
            });
        }

        Ok(CompiledSemanticModelPack {
            manifest,
            manifest_bytes: self.manifest_bytes.to_vec(),
            shards,
        })
    }
}

/// An explicitly registered, ordered set of Bifrost-shipped packs.
#[derive(Debug, Clone, Copy)]
pub struct EmbeddedPackRegistry<'a> {
    packs: &'a [EmbeddedSemanticPack<'a>],
}

impl<'a> EmbeddedPackRegistry<'a> {
    pub const fn new(packs: &'a [EmbeddedSemanticPack<'a>]) -> Self {
        Self { packs }
    }

    pub fn packs(&self) -> &[EmbeddedSemanticPack<'a>] {
        self.packs
    }

    /// Validate all artifacts before catalog mutation.
    ///
    /// Registration and the returned provenance records follow registry order.
    /// Callers must use the limits configured on the target catalog.
    pub fn register_all(
        &self,
        catalog: &SemanticPackCatalog,
        limits: &DecodeLimits,
    ) -> Result<Vec<EmbeddedPackRegistration>, EmbeddedPackError> {
        let decoded = self
            .packs
            .iter()
            .map(|pack| pack.decode(limits).map(|decoded| (pack.source_id, decoded)))
            .collect::<Result<Vec<_>, _>>()?;

        decoded
            .iter()
            .map(|(source_id, pack)| {
                let manifest_digest = catalog.register_session_pack(
                    pack,
                    &SessionPackSource {
                        kind: SessionPackSourceKind::Embedded,
                        source_id: (*source_id).to_owned(),
                    },
                )?;
                Ok(EmbeddedPackRegistration {
                    source_id: (*source_id).to_owned(),
                    manifest_digest,
                })
            })
            .collect()
    }
}

/// The Bifrost-curated production registry.
///
/// The reviewed behavior packs shipped with Bifrost.
const SCALA_CASE_CLASS_SHARDS: &[&[u8]] = &[include_bytes!(
    "../embedded/scala-case-class/shards/scala.case-class.generated-members.deflate"
)];
const LOMBOK_1_18_42_SHARDS: &[&[u8]] = &[include_bytes!(
    "../embedded/lombok-1.18.42/shards/java.lombok.generated-accessors.deflate"
)];
const GETSET_0_1_7_SHARDS: &[&[u8]] = &[include_bytes!(
    "../embedded/getset-0.1.7/shards/rust.getset.generated-getter.deflate"
)];
const GO_STDLIB_OS_SHARDS: &[&[u8]] = &[include_bytes!(
    "../embedded/go-stdlib-os/shards/go.stdlib.os.result-contracts.deflate"
)];
const GO_STDLIB_OS_DECLARATION_SHARDS: &[&[u8]] = &[include_bytes!(
    "../embedded/go-stdlib-os-declarations/shards/go.stdlib.os.declarations.deflate"
)];
const GO_STDLIB_ERRORS_SHARDS: &[&[u8]] = &[include_bytes!(
    "../embedded/go-stdlib-errors/shards/go.stdlib.errors.conditional-result-refinements.json"
)];
const GO_STDLIB_ERRORS_DECLARATION_SHARDS: &[&[u8]] = &[include_bytes!(
    "../embedded/go-stdlib-errors-declarations/shards/go.stdlib.errors.declarations.json"
)];
const GO_STDLIB_LOG_SHARDS: &[&[u8]] = &[include_bytes!(
    "../embedded/go-stdlib-log/shards/go.stdlib.log.normal-continuation.deflate"
)];
const GO_STDLIB_LOG_DECLARATION_SHARDS: &[&[u8]] = &[include_bytes!(
    "../embedded/go-stdlib-log-declarations/shards/go.stdlib.log.declarations.deflate"
)];
const GO_STDLIB_NET_SHARDS: &[&[u8]] = &[include_bytes!(
    "../embedded/go-stdlib-net/shards/go.stdlib.net.result-contracts.deflate"
)];
const GO_STDLIB_NET_DECLARATION_SHARDS: &[&[u8]] = &[include_bytes!(
    "../embedded/go-stdlib-net-declarations/shards/go.stdlib.net.declarations.deflate"
)];
const GO_STDLIB_NET_URL_SHARDS: &[&[u8]] = &[include_bytes!(
    "../embedded/go-stdlib-net-url/shards/go.stdlib.net-url.result-contracts.json"
)];
const GO_STDLIB_NET_URL_DECLARATION_SHARDS: &[&[u8]] = &[include_bytes!(
    "../embedded/go-stdlib-net-url-declarations/shards/go.stdlib.net-url.declarations.deflate"
)];
const GO_STDLIB_BYTES_DECLARATION_SHARDS: &[&[u8]] = &[include_bytes!(
    "../embedded/go-stdlib-bytes-declarations/shards/go.stdlib.bytes.declarations.json"
)];
const GO_STDLIB_ENCODING_PEM_SHARDS: &[&[u8]] = &[include_bytes!(
    "../embedded/go-stdlib-encoding-pem/shards/go.stdlib.encoding-pem.result-contracts.json"
)];
const GO_STDLIB_ENCODING_PEM_DECLARATION_SHARDS: &[&[u8]] = &[include_bytes!(
    "../embedded/go-stdlib-encoding-pem-declarations/shards/go.stdlib.encoding-pem.declarations.deflate"
)];
const GO_STDLIB_CRYPTO_X509_SHARDS: &[&[u8]] = &[include_bytes!(
    "../embedded/go-stdlib-crypto-x509/shards/go.stdlib.crypto-x509.parameter-preconditions.json"
)];
const GO_STDLIB_CRYPTO_X509_DECLARATION_SHARDS: &[&[u8]] = &[include_bytes!(
    "../embedded/go-stdlib-crypto-x509-declarations/shards/go.stdlib.crypto-x509.declarations.json"
)];
const GO_STDLIB_PATH_FILEPATH_SHARDS: &[&[u8]] = &[include_bytes!(
    "../embedded/go-stdlib-path-filepath/shards/go.stdlib.path-filepath.declarations.json"
)];
const GO_STDLIB_TESTING_SHARDS: &[&[u8]] = &[
    include_bytes!(
        "../embedded/go-stdlib-testing/shards/go.stdlib.testing.concrete-receivers.deflate"
    ),
    include_bytes!(
        "../embedded/go-stdlib-testing/shards/go.stdlib.testing.normal-continuation.deflate"
    ),
];
const GO_TESTIFY_REQUIRE_SHARDS: &[&[u8]] = &[include_bytes!(
    "../embedded/go-testify-require/shards/go.testify.require.normal-return-refinements.json"
)];
const GO_TESTIFY_REQUIRE_DECLARATION_SHARDS: &[&[u8]] = &[include_bytes!(
    "../embedded/go-testify-require-declarations/shards/go.testify.require.declarations.deflate"
)];
const GO_TESTIFY_ASSERT_SHARDS: &[&[u8]] = &[include_bytes!(
    "../embedded/go-testify-assert/shards/go.testify.assert.conditional-result-refinements.json"
)];
const GO_TESTIFY_ASSERT_DECLARATION_SHARDS: &[&[u8]] = &[include_bytes!(
    "../embedded/go-testify-assert-declarations/shards/go.testify.assert.declarations.deflate"
)];

const BIFROST_EMBEDDED_PACK_ENTRIES: &[EmbeddedSemanticPack<'static>] = &[
    EmbeddedSemanticPack::new(
        "bifrost.scala.case-class@1.0.0",
        include_bytes!("../embedded/scala-case-class/manifest.json"),
        SCALA_CASE_CLASS_SHARDS,
    ),
    EmbeddedSemanticPack::new(
        "bifrost.java.lombok@1.0.0",
        include_bytes!("../embedded/lombok-1.18.42/manifest.json"),
        LOMBOK_1_18_42_SHARDS,
    ),
    EmbeddedSemanticPack::new(
        "bifrost.rust.getset@1.0.0",
        include_bytes!("../embedded/getset-0.1.7/manifest.json"),
        GETSET_0_1_7_SHARDS,
    ),
    EmbeddedSemanticPack::new(
        "bifrost.go.stdlib.os@1.0.0",
        include_bytes!("../embedded/go-stdlib-os/manifest.json"),
        GO_STDLIB_OS_SHARDS,
    ),
    EmbeddedSemanticPack::new(
        "bifrost.go.stdlib.os-declarations@1.0.0",
        include_bytes!("../embedded/go-stdlib-os-declarations/manifest.json"),
        GO_STDLIB_OS_DECLARATION_SHARDS,
    ),
    EmbeddedSemanticPack::new(
        "bifrost.go.stdlib.errors@1.0.0",
        include_bytes!("../embedded/go-stdlib-errors/manifest.json"),
        GO_STDLIB_ERRORS_SHARDS,
    ),
    EmbeddedSemanticPack::new(
        "bifrost.go.stdlib.errors-declarations@1.0.0",
        include_bytes!("../embedded/go-stdlib-errors-declarations/manifest.json"),
        GO_STDLIB_ERRORS_DECLARATION_SHARDS,
    ),
    EmbeddedSemanticPack::new(
        "bifrost.go.stdlib.log@1.0.0",
        include_bytes!("../embedded/go-stdlib-log/manifest.json"),
        GO_STDLIB_LOG_SHARDS,
    ),
    EmbeddedSemanticPack::new(
        "bifrost.go.stdlib.log-declarations@1.0.0",
        include_bytes!("../embedded/go-stdlib-log-declarations/manifest.json"),
        GO_STDLIB_LOG_DECLARATION_SHARDS,
    ),
    EmbeddedSemanticPack::new(
        "bifrost.go.stdlib.net@1.1.0",
        include_bytes!("../embedded/go-stdlib-net/manifest.json"),
        GO_STDLIB_NET_SHARDS,
    ),
    EmbeddedSemanticPack::new(
        "bifrost.go.stdlib.net-declarations@1.1.0",
        include_bytes!("../embedded/go-stdlib-net-declarations/manifest.json"),
        GO_STDLIB_NET_DECLARATION_SHARDS,
    ),
    EmbeddedSemanticPack::new(
        "bifrost.go.stdlib.net-url@1.0.0",
        include_bytes!("../embedded/go-stdlib-net-url/manifest.json"),
        GO_STDLIB_NET_URL_SHARDS,
    ),
    EmbeddedSemanticPack::new(
        "bifrost.go.stdlib.net-url-declarations@1.0.0",
        include_bytes!("../embedded/go-stdlib-net-url-declarations/manifest.json"),
        GO_STDLIB_NET_URL_DECLARATION_SHARDS,
    ),
    EmbeddedSemanticPack::new(
        "bifrost.go.stdlib.bytes-declarations@1.0.0",
        include_bytes!("../embedded/go-stdlib-bytes-declarations/manifest.json"),
        GO_STDLIB_BYTES_DECLARATION_SHARDS,
    ),
    EmbeddedSemanticPack::new(
        "bifrost.go.stdlib.encoding-pem@1.0.0",
        include_bytes!("../embedded/go-stdlib-encoding-pem/manifest.json"),
        GO_STDLIB_ENCODING_PEM_SHARDS,
    ),
    EmbeddedSemanticPack::new(
        "bifrost.go.stdlib.encoding-pem-declarations@1.0.0",
        include_bytes!("../embedded/go-stdlib-encoding-pem-declarations/manifest.json"),
        GO_STDLIB_ENCODING_PEM_DECLARATION_SHARDS,
    ),
    EmbeddedSemanticPack::new(
        "bifrost.go.stdlib.crypto-x509@1.0.0",
        include_bytes!("../embedded/go-stdlib-crypto-x509/manifest.json"),
        GO_STDLIB_CRYPTO_X509_SHARDS,
    ),
    EmbeddedSemanticPack::new(
        "bifrost.go.stdlib.crypto-x509-declarations@1.0.0",
        include_bytes!("../embedded/go-stdlib-crypto-x509-declarations/manifest.json"),
        GO_STDLIB_CRYPTO_X509_DECLARATION_SHARDS,
    ),
    EmbeddedSemanticPack::new(
        "bifrost.go.stdlib.path-filepath@1.0.0",
        include_bytes!("../embedded/go-stdlib-path-filepath/manifest.json"),
        GO_STDLIB_PATH_FILEPATH_SHARDS,
    ),
    EmbeddedSemanticPack::new(
        "bifrost.go.stdlib.testing@1.0.0",
        include_bytes!("../embedded/go-stdlib-testing/manifest.json"),
        GO_STDLIB_TESTING_SHARDS,
    ),
    EmbeddedSemanticPack::new(
        "bifrost.go.testify.require@1.0.0",
        include_bytes!("../embedded/go-testify-require/manifest.json"),
        GO_TESTIFY_REQUIRE_SHARDS,
    ),
    EmbeddedSemanticPack::new(
        "bifrost.go.testify.require-declarations@1.0.0",
        include_bytes!("../embedded/go-testify-require-declarations/manifest.json"),
        GO_TESTIFY_REQUIRE_DECLARATION_SHARDS,
    ),
    EmbeddedSemanticPack::new(
        "bifrost.go.testify.assert@1.0.0",
        include_bytes!("../embedded/go-testify-assert/manifest.json"),
        GO_TESTIFY_ASSERT_SHARDS,
    ),
    EmbeddedSemanticPack::new(
        "bifrost.go.testify.assert-declarations@1.0.0",
        include_bytes!("../embedded/go-testify-assert-declarations/manifest.json"),
        GO_TESTIFY_ASSERT_DECLARATION_SHARDS,
    ),
];

pub static BIFROST_EMBEDDED_PACKS: EmbeddedPackRegistry<'static> =
    EmbeddedPackRegistry::new(BIFROST_EMBEDDED_PACK_ENTRIES);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmbeddedPackRegistration {
    pub source_id: String,
    pub manifest_digest: String,
}

#[derive(Debug)]
pub enum EmbeddedPackError {
    EmptySourceId,
    ShardCount { declared: usize, embedded: usize },
    Artifact(ArtifactError),
    Catalog(CatalogError),
}

impl Display for EmbeddedPackError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptySourceId => formatter.write_str("embedded pack source id must not be empty"),
            Self::ShardCount { declared, embedded } => write!(
                formatter,
                "embedded pack declares {declared} shards but contains {embedded} shard payloads"
            ),
            Self::Artifact(error) => write!(formatter, "invalid embedded pack artifact: {error}"),
            Self::Catalog(error) => write!(formatter, "failed to register embedded pack: {error}"),
        }
    }
}

impl Error for EmbeddedPackError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Artifact(error) => Some(error),
            Self::Catalog(error) => Some(error),
            Self::EmptySourceId | Self::ShardCount { .. } => None,
        }
    }
}

impl From<ArtifactError> for EmbeddedPackError {
    fn from(error: ArtifactError) -> Self {
        Self::Artifact(error)
    }
}

impl From<CatalogError> for EmbeddedPackError {
    fn from(error: CatalogError) -> Self {
        Self::Catalog(error)
    }
}

#[cfg(test)]
#[path = "../../../test-support/inline_project.rs"]
mod inline_project;

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::PathBuf;
    use std::process::Command;
    use std::sync::Arc;
    use std::time::Duration;

    use brokk_bifrost_analysis::analyzer::semantic_model::{
        CatalogCoordinate, CatalogOptions, CompiledConditionalResultRefinement,
        CompiledDeclaredEffect, CompiledDeclaredEffectCertainty, CompiledDeclaredEffectTiming,
        CompiledNormalReturnRefinement, CompiledOperationPrecondition,
        CompiledPredicateProofEffect, CompiledResultMemberContract, CompiledResultPredicate,
        CompiledSummaryEffect, CompiledSummaryInput, CompiledSummaryOutput, CompilerOptions,
        Completeness, DependencyDiscoveryOutcome, DependencyPackLimits, DurablePackSource,
        DurablePackSourceKind, Locator, MemberIdentity, MemberKind, ProcedureSummaryMemberKey,
        SemanticModelActivationEvidence, SemanticModelActivationRequest,
        SemanticModelMatchDisposition, SemanticModelRuntimeLimits, SemanticModelRuntimeOutcome,
        SemanticPackSelectorQuery, SourceFormat, TypeIdentity, TypeKind, TypeRef,
        acquire_active_semantic_models, compile_source, member_declaration_id,
        prepare_compatible_installed_semantic_packs, type_declaration_id,
    };
    use brokk_bifrost_analysis::analyzer::usages::call_relations::CallRelationLimits;
    use brokk_bifrost_analysis::analyzer::usages::call_shape::call_shapes_in_file;
    use brokk_bifrost_analysis::analyzer::usages::effects::{
        ModeledCallApplication, ModeledCallTargetCoverage, ModeledCallTargetOrigin,
        modeled_call_targets_for_shape,
    };
    use brokk_bifrost_analysis::analyzer::{
        GoAnalyzerConfig, GoDependencyDiscoveryMode, resolve_go_semantic_pack_dependencies,
    };
    use brokk_bifrost_analysis::{AnalyzerConfig, CancellationToken, Language};

    use super::inline_project::InlineTestProject;
    use super::*;

    const PACK_SOURCE: &[u8] = br#"{
      "schema_version": 1,
      "pack_id": "bifrost.fixture.embedded",
      "version": "1.0.0",
      "producer": { "name": "bifrost-fixture", "version": "1.0.0" },
      "language": "java",
      "ecosystem": "maven",
      "compatibility": { "bifrost": ">=0.8.0, <1.0.0", "toolchains": [] },
      "provenance": { "source": "bifrost-test-fixture", "revision": "fixture-v1" },
      "license": "Apache-2.0",
      "completeness": "complete",
      "safety": { "generated_code_only": false, "review_required": false },
      "shards": [{
        "id": "fixture.core",
        "activation": [{ "package": { "name": "example:fixture", "version": "=1.0.0" } }],
        "payload": {
          "kind": "declaration_facts",
          "types": [{
            "id": "fixture.type",
            "name": "example.Fixture",
            "type_kind": "class",
            "visibility": "public",
            "type_parameters": [],
            "hierarchy": [],
            "aliases": [],
            "extension_surfaces": [],
            "locator": { "kind": "artifact", "path": "example/Fixture.class", "symbol": "example.Fixture" }
          }],
          "members": [],
          "relations": []
        }
      }]
    }"#;

    fn compiled_fixture() -> CompiledSemanticModelPack {
        compile_source(SourceFormat::Json, PACK_SOURCE, &CompilerOptions::default())
            .unwrap_or_else(|diagnostics| panic!("fixture compilation failed: {diagnostics:#?}"))
    }

    #[test]
    fn embedded_pack_decodes_and_registers_idempotently() {
        let compiled = compiled_fixture();
        let shard_bytes = compiled
            .shards
            .iter()
            .map(|shard| shard.bytes.as_slice())
            .collect::<Vec<_>>();
        let embedded = EmbeddedSemanticPack::new(
            "bifrost.fixture.embedded@1",
            &compiled.manifest_bytes,
            &shard_bytes,
        );
        let packs = [embedded];
        let registry = EmbeddedPackRegistry::new(&packs);
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();

        let first = registry
            .register_all(&catalog, &DecodeLimits::default())
            .unwrap();
        let second = registry
            .register_all(&catalog, &DecodeLimits::default())
            .unwrap();

        assert_eq!(first, second);
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].source_id, "bifrost.fixture.embedded@1");
        assert_eq!(first[0].manifest_digest, compiled.manifest.content_sha256);
    }

    #[test]
    fn registry_preserves_declared_registration_order() {
        let compiled = compiled_fixture();
        let shard_bytes = compiled
            .shards
            .iter()
            .map(|shard| shard.bytes.as_slice())
            .collect::<Vec<_>>();
        let packs = [
            EmbeddedSemanticPack::new(
                "bifrost.fixture.second@1",
                &compiled.manifest_bytes,
                &shard_bytes,
            ),
            EmbeddedSemanticPack::new(
                "bifrost.fixture.first@1",
                &compiled.manifest_bytes,
                &shard_bytes,
            ),
        ];
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();

        let registrations = EmbeddedPackRegistry::new(&packs)
            .register_all(&catalog, &DecodeLimits::default())
            .unwrap();

        assert_eq!(
            registrations
                .iter()
                .map(|registration| registration.source_id.as_str())
                .collect::<Vec<_>>(),
            ["bifrost.fixture.second@1", "bifrost.fixture.first@1"]
        );
    }

    #[test]
    fn every_shipped_pack_decodes_and_the_go_contracts_are_present() {
        let decoded = BIFROST_EMBEDDED_PACKS
            .packs()
            .iter()
            .map(|pack| {
                pack.decode(&DecodeLimits::default())
                    .unwrap_or_else(|error| {
                        panic!("{} failed to decode: {error}", pack.source_id())
                    })
            })
            .collect::<Vec<_>>();

        for pack_id in [
            "bifrost.go.stdlib.os-declarations",
            "bifrost.go.stdlib.errors-declarations",
            "bifrost.go.stdlib.log-declarations",
            "bifrost.go.stdlib.net-declarations",
            "bifrost.go.stdlib.net-url-declarations",
            "bifrost.go.stdlib.bytes-declarations",
            "bifrost.go.stdlib.encoding-pem-declarations",
            "bifrost.go.stdlib.crypto-x509-declarations",
            "bifrost.go.stdlib.path-filepath",
            "bifrost.go.testify.assert-declarations",
            "bifrost.go.testify.require-declarations",
        ] {
            let pack = decoded
                .iter()
                .find(|pack| pack.manifest.pack_id == pack_id)
                .unwrap_or_else(|| panic!("the {pack_id} declaration pack ships"));
            assert_eq!(
                pack.manifest.completeness,
                Completeness::Partial,
                "a reviewed declaration subset cannot claim package completeness"
            );
            let [artifact] = pack.shards.as_slice() else {
                panic!("the {pack_id} companion has one declaration shard: {pack:#?}");
            };
            let shard = decode_shard_for_manifest(
                &pack.manifest,
                &artifact.descriptor,
                &artifact.bytes,
                &DecodeLimits::default(),
            )
            .unwrap_or_else(|error| panic!("the {pack_id} declaration shard decodes: {error}"));
            let (types, members, _) = shard
                .payload()
                .declaration_facts()
                .unwrap_or_else(|| panic!("the {pack_id} companion carries declaration facts"));
            assert!(
                !types.is_empty() && !members.is_empty(),
                "the {pack_id} companion publishes positive package and member facts"
            );
        }

        let filepath = decoded
            .iter()
            .find(|pack| pack.manifest.pack_id == "bifrost.go.stdlib.path-filepath")
            .expect("the Go path/filepath declaration pack ships");
        let filepath_shard = decode_shard_for_manifest(
            &filepath.manifest,
            &filepath.shards[0].descriptor,
            &filepath.shards[0].bytes,
            &DecodeLimits::default(),
        )
        .expect("the Go path/filepath declaration shard decodes");
        let (types, members, relations) = filepath_shard
            .payload()
            .declaration_facts()
            .expect("the Go path/filepath pack carries declaration facts");
        assert!(relations.is_empty());
        assert_eq!(types.len(), 1);
        assert_eq!(types[0].name, "path/filepath");
        let [join] = members else {
            panic!("the Go path/filepath pack carries only Join: {members:#?}");
        };
        assert_eq!(join.name, "Join");
        assert!(join.is_static);
        let signature = join
            .signature
            .as_ref()
            .expect("path/filepath.Join has a structured signature");
        let [elements] = signature.parameters.as_slice() else {
            panic!("path/filepath.Join has one variadic parameter: {signature:#?}");
        };
        assert!(elements.variadic);
        assert!(matches!(
            signature.returns.as_ref(),
            Some(TypeRef::Named { name, .. }) if name == "string"
        ));

        let go = decoded
            .iter()
            .find(|pack| pack.manifest.pack_id == "bifrost.go.stdlib.os")
            .expect("the Go standard-library pack ships");
        let shard = decode_shard_for_manifest(
            &go.manifest,
            &go.shards[0].descriptor,
            &go.shards[0].bytes,
            &DecodeLimits::default(),
        )
        .expect("the Go shard decodes");
        let summaries = shard
            .payload()
            .procedure_summaries()
            .expect("the Go shard carries procedure summaries");

        assert_eq!(go.manifest.provenance.source, "https://pkg.go.dev/os");
        assert_eq!(go.manifest.provenance.revision.as_deref(), Some("go1.26.0"));

        assert_eq!(summaries.len(), 9);
        let exit = summaries
            .iter()
            .find(|summary| summary.id == "os.exit")
            .expect("the shipped os.Exit summary is present");
        assert!(exit.normal_continuation_absent);
        assert_eq!(exit.target.symbol, "os.Exit(code int)");
        assert!(!exit.target.has_receiver);
        assert_eq!(exit.target.parameter_count, 1);
        assert!(exit.transfers.is_empty());
        assert!(exit.effects.is_empty());
        assert!(exit.result_contracts.is_empty());

        let is_not_exist = summaries
            .iter()
            .find(|summary| summary.id == "os.is-not-exist")
            .expect("the shipped os.IsNotExist summary is present");
        assert_eq!(is_not_exist.target.path, "src/os/error.go");
        assert_eq!(is_not_exist.target.symbol, "os.IsNotExist(err error)");
        assert!(!is_not_exist.target.has_receiver);
        assert!(!is_not_exist.target.variadic);
        assert_eq!(is_not_exist.target.parameter_count, 1);
        assert_eq!(is_not_exist.normal_result_count, Some(1));
        assert_eq!(
            is_not_exist.conditional_result_refinements,
            [
                CompiledConditionalResultRefinement {
                    result_ordinal: 0,
                    outcome: false,
                    parameter_ordinal: 0,
                    predicate: CompiledResultPredicate::Null,
                    proof_effect: CompiledPredicateProofEffect::DoesNotEstablish,
                },
                CompiledConditionalResultRefinement {
                    result_ordinal: 0,
                    outcome: true,
                    parameter_ordinal: 0,
                    predicate: CompiledResultPredicate::NonNull,
                    proof_effect: CompiledPredicateProofEffect::Establishes,
                },
            ]
        );
        assert!(is_not_exist.transfers.is_empty());
        assert!(is_not_exist.effects.is_empty());
        assert!(is_not_exist.result_contracts.is_empty());

        let os_declarations = decoded
            .iter()
            .find(|pack| pack.manifest.pack_id == "bifrost.go.stdlib.os-declarations")
            .expect("the Go os declaration pack ships");
        let shard = decode_shard_for_manifest(
            &os_declarations.manifest,
            &os_declarations.shards[0].descriptor,
            &os_declarations.shards[0].bytes,
            &DecodeLimits::default(),
        )
        .expect("the Go os declaration shard decodes");
        let (_, members, _) = shard
            .payload()
            .declaration_facts()
            .expect("the Go os declaration shard carries declaration facts");
        let matching = members
            .iter()
            .filter(|member| member.name == "IsNotExist")
            .collect::<Vec<_>>();
        let [is_not_exist_declaration] = matching.as_slice() else {
            panic!("one shipped os.IsNotExist declaration is present: {matching:#?}");
        };
        assert_eq!(
            is_not_exist_declaration.id,
            "member.0b7d3d36d4dcea4848b41d65abae44a3cb91da603e4b679f99fb8fa8d8be38f6"
        );
        assert_eq!(
            is_not_exist_declaration.owner,
            "type.c63a4fb7a5f3c55b371944a7bc438a3a8ed7e1810420d3fa514fdca43dd2135d"
        );
        assert_eq!(is_not_exist_declaration.member_kind, MemberKind::Function);
        assert!(is_not_exist_declaration.is_static);
        assert!(is_not_exist_declaration.receiver.is_none());
        assert!(matches!(
            &is_not_exist_declaration.locator,
            Locator::Artifact { path, symbol }
                if path == "os/error.go" && symbol == "os.IsNotExist"
        ));
        let signature = is_not_exist_declaration
            .signature
            .as_ref()
            .expect("os.IsNotExist has a structured signature");
        let [err] = signature.parameters.as_slice() else {
            panic!("os.IsNotExist has one parameter: {signature:#?}");
        };
        assert!(!err.optional);
        assert!(!err.variadic);
        assert!(matches!(
            &err.r#type,
            TypeRef::Named { name, .. } if name == "error"
        ));
        assert!(matches!(
            signature.returns.as_ref(),
            Some(TypeRef::Named { name, .. }) if name == "bool"
        ));

        let matching = members
            .iter()
            .filter(|member| member.name == "Fd")
            .collect::<Vec<_>>();
        let [fd_declaration] = matching.as_slice() else {
            panic!("one shipped (*os.File).Fd declaration is present: {matching:#?}");
        };
        assert_eq!(
            fd_declaration.id,
            "member.1aa9023d68a858f9ffa30edc7edbe7acb72f4c4710a0e7335081470d673ba028"
        );
        assert_eq!(
            fd_declaration.owner,
            "type.98a1235b91e4f66cb179865e5a323fd24dce0996c65a2383595eb2373409b147"
        );
        assert_eq!(fd_declaration.member_kind, MemberKind::Method);
        assert!(!fd_declaration.is_static);
        assert!(
            fd_declaration
                .receiver
                .as_ref()
                .is_some_and(|receiver| receiver.pointer)
        );
        assert!(matches!(
            &fd_declaration.locator,
            Locator::Artifact { path, symbol }
                if path == "os/file.go" && symbol == "os.File.Fd"
        ));
        let signature = fd_declaration
            .signature
            .as_ref()
            .expect("(*os.File).Fd has a structured signature");
        assert!(signature.parameters.is_empty());
        assert!(matches!(
            signature.returns.as_ref(),
            Some(TypeRef::Named { name, .. }) if name == "uintptr"
        ));
        assert_eq!(
            fd_declaration.id,
            member_declaration_id(MemberIdentity {
                owner_id: &fd_declaration.owner,
                kind: fd_declaration.member_kind,
                is_static: fd_declaration.is_static,
                parameter_arity: signature.parameters.len(),
                name: &fd_declaration.name,
                generic_arity: signature.type_parameters.len(),
                parameter_types: &[],
                parameter_variadics: &[],
                return_type: signature.returns.as_ref(),
            }),
            "the authored Fd member uses the Go artifact producer's canonical identity"
        );

        let file_stat = summaries
            .iter()
            .find(|summary| summary.id == "os.file-stat")
            .expect("the receiver-bearing os.File.Stat summary is present");
        assert_eq!(file_stat.target.path, "src/os/stat_unix.go");
        assert_eq!(file_stat.target.symbol, "os.File.Stat()");
        assert!(file_stat.target.has_receiver);
        assert_eq!(file_stat.target.parameter_count, 0);

        let receiver_non_null = || {
            Some(vec![CompiledOperationPrecondition {
                input: CompiledSummaryInput::Receiver {},
                predicate: CompiledResultPredicate::NonNull,
            }])
        };
        let file_members = || {
            vec![
                CompiledResultMemberContract {
                    member: "Close".to_owned(),
                    parameter_count: 0,
                    completeness: Completeness::Complete,
                    preconditions: Some(Vec::new()),
                    declared_effects: vec![CompiledDeclaredEffect {
                        id: "go.stdlib.os.file.close".to_owned(),
                        timing: CompiledDeclaredEffectTiming::Immediate,
                        certainty: CompiledDeclaredEffectCertainty::Definite,
                    }],
                },
                CompiledResultMemberContract {
                    member: "Fd".to_owned(),
                    parameter_count: 0,
                    completeness: Completeness::Complete,
                    preconditions: Some(Vec::new()),
                    declared_effects: vec![CompiledDeclaredEffect {
                        id: "go.stdlib.os.file.fd".to_owned(),
                        timing: CompiledDeclaredEffectTiming::Immediate,
                        certainty: CompiledDeclaredEffectCertainty::Definite,
                    }],
                },
                CompiledResultMemberContract {
                    member: "Name".to_owned(),
                    parameter_count: 0,
                    completeness: Completeness::Complete,
                    preconditions: receiver_non_null(),
                    declared_effects: vec![CompiledDeclaredEffect {
                        id: "go.stdlib.os.file.name".to_owned(),
                        timing: CompiledDeclaredEffectTiming::Immediate,
                        certainty: CompiledDeclaredEffectCertainty::Definite,
                    }],
                },
                CompiledResultMemberContract {
                    member: "Read".to_owned(),
                    parameter_count: 1,
                    completeness: Completeness::Complete,
                    preconditions: Some(Vec::new()),
                    declared_effects: vec![CompiledDeclaredEffect {
                        id: "go.stdlib.os.file.read".to_owned(),
                        timing: CompiledDeclaredEffectTiming::Immediate,
                        certainty: CompiledDeclaredEffectCertainty::Definite,
                    }],
                },
                CompiledResultMemberContract {
                    member: "Seek".to_owned(),
                    parameter_count: 2,
                    completeness: Completeness::Complete,
                    preconditions: Some(Vec::new()),
                    declared_effects: Vec::new(),
                },
                CompiledResultMemberContract {
                    member: "Stat".to_owned(),
                    parameter_count: 0,
                    completeness: Completeness::Complete,
                    preconditions: Some(Vec::new()),
                    declared_effects: Vec::new(),
                },
            ]
        };
        let file_info_members = || {
            ["Name", "Size", "Mode", "ModTime", "IsDir", "Sys"]
                .into_iter()
                .map(|member| CompiledResultMemberContract {
                    member: member.to_owned(),
                    parameter_count: 0,
                    completeness: Completeness::Complete,
                    preconditions: receiver_non_null(),
                    declared_effects: Vec::new(),
                })
                .collect::<Vec<_>>()
        };

        let result_contracts = summaries
            .iter()
            .filter(|summary| !summary.result_contracts.is_empty())
            .collect::<Vec<_>>();
        assert_eq!(result_contracts.len(), 7);
        assert!(result_contracts.into_iter().all(|summary| {
            let allocates_file = matches!(
                summary.id.as_str(),
                "os.create" | "os.create-temp" | "os.open" | "os.open-file"
            );
            let returns_file_info =
                matches!(summary.id.as_str(), "os.file-stat" | "os.stat" | "os.lstat");
            let [contract] = summary.result_contracts.as_slice() else {
                return false;
            };
            let expected_members = if allocates_file {
                file_members()
            } else if returns_file_info {
                file_info_members()
            } else {
                return false;
            };
            summary.normal_result_count == Some(2)
                && contract.result_ordinal == 0
                && contract.condition_result_ordinal == Some(1)
                && contract.predicate == Some(CompiledResultPredicate::Null)
                && contract.result_success_predicate == Some(CompiledResultPredicate::NonNull)
                && contract.member_contracts == expected_members
                && summary.effects.iter().any(|effect| {
                    matches!(
                        effect,
                        CompiledSummaryEffect::Allocation {
                            output: CompiledSummaryOutput::IndexedNormalReturn { ordinal: 0 },
                            ..
                        }
                    )
                }) == allocates_file
        }));

        let errors = decoded
            .iter()
            .find(|pack| pack.manifest.pack_id == "bifrost.go.stdlib.errors")
            .expect("the Go errors pack ships");
        let shard = decode_shard_for_manifest(
            &errors.manifest,
            &errors.shards[0].descriptor,
            &errors.shards[0].bytes,
            &DecodeLimits::default(),
        )
        .expect("the Go errors shard decodes");
        let summaries = shard
            .payload()
            .procedure_summaries()
            .expect("the Go errors shard carries procedure summaries");
        let [errors_is] = summaries else {
            panic!("the Go errors pack must carry only errors.Is: {summaries:#?}");
        };
        assert_eq!(errors_is.target.symbol, "errors.Is(err, target error)");
        assert!(!errors_is.target.has_receiver);
        assert_eq!(errors_is.target.parameter_count, 2);
        assert_eq!(errors_is.normal_result_count, Some(1));
        assert_eq!(
            errors_is.conditional_result_refinements,
            [CompiledConditionalResultRefinement {
                result_ordinal: 0,
                outcome: false,
                parameter_ordinal: 0,
                predicate: CompiledResultPredicate::Null,
                proof_effect: CompiledPredicateProofEffect::DoesNotEstablish,
            }]
        );

        let net_url = decoded
            .iter()
            .find(|pack| pack.manifest.pack_id == "bifrost.go.stdlib.net-url")
            .expect("the Go net/url pack ships");
        let shard = decode_shard_for_manifest(
            &net_url.manifest,
            &net_url.shards[0].descriptor,
            &net_url.shards[0].bytes,
            &DecodeLimits::default(),
        )
        .expect("the Go net/url shard decodes");
        let summaries = shard
            .payload()
            .procedure_summaries()
            .expect("the Go net/url shard carries procedure summaries");
        assert_eq!(summaries.len(), 2);
        assert!(summaries.iter().all(|summary| {
            let [contract] = summary.result_contracts.as_slice() else {
                return false;
            };
            contract.result_success_predicate == Some(CompiledResultPredicate::NonNull)
        }));

        let testify = decoded
            .iter()
            .find(|pack| pack.manifest.pack_id == "bifrost.go.testify.require")
            .expect("the Go Testify require pack ships");
        let shard = decode_shard_for_manifest(
            &testify.manifest,
            &testify.shards[0].descriptor,
            &testify.shards[0].bytes,
            &DecodeLimits::default(),
        )
        .expect("the Testify shard decodes");
        let summaries = shard
            .payload()
            .procedure_summaries()
            .expect("the Testify shard carries procedure summaries");
        assert_eq!(summaries.len(), 1);
        assert_eq!(
            summaries[0].target.symbol,
            "github.com/stretchr/testify/require.NoError(t TestingT, err error, msgAndArgs ...interface{})"
        );
        assert!(summaries[0].target.variadic);
        assert_eq!(summaries[0].target.parameter_count, 3);
        assert_eq!(summaries[0].target.minimum_parameter_count(), 2);
        assert!(
            summaries[0].normal_return_refinements[0].parameter_ordinal
                < summaries[0].target.minimum_parameter_count(),
            "the Testify claim refines fixed `err`, never the variadic message tail"
        );
        assert_eq!(
            summaries[0].normal_return_refinements,
            [CompiledNormalReturnRefinement {
                parameter_ordinal: 1,
                predicate: CompiledResultPredicate::Null,
            }]
        );

        let testify_assert = decoded
            .iter()
            .find(|pack| pack.manifest.pack_id == "bifrost.go.testify.assert")
            .expect("the Go Testify assert pack ships");
        let shard = decode_shard_for_manifest(
            &testify_assert.manifest,
            &testify_assert.shards[0].descriptor,
            &testify_assert.shards[0].bytes,
            &DecodeLimits::default(),
        )
        .expect("the Testify assert shard decodes");
        let summaries = shard
            .payload()
            .procedure_summaries()
            .expect("the Testify assert shard carries procedure summaries");
        let [no_error] = summaries else {
            panic!("the Testify assert pack carries only assert.NoError: {summaries:#?}");
        };
        assert_eq!(
            no_error.target.symbol,
            "github.com/stretchr/testify/assert.NoError(t TestingT, err error, msgAndArgs ...interface{})"
        );
        assert!(no_error.target.variadic);
        assert_eq!(no_error.target.parameter_count, 3);
        assert_eq!(no_error.target.minimum_parameter_count(), 2);
        assert_eq!(no_error.normal_result_count, Some(1));
        assert!(
            no_error
                .conditional_result_refinements
                .iter()
                .all(|refinement| {
                    refinement.parameter_ordinal < no_error.target.minimum_parameter_count()
                })
        );
        assert_eq!(
            no_error.conditional_result_refinements,
            [
                CompiledConditionalResultRefinement {
                    result_ordinal: 0,
                    outcome: false,
                    parameter_ordinal: 1,
                    predicate: CompiledResultPredicate::Null,
                    proof_effect: CompiledPredicateProofEffect::DoesNotEstablish,
                },
                CompiledConditionalResultRefinement {
                    result_ordinal: 0,
                    outcome: true,
                    parameter_ordinal: 1,
                    predicate: CompiledResultPredicate::Null,
                    proof_effect: CompiledPredicateProofEffect::Establishes,
                },
            ]
        );
    }

    #[test]
    fn shipped_go_encoding_pem_pack_preserves_direct_contract_and_canonical_declarations() {
        let behavior = BIFROST_EMBEDDED_PACKS
            .packs()
            .iter()
            .find(|pack| pack.source_id() == "bifrost.go.stdlib.encoding-pem@1.0.0")
            .expect("the Go encoding/pem behavior pack ships")
            .decode(&DecodeLimits::default())
            .expect("the Go encoding/pem behavior pack decodes");
        assert_eq!(behavior.manifest.pack_id, "bifrost.go.stdlib.encoding-pem");
        assert_eq!(behavior.manifest.completeness, Completeness::Complete);
        assert_eq!(
            behavior.manifest.provenance.source,
            "https://pkg.go.dev/encoding/pem"
        );
        assert_eq!(
            behavior.manifest.provenance.revision.as_deref(),
            Some("go1.26.0")
        );
        let [shard] = behavior.shards.as_slice() else {
            panic!("the Go encoding/pem behavior pack has one shard: {behavior:#?}");
        };
        let shard = decode_shard_for_manifest(
            &behavior.manifest,
            &shard.descriptor,
            &shard.bytes,
            &DecodeLimits::default(),
        )
        .expect("the Go encoding/pem behavior shard decodes");
        let summaries = shard
            .payload()
            .procedure_summaries()
            .expect("the Go encoding/pem behavior shard carries procedure summaries");
        let [decode] = summaries else {
            panic!("the Go encoding/pem behavior pack carries only Decode: {summaries:#?}");
        };
        assert_eq!(decode.id, "encoding-pem.decode");
        assert_eq!(decode.target.path, "src/encoding/pem/pem.go");
        assert_eq!(decode.target.symbol, "encoding/pem.Decode(data []byte)");
        assert!(!decode.target.has_receiver);
        assert!(!decode.target.variadic);
        assert_eq!(decode.target.parameter_count, 1);
        assert_eq!(decode.normal_result_count, Some(2));
        assert_eq!(decode.completeness, Completeness::Complete);
        assert!(decode.transfers.is_empty());
        assert!(decode.effects.is_empty());
        let [contract] = decode.result_contracts.as_slice() else {
            panic!("encoding/pem.Decode has one direct result contract: {decode:#?}");
        };
        assert_eq!(contract.result_ordinal, 0);
        assert_eq!(contract.condition_result_ordinal, None);
        assert_eq!(contract.predicate, None);
        assert_eq!(
            contract.result_success_predicate,
            Some(CompiledResultPredicate::NonNull)
        );
        assert!(contract.member_contracts.is_empty());

        let declarations = BIFROST_EMBEDDED_PACKS
            .packs()
            .iter()
            .find(|pack| pack.source_id() == "bifrost.go.stdlib.encoding-pem-declarations@1.0.0")
            .expect("the Go encoding/pem declaration pack ships")
            .decode(&DecodeLimits::default())
            .expect("the Go encoding/pem declaration pack decodes");
        assert_eq!(
            declarations.manifest.pack_id,
            "bifrost.go.stdlib.encoding-pem-declarations"
        );
        assert_eq!(declarations.manifest.completeness, Completeness::Partial);
        let [shard] = declarations.shards.as_slice() else {
            panic!("the Go encoding/pem declaration pack has one shard: {declarations:#?}");
        };
        let shard = decode_shard_for_manifest(
            &declarations.manifest,
            &shard.descriptor,
            &shard.bytes,
            &DecodeLimits::default(),
        )
        .expect("the Go encoding/pem declaration shard decodes");
        let (types, members, relations) = shard
            .payload()
            .declaration_facts()
            .expect("the Go encoding/pem declaration shard carries declaration facts");
        assert!(relations.is_empty());
        assert_eq!(types.len(), 2, "only encoding/pem and Block are reviewed");
        for fact in types {
            assert_eq!(
                fact.id,
                type_declaration_id(TypeIdentity {
                    ecosystem: "go",
                    name: &fact.name,
                }),
                "the authored type ID uses the Go artifact producer's canonical identity"
            );
        }
        let module = types
            .iter()
            .find(|fact| fact.name == "encoding/pem")
            .expect("the encoding/pem module declaration ships");
        assert_eq!(module.type_kind, TypeKind::Module);
        assert_eq!(
            module.id,
            "type.523ee6b9392fc5418155ad19c06446eb7eaceddbc940e19a6b37c264962f1bab"
        );
        let block = types
            .iter()
            .find(|fact| fact.name == "encoding/pem.Block")
            .expect("the encoding/pem.Block declaration ships");
        assert_eq!(block.type_kind, TypeKind::Struct);
        assert_eq!(
            block.id,
            "type.502f31c39e30446071dc33aad9163f6dbce9fd0dd0cdbe6c02f6d9c35f4f84c3"
        );

        assert_eq!(
            members.len(),
            4,
            "Decode and the three public Block fields are reviewed"
        );
        for member in members {
            let signature = member
                .signature
                .as_ref()
                .unwrap_or_else(|| panic!("{} has a structured signature", member.name));
            let parameter_types = signature
                .parameters
                .iter()
                .map(|parameter| parameter.r#type.clone())
                .collect::<Vec<_>>();
            let parameter_variadics = signature
                .parameters
                .iter()
                .map(|parameter| parameter.variadic)
                .collect::<Vec<_>>();
            assert_eq!(
                member.id,
                member_declaration_id(MemberIdentity {
                    owner_id: &member.owner,
                    kind: member.member_kind,
                    is_static: member.is_static,
                    parameter_arity: parameter_types.len(),
                    name: &member.name,
                    generic_arity: signature.type_parameters.len(),
                    parameter_types: &parameter_types,
                    parameter_variadics: &parameter_variadics,
                    return_type: signature.returns.as_ref(),
                }),
                "the authored member ID uses the Go artifact producer's canonical identity"
            );
        }

        let decode_declaration = members
            .iter()
            .find(|member| member.name == "Decode")
            .expect("encoding/pem.Decode declaration ships");
        assert_eq!(
            decode_declaration.id,
            "member.bb759c857a5e84d42a5a6028af28ff437269463c0abd0a5fe73529d904c0cbf8"
        );
        assert_eq!(decode_declaration.owner, module.id);
        assert_eq!(decode_declaration.member_kind, MemberKind::Function);
        assert!(decode_declaration.is_static);
        assert!(decode_declaration.receiver.is_none());
        assert!(matches!(
            &decode_declaration.locator,
            Locator::Artifact { path, symbol }
                if path == "encoding/pem/pem.go" && symbol == "encoding/pem.Decode"
        ));
        let signature = decode_declaration
            .signature
            .as_ref()
            .expect("encoding/pem.Decode has a structured signature");
        assert!(signature.type_parameters.is_empty());
        let [data] = signature.parameters.as_slice() else {
            panic!("encoding/pem.Decode has one parameter: {signature:#?}");
        };
        assert_eq!(data.name.as_deref(), Some("data"));
        assert!(!data.optional);
        assert!(!data.variadic);
        assert!(matches!(
            &data.r#type,
            TypeRef::Slice { element }
                if matches!(
                    element.as_ref(),
                    TypeRef::Named { name, arguments, nullable }
                        if name == "byte" && arguments.is_empty() && !nullable
                )
        ));
        let Some(TypeRef::Tuple { elements }) = signature.returns.as_ref() else {
            panic!("encoding/pem.Decode returns (*Block, []byte): {signature:#?}");
        };
        let [decoded_block, rest] = elements.as_slice() else {
            panic!("encoding/pem.Decode returns two results: {signature:#?}");
        };
        assert!(matches!(
            decoded_block,
            TypeRef::Pointer { element }
                if matches!(
                    element.as_ref(),
                    TypeRef::Declared { id, arguments, nullable }
                        if id == &block.id && arguments.is_empty() && !nullable
                )
        ));
        assert!(matches!(
            rest,
            TypeRef::Slice { element }
                if matches!(
                    element.as_ref(),
                    TypeRef::Named { name, arguments, nullable }
                        if name == "byte" && arguments.is_empty() && !nullable
                )
        ));

        for (name, expected_id) in [
            (
                "Type",
                "member.3f0d9ca8f7462d2cdc7d21d1d70e04cf37acbadff593bc8319c0b80e28924389",
            ),
            (
                "Headers",
                "member.f6a87143d5cd7d9bfc4a9fe7b1b960b3087cfd166e3e8b34900d0d1a32ce48b4",
            ),
            (
                "Bytes",
                "member.5aaed0395fdc8573e6c6c4921dc6ec3efbab63b17f4f429a65afa78916809ee8",
            ),
        ] {
            let field = members
                .iter()
                .find(|member| member.name == name)
                .unwrap_or_else(|| panic!("encoding/pem.Block.{name} declaration ships"));
            assert_eq!(field.id, expected_id);
            assert_eq!(field.owner, block.id);
            assert_eq!(field.member_kind, MemberKind::Field);
            assert!(!field.is_static);
            assert!(field.receiver.is_none());
            assert!(matches!(
                &field.locator,
                Locator::Artifact { path, symbol }
                    if path == "encoding/pem/pem.go"
                        && symbol == &format!("encoding/pem.Block.{name}")
            ));
            let signature = field
                .signature
                .as_ref()
                .unwrap_or_else(|| panic!("encoding/pem.Block.{name} has a signature"));
            assert!(signature.type_parameters.is_empty());
            assert!(signature.parameters.is_empty());
            match name {
                "Type" => assert!(matches!(
                    signature.returns.as_ref(),
                    Some(TypeRef::Named { name, arguments, nullable })
                        if name == "string" && arguments.is_empty() && !nullable
                )),
                "Headers" => {
                    let Some(TypeRef::Map { key, value }) = signature.returns.as_ref() else {
                        panic!(
                            "encoding/pem.Block.Headers returns map[string]string: {signature:#?}"
                        );
                    };
                    for part in [key.as_ref(), value.as_ref()] {
                        assert!(matches!(
                            part,
                            TypeRef::Named { name, arguments, nullable }
                                if name == "string" && arguments.is_empty() && !nullable
                        ));
                    }
                }
                "Bytes" => assert!(matches!(
                    signature.returns.as_ref(),
                    Some(TypeRef::Slice { element })
                        if matches!(
                            element.as_ref(),
                            TypeRef::Named { name, arguments, nullable }
                                if name == "byte" && arguments.is_empty() && !nullable
                        )
                )),
                _ => unreachable!("the reviewed Block field matrix is exhaustive"),
            }
        }
    }

    #[test]
    fn shipped_go_bytes_declaration_preserves_trim_space_arity() {
        let declarations = BIFROST_EMBEDDED_PACKS
            .packs()
            .iter()
            .find(|pack| pack.source_id() == "bifrost.go.stdlib.bytes-declarations@1.0.0")
            .expect("the Go bytes declaration pack ships")
            .decode(&DecodeLimits::default())
            .expect("the Go bytes declaration pack decodes");
        assert_eq!(declarations.manifest.completeness, Completeness::Partial);
        assert_eq!(
            declarations.manifest.provenance.revision.as_deref(),
            Some("go1.26.0")
        );
        let [shard] = declarations.shards.as_slice() else {
            panic!("the Go bytes declaration pack has one shard: {declarations:#?}");
        };
        let shard = decode_shard_for_manifest(
            &declarations.manifest,
            &shard.descriptor,
            &shard.bytes,
            &DecodeLimits::default(),
        )
        .expect("the Go bytes declaration shard decodes");
        let ([module], [function], []) = shard
            .payload()
            .declaration_facts()
            .expect("the Go bytes shard carries declaration facts")
        else {
            panic!("only the reviewed module and TrimSpace declaration ship");
        };
        assert_eq!(module.name, "bytes");
        assert_eq!(module.type_kind, TypeKind::Module);
        assert_eq!(
            module.id,
            type_declaration_id(TypeIdentity {
                ecosystem: "go",
                name: "bytes",
            })
        );
        assert_eq!(function.owner, module.id);
        assert_eq!(function.name, "TrimSpace");
        assert_eq!(function.member_kind, MemberKind::Function);
        assert!(function.is_static);
        let signature = function
            .signature
            .as_ref()
            .expect("bytes.TrimSpace has a structured signature");
        let [input] = signature.parameters.as_slice() else {
            panic!("bytes.TrimSpace has one input parameter: {signature:#?}");
        };
        for r#type in [&input.r#type, signature.returns.as_ref().unwrap()] {
            assert!(matches!(
                r#type,
                TypeRef::Slice { element }
                    if matches!(
                        element.as_ref(),
                        TypeRef::Named { name, arguments, nullable }
                            if name == "byte" && arguments.is_empty() && !nullable
                    )
            ));
        }
        let parameter_types = [input.r#type.clone()];
        let parameter_variadics = [input.variadic];
        assert_eq!(
            function.id,
            member_declaration_id(MemberIdentity {
                owner_id: &function.owner,
                kind: function.member_kind,
                is_static: function.is_static,
                parameter_arity: 1,
                name: &function.name,
                generic_arity: 0,
                parameter_types: &parameter_types,
                parameter_variadics: &parameter_variadics,
                return_type: signature.returns.as_ref(),
            })
        );
    }

    #[test]
    fn shipped_go_crypto_x509_pack_preserves_exact_parameter_precondition_and_declaration() {
        let behavior = BIFROST_EMBEDDED_PACKS
            .packs()
            .iter()
            .find(|pack| pack.source_id() == "bifrost.go.stdlib.crypto-x509@1.0.0")
            .expect("the Go crypto/x509 behavior pack ships")
            .decode(&DecodeLimits::default())
            .expect("the Go crypto/x509 behavior pack decodes");
        assert_eq!(behavior.manifest.completeness, Completeness::Complete);
        assert_eq!(
            behavior.manifest.provenance.source,
            "https://pkg.go.dev/crypto/x509"
        );
        assert_eq!(
            behavior.manifest.provenance.revision.as_deref(),
            Some("go1.26.0")
        );
        let [shard] = behavior.shards.as_slice() else {
            panic!("the Go crypto/x509 behavior pack has one shard: {behavior:#?}");
        };
        let shard = decode_shard_for_manifest(
            &behavior.manifest,
            &shard.descriptor,
            &shard.bytes,
            &DecodeLimits::default(),
        )
        .expect("the Go crypto/x509 behavior shard decodes");
        let [summary] = shard
            .payload()
            .procedure_summaries()
            .expect("the Go crypto/x509 shard carries procedure summaries")
        else {
            panic!("the Go crypto/x509 behavior pack carries one reviewed function");
        };
        assert_eq!(summary.id, "crypto-x509.is-encrypted-pem-block");
        assert_eq!(summary.target.path, "src/crypto/x509/pem_decrypt.go");
        assert_eq!(
            summary.target.symbol,
            "crypto/x509.IsEncryptedPEMBlock(b *pem.Block)"
        );
        assert!(!summary.target.has_receiver);
        assert_eq!(summary.target.parameter_count, 1);
        assert_eq!(summary.completeness, Completeness::Complete);
        assert_eq!(summary.normal_result_count, Some(1));
        assert_eq!(
            summary.preconditions,
            Some(vec![CompiledOperationPrecondition {
                input: CompiledSummaryInput::Parameter { ordinal: 0 },
                predicate: CompiledResultPredicate::NonNull,
            }])
        );

        let declarations = BIFROST_EMBEDDED_PACKS
            .packs()
            .iter()
            .find(|pack| pack.source_id() == "bifrost.go.stdlib.crypto-x509-declarations@1.0.0")
            .expect("the Go crypto/x509 declaration pack ships")
            .decode(&DecodeLimits::default())
            .expect("the Go crypto/x509 declaration pack decodes");
        assert_eq!(declarations.manifest.completeness, Completeness::Partial);
        let [shard] = declarations.shards.as_slice() else {
            panic!("the Go crypto/x509 declaration pack has one shard: {declarations:#?}");
        };
        let shard = decode_shard_for_manifest(
            &declarations.manifest,
            &shard.descriptor,
            &shard.bytes,
            &DecodeLimits::default(),
        )
        .expect("the Go crypto/x509 declaration shard decodes");
        let ([module], [function], []) = shard
            .payload()
            .declaration_facts()
            .expect("the Go crypto/x509 shard carries declaration facts")
        else {
            panic!("only the reviewed module and function declaration ship");
        };
        assert_eq!(module.name, "crypto/x509");
        assert_eq!(module.type_kind, TypeKind::Module);
        assert_eq!(
            module.id,
            type_declaration_id(TypeIdentity {
                ecosystem: "go",
                name: "crypto/x509",
            })
        );
        assert_eq!(function.owner, module.id);
        assert_eq!(function.name, "IsEncryptedPEMBlock");
        assert_eq!(function.member_kind, MemberKind::Function);
        assert!(function.is_static);
        let signature = function
            .signature
            .as_ref()
            .expect("IsEncryptedPEMBlock has a structured signature");
        let [block] = signature.parameters.as_slice() else {
            panic!("IsEncryptedPEMBlock has one block parameter: {signature:#?}");
        };
        assert!(matches!(
            &block.r#type,
            TypeRef::Pointer { element }
                if matches!(
                    element.as_ref(),
                    TypeRef::Named { name, arguments, nullable }
                        if name == "encoding/pem.Block" && arguments.is_empty() && !nullable
                )
        ));
        let parameter_types = [block.r#type.clone()];
        let parameter_variadics = [block.variadic];
        assert_eq!(
            function.id,
            member_declaration_id(MemberIdentity {
                owner_id: &function.owner,
                kind: function.member_kind,
                is_static: function.is_static,
                parameter_arity: 1,
                name: &function.name,
                generic_arity: 0,
                parameter_types: &parameter_types,
                parameter_variadics: &parameter_variadics,
                return_type: signature.returns.as_ref(),
            })
        );
    }

    #[test]
    fn testify_packs_require_the_reviewed_module_version() {
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default())
            .expect("ephemeral semantic-pack catalog");
        BIFROST_EMBEDDED_PACKS
            .register_all(&catalog, &DecodeLimits::default())
            .expect("shipped semantic packs register");

        let candidates = |ecosystem: &str, module: Option<CatalogCoordinate>| -> BTreeSet<String> {
            testify_candidates_for_evidence(
                &catalog,
                &[SemanticModelActivationEvidence {
                    language: "go".to_owned(),
                    ecosystem: ecosystem.to_owned(),
                    package: None,
                    module,
                    toolchain: None,
                    target: None,
                    configuration: None,
                    artifact_sha256: None,
                }],
            )
        };

        assert!(candidates("go", None).is_empty());
        assert!(
            candidates(
                "go-module",
                Some(CatalogCoordinate {
                    name: "github.com/stretchr/testify".to_owned(),
                    version: None,
                }),
            )
            .is_empty(),
            "a local replacement without reviewed version evidence stays inactive"
        );
        assert!(
            candidates(
                "go-module",
                Some(CatalogCoordinate {
                    name: "github.com/stretchr/testify".to_owned(),
                    version: Some("1.10.0".parse().expect("fixture version")),
                }),
            )
            .is_empty(),
            "an unreviewed Testify version stays inactive"
        );
        assert_eq!(
            candidates(
                "go-module",
                Some(CatalogCoordinate {
                    name: "github.com/stretchr/testify".to_owned(),
                    version: Some("1.11.1".parse().expect("fixture version")),
                }),
            ),
            BTreeSet::from([
                "bifrost.go.testify.assert@1.0.0".to_owned(),
                "bifrost.go.testify.assert-declarations@1.0.0".to_owned(),
                "bifrost.go.testify.require@1.0.0".to_owned(),
                "bifrost.go.testify.require-declarations@1.0.0".to_owned(),
            ])
        );
    }

    fn discover_local_go_dependencies(
        testify_version: &str,
        import_testify_from_test: bool,
    ) -> Option<DependencyDiscoveryOutcome> {
        if Command::new("go").arg("version").output().is_err() {
            return None;
        }
        let test_source = if import_testify_from_test {
            r#"package sample

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValue(t *testing.T) {
	require.NoError(t, nil)
}
"#
        } else {
            r#"package sample

import "testing"

func TestValue(t *testing.T) {
	if Value() == "" {
		t.Fatal("empty value")
	}
}
"#
        };
        let project = InlineTestProject::with_language(Language::Go)
            .file(
                "go.mod",
                format!(
                    "module example.com/sample\n\ngo 1.21\n\nrequire (\n\texample.com/ordinary v1.0.0\n\tgithub.com/stretchr/testify v{testify_version}\n)\n\nreplace example.com/ordinary => ./ordinary\nreplace github.com/stretchr/testify => ./testify\n"
                ),
            )
            .file(
                "sample.go",
                "package sample\n\nimport \"example.com/ordinary\"\n\nfunc Value() string { return ordinary.Value() }\n",
            )
            .file("sample_test.go", test_source)
            .file(
                "ordinary/go.mod",
                "module example.com/ordinary\n\ngo 1.21\n",
            )
            .file(
                "ordinary/ordinary.go",
                "package ordinary\n\nfunc Value() string { return \"ordinary\" }\n",
            )
            .file(
                "testify/go.mod",
                "module github.com/stretchr/testify\n\ngo 1.21\n",
            )
            .file(
                "testify/require/require.go",
                "package require\n\nfunc NoError(t interface{}, err error, msgAndArgs ...interface{}) {}\n",
            )
            .build();
        let mut config = GoAnalyzerConfig::default();
        config.dependency_discovery.mode = GoDependencyDiscoveryMode::CuratedPackEvidence;
        config.dependency_discovery.go_executable = Some(PathBuf::from("go"));
        config.dependency_discovery.workspace_patterns = vec![".".to_owned()];
        config.dependency_discovery.timeout = Duration::from_secs(30);
        let outcome = resolve_go_semantic_pack_dependencies(
            &config,
            project.project(),
            &DependencyPackLimits::default(),
            None,
        );
        assert!(outcome.complete, "{:#?}", outcome.diagnostics);
        Some(outcome)
    }

    fn testify_candidates_for_evidence(
        catalog: &SemanticPackCatalog,
        evidence: &[SemanticModelActivationEvidence],
    ) -> BTreeSet<String> {
        evidence
            .iter()
            .flat_map(|evidence| {
                catalog
                    .candidates(&SemanticPackSelectorQuery {
                        language: evidence.language.clone(),
                        ecosystem: evidence.ecosystem.clone(),
                        package: evidence.package.clone(),
                        module: evidence.module.clone(),
                        toolchain: evidence.toolchain.clone(),
                        target: evidence.target.clone(),
                        configuration: evidence.configuration.clone(),
                        artifact_sha256: evidence.artifact_sha256.clone(),
                        bifrost_version: env!("CARGO_PKG_VERSION")
                            .parse()
                            .expect("crate version is semver"),
                    })
                    .expect("catalog query completes")
            })
            .map(|candidate| candidate.source_id().to_owned())
            .filter(|source_id| source_id.starts_with("bifrost.go.testify."))
            .collect()
    }

    #[test]
    fn test_only_go_dependency_selects_reviewed_testify_packs() {
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default())
            .expect("ephemeral semantic-pack catalog");
        BIFROST_EMBEDDED_PACKS
            .register_all(&catalog, &DecodeLimits::default())
            .expect("shipped semantic packs register");
        let expected = BTreeSet::from([
            "bifrost.go.testify.assert@1.0.0".to_owned(),
            "bifrost.go.testify.assert-declarations@1.0.0".to_owned(),
            "bifrost.go.testify.require@1.0.0".to_owned(),
            "bifrost.go.testify.require-declarations@1.0.0".to_owned(),
        ]);

        let Some(reviewed) = discover_local_go_dependencies("1.11.1", true) else {
            return;
        };
        assert!(
            reviewed
                .dependencies
                .iter()
                .all(|dependency| dependency.artifacts.is_empty())
        );
        assert!(reviewed.dependencies.iter().any(|dependency| {
            let evidence = &dependency.evidence;
            evidence.module.as_ref().is_some_and(|module| {
                module.name == "example.com/ordinary"
                    && module.version == Some("1.0.0".parse().expect("fixture version"))
            })
        }));
        assert!(reviewed.dependencies.iter().any(|dependency| {
            let evidence = &dependency.evidence;
            evidence.ecosystem == "go-module"
                && evidence.module.as_ref().is_some_and(|module| {
                    module.name == "github.com/stretchr/testify"
                        && module.version == Some("1.11.1".parse().expect("fixture version"))
                })
        }));
        let reviewed_preparation = prepare_compatible_installed_semantic_packs(
            &catalog,
            &reviewed.dependencies,
            &DependencyPackLimits::default(),
            None,
        );
        assert!(
            reviewed_preparation.complete,
            "{:#?}",
            reviewed_preparation.diagnostics
        );
        assert!(reviewed_preparation.packs.is_empty());
        assert_eq!(reviewed_preparation.profile.artifacts_read, 0);
        assert_eq!(reviewed_preparation.profile.artifact_bytes_read, 0);
        assert_eq!(reviewed_preparation.profile.generated_packs, 0);
        assert_eq!(reviewed_preparation.profile.installed_packs, 1);
        assert_eq!(
            reviewed_preparation.installed_packs[0]
                .manifest_digests
                .len(),
            4
        );
        assert_eq!(
            testify_candidates_for_evidence(&catalog, &reviewed_preparation.evidence),
            expected
        );
        let activation_project = InlineTestProject::with_language(Language::Go)
            .file("go.mod", "module example.com/activation\n\ngo 1.21\n")
            .file("main.go", "package activation\n")
            .build();
        let activation_workspace = activation_project.workspace_analyzer(AnalyzerConfig::default());
        let runtime = acquire_active_semantic_models(
            activation_workspace.analyzer(),
            &catalog,
            None,
            &SemanticModelActivationRequest {
                bifrost_version: env!("CARGO_PKG_VERSION")
                    .parse()
                    .expect("crate version is semver"),
                evidence: reviewed_preparation.evidence.clone(),
                controls: Vec::new(),
                limits: SemanticModelRuntimeLimits::default(),
            },
            &CancellationToken::default(),
        );
        let SemanticModelRuntimeOutcome::Ready { active, .. } = runtime else {
            panic!("exact reviewed Testify evidence activates: {runtime:#?}");
        };
        let active_testify = active
            .shards()
            .iter()
            .map(|shard| format!("{}@{}", shard.manifest.pack_id, shard.manifest.version))
            .filter(|pack_id| pack_id.starts_with("bifrost.go.testify."))
            .collect::<BTreeSet<_>>();
        assert_eq!(active_testify, expected);

        let installed_catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default())
            .expect("ephemeral installed-pack catalog");
        let partial_declarations = BIFROST_EMBEDDED_PACKS
            .packs()
            .iter()
            .find(|pack| pack.source_id() == "bifrost.go.testify.require-declarations@1.0.0")
            .expect("partial Testify declaration pack ships")
            .decode(&DecodeLimits::default())
            .expect("partial Testify declaration pack decodes");
        installed_catalog
            .install(
                &partial_declarations,
                &DurablePackSource {
                    kind: DurablePackSourceKind::Installed,
                    source_id: "test-arbitrary-local-install".to_owned(),
                },
            )
            .expect("partial pack installs without release accounting");
        let arbitrary_partial = prepare_compatible_installed_semantic_packs(
            &installed_catalog,
            &reviewed.dependencies,
            &DependencyPackLimits::default(),
            None,
        );
        assert!(
            arbitrary_partial.complete,
            "{:#?}",
            arbitrary_partial.diagnostics
        );
        assert!(arbitrary_partial.installed_packs.is_empty());
        assert!(arbitrary_partial.evidence.is_empty());

        let mixed_catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default())
            .expect("ephemeral mixed-source catalog");
        let complete_shipped = BIFROST_EMBEDDED_PACKS
            .packs()
            .iter()
            .find(|pack| pack.source_id() == "bifrost.go.testify.require@1.0.0")
            .expect("complete Testify behavior pack ships");
        EmbeddedPackRegistry::new(std::slice::from_ref(complete_shipped))
            .register_all(&mixed_catalog, &DecodeLimits::default())
            .expect("complete shipped pack registers");
        mixed_catalog
            .install(
                &partial_declarations,
                &DurablePackSource {
                    kind: DurablePackSourceKind::Installed,
                    source_id: "test-mixed-arbitrary-local-install".to_owned(),
                },
            )
            .expect("partial local pack installs alongside shipped pack");
        let mixed_preparation = prepare_compatible_installed_semantic_packs(
            &mixed_catalog,
            &reviewed.dependencies,
            &DependencyPackLimits::default(),
            None,
        );
        assert!(
            mixed_preparation.complete,
            "{:#?}",
            mixed_preparation.diagnostics
        );
        assert!(mixed_preparation.installed_packs.is_empty());
        assert!(mixed_preparation.evidence.is_empty());
        let mixed_runtime = acquire_active_semantic_models(
            activation_workspace.analyzer(),
            &mixed_catalog,
            None,
            &SemanticModelActivationRequest {
                bifrost_version: env!("CARGO_PKG_VERSION")
                    .parse()
                    .expect("crate version is semver"),
                evidence: mixed_preparation.evidence,
                controls: Vec::new(),
                limits: SemanticModelRuntimeLimits::default(),
            },
            &CancellationToken::default(),
        );
        let SemanticModelRuntimeOutcome::Ready {
            active: mixed_active,
            ..
        } = mixed_runtime
        else {
            panic!("empty refused evidence resolves without Testify: {mixed_runtime:#?}");
        };
        assert!(
            mixed_active
                .shards()
                .iter()
                .all(|shard| { !shard.manifest.pack_id.starts_with("bifrost.go.testify.") })
        );

        let Some(unused) = discover_local_go_dependencies("1.11.1", false) else {
            return;
        };
        assert!(unused.dependencies.iter().any(|dependency| {
            let evidence = &dependency.evidence;
            evidence
                .module
                .as_ref()
                .is_some_and(|module| module.name == "example.com/ordinary")
        }));
        assert!(!unused.dependencies.iter().any(|dependency| {
            let evidence = &dependency.evidence;
            evidence
                .module
                .as_ref()
                .is_some_and(|module| module.name == "github.com/stretchr/testify")
        }));
        let unused_preparation = prepare_compatible_installed_semantic_packs(
            &catalog,
            &unused.dependencies,
            &DependencyPackLimits::default(),
            None,
        );
        assert!(
            unused_preparation.complete,
            "{:#?}",
            unused_preparation.diagnostics
        );
        assert!(unused_preparation.installed_packs.is_empty());
        assert!(testify_candidates_for_evidence(&catalog, &unused_preparation.evidence).is_empty());

        let Some(unreviewed) = discover_local_go_dependencies("1.10.0", true) else {
            return;
        };
        assert!(unreviewed.dependencies.iter().any(|dependency| {
            let evidence = &dependency.evidence;
            evidence.ecosystem == "go-module"
                && evidence.module.as_ref().is_some_and(|module| {
                    module.name == "github.com/stretchr/testify"
                        && module.version == Some("1.10.0".parse().expect("fixture version"))
                })
        }));
        let unreviewed_preparation = prepare_compatible_installed_semantic_packs(
            &catalog,
            &unreviewed.dependencies,
            &DependencyPackLimits::default(),
            None,
        );
        assert!(
            unreviewed_preparation.complete,
            "{:#?}",
            unreviewed_preparation.diagnostics
        );
        assert!(unreviewed_preparation.installed_packs.is_empty());
        assert!(
            unreviewed_preparation
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "dependency.pack_version_mismatch")
        );
        assert!(
            testify_candidates_for_evidence(&catalog, &unreviewed_preparation.evidence).is_empty()
        );
    }

    #[test]
    fn shipped_go_log_pack_is_the_exact_package_and_logger_method_matrix() {
        let pack = BIFROST_EMBEDDED_PACKS
            .packs()
            .iter()
            .find(|pack| pack.source_id() == "bifrost.go.stdlib.log@1.0.0")
            .expect("the Go log pack ships")
            .decode(&DecodeLimits::default())
            .expect("the Go log pack decodes");
        let [shard] = pack.shards.as_slice() else {
            panic!("the Go log pack has one reviewed shard: {pack:#?}");
        };
        let shard = decode_shard_for_manifest(
            &pack.manifest,
            &shard.descriptor,
            &shard.bytes,
            &DecodeLimits::default(),
        )
        .expect("the Go log shard decodes");
        let summaries = shard
            .payload()
            .procedure_summaries()
            .expect("the Go log shard carries procedure summaries");

        let matrix = [
            (
                "fatal",
                "Fatal",
                "Fatal(v ...any)",
                "member.66d2922ed2d140e6933d5d8d1bd700a9b4cc601ec415399709814cb76fc1762f",
                "member.12e437dc9a1956095976c819f301a594712cde481e850263b3b44914d5d9613b",
                1,
            ),
            (
                "fatalf",
                "Fatalf",
                "Fatalf(format string, v ...any)",
                "member.d22ee2dd7d4cd53dd0771d2e052131b82216782d70ccad91793439b536b79040",
                "member.8ebcfaee00774c3060c16a5e29ef31952de1ee74fc1d15df6168b6a45a7b2b39",
                2,
            ),
            (
                "fatalln",
                "Fatalln",
                "Fatalln(v ...any)",
                "member.b87240c0ec482c00c0d8a26fdb5add598e669a30eefdb5620fd327ccf79524d8",
                "member.a9ce4feeeffe226c4bffb4cdd4bead6f958e2e5142861e4c00107243e6745a15",
                1,
            ),
            (
                "panic",
                "Panic",
                "Panic(v ...any)",
                "member.0666b4b8db7db19e1a8936a14244aa37d3bbd2f70229691fffd54cc9f4d75af7",
                "member.02661ce2b4ad570b8892c03cb76624cd7c2fac1ebd2274a50d6731ee68d3c342",
                1,
            ),
            (
                "panicf",
                "Panicf",
                "Panicf(format string, v ...any)",
                "member.e855829aefae7b680c8e290e8cd13e2648cb88ff45f8e0dbb78e90b57838862a",
                "member.fa4cd66ff4d9b77956dfafaeee4fac69c1e8c01fd4955f8e9159fadb5fb29eb9",
                2,
            ),
            (
                "panicln",
                "Panicln",
                "Panicln(v ...any)",
                "member.0a615e08b73ac1f1fc4c5f0af10a84d4d2c8ae60bca33ed4051f5325bd27d34d",
                "member.02c40e6a8b167e3b2215b74b194ffe47b6ec436792f4119d5155102f282c8fa8",
                1,
            ),
        ];
        assert_eq!(summaries.len(), matrix.len() * 2);
        let assert_summary = |id: &str, symbol: &str, has_receiver, parameter_count| {
            let matching = summaries
                .iter()
                .filter(|summary| summary.id == id)
                .collect::<Vec<_>>();
            let [summary] = matching.as_slice() else {
                panic!("one reviewed summary for {id}: {matching:#?}");
            };
            assert_eq!(summary.target.path, "src/log/log.go");
            assert_eq!(summary.target.symbol, symbol);
            assert_eq!(summary.target.has_receiver, has_receiver);
            assert!(summary.target.variadic);
            assert_eq!(summary.target.parameter_count, parameter_count);
            assert_eq!(summary.completeness, Completeness::Partial);
            assert!(summary.normal_continuation_absent);
            assert!(!summary.covers_overrides);
            assert!(summary.transfers.is_empty());
            assert!(summary.effects.is_empty());
            assert!(summary.result_contracts.is_empty());
        };
        for (id_suffix, _, signature, _, _, parameter_count) in matrix {
            assert_summary(
                &format!("log.{id_suffix}"),
                &format!("log.{signature}"),
                false,
                parameter_count,
            );
            assert_summary(
                &format!("log.logger.{id_suffix}"),
                &format!("log.Logger.{signature}"),
                true,
                parameter_count,
            );
        }

        let declarations = BIFROST_EMBEDDED_PACKS
            .packs()
            .iter()
            .find(|pack| pack.source_id() == "bifrost.go.stdlib.log-declarations@1.0.0")
            .expect("the Go log declaration pack ships")
            .decode(&DecodeLimits::default())
            .expect("the Go log declaration pack decodes");
        let [shard] = declarations.shards.as_slice() else {
            panic!("the Go log declaration pack has one shard: {declarations:#?}");
        };
        let shard = decode_shard_for_manifest(
            &declarations.manifest,
            &shard.descriptor,
            &shard.bytes,
            &DecodeLimits::default(),
        )
        .expect("the Go log declaration shard decodes");
        let (types, members, relations) = shard
            .payload()
            .declaration_facts()
            .expect("the Go log declaration shard carries declaration facts");
        assert!(relations.is_empty());
        assert_eq!(types.len(), 2, "package log and log.Logger are reviewed");
        let module = types
            .iter()
            .find(|fact| fact.name == "log")
            .expect("the declaration surface contains package log");
        assert_eq!(
            module.id,
            "type.1bfd7f7f8d262c8bd74df76a79e63800b7ab1ce63b2fade5fb70a3440172b7cf"
        );
        assert_eq!(module.name, "log");
        assert_eq!(module.type_kind, TypeKind::Module);
        assert!(matches!(
            &module.locator,
            Locator::Artifact { path, symbol } if path == "log/log.go" && symbol == "log"
        ));
        let logger = types
            .iter()
            .find(|fact| fact.name == "log.Logger")
            .expect("the declaration surface contains log.Logger");
        assert_eq!(
            logger.id,
            "type.934b81bf9bda0c9cad8d242c7249cdbb6a44ad697fecee0ab01855549a81e8ee"
        );
        assert_eq!(logger.type_kind, TypeKind::Struct);
        assert!(logger.aliases.is_empty());
        assert!(matches!(
            &logger.locator,
            Locator::Artifact { path, symbol }
                if path == "log/log.go" && symbol == "log.Logger"
        ));

        assert_eq!(members.len(), matrix.len() * 2);
        let assert_member = |owner: &str,
                             name: &str,
                             member_id: &str,
                             member_kind,
                             symbol: &str,
                             parameter_count| {
            let matching = members
                .iter()
                .filter(|member| member.owner == owner && member.name == name)
                .collect::<Vec<_>>();
            let [member] = matching.as_slice() else {
                panic!("one reviewed declaration for {symbol}: {matching:#?}");
            };
            assert_eq!(member.id, member_id);
            assert_eq!(member.owner, owner);
            assert_eq!(member.member_kind, member_kind);
            match member_kind {
                MemberKind::Function => {
                    assert!(member.is_static);
                    assert!(member.receiver.is_none());
                }
                MemberKind::Method => {
                    assert!(!member.is_static);
                    assert_eq!(
                        member.receiver.as_ref().map(|receiver| receiver.pointer),
                        Some(true)
                    );
                }
                _ => panic!("reviewed log callable must be a function or method: {member:#?}"),
            }
            assert!(matches!(
                &member.locator,
                Locator::Artifact { path, symbol: actual }
                    if path == "log/log.go" && actual == symbol
            ));
            let signature = member
                .signature
                .as_ref()
                .unwrap_or_else(|| panic!("{symbol} has a structured signature"));
            let parameter_count = usize::try_from(parameter_count)
                .expect("the reviewed declaration parameter count fits usize");
            assert_eq!(signature.parameters.len(), parameter_count);
            let expected_parameters: &[(&str, &str, bool)] = if parameter_count == 1 {
                &[("v", "any", true)]
            } else {
                &[("format", "string", false), ("v", "any", true)]
            };
            assert!(signature.parameters.iter().zip(expected_parameters).all(
                |(parameter, (expected_name, expected_type, expected_variadic))| {
                    parameter.name.as_deref() == Some(*expected_name)
                        && matches!(
                            &parameter.r#type,
                            TypeRef::Named { name, .. } if name == *expected_type
                        )
                        && !parameter.optional
                        && parameter.variadic == *expected_variadic
                }
            ));
            assert!(signature.returns.is_none());
        };
        for (_, name, _, package_member_id, method_member_id, parameter_count) in matrix {
            assert_member(
                "type.1bfd7f7f8d262c8bd74df76a79e63800b7ab1ce63b2fade5fb70a3440172b7cf",
                name,
                package_member_id,
                MemberKind::Function,
                &format!("log.{name}"),
                parameter_count,
            );
            assert_member(
                "type.934b81bf9bda0c9cad8d242c7249cdbb6a44ad697fecee0ab01855549a81e8ee",
                name,
                method_member_id,
                MemberKind::Method,
                &format!("log.Logger.{name}"),
                parameter_count,
            );
        }
    }

    #[test]
    fn activated_go_log_pack_binds_the_reviewed_logger_panic_method() {
        let source = r#"package sample

import "log"

func concrete(logger *log.Logger) {
    logger.Panic("stop", 1)
}
"#;
        let project = InlineTestProject::with_language(Language::Go)
            .file("go.mod", "module example.com/log-model\n")
            .file(
                "alias.go",
                r#"package sample

import logger "log"

func packageAlias() {
    logger.Panic("package")
}
"#,
            )
            .file("main.go", source)
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default())
            .expect("ephemeral semantic-pack catalog");
        BIFROST_EMBEDDED_PACKS
            .register_all(&catalog, &DecodeLimits::default())
            .expect("shipped semantic packs register");
        let outcome = acquire_active_semantic_models(
            workspace.analyzer(),
            &catalog,
            None,
            &SemanticModelActivationRequest {
                bifrost_version: env!("CARGO_PKG_VERSION")
                    .parse()
                    .expect("crate version is semver"),
                evidence: vec![SemanticModelActivationEvidence {
                    language: "go".to_owned(),
                    ecosystem: "go".to_owned(),
                    package: None,
                    module: None,
                    toolchain: None,
                    target: None,
                    configuration: None,
                    artifact_sha256: None,
                }],
                controls: Vec::new(),
                limits: SemanticModelRuntimeLimits::default(),
            },
            &CancellationToken::default(),
        );
        assert!(
            matches!(outcome, SemanticModelRuntimeOutcome::Ready { .. }),
            "Go stdlib activation completes: {outcome:#?}"
        );

        let file = project.file("main.go");
        let provider = workspace
            .analyzer()
            .structural_fact_providers()
            .into_iter()
            .find(|provider| provider.structural_language() == Language::Go)
            .expect("Go structural facts provider");
        let facts = provider
            .structural_facts(&file)
            .expect("Go structural facts");
        let shapes = call_shapes_in_file(&facts, &file, usize::MAX);
        let [shape] = shapes.as_slice() else {
            panic!("fixture contains one call: {shapes:#?}");
        };
        let lookup = modeled_call_targets_for_shape(
            workspace.analyzer(),
            shape,
            Arc::from(source),
            CallRelationLimits {
                max_files: 1,
                max_source_bytes: usize::MAX,
                max_candidates: 100,
            },
            None,
        );
        assert_eq!(lookup.coverage, ModeledCallTargetCoverage::Exhaustive);
        assert_eq!(
            lookup.call_application,
            ModeledCallApplication::BoundReceiver
        );
        let [arm] = lookup.arms.as_slice() else {
            panic!("one exact log.Logger.Panic arm: {lookup:#?}");
        };
        assert_eq!(arm.key.language, "go");
        assert_eq!(arm.key.owner, "log.Logger");
        assert_eq!(arm.key.member, "Panic");
        assert!(arm.key.has_receiver);
        assert_eq!(arm.key.parameter_count, 2);
        assert_eq!(arm.origin, ModeledCallTargetOrigin::UnmaterializedExternal);

        let snapshot = workspace
            .analyzer()
            .active_semantic_model_snapshot()
            .expect("activation publishes one atomic model snapshot");
        assert!(snapshot.active_models().proves_normal_continuation_absent(
            ProcedureSummaryMemberKey::new(
                &arm.key.language,
                &arm.key.owner,
                &arm.key.member,
                arm.key.has_receiver,
                arm.key.parameter_count,
            )
        ));
    }

    #[test]
    fn shipped_go_testing_pack_is_the_exact_concrete_receiver_matrix() {
        let pack = BIFROST_EMBEDDED_PACKS
            .packs()
            .iter()
            .find(|pack| pack.source_id() == "bifrost.go.stdlib.testing@1.0.0")
            .expect("the Go testing pack ships")
            .decode(&DecodeLimits::default())
            .expect("the Go testing pack decodes");
        let shards = pack
            .shards
            .iter()
            .map(|shard| {
                decode_shard_for_manifest(
                    &pack.manifest,
                    &shard.descriptor,
                    &shard.bytes,
                    &DecodeLimits::default(),
                )
                .expect("a Go testing shard decodes")
            })
            .collect::<Vec<_>>();
        let (types, members, relations) = shards
            .iter()
            .find_map(|shard| shard.payload().declaration_facts())
            .expect("the Go testing declarations ship");

        assert!(relations.is_empty());
        assert_eq!(types.len(), 4);
        assert!(types.iter().any(|fact| fact.name == "testing"));
        assert!(
            ["testing.T", "testing.B", "testing.F"]
                .iter()
                .all(|name| types.iter().any(|fact| fact.name == *name))
        );
        assert!(
            types
                .iter()
                .all(|fact| !matches!(fact.name.as_str(), "testing.common" | "testing.TB"))
        );
        assert_eq!(members.len(), 18);
        let method_names = ["FailNow", "Fatal", "Fatalf", "Skip", "Skipf", "SkipNow"];
        for owner in ["type.testing.t", "type.testing.b", "type.testing.f"] {
            for method in method_names {
                let matching = members
                    .iter()
                    .filter(|fact| fact.owner == owner && fact.name == method)
                    .collect::<Vec<_>>();
                assert!(
                    matches!(matching.as_slice(), [fact] if fact.receiver.is_some_and(|receiver| receiver.pointer)),
                    "one pointer-receiver fact for {owner}.{method}: {matching:#?}"
                );
            }
        }

        let summaries = shards
            .iter()
            .find_map(|shard| shard.payload().procedure_summaries())
            .expect("the Go testing summaries ship");
        assert_eq!(summaries.len(), 18);
        let shapes = [
            ("FailNow", 0, false),
            ("Fatal", 1, true),
            ("Fatalf", 2, true),
            ("Skip", 1, true),
            ("Skipf", 2, true),
            ("SkipNow", 0, false),
        ];
        for receiver in ["T", "B", "F"] {
            for (method, parameter_count, variadic) in shapes {
                let prefix = format!("testing.{receiver}.{method}(");
                let matching = summaries
                    .iter()
                    .filter(|summary| summary.target.symbol.starts_with(&prefix))
                    .collect::<Vec<_>>();
                let [summary] = matching.as_slice() else {
                    panic!("one summary for {prefix}: {matching:#?}");
                };
                assert!(summary.target.has_receiver);
                assert_eq!(summary.target.parameter_count, parameter_count);
                assert_eq!(summary.target.variadic, variadic);
                assert_eq!(summary.completeness, Completeness::Partial);
                assert!(summary.normal_continuation_absent);
                assert!(!summary.covers_overrides);
                assert!(summary.transfers.is_empty());
                assert!(summary.effects.is_empty());
            }
        }
        assert!(summaries.iter().all(|summary| {
            !summary.target.symbol.starts_with("testing.TB.")
                && !summary.target.symbol.starts_with("testing.common.")
        }));
    }

    #[test]
    fn activated_go_testing_pack_binds_only_the_reviewed_concrete_receiver_call() {
        let source = r#"package sample

import "testing"

func concrete(t *testing.T) {
    t.Fatal("concrete")
}

func interfaceReceiver(t testing.TB) {
    t.Fatal("interface")
}

type Local = testing.T

func localAlias(t *Local) {
    t.Fatal("alias")
}

func methodExpression(t *testing.T) {
    (*testing.T).Fatal(t, "expression")
}
"#;
        let project = InlineTestProject::with_language(Language::Go)
            .file("go.mod", "module example.com/testing-model\n")
            .file("main.go", source)
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default())
            .expect("ephemeral semantic-pack catalog");
        BIFROST_EMBEDDED_PACKS
            .register_all(&catalog, &DecodeLimits::default())
            .expect("shipped semantic packs register");
        let outcome = acquire_active_semantic_models(
            workspace.analyzer(),
            &catalog,
            None,
            &SemanticModelActivationRequest {
                bifrost_version: env!("CARGO_PKG_VERSION")
                    .parse()
                    .expect("crate version is semver"),
                evidence: vec![SemanticModelActivationEvidence {
                    language: "go".to_owned(),
                    ecosystem: "go".to_owned(),
                    package: None,
                    module: None,
                    toolchain: None,
                    target: None,
                    configuration: None,
                    artifact_sha256: None,
                }],
                controls: Vec::new(),
                limits: SemanticModelRuntimeLimits::default(),
            },
            &CancellationToken::default(),
        );
        assert!(
            matches!(outcome, SemanticModelRuntimeOutcome::Ready { .. }),
            "Go stdlib activation completes: {outcome:#?}"
        );

        let file = project.file("main.go");
        let provider = workspace
            .analyzer()
            .structural_fact_providers()
            .into_iter()
            .find(|provider| provider.structural_language() == Language::Go)
            .expect("Go structural facts provider");
        let facts = provider
            .structural_facts(&file)
            .expect("Go structural facts");
        let shapes = call_shapes_in_file(&facts, &file, usize::MAX);
        assert_eq!(shapes.len(), 4, "fixture contains four calls: {shapes:#?}");
        let source: Arc<str> = Arc::from(source);
        let lookups = shapes
            .iter()
            .map(|shape| {
                let call = source
                    .get(shape.outcome.range.start_byte..shape.outcome.range.end_byte)
                    .expect("call range belongs to the indexed source")
                    .to_owned();
                let lookup = modeled_call_targets_for_shape(
                    workspace.analyzer(),
                    shape,
                    Arc::clone(&source),
                    CallRelationLimits {
                        max_files: 1,
                        max_source_bytes: usize::MAX,
                        max_candidates: 100,
                    },
                    None,
                );
                (call, lookup)
            })
            .collect::<BTreeMap<_, _>>();

        let exact = &lookups["t.Fatal(\"concrete\")"];
        assert_eq!(exact.coverage, ModeledCallTargetCoverage::Exhaustive);
        assert_eq!(
            exact.call_application,
            ModeledCallApplication::BoundReceiver
        );
        let [arm] = exact.arms.as_slice() else {
            panic!("one exact concrete-receiver arm: {exact:#?}");
        };
        assert_eq!(arm.key.language, "go");
        assert_eq!(arm.key.owner, "testing.T");
        assert_eq!(arm.key.member, "Fatal");
        assert!(arm.key.has_receiver);
        assert_eq!(arm.key.parameter_count, 1);
        assert_eq!(arm.origin, ModeledCallTargetOrigin::UnmaterializedExternal);
        let snapshot = workspace
            .analyzer()
            .active_semantic_model_snapshot()
            .expect("activation publishes one atomic model snapshot");
        assert!(snapshot.active_models().proves_normal_continuation_absent(
            ProcedureSummaryMemberKey::new(
                &arm.key.language,
                &arm.key.owner,
                &arm.key.member,
                arm.key.has_receiver,
                arm.key.parameter_count,
            )
        ));

        for call in [
            "t.Fatal(\"interface\")",
            "t.Fatal(\"alias\")",
            "(*testing.T).Fatal(t, \"expression\")",
        ] {
            let lookup = &lookups[call];
            assert!(
                lookup.arms.is_empty(),
                "near miss stayed open: {call}: {lookup:#?}"
            );
            assert_eq!(
                lookup.coverage,
                ModeledCallTargetCoverage::Open,
                "near miss stayed open: {call}: {lookup:#?}"
            );
        }
    }

    #[test]
    fn registry_validates_every_pack_before_catalog_registration() {
        let compiled = compiled_fixture();
        let valid_shards = compiled
            .shards
            .iter()
            .map(|shard| shard.bytes.as_slice())
            .collect::<Vec<_>>();
        let missing_shards: [&[u8]; 0] = [];
        let packs = [
            EmbeddedSemanticPack::new(
                "bifrost.fixture.valid@1",
                &compiled.manifest_bytes,
                &valid_shards,
            ),
            EmbeddedSemanticPack::new(
                "bifrost.fixture.invalid@1",
                &compiled.manifest_bytes,
                &missing_shards,
            ),
        ];
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();

        let error = EmbeddedPackRegistry::new(&packs)
            .register_all(&catalog, &DecodeLimits::default())
            .unwrap_err();

        assert!(matches!(
            error,
            EmbeddedPackError::ShardCount {
                declared: 1,
                embedded: 0
            }
        ));
        assert_eq!(catalog.accounting().unwrap().logical_shard_count, 0);
    }

    #[test]
    fn activated_go_os_pack_binds_fd_only_to_the_reviewed_file_receiver() {
        let source = r#"package sample

import "os"

type localFile struct{}

func (*localFile) Fd() uintptr { return 0 }

func calls(local *localFile) uintptr {
    file, _ := os.Open("sample.txt")
    descriptor := file.Fd()
    return descriptor + local.Fd()
}
"#;
        let project = InlineTestProject::with_language(Language::Go)
            .file("go.mod", "module example.com/os-model\n")
            .file("main.go", source)
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default())
            .expect("ephemeral semantic-pack catalog");
        BIFROST_EMBEDDED_PACKS
            .register_all(&catalog, &DecodeLimits::default())
            .expect("shipped semantic packs register");
        let outcome = acquire_active_semantic_models(
            workspace.analyzer(),
            &catalog,
            None,
            &SemanticModelActivationRequest {
                bifrost_version: env!("CARGO_PKG_VERSION")
                    .parse()
                    .expect("crate version is semver"),
                evidence: vec![SemanticModelActivationEvidence {
                    language: "go".to_owned(),
                    ecosystem: "go".to_owned(),
                    package: None,
                    module: None,
                    toolchain: None,
                    target: None,
                    configuration: None,
                    artifact_sha256: None,
                }],
                controls: Vec::new(),
                limits: SemanticModelRuntimeLimits::default(),
            },
            &CancellationToken::default(),
        );
        assert!(
            matches!(outcome, SemanticModelRuntimeOutcome::Ready { .. }),
            "Go stdlib activation completes: {outcome:#?}"
        );

        let file = project.file("main.go");
        let provider = workspace
            .analyzer()
            .structural_fact_providers()
            .into_iter()
            .find(|provider| provider.structural_language() == Language::Go)
            .expect("Go structural facts provider");
        let facts = provider
            .structural_facts(&file)
            .expect("Go structural facts");
        let shapes = call_shapes_in_file(&facts, &file, usize::MAX);
        assert_eq!(shapes.len(), 3, "fixture contains three calls: {shapes:#?}");
        let source: Arc<str> = Arc::from(source);
        let lookups = shapes
            .iter()
            .map(|shape| {
                let call = source
                    .get(shape.outcome.range.start_byte..shape.outcome.range.end_byte)
                    .expect("call range belongs to the indexed source")
                    .to_owned();
                let lookup = modeled_call_targets_for_shape(
                    workspace.analyzer(),
                    shape,
                    Arc::clone(&source),
                    CallRelationLimits {
                        max_files: 1,
                        max_source_bytes: usize::MAX,
                        max_candidates: 100,
                    },
                    None,
                );
                (call, lookup)
            })
            .collect::<BTreeMap<_, _>>();

        let exact = &lookups["file.Fd()"];
        assert_eq!(exact.coverage, ModeledCallTargetCoverage::Exhaustive);
        assert_eq!(
            exact.call_application,
            ModeledCallApplication::BoundReceiver
        );
        let [arm] = exact.arms.as_slice() else {
            panic!("one exact external arm for (*os.File).Fd: {exact:#?}");
        };
        assert_eq!(arm.key.language, "go");
        assert_eq!(arm.key.owner, "os.File");
        assert_eq!(arm.key.member, "Fd");
        assert!(arm.key.has_receiver);
        assert_eq!(arm.key.parameter_count, 0);
        assert_eq!(arm.origin, ModeledCallTargetOrigin::UnmaterializedExternal);

        let near_miss = &lookups["local.Fd()"];
        assert_eq!(
            near_miss.coverage,
            ModeledCallTargetCoverage::Open,
            "the local pointer-receiver call retains its conservative residual: {near_miss:#?}"
        );
        assert_eq!(
            near_miss.call_application,
            ModeledCallApplication::BoundReceiver
        );
        assert!(near_miss.arms.is_empty(), "{near_miss:#?}");
        let [local_name] = near_miss.adjudicable_workspace_names.as_slice() else {
            panic!("one structured workspace identity for the local Fd method: {near_miss:#?}");
        };
        assert_eq!(local_name.language, "go");
        assert_eq!(local_name.owner, "example.com/os-model.localFile");
        assert_eq!(local_name.member, "Fd");
        assert!(local_name.has_receiver);
    }

    #[test]
    fn shipped_go_net_pack_preserves_exact_contracts_and_canonical_declarations() {
        let behavior = BIFROST_EMBEDDED_PACKS
            .packs()
            .iter()
            .find(|pack| pack.source_id() == "bifrost.go.stdlib.net@1.1.0")
            .expect("the Go net behavior pack ships")
            .decode(&DecodeLimits::default())
            .expect("the Go net behavior pack decodes");
        assert_eq!(behavior.manifest.completeness, Completeness::Complete);
        assert_eq!(
            behavior.manifest.provenance.source,
            "https://pkg.go.dev/net"
        );
        assert_eq!(
            behavior.manifest.provenance.revision.as_deref(),
            Some("go1.26.0")
        );
        let [shard] = behavior.shards.as_slice() else {
            panic!("the Go net behavior pack has one shard: {behavior:#?}");
        };
        let shard = decode_shard_for_manifest(
            &behavior.manifest,
            &shard.descriptor,
            &shard.bytes,
            &DecodeLimits::default(),
        )
        .expect("the Go net behavior shard decodes");
        let summaries = shard
            .payload()
            .procedure_summaries()
            .expect("the Go net behavior shard carries procedure summaries");
        let conn_operation_matrix = BTreeMap::from([
            ("Close", 0),
            ("LocalAddr", 0),
            ("Read", 1),
            ("RemoteAddr", 0),
            ("SetDeadline", 1),
            ("SetReadDeadline", 1),
            ("SetWriteDeadline", 1),
            ("Write", 1),
        ]);
        let listener_operation_matrix = BTreeMap::from([("Accept", 0), ("Addr", 0), ("Close", 0)]);
        let summary_matrix = [
            (
                "net.dial",
                "net.Dial(network, address string)",
                2,
                &conn_operation_matrix,
            ),
            (
                "net.dial-timeout",
                "net.DialTimeout(network, address string, timeout time.Duration)",
                3,
                &conn_operation_matrix,
            ),
            (
                "net.listen",
                "net.Listen(network, address string)",
                2,
                &listener_operation_matrix,
            ),
        ];
        assert_eq!(summaries.len(), summary_matrix.len());
        for (id, symbol, parameter_count, operation_matrix) in summary_matrix {
            let summary = summaries
                .iter()
                .find(|summary| summary.id == id)
                .unwrap_or_else(|| panic!("the reviewed net summary {id} ships"));
            assert_eq!(summary.target.path, "src/net/dial.go");
            assert_eq!(summary.target.symbol, symbol);
            assert!(!summary.target.has_receiver);
            assert!(!summary.target.variadic);
            assert_eq!(summary.target.parameter_count, parameter_count);
            assert_eq!(summary.normal_result_count, Some(2));
            assert_eq!(summary.completeness, Completeness::Complete);
            assert!(summary.transfers.is_empty());
            assert!(summary.effects.is_empty());
            let [contract] = summary.result_contracts.as_slice() else {
                panic!("{id} has one success-conditioned result: {summary:#?}");
            };
            assert_eq!(contract.result_ordinal, 0);
            assert_eq!(contract.condition_result_ordinal, Some(1));
            assert_eq!(contract.predicate, Some(CompiledResultPredicate::Null));
            assert_eq!(
                contract.result_success_predicate,
                Some(CompiledResultPredicate::NonNull)
            );
            assert_eq!(contract.member_contracts.len(), operation_matrix.len());
            for member in &contract.member_contracts {
                assert_eq!(
                    operation_matrix.get(member.member.as_str()),
                    Some(&member.parameter_count),
                    "only the reviewed operation surface for {id} is modeled: {member:#?}"
                );
                assert_eq!(member.completeness, Completeness::Complete);
                assert_eq!(
                    member.preconditions,
                    Some(vec![CompiledOperationPrecondition {
                        input: CompiledSummaryInput::Receiver {},
                        predicate: CompiledResultPredicate::NonNull,
                    }])
                );
                assert!(member.declared_effects.is_empty());
            }
        }

        let declarations = BIFROST_EMBEDDED_PACKS
            .packs()
            .iter()
            .find(|pack| pack.source_id() == "bifrost.go.stdlib.net-declarations@1.1.0")
            .expect("the Go net declaration pack ships")
            .decode(&DecodeLimits::default())
            .expect("the Go net declaration pack decodes");
        assert_eq!(declarations.manifest.completeness, Completeness::Partial);
        let [shard] = declarations.shards.as_slice() else {
            panic!("the Go net declaration pack has one shard: {declarations:#?}");
        };
        let shard = decode_shard_for_manifest(
            &declarations.manifest,
            &shard.descriptor,
            &shard.bytes,
            &DecodeLimits::default(),
        )
        .expect("the Go net declaration shard decodes");
        let (types, members, relations) = shard
            .payload()
            .declaration_facts()
            .expect("the Go net declaration shard carries declaration facts");
        assert!(relations.is_empty());
        assert_eq!(
            types.len(),
            4,
            "net, net.Conn, net.Listener, and net.Addr are reviewed"
        );
        for fact in types {
            assert_eq!(
                fact.id,
                type_declaration_id(TypeIdentity {
                    ecosystem: "go",
                    name: &fact.name,
                }),
                "the authored type ID uses the Go artifact producer's canonical identity"
            );
        }
        let module = types
            .iter()
            .find(|fact| fact.name == "net")
            .expect("the net module declaration ships");
        assert_eq!(module.type_kind, TypeKind::Module);
        assert_eq!(
            module.id,
            "type.d38a97811c1f5377b31ce35fec4044aade55f1f9cabbd6d84bb45563d695de48"
        );
        let conn = types
            .iter()
            .find(|fact| fact.name == "net.Conn")
            .expect("the net.Conn interface declaration ships");
        assert_eq!(conn.type_kind, TypeKind::Interface);
        assert!(conn.is_abstract);
        assert_eq!(
            conn.id,
            "type.e787bbcd3ab1d2d588b3b05c3f88fa0dcdd40bb4ecba196ca5cc8e5638016f77"
        );
        let listener = types
            .iter()
            .find(|fact| fact.name == "net.Listener")
            .expect("the net.Listener interface declaration ships");
        assert_eq!(listener.type_kind, TypeKind::Interface);
        assert!(listener.is_abstract);
        assert_eq!(
            listener.id,
            "type.d5d96e805db6a6ba6abef788cfe33345bb3d78948c5b1fe95abb810898505e3d"
        );
        let addr = types
            .iter()
            .find(|fact| fact.name == "net.Addr")
            .expect("the net.Addr interface declaration ships");
        assert_eq!(addr.type_kind, TypeKind::Interface);
        assert!(addr.is_abstract);
        assert_eq!(
            addr.id,
            "type.fdff4962d361a2e29fa9b73643fd573cd0ebab82d9d459416bfe025d698bd1ae"
        );

        assert_eq!(
            members.len(),
            conn_operation_matrix.len() + listener_operation_matrix.len() + 3
        );
        for member in members {
            let signature = member
                .signature
                .as_ref()
                .unwrap_or_else(|| panic!("{} has a structured signature", member.name));
            let parameter_types = signature
                .parameters
                .iter()
                .map(|parameter| parameter.r#type.clone())
                .collect::<Vec<_>>();
            let parameter_variadics = signature
                .parameters
                .iter()
                .map(|parameter| parameter.variadic)
                .collect::<Vec<_>>();
            assert_eq!(
                member.id,
                member_declaration_id(MemberIdentity {
                    owner_id: &member.owner,
                    kind: member.member_kind,
                    is_static: member.is_static,
                    parameter_arity: parameter_types.len(),
                    name: &member.name,
                    generic_arity: signature.type_parameters.len(),
                    parameter_types: &parameter_types,
                    parameter_variadics: &parameter_variadics,
                    return_type: signature.returns.as_ref(),
                }),
                "the authored member ID uses the Go artifact producer's canonical identity"
            );
            if member.owner == module.id {
                assert_eq!(member.member_kind, MemberKind::Function);
                assert!(member.is_static);
                assert!(matches!(
                    member.name.as_str(),
                    "Dial" | "DialTimeout" | "Listen"
                ));
            } else {
                let operation_matrix = if member.owner == conn.id {
                    &conn_operation_matrix
                } else {
                    assert_eq!(member.owner, listener.id);
                    &listener_operation_matrix
                };
                assert_eq!(member.member_kind, MemberKind::Method);
                assert!(!member.is_static);
                assert!(member.is_abstract);
                assert!(member.is_virtual);
                assert_eq!(
                    operation_matrix.get(member.name.as_str()),
                    Some(&u32::try_from(signature.parameters.len()).expect("Go arity fits u32"))
                );
            }
        }
        let dial = members
            .iter()
            .find(|member| member.name == "Dial")
            .expect("net.Dial declaration ships");
        assert_eq!(
            dial.id,
            "member.d0aa465e92136c45be3c6a1d2b6f54fb1addae8b625dd4ce3b9c8e2a51f1dd17"
        );
        let dial_timeout = members
            .iter()
            .find(|member| member.name == "DialTimeout")
            .expect("net.DialTimeout declaration ships");
        assert_eq!(
            dial_timeout.id,
            "member.ead53a44232a9997505b0c78665160d60989ad5374576153b2a28ee96ac1ef57"
        );
        let listen = members
            .iter()
            .find(|member| member.name == "Listen")
            .expect("net.Listen declaration ships");
        assert_eq!(
            listen.id,
            "member.7e970dc0ebba4aec16eaf04bffd6ef9ce97abecd540ebe6c1613cd59d5dd3cb1"
        );
    }

    #[test]
    fn activated_go_net_pack_binds_only_reviewed_package_functions() {
        let source = r#"package sample

import (
    "net"
    "time"
)

func packageCalls() {
    direct, _ := net.Dial("tcp", "example.test:80")
    _ = direct
    timed, _ := net.DialTimeout("tcp", "example.test:80", time.Second)
    _ = timed
    listener, _ := net.Listen("tcp", "127.0.0.1:0")
    _ = listener
}

type localListenerConfig struct{}

func (*localListenerConfig) Listen(network, address string) (net.Listener, error) {
    return nil, nil
}

func receiverNearMiss(d *net.Dialer, config *localListenerConfig) {
    local, _ := d.Dial("tcp", "example.test:80")
    _ = local
    listener, _ := config.Listen("tcp", "127.0.0.1:0")
    _ = listener
}
"#;
        let project = InlineTestProject::with_language(Language::Go)
            .file("go.mod", "module example.com/net-model\n")
            .file("main.go", source)
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default())
            .expect("ephemeral semantic-pack catalog");
        BIFROST_EMBEDDED_PACKS
            .register_all(&catalog, &DecodeLimits::default())
            .expect("shipped semantic packs register");
        let outcome = acquire_active_semantic_models(
            workspace.analyzer(),
            &catalog,
            None,
            &SemanticModelActivationRequest {
                bifrost_version: env!("CARGO_PKG_VERSION")
                    .parse()
                    .expect("crate version is semver"),
                evidence: vec![SemanticModelActivationEvidence {
                    language: "go".to_owned(),
                    ecosystem: "go".to_owned(),
                    package: None,
                    module: None,
                    toolchain: None,
                    target: None,
                    configuration: None,
                    artifact_sha256: None,
                }],
                controls: Vec::new(),
                limits: SemanticModelRuntimeLimits::default(),
            },
            &CancellationToken::default(),
        );
        assert!(
            matches!(outcome, SemanticModelRuntimeOutcome::Ready { .. }),
            "Go stdlib activation completes: {outcome:#?}"
        );

        let file = project.file("main.go");
        let provider = workspace
            .analyzer()
            .structural_fact_providers()
            .into_iter()
            .find(|provider| provider.structural_language() == Language::Go)
            .expect("Go structural facts provider");
        let facts = provider
            .structural_facts(&file)
            .expect("Go structural facts");
        let shapes = call_shapes_in_file(&facts, &file, usize::MAX);
        assert_eq!(shapes.len(), 5, "fixture contains five calls: {shapes:#?}");
        let source: Arc<str> = Arc::from(source);
        let lookups = shapes
            .iter()
            .map(|shape| {
                let call = source
                    .get(shape.outcome.range.start_byte..shape.outcome.range.end_byte)
                    .expect("call range belongs to the indexed source")
                    .to_owned();
                let lookup = modeled_call_targets_for_shape(
                    workspace.analyzer(),
                    shape,
                    Arc::clone(&source),
                    CallRelationLimits {
                        max_files: 1,
                        max_source_bytes: usize::MAX,
                        max_candidates: 100,
                    },
                    None,
                );
                (call, lookup)
            })
            .collect::<BTreeMap<_, _>>();

        let snapshot = workspace
            .analyzer()
            .active_semantic_model_snapshot()
            .expect("activation publishes one atomic model snapshot");
        for (call, member, parameter_count) in [
            ("net.Dial(\"tcp\", \"example.test:80\")", "Dial", 2),
            (
                "net.DialTimeout(\"tcp\", \"example.test:80\", time.Second)",
                "DialTimeout",
                3,
            ),
            ("net.Listen(\"tcp\", \"127.0.0.1:0\")", "Listen", 2),
        ] {
            let lookup = &lookups[call];
            assert_eq!(lookup.coverage, ModeledCallTargetCoverage::Exhaustive);
            assert_eq!(
                lookup.call_application,
                ModeledCallApplication::PackageFunction
            );
            let [arm] = lookup.arms.as_slice() else {
                panic!("one exact external arm for {call}: {lookup:#?}");
            };
            assert_eq!(arm.key.language, "go");
            assert_eq!(arm.key.owner, "net");
            assert_eq!(arm.key.member, member);
            assert!(!arm.key.has_receiver);
            assert_eq!(arm.key.parameter_count, parameter_count);
            assert_eq!(arm.origin, ModeledCallTargetOrigin::UnmaterializedExternal);

            let matched = snapshot.active_models().procedure_summaries_for_member(
                ProcedureSummaryMemberKey::new(
                    &arm.key.language,
                    &arm.key.owner,
                    &arm.key.member,
                    arm.key.has_receiver,
                    arm.key.parameter_count,
                ),
            );
            assert_eq!(matched.disposition, SemanticModelMatchDisposition::Unique);
            let [summary] = matched.records.as_slice() else {
                panic!("one reviewed summary binds {call}: {matched:#?}");
            };
            let [contract] = summary.result_contracts() else {
                panic!("{call} carries one result contract: {summary:#?}");
            };
            assert_eq!(contract.result_ordinal, 0);
            assert_eq!(contract.condition_result_ordinal, Some(1));
            assert_eq!(contract.predicate, Some(CompiledResultPredicate::Null));
            assert_eq!(
                contract.result_success_predicate,
                Some(CompiledResultPredicate::NonNull)
            );
        }

        for (call, message) in [
            (
                "d.Dial(\"tcp\", \"example.test:80\")",
                "(*net.Dialer).Dial must not inherit net.Dial's receiverless contract",
            ),
            (
                "config.Listen(\"tcp\", \"127.0.0.1:0\")",
                "a workspace receiver method must not inherit net.Listen's package contract",
            ),
        ] {
            let near_miss = &lookups[call];
            assert!(near_miss.arms.is_empty(), "{near_miss:#?}");
            assert_ne!(
                near_miss.coverage,
                ModeledCallTargetCoverage::Exhaustive,
                "{message}: {near_miss:#?}"
            );
        }
    }
}
