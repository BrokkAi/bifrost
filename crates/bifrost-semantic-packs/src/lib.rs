//! Optional Bifrost-curated semantic packs and their distribution lifecycle.
//!
//! Generic pack artifacts, catalogs, activation, and analyzer overlays remain in
//! `brokk-bifrost-analysis`. This downstream crate owns only Bifrost's prebuilt
//! content and product distribution policy. Analyzer consumers can omit it and
//! register their own packs.

#[cfg(feature = "release-tooling")]
pub mod release_bundle;

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

const BIFROST_EMBEDDED_PACK_ENTRIES: &[EmbeddedSemanticPack<'static>] =
    &[EmbeddedSemanticPack::new(
        "bifrost.scala.case-class@1.0.0",
        include_bytes!("../embedded/scala-case-class/manifest.json"),
        SCALA_CASE_CLASS_SHARDS,
    )];

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
mod tests {
    use brokk_bifrost_analysis::analyzer::semantic_model::{
        CatalogOptions, CompilerOptions, SourceFormat, compile_source,
    };

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
}
