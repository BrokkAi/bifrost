use super::*;
use crate::analyzer::semantic_model::{
    artifact::CompiledSemanticModelPack,
    catalog::{DurablePackSource, DurablePackSourceKind, SemanticPackCatalog},
    compiler::{CompilerOptions, compile_source},
    model::Producer,
    producer::ArtifactProducerLimits,
    source::SourceFormat,
};
use std::sync::Mutex;

/// A complete CPython standard-library pack that activates for the whole
/// `>=3.10.0, <3.15.0` range the shipped typeshed pack declares, so a
/// workspace that pins 3.10.0 from `requires-python` selects it.
#[doc(hidden)]
pub const CPYTHON_PACK: &str = r#"{
  "schema_version": 2,
  "pack_id": "fixture.python-stdlib",
  "version": "2026.9.4",
  "producer": { "name": "bifrost-fixture", "version": "1.0.0" },
  "language": "python",
  "ecosystem": "python",
  "compatibility": {
    "bifrost": ">=0.8.0, <1.0.0",
    "toolchains": [{ "name": "cpython", "requirement": ">=3.10.0, <3.15.0" }]
  },
  "provenance": { "source": "checked-in test source", "revision": "fixture-v1" },
  "license": "Apache-2.0",
  "completeness": "complete",
  "safety": { "generated_code_only": false, "review_required": false },
  "shards": [{
    "id": "python.stdlib",
    "activation": [{
      "toolchain": { "name": "cpython", "version": ">=3.10.0, <3.15.0" }
    }],
    "payload": {
      "kind": "declaration_facts",
      "types": [{
        "id": "python.types-nonetype",
        "name": "types.NoneType",
        "type_kind": "class",
        "visibility": "public",
        "type_parameters": [],
        "hierarchy": [],
        "aliases": [],
        "extension_surfaces": [],
        "locator": {
          "kind": "artifact",
          "path": "stdlib/types.pyi",
          "symbol": "types.NoneType"
        }
      }],
      "members": [],
      "relations": []
    }
  }]
}"#;
pub(super) static HOOK_GUARD: Mutex<()> = Mutex::new(());
static HOOK_REQUESTS: Mutex<Vec<String>> = Mutex::new(Vec::new());
static HOOK_BEHAVIOR: Mutex<HookBehavior> = Mutex::new(HookBehavior::RecordOnly);
/// What the fixture hook does when preparation reaches it. The behavior is
/// an enum rather than a set of flags so exactly one of the three
/// acquisition outcomes is selected at a time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub enum HookBehavior {
    RecordOnly,
    Fail,
    Install,
}

#[doc(hidden)]
fn recording_hook(
    catalog: &SemanticPackCatalog,
    request: &AcquisitionRequest<'_>,
) -> Result<(), String> {
    let description = match request {
        AcquisitionRequest::GeneratedProduction(key) => {
            format!("generated:{}", key.production_digest())
        }
        AcquisitionRequest::DeclaredPack(query) => {
            let toolchain = query
                .toolchain
                .as_ref()
                .expect("declared toolchain dependency query carries a toolchain coordinate");
            let version = toolchain
                .version
                .as_ref()
                .expect("declared toolchain dependency query carries an exact version");
            format!("declared:{}:{}@{version}", query.ecosystem, toolchain.name)
        }
    };
    HOOK_REQUESTS
        .lock()
        .expect("fixture hook request log poisoned")
        .push(description);
    match *HOOK_BEHAVIOR
        .lock()
        .expect("fixture hook behavior poisoned")
    {
        HookBehavior::RecordOnly => Ok(()),
        HookBehavior::Fail => Err("fixture acquisition unavailable".to_owned()),
        HookBehavior::Install => install_fixture_pack(catalog, &compiled_pack(CPYTHON_PACK)),
    }
}

#[doc(hidden)]
pub fn compiled_pack(source: &str) -> CompiledSemanticModelPack {
    compile_source(
        SourceFormat::Json,
        source.as_bytes(),
        &CompilerOptions::default(),
    )
    .unwrap_or_else(|diagnostics| panic!("fixture compilation failed: {diagnostics:#?}"))
}

#[doc(hidden)]
pub fn install_fixture_pack(
    catalog: &SemanticPackCatalog,
    pack: &CompiledSemanticModelPack,
) -> Result<(), String> {
    catalog
        .install(
            pack,
            &DurablePackSource {
                kind: DurablePackSourceKind::PreShipped,
                source_id: format!("test:{}@{}", pack.manifest.pack_id, pack.manifest.version),
            },
        )
        .map(|_| ())
        .map_err(|error| error.to_string())
}

struct NeverProducingAdapter;

impl DependencyPackAdapter for NeverProducingAdapter {
    fn adapter_name(&self) -> &str {
        "fixture-declared"
    }

    fn adapter_version(&self) -> &str {
        "1"
    }

    fn producer(&self) -> Producer {
        Producer {
            name: "fixture-declared".to_owned(),
            version: "1".to_owned(),
        }
    }

    fn produce(
        &self,
        _dependency: &ResolvedDependency,
        _artifacts: &[ExactDependencyArtifact],
        _limits: &ArtifactProducerLimits,
        _cancellation: Option<&CancellationToken>,
    ) -> DependencyPackProduction {
        unimplemented!("an artifact-less dependency never reaches production")
    }
}

#[doc(hidden)]
pub struct HookFixture<'a> {
    _guard: std::sync::MutexGuard<'a, ()>,
    previous: Option<SemanticPackAcquisitionHook>,
}

impl HookFixture<'_> {
    pub fn install(behavior: HookBehavior) -> Self {
        let guard = HOOK_GUARD
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        HOOK_REQUESTS
            .lock()
            .expect("fixture hook request log poisoned")
            .clear();
        *HOOK_BEHAVIOR
            .lock()
            .expect("fixture hook behavior poisoned") = behavior;
        let previous = set_semantic_pack_acquisition_hook(Some(recording_hook));
        Self {
            _guard: guard,
            previous,
        }
    }

    pub fn requests(&self) -> Vec<String> {
        HOOK_REQUESTS
            .lock()
            .expect("fixture hook request log poisoned")
            .clone()
    }
}

impl Drop for HookFixture<'_> {
    fn drop(&mut self) {
        set_semantic_pack_acquisition_hook(self.previous);
    }
}

#[doc(hidden)]
pub fn prepare(
    catalog: &SemanticPackCatalog,
    dependency: ResolvedDependency,
) -> DependencyPackPreparationOutcome {
    prepare_dependency_semantic_packs(
        catalog,
        &NeverProducingAdapter,
        &[dependency],
        &DependencyPackLimits::default(),
        None,
    )
}
