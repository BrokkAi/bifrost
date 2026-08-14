//! JVM realm support shared by the Java, Scala, and Kotlin analyzers.
//!
//! Java, Scala, and Kotlin compile to one classpath, so they share one
//! dependency universe: the same Maven/Gradle artifacts, the same jar-backed
//! declaration index, and the same build-manifest inputs that invalidate it.
//! Everything in this module is language-neutral by construction; per-language
//! behaviour belongs in `crate::analyzer::{java, scala, kotlin}`.

pub(crate) mod dependency_discovery;
pub(crate) mod external;
pub(crate) mod java_artifact;
pub(crate) mod jdk_artifact;
pub(crate) mod kotlin_artifact;
pub(crate) mod realm_builder;
pub(crate) mod scala_artifact;

use brokk_bifrost_jvm::proof::{
    JvmActiveSemanticModel, JvmModelDisposition, JvmRetainedExternalIndex,
};
use external::JvmExternalDeclarationIndex;

/// Classify a peeked `OnceLock<JvmExternalDeclarationIndex>` cell for the
/// proof-gated diagnostic ladder (#1619).
///
/// All three JVM analyzers hold that cell and all three must read it the same
/// way, so the mapping lives here rather than three times over. `None` is a
/// cell no resolution and no `warm_query_indexes` has filled yet: a diagnostic
/// may not fill it, because building it reads jars.
pub(crate) fn retained_external_index_state(
    retained: Option<&JvmExternalDeclarationIndex>,
) -> JvmRetainedExternalIndex {
    match retained {
        None => JvmRetainedExternalIndex::Unbuilt,
        Some(external) if external.production_diagnostic_count() > 0 => {
            JvmRetainedExternalIndex::Partial
        }
        Some(_) => JvmRetainedExternalIndex::Complete,
    }
}

/// The active dependency model, as [`JvmActiveSemanticModel`] narrows it for
/// `brokk-bifrost-jvm`.
///
/// The overlay is the *dispatching* analyzer's, so this is built at the
/// analysis-side shim where that analyzer is in hand, not inside a language
/// analyzer that only knows its own generation.
pub(crate) struct JvmOverlayModel(
    pub(crate) Option<std::sync::Arc<crate::analyzer::semantic_model::SemanticModelOverlay>>,
);

impl JvmActiveSemanticModel for JvmOverlayModel {
    fn is_published(&self) -> bool {
        self.0.is_some()
    }

    fn qualified_name_disposition(&self, fqn: &str) -> JvmModelDisposition {
        let Some(overlay) = self.0.as_ref() else {
            return JvmModelDisposition::Absent;
        };
        // `symbols_named` posts every symbol under its simple name, its
        // qualified name and each alias, so it answers a bare `Widget` with
        // `com.acme.Widget`. A JVM caller has already walked its own import
        // tiers to produce a *qualified* spelling, and accepting the simple-name
        // posting would let any dependency type that happens to share a short
        // name silence a real error. Only the qualified spellings count: the
        // declared one, and the aliases, which are qualified too.
        let declarations = overlay
            .symbols_named(fqn)
            .records
            .iter()
            .filter(|symbol| {
                symbol.qualified_name == fqn || symbol.aliases.iter().any(|alias| alias == fqn)
            })
            .count();
        match declarations {
            0 => JvmModelDisposition::Absent,
            1 => JvmModelDisposition::Unique,
            declarations => JvmModelDisposition::Conflicting { declarations },
        }
    }
}
