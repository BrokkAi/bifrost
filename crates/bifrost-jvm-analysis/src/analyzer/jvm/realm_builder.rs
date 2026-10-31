//! The shim half of the JVM source realm.
//!
//! [`brokk_bifrost_jvm::realm::JvmSourceRealm`] and its two peer queries live
//! in the JVM language crate, because every consumer of them is JVM language
//! knowledge. Finding the members cannot: it means downcasting an
//! `&dyn IAnalyzer` to [`JavaAnalyzer`], [`ScalaAnalyzer`] and
//! [`KotlinAnalyzer`], three types the language crate must not name. So the
//! realm's only constructor stays here, on the same side of the seam as
//! `resolve_analyzer`, and hands the crate a finished member list.
//!
//! Each analyzer's [`JvmRealmMember`] impl forwards to its
//! [`ForwardQueryProvider`] impl, which `impl_forward_query_provider!` already
//! generated from the same `self.inner` index, and to its
//! [`TypeHierarchyProvider`] impl for a peer's direct supertypes (#2918).

use brokk_bifrost_core::analyzer::model::CodeUnit;

use brokk_bifrost_analysis::analyzer::analyzer_definition_lookup::ForwardQueryProvider;

use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

use crate::analyzer::JavaAnalyzer;

use crate::analyzer::KotlinAnalyzer;

use brokk_bifrost_core::analyzer::model::Language;

use crate::analyzer::ScalaAnalyzer;

use brokk_bifrost_core::analyzer::capabilities::TypeHierarchyProvider;

use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;
use brokk_bifrost_jvm::realm::{JvmRealmMember, JvmSourceRealm};

macro_rules! impl_jvm_realm_member {
    ($analyzer:ty, $language:expr) => {
        impl JvmRealmMember for $analyzer {
            fn forward_definition_fqn(&self, fqn: &str) -> Vec<CodeUnit> {
                ForwardQueryProvider::forward_definition_fqn(self, fqn)
            }

            /// The analyzer's own memoized `get_direct_ancestors`, which
            /// resolves the unit's spelled supertypes with this language's
            /// rules and the declaring file's imports. Ownership is the
            /// file's language: each JVM adapter claims exactly the files of
            /// its own language, which is also how `jvm_source_realm` keys
            /// the member list.
            ///
            /// Kotlin's answer here is its realm-less one -- a Kotlin analyzer
            /// cannot see its siblings from inside -- so a Kotlin unit's Java
            /// or Scala supertypes are absent from it. No walk asks a Kotlin
            /// peer today: the Java and Scala hierarchy walks resolve against
            /// their own declarations only and never reach a Kotlin unit.
            fn direct_ancestor_fqns(&self, unit: &CodeUnit) -> Option<Vec<String>> {
                if unit.source().language() != $language {
                    return None;
                }
                let answer = TypeHierarchyProvider::get_direct_ancestors(self, unit);
                answer
                    .is_complete()
                    .then(|| answer.edges.iter().map(CodeUnit::fq_name).collect())
            }
        }
    };
}

impl_jvm_realm_member!(JavaAnalyzer, Language::Java);
impl_jvm_realm_member!(ScalaAnalyzer, Language::Scala);
impl_jvm_realm_member!(KotlinAnalyzer, Language::Kotlin);

/// Every JVM analyzer reachable from `analyzer`, viewed as one realm.
///
/// Works identically for a single-language analyzer and for a
/// [`brokk_bifrost_analysis::analyzer::MultiAnalyzer`]; the caller does not have to know which
/// it holds.
pub(crate) fn jvm_source_realm(analyzer: &dyn IAnalyzer) -> JvmSourceRealm<'_> {
    let mut members: Vec<(Language, &dyn JvmRealmMember)> = Vec::new();
    if let Some(java) = resolve_analyzer::<JavaAnalyzer>(analyzer) {
        members.push((Language::Java, java));
    }
    if let Some(scala) = resolve_analyzer::<ScalaAnalyzer>(analyzer) {
        members.push((Language::Scala, scala));
    }
    if let Some(kotlin) = resolve_analyzer::<KotlinAnalyzer>(analyzer) {
        members.push((Language::Kotlin, kotlin));
    }
    JvmSourceRealm::new(members)
}
