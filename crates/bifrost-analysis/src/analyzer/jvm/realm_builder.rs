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
//! generated from the same `self.inner` index.

use crate::analyzer::{
    CodeUnit, ForwardQueryProvider, IAnalyzer, JavaAnalyzer, KotlinAnalyzer, Language,
    ScalaAnalyzer, resolve_analyzer,
};
use brokk_bifrost_jvm::realm::{JvmRealmMember, JvmSourceRealm};

macro_rules! impl_jvm_realm_member {
    ($analyzer:ty) => {
        impl JvmRealmMember for $analyzer {
            fn forward_definition_fqn(&self, fqn: &str) -> Vec<CodeUnit> {
                ForwardQueryProvider::forward_definition_fqn(self, fqn)
            }
        }
    };
}

impl_jvm_realm_member!(JavaAnalyzer);
impl_jvm_realm_member!(ScalaAnalyzer);
impl_jvm_realm_member!(KotlinAnalyzer);

/// Every JVM analyzer reachable from `analyzer`, viewed as one realm.
///
/// Works identically for a single-language analyzer and for a
/// [`crate::analyzer::MultiAnalyzer`]; the caller does not have to know which
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
