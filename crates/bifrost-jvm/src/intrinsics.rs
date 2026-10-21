//! Pinned language knowledge for unavailable JVM default-import providers.
//!
//! The tables certify name absence only. A present name still requires indexed
//! declarations for its types, members, overloads, and receiver applicability.
//! These fixed tables never depend on workspace size or active semantic packs.

use brokk_bifrost_core::analyzer::{Language, fq_name::joined_segments};

#[path = "intrinsic_inventory_data.rs"]
mod data;

pub const KOTLIN_STDLIB_VERSION: &str = "2.1.20";
pub const SCALA_LIBRARY_VERSION: &str = "2.13.16";
pub const SCALA3_LIBRARY_VERSION: &str = "3.3.5";
pub const JAVA_LANG_VERSION: &str = "Temurin-21.0.12.1+1-LTS";

/// One name in a language-defined root's closed member inventory. Ordinals
/// distinguish Java Object overloads; source-language roots need name presence.
#[derive(Clone, Copy)]
pub struct IntrinsicMember {
    pub name: &'static str,
    pub visibility: &'static str,
}

/// The complete spelling inventory of one of this language's default providers.
/// Scala 3 includes both scala-library 2.13 and scala3-library on its classpath.
pub fn default_provider_names(
    language: Language,
    provider: &str,
) -> Option<&'static [&'static str]> {
    let is_default = match language {
        Language::Java => provider == "java.lang",
        Language::Kotlin => crate::kotlin::imports::KOTLIN_DEFAULT_IMPORT_PACKAGES
            .iter()
            .any(|package| package.rendered == provider),
        Language::Scala => matches!(provider, "java.lang" | "scala" | "scala.Predef"),
        _ => false,
    };
    if !is_default {
        return None;
    }
    data::DEFAULT_PROVIDER_NAMES
        .iter()
        .find_map(|(name, names)| (*name == provider).then_some(*names))
}

/// A certified name absence discharges this exact unindexed provider. A known
/// name, an unknown package, or another language provides no negative evidence.
pub fn default_provider_excludes_name(language: Language, provider: &str, name: &str) -> bool {
    default_provider_names(language, provider)
        .is_some_and(|names| names.binary_search(&name).is_err())
}

/// Closed member inventories include inherited names and exclude constructors.
/// Indexed artifacts retain ownership of their own member ordinals.
pub fn root_member_inventory(owner: &str) -> Option<&'static [IntrinsicMember]> {
    data::ROOT_MEMBERS
        .iter()
        .find_map(|(name, members)| (*name == owner).then_some(*members))
}

// These source-language roots have closed hierarchies as well as closed member
// inventories. Java Object retains its existing producer obligation and ordinals.
const SOURCE_LANGUAGE_ROOTS: &[(Language, &str)] = &[
    (Language::Kotlin, "kotlin.Any"),
    (Language::Kotlin, "kotlin.Annotation"),
    (Language::Scala, "scala.Any"),
    (Language::Scala, "scala.AnyRef"),
];

/// A synthetic absolute route to one of these roots needs no open hierarchy
/// obligation. The member tables already include the root's inherited members.
pub(crate) fn source_root_hierarchy_is_intrinsic<'a>(
    segments: impl Iterator<Item = &'a str> + Clone,
) -> bool {
    SOURCE_LANGUAGE_ROOTS.iter().any(|(_, owner)| {
        debug_assert!(root_member_inventory(owner).is_some());
        joined_segments(owner, ".").eq(segments.clone())
    })
}

/// Roots introduced by this source language, plus the JVM's shared Object root.
pub fn language_root_member_inventory(
    language: Language,
    owner: &str,
) -> Option<&'static [IntrinsicMember]> {
    let defined = SOURCE_LANGUAGE_ROOTS.contains(&(language, owner))
        || (owner == "java.lang.Object"
            && matches!(
                language,
                Language::Java | Language::Kotlin | Language::Scala
            ));
    if defined {
        root_member_inventory(owner)
    } else {
        None
    }
}
