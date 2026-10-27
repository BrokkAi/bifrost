//! Pinned language knowledge for unavailable JVM default-import providers.
//!
//! The tables certify name absence only. A present name still requires indexed
//! declarations for its types, members, overloads, and receiver applicability.
//! These fixed tables never depend on workspace size or active semantic packs.

use brokk_bifrost_core::analyzer::{Language, fq_name::joined_segments};

#[path = "intrinsic_inventory_data.rs"]
mod data;

/// Exact generated data participates in JVM analyzer epochs, including all
/// root, default-provider and closed-owner inventories. Regeneration invalidates
/// persisted resolution inputs automatically.
pub const INVENTORY_EPOCH_INPUT: &str = include_str!("intrinsic_inventory_data.rs");

/// Whether this language can use an inventory as an absence-only provider.
pub fn language_has_member_inventory(language: Language, owner: &str) -> bool {
    language_root_member_inventory(language, owner).is_some()
        || (language == Language::Kotlin && closed_owner_member_inventory(owner).is_some())
}

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClosedMemberKind {
    Callable,
    Value,
    Type,
}

pub struct ClosedOwnerMember {
    pub name: &'static str,
    pub kind: ClosedMemberKind,
    pub visibility: &'static str,
}

/// A flattened, complete name inventory: it already includes inherited and mapped names,
/// so no hierarchy walk is needed. Name presence only; no signatures or declarations.
pub fn closed_owner_member_inventory(owner: &str) -> Option<&'static [ClosedOwnerMember]> {
    data::CLOSED_OWNER_MEMBERS
        .iter()
        .find_map(|(name, members)| (*name == owner).then_some(*members))
}

#[test]
fn closed_owner_inventory_is_sorted_and_deduplicated() {
    assert!(!data::CLOSED_OWNER_MEMBERS.is_empty());
    assert!(
        data::CLOSED_OWNER_MEMBERS
            .windows(2)
            .all(|pair| pair[0].0 < pair[1].0)
    );
    for (owner, members) in data::CLOSED_OWNER_MEMBERS {
        assert!(!members.is_empty(), "{owner}");
        assert!(
            members.windows(2).all(|pair| {
                (pair[0].name, pair[0].kind as u8) < (pair[1].name, pair[1].kind as u8)
            }),
            "{owner}"
        );
    }
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

/// One method in a JVM rule's fixed inventory. The parentless-interface subset
/// contains only public instance methods. Parameter lists retain overload
/// identity; selected providers still supply declaration and applicability
/// evidence. The interface rule supplies its own declared modifiers.
#[derive(Debug, Clone, Copy)]
pub struct JvmImplicitInterfaceMethod {
    pub name: &'static str,
    pub parameters: &'static [&'static str],
    pub returns: &'static str,
}

/// Language knowledge for an interface's lookup-only member root. Other JVM
/// languages opt in independently; this is not a nominal inheritance edge.
#[derive(Debug)]
pub struct JvmImplicitInterfaceMembers {
    pub owner: &'static str,
    pub simple_name: &'static str,
    pub methods: &'static [JvmImplicitInterfaceMethod],
    pub visibility: brokk_bifrost_core::analyzer::structural::resolution::DeclaredVisibility,
    pub is_abstract: bool,
}

/// JLS 9.2 implicitly declares Object's public instance methods. Protected
/// clone/finalize are deliberately absent. No Kotlin/Scala rule is assumed.
pub fn implicit_interface_members(
    language: Language,
) -> Option<&'static JvmImplicitInterfaceMembers> {
    static JAVA: JvmImplicitInterfaceMembers = JvmImplicitInterfaceMembers {
        owner: "java.lang.Object",
        simple_name: "Object",
        methods: &JAVA_OBJECT_PUBLIC_METHODS,
        visibility:
            brokk_bifrost_core::analyzer::structural::resolution::DeclaredVisibility::Public,
        is_abstract: true,
    };
    match language {
        Language::Java => Some(&JAVA),
        _ => None,
    }
}

// Object is special because JLS 4.3.2 fixes its members. This is a complete
// method inventory, not a claim that other JDK declarations are enumerated.
const JAVA_OBJECT_PUBLIC_METHODS: [JvmImplicitInterfaceMethod; 9] = [
    JvmImplicitInterfaceMethod {
        name: "getClass",
        parameters: &[],
        returns: "java.lang.Class<?>",
    },
    JvmImplicitInterfaceMethod {
        name: "hashCode",
        parameters: &[],
        returns: "int",
    },
    JvmImplicitInterfaceMethod {
        name: "equals",
        parameters: &["java.lang.Object"],
        returns: "boolean",
    },
    JvmImplicitInterfaceMethod {
        name: "toString",
        parameters: &[],
        returns: "java.lang.String",
    },
    JvmImplicitInterfaceMethod {
        name: "notify",
        parameters: &[],
        returns: "void",
    },
    JvmImplicitInterfaceMethod {
        name: "notifyAll",
        parameters: &[],
        returns: "void",
    },
    JvmImplicitInterfaceMethod {
        name: "wait",
        parameters: &[],
        returns: "void",
    },
    JvmImplicitInterfaceMethod {
        name: "wait",
        parameters: &["long"],
        returns: "void",
    },
    JvmImplicitInterfaceMethod {
        name: "wait",
        parameters: &["long", "int"],
        returns: "void",
    },
];
const JAVA_OBJECT_METHODS: [JvmImplicitInterfaceMethod; 11] = [
    JAVA_OBJECT_PUBLIC_METHODS[0],
    JAVA_OBJECT_PUBLIC_METHODS[1],
    JAVA_OBJECT_PUBLIC_METHODS[2],
    JAVA_OBJECT_PUBLIC_METHODS[3],
    JAVA_OBJECT_PUBLIC_METHODS[4],
    JAVA_OBJECT_PUBLIC_METHODS[5],
    JAVA_OBJECT_PUBLIC_METHODS[6],
    JAVA_OBJECT_PUBLIC_METHODS[7],
    JAVA_OBJECT_PUBLIC_METHODS[8],
    JvmImplicitInterfaceMethod {
        name: "clone",
        parameters: &[],
        returns: "java.lang.Object",
    },
    JvmImplicitInterfaceMethod {
        name: "finalize",
        parameters: &[],
        returns: "void",
    },
];

/// A method inventory fixed by the platform language specification. It proves
/// enumeration only; actual selected declarations still supply signatures.
pub fn specified_method_inventory(owner: &str) -> Option<&'static [JvmImplicitInterfaceMethod]> {
    match owner {
        "java.lang.Object" => Some(&JAVA_OBJECT_METHODS),
        _ => None,
    }
}
