//! Pinned language knowledge for unavailable JVM default-import providers.
//!
//! The inventories certify name absence. Erased aliases supply target spellings.
//! A present name still requires indexed
//! declarations for its types, members, overloads, and receiver applicability.
//! These fixed tables never depend on workspace size or active semantic packs.

use brokk_bifrost_core::analyzer::{Language, fq_name::joined_segments};

#[path = "intrinsic_inventory_data.rs"]
mod data;

/// Exact generated data participates in JVM analyzer epochs, including all
/// root, default-provider and closed-owner inventories. Regeneration invalidates
/// persisted resolution inputs automatically.
pub const INVENTORY_EPOCH_INPUT: &str = include_str!("intrinsic_inventory_data.rs");

/// An implicit provider that can make a bare JVM name visible without an
/// explicit import in the source file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub enum JvmImplicitRootProvider {
    Package(&'static str),
    ScalaPredef,
}

// List order is part of external-provider identity. Precedence is separate:
// lower ranks shadow higher ranks; equal ranks form an unordered group in the walk.
const JAVA_IMPLICIT_ROOTS: [(JvmImplicitRootProvider, u32); 1] =
    [(JvmImplicitRootProvider::Package("java.lang"), 0)];
const KOTLIN_IMPLICIT_ROOTS: [(JvmImplicitRootProvider, u32); 10] = [
    (JvmImplicitRootProvider::Package("kotlin"), 0),
    (JvmImplicitRootProvider::Package("kotlin.annotation"), 0),
    (JvmImplicitRootProvider::Package("kotlin.collections"), 0),
    (JvmImplicitRootProvider::Package("kotlin.comparisons"), 0),
    (JvmImplicitRootProvider::Package("kotlin.io"), 0),
    (JvmImplicitRootProvider::Package("kotlin.ranges"), 0),
    (JvmImplicitRootProvider::Package("kotlin.sequences"), 0),
    (JvmImplicitRootProvider::Package("kotlin.text"), 0),
    (JvmImplicitRootProvider::Package("kotlin.jvm"), 0),
    (JvmImplicitRootProvider::Package("java.lang"), 1),
];
const SCALA_IMPLICIT_ROOTS: [(JvmImplicitRootProvider, u32); 3] = [
    (JvmImplicitRootProvider::Package("java.lang"), 2),
    (JvmImplicitRootProvider::Package("scala"), 1),
    (JvmImplicitRootProvider::ScalaPredef, 0),
];

const fn providers<const N: usize>(
    entries: &[(JvmImplicitRootProvider, u32); N],
) -> [JvmImplicitRootProvider; N] {
    let mut result = [JvmImplicitRootProvider::ScalaPredef; N];
    let mut index = 0;
    while index < N {
        result[index] = entries[index].0;
        index += 1;
    }
    result
}

const JAVA_IMPLICIT_ROOT_PROVIDERS: [JvmImplicitRootProvider; 1] = providers(&JAVA_IMPLICIT_ROOTS);
const KOTLIN_IMPLICIT_ROOT_PROVIDERS: [JvmImplicitRootProvider; 10] =
    providers(&KOTLIN_IMPLICIT_ROOTS);
const SCALA_IMPLICIT_ROOT_PROVIDERS: [JvmImplicitRootProvider; 3] =
    providers(&SCALA_IMPLICIT_ROOTS);

/// Implicit providers in identity order, with their language-defined precedence.
pub fn language_implicit_roots(language: Language) -> &'static [(JvmImplicitRootProvider, u32)] {
    let (entries, same_rank_groups): (&[(JvmImplicitRootProvider, u32)], &[u32]) = match language {
        Language::Java => (&JAVA_IMPLICIT_ROOTS, &[]),
        Language::Kotlin => (&KOTLIN_IMPLICIT_ROOTS, &[0]),
        Language::Scala => (&SCALA_IMPLICIT_ROOTS, &[]),
        _ => (&[], &[]),
    };
    for (index, (provider, rank)) in entries.iter().enumerate() {
        for (other, other_rank) in &entries[..index] {
            debug_assert_ne!(provider, other, "implicit provider groups are sets");
            debug_assert!(
                rank != other_rank || same_rank_groups.contains(rank),
                "equal ranks require an explicit group"
            );
        }
    }
    entries
}

/// The implicit providers in stable identity order, independent of precedence.
#[doc(hidden)]
pub const fn language_implicit_root_providers(
    language: Language,
) -> &'static [JvmImplicitRootProvider] {
    match language {
        Language::Java => &JAVA_IMPLICIT_ROOT_PROVIDERS,
        Language::Kotlin => &KOTLIN_IMPLICIT_ROOT_PROVIDERS,
        Language::Scala => &SCALA_IMPLICIT_ROOT_PROVIDERS,
        _ => &[],
    }
}

/// A certified empty root walk is distinct from an unavailable provider.
#[doc(hidden)]
#[derive(Debug, PartialEq, Eq)]
pub enum ImplicitRootLookup<T> {
    Answer(T),
    Absent,
    Open,
}

impl<T> ImplicitRootLookup<T> {
    pub fn into_answer(self) -> Option<T> {
        match self {
            Self::Answer(answer) => Some(answer),
            Self::Absent | Self::Open => None,
        }
    }
}

/// Select the first answering implicit root, or leave the name open when a
/// higher root cannot certify absence. Ranks order precedence independently of identity.
pub fn ordered_implicit_root<T: PartialEq>(
    language: Language,
    name: &str,
    mut lookup: impl FnMut(&'static str) -> Option<T>,
) -> ImplicitRootLookup<T> {
    let mut roots = language_implicit_roots(language).to_vec();
    roots.sort_by_key(|(_, rank)| *rank);
    let mut groups = roots.as_slice();
    while let Some((_, rank)) = groups.first() {
        let end = groups.partition_point(|(_, candidate)| candidate == rank);
        let (group, remaining) = groups.split_at(end);
        let mut answer = None;
        let mut open = false;
        for (root, _) in group {
            let root = match root {
                JvmImplicitRootProvider::Package(name) => *name,
                JvmImplicitRootProvider::ScalaPredef => "scala.Predef",
            };
            if let Some(candidate) = lookup(root) {
                if answer.as_ref().is_some_and(|answer| *answer != candidate) {
                    return ImplicitRootLookup::Open;
                }
                answer = Some(candidate);
            } else if !default_provider_excludes_name(language, root, name) {
                open = true;
            }
        }
        if open {
            return ImplicitRootLookup::Open;
        }
        if let Some(answer) = answer {
            return ImplicitRootLookup::Answer(answer);
        }
        groups = remaining;
    }
    ImplicitRootLookup::Absent
}

/// Erased type aliases of the implicit Scala roots, with fully qualified targets.
/// Like DEFAULT_PROVIDER_NAMES, the version basis is scala-library 2.13.16
/// (scala/package.scala:20-144 and scala/Predef.scala:146-187). These entries
/// are shared by the supported 2.13/Scala 3 library envelope, not version keyed.
/// Scala 3.3.5 uses the 2.13 library; its stdLibPatches/Predef.scala adds
/// methods but no replacement type aliases. This table supplies no members or
/// declaration locations: callers must resolve the target through their index.
pub const SCALA_IMPLICIT_ROOT_TYPE_ALIASES: &[(&str, &str, &str)] = &[
    ("scala", "Cloneable", "java.lang.Cloneable"),
    ("scala", "Serializable", "java.io.Serializable"),
    ("scala", "Throwable", "java.lang.Throwable"),
    ("scala", "Exception", "java.lang.Exception"),
    ("scala", "Error", "java.lang.Error"),
    ("scala", "RuntimeException", "java.lang.RuntimeException"),
    (
        "scala",
        "NullPointerException",
        "java.lang.NullPointerException",
    ),
    (
        "scala",
        "ClassCastException",
        "java.lang.ClassCastException",
    ),
    (
        "scala",
        "IndexOutOfBoundsException",
        "java.lang.IndexOutOfBoundsException",
    ),
    (
        "scala",
        "ArrayIndexOutOfBoundsException",
        "java.lang.ArrayIndexOutOfBoundsException",
    ),
    (
        "scala",
        "StringIndexOutOfBoundsException",
        "java.lang.StringIndexOutOfBoundsException",
    ),
    (
        "scala",
        "UnsupportedOperationException",
        "java.lang.UnsupportedOperationException",
    ),
    (
        "scala",
        "IllegalArgumentException",
        "java.lang.IllegalArgumentException",
    ),
    (
        "scala",
        "NoSuchElementException",
        "java.util.NoSuchElementException",
    ),
    (
        "scala",
        "NumberFormatException",
        "java.lang.NumberFormatException",
    ),
    (
        "scala",
        "AbstractMethodError",
        "java.lang.AbstractMethodError",
    ),
    (
        "scala",
        "InterruptedException",
        "java.lang.InterruptedException",
    ),
    ("scala", "TraversableOnce", "scala.collection.IterableOnce"),
    ("scala", "IterableOnce", "scala.collection.IterableOnce"),
    ("scala", "Traversable", "scala.collection.Iterable"),
    ("scala", "Iterable", "scala.collection.Iterable"),
    ("scala", "Seq", "scala.collection.immutable.Seq"),
    (
        "scala",
        "IndexedSeq",
        "scala.collection.immutable.IndexedSeq",
    ),
    ("scala", "Iterator", "scala.collection.Iterator"),
    (
        "scala",
        "BufferedIterator",
        "scala.collection.BufferedIterator",
    ),
    ("scala", "List", "scala.collection.immutable.List"),
    ("scala", "::", "scala.collection.immutable.::"),
    ("scala", "Stream", "scala.collection.immutable.Stream"),
    ("scala", "LazyList", "scala.collection.immutable.LazyList"),
    ("scala", "Vector", "scala.collection.immutable.Vector"),
    (
        "scala",
        "StringBuilder",
        "scala.collection.mutable.StringBuilder",
    ),
    ("scala", "Range", "scala.collection.immutable.Range"),
    ("scala", "BigDecimal", "scala.math.BigDecimal"),
    ("scala", "BigInt", "scala.math.BigInt"),
    ("scala", "Equiv", "scala.math.Equiv"),
    ("scala", "Fractional", "scala.math.Fractional"),
    ("scala", "Integral", "scala.math.Integral"),
    ("scala", "Numeric", "scala.math.Numeric"),
    ("scala", "Ordered", "scala.math.Ordered"),
    ("scala", "Ordering", "scala.math.Ordering"),
    ("scala", "PartialOrdering", "scala.math.PartialOrdering"),
    ("scala", "PartiallyOrdered", "scala.math.PartiallyOrdered"),
    ("scala", "Either", "scala.util.Either"),
    ("scala", "Left", "scala.util.Left"),
    ("scala", "Right", "scala.util.Right"),
    ("scala.Predef", "String", "java.lang.String"),
    ("scala.Predef", "Class", "java.lang.Class"),
    ("scala.Predef", "Function", "scala.Function1"),
    ("scala.Predef", "Map", "scala.collection.immutable.Map"),
    ("scala.Predef", "Set", "scala.collection.immutable.Set"),
    ("scala.Predef", "OptManifest", "scala.reflect.OptManifest"),
    ("scala.Predef", "Manifest", "scala.reflect.Manifest"),
];

pub fn implicit_root_type_alias(
    language: Language,
    root: &str,
    name: &str,
) -> Option<&'static str> {
    if !language_implicit_root_providers(language)
        .iter()
        .any(|provider| match provider {
            JvmImplicitRootProvider::Package(package) => *package == root,
            JvmImplicitRootProvider::ScalaPredef => root == "scala.Predef",
        })
    {
        return None;
    }
    SCALA_IMPLICIT_ROOT_TYPE_ALIASES
        .iter()
        .find_map(|&(provider, alias, target)| {
            (provider == root && alias == name).then_some(target)
        })
}

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
    let is_default = language_implicit_root_providers(language)
        .iter()
        .any(|root| match root {
            JvmImplicitRootProvider::Package(name) => *name == provider,
            JvmImplicitRootProvider::ScalaPredef => provider == "scala.Predef",
        });
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

/// Compiler and language-defined roots whose member names are complete.
/// Java Object retains its separate JLS method authority.
pub fn source_language_root_member_inventory(owner: &str) -> Option<&'static [IntrinsicMember]> {
    SOURCE_LANGUAGE_ROOTS
        .iter()
        .any(|(_, root)| *root == owner)
        .then(|| root_member_inventory(owner))
        .flatten()
}

// These source-language roots have closed hierarchies as well as closed member
// inventories. Java Object retains its existing producer obligation and ordinals.
const JVM_OBJECT_ROOT: &str = "java.lang.Object";

const SOURCE_LANGUAGE_ROOTS: &[(Language, &str)] = &[
    (Language::Kotlin, "kotlin.Any"),
    (Language::Kotlin, "kotlin.Annotation"),
    (Language::Scala, "scala.Any"),
    (Language::Scala, "scala.AnyRef"),
];

const IMPLICIT_SUPERCLASS_ROOTS: &[(Language, &str)] = &[
    (Language::Java, JVM_OBJECT_ROOT),
    (Language::Kotlin, "kotlin.Any"),
    (Language::Scala, "scala.AnyRef"),
];

/// The closed parent named by each JVM producer's ImplicitSuperclass fact.
pub fn implicit_superclass_root(language: Language) -> Option<&'static str> {
    IMPLICIT_SUPERCLASS_ROOTS
        .iter()
        .find_map(|&(candidate, root)| (candidate == language).then_some(root))
        .inspect(|root| assert_eq!(intrinsic_root_owner(root), Some(*root)))
}

/// Canonical owner for a closed source-language root or the shared JVM Object.
/// Hierarchy projections use this same set as the language-root inventories.
pub fn intrinsic_root_owner(owner: &str) -> Option<&'static str> {
    SOURCE_LANGUAGE_ROOTS
        .iter()
        .map(|(_, name)| *name)
        .chain(std::iter::once(JVM_OBJECT_ROOT))
        .find(|name| *name == owner)
}

// Compiler declarations are positive Type authority, separate from inventories
// that merely certify name absence in an implicit provider.
const COMPILER_ROOT_OWNERS: &[(Language, &str, &str, &str)] = &[
    (Language::Scala, "scala", "Any", "scala.Any"),
    (Language::Scala, "scala", "AnyRef", "scala.AnyRef"),
];

/// Return the intrinsic owner FQN of a compiler-synthesized Type declaration.
pub fn compiler_root_owner(language: Language, package: &str, name: &str) -> Option<&'static str> {
    COMPILER_ROOT_OWNERS
        .iter()
        .find_map(|&(lang, pkg, member, owner)| {
            (language == lang && package == pkg && name == member).then_some(owner)
        })
}

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
        || (owner == JVM_OBJECT_ROOT
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
pub use brokk_bifrost_core::analyzer::capabilities::PlatformInventoryMethod as JvmImplicitInterfaceMethod;

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

// JLS 4.3.2 and 8.4.8: Object's final methods cannot be overridden.
// JLS 8.9.3 and 8.10.3 fix Enum's and Record's own overridable sets.
// These sets are fixed across platform releases, independent of the selected JDK.
const JAVA_OBJECT_OVERRIDABLE_METHODS: [JvmImplicitInterfaceMethod; 5] = [
    JAVA_OBJECT_METHODS[1],
    JAVA_OBJECT_METHODS[2],
    JAVA_OBJECT_METHODS[3],
    JAVA_OBJECT_METHODS[9],
    JAVA_OBJECT_METHODS[10],
];
const JAVA_ENUM_OVERRIDABLE_METHODS: [JvmImplicitInterfaceMethod; 1] = [JAVA_OBJECT_METHODS[3]];
const JAVA_RECORD_OVERRIDABLE_METHODS: [JvmImplicitInterfaceMethod; 5] =
    JAVA_OBJECT_OVERRIDABLE_METHODS;

// Keep the index-selected inventories tied to their specified method names.
const _: () = {
    const fn same_name(actual: &str, expected: &str) -> bool {
        let actual = actual.as_bytes();
        let expected = expected.as_bytes();
        if actual.len() != expected.len() {
            return false;
        }
        let mut index = 0;
        while index < actual.len() {
            if actual[index] != expected[index] {
                return false;
            }
            index += 1;
        }
        true
    }
    let expected = ["hashCode", "equals", "toString", "clone", "finalize"];
    let mut index = 0;
    while index < expected.len() {
        assert!(same_name(
            JAVA_OBJECT_OVERRIDABLE_METHODS[index].name,
            expected[index]
        ));
        assert!(same_name(
            JAVA_RECORD_OVERRIDABLE_METHODS[index].name,
            expected[index]
        ));
        index += 1;
    }
    assert!(same_name(JAVA_ENUM_OVERRIDABLE_METHODS[0].name, "toString"));
};

/// Overridable platform member inventories for a source member-family walk.
/// Interfaces use `implicit_interface_members` (JLS 9.2) instead.
pub fn overridable_method_inventory(owner: &str) -> Option<&'static [JvmImplicitInterfaceMethod]> {
    match owner {
        "java.lang.Object" => Some(&JAVA_OBJECT_OVERRIDABLE_METHODS),
        "java.lang.Enum" => Some(&JAVA_ENUM_OVERRIDABLE_METHODS),
        "java.lang.Record" => Some(&JAVA_RECORD_OVERRIDABLE_METHODS),
        _ => None,
    }
}

/// A method inventory fixed by the platform language specification. It proves
/// enumeration only; actual selected declarations still supply signatures.
pub fn specified_method_inventory(owner: &str) -> Option<&'static [JvmImplicitInterfaceMethod]> {
    match owner {
        "java.lang.Object" => Some(&JAVA_OBJECT_METHODS),
        _ => None,
    }
}

#[test]
fn implicit_root_groups_preserve_ambiguity_and_shared_targets() {
    use ImplicitRootLookup::{Answer, Open};
    assert_eq!(
        ordered_implicit_root(Language::Kotlin, "String", |root| {
            (root != "java.lang").then_some("shared.Target")
        }),
        Answer("shared.Target")
    );
    assert_eq!(
        ordered_implicit_root(Language::Kotlin, "String", |root| {
            (root == "kotlin.collections").then_some("shared.Target")
        }),
        Open
    );
    assert_eq!(
        ordered_implicit_root(Language::Kotlin, "String", |root| {
            matches!(root, "kotlin" | "kotlin.collections").then_some(root)
        }),
        Open
    );
    assert_eq!(
        ordered_implicit_root(Language::Kotlin, "String", |root| {
            (root == "java.lang").then_some("java.lang.String")
        }),
        Open
    );
}
