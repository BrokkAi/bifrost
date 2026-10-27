//! The names the implicit std and core preludes inject, by edition.
//!
//! rustc makes every name of the crate's prelude visible in every module at
//! the lowest precedence: a lexical binding of the same name wins, and a name
//! no scope binds falls through to it. A crate uses `std::prelude::rust_20xx`
//! for its edition, `core::prelude::rust_20xx` under `#![no_std]`, and no
//! prelude under `#![no_core]`. Bifrost indexes neither std nor core, so such
//! a name is an open boundary on the unindexed crate, never a proved absence.
//!
//! The table covers the type and value namespaces. Prelude macros and derive
//! macros are the macro namespace, which this table does not model.

/// Which crate supplies a crate's implicit prelude.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RustPreludeCrate {
    Std,
    Core,
}

impl RustPreludeCrate {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Std => "std",
            Self::Core => "core",
        }
    }
}

/// The namespace a prelude name occupies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RustPreludeNamespace {
    Type,
    Value,
}

/// A Rust edition, in the order editions were introduced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RustEdition {
    E2015,
    E2018,
    E2021,
    E2024,
}

impl RustEdition {
    /// The edition a crate row names (`2015`, `2018`, `2021`, `2024`).
    pub fn from_crate_row(edition: &str) -> Option<Self> {
        match edition {
            "2015" => Some(Self::E2015),
            "2018" => Some(Self::E2018),
            "2021" => Some(Self::E2021),
            "2024" => Some(Self::E2024),
            _ => None,
        }
    }

    /// The prelude module's name for this edition (`rust_2021`).
    pub const fn prelude_module(self) -> &'static str {
        match self {
            Self::E2015 => "rust_2015",
            Self::E2018 => "rust_2018",
            Self::E2021 => "rust_2021",
            Self::E2024 => "rust_2024",
        }
    }
}

/// One name a prelude injects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RustPreludeName {
    pub name: &'static str,
    pub namespace: RustPreludeNamespace,
    /// `true` when only std's prelude has it (core has no allocator types).
    pub std_only: bool,
    /// The first edition whose prelude injects it.
    pub since: RustEdition,
}

const fn name(
    name: &'static str,
    namespace: RustPreludeNamespace,
    std_only: bool,
    since: RustEdition,
) -> RustPreludeName {
    RustPreludeName {
        name,
        namespace,
        std_only,
        since,
    }
}

use RustEdition::{E2015, E2021, E2024};
use RustPreludeNamespace::{Type, Value};

/// Every prelude name of every edition, std and core, type and value.
pub const RUST_PRELUDE_NAMES: &[RustPreludeName] = &[
    // core::marker
    name("Copy", Type, false, E2015),
    name("Send", Type, false, E2015),
    name("Sized", Type, false, E2015),
    name("Sync", Type, false, E2015),
    name("Unpin", Type, false, E2015),
    // core::ops
    name("Drop", Type, false, E2015),
    name("Fn", Type, false, E2015),
    name("FnMut", Type, false, E2015),
    name("FnOnce", Type, false, E2015),
    name("AsyncFn", Type, false, E2015),
    name("AsyncFnMut", Type, false, E2015),
    name("AsyncFnOnce", Type, false, E2015),
    // core::mem
    name("drop", Value, false, E2015),
    name("align_of", Value, false, E2015),
    name("align_of_val", Value, false, E2015),
    name("size_of", Value, false, E2015),
    name("size_of_val", Value, false, E2015),
    // core::clone, core::cmp, core::convert, core::default
    name("Clone", Type, false, E2015),
    name("Eq", Type, false, E2015),
    name("Ord", Type, false, E2015),
    name("PartialEq", Type, false, E2015),
    name("PartialOrd", Type, false, E2015),
    name("AsMut", Type, false, E2015),
    name("AsRef", Type, false, E2015),
    name("From", Type, false, E2015),
    name("Into", Type, false, E2015),
    name("Default", Type, false, E2015),
    // core::iter
    name("DoubleEndedIterator", Type, false, E2015),
    name("ExactSizeIterator", Type, false, E2015),
    name("Extend", Type, false, E2015),
    name("IntoIterator", Type, false, E2015),
    name("Iterator", Type, false, E2015),
    // core::option, core::result
    name("Option", Type, false, E2015),
    name("Some", Value, false, E2015),
    name("None", Value, false, E2015),
    name("Result", Type, false, E2015),
    name("Ok", Value, false, E2015),
    name("Err", Value, false, E2015),
    // std only: alloc's boxed, borrow, string and vec
    name("Box", Type, true, E2015),
    name("ToOwned", Type, true, E2015),
    name("String", Type, true, E2015),
    name("ToString", Type, true, E2015),
    name("Vec", Type, true, E2015),
    // rust_2021
    name("TryFrom", Type, false, E2021),
    name("TryInto", Type, false, E2021),
    name("FromIterator", Type, false, E2021),
    // rust_2024
    name("Future", Type, false, E2024),
    name("IntoFuture", Type, false, E2024),
];

/// The canonical module of a trait injected by a standard prelude. This is
/// language-owned name routing, not evidence that a source name resolves to
/// the trait: callers must first prove the selected prelude binding.
pub fn rust_prelude_trait_module(name: &str) -> Option<&'static str> {
    match name {
        "Clone" => Some("clone"),
        "Copy" | "Send" | "Sized" | "Sync" | "Unpin" => Some("marker"),
        "Drop" | "Fn" | "FnMut" | "FnOnce" | "AsyncFn" | "AsyncFnMut" | "AsyncFnOnce" => {
            Some("ops")
        }
        "Eq" | "Ord" | "PartialEq" | "PartialOrd" => Some("cmp"),
        "AsMut" | "AsRef" | "From" | "Into" | "TryFrom" | "TryInto" => Some("convert"),
        "Default" => Some("default"),
        "DoubleEndedIterator"
        | "ExactSizeIterator"
        | "Extend"
        | "IntoIterator"
        | "Iterator"
        | "FromIterator" => Some("iter"),
        "ToOwned" => Some("borrow"),
        "ToString" => Some("string"),
        "Future" | "IntoFuture" => Some("future"),
        _ => None,
    }
}

/// A `core`/`std` marker trait whose own surface declares no associated items.
/// The standard crate path is `core::<module>::<name>` or its `std` re-export.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RustMarkerTraitWithoutAssociatedItems {
    pub name: &'static str,
    pub module: &'static str,
    /// Whether this trait is also injected by the implicit prelude.
    pub in_prelude: bool,
}

/// Standard marker traits with no associated items of their own.
///
/// `Copy` is a marker; the associated items belong to `Clone`, a separate
/// trait. The prelude flag records only the language's implicit imports. A
/// caller must still establish that a reference resolves to this standard
/// trait through the selected crate's prelude or a structured standard-crate
/// route before using the itemless-surface fact.
pub const RUST_MARKER_TRAITS_WITHOUT_ASSOCIATED_ITEMS: &[RustMarkerTraitWithoutAssociatedItems] = &[
    RustMarkerTraitWithoutAssociatedItems {
        name: "Copy",
        module: "marker",
        in_prelude: true,
    },
    RustMarkerTraitWithoutAssociatedItems {
        name: "Send",
        module: "marker",
        in_prelude: true,
    },
    RustMarkerTraitWithoutAssociatedItems {
        name: "Sized",
        module: "marker",
        in_prelude: true,
    },
    RustMarkerTraitWithoutAssociatedItems {
        name: "Sync",
        module: "marker",
        in_prelude: true,
    },
    RustMarkerTraitWithoutAssociatedItems {
        name: "Unpin",
        module: "marker",
        in_prelude: true,
    },
    RustMarkerTraitWithoutAssociatedItems {
        name: "UnwindSafe",
        module: "panic",
        in_prelude: false,
    },
    RustMarkerTraitWithoutAssociatedItems {
        name: "RefUnwindSafe",
        module: "panic",
        in_prelude: false,
    },
];

/// The standard marker-trait fact for one name, if any.
///
/// This table lookup does not resolve the spelling. Callers may use it only
/// after the type reference's selected resolution proves a `core`/`std`
/// identity; a same-spelled workspace trait is a different item.
pub fn rust_marker_trait_without_associated_items(
    name: &str,
) -> Option<&'static RustMarkerTraitWithoutAssociatedItems> {
    RUST_MARKER_TRAITS_WITHOUT_ASSOCIATED_ITEMS
        .iter()
        .find(|marker| marker.name == name)
}

/// What dropping a value of a reviewed standard type can execute (#3757).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RustStdDropGlue {
    /// The destructor only releases memory the value owns. It runs no user
    /// code and moves no value anywhere the program can observe.
    OwnedMemoryOnly,
    /// The destructor drops the values of its type arguments, then releases
    /// memory the value owns. It runs user code only through those values.
    TypeArguments,
}

/// A reviewed fact about one prelude type of the standard library (#3757).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RustStdTypeFact {
    /// The prelude type name.
    pub name: &'static str,
    /// The type's canonical path in `std`, outermost segment first.
    pub path: &'static [&'static str],
    /// How many type arguments the written type carries.
    pub type_arguments: usize,
    pub drop_glue: RustStdDropGlue,
}

/// The reviewed standard prelude types whose destructors run no user code of
/// their own.
///
/// This table is the interim home of these facts. The follow-up is a
/// drop-glue fact in the semantic-model declaration schema, carried by a
/// regenerated std pack. A type that is not listed here stays unproven.
pub const RUST_STD_TYPE_FACTS: &[RustStdTypeFact] = &[
    RustStdTypeFact {
        name: "String",
        path: &["std", "string", "String"],
        type_arguments: 0,
        drop_glue: RustStdDropGlue::OwnedMemoryOnly,
    },
    RustStdTypeFact {
        name: "Option",
        path: &["std", "option", "Option"],
        type_arguments: 1,
        drop_glue: RustStdDropGlue::TypeArguments,
    },
    RustStdTypeFact {
        name: "Result",
        path: &["std", "result", "Result"],
        type_arguments: 2,
        drop_glue: RustStdDropGlue::TypeArguments,
    },
    RustStdTypeFact {
        name: "Vec",
        path: &["std", "vec", "Vec"],
        type_arguments: 1,
        drop_glue: RustStdDropGlue::TypeArguments,
    },
    RustStdTypeFact {
        name: "Box",
        path: &["std", "boxed", "Box"],
        type_arguments: 1,
        drop_glue: RustStdDropGlue::TypeArguments,
    },
];

/// The reviewed fact for one prelude type name, if any.
///
/// Like [`rust_marker_trait_without_associated_items`], this lookup does not
/// resolve the spelling. Callers may use it only after the type reference's
/// selected resolution proves the `std` or `core` prelude item.
pub fn rust_std_type_fact(name: &str) -> Option<&'static RustStdTypeFact> {
    RUST_STD_TYPE_FACTS.iter().find(|fact| fact.name == name)
}

/// The value a reviewed standard operation produces (#3757).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RustStdValue {
    /// A value of the named [`RUST_STD_TYPE_FACTS`] type.
    StdType(&'static str),
    /// A value of the named primitive type.
    Primitive(&'static str),
}

/// A receiver type whose standard methods the reviewed facts describe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RustStdReceiver {
    /// `str`, reached from a string literal or a `&str` binding through
    /// built-in reference dereferences only.
    Str,
    /// `String`, whose inherent methods may use the built-in `str`
    /// dereference but retain the owned receiver's standard identity.
    String,
}

impl RustStdReceiver {
    /// The canonical owner path the receiver's methods are published under.
    /// `std::primitive::str` is the standard path that names the primitive.
    pub const fn owner_path(self) -> &'static [&'static str] {
        match self {
            Self::Str => &["std", "primitive", "str"],
            Self::String => &["std", "string", "String"],
        }
    }
}

/// The result type of one standard method on a reviewed receiver type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RustStdMethodFact {
    pub receiver: RustStdReceiver,
    pub method: &'static str,
    /// The written argument count, excluding the receiver.
    pub arity: usize,
    pub result: RustStdValue,
}

/// Reviewed standard method result types.
///
/// `str` has no inherent `to_owned`; the call reaches `<str as
/// ToOwned>::to_owned`, whose `Owned` type is `String`. A method that is not
/// listed here leaves its result type unproven. The taint transfer of each
/// method is not a type fact: it ships as a reviewed procedure summary.
pub const RUST_STD_METHOD_FACTS: &[RustStdMethodFact] = &[
    RustStdMethodFact {
        receiver: RustStdReceiver::Str,
        method: "to_owned",
        arity: 0,
        result: RustStdValue::StdType("String"),
    },
    RustStdMethodFact {
        receiver: RustStdReceiver::Str,
        method: "len",
        arity: 0,
        result: RustStdValue::Primitive("usize"),
    },
    RustStdMethodFact {
        receiver: RustStdReceiver::String,
        method: "len",
        arity: 0,
        result: RustStdValue::Primitive("usize"),
    },
];

/// The reviewed result type of `method` with `arity` written arguments on a
/// receiver of type `receiver`, if any.
pub fn rust_std_method_fact(
    receiver: RustStdReceiver,
    method: &str,
    arity: usize,
) -> Option<&'static RustStdMethodFact> {
    RUST_STD_METHOD_FACTS
        .iter()
        .find(|fact| fact.receiver == receiver && fact.method == method && fact.arity == arity)
}

/// The result type of one associated function of a reviewed std prelude
/// type, called through the type's path, such as `String::new()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RustStdAssociatedFact {
    /// The [`RUST_STD_TYPE_FACTS`] type the function is associated with.
    pub owner: &'static str,
    pub function: &'static str,
    /// The written argument count.
    pub arity: usize,
    pub result: RustStdValue,
}

/// Reviewed associated-function result types. A function that is not listed
/// leaves its result type unproven.
pub const RUST_STD_ASSOCIATED_FACTS: &[RustStdAssociatedFact] = &[RustStdAssociatedFact {
    owner: "String",
    function: "new",
    arity: 0,
    result: RustStdValue::StdType("String"),
}];

/// The reviewed result type of `owner::function` with `arity` written
/// arguments, if any. Callers may use it only after the owner's selected
/// resolution proves the `std` prelude type.
pub fn rust_std_associated_fact(
    owner: &str,
    function: &str,
    arity: usize,
) -> Option<&'static RustStdAssociatedFact> {
    RUST_STD_ASSOCIATED_FACTS
        .iter()
        .find(|fact| fact.owner == owner && fact.function == function && fact.arity == arity)
}

/// `String + &str` is `<String as Add<&str>>::add`, whose output is
/// `String`. It is the only standard `Add` implementation with a `String`
/// left operand, and the right operand must be proven to be `&str`.
pub const RUST_STD_STRING_ADD_STR: RustStdValue = RustStdValue::StdType("String");

/// A prelude value that constructs a variant of a reviewed standard type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RustStdConstructorFact {
    /// The prelude value name.
    pub name: &'static str,
    /// The [`RUST_STD_TYPE_FACTS`] type it constructs.
    pub constructs: &'static str,
    /// The written argument count.
    pub arity: usize,
}

/// `Ok(x)` and `Err(x)` construct a `Result` and `Some(x)` an `Option`. The
/// constructed variant holds its argument; the transfer itself ships as a
/// reviewed procedure summary on the constructor's canonical identity.
pub const RUST_STD_CONSTRUCTOR_FACTS: &[RustStdConstructorFact] = &[
    RustStdConstructorFact {
        name: "Ok",
        constructs: "Result",
        arity: 1,
    },
    RustStdConstructorFact {
        name: "Err",
        constructs: "Result",
        arity: 1,
    },
    RustStdConstructorFact {
        name: "Some",
        constructs: "Option",
        arity: 1,
    },
];

/// The reviewed fact for one prelude value constructor, if any. Callers may
/// use it only after the callee's selected resolution proves the `std` or
/// `core` prelude value.
pub fn rust_std_constructor_fact(name: &str) -> Option<&'static RustStdConstructorFact> {
    RUST_STD_CONSTRUCTOR_FACTS
        .iter()
        .find(|fact| fact.name == name)
}

/// Whether any edition's std or core prelude injects `name` into
/// `namespace`. A producer that does not know the crate asks this; the crate
/// context narrows it with [`rust_prelude_name`].
pub fn rust_prelude_candidate(name: &str, namespace: RustPreludeNamespace) -> bool {
    RUST_PRELUDE_NAMES
        .iter()
        .any(|entry| entry.name == name && entry.namespace == namespace)
}

/// The prelude entry `name` resolves to in a crate of `edition` whose prelude
/// comes from `prelude`, if that prelude injects it.
pub fn rust_prelude_name(
    name: &str,
    namespace: RustPreludeNamespace,
    edition: RustEdition,
    prelude: RustPreludeCrate,
) -> Option<&'static RustPreludeName> {
    RUST_PRELUDE_NAMES.iter().find(|entry| {
        entry.name == name
            && entry.namespace == namespace
            && entry.since <= edition
            && !(entry.std_only && prelude == RustPreludeCrate::Core)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_test_macros::hardwon;

    fn names(edition: RustEdition, prelude: RustPreludeCrate) -> Vec<&'static str> {
        let mut names = RUST_PRELUDE_NAMES
            .iter()
            .filter(|entry| {
                rust_prelude_name(entry.name, entry.namespace, edition, prelude).is_some()
            })
            .map(|entry| entry.name)
            .collect::<Vec<_>>();
        names.sort_unstable();
        names
    }

    fn delta(from: &[&'static str], to: &[&'static str]) -> Vec<&'static str> {
        to.iter()
            .copied()
            .filter(|name| !from.contains(name))
            .collect()
    }

    #[test]
    #[hardwon(
        "#3746: standard marker traits were treated as traits with associated member surfaces"
    )]
    fn itemless_standard_marker_traits_are_distinct_from_clone() {
        let mut entries = RUST_MARKER_TRAITS_WITHOUT_ASSOCIATED_ITEMS
            .iter()
            .map(|entry| {
                // Registry entries must round-trip through the lookup API,
                // including explicit panic routes outside the prelude.
                let selected = rust_marker_trait_without_associated_items(entry.name)
                    .expect("registered standard marker is selectable");
                (selected.name, selected.module, selected.in_prelude)
            })
            .collect::<Vec<_>>();
        entries.sort_unstable();
        assert_eq!(
            entries,
            vec![
                ("Copy", "marker", true),
                ("RefUnwindSafe", "panic", false),
                ("Send", "marker", true),
                ("Sized", "marker", true),
                ("Sync", "marker", true),
                ("Unpin", "marker", true),
                ("UnwindSafe", "panic", false),
            ]
        );
        assert!(rust_marker_trait_without_associated_items("Clone").is_none());
    }

    #[test]
    fn edition_preludes_differ_by_the_documented_additions() {
        for prelude in [RustPreludeCrate::Std, RustPreludeCrate::Core] {
            let e2015 = names(RustEdition::E2015, prelude);
            let e2018 = names(RustEdition::E2018, prelude);
            let e2021 = names(RustEdition::E2021, prelude);
            let e2024 = names(RustEdition::E2024, prelude);
            assert_eq!(e2015, e2018);
            let mut added = delta(&e2018, &e2021);
            added.sort_unstable();
            assert_eq!(added, vec!["FromIterator", "TryFrom", "TryInto"]);
            let mut added = delta(&e2021, &e2024);
            added.sort_unstable();
            assert_eq!(added, vec!["Future", "IntoFuture"]);
            for (earlier, later) in [(&e2015, &e2021), (&e2021, &e2024)] {
                assert!(
                    delta(later, earlier).is_empty(),
                    "{prelude:?} removes a name"
                );
            }
        }
    }

    #[test]
    fn std_adds_exactly_the_allocator_names_to_core() {
        for edition in [
            RustEdition::E2015,
            RustEdition::E2018,
            RustEdition::E2021,
            RustEdition::E2024,
        ] {
            let std = names(edition, RustPreludeCrate::Std);
            let core = names(edition, RustPreludeCrate::Core);
            let mut added = delta(&core, &std);
            added.sort_unstable();
            assert_eq!(added, vec!["Box", "String", "ToOwned", "ToString", "Vec"]);
            assert!(delta(&std, &core).is_empty());
        }
    }

    #[test]
    fn the_value_namespace_holds_the_variants_and_functions() {
        let mut values = RUST_PRELUDE_NAMES
            .iter()
            .filter(|entry| entry.namespace == RustPreludeNamespace::Value)
            .map(|entry| entry.name)
            .collect::<Vec<_>>();
        values.sort_unstable();
        assert_eq!(
            values,
            vec![
                "Err",
                "None",
                "Ok",
                "Some",
                "align_of",
                "align_of_val",
                "drop",
                "size_of",
                "size_of_val"
            ]
        );
    }
}
