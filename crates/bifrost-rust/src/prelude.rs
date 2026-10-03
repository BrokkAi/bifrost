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

    /// The documented edition preludes differ only by the names each edition
    /// added: `rust_2018` equals `rust_2015` (the v1 prelude), `rust_2021`
    /// adds `TryFrom`, `TryInto` and `FromIterator`, and `rust_2024` adds
    /// `Future` and `IntoFuture`. No edition removes a name.
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

    /// std's prelude is core's plus the allocator names `Box`, `String`,
    /// `ToOwned`, `ToString` and `Vec`, in every edition.
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

    /// Value-namespace names are the variants and functions the prelude
    /// re-exports; every other name is a type or trait.
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

    #[test]
    fn itemless_standard_marker_traits_are_distinct_from_clone() {
        let mut entries = RUST_MARKER_TRAITS_WITHOUT_ASSOCIATED_ITEMS
            .iter()
            .map(|entry| (entry.name, entry.module, entry.in_prelude))
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
}
