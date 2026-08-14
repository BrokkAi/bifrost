//! The occurrence-role vocabulary: what the parser says an identifier token
//! *is* at one exact position (issue #1473).
//!
//! This is a separate axis from [`super::kinds::Role`]. A `Role` names a child
//! position of a Call/Assignment/Import fact (callee, receiver, args, ...) and
//! is scoped to its parent's kind. An [`OccurrenceRole`] classifies a single
//! identifier-bearing node on its own terms — declaration name, binder, type
//! operand, map key — and is what the semantic layer must agree with.
//!
//! Support is declared, never assumed: [`OccurrenceRoleSupport`] is a total
//! table sized by [`OccurrenceRole::COUNT`], so an adapter that says nothing
//! says `Unsupported` for everything, and a query that depends on a role the
//! adapter cannot model becomes incomplete rather than silently empty.

use super::kinds::NormalizedKind;
use serde::{Deserialize, Serialize};
use std::fmt;

macro_rules! occurrence_roles {
    ($($variant:ident => $label:literal: $class:ident, $description:literal,)+) => {
        /// What one identifier-bearing token is, syntactically.
        #[repr(u8)]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(rename_all = "snake_case")]
        pub enum OccurrenceRole {
            $($variant,)+
        }

        /// Every occurrence role, in declaration order, for iteration in
        /// validation, docs and tests. Also sizes [`OccurrenceRoleSupport`].
        pub const ALL_OCCURRENCE_ROLES: &[OccurrenceRole] = &[
            $(OccurrenceRole::$variant,)+
        ];

        impl OccurrenceRole {
            pub const COUNT: usize = ALL_OCCURRENCE_ROLES.len();

            /// Stable slot in the total support table. Matches declaration order.
            pub const fn index(self) -> usize {
                self as usize
            }

            /// The snake_case label used in query JSON and rendered output,
            /// kept in lock-step with the serde representation (asserted by test).
            pub const fn label(self) -> &'static str {
                match self {
                    $(OccurrenceRole::$variant => $label,)+
                }
            }

            pub fn from_label(label: &str) -> Option<OccurrenceRole> {
                ALL_OCCURRENCE_ROLES
                    .iter()
                    .copied()
                    .find(|role| role.label() == label)
            }

            pub const fn signature(self) -> &'static str {
                self.label()
            }

            pub const fn description(self) -> &'static str {
                match self {
                    $(OccurrenceRole::$variant => $description,)+
                }
            }

            /// The occurrence class this role always belongs to.
            ///
            /// The mapping is total and a role never straddles classes. Where
            /// one syntactic shape can be either (JS shorthand is a binder in a
            /// pattern and a read in an expression), the adapter must emit the
            /// role that matches the concrete node, and the class follows.
            pub const fn class(self) -> OccurrenceClass {
                match self {
                    $(OccurrenceRole::$variant => OccurrenceClass::$class,)+
                }
            }
        }
    };
}

occurrence_roles! {
    DeclarationName => "declaration_name": Declaration,
        "The name token of a declaration head.",
    Binder => "binder": Binding,
        "A pure binding introduction: parameter, local, pattern binder, loop variable, catch variable.",
    LabelOrKey => "label_or_key": NonReference,
        "A label, keyword-argument name, or keyed-field/map-key position.",
    TypeOperand => "type_operand": Reference,
        "An identifier consumed as a type: annotations, ascriptions, generic arguments, extends/implements operands.",
    PathSegment => "path_segment": Reference,
        "A non-terminal segment of a qualified path or scoped name.",
    ImportAlias => "import_alias": NonReference,
        "The locally introduced alias name in an import or export.",
    ImportTarget => "import_target": Reference,
        "The imported or exported source name.",
    ReceiverPosition => "receiver_position": Reference,
        "The receiver of a member access or call.",
    MemberPosition => "member_position": Reference,
        "The member name in a member access or call.",
    PatternPosition => "pattern_position": Reference,
        "A non-binding identifier inside a pattern, such as a matched constant or struct-pattern field name.",
    GeneratedSource => "generated_source": NonReference,
        "A token whose presence generates declarations elsewhere, such as property macros or accessor-generating fields.",
    ValueReference => "value_reference": Reference,
        "A plain read or write of a value in expression position.",
}

impl fmt::Display for OccurrenceRole {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.label())
    }
}

macro_rules! labelled_enum {
    ($(#[$meta:meta])* $name:ident, $all:ident { $($variant:ident => $label:literal,)+ }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(rename_all = "snake_case")]
        pub enum $name {
            $($variant,)+
        }

        pub const $all: &[$name] = &[$($name::$variant,)+];

        impl $name {
            pub const fn label(self) -> &'static str {
                match self {
                    $($name::$variant => $label,)+
                }
            }

            pub fn from_label(label: &str) -> Option<$name> {
                $all.iter().copied().find(|value| value.label() == label)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.label())
            }
        }
    };
}

// The sibling resolution registry (issue #1474) declares its vocabularies the
// same way, so the macro is shared rather than copied.
pub(crate) use labelled_enum;

labelled_enum! {
    /// The coarse partition every occurrence row carries, derived from its role.
    OccurrenceClass, ALL_OCCURRENCE_CLASSES {
        Declaration => "declaration",
        Reference => "reference",
        Binding => "binding",
        NonReference => "non_reference",
    }
}

labelled_enum! {
    /// The naming space an occurrence resolves in. Promoted from the semantics
    /// of the Rust resolver's private `RustSymbolNamespace`; the Rust-internal
    /// type stays where it is until the resolver work in #1474/#1475.
    Namespace, ALL_NAMESPACES {
        Type => "type",
        Value => "value",
        Module => "module",
        Macro => "macro",
        Label => "label",
    }
}

/// Whether an adapter classifies a given occurrence role precisely enough for
/// queries and assertions to depend on it.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OccurrenceSupport {
    Supported,
    #[default]
    Unsupported,
}

impl OccurrenceSupport {
    pub const fn is_supported(self) -> bool {
        matches!(self, Self::Supported)
    }
}

/// A total occurrence-role support table. Every role an adapter does not name
/// explicitly is explicitly unsupported, so a new role cannot silently inherit
/// "supported" from an adapter that has never seen it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OccurrenceRoleSupport {
    support: [OccurrenceSupport; OccurrenceRole::COUNT],
}

impl Default for OccurrenceRoleSupport {
    fn default() -> Self {
        Self::NONE
    }
}

impl OccurrenceRoleSupport {
    /// The all-unsupported table. Adapters build their own by chaining
    /// [`OccurrenceRoleSupport::supported`] off this in a `static` initializer;
    /// the chain is `const` precisely so no adapter needs lazy storage to
    /// declare a table the spec trait hands out by reference.
    pub const NONE: Self = Self {
        support: [OccurrenceSupport::Unsupported; OccurrenceRole::COUNT],
    };

    pub const fn supported(mut self, role: OccurrenceRole) -> Self {
        self.support[role.index()] = OccurrenceSupport::Supported;
        self
    }

    pub const fn unsupported(mut self, role: OccurrenceRole) -> Self {
        self.support[role.index()] = OccurrenceSupport::Unsupported;
        self
    }

    pub const fn support(&self, role: OccurrenceRole) -> OccurrenceSupport {
        self.support[role.index()]
    }

    pub const fn is_supported(&self, role: OccurrenceRole) -> bool {
        self.support(role).is_supported()
    }

    pub fn is_empty(&self) -> bool {
        self.support.iter().all(|support| !support.is_supported())
    }

    /// Iterate in the stable order declared by [`ALL_OCCURRENCE_ROLES`].
    pub fn iter(&self) -> impl ExactSizeIterator<Item = (OccurrenceRole, OccurrenceSupport)> + '_ {
        ALL_OCCURRENCE_ROLES
            .iter()
            .map(|&role| (role, self.support(role)))
    }
}

/// The table every adapter that has not yet learned occurrence roles returns.
pub static NO_OCCURRENCE_ROLE_SUPPORT: OccurrenceRoleSupport = OccurrenceRoleSupport::NONE;

/// The namespace an occurrence role lands in, given the normalized kind of the
/// fact this token *declares* -- that is, the enclosing fact whose own name
/// span is this token (`None` when the token names no fact).
///
/// `None` means "this adapter has not said": the derivation layer omits the
/// row and marks the file incomplete for that role rather than guessing. Only
/// [`OccurrenceRole::PathSegment`] is left open by default, because a scope
/// segment is a module in some grammars (`os.path`, a TypeScript namespace)
/// and either a module or a type in others (`java.util.Map.Entry`,
/// `Option::Some`); an adapter that can tell them apart overrides
/// `StructuralSpec::occurrence_namespace`.
pub const fn default_occurrence_namespace(
    role: OccurrenceRole,
    declares: Option<NormalizedKind>,
) -> Option<Namespace> {
    match role {
        OccurrenceRole::TypeOperand => Some(Namespace::Type),
        OccurrenceRole::LabelOrKey => Some(Namespace::Label),
        OccurrenceRole::PathSegment => None,
        // A declaration name inherits the namespace of the thing it declares.
        // `declares` is deliberately not "nearest enclosing fact": a Rust
        // struct field's name sits under the `struct_item` fact but names the
        // field, not the struct, and inheriting the container's kind would put
        // a value in the type namespace.
        OccurrenceRole::DeclarationName => match declares {
            Some(NormalizedKind::Class) => Some(Namespace::Type),
            _ => Some(Namespace::Value),
        },
        _ => Some(Namespace::Value),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn occurrence_role_labels_are_unique_and_round_trip_through_serde() {
        let mut labels = HashSet::new();
        for &role in ALL_OCCURRENCE_ROLES {
            assert!(labels.insert(role.label()), "duplicate label for {role:?}");
            assert_eq!(OccurrenceRole::from_label(role.label()), Some(role));

            let json = serde_json::to_value(role).expect("serialize occurrence role");
            assert_eq!(
                json,
                serde_json::Value::String(role.label().to_owned()),
                "serde label diverges from label() for {role:?}"
            );
            let back: OccurrenceRole = serde_json::from_value(json).expect("deserialize role");
            assert_eq!(back, role);
        }
        assert!(OccurrenceRole::from_label("not_a_role").is_none());
    }

    #[test]
    fn class_and_namespace_vocabularies_are_unique_and_round_trip() {
        for &class in ALL_OCCURRENCE_CLASSES {
            assert_eq!(OccurrenceClass::from_label(class.label()), Some(class));
            assert_eq!(
                serde_json::to_value(class).expect("serialize class"),
                serde_json::Value::String(class.label().to_owned())
            );
        }
        for &namespace in ALL_NAMESPACES {
            assert_eq!(Namespace::from_label(namespace.label()), Some(namespace));
            assert_eq!(
                serde_json::to_value(namespace).expect("serialize namespace"),
                serde_json::Value::String(namespace.label().to_owned())
            );
        }
    }

    /// The role→class mapping must be a total partition: every class is
    /// reachable and every role lands in exactly one of them.
    #[test]
    fn role_to_class_mapping_is_a_total_partition() {
        let mut covered = HashSet::new();
        let mut partitioned = 0usize;
        for &class in ALL_OCCURRENCE_CLASSES {
            let members = ALL_OCCURRENCE_ROLES
                .iter()
                .filter(|role| role.class() == class)
                .count();
            partitioned += members;
            if members > 0 {
                covered.insert(class);
            }
        }
        assert_eq!(partitioned, ALL_OCCURRENCE_ROLES.len());
        assert_eq!(covered.len(), ALL_OCCURRENCE_CLASSES.len());
        assert_eq!(
            OccurrenceRole::DeclarationName.class(),
            OccurrenceClass::Declaration
        );
        assert_eq!(OccurrenceRole::Binder.class(), OccurrenceClass::Binding);
        assert_eq!(
            OccurrenceRole::ValueReference.class(),
            OccurrenceClass::Reference
        );
        assert_eq!(
            OccurrenceRole::ImportAlias.class(),
            OccurrenceClass::NonReference
        );
    }

    #[test]
    fn indices_are_dense_and_size_the_support_table() {
        assert_eq!(ALL_OCCURRENCE_ROLES.len(), OccurrenceRole::COUNT);
        for (slot, &role) in ALL_OCCURRENCE_ROLES.iter().enumerate() {
            assert_eq!(role.index(), slot);
        }
        assert_eq!(
            OccurrenceRoleSupport::NONE.iter().count(),
            OccurrenceRole::COUNT
        );
    }

    #[test]
    fn support_table_is_total_and_defaults_to_unsupported() {
        let table = OccurrenceRoleSupport::default();
        assert!(table.is_empty());
        for &role in ALL_OCCURRENCE_ROLES {
            assert_eq!(table.support(role), OccurrenceSupport::Unsupported);
        }

        let declared = OccurrenceRoleSupport::NONE
            .supported(OccurrenceRole::DeclarationName)
            .supported(OccurrenceRole::Binder)
            .unsupported(OccurrenceRole::Binder);
        assert!(declared.is_supported(OccurrenceRole::DeclarationName));
        assert!(!declared.is_supported(OccurrenceRole::Binder));
        assert!(!declared.is_supported(OccurrenceRole::GeneratedSource));
        assert!(!declared.is_empty());
        assert!(NO_OCCURRENCE_ROLE_SUPPORT.is_empty());
    }
}
