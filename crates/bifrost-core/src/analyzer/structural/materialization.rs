//! The declaration-materialization vocabulary: where a declaration comes from,
//! what a generation site produces, and what state a declaration is in
//! (issue #1476).
//!
//! Today the analyzers materialize declarations from macro-like constructs
//! (Ruby `attr_accessor`/`alias_method`, C `#define`), from export forms
//! (JavaScript `export default`/`module.exports`), from declaration-only
//! signatures (Python `@overload`), and from parser recovery over broken
//! source — and record none of it. These enums are the typed values that
//! provenance becomes: a [`DeclarationOrigin`] for how a declaration came to
//! exist, a [`GenerationKind`] and [`GenerationInputClass`] for the construct
//! that produced it and whether its inputs were literal, and an [`ExportForm`]
//! for how an export binds.
//!
//! Support is declared, never assumed: [`DeclarationMaterializationSupport`]
//! is a total table sized by [`MaterializationAxis::COUNT`], so an adapter
//! that says nothing says `Unsupported` for every axis, and a query that
//! depends on an axis the adapter cannot model becomes incomplete rather than
//! silently empty. This mirrors [`super::resolution::LexicalEnvironmentSupport`]
//! exactly. Unlike the occurrence and environment tables, the claimed matrix
//! is deliberately non-uniform across languages: the mined bug shapes are
//! per-language by nature (generation is Ruby and C++, exports are JS/TS,
//! declaration-only linkage is Python), so each language claims exactly the
//! axes its producers compute.

use super::occurrences::labelled_enum;
use serde::{Deserialize, Serialize};
use std::fmt;

labelled_enum! {
    /// How a declaration came to exist in the model.
    ///
    /// - `Parsed`: extracted from its own declaration node in a clean parse.
    /// - `Generated`: materialized by a macro-like construct with no
    ///   declaration node of its own (a Ruby `attr_accessor` method, a
    ///   CommonJS export member).
    /// - `Recovered`: reconstructed from a broken parse (an ERROR-node shape
    ///   the C++ analyzer recognizes), so its identity is a recovery claim
    ///   rather than a plain reading of the tree.
    DeclarationOrigin, ALL_DECLARATION_ORIGINS {
        Parsed => "parsed",
        Generated => "generated",
        Recovered => "recovered",
    }
}

labelled_enum! {
    /// Whether a generation site's inputs are literal enough to name the
    /// generated declarations.
    ///
    /// `Dynamic` is the honesty carrier: `attr_accessor name.to_sym`
    /// generates *something*, but no analyzer can say what, so the site is
    /// recorded with an explicitly unknown generated set and every consumer
    /// of that set reports incomplete rather than empty.
    GenerationInputClass, ALL_GENERATION_INPUT_CLASSES {
        Literal => "literal",
        Dynamic => "dynamic",
    }
}

labelled_enum! {
    /// What kind of construct a generation site is.
    ///
    /// - `AccessorMacro`: a member-generating attribute macro
    ///   (`attr_accessor`, `attr_reader`, `attr_writer`).
    /// - `AliasMacro`: an alias-generating call (`alias_method`).
    /// - `PreprocessorDefinition`: a `#define` that materializes a macro unit.
    GenerationKind, ALL_GENERATION_KINDS {
        AccessorMacro => "accessor_macro",
        AliasMacro => "alias_macro",
        PreprocessorDefinition => "preprocessor_definition",
    }
}

labelled_enum! {
    /// How an export declaration binds.
    ///
    /// - `Named`: `export const x`, `export function f`, a named re-export.
    /// - `DefaultNamed`: `export default function f() {}` — the default
    ///   export carries a usable local name.
    /// - `DefaultAnonymous`: `export default { ... }` or an anonymous
    ///   function/class — a declaration with no declared name of its own.
    /// - `CommonJsRoot`: `module.exports = ...` as the whole export surface.
    /// - `CommonJsMember`: one property of a `module.exports` object literal,
    ///   materialized as its own declaration.
    ExportForm, ALL_EXPORT_FORMS {
        Named => "named",
        DefaultNamed => "default_named",
        DefaultAnonymous => "default_anonymous",
        CommonJsRoot => "common_js_root",
        CommonJsMember => "common_js_member",
    }
}

macro_rules! materialization_axes {
    ($($variant:ident => $label:literal: $description:literal,)+) => {
        /// One independently answerable part of a file's declaration
        /// materialization story. Support is declared per axis so an adapter
        /// that records its generation sites but has no export model reports
        /// exactly that.
        #[repr(u8)]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(rename_all = "snake_case")]
        pub enum MaterializationAxis {
            $($variant,)+
        }

        /// Every axis, in declaration order, for iteration in validation,
        /// docs and tests. Also sizes [`DeclarationMaterializationSupport`].
        pub const ALL_MATERIALIZATION_AXES: &[MaterializationAxis] = &[
            $(MaterializationAxis::$variant,)+
        ];

        impl MaterializationAxis {
            pub const COUNT: usize = ALL_MATERIALIZATION_AXES.len();

            /// Stable slot in the total support table. Matches declaration order.
            pub const fn index(self) -> usize {
                self as usize
            }

            pub const fn label(self) -> &'static str {
                match self {
                    $(MaterializationAxis::$variant => $label,)+
                }
            }

            pub fn from_label(label: &str) -> Option<MaterializationAxis> {
                ALL_MATERIALIZATION_AXES
                    .iter()
                    .copied()
                    .find(|axis| axis.label() == label)
            }

            pub const fn signature(self) -> &'static str {
                self.label()
            }

            pub const fn description(self) -> &'static str {
                match self {
                    $(MaterializationAxis::$variant => $description,)+
                }
            }
        }
    };
}

materialization_axes! {
    DeclarationState => "declaration_state":
        "The origin, declaration-only flag, and configuration gate of each declaration in a file.",
    GenerationSites => "generation_sites":
        "Which constructs in a file materialize declarations, with their kind and input class.",
    GeneratedSets => "generated_sets":
        "The exact set of declarations each literal generation site produces.",
    Exports => "exports":
        "The export declarations of a file, with their form and local target.",
    ImplementationLinkage => "implementation_linkage":
        "The link from a declaration-only signature to the implementation that carries its behavior.",
    ConfigurationGating => "configuration_gating":
        "Which declarations exist only under a preprocessing or build configuration, without deciding which configuration is active.",
}

impl fmt::Display for MaterializationAxis {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.label())
    }
}

/// Whether an adapter answers a given materialization axis precisely enough
/// for queries and assertions to depend on it.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MaterializationSupport {
    Supported,
    #[default]
    Unsupported,
}

impl MaterializationSupport {
    pub const fn is_supported(self) -> bool {
        matches!(self, Self::Supported)
    }
}

/// A total materialization-axis support table. Every axis an adapter does not
/// name explicitly is explicitly unsupported, so a new axis cannot silently
/// inherit "supported" from an adapter that has never seen it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclarationMaterializationSupport {
    support: [MaterializationSupport; MaterializationAxis::COUNT],
}

impl Default for DeclarationMaterializationSupport {
    fn default() -> Self {
        Self::NONE
    }
}

impl DeclarationMaterializationSupport {
    /// The all-unsupported table. Adapters build their own by chaining
    /// [`DeclarationMaterializationSupport::supported`] off this in a `static`
    /// initializer; the chain is `const` precisely so no adapter needs lazy
    /// storage to declare a table the spec trait hands out by reference.
    pub const NONE: Self = Self {
        support: [MaterializationSupport::Unsupported; MaterializationAxis::COUNT],
    };

    pub const fn supported(mut self, axis: MaterializationAxis) -> Self {
        self.support[axis.index()] = MaterializationSupport::Supported;
        self
    }

    pub const fn unsupported(mut self, axis: MaterializationAxis) -> Self {
        self.support[axis.index()] = MaterializationSupport::Unsupported;
        self
    }

    pub const fn support(&self, axis: MaterializationAxis) -> MaterializationSupport {
        self.support[axis.index()]
    }

    pub const fn is_supported(&self, axis: MaterializationAxis) -> bool {
        self.support(axis).is_supported()
    }

    pub fn is_empty(&self) -> bool {
        self.support.iter().all(|support| !support.is_supported())
    }

    /// Iterate in the stable order declared by [`ALL_MATERIALIZATION_AXES`].
    pub fn iter(
        &self,
    ) -> impl ExactSizeIterator<Item = (MaterializationAxis, MaterializationSupport)> + '_ {
        ALL_MATERIALIZATION_AXES
            .iter()
            .map(|&axis| (axis, self.support(axis)))
    }
}

/// The table every adapter that records no materialization provenance returns.
pub static NO_MATERIALIZATION_SUPPORT: DeclarationMaterializationSupport =
    DeclarationMaterializationSupport::NONE;

/// Ruby: literal `attr_accessor`/`attr_reader`/`attr_writer`/`alias_method`
/// calls are generation sites with exact generated sets, and every declared
/// unit can state its origin. Ruby has no export model, no declaration-only
/// signatures, and no preprocessor.
pub static RUBY_MATERIALIZATION_SUPPORT: DeclarationMaterializationSupport =
    DeclarationMaterializationSupport::NONE
        .supported(MaterializationAxis::DeclarationState)
        .supported(MaterializationAxis::GenerationSites)
        .supported(MaterializationAxis::GeneratedSets);

/// Python: `@overload` signatures are declaration-only state, and the join
/// from a stub to the runnable `def` of the same callable is the
/// implementation linkage. Python generates no declarations from macros and
/// has no export-form model here.
pub static PYTHON_MATERIALIZATION_SUPPORT: DeclarationMaterializationSupport =
    DeclarationMaterializationSupport::NONE
        .supported(MaterializationAxis::DeclarationState)
        .supported(MaterializationAxis::ImplementationLinkage);

/// JS/TS: default exports (named and anonymous), named exports, and CommonJS
/// `module.exports` roots and members are export rows, and every declared unit
/// can state its origin (a CommonJS member is a generated declaration).
pub static JS_TS_MATERIALIZATION_SUPPORT: DeclarationMaterializationSupport =
    DeclarationMaterializationSupport::NONE
        .supported(MaterializationAxis::DeclarationState)
        .supported(MaterializationAxis::Exports);

/// C++: `#define` sites materialize macro units (generation with exact sets),
/// recovery-shaped declarators state a `recovered` origin, and declarations
/// under preprocessor conditionals are configuration-gated. No preprocessor
/// evaluation exists, so the gating axis states the gate, never the verdict.
pub static CPP_MATERIALIZATION_SUPPORT: DeclarationMaterializationSupport =
    DeclarationMaterializationSupport::NONE
        .supported(MaterializationAxis::DeclarationState)
        .supported(MaterializationAxis::GenerationSites)
        .supported(MaterializationAxis::GeneratedSets)
        .supported(MaterializationAxis::ConfigurationGating);

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// Every labelled vocabulary in this registry must have unique labels that
    /// round-trip through both `from_label` and serde, so a JSON surface and a
    /// rendered surface never disagree about a name.
    #[test]
    fn materialization_vocabularies_are_unique_and_round_trip() {
        macro_rules! check {
            ($all:expr, $type:ty) => {{
                let mut labels = HashSet::new();
                for &value in $all {
                    assert!(labels.insert(value.label()), "duplicate label {value:?}");
                    assert_eq!(<$type>::from_label(value.label()), Some(value));
                    let json = serde_json::to_value(value).expect("serialize");
                    assert_eq!(
                        json,
                        serde_json::Value::String(value.label().to_owned()),
                        "serde label diverges from label() for {value:?}"
                    );
                    let back: $type = serde_json::from_value(json).expect("deserialize");
                    assert_eq!(back, value);
                }
                assert_eq!(labels.len(), $all.len());
            }};
        }

        check!(ALL_DECLARATION_ORIGINS, DeclarationOrigin);
        check!(ALL_GENERATION_INPUT_CLASSES, GenerationInputClass);
        check!(ALL_GENERATION_KINDS, GenerationKind);
        check!(ALL_EXPORT_FORMS, ExportForm);
        check!(ALL_MATERIALIZATION_AXES, MaterializationAxis);

        assert!(DeclarationOrigin::from_label("not_an_origin").is_none());
        assert!(MaterializationAxis::from_label("not_an_axis").is_none());
    }

    #[test]
    fn axis_indices_are_dense_and_size_the_support_table() {
        assert_eq!(ALL_MATERIALIZATION_AXES.len(), MaterializationAxis::COUNT);
        for (slot, &axis) in ALL_MATERIALIZATION_AXES.iter().enumerate() {
            assert_eq!(axis.index(), slot);
        }
        assert_eq!(
            DeclarationMaterializationSupport::NONE.iter().count(),
            MaterializationAxis::COUNT
        );
    }

    #[test]
    fn support_table_is_total_and_defaults_to_unsupported() {
        let table = DeclarationMaterializationSupport::default();
        assert!(table.is_empty());
        for &axis in ALL_MATERIALIZATION_AXES {
            assert_eq!(table.support(axis), MaterializationSupport::Unsupported);
            assert!(!table.is_supported(axis));
        }

        let declared = DeclarationMaterializationSupport::NONE
            .supported(MaterializationAxis::GenerationSites)
            .supported(MaterializationAxis::ConfigurationGating)
            .unsupported(MaterializationAxis::ConfigurationGating);
        assert!(declared.is_supported(MaterializationAxis::GenerationSites));
        assert!(!declared.is_supported(MaterializationAxis::ConfigurationGating));
        assert!(!declared.is_supported(MaterializationAxis::Exports));
        assert!(!declared.is_empty());
        assert!(NO_MATERIALIZATION_SUPPORT.is_empty());
    }

    /// The per-language tables are the one place each claiming adapter states
    /// what it answers, so their contents are asserted once here rather than
    /// in each adapter. The matrix is deliberately non-uniform: each language
    /// claims exactly the axes its producers compute, and nothing claims what
    /// no producer computes (no language claims every axis).
    #[test]
    fn claimed_tables_state_the_per_language_matrix() {
        use MaterializationAxis::*;

        let expect = |table: &DeclarationMaterializationSupport,
                      name: &str,
                      claimed: &[MaterializationAxis]| {
            for &axis in ALL_MATERIALIZATION_AXES {
                assert_eq!(
                    table.is_supported(axis),
                    claimed.contains(&axis),
                    "unexpected {name} support for {axis}"
                );
            }
        };

        expect(
            &RUBY_MATERIALIZATION_SUPPORT,
            "ruby",
            &[DeclarationState, GenerationSites, GeneratedSets],
        );
        expect(
            &PYTHON_MATERIALIZATION_SUPPORT,
            "python",
            &[DeclarationState, ImplementationLinkage],
        );
        expect(
            &JS_TS_MATERIALIZATION_SUPPORT,
            "js_ts",
            &[DeclarationState, Exports],
        );
        expect(
            &CPP_MATERIALIZATION_SUPPORT,
            "cpp",
            &[
                DeclarationState,
                GenerationSites,
                GeneratedSets,
                ConfigurationGating,
            ],
        );

        for table in [
            &RUBY_MATERIALIZATION_SUPPORT,
            &PYTHON_MATERIALIZATION_SUPPORT,
            &JS_TS_MATERIALIZATION_SUPPORT,
            &CPP_MATERIALIZATION_SUPPORT,
        ] {
            assert!(!table.iter().all(|(_, support)| support.is_supported()));
        }
    }

    #[test]
    fn every_axis_describes_itself() {
        for &axis in ALL_MATERIALIZATION_AXES {
            assert!(!axis.description().is_empty());
            assert_eq!(axis.signature(), axis.label());
        }
    }
}
