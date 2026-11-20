//! Typed, per-file inputs to unit derivations. Publication wiring owns retirement.
use super::resolution::resolution_bundle_epoch;
use super::source_facts::SOURCE_FACTS_VERSION;
use crate::analyzer::canonical_hash::{CanonicalHasher, lower_hex_string};
use brokk_bifrost_core::analyzer::Language;
use brokk_bifrost_core::analyzer::go_facts::{GO_SOURCE_FACTS_VERSION, GO_SOURCE_HEADER_SQL};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params, types::Value};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug)]
pub enum ColumnKind {
    Value,
    Ref(u32),
    Excluded,
    /// The view preserves the store-global ID for joins. Hash its content instead:
    /// identity_digest is unique. ResolutionLookupSemanticRecipe::new_in_domain
    /// hashes the language domain, namespace and spelling, so the digest covers
    /// all recipe fields read by Go without depending on interning order.
    IdentityRef,
}
#[derive(Clone, Copy, Debug)]
pub enum Membership {
    Own(u32, &'static str),
    Member(u32, &'static str),
}
impl Membership {
    fn parts(self) -> (u32, &'static str) {
        match self {
            Self::Own(s, c) | Self::Member(s, c) => (s, c),
        }
    }
}
#[derive(Clone, Copy, Debug)]
pub enum RelationSource {
    Table(&'static str),
    /// A structured, same-blob SELECT. Its complete SQL definition enters
    /// list_digest, so changing an edge definition invalidates older products.
    Derived(&'static str),
    /// Same-blob construction SQL, materialized before the consumer runs.
    /// Unlike Derived, generated accessors never evaluate its raw fact reads.
    Materialized(&'static str),
}
impl RelationSource {
    fn qualified_name(self, relation_name: &str) -> String {
        match self {
            Self::Table(table) => format!("main.{table}"),
            Self::Derived(_) | Self::Materialized(_) => format!("temp.{relation_name}_source"),
        }
    }
}
#[derive(Clone, Copy, Debug)]
pub struct Relation {
    pub name: &'static str,
    pub source: RelationSource,
    pub language: &'static str,
    pub membership: Membership,
    pub seed: Option<&'static str>,
    pub columns: &'static [(&'static str, ColumnKind)],
}
use ColumnKind::{Excluded as X, IdentityRef as I, Ref as R, Value as V};
use Membership::{Member as M, Own as O};
// Spaces: site=0, semantic=1, declaration=2, Go type=3, occurrence=4,
// import=5, node=6. Numbers are persisted only inside this list's namespace.
pub static GO_RELATIONS: &[Relation] = &[
    Relation {
        name: "surface_go_members",
        source: RelationSource::Table("resolution_package_members"),
        language: "go",
        membership: O(0, "source_site"),
        seed: Some("1"),
        columns: &[
            ("source_site", R(0)),
            ("definition_key", R(1)),
            ("lookup_key", R(1)),
            ("namespace", V),
        ],
    },
    Relation {
        name: "surface_go_catalog",
        source: RelationSource::Table("resolution_semantic_catalog"),
        language: "go",
        membership: O(1, "local_key"),
        seed: None,
        columns: &[("local_key", R(1)), ("shared_identity", I)],
    },
    Relation {
        name: "surface_go_aliases",
        source: RelationSource::Table("source_go_aliases"),
        language: "go",
        membership: O(2, "declaration_id"),
        seed: Some("1"),
        columns: &[("name", V), ("target_type_id", R(3))],
    },
    Relation {
        name: "surface_go_types",
        source: RelationSource::Table("source_go_types"),
        language: "go",
        membership: O(3, "type_id"),
        seed: None,
        columns: &[("type_id", R(3)), ("kind", V), ("occurrence_id", R(4))],
    },
    Relation {
        name: "surface_go_type_names",
        source: RelationSource::Table("source_go_type_names"),
        language: "go",
        membership: M(3, "type_id"),
        seed: None,
        columns: &[("type_id", R(3)), ("ordinal", V), ("name", V)],
    },
    Relation {
        name: "surface_go_occurrences",
        source: RelationSource::Table("source_occurrences"),
        language: "go",
        membership: O(4, "occurrence_id"),
        seed: None,
        columns: &[("occurrence_id", R(4)), ("start_byte", X), ("end_byte", X)],
    },
    Relation {
        name: "surface_go_sites",
        source: RelationSource::Table("resolution_sites"),
        language: "go",
        membership: O(0, "site"),
        seed: None,
        columns: &[
            ("site", R(0)),
            ("role", V),
            ("start_byte", X),
            ("end_byte", X),
        ],
    },
    Relation {
        name: "surface_go_paths",
        source: RelationSource::Table("resolution_paths"),
        language: "go",
        membership: M(0, "start_node"),
        seed: None,
        columns: &[
            ("start_node", R(0)),
            ("end_node", R(6)),
            ("end_lead_identity", I),
            ("root_terminal", I),
        ],
    },
    Relation {
        name: "surface_go_imports",
        source: RelationSource::Table("source_imports"),
        language: "go",
        membership: O(5, "import_id"),
        seed: Some("1"),
        columns: &[
            ("import_id", R(5)),
            ("alias", V),
            ("declaration_start_byte", X),
            ("declaration_end_byte", X),
        ],
    },
    Relation {
        name: "surface_go_import_segments",
        source: RelationSource::Table("source_import_segments"),
        language: "go",
        membership: M(5, "import_id"),
        seed: None,
        columns: &[("import_id", R(5)), ("ordinal", V), ("segment", V)],
    },
    Relation {
        name: "surface_go_import_bindings",
        source: RelationSource::Table("resolution_go_package_imports"),
        language: "go",
        membership: O(1, "definition_key"),
        seed: Some("1"),
        columns: &[
            ("definition_key", R(1)),
            ("kind", V),
            ("start_byte", X),
            ("end_byte", X),
        ],
    },
    // UNIT_IMPORTS_SQL matches every import against all binding rows of the same
    // blob by exact declaration range, with no kind filter or innermost choice.
    // M2 reads this bridge view instead of performing that range join itself.
    Relation {
        name: "surface_go_import_binding_pairs",
        source: RelationSource::Derived(
            "SELECT imports.blob_id, imports.import_id, bindings.definition_key
             FROM main.source_imports imports
             JOIN main.resolution_go_package_imports bindings
               ON bindings.blob_id=imports.blob_id
              AND bindings.start_byte=imports.declaration_start_byte
              AND bindings.end_byte=imports.declaration_end_byte",
        ),
        language: "go",
        membership: M(5, "import_id"),
        seed: None,
        columns: &[("import_id", R(5)), ("definition_key", R(1))],
    },
    // UNIT_ALIAS_EXPORTS_SQL takes ALL role=0 sites of this blob contained in
    // each alias target occurrence. It does not choose the innermost site.
    // M2 reads this bridge view instead of performing that containment join.
    Relation {
        name: "surface_go_alias_target_sites",
        source: RelationSource::Derived(
            "SELECT target.blob_id, target.occurrence_id, sites.site
             FROM main.source_go_aliases aliases
             JOIN main.source_go_types target
               ON target.blob_id=aliases.blob_id AND target.type_id=aliases.target_type_id
             JOIN main.source_occurrences occurrence
               ON occurrence.blob_id=target.blob_id AND occurrence.occurrence_id=target.occurrence_id
             JOIN main.resolution_sites sites
               ON sites.blob_id=target.blob_id AND sites.role=0
              AND sites.start_byte>=occurrence.start_byte
              AND sites.end_byte<=occurrence.end_byte",
        ),
        language: "go",
        membership: M(4, "occurrence_id"),
        seed: None,
        columns: &[("occurrence_id", R(4)), ("site", R(0))],
    },
];

// Python module syntax allocates its module slots before function inventories.
// Ordinary body reads, locals, calls, nested functions and lambdas cannot change
// their dense rank. A function-body global write can allocate a module slot and
// is itself a surface seed: deleting or moving it must change the fingerprint.
// All body imports are seeds too: STAGE_IMPORTS/STAGE_SEGMENTS read them.
// Spaces: slot=0, import=1, event=2, source marker=3, export=4, path=5.
pub static PYTHON_RELATIONS: &[Relation] = &[
    Relation {
        name: "surface_python_slots",
        // Import closure reaches local slots too. Preserve the module-membership
        // predicate read by STAGE_MODULE_NAMES without exposing dense scope IDs.
        source: RelationSource::Derived(
            "SELECT blob_id,slot,name,(scope=0) AS module_scope FROM main.resolution_binding_slots",
        ),
        language: "python",
        membership: O(0, "slot"),
        seed: Some("module_scope=1"),
        columns: &[("slot", R(0)), ("name", V), ("module_scope", V)],
    },
    Relation {
        name: "surface_python_imports",
        source: RelationSource::Table("python_binding_imports"),
        language: "python",
        membership: O(1, "import_site"),
        seed: Some("1"),
        columns: &[
            ("import_site", R(1)),
            ("relative_level", V),
            ("form", V),
            ("route", V),
            ("module_segments", V),
            ("binding_event", R(2)),
        ],
    },
    Relation {
        name: "surface_python_events",
        source: RelationSource::Table("resolution_binding_events"),
        language: "python",
        membership: O(2, "event"),
        seed: None,
        columns: &[("event", R(2)), ("slot", R(0))],
    },
    Relation {
        name: "surface_python_source",
        source: RelationSource::Table("python_binding_source"),
        language: "python",
        membership: O(3, "blob_id"),
        seed: Some("1"),
        columns: &[("format", V), ("export_curated", V), ("export_wildcard", V)],
    },
    Relation {
        name: "surface_python_exports",
        source: RelationSource::Table("python_binding_export_operations"),
        language: "python",
        membership: O(4, "ordinal"),
        seed: Some("1"),
        columns: &[("kind", V), ("members", V)],
    },
    Relation {
        name: "surface_python_path_extensions",
        source: RelationSource::Table("python_package_path_extensions"),
        language: "python",
        membership: O(5, "ordinal"),
        seed: Some("1"),
        columns: &[("directory", V)],
    },
];

// Rust spaces: site=0, semantic=1, declaration=2, occurrence=3, import=4,
// native scope=5, module scope=7, module route=8, macro=9,
// import target=12, attribute=13, unit=14.
// Seeds include items in every lexical context, modules, imports, impl headers,
// macro definitions/classifications, item expansions and inner attributes.
// Initializer values and alias targets are not unconditional seeds.
// Consumer ownership and event order are constructed once before fingerprinting
// or staging. Only their materialized, coordinate-free outputs enter accessors.
// Native node keys remain construction locators, never fingerprint values.
// Both writers preserve the native facts.sites index: fact_lowering.rs builds
// LoweredSemanticSite from identifier.site; prepare_site_rows writes site().get().
// prepare_gap_rows writes identities.gap_reasons' site.get() (including sites
// without a lowered semantic). REASON_OWNERS_SQL in rust_crate_access.rs joins
// site.site=gap.site: these two relations jointly own the native site space.
const RUST_SITE_OWNERS: &[(&str, &str)] = &[
    ("resolution_sites", "site"),
    ("resolution_gap_reasons", "site"),
];

pub static RUST_RELATIONS: &[Relation] = &[
    Relation {
        name: "surface_rust_resolution_additional_definition_namespaces",
        source: RelationSource::Table("resolution_additional_definition_namespaces"),
        language: "rust",
        membership: O(1, "definition_semantic_key"),
        seed: None,
        columns: &[("definition_semantic_key", R(1)), ("namespace", V)],
    },
    Relation {
        name: "surface_rust_resolution_inherent_implementations",
        source: RelationSource::Table("resolution_inherent_implementations"),
        language: "rust",
        membership: O(0, "impl_site"),
        seed: Some("1"),
        columns: &[
            ("impl_declaration_id", R(2)),
            ("impl_end_byte", X),
            ("impl_site", R(0)),
            ("impl_start_byte", X),
            ("position", V),
            ("relation_key", X),
            ("segment", V),
            ("terminal_spelling", V),
        ],
    },
    Relation {
        name: "surface_rust_resolution_member_owner_properties",
        source: RelationSource::Table("resolution_member_owner_properties"),
        language: "rust",
        membership: O(1, "definition_semantic_key"),
        seed: None,
        columns: &[
            ("definition_semantic_key", R(1)),
            ("owner_definition_semantic_key", R(1)),
        ],
    },
    Relation {
        name: "surface_rust_resolution_rust_declaration_authorities",
        source: RelationSource::Table("resolution_rust_declaration_authorities"),
        language: "rust",
        membership: O(1, "semantic_key"),
        seed: Some("1"),
        columns: &[
            ("cfg_condition", V),
            ("declaration", R(2)),
            ("semantic_key", R(1)),
            ("source_site", R(0)),
        ],
    },
    Relation {
        name: "surface_rust_resolution_semantic_sites",
        source: RelationSource::Table("resolution_semantic_sites"),
        language: "rust",
        membership: O(0, "source_site"),
        seed: None,
        columns: &[
            ("namespace", V),
            ("semantic_key", R(1)),
            ("semantic_role", V),
            ("source_site", R(0)),
        ],
    },
    Relation {
        name: "surface_rust_resolution_rust_structural_trait_impls",
        source: RelationSource::Table("resolution_rust_structural_trait_impls"),
        language: "rust",
        membership: O(0, "impl_site"),
        seed: Some("1"),
        columns: &[
            ("impl_end_byte", X),
            ("impl_site", R(0)),
            ("impl_start_byte", X),
            ("relation_key", X),
            ("trait_terminal_spelling", V),
        ],
    },
    Relation {
        name: "surface_rust_resolution_trait_implementations",
        source: RelationSource::Table("resolution_trait_implementations"),
        language: "rust",
        membership: O(0, "impl_site"),
        seed: Some("1"),
        columns: &[
            ("impl_end_byte", X),
            ("impl_site", R(0)),
            ("impl_start_byte", X),
            ("position", V),
            ("relation_key", X),
            ("segment", V),
            ("side", V),
            ("terminal_spelling", V),
        ],
    },
    Relation {
        name: "surface_rust_source_declaration_units",
        source: RelationSource::Table("source_declaration_units"),
        language: "rust",
        membership: O(2, "declaration_id"),
        seed: None,
        columns: &[("declaration_id", R(2)), ("unit_key", R(14))],
    },
    Relation {
        name: "surface_rust_source_declaration_visibilities",
        source: RelationSource::Table("source_declaration_visibilities"),
        language: "rust",
        membership: O(2, "declaration_id"),
        seed: None,
        columns: &[("declaration_id", R(2))],
    },
    Relation {
        name: "surface_rust_source_declarations",
        source: RelationSource::Table("source_declarations"),
        language: "rust",
        membership: O(2, "declaration_id"),
        seed: None,
        // Block-local items can have neither a unit row nor a shared identity.
        // Their spelling still participates in selected-definition reads.
        columns: &[
            ("declaration_id", R(2)),
            ("end_byte", X),
            ("lexical_identifier", V),
            ("start_byte", X),
        ],
    },
    Relation {
        name: "surface_rust_source_import_segments",
        source: RelationSource::Table("source_import_segments"),
        language: "rust",
        membership: O(4, "import_id"),
        seed: None,
        columns: &[("import_id", R(4)), ("ordinal", V), ("segment", V)],
    },
    Relation {
        name: "surface_rust_source_imports",
        source: RelationSource::Table("source_imports"),
        language: "rust",
        membership: O(4, "import_id"),
        seed: Some("1"),
        columns: &[
            ("alias", V),
            ("alias_occurrence_id", R(3)),
            ("declaration_end_byte", X),
            ("declaration_occurrence_id", R(3)),
            ("declaration_start_byte", X),
            ("identifier", V),
            ("import_id", R(4)),
            ("is_global", V),
            ("is_macro_use", V),
            ("is_wildcard", V),
            ("path_kind", V),
            ("target_occurrence_id", R(3)),
        ],
    },
    Relation {
        name: "surface_rust_source_native_declaration_bridges",
        source: RelationSource::Table("source_native_declaration_bridges"),
        language: "rust",
        membership: O(2, "declaration_id"),
        seed: None,
        columns: &[("declaration_id", R(2)), ("source_site", R(0))],
    },
    Relation {
        name: "surface_rust_source_rust_alias_items",
        source: RelationSource::Table("source_rust_alias_items"),
        language: "rust",
        membership: O(2, "declaration_id"),
        seed: None,
        columns: &[("context_occurrence_id", R(3)), ("declaration_id", R(2))],
    },
    Relation {
        name: "surface_rust_source_rust_callable_items",
        source: RelationSource::Table("source_rust_callable_items"),
        language: "rust",
        membership: O(2, "declaration_id"),
        seed: None,
        columns: &[("context_occurrence_id", R(3)), ("declaration_id", R(2))],
    },
    Relation {
        name: "surface_rust_source_rust_constructor_fields",
        source: RelationSource::Table("source_rust_constructor_fields"),
        language: "rust",
        membership: O(2, "declaration_id"),
        seed: None,
        columns: &[("declaration_id", R(2)), ("visibility", V)],
    },
    Relation {
        name: "surface_rust_source_rust_declaration_properties",
        source: RelationSource::Table("source_rust_declaration_properties"),
        language: "rust",
        membership: O(2, "declaration_id"),
        seed: Some("1"),
        columns: &[
            ("cfg_condition", V),
            ("constructor_non_exhaustive", V),
            ("declaration_id", R(2)),
            ("declaration_kind", V),
            ("generated_surface", V),
            ("macro_exported", V),
            ("nearest_declaration_boundary", V),
            ("visibility", V),
        ],
    },
    Relation {
        name: "surface_rust_source_rust_impl_items",
        source: RelationSource::Table("source_rust_impl_items"),
        language: "rust",
        membership: O(2, "declaration_id"),
        seed: Some("1"),
        columns: &[
            ("context_occurrence_id", R(3)),
            ("declaration_id", R(2)),
            ("target_type_occurrence_id", R(3)),
            ("trait_type_occurrence_id", R(3)),
        ],
    },
    Relation {
        name: "surface_rust_source_rust_import_contexts",
        source: RelationSource::Table("source_rust_import_contexts"),
        language: "rust",
        membership: O(3, "declaration_occurrence_id"),
        seed: None,
        columns: &[
            ("cfg_condition", V),
            ("declaration_occurrence_id", R(3)),
            ("local_scope_end_byte", X),
            ("local_scope_occurrence_id", X),
            ("local_scope_start_byte", X),
            ("native_scope", R(5)),
            ("owner_module", V),
            ("owner_scope_end_byte", X),
            ("owner_scope_occurrence_id", X),
            ("owner_scope_start_byte", X),
            ("visibility", V),
        ],
    },
    Relation {
        name: "surface_rust_source_rust_import_module_segments",
        source: RelationSource::Table("source_rust_import_module_segments"),
        language: "rust",
        membership: O(12, "import_ordinal"),
        seed: None,
        columns: &[("import_ordinal", R(12)), ("ordinal", V), ("segment", V)],
    },
    Relation {
        name: "surface_rust_source_rust_import_targets",
        source: RelationSource::Table("source_rust_import_targets"),
        language: "rust",
        membership: O(12, "ordinal"),
        seed: Some("1"),
        columns: &[
            ("bound_name", V),
            ("cfg_condition", V),
            ("imported_name", V),
            ("is_extern_crate", V),
            ("is_glob", V),
            ("is_macro_use", V),
            ("leading_absolute", V),
            ("local_end", X),
            ("local_start", X),
            ("module_path", V),
            ("native_scope", R(5)),
            ("ordinal", R(12)),
            ("owner_module", V),
            ("source_import_id", R(4)),
            ("visibility", V),
        ],
    },
    Relation {
        name: "surface_rust_source_rust_inner_attributes",
        source: RelationSource::Table("source_rust_inner_attributes"),
        language: "rust",
        membership: O(13, "ordinal"),
        seed: Some("1"),
        columns: &[("name", V), ("ordinal", R(13))],
    },
    Relation {
        name: "surface_rust_source_rust_item_macro_expansions",
        source: RelationSource::Table("source_rust_item_macro_expansions"),
        language: "rust",
        membership: O(3, "invocation_occurrence_id"),
        seed: Some("1"),
        columns: &[
            ("context_occurrence_id", R(3)),
            ("expansion_kind", V),
            ("invocation_end_byte", X),
            ("invocation_occurrence_id", R(3)),
            ("invocation_start_byte", X),
            ("root_occurrence_id", R(3)),
            ("source_position", X),
        ],
    },
    Relation {
        name: "surface_rust_source_rust_item_macros",
        source: RelationSource::Table("source_rust_item_macros"),
        language: "rust",
        membership: O(9, "ordinal"),
        seed: Some("1"),
        columns: &[
            ("arguments_only", V),
            ("declaration_id", R(2)),
            ("declares_no_item", V),
            ("decoration_cfg", V),
            ("lang", V),
            ("macro_name", V),
            ("ordinal", R(9)),
            ("passthrough", V),
            ("writes_only_impls", V),
        ],
    },
    Relation {
        name: "surface_rust_source_rust_item_syntax",
        source: RelationSource::Table("source_rust_item_syntax"),
        language: "rust",
        membership: O(3, "occurrence_id"),
        seed: None,
        columns: &[("has_error", V), ("occurrence_id", R(3))],
    },
    Relation {
        name: "surface_rust_source_rust_macro_arms",
        source: RelationSource::Table("source_rust_macro_arms"),
        language: "rust",
        membership: O(2, "declaration_id"),
        seed: None,
        columns: &[("declaration_id", R(2)), ("transcriber_identifiers", V)],
    },
    Relation {
        name: "surface_rust_source_rust_macro_definitions",
        source: RelationSource::Table("source_rust_macro_definitions"),
        language: "rust",
        membership: O(2, "declaration_id"),
        seed: Some("1"),
        columns: &[("context_occurrence_id", R(3)), ("declaration_id", R(2))],
    },
    Relation {
        name: "surface_rust_source_rust_macro_inputs",
        source: RelationSource::Table("source_rust_macro_inputs"),
        language: "rust",
        membership: O(3, "invocation_occurrence_id"),
        seed: None,
        columns: &[
            ("cfg_condition", V),
            ("invocation_occurrence_id", R(3)),
            ("native_gap_site", R(0)),
        ],
    },
    Relation {
        name: "surface_rust_source_rust_macro_invocations",
        source: RelationSource::Table("source_rust_macro_invocations"),
        language: "rust",
        membership: O(3, "occurrence_id"),
        seed: None,
        columns: &[("macro_name", V), ("occurrence_id", R(3))],
    },
    Relation {
        name: "surface_rust_source_rust_module_declarations",
        source: RelationSource::Table("source_rust_module_declarations"),
        language: "rust",
        membership: O(2, "declaration_id"),
        seed: Some("1"),
        columns: &[
            ("body_end_byte", X),
            ("body_occurrence_id", R(3)),
            ("body_start_byte", X),
            ("declaration_id", R(2)),
            ("macro_use", V),
            ("module_name", V),
            ("path_attribute", V),
        ],
    },
    Relation {
        name: "surface_rust_source_rust_module_inventory",
        source: RelationSource::Table("source_rust_module_inventory"),
        language: "rust",
        membership: M(7, "parent_scope_ordinal"),
        seed: None,
        columns: &[("declaration_id", R(2)), ("parent_scope_ordinal", R(7))],
    },
    Relation {
        name: "surface_rust_source_rust_module_route_gates",
        source: RelationSource::Table("source_rust_module_route_gates"),
        language: "rust",
        membership: O(8, "route_ordinal"),
        seed: None,
        columns: &[("invocation_occurrence_id", R(3)), ("route_ordinal", R(8))],
    },
    Relation {
        name: "surface_rust_source_rust_module_routes",
        source: RelationSource::Table("source_rust_module_routes"),
        language: "rust",
        membership: O(8, "ordinal"),
        seed: Some("1"),
        columns: &[
            ("declaration_id", R(2)),
            ("ordinal", R(8)),
            ("scope_ordinal", R(7)),
        ],
    },
    Relation {
        name: "surface_rust_source_rust_module_scopes",
        source: RelationSource::Table("source_rust_module_scopes"),
        language: "rust",
        membership: O(7, "ordinal"),
        seed: Some("1"),
        columns: &[
            ("declaration_id", R(2)),
            ("ordinal", R(7)),
            ("parent_ordinal", R(7)),
            ("resolution_scope", R(5)),
        ],
    },
    Relation {
        name: "surface_rust_source_rust_type_segments",
        source: RelationSource::Table("source_rust_type_segments"),
        language: "rust",
        membership: O(3, "type_occurrence_id"),
        seed: None,
        columns: &[("occurrence_id", R(3)), ("type_occurrence_id", R(3))],
    },
    Relation {
        name: "surface_rust_source_rust_types",
        source: RelationSource::Table("source_rust_types"),
        language: "rust",
        membership: O(3, "occurrence_id"),
        seed: None,
        columns: &[("leading_absolute", V), ("occurrence_id", R(3))],
    },
    Relation {
        name: "surface_rust_source_rust_value_items",
        source: RelationSource::Table("source_rust_value_items"),
        language: "rust",
        membership: O(2, "declaration_id"),
        seed: None,
        columns: &[("context_occurrence_id", R(3)), ("declaration_id", R(2))],
    },
    Relation {
        name: "surface_rust_catalog",
        source: RelationSource::Table("resolution_semantic_catalog"),
        language: "rust",
        membership: O(1, "local_key"),
        seed: None,
        columns: &[("local_key", R(1)), ("shared_identity", I)],
    },
    Relation {
        name: "surface_rust_units",
        source: RelationSource::Table("code_units"),
        language: "rust",
        membership: O(14, "unit_key"),
        seed: None,
        columns: &[("unit_key", R(14)), ("identifier", V), ("exact_fqn", V)],
    },
    Relation {
        name: "surface_rust_member_scopes",
        source: RelationSource::Materialized(
            "SELECT p.blob_id,p.definition_semantic_key,n.source_scope,p.scope_kind FROM main.resolution_member_scope_properties p JOIN main.resolution_node_catalog n ON n.blob_id=p.blob_id AND n.local_key=p.scope_head_node_key WHERE p.blob_id=?1",
        ),
        language: "rust",
        membership: M(1, "definition_semantic_key"),
        seed: None,
        columns: &[
            ("definition_semantic_key", R(1)),
            ("source_scope", R(5)),
            ("scope_kind", V),
        ],
    },
    Relation {
        // The module a trait or inherent impl header is placed in. A header a
        // macro replays has no impl declaration row at its call site, so
        // `surface_rust_declaration_owners` cannot place it; its own byte span
        // does, with the innermost-module rule of that relation.
        name: "surface_rust_impl_owners",
        source: RelationSource::Materialized(
            "WITH impls AS (SELECT blob_id,impl_site,impl_start_byte,impl_end_byte FROM main.resolution_trait_implementations WHERE blob_id=?1 UNION SELECT blob_id,impl_site,impl_start_byte,impl_end_byte FROM main.resolution_inherent_implementations WHERE blob_id=?1) SELECT DISTINCT impl.blob_id,impl.impl_site,COALESCE(module.ordinal,0) AS module_scope FROM impls AS impl LEFT JOIN main.rust_module_scopes AS module ON module.blob_id=impl.blob_id AND impl.impl_start_byte>=module.body_start AND impl.impl_end_byte<=module.body_end AND NOT EXISTS(SELECT 1 FROM main.rust_module_scopes AS inner_module WHERE inner_module.blob_id=impl.blob_id AND impl.impl_start_byte>=inner_module.body_start AND impl.impl_end_byte<=inner_module.body_end AND inner_module.body_start>module.body_start)",
        ),
        language: "rust",
        membership: O(0, "impl_site"),
        seed: Some("1"),
        columns: &[("impl_site", R(0)), ("module_scope", R(7))],
    },
    Relation {
        name: "surface_rust_gaps",
        source: RelationSource::Table("resolution_gap_reasons"),
        language: "rust",
        membership: M(0, "site"),
        seed: None,
        columns: &[("site", R(0)), ("origin", V)],
    },
    Relation {
        name: "surface_rust_lexical_declarations",
        source: RelationSource::Materialized(include_str!("surface_rust_lexical_declarations.sql")),
        language: "rust",
        membership: M(5, "scope"),
        seed: Some("1"),
        columns: &[
            ("scope", R(5)),
            ("semantic_key", R(1)),
            ("namespace", V),
            ("spelling", V),
        ],
    },
    Relation {
        name: "surface_rust_declaration_owners",
        // The declaration is the membership identity. A NULL owner_scope retains
        // unknown native attachment in the admitted row and its fingerprint;
        // lexical consumers must not treat it as a known module/root scope.
        source: RelationSource::Materialized(include_str!("surface_rust_declaration_owners.sql")),
        language: "rust",
        membership: O(2, "declaration_id"),
        seed: Some("1"),
        columns: &[
            ("declaration_id", R(2)),
            ("module_scope", R(7)),
            ("owner_scope", R(5)),
        ],
    },
    Relation {
        name: "surface_rust_import_owners",
        source: RelationSource::Materialized(include_str!("surface_rust_import_owners.sql")),
        language: "rust",
        membership: O(12, "import_ordinal"),
        seed: Some("1"),
        columns: &[
            ("import_ordinal", R(12)),
            ("module_scope", R(7)),
            ("owner_scope", R(5)),
            ("module_import", V),
            ("extern_root_eligible", V),
        ],
    },
    Relation {
        name: "surface_rust_lexical_owners",
        source: RelationSource::Materialized(include_str!("surface_rust_lexical_owners.sql")),
        language: "rust",
        membership: O(5, "scope"),
        seed: Some("1"),
        columns: &[
            ("scope", R(5)),
            ("parent_scope", R(5)),
            ("module_scope", R(7)),
            ("member_body", V),
        ],
    },
    Relation {
        name: "surface_rust_expansion_owners",
        source: RelationSource::Materialized(include_str!("surface_rust_expansion_owners.sql")),
        language: "rust",
        membership: O(3, "invocation"),
        seed: Some("1"),
        columns: &[
            ("invocation", R(3)),
            ("module_scope", R(7)),
            ("context", R(3)),
            ("item_position", V),
        ],
    },
    Relation {
        name: "surface_rust_source_rust_item_contexts",
        source: RelationSource::Table("source_rust_item_contexts"),
        language: "rust",
        membership: O(3, "occurrence_id"),
        // Every item context that owns a declaration is admitted, so an empty
        // `struct S;` or `trait T {}` stays visible to macro and open-inventory
        // ancestry. Body-only block contexts stay unseeded.
        seed: Some("b.owner_declaration_id IS NOT NULL"),
        columns: &[
            ("occurrence_id", R(3)),
            ("parent_occurrence_id", R(3)),
            ("owner_declaration_id", R(2)),
            ("context_kind", V),
            ("start_byte", X),
            ("end_byte", X),
            ("ordinal", X),
        ],
    },
    Relation {
        name: "surface_rust_resolution_rust_reference_contexts",
        source: RelationSource::Table("resolution_rust_reference_contexts"),
        language: "rust",
        membership: O(1, "semantic_key"),
        seed: Some(
            "EXISTS(SELECT 1 FROM main.resolution_trait_implementations impl WHERE impl.blob_id=b.blob_id AND impl.impl_site=b.semantic_key)",
        ),
        columns: &[("semantic_key", R(1)), ("source_occurrence", R(3))],
    },
    Relation {
        name: "surface_rust_macro_events",
        source: RelationSource::Materialized(include_str!("surface_rust_macro_events.sql")),
        language: "rust",
        membership: M(3, "context"),
        seed: Some("1"),
        columns: &[
            ("context", R(3)),
            ("event", R(3)),
            ("event_kind", V),
            ("order_in_context", V),
            ("definition", R(2)),
        ],
    },
    Relation {
        name: "surface_rust_include_edges",
        source: RelationSource::Materialized(include_str!("surface_rust_include_edges.sql")),
        language: "rust",
        membership: O(3, "invocation"),
        seed: Some("1"),
        columns: &[
            ("invocation", R(3)),
            ("including_owner", R(3)),
            ("relative_path", V),
        ],
    },
    Relation {
        name: "surface_rust_source_rust_item_import_contexts",
        source: RelationSource::Table("source_rust_item_import_contexts"),
        language: "rust",
        membership: M(3, "context_occurrence_id"),
        seed: Some("1"),
        columns: &[("context_occurrence_id", R(3))],
    },
    Relation {
        name: "surface_rust_source_rust_item_body_children",
        source: RelationSource::Table("source_rust_item_body_children"),
        language: "rust",
        membership: M(2, "owner_declaration_id"),
        seed: None,
        columns: &[
            ("owner_declaration_id", R(2)),
            ("occurrence_id", R(3)),
            ("declaration_id", R(2)),
            ("syntax_kind", V),
            ("ordinal", X),
            ("start_byte", X),
            ("end_byte", X),
        ],
    },
    Relation {
        name: "surface_rust_source_rust_item_generic_parameters",
        source: RelationSource::Table("source_rust_item_generic_parameters"),
        language: "rust",
        membership: M(2, "declaration_id"),
        seed: None,
        columns: &[
            ("declaration_id", R(2)),
            ("occurrence_id", R(3)),
            ("syntax_kind", V),
            ("name_occurrence_id", R(3)),
            ("name", V),
            ("ordinal", V),
            ("start_byte", X),
            ("end_byte", X),
        ],
    },
];

struct SurfaceDescription<'a> {
    relations: &'a [Relation],
    language: Language,
    source_header: &'static str,
    source_version: i64,
    auxiliary_version: Option<i64>,
    header_version: i64,
}
const PYTHON_SOURCE_HEADER: &str = "SELECT b.id FROM blobs b
 JOIN blob_meta m ON m.blob_id=b.id
 JOIN source_fact_manifests f ON f.blob_id=b.id
 JOIN source_fact_readiness r ON r.blob_id=b.id
 JOIN python_binding_source p ON p.blob_id=b.id
 WHERE b.blob_oid=?1 AND b.generation=?2 AND b.lang='python'
 AND f.facts_version=?4 AND f.publication_state='complete'
 AND m.is_complete=1 AND r.available=1 AND p.format=?3";
const RUST_SOURCE_HEADER: &str = "SELECT b.id FROM blobs b
 JOIN blob_meta m ON m.blob_id=b.id
 JOIN source_fact_manifests f ON f.blob_id=b.id
 JOIN source_fact_readiness r ON r.blob_id=b.id
 WHERE b.blob_oid=?1 AND b.generation=?2 AND b.lang='rust'
 AND f.facts_version=?4 AND ?3=?4 AND f.publication_state='complete'
 AND m.is_complete=1 AND r.available=1";
fn description(language: &str) -> Option<SurfaceDescription<'static>> {
    match language {
        "go" => Some(SurfaceDescription {
            relations: GO_RELATIONS,
            language: Language::Go,
            source_header: GO_SOURCE_HEADER_SQL,
            source_version: SOURCE_FACTS_VERSION,
            auxiliary_version: Some(GO_SOURCE_FACTS_VERSION),
            header_version: GO_SOURCE_FACTS_VERSION,
        }),
        "rust" => Some(SurfaceDescription {
            relations: RUST_RELATIONS,
            language: Language::Rust,
            source_header: RUST_SOURCE_HEADER,
            source_version: SOURCE_FACTS_VERSION,
            auxiliary_version: None,
            header_version: SOURCE_FACTS_VERSION,
        }),
        "python" => Some(SurfaceDescription {
            relations: PYTHON_RELATIONS,
            language: Language::Python,
            source_header: PYTHON_SOURCE_HEADER,
            source_version: SOURCE_FACTS_VERSION,
            auxiliary_version: None,
            header_version: super::python_binding_rows::NATIVE_SOURCE_FORMAT,
        }),
        _ => None,
    }
}

/// Bound the rows added by surface publication without writing any facts.
/// Keep this separate from the fragment's logical rows: publication adds its
/// measured surface cost to those rows after ensure_surface_set_tx.
pub(super) fn prepared_surface_cost(
    blob: &super::PreparedParsedBlob,
) -> super::PersistedMutationCost {
    let Some(description) = description(blob.lang()) else {
        return super::PersistedMutationCost::default();
    };
    let ids = if description.language == Language::Python {
        // PYTHON_RELATIONS seeds module slots, imports, the source header,
        // export operations and path extensions. Only imports add edges:
        // import -> binding event -> slot. Count distinct IDs in each space,
        // exactly as the publisher's ranks map does, including local slots
        // reached by imports and events shared by more than one import.
        let facts = &blob.state.resolution_facts;
        let mut slots = facts
            .binding_slots
            .iter()
            .filter_map(|slot| {
                let site = &facts.sites[slot.declaration.index()];
                (site.scope.get() == 0).then_some(slot.declaration)
            })
            .collect::<BTreeSet<_>>();
        let events = facts
            .python_imports
            .iter()
            .filter_map(|import| import.binding_event)
            .collect::<BTreeSet<_>>();
        for event in &facts.binding_events {
            if events.contains(&event.ordinal) {
                slots.insert(event.slot);
            }
        }
        slots
            .len()
            .saturating_add(events.len())
            .saturating_add(facts.python_imports.len())
            .saturating_add(usize::from(!facts.scopes.is_empty()))
            .saturating_add(facts.python_export_operations.len())
            .saturating_add(facts.python_package_path_extensions.len())
    } else {
        // Bound the union of the ref_owners spaces, not every logical row.
        // Seed-only Go aliases use declaration IDs from the same source arena;
        // all other seeds either have a self-Ref checked by publication or are
        // subsets of these owner families. Closure only admits backed IDs.
        // Duplicate owners (sites/scopes in particular) conservatively overcount.
        let facts = blob.state.source_facts.as_ref();
        let common = super::saturating_sum([
            blob.resolution.surface_owner_rows(),
            facts.map_or(0, |facts| facts.occurrences.occurrence_count()),
            facts.map_or(0, |facts| facts.occurrences.declaration_count()),
            facts.map_or(0, |facts| facts.imports.len()),
        ]);
        if description.language == Language::Go {
            common.saturating_add(
                facts
                    .and_then(|facts| facts.go.as_ref())
                    .map_or(0, |go| go.types.len()),
            )
        } else {
            let modules = facts.and_then(|facts| facts.rust_modules.as_ref());
            super::saturating_sum([
                common,
                modules.map_or(0, |modules| modules.scopes.len()),
                modules.map_or(0, |modules| modules.routes.len()),
                modules.map_or(0, |modules| modules.inner_attributes.len()),
                blob.rust_facts.module_routes.item_macros.len(),
                blob.rust_facts.import_targets.len(),
                blob.units.len(),
            ])
        }
    };
    super::PersistedMutationCost {
        logical_rows: 1usize.saturating_add(ids),
        payload_bytes: blob.resolution.producer_epoch().len().saturating_add(64),
    }
}

// Keep bootstrap and selected readers on the same member-to-blob join.
fn member_blob_translation_sql(files: &str) -> String {
    format!(
        r#"SELECT members.summary_id, members.member_ordinal, members.rel_path, blobs.id AS blob_id, blobs.blob_oid
         FROM main.resolution_unit_summary_members AS members
         JOIN main.resolution_unit_summaries AS summaries
           ON summaries.summary_id = members.summary_id
         JOIN {files} AS files
           ON files.lang = summaries.lang AND files.rel_path = members.rel_path
         JOIN main.blobs AS blobs
           ON blobs.blob_oid = files.blob_oid AND blobs.lang = files.lang
          AND blobs.parse_variant = files.parse_variant
          AND blobs.generation = files.generation"#
    )
}

pub(super) fn member_blobs_at_revision_sql() -> String {
    format!(
        "{} WHERE members.summary_id=?1 AND files.workspace_id=?2
        AND files.generation=?3 AND files.valid_from<=?4
        AND (files.valid_until IS NULL OR ?4<files.valid_until)
        ORDER BY members.member_ordinal",
        member_blob_translation_sql(
            "(SELECT versions.*, COALESCE(decisions.decision_digest, x'') AS parse_variant FROM main.workspace_file_versions versions LEFT JOIN main.csharp_file_version_decisions decisions ON decisions.file_version_id=versions.file_version_id WHERE versions.input_kind='source')"
        )
    )
}

/// One MemberInput witness for persisted liveness and selected-mount coverage.
/// Plain equality deliberately rejects legacy NULL/NULL member inputs.
fn member_input_equals_sql(recorded: &str, blob: &str, list: &str) -> String {
    format!(
        "(EXISTS(SELECT 1 FROM main.surface_sets AS sets
                   WHERE sets.blob_id = {blob}.id AND sets.list_digest = {list}
                     AND sets.fingerprint = {recorded}.member_surface_fingerprint)
          OR ({recorded}.member_no_facts_oid = {blob}.blob_oid
              AND NOT EXISTS(SELECT 1 FROM main.surface_sets AS sets
                             WHERE sets.blob_id = {blob}.id
                               AND sets.list_digest = {list})))"
    )
}

/// The liveness gate of a Go or Python unit summary, written once. A summary is
/// live only while every member's recorded input equals the input of the blob now
/// selected for that member at the revision (the join of
/// `member_blob_translation_sql`, read from `main` so it runs on any connection):
/// a recorded fingerprint must equal the fingerprint of the blob's current-list
/// set, and a recorded no-facts OID needs the same OID and no current-list set.
/// A member without a selected blob, a legacy row that recorded neither input,
/// and a blob whose set is missing all fail the comparison, so the summary is not
/// live and readers report their existing unavailable or incomplete result instead
/// of translating old surface ordinals through a repaired blob's new set.
/// `summary`, `workspace`, `generation` and `revision` are SQL expressions of the
/// caller; every access is an indexed probe per member.
pub(super) fn members_current_sql(
    lang: &str,
    summary: &str,
    workspace: &str,
    generation: &str,
    revision: &str,
) -> String {
    let relations = match lang {
        "go" => GO_RELATIONS,
        "python" => PYTHON_RELATIONS,
        _ => unreachable!("only converted unit languages record member inputs"),
    };
    let list = lower_hex_string(&list_digest(relations));
    let equal = member_input_equals_sql("recorded", "blobs", &format!("x'{list}'"));
    format!(
        "NOT EXISTS(
           SELECT 1 FROM main.resolution_unit_summary_members AS recorded
           WHERE recorded.summary_id = {summary}
             AND NOT EXISTS(
               SELECT 1 FROM main.workspace_file_versions AS files
               JOIN main.blobs AS blobs
                 ON blobs.blob_oid = files.blob_oid AND blobs.lang = files.lang
                AND blobs.generation = files.generation
                AND blobs.parse_variant = COALESCE((SELECT decisions.decision_digest
                      FROM main.csharp_file_version_decisions AS decisions
                      WHERE decisions.file_version_id = files.file_version_id), x'')
               WHERE files.workspace_id = {workspace} AND files.lang = '{lang}'
                 AND files.generation = {generation} AND files.input_kind = 'source'
                 AND files.rel_path = recorded.rel_path
                 AND files.valid_from <= {revision}
                 AND (files.valid_until IS NULL OR {revision} < files.valid_until)
                 AND {equal}))"
    )
}

/// Both directions of one selected member set, including role. Input equality
/// remains the existing members_current_sql predicate above.
pub(super) fn member_set_current_sql(summary: &str, current: &str) -> String {
    format!(
        "NOT EXISTS(SELECT 1 FROM ({current}) selected
              WHERE NOT EXISTS(SELECT 1 FROM main.resolution_unit_summary_members recorded
                WHERE recorded.summary_id={summary} AND recorded.rel_path=selected.rel_path
                  AND recorded.source_role=selected.source_role))
      AND NOT EXISTS(SELECT 1 FROM main.resolution_unit_summary_members recorded
              WHERE recorded.summary_id={summary} AND NOT EXISTS(
                SELECT 1 FROM ({current}) selected WHERE selected.rel_path=recorded.rel_path
                  AND selected.source_role=recorded.source_role))"
    )
}

/// Resolve summary members before selected mounts exist, at one workspace revision.
pub fn member_blobs_at_revision(
    conn: &Connection,
    summary: i64,
    snapshot: &super::WorkspaceSnapshotId,
) -> rusqlite::Result<Vec<(String, String)>> {
    let sql = member_blobs_at_revision_sql();
    conn.prepare(&sql)?
        .query_map(
            params![
                summary,
                snapshot.workspace_id.as_str(),
                snapshot.generation.0,
                snapshot.revision
            ],
            |row| Ok((row.get(2)?, row.get(4)?)),
        )?
        .collect()
}

/// The list digest that keys one language's `surface_sets` rows. Summary
/// writers bind it and translate dense ids with a correlated seek on
/// `surface_sets (blob_id, list_digest)` then the `surface_ids` primary key,
/// so they never materialize `temp.surface_dense`.
pub(super) fn surface_list_digest(lang: &str) -> [u8; 32] {
    list_digest(
        description(lang)
            .unwrap_or_else(|| panic!("no surface description for {lang}"))
            .relations,
    )
}

pub(super) fn surface_dense_sql() -> String {
    let go = lower_hex_string(&list_digest(GO_RELATIONS));
    let python = lower_hex_string(&list_digest(PYTHON_RELATIONS));
    let rust = lower_hex_string(&list_digest(RUST_RELATIONS));
    format!(
        "SELECT sets.blob_id, ids.id_space, ids.surface_ordinal, ids.dense_id
         FROM main.surface_sets AS sets
         JOIN main.blobs AS blobs ON blobs.id = sets.blob_id
         JOIN main.surface_ids AS ids ON ids.set_id = sets.set_id
         WHERE sets.list_digest = CASE blobs.lang
           WHEN 'go' THEN x'{go}' WHEN 'python' THEN x'{python}'
           WHEN 'rust' THEN x'{rust}' END"
    )
}

/// Install the shared summary coordinate bridges on a selected connection.
/// Foreign rows are coordinate-free name facts; these views translate own rows.
/// These are flattened views: querying one member or one blob does not stage
/// translations for unrelated units. No rows or memory survive the query.
pub(super) fn create_summary_translation_views(conn: &Connection) -> rusqlite::Result<()> {
    let surface_dense = surface_dense_sql();
    let rust_list = lower_hex_string(&list_digest(RUST_RELATIONS));
    let member_blobs = member_blob_translation_sql("temp.selected_workspace_file_versions");
    let go_list = lower_hex_string(&list_digest(GO_RELATIONS));
    let python_list = lower_hex_string(&list_digest(PYTHON_RELATIONS));
    let list = format!(
        "CASE summaries.lang WHEN 'go' THEN x'{go_list}' WHEN 'python' THEN x'{python_list}' END"
    );
    let equal = member_input_equals_sql("members", "mounted_blob", &list);
    conn.execute_batch(&format!(
        "CREATE TEMP VIEW IF NOT EXISTS selected_unit_member_blobs AS
         {member_blobs};
         CREATE TEMP VIEW IF NOT EXISTS selected_unit_member_paths AS
         SELECT members.summary_id, members.member_ordinal, members.rel_path,
                mounts.blob_id AS mount_blob_id, mounts.mount_ordinal,
                ({equal} AND (summaries.lang <> 'go' OR mounts.file_version_id IS NOT NULL OR EXISTS(SELECT 1 FROM temp.selected_go_transient_placements placement WHERE placement.mount_ordinal=mounts.mount_ordinal))) AS covered
         FROM main.resolution_unit_summary_members AS members
         JOIN main.resolution_unit_summaries AS summaries
           ON summaries.summary_id = members.summary_id
         JOIN temp.selected_resolution_mounts AS mounts
           ON mounts.storage_language = summaries.lang
          AND mounts.persisted_relative_path = members.rel_path
         JOIN main.blobs AS mounted_blob ON mounted_blob.id = mounts.blob_id;
         CREATE TEMP VIEW IF NOT EXISTS selected_unit_member_mounts AS
         SELECT summary_id, member_ordinal, rel_path, mount_blob_id AS blob_id, mount_ordinal
         FROM temp.selected_unit_member_paths WHERE covered;
         CREATE TEMP VIEW IF NOT EXISTS surface_dense AS
         {surface_dense};
         -- Persisted placements (and their descendants) whose declaring edge or
         -- own module scope the selected root no longer proves; filled once by
         -- the selected placement fill and empty on every connection that has
         -- no overlay. `module_path` and `rel_path` name the module and the file
         -- of the placement, for the gap rows below.
         CREATE TEMP TABLE IF NOT EXISTS selected_rust_unplaced_placements(
           summary_id INTEGER NOT NULL,
           container_path TEXT NOT NULL,
           member_ordinal INTEGER NOT NULL,
           module_path TEXT,
           rel_path TEXT NOT NULL,
           PRIMARY KEY(summary_id, container_path, member_ordinal)
         ) WITHOUT ROWID, STRICT;
         -- Module and include edges that the selected content of a changed
         -- declaring file `rel_path` holds and the persisted topology lacks (a new
         -- `mod x;`, a new `include!`, a `#[path]` retarget, a re-activated cfg
         -- gate); filled once by the selected placement fill and empty on every
         -- connection that has no overlay. `child_module` is NULL for an include,
         -- whose `target_path` names the included file. `macro_use` says the edge
         -- moves textual macro scope into the parent (`#[macro_use] mod x;`, an
         -- include). An inline module is a row too: its scope has no persisted
         -- placement to align with. A `mod x;` edge has one row per file it can
         -- mount in `target_path` (`x.rs` and `x/mod.rs`, or the `#[path]` value,
         -- by the module walk's own rule `cr_module_candidates`); an inline module
         -- and an edge whose path leaves the workspace have a NULL `target_path`.
         CREATE TEMP TABLE IF NOT EXISTS selected_rust_added_edges(
           summary_id INTEGER NOT NULL,
           parent_module TEXT NOT NULL,
           child_module TEXT,
           target_path TEXT,
           rel_path TEXT NOT NULL,
           macro_use INTEGER NOT NULL
         ) STRICT;
         CREATE INDEX IF NOT EXISTS temp.selected_rust_added_edges_child
           ON selected_rust_added_edges(summary_id, child_module);
         CREATE INDEX IF NOT EXISTS temp.selected_rust_added_edges_macro_use
           ON selected_rust_added_edges(summary_id, macro_use);
         CREATE INDEX IF NOT EXISTS temp.selected_rust_added_edges_file
           ON selected_rust_added_edges(rel_path);
         CREATE INDEX IF NOT EXISTS temp.selected_rust_added_edges_target_path
           ON selected_rust_added_edges(target_path) WHERE target_path IS NOT NULL;
         -- Every overlay topology gap, in the shape of the persisted gaps (the
         -- module path is the subject): an `unplaced_module` row for each module the
         -- selection unplaced and for each child module it added, and an
         -- `open_export_inventory` row on the parent module (the host module of an
         -- added include) because its inventory now names a module or file that no
         -- persisted export row covers. Filled once by the selected placement fill
         -- from the two tables above.
         CREATE TEMP TABLE IF NOT EXISTS selected_rust_overlay_gaps(
           summary_id INTEGER NOT NULL,
           gap_kind TEXT NOT NULL,
           subject TEXT NOT NULL,
           detail BLOB NOT NULL
         ) STRICT;
         CREATE INDEX IF NOT EXISTS temp.selected_rust_overlay_gaps_subject
           ON selected_rust_overlay_gaps(summary_id, subject);
         -- Every overlay topology gap, in the persisted gap shape. A reader of the
         -- persisted gap table unions this view as a second arm. It is a plain
         -- select over one table so that SQLite flattens it into the reader's join
         -- and seeks the index above; a view that unions the two sources is
         -- materialized whole and gets an automatic index.
         CREATE TEMP VIEW IF NOT EXISTS selected_rust_unplaced_gaps AS
         SELECT summary_id, gap_kind, subject, detail
         FROM temp.selected_rust_overlay_gaps;
         -- Rust-only derived-from blob until #11183 M3 converts Rust child rows
         CREATE TEMP VIEW IF NOT EXISTS rust_unit_summary_placements AS
         SELECT p.summary_id, a.module_path, p.member_ordinal, a.source_kind,
                (SELECT ids.dense_id FROM main.surface_ids AS ids
                 WHERE ids.set_id = (SELECT sets.set_id FROM main.surface_sets AS sets
                   WHERE sets.blob_id = (SELECT m.blob_id FROM main.resolution_unit_summary_members AS m
                     WHERE m.summary_id=p.summary_id AND m.member_ordinal=p.member_ordinal)
                     AND sets.list_digest=x'{rust_list}')
                   AND ids.id_space=7 AND ids.surface_ordinal=p.scope_surface_ordinal) AS scope_ordinal,
                a.enum_scope_node_key,
                CASE c.parent_container_path WHEN '' THEN 'crate' ELSE c.parent_container_path END AS parent_module_path
         FROM main.resolution_unit_summary_placements AS p
         JOIN main.rust_resolution_unit_summary_placement_attributes AS a USING(summary_id,container_path,member_ordinal)
         JOIN main.resolution_unit_summary_containers AS c USING(summary_id,container_path)
         WHERE NOT EXISTS (SELECT 1 FROM temp.selected_rust_unplaced_placements AS unplaced
                           WHERE unplaced.summary_id=p.summary_id
                             AND unplaced.container_path=p.container_path
                             AND unplaced.member_ordinal=p.member_ordinal);
"
    ))
}

pub fn list_digest(relations: &[Relation]) -> [u8; 32] {
    let mut h = CanonicalHasher::new(b"bifrost-surface-list:v1");
    for r in relations {
        h.value(r.name.as_bytes());
        match r.source {
            RelationSource::Table(table) => {
                h.value(&[0]);
                h.value(table.as_bytes());
            }
            // Length-delimited exact SQL is the canonical definition of this
            // static entry; even an SQL edit preserving columns changes the list.
            RelationSource::Derived(sql) | RelationSource::Materialized(sql) => {
                h.value(&[if matches!(r.source, RelationSource::Materialized(_)) {
                    2
                } else {
                    1
                }]);
                h.value(sql.as_bytes());
            }
        }
        h.value(r.language.as_bytes());
        let (s, c) = r.membership.parts();
        h.value(&s.to_be_bytes());
        h.value(c.as_bytes());
        h.value(&[matches!(r.membership, Membership::Own(..)) as u8]);
        h.value(&[r.seed.is_some() as u8]);
        h.value(r.seed.unwrap_or_default().as_bytes());
        h.value(&(r.columns.len() as u64).to_be_bytes());
        for (c, k) in r.columns {
            h.value(c.as_bytes());
            match k {
                ColumnKind::Value => h.value(&[0]),
                ColumnKind::Ref(s) => {
                    h.value(&[1]);
                    h.value(&s.to_be_bytes());
                    let language = description(r.language)
                        .expect("surface language has an owner list")
                        .language;
                    for (table, column) in ref_owners(language, *s) {
                        h.value(table.as_bytes());
                        h.value(column.as_bytes());
                    }
                }
                ColumnKind::Excluded => h.value(&[2]),
                ColumnKind::IdentityRef => h.value(&[3]),
            }
        }
    }
    h.finish()
}

// Dense source views are writer implementation details, not derivation
// accessors. Only the ordinal views named by Relation::name are accessors.
// Both the writer and those views read these generated SELECTs, so structured
// range joins are defined once and run only inside generated views.
fn create_source_views(conn: &Connection, relations: &[Relation]) -> rusqlite::Result<()> {
    for r in relations {
        if let RelationSource::Derived(sql) = r.source {
            conn.execute_batch(&format!(
                "DROP VIEW IF EXISTS temp.{name}_source; CREATE TEMP VIEW {name}_source AS {sql}",
                name = r.name,
            ))?;
        }
    }
    Ok(())
}

// Schema construction and publication follow catalog order, so a projection
// can consume an earlier projection. The SELECTs are never accessor definitions.
fn create_materialized_sources(conn: &Connection, relations: &[Relation]) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TEMP TABLE IF NOT EXISTS surface_published_blob(blob_id INTEGER PRIMARY KEY) WITHOUT ROWID, STRICT",
    )?;
    for relation in relations {
        if let RelationSource::Materialized(_) = relation.source {
            // Accessor installation declares only the projected schema. It must
            // not prepare construction reads before the publisher is invoked.
            let columns = relation
                .columns
                .iter()
                .map(|(column, kind)| match kind {
                    // Id columns compare with INTEGER surface_ids columns, so an
                    // untyped column would keep the planner from seeking its index.
                    ColumnKind::Ref(_) => format!("{column} INTEGER"),
                    _ => (*column).to_owned(),
                })
                .collect::<Vec<_>>()
                .join(",");
            // Views seek a projection row by its owner id within a blob, so the
            // owner column follows blob_id in the index.
            let (_, owner) = relation.membership.parts();
            conn.execute_batch(&format!(
                "CREATE TEMP TABLE IF NOT EXISTS {name}_source(blob_id INTEGER,{columns})",
                name = relation.name,
            ))?;
            conn.execute_batch(&format!(
                "CREATE INDEX IF NOT EXISTS temp.{name}_source_owner ON {name}_source(blob_id,{owner})",
                name = relation.name,
            ))?;
        }
    }
    Ok(())
}

/// Stage the materialized projections of `blobs`, replacing only those blobs'
/// rows. The temp tables are shared by every publisher on a connection: an
/// operation publishes its whole blob set, and a lazy `ensure_surface_set` for
/// one more blob publishes that blob while fingerprinting it. A truncate-all
/// here would let the lazy publication silently empty the operation's rows.
/// Replacing per blob is correct because a blob's rows are a pure function of
/// its immutable facts, and every view joins `surface_sets` on its own
/// blob_id, so rows of blobs outside a set are never read. The refusal check
/// is scoped to `blobs` for the same reason: another publisher's blob must not
/// make this publication fail, and this publication's blobs always do.
fn publish_materialized_sources(
    conn: &Connection,
    relations: &[Relation],
    blobs: &[i64],
) -> rusqlite::Result<()> {
    create_materialized_sources(conn, relations)?;
    for relation in relations {
        if let RelationSource::Materialized(sql) = relation.source {
            let mut delete = conn.prepare_cached(&format!(
                "DELETE FROM temp.{}_source WHERE blob_id=?1",
                relation.name
            ))?;
            let mut insert =
                conn.prepare_cached(&format!("INSERT INTO temp.{}_source {sql}", relation.name,))?;
            let (_, owner) = relation.membership.parts();
            let mut unknown = conn.prepare_cached(&format!(
                "SELECT 1 FROM temp.{}_source WHERE blob_id=?1 AND {owner} IS NULL LIMIT 1",
                relation.name
            ))?;
            for blob in blobs {
                delete.execute([blob])?;
                insert.execute([blob])?;
                if unknown.exists([blob])? {
                    return Err(rusqlite::Error::UserFunctionError(Box::new(
                        UnknownSurfaceOwner {
                            relation: relation.name,
                            blob_id: *blob,
                        },
                    )));
                }
            }
        }
    }
    Ok(())
}

/// Construct the shared Rust consumer projections before entering the closure
/// read guard. This replaces operation-local staging, including on a newly
/// opened connection; a persisted surface set does not imply staged rows exist.
/// Fingerprint publication uses the same catalog SELECTs. Accessor views read
/// the materialization, never the construction SQL or its geometry.
///
/// No rows survive in main, and no recompute/snapshot choice is assumed. The
/// caller owns the operation's connection and must not replace these rows while
/// a consumer is running. It must also keep the main fact/set snapshot fixed
/// across publication and consumption (normally in the enclosing transaction),
/// so dense rows cannot be translated through a different set's ordinals.
/// Failure restores the previous complete staging.
///
/// Residency is bounded: after this call the staging tables hold exactly the
/// rows of `blobs` (recorded in `surface_published_blob`), so a warm connection
/// does not accumulate rows of blobs from earlier operations or earlier edits.
/// A later fingerprint publication adds one transient blob and removes it again.
pub fn publish_rust_consumer_projections(conn: &Connection, blobs: &[i64]) -> rusqlite::Result<()> {
    conn.execute_batch("SAVEPOINT rust_surface_projection_publication")?;
    match publish_materialized_sources(conn, RUST_RELATIONS, blobs)
        .and_then(|()| record_published_blobs(conn, RUST_RELATIONS, blobs))
    {
        Ok(()) => conn.execute_batch("RELEASE rust_surface_projection_publication"),
        Err(error) => {
            conn.execute_batch("ROLLBACK TO rust_surface_projection_publication; RELEASE rust_surface_projection_publication")?;
            Err(error)
        }
    }
}

/// Make the staged rows exactly those of `blobs`: record them as the
/// operation's published set and evict every other blob's rows.
fn record_published_blobs(
    conn: &Connection,
    relations: &[Relation],
    blobs: &[i64],
) -> rusqlite::Result<()> {
    conn.execute("DELETE FROM temp.surface_published_blob", [])?;
    let mut record = conn
        .prepare_cached("INSERT OR IGNORE INTO temp.surface_published_blob(blob_id) VALUES(?1)")?;
    for blob in blobs {
        record.execute([blob])?;
    }
    evict_unpublished_blobs(conn, relations)
}

/// Delete the staged rows of every blob outside the operation's published set.
fn evict_unpublished_blobs(conn: &Connection, relations: &[Relation]) -> rusqlite::Result<()> {
    for relation in relations {
        if let RelationSource::Materialized(_) = relation.source {
            conn.prepare_cached(&format!(
                "DELETE FROM temp.{}_source WHERE blob_id NOT IN (SELECT blob_id FROM temp.surface_published_blob)",
                relation.name
            ))?
            .execute([])?;
        }
    }
    Ok(())
}

/// Delete one transient blob's staged rows unless the operation published it.
/// The predicate is a key seek on the (blob_id, owner) index, so a fingerprint
/// does not scan the operation's resident rows.
fn evict_transient_blob(
    conn: &Connection,
    relations: &[Relation],
    blob_id: i64,
) -> rusqlite::Result<()> {
    for relation in relations {
        if let RelationSource::Materialized(_) = relation.source {
            conn.prepare_cached(&format!(
                "DELETE FROM temp.{}_source WHERE blob_id=?1 AND blob_id NOT IN (SELECT blob_id FROM temp.surface_published_blob)",
                relation.name
            ))?
            .execute([blob_id])?;
        }
    }
    Ok(())
}

/// Generate views for exactly this binary's list, without exposing coordinates.
pub fn create_surface_views(conn: &Connection, relations: &[Relation]) -> rusqlite::Result<()> {
    create_materialized_sources(conn, relations)?;
    let digest = lower_hex_string(&list_digest(relations));
    for r in relations {
        let (space, column) = r.membership.parts();
        let mut projections = vec!["b.blob_id".to_owned(), "owner.surface_ordinal".to_owned()];
        for (column, kind) in r.columns {
            let expression = match kind {
                ColumnKind::Excluded => continue,
                ColumnKind::Ref(s) => format!(
                    "CASE WHEN b.{column}<0 THEN b.{column} ELSE (SELECT surface_ordinal FROM main.surface_ids WHERE set_id=sets.set_id AND id_space={s} AND dense_id=b.{column}) END"
                ),
                _ => format!("b.{column}"),
            };
            projections.push(format!("{expression} AS {column}"));
        }
        let source = match r.source {
            RelationSource::Table(table) => format!("main.{table}"),
            RelationSource::Derived(sql) => format!("({sql})"),
            RelationSource::Materialized(_) => format!("temp.{}_source", r.name),
        };
        conn.execute_batch(&format!("DROP VIEW IF EXISTS temp.{name}; CREATE TEMP VIEW {name} AS SELECT {projection} FROM {source} b JOIN main.surface_sets sets ON sets.blob_id=b.blob_id AND sets.list_digest=x'{digest}' JOIN main.surface_ids owner ON owner.set_id=sets.set_id AND owner.id_space={space} AND owner.dense_id=b.{column}",name=r.name,projection=projections.join(","),source=source))?;
    }
    Ok(())
}

fn hash_value(h: &mut CanonicalHasher, v: &Value) {
    match v {
        Value::Null => h.value(&[0]),
        Value::Integer(n) => {
            h.value(&[1]);
            h.value(&n.to_be_bytes());
        }
        Value::Real(n) => {
            h.value(&[2]);
            h.value(&n.to_bits().to_be_bytes());
        }
        Value::Text(s) => {
            h.value(&[3]);
            h.value(s.as_bytes());
        }
        Value::Blob(b) => {
            h.value(&[4]);
            h.value(b);
        }
    }
}

fn ref_owners(language: Language, space: u32) -> &'static [(&'static str, &'static str)] {
    match (language, space) {
        (Language::Rust, 0) => RUST_SITE_OWNERS,
        (Language::Go, 0) => &[("resolution_sites", "site")],
        (Language::Go | Language::Rust, 1) => &[("resolution_semantic_catalog", "local_key")],
        (Language::Go | Language::Rust, 2) => &[("source_declarations", "declaration_id")],
        (Language::Go, 3) => &[("source_go_types", "type_id")],
        (Language::Go, 4) | (Language::Rust, 3) => &[("source_occurrences", "occurrence_id")],
        (Language::Go, 5) | (Language::Rust, 4) => &[("source_imports", "import_id")],
        (Language::Go, 6) => &[("resolution_node_catalog", "local_key")],
        (Language::Rust, 5) => &[("resolution_node_catalog", "source_scope")],
        (Language::Rust, 7) => &[("source_rust_module_scopes", "ordinal")],
        (Language::Rust, 8) => &[("source_rust_module_routes", "ordinal")],
        (Language::Rust, 9) => &[("source_rust_item_macros", "ordinal")],
        (Language::Rust, 12) => &[("source_rust_import_targets", "ordinal")],
        (Language::Rust, 13) => &[("source_rust_inner_attributes", "ordinal")],
        (Language::Rust, 14) => &[("code_units", "unit_key")],
        (Language::Python, 0) => &[("resolution_binding_slots", "slot")],
        (Language::Python, 1) => &[("python_binding_imports", "import_site")],
        (Language::Python, 2) => &[("resolution_binding_events", "event")],
        _ => unreachable!("no Ref owner for {language:?} space {space}"),
    }
}

/// A referenced fact is absent from the owning relation in this blob.
#[derive(Debug, PartialEq, Eq)]
pub struct DanglingSurfaceRef {
    pub blob_id: i64,
    pub id_space: u32,
    pub dense_id: i64,
}
impl std::fmt::Display for DanglingSurfaceRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "dangling surface reference: {self:?}")
    }
}
impl std::error::Error for DanglingSurfaceRef {}

/// A relation's required membership identity is unknown in this publication.
/// In particular, an include with a NULL invocation must not disappear from
/// the fingerprint or acquire a made-up root/occurrence identity.
/// Nullable attachment references are different: their NULL value remains in
/// the admitted row and fingerprint, and consumers needing that attachment must
/// report it unknown rather than infer a scope from publication success.
#[derive(Debug)]
pub struct UnknownSurfaceOwner {
    pub relation: &'static str,
    pub blob_id: i64,
}
impl std::fmt::Display for UnknownSurfaceOwner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "unknown surface owner: {self:?}")
    }
}
impl std::error::Error for UnknownSurfaceOwner {}

fn is_refusal(error: &rusqlite::Error) -> bool {
    matches!(error, rusqlite::Error::UserFunctionError(cause) if cause.is::<DanglingSurfaceRef>() || cause.is::<UnknownSurfaceOwner>())
}

/// Compute and atomically replace this list's set. Absent facts have no set.
/// Callers replacing facts must delete *all* sets before publishing those facts.
/// A dangling Ref retires this blob's sets and returns UserFunctionError carrying
/// DanglingSurfaceRef. Other database errors roll back this operation.
pub fn ensure_surface_set(
    conn: &mut Connection,
    blob_id: i64,
) -> rusqlite::Result<Option<[u8; 32]>> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let result = compute_surface_set_tx(&tx, blob_id);
    if result.as_ref().err().is_none_or(is_refusal) {
        tx.commit()?;
    }
    result.map(|result| result.0)
}

/// Publish within the fact writer's transaction, so readers never see stale sets.
pub(super) fn ensure_surface_set_tx(
    tx: &rusqlite::Transaction<'_>,
    blob_id: i64,
) -> rusqlite::Result<(Option<[u8; 32]>, super::PersistedMutationCost)> {
    surface_publication_result(compute_surface_set_tx(tx, blob_id))
}

/// The writer already validated this exact publication in its transaction.
/// Reuse its parent scalars instead of selecting the blob again.
pub(super) fn ensure_surface_set_for_publication_tx(
    tx: &rusqlite::Transaction<'_>,
    publication: &super::SourcePublicationWitness,
) -> rusqlite::Result<(Option<[u8; 32]>, super::PersistedMutationCost)> {
    let key = publication.key();
    let Some(description) = description(&key.lang) else {
        return Ok((None, super::PersistedMutationCost::default()));
    };
    surface_publication_result(compute_surface_input_tx(
        tx,
        publication.blob_id(),
        &key.oid.to_string(),
        publication.generation().get(),
        description,
    ))
}

fn surface_publication_result(
    result: rusqlite::Result<(Option<[u8; 32]>, super::PersistedMutationCost)>,
) -> rusqlite::Result<(Option<[u8; 32]>, super::PersistedMutationCost)> {
    match result {
        Err(error) if is_refusal(&error) => {
            // The refused set was retired; keep the fact publication.
            Ok((None, super::PersistedMutationCost::default()))
        }
        result => result,
    }
}

fn surface_input(
    conn: &Connection,
    blob_id: i64,
) -> rusqlite::Result<Option<(String, i64, SurfaceDescription<'static>)>> {
    // Use the same scalar admission as Go fact readers, including current,
    // complete source and Go manifests and canonical source readiness. Metadata
    // and a complete resolution interior alone can survive a lost manifest.
    // The resolution bundle must also match this binary's producer and the
    // store's active producer; complete interiors can survive an epoch advance.
    let blob = conn
        .query_row(
            "SELECT blob_oid,generation,lang FROM blobs WHERE id=?1",
            [blob_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .optional()?;
    Ok(blob.and_then(|(oid, generation, language)| {
        description(&language).map(|description| (oid, generation, description))
    }))
}

fn compute_surface_set_tx(
    tx: &rusqlite::Transaction<'_>,
    blob_id: i64,
) -> rusqlite::Result<(Option<[u8; 32]>, super::PersistedMutationCost)> {
    let Some((oid, generation, description)) = surface_input(tx, blob_id)? else {
        return Ok((None, super::PersistedMutationCost::default()));
    };
    compute_surface_input_tx(tx, blob_id, &oid, generation, description)
}

/// Exercise alternate relation catalogs against the production fingerprint path.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn ensure_surface_set_for_relations(
    conn: &mut Connection,
    blob_id: i64,
    relations: &[Relation],
) -> rusqlite::Result<Option<[u8; 32]>> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let Some((oid, generation, description)) = surface_input(&tx, blob_id)? else {
        return Ok(None);
    };
    let result = compute_surface_input_tx(
        &tx,
        blob_id,
        &oid,
        generation,
        SurfaceDescription {
            relations,
            ..description
        },
    );
    if result.as_ref().err().is_none_or(is_refusal) {
        tx.commit()?;
    }
    result.map(|result| result.0)
}

type SurfaceIdentity = (i64, i64, Option<i64>, String, i64);

fn admitted_surface_identity(
    conn: &Connection,
    blob_id: i64,
    oid: &str,
    generation: i64,
    description: &SurfaceDescription<'_>,
) -> rusqlite::Result<Option<SurfaceIdentity>> {
    let identity = {
        conn.query_row(
            &format!(
                "SELECT b.generation,?4 AS source_facts_version,?3 AS go_source_version,
                             i.producer_epoch,m.publication_witness
                      FROM ({header}) admitted
                      JOIN blobs b ON b.id=admitted.id
                      JOIN blob_meta m ON m.blob_id=b.id
                      JOIN resolution_fragment_interiors i ON i.blob_id=b.id
                      JOIN resolution_producer_epochs active
                        ON active.lang=b.lang AND active.producer_epoch=i.producer_epoch
                      WHERE b.id=?5 AND i.publication_state='complete'
                        AND i.producer_epoch=?6
                        AND m.publication_witness IS NOT NULL",
                header = description.source_header
            ),
            params![
                oid,
                generation,
                description.header_version,
                description.source_version,
                blob_id,
                resolution_bundle_epoch(description.language)
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    description.auxiliary_version,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .optional()?
    };
    Ok(identity)
}

pub(super) fn member_has_admitted_facts(conn: &Connection, blob_id: i64) -> rusqlite::Result<bool> {
    let Some((oid, generation, description)) = surface_input(conn, blob_id)? else {
        return Ok(false);
    };
    Ok(admitted_surface_identity(conn, blob_id, &oid, generation, &description)?.is_some())
}

/// Fingerprint one blob. Its projection rows are staged only to be read, so
/// they are evicted again afterwards (success or refusal) unless the blob
/// belongs to the operation's published set; the rows an operation published
/// stay, and at most one transient blob is resident beyond them.
fn compute_surface_input_tx(
    tx: &rusqlite::Transaction<'_>,
    blob_id: i64,
    oid: &str,
    generation: i64,
    description: SurfaceDescription<'_>,
) -> rusqlite::Result<(Option<[u8; 32]>, super::PersistedMutationCost)> {
    let relations = description.relations;
    create_materialized_sources(tx, relations)?;
    let result = stage_and_fingerprint_tx(tx, blob_id, oid, generation, description);
    evict_transient_blob(tx, relations, blob_id)?;
    result
}

fn stage_and_fingerprint_tx(
    tx: &rusqlite::Transaction<'_>,
    blob_id: i64,
    oid: &str,
    generation: i64,
    description: SurfaceDescription<'_>,
) -> rusqlite::Result<(Option<[u8; 32]>, super::PersistedMutationCost)> {
    let relations = description.relations;
    let identity = admitted_surface_identity(tx, blob_id, oid, generation, &description)?;
    let Some((generation, facts, go, epoch, witness)) = identity else {
        tx.execute("DELETE FROM surface_sets WHERE blob_id=?1", [blob_id])?;
        return Ok((None, super::PersistedMutationCost::default()));
    };
    let digest = list_digest(relations);
    // Retire every list of stale facts; matching lists belong to other binaries
    // and must survive. The immediate transaction serializes concurrent writers.
    tx.execute(
        "DELETE FROM surface_sets WHERE blob_id=?1 AND (generation<>?2 OR source_facts_version<>?3 OR go_source_version IS NOT ?4 OR producer_epoch<>?5 OR publication_witness<>?6)",
        params![blob_id,generation,facts,go,epoch,witness],
    )?;
    if let Some(fingerprint) = tx
        .query_row(
            "SELECT fingerprint FROM surface_sets WHERE blob_id=?1 AND list_digest=?2",
            params![blob_id, digest],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?
    {
        let fingerprint = fingerprint
            .try_into()
            .expect("surface_sets constrains fingerprints to 32 bytes");
        return Ok((Some(fingerprint), super::PersistedMutationCost::default()));
    }
    create_source_views(tx, relations)?;
    if let Err(error) = publish_materialized_sources(tx, relations, &[blob_id]) {
        if is_refusal(&error) {
            tx.execute("DELETE FROM surface_sets WHERE blob_id=?1", [blob_id])?;
        }
        return Err(error);
    }
    let mut ids: BTreeMap<u32, BTreeSet<i64>> = BTreeMap::new();
    let mut rows = Vec::new();
    for r in relations {
        let (space, owner) = r.membership.parts();
        let cols = r
            .columns
            .iter()
            .map(|(c, _)| format!("b.{c}"))
            .collect::<Vec<_>>()
            .join(",");
        let seed = r.seed.unwrap_or("0");
        let mut stmt = tx.prepare(&format!(
            "SELECT b.{owner}, ({seed}), {cols} FROM {} b WHERE b.blob_id=?1",
            r.source.qualified_name(r.name)
        ))?;
        let values = stmt
            .query_map([blob_id], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, bool>(1)?,
                    (0..r.columns.len())
                        .map(|i| row.get::<_, Value>(i + 2))
                        .collect::<rusqlite::Result<Vec<_>>>()?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for (owner, seed, _) in &values {
            if *seed {
                // A seeded Member admits its structural owner, without giving
                // the member row an independent identity space.
                ids.entry(space).or_default().insert(*owner);
            }
        }
        rows.push(values);
    }
    let mut existing: BTreeMap<u32, BTreeSet<i64>> = BTreeMap::new();
    loop {
        let mut changed = false;
        for (r, rows) in relations.iter().zip(&rows) {
            let (space, _) = r.membership.parts();
            for (owner, _, values) in rows {
                if !ids.get(&space).is_some_and(|s| s.contains(owner)) {
                    continue;
                }
                for ((_, kind), value) in r.columns.iter().zip(values) {
                    if let (ColumnKind::Ref(s), Value::Integer(id)) = (kind, value)
                        && *id >= 0
                    {
                        let targets = match existing.entry(*s) {
                            std::collections::btree_map::Entry::Occupied(entry) => entry.into_mut(),
                            std::collections::btree_map::Entry::Vacant(entry) => {
                                let mut targets = BTreeSet::new();
                                for (table, column) in ref_owners(description.language, *s) {
                                    let mut statement = tx.prepare(&format!(
                                        "SELECT fact.{column},fact.blob_id,owner.generation FROM main.{table} fact JOIN main.blobs owner ON owner.id=fact.blob_id WHERE fact.blob_id=?1 AND fact.{column} IS NOT NULL"
                                    ))?;
                                    targets.extend(
                                        statement
                                            .query_map([blob_id], |row| {
                                                // Both owner tables reference the same blob publication:
                                                // no independent generation or contradictory kind/span
                                                // exists on gap provenance rows.
                                                #[cfg(any(debug_assertions, test))]
                                                {
                                                    assert_eq!(row.get::<_, i64>(1)?, blob_id);
                                                    assert_eq!(row.get::<_, i64>(2)?, generation);
                                                }
                                                row.get(0)
                                            })?
                                            .collect::<rusqlite::Result<BTreeSet<i64>>>()?,
                                    );
                                }
                                entry.insert(targets)
                            }
                        };
                        if !targets.contains(id) {
                            tx.execute("DELETE FROM surface_sets WHERE blob_id=?1", [blob_id])?;
                            return Err(rusqlite::Error::UserFunctionError(Box::new(
                                DanglingSurfaceRef {
                                    blob_id,
                                    id_space: *s,
                                    dense_id: *id,
                                },
                            )));
                        }
                        changed |= ids.entry(*s).or_default().insert(*id);
                    }
                }
            }
        }
        if !changed {
            break;
        }
    }
    let ranks: BTreeMap<_, _> = ids
        .iter()
        .flat_map(|(s, ids)| {
            ids.iter()
                .enumerate()
                .map(move |(rank, id)| ((*s, *id), rank as i64))
        })
        .collect();
    let mut h = CanonicalHasher::new(b"bifrost-surface-fingerprint:v1");
    h.value(&digest);
    for (r, rows) in relations.iter().zip(&rows) {
        h.value(r.name.as_bytes());
        let (space, _) = r.membership.parts();
        let mut canonical = Vec::new();
        for (owner, _, values) in rows {
            let Some(rank) = ranks.get(&(space, *owner)) else {
                continue;
            };
            let mut translated = vec![Value::Integer(*rank)];
            for ((_, kind), value) in r.columns.iter().zip(values) {
                match (kind, value) {
                    (ColumnKind::Excluded, _) => {}
                    (ColumnKind::Ref(s), Value::Integer(id)) if *id >= 0 => {
                        let rank = ranks
                            .get(&(*s, *id))
                            .expect("every surface Ref resolves after closure");
                        translated.push(Value::Integer(i64::from(*s)));
                        translated.push(Value::Integer(*rank));
                    }
                    (ColumnKind::IdentityRef, Value::Integer(id)) => {
                        let digest = tx.query_row(
                            "SELECT identity_digest FROM resolution_identities WHERE id=?1",
                            [id],
                            |r| r.get::<_, Vec<u8>>(0),
                        )?;
                        translated.push(Value::Blob(digest));
                    }
                    _ => translated.push(value.clone()),
                }
            }
            canonical.push(translated);
        }
        // Member rows have no own ID: owner rank then the full typed row gives a
        // deterministic multiset order, keeping duplicate rows in the fingerprint.
        let mut encoded = canonical
            .into_iter()
            .map(|row| {
                let mut bytes = Vec::new();
                for v in row {
                    match v {
                        Value::Null => bytes.push(0),
                        Value::Integer(n) => {
                            bytes.push(1);
                            bytes.extend(n.to_be_bytes());
                        }
                        Value::Real(n) => {
                            bytes.push(2);
                            bytes.extend(n.to_bits().to_be_bytes());
                        }
                        Value::Text(s) => {
                            bytes.push(3);
                            bytes.extend((s.len() as u64).to_be_bytes());
                            bytes.extend(s.as_bytes());
                        }
                        Value::Blob(b) => {
                            bytes.push(4);
                            bytes.extend((b.len() as u64).to_be_bytes());
                            bytes.extend(b);
                        }
                    }
                }
                bytes
            })
            .collect::<Vec<_>>();
        encoded.sort();
        h.value(&(encoded.len() as u64).to_be_bytes());
        for row in encoded {
            hash_value(&mut h, &Value::Blob(row));
        }
    }
    let fingerprint = h.finish();
    tx.execute("INSERT INTO surface_sets(blob_id,generation,source_facts_version,go_source_version,producer_epoch,publication_witness,list_digest,fingerprint) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",params![blob_id,generation,facts,go,epoch,witness,digest,fingerprint])?;
    let cost = super::PersistedMutationCost {
        logical_rows: 1 + ranks.len(),
        payload_bytes: epoch.len() + 64,
    };
    let set = tx.last_insert_rowid();
    for ((space, id), rank) in ranks {
        tx.execute(
            "INSERT INTO surface_ids VALUES(?1,?2,?3,?4)",
            params![set, space, id, rank],
        )?;
    }
    Ok((Some(fingerprint), cost))
}

// Core validates this schema at cache_db.rs:3223 (current_schema_shape_is_valid).
#[cfg(any(test, feature = "test-support"))]
static FENCE_SCHEMA: std::sync::LazyLock<(BTreeSet<String>, BTreeSet<String>)> =
    std::sync::LazyLock::new(|| {
        let conn = Connection::open_in_memory().expect("open fence schema inventory");
        conn.execute_batch(include_str!(
            "../../../../bifrost-core/migrations/cache/current-schema.sql"
        ))
        .expect("create fence schema inventory");
        let tables = conn.prepare("SELECT name FROM main.sqlite_schema AS schema WHERE type='table' AND name NOT IN ('surface_sets','surface_ids') AND EXISTS(SELECT 1 FROM pragma_table_info(schema.name) WHERE name='blob_id')").unwrap().query_map([], |row| row.get(0)).unwrap().collect::<rusqlite::Result<BTreeSet<String>>>().unwrap();
        let views = conn
            .prepare("SELECT name FROM main.sqlite_schema WHERE type='view'")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<rusqlite::Result<BTreeSet<String>>>()
            .unwrap();
        (tables, views)
    });

#[cfg(any(test, feature = "test-support"))]
fn catalog_source_views(relations: &[Relation]) -> BTreeSet<String> {
    FENCE_SCHEMA.1.iter().filter(|name| relations.iter().any(|relation| matches!(relation.source, RelationSource::Table(source) if source == name.as_str()))).cloned().collect()
}

/// Deny direct reads of catalog relation sources while allowing generated views.
#[cfg(any(test, feature = "test-support"))]
pub fn install_surface_authorizer(
    conn: &Connection,
    relations: &'static [Relation],
) -> rusqlite::Result<()> {
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
    // A relation source can be a catalog view: source_occurrences,
    // source_rust_import_targets and source_rust_import_module_segments are
    // views, not base tables. FENCE_SCHEMA records the production catalog, so
    // a fixture that materializes a source as a table would otherwise fall
    // outside the denied set. Name every relation source explicitly.
    let denied: BTreeSet<String> = FENCE_SCHEMA
        .0
        .iter()
        .cloned()
        .chain(
            relations
                .iter()
                .filter_map(|relation| match relation.source {
                    RelationSource::Table(source) => Some(source.to_owned()),
                    RelationSource::Materialized(_) => Some(format!("{}_source", relation.name)),
                    RelationSource::Derived(_) => None,
                }),
        )
        .collect();
    // SQLite reports the innermost view as accessor. It cannot distinguish
    // a direct source-view read from a generated surface view using that view.
    // derivation_sql_uses_only_generated_source_views checks the direct case.
    let source_views = catalog_source_views(relations);
    super::connection_authorizer::compose_guard(conn, move |context: AuthContext<'_>| {
        if let AuthAction::Read { table_name, .. } = context.action
            && denied.contains(table_name)
            && !context.accessor.is_some_and(|accessor| {
                source_views.contains(accessor)
                    || relations.iter().any(|relation| accessor == relation.name)
            })
        {
            return Authorization::Deny;
        }
        Authorization::Allow
    })
}

/// Scope the test-only derivation read fence to the deriving connection.
#[cfg(any(test, feature = "test-support"))]
pub(super) struct SurfaceReadGuard<'a> {
    _restore: super::connection_authorizer::Restore<'a>,
}

#[cfg(any(test, feature = "test-support"))]
impl<'a> SurfaceReadGuard<'a> {
    pub(super) fn new(
        conn: &'a Connection,
        relations: &'static [Relation],
    ) -> rusqlite::Result<Self> {
        conn.flush_prepared_statement_cache();
        let restore = super::connection_authorizer::restore_guard_on_drop(conn);
        install_surface_authorizer(conn, relations)?;
        Ok(Self { _restore: restore })
    }
}

#[cfg(test)]
mod summary_translation_tests {
    use super::*;

    #[test]
    fn selected_member_witness_rejects_null_and_translates_mount_dense_ids() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE blobs(id INTEGER PRIMARY KEY, blob_oid TEXT, lang TEXT, parse_variant BLOB, generation INTEGER);
             CREATE TABLE resolution_unit_summaries(summary_id INTEGER PRIMARY KEY, lang TEXT);
             CREATE TABLE resolution_unit_summary_members(summary_id INTEGER, member_ordinal INTEGER, rel_path TEXT,
               member_surface_fingerprint BLOB, member_no_facts_oid TEXT, PRIMARY KEY(summary_id,member_ordinal)) WITHOUT ROWID;
             CREATE TABLE workspace_file_versions(file_version_id INTEGER PRIMARY KEY, workspace_id TEXT, lang TEXT,
               generation INTEGER, input_kind TEXT, rel_path TEXT, blob_oid TEXT, valid_from INTEGER, valid_until INTEGER);
             CREATE TABLE csharp_file_version_decisions(file_version_id INTEGER PRIMARY KEY, decision_digest BLOB);
             CREATE TEMP TABLE selected_workspace_file_versions(lang TEXT, rel_path TEXT, blob_oid TEXT, parse_variant BLOB, generation INTEGER);
             CREATE TEMP TABLE selected_go_transient_placements(mount_ordinal INTEGER PRIMARY KEY, file_version_id INTEGER);
             CREATE TEMP TABLE selected_resolution_mounts(mount_ordinal INTEGER PRIMARY KEY, storage_language TEXT, persisted_relative_path TEXT,
               blob_id INTEGER, file_version_id INTEGER, UNIQUE(storage_language,persisted_relative_path));
             INSERT INTO resolution_unit_summaries VALUES(1,'python');
             INSERT INTO resolution_unit_summary_members VALUES(1,0,'client.py',NULL,NULL);
             INSERT INTO blobs VALUES(1,'old','python',x'',1),(2,'new','python',x'',1),(3,'missing','python',x'',1);
             INSERT INTO workspace_file_versions VALUES(1,'workspace','python',1,'source','client.py','old',1,NULL);
             INSERT INTO selected_workspace_file_versions VALUES('python','client.py','old',x'',1);
             INSERT INTO selected_resolution_mounts VALUES(0,'python','client.py',1,1);",
        ).unwrap();
        conn.execute_batch(include_str!(
            "../../../../bifrost-core/migrations/cache/0316-surface-relations.sql"
        ))
        .unwrap();
        let digest = surface_list_digest("python");
        for blob in [1, 2] {
            conn.execute(
                "INSERT INTO surface_sets VALUES(?1,?1,1,1,NULL,'epoch',1,?2,zeroblob(32))",
                params![blob, digest.as_slice()],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO surface_ids VALUES(?1,1,?2,0)",
                params![blob, blob * 10],
            )
            .unwrap();
        }
        create_summary_translation_views(&conn).unwrap();
        let current = members_current_sql("python", "1", "'workspace'", "1", "1");
        let current = format!("SELECT {current}");
        assert!(
            !conn
                .query_row(&current, [], |r| r.get::<_, bool>(0))
                .unwrap()
        );
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM selected_unit_member_mounts",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
        conn.execute_batch(
            "UPDATE resolution_unit_summary_members SET member_surface_fingerprint=zeroblob(32)",
        )
        .unwrap();
        assert!(
            conn.query_row(&current, [], |r| r.get::<_, bool>(0))
                .unwrap()
        );
        let dense = "SELECT dense.dense_id FROM selected_unit_member_mounts member JOIN surface_dense dense
          ON dense.blob_id=member.blob_id AND dense.id_space=1 AND dense.surface_ordinal=0 WHERE member.summary_id=1 AND member.member_ordinal=0";
        assert_eq!(
            conn.query_row(dense, [], |r| r.get::<_, i64>(0)).unwrap(),
            10
        );
        conn.execute_batch("UPDATE selected_resolution_mounts SET blob_id=2,file_version_id=NULL")
            .unwrap();
        assert_eq!(
            conn.query_row(dense, [], |r| r.get::<_, i64>(0)).unwrap(),
            20
        );
        // Exercise the production bare-B reader with a mount-local import ID.
        // Equal fingerprints preserve ordinal zero, not dense IDs 10 and 20.
        conn.execute_batch("CREATE TABLE python_unit_summary_imports(summary_id INTEGER,member_ordinal INTEGER,import_surface_ordinal INTEGER,
          importer_container TEXT,target_container TEXT,module_name TEXT,relative_level INTEGER,requested_name TEXT,bound_name TEXT,form TEXT,state TEXT);
          CREATE TABLE resolution_root_import_segments(blob_id INTEGER,import_site INTEGER);
          CREATE TABLE resolution_import_selectors(blob_id INTEGER,site INTEGER,source_name TEXT);
          CREATE TABLE python_unit_summary_providers(summary_id INTEGER,container_path TEXT,module_name TEXT,root_slot INTEGER,state TEXT);
          CREATE TABLE python_unit_summary_spellings(summary_id INTEGER,source_root TEXT,module_name TEXT,target_container TEXT,admitted INTEGER);
          INSERT INTO python_unit_summary_imports VALUES(1,0,0,'client','model','model',0,'pick','pick','from','activation_open')").unwrap();
        let route = super::super::resolution_operation::python_demand::PYTHON_IMPORT_STARTS_SQL;
        assert_eq!(
            conn.query_row(route, params![1, "client", 20, 2], |row| row
                .get::<_, String>(0))
                .unwrap(),
            "model"
        );
        assert!(
            conn.query_row(route, params![1, "client", 10, 2], |row| row
                .get::<_, String>(0))
                .optional()
                .unwrap()
                .is_none()
        );
        conn.execute_batch("UPDATE selected_resolution_mounts SET blob_id=3")
            .unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM selected_unit_member_mounts",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
        conn.execute_batch("UPDATE selected_resolution_mounts SET blob_id=2; UPDATE surface_sets SET fingerprint=randomblob(32) WHERE blob_id=2").unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM selected_unit_member_mounts",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
        assert_eq!(
            conn.query_row("SELECT count(*) FROM selected_unit_member_paths", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            1
        );
        // No-facts OIDs cover only the same content, with no current surface set.
        conn.execute_batch("DELETE FROM surface_sets WHERE blob_id=1;
          UPDATE resolution_unit_summary_members SET member_surface_fingerprint=NULL,member_no_facts_oid='old';
          UPDATE selected_resolution_mounts SET blob_id=1,file_version_id=1").unwrap();
        assert!(
            conn.query_row(&current, [], |r| r.get::<_, bool>(0))
                .unwrap()
        );
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM selected_unit_member_mounts",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            1
        );
        conn.execute_batch("UPDATE selected_resolution_mounts SET blob_id=2,file_version_id=NULL")
            .unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM selected_unit_member_mounts",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#11183: nested catalog source views must be fenced without admitting direct derivation reads"
    )]
    fn derivation_sql_uses_only_generated_source_views() {
        for (relations, sql_source) in [
            (GO_RELATIONS, include_str!("go_unit_summaries.rs")),
            (PYTHON_RELATIONS, include_str!("python_unit_summaries.rs")),
        ] {
            for view in catalog_source_views(relations) {
                // Checking the whole module includes every SQL constant and
                // format string executed by stage, inputs, and derive.
                assert!(
                    !sql_source.contains(&view),
                    "derivation SQL directly names catalog view {view}"
                );
            }
        }
    }

    #[test]
    fn summary_bridges_select_current_blob_and_current_surface_list() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE blobs(id INTEGER PRIMARY KEY, blob_oid TEXT, lang TEXT,
                parse_variant BLOB, generation INTEGER, UNIQUE(blob_oid,lang,parse_variant));
             CREATE TABLE resolution_unit_summaries(summary_id INTEGER PRIMARY KEY, lang TEXT);
             CREATE TABLE resolution_unit_summary_members(summary_id INTEGER, member_ordinal INTEGER,
                rel_path TEXT, PRIMARY KEY(summary_id,member_ordinal)) WITHOUT ROWID;
             CREATE TEMP TABLE selected_workspace_file_versions(lang TEXT, rel_path TEXT, blob_oid TEXT,
                parse_variant BLOB, generation INTEGER, PRIMARY KEY(lang,rel_path)) WITHOUT ROWID;",
        ).unwrap();
        conn.execute_batch(include_str!(
            "../../../../bifrost-core/migrations/cache/0316-surface-relations.sql"
        ))
        .unwrap();
        create_summary_translation_views(&conn).unwrap();
        create_summary_translation_views(&conn).unwrap();
        let digest = list_digest(GO_RELATIONS);
        for unit in 1..=4_i64 {
            conn.execute(
                "INSERT INTO resolution_unit_summaries VALUES(?1,'go')",
                [unit],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO resolution_unit_summary_members VALUES(?1,0,?2)",
                params![unit, format!("{unit}.go")],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO blobs VALUES(?1,?2,'go',x'',1)",
                params![unit, format!("oid{unit}")],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO selected_workspace_file_versions VALUES('go',?1,?2,x'',1)",
                params![format!("{unit}.go"), format!("oid{unit}")],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO surface_sets VALUES(?1,?1,1,1,NULL,'epoch',1,?2,zeroblob(32))",
                params![unit, digest.as_slice()],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO surface_ids VALUES(?1,0,?2,0)",
                params![unit, unit * 10],
            )
            .unwrap();
        }
        assert_eq!(
            super::super::unit_summaries::member_input_selected(&conn, "go", 1, "oid1").unwrap(),
            Some(
                super::super::unit_summaries::member_input_for_derivation(&conn, "go", 1, "oid1")
                    .unwrap()
            )
        );
        // A retained set from a different binary must never supply a translation.
        conn.execute(
            "INSERT INTO surface_sets VALUES(5,1,1,1,NULL,'epoch',1,zeroblob(32),zeroblob(32))",
            [],
        )
        .unwrap();
        conn.execute("INSERT INTO surface_ids VALUES(5,0,999,0)", [])
            .unwrap();
        let read = || {
            conn.query_row(
                "SELECT dense_id FROM selected_unit_member_blobs AS members
             JOIN surface_dense AS ids ON ids.blob_id=members.blob_id
             WHERE summary_id=1 AND member_ordinal=0 AND id_space=0 AND surface_ordinal=0",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap()
        };
        assert_eq!(read(), 10);
        // Keeping the summary while selecting new file facts rebinds coordinates.
        conn.execute(
            "UPDATE selected_workspace_file_versions SET blob_oid='oid2' WHERE rel_path='1.go'",
            [],
        )
        .unwrap();
        assert_eq!(read(), 20);
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#11581: the member bridge silently yielded no rows without the summary header and selected revision"
    )]
    fn selected_member_bridge_requires_the_summary_header_and_selected_revision() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE blobs(id INTEGER PRIMARY KEY, blob_oid TEXT, lang TEXT,
                parse_variant BLOB, generation INTEGER, UNIQUE(blob_oid,lang,parse_variant));
             CREATE TABLE workspace_file_versions(
                file_version_id INTEGER PRIMARY KEY, workspace_id TEXT NOT NULL,
                lang TEXT NOT NULL, generation INTEGER NOT NULL, rel_path TEXT NOT NULL,
                blob_oid TEXT NOT NULL, projection_digest TEXT,
                input_kind TEXT NOT NULL DEFAULT 'source', valid_from INTEGER NOT NULL,
                valid_until INTEGER);
             CREATE TABLE csharp_file_version_decisions(
                file_version_id INTEGER PRIMARY KEY, decision_digest BLOB);
             CREATE TABLE resolution_unit_summaries(summary_id INTEGER PRIMARY KEY, lang TEXT NOT NULL);
             CREATE TABLE resolution_unit_summary_members(summary_id INTEGER, member_ordinal INTEGER,
                rel_path TEXT, PRIMARY KEY(summary_id,member_ordinal)) WITHOUT ROWID;",
        )
        .unwrap();
        crate::analyzer::store::ensure_revisioned_workspace_views(&conn).unwrap();
        let workspace = "a".repeat(64);
        let oid = "0".repeat(40);
        conn.execute(
            "INSERT INTO temp.selected_workspace_revisions VALUES(?1,'python',0,1)",
            [&workspace],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO resolution_unit_summaries VALUES(1,'python')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO resolution_unit_summary_members VALUES(1,0,'pkg/model.py')",
            [],
        )
        .unwrap();
        conn.execute("INSERT INTO blobs VALUES(1,?1,'python',x'',0)", [&oid])
            .unwrap();
        conn.execute(
            "INSERT INTO workspace_file_versions(file_version_id,workspace_id,lang,generation,rel_path,blob_oid,projection_digest,input_kind,valid_from)
             VALUES(1,?1,'python',0,'pkg/model.py',?2,?3,'source',1)",
            params![workspace, oid, "0".repeat(64)],
        )
        .unwrap();
        let count = || {
            conn.query_row(
                "SELECT count(*) FROM selected_unit_member_blobs WHERE summary_id=1",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap()
        };
        assert_eq!(
            count(),
            1,
            "the header and selected revision must translate the member"
        );
        conn.execute("DELETE FROM resolution_unit_summaries", [])
            .unwrap();
        assert_eq!(
            count(),
            0,
            "a member without its summary header has no blob translation"
        );
        conn.execute(
            "INSERT INTO resolution_unit_summaries VALUES(1,'python')",
            [],
        )
        .unwrap();
        conn.execute("DELETE FROM temp.selected_workspace_revisions", [])
            .unwrap();
        assert_eq!(
            count(),
            0,
            "a member without a selected revision has no blob translation"
        );
    }
}

#[cfg(test)]
mod lexical_owner_plan_tests {
    use brokk_bifrost_core::cache_gc::PlannerStatisticsState;
    use brokk_bifrost_test_macros::hardwon;

    use super::super::AnalyzerStore;
    use super::super::planner_statistics::pinned_plans::{
        explain_pin, pinned, prepare_pin_context,
    };

    #[test]
    #[hardwon("#14394: lexical-owner hops scanned every blob path per hop and stalled a cold warm")]
    fn lexical_owner_hops_seek_paths_by_start_node() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let conn = store.conn.lock().unwrap();
        store
            .select_writer_workspace_snapshots(&conn, &Default::default())
            .unwrap();
        prepare_pin_context(&conn);
        let query = pinned("surface_rust_lexical_owners");
        for state in PlannerStatisticsState::BOTH {
            state.install(&conn);
            let plan = explain_pin(&conn, &query);
            // The base and recursive hop steps each read one node's paths. A
            // blob-wide path range inside the recursion is quadratic per file.
            let path_steps = plan
                .iter()
                .filter(|step| step.starts_with("SEARCH path ") || step.starts_with("SCAN path"))
                .collect::<Vec<_>>();
            assert_eq!(path_steps.len(), 2, "{state:?}: {plan:?}");
            for step in path_steps {
                assert!(
                    step.contains("resolution_paths_forward (blob_id=? AND start_node=?"),
                    "{state:?}: {step} in {plan:?}"
                );
            }
        }
    }
}
