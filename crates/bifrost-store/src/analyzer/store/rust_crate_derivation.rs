//! SQL derivation of a single missing topology on its worker's reader.
use super::*;
use brokk_bifrost_core::analyzer::rust_facts::{RustVisibility, decode_rust_visibility};
use rusqlite::types::Value;

#[path = "rust_crate_binding_authority.rs"]
mod binding_authority;
#[path = "rust_crate_binding_relation.rs"]
#[doc(hidden)]
pub mod binding_relation;

#[doc(hidden)]
pub const RESTRICTION_INPUTS_SQL: &str = include_str!("rust_crate_visibility_inputs.sql");
#[doc(hidden)]
pub const RESTRICTIONS_SQL: &str = include_str!("rust_crate_visibility_routes.sql");
pub(super) const CONSTRUCTOR_VISIBILITIES_SQL: &str =
    include_str!("rust_crate_constructor_visibility.sql");
pub(super) const RESTRICTION_GAPS_SQL: &str = "INSERT INTO cr_gaps
 SELECT 'unresolved_visibility', module_path,
 json_object('visibility', visibility, 'reason', 'UnresolvedVisibility')
 FROM cr_restrictions WHERE restricted_module_path IS NULL";

#[doc(hidden)]
pub const DECLARATIONS_SQL: &str = include_str!("rust_crate_export_declarations.sql");
#[doc(hidden)]
pub const SOURCE_DECLARATIONS_SQL: &str = include_str!("rust_crate_source_declarations.sql");
pub(super) const MACRO_ITEMS_SQL: &str = include_str!("rust_crate_macro_items.sql");
/// The active, declarable candidates of `rust_crate_macro_items.sql` become
/// crate rows: one per item, and a tuple or unit struct's value constructor as
/// a second row in the value namespace.
pub(super) const MACRO_ITEM_ROWS_SQL: &str = "INSERT INTO cr_macro_items(module_path, namespace,
  name, visibility, restricted_module_path, blob_id, invocation_occurrence_id, declaration_id,
  module_item)
 SELECT module_path, CASE WHEN declaration_kind IN (6, 10, 11) THEN 'value' ELSE 'type' END,
        name, visibility, restricted_module_path, blob_id, invocation_occurrence_id,
        declaration_id, declaration_kind IN (4, 5)
 FROM cr_macro_item_candidates WHERE declarable = 1 AND activation = 1
 UNION ALL
 SELECT candidate.module_path, 'value', candidate.name, constructor.visibility,
        constructor.restricted_module_path, candidate.blob_id,
        candidate.invocation_occurrence_id, candidate.declaration_id, 0
 FROM cr_macro_item_candidates AS candidate
 CROSS JOIN cr_constructor_visibilities AS constructor
   ON constructor.module_path = candidate.module_path
  AND constructor.blob_id = candidate.blob_id
  AND constructor.declaration_id = candidate.declaration_id
 WHERE candidate.declarable = 1 AND candidate.activation = 1
   AND candidate.declaration_kind = 0 AND candidate.value_constructor = 1
   AND constructor.visibility IS NOT NULL
 ON CONFLICT DO NOTHING";
pub(super) const MACRO_ITEM_COVERAGE_SQL: &str = include_str!("rust_crate_macro_item_coverage.sql");
pub(super) const SELECT_MACRO_ITEMS_SQL: &str = "SELECT module_path, namespace, name, visibility, restricted_module_path, blob_id, invocation_occurrence_id, declaration_id, module_item FROM cr_macro_items ORDER BY module_path, namespace, name, blob_id, declaration_id";
pub(super) const INSERT_MACRO_ITEMS_SQL: &str =
    "INSERT INTO rust_crate_macro_items VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)";
/// A public item a decided macro declares is part of what a dependent sees.
pub(super) const MACRO_ITEM_SURFACE_SQL: &str = "SELECT module_path, namespace, name FROM cr_macro_items WHERE visibility = 'public' ORDER BY 1, 2, 3";
const ROUTE_WALK_SQL: &str = include_str!("rust_crate_route_walk.sql");
fn route_walk(sources: &str, segments: &str, key: &str, output: &str) -> String {
    ROUTE_WALK_SQL
        .replace("{sources}", sources)
        .replace("{segments}", segments)
        .replace("{key}", key)
        .replace("{output}", output)
}
#[doc(hidden)]
pub static ROUTES_SQL: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    route_walk(
        "cr_source_imports",
        "source_rust_import_module_segments",
        "import_ordinal",
        "cr_routes",
    )
});
pub(super) static ROOT_ROUTES_SQL: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    route_walk(
        "cr_root_sources",
        "cr_root_segments",
        "route_key",
        "cr_root_routes",
    )
});
#[doc(hidden)]
pub const ROOT_SOURCES_SQL: &str = include_str!("rust_crate_root_sources.sql");
pub(super) const PUBLIC_SURFACE_BINDINGS_SQL: &str = include_str!("rust_crate_public_surface.sql");
const PUBLIC_SURFACE_ALIAS_TEMPLATE: &str = include_str!("rust_crate_public_surface_aliases.sql");
fn public_surface_aliases(
    frontier: &str,
    output: &str,
    owner_columns: &str,
    name_predicate: &str,
    origin_column: &str,
) -> String {
    PUBLIC_SURFACE_ALIAS_TEMPLATE
        .replace("{frontier}", frontier)
        .replace("{output}", output)
        .replace("{owner_columns}", owner_columns)
        .replace("{name_predicate}", name_predicate)
        .replace("{origin_column}", origin_column)
}
pub(super) static PUBLIC_SURFACE_ALIASES_SQL: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| {
        public_surface_aliases("cr_surface_frontier", "cr_surface_aliases", "", "", "")
    });
pub(super) const PUBLIC_SURFACE_LOOKUP_SQL: &str =
    include_str!("rust_crate_public_surface_lookup.sql");
pub(super) static PUBLIC_SURFACE_LOOKUP_ALIASES_SQL: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| {
        public_surface_aliases(
            "cr_surface_pending",
            "cr_surface_lookup",
            "demand.owner_crate_key, demand.owner_module_path, demand.owner_namespace, demand.owner_name, ",
            "AND demand.owner_namespace = 'type' AND routes.bound_name = demand.name",
            ", 'reexport'",
        )
    });
pub(super) const PUBLIC_SURFACE_CANDIDATES_SQL: &str =
    include_str!("rust_crate_public_surface_candidates.sql");
pub(super) const PUBLIC_SURFACE_GLOBS_SQL: &str =
    include_str!("rust_crate_public_surface_globs.sql");
pub(super) const PUBLIC_SURFACE_TERMINALS_SQL: &str =
    include_str!("rust_crate_public_surface_terminals.sql");
pub(super) const PUBLIC_SURFACE_NAMED_REQUESTS_SQL: &str =
    include_str!("rust_crate_public_surface_named_requests.sql");
pub(super) const PUBLIC_SURFACE_PRUNE_TERMINALS_SQL: &str =
    include_str!("rust_crate_public_surface_prune_terminals.sql");
pub(super) const PUBLIC_SURFACE_FACTS_SQL: &str =
    include_str!("rust_crate_public_surface_facts.sql");
pub(super) const PUBLIC_SURFACE_INVENTORIES_SQL: &str =
    include_str!("rust_crate_public_surface_inventories.sql");
pub(super) const PUBLIC_SURFACE_GAPS_SQL: &str = include_str!("rust_crate_public_surface_gaps.sql");
pub(super) const PUBLIC_SURFACE_REACHABILITY_SQL: &str =
    include_str!("rust_crate_public_surface_reachability.sql");
pub(super) const INSERT_PUBLIC_MODULE_REACHABILITY_SQL: &str = "INSERT INTO rust_crate_public_module_reachability(topology_id, target_crate_key, target_module_path) VALUES(?1,?2,?3)";
pub(super) const PUBLIC_SURFACE_SELECT_SQL: &str = "SELECT kind, crate_key, module_path,
    namespace, name, target_crate_key, target_module_path FROM cr_surface_facts
    ORDER BY kind, crate_key, module_path, namespace, name, target_crate_key, target_module_path";

#[doc(hidden)]
pub static IMPL_SOURCES_SQL: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    placed_impl_sources_sql(include_str!("rust_crate_trait_impl_sources.sql"))
});
static INHERENT_IMPL_SOURCES_SQL: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    placed_impl_sources_sql(include_str!("rust_crate_inherent_impl_sources.sql"))
});

// Both header forms use exactly the same innermost-module placement rule.
fn placed_impl_sources_sql(template: &str) -> String {
    template.replace(
        "{placement}",
        r#"WHERE subject.impl_start_byte >= members.start_byte
  AND subject.impl_end_byte <= members.end_byte
  AND NOT EXISTS(SELECT 1 FROM cr_scopes AS inner_module
      WHERE inner_module.blob_id=members.blob_id
        AND inner_module.scope_ordinal<>members.scope_ordinal
        AND inner_module.start_byte>=members.start_byte
        AND inner_module.end_byte<=members.end_byte
        AND subject.impl_start_byte>=inner_module.start_byte
        AND subject.impl_end_byte<=inner_module.end_byte)"#,
    )
}
pub(super) static IMPL_SUBJECT_ROUTES_SQL: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| {
        route_walk(
            "cr_impl_sources",
            "cr_impl_subject_segments",
            "relation_key",
            "cr_impl_subject_routes",
        )
    });
pub(super) static IMPL_TRAIT_ROUTES_SQL: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| {
        route_walk(
            "cr_impl_sources",
            "cr_impl_trait_segments",
            "relation_key",
            "cr_impl_trait_routes",
        )
    });
const IMPL_BINDINGS_SQL: &str = include_str!("rust_crate_trait_impl_bindings.sql");
// A bare name a glob import brings in. Weaker than a named import and than the
// module's own declaration, so it runs after them and fills only what they
// left unbound.
//
// A glob brings in every name the module it reaches can name and the importer
// can see, and that includes the reached module's own `use` bindings, not only
// its items and re-exports. A private `use` is in scope in the module that
// writes it and in every module below it, so `mod tests { use super::*; }`
// names what its parent imported, privately, by a named `use` or by a glob of
// its own. `cr_exports` carries only a module's items and its non-private
// re-exports, so the reached module's private bindings are read here: its
// named imports from `cr_imports`, and its globs by following them in turn.
// Both apply only while the impl's module is the reached module or below it,
// which also bounds the chase: it climbs the impl module's own ancestors and
// the globs they wrote, and `UNION` visits each reached module once.
//
// A glob binds a name only when the globs in scope agree about which
// declaration it names. `use a::*; use b::*;` where both export `Runnable`
// leaves `Runnable` ambiguous, and Rust rejects a use of it; binding one of
// them because it happened to be inserted first would make the relation claim
// an implementation the compiler does not accept. Distinctness is on the
// declaration, not on the (crate, module, name) triple, so a type reached
// through its own module and through a re-export of it is still one candidate.
// The triple the binding keeps is the bare columns of the group, which SQLite
// evaluates against one row of it, so it is always a triple some candidate
// holds; every candidate in an agreeing group names the same declaration, which
// is all the declaration statement reads from it.
#[cfg(any(test, feature = "test-support"))]
const IMPL_GLOB_BINDINGS_SQL: &str = "INSERT OR IGNORE INTO cr_impl_bindings
    WITH RECURSIVE reach(blob_id, relation_key, module_path, name, crate_key, reached) AS (
      SELECT source.blob_id, source.relation_key, source.module_path, source.{name},
             globs.target_crate_key, globs.target_module_path
      FROM cr_impl_sources AS source
      CROSS JOIN cr_globs AS globs ON globs.module_path=source.module_path
      WHERE source.{segments} = 0
        AND NOT EXISTS(SELECT 1 FROM cr_impl_bindings AS bound
                       WHERE bound.blob_id=source.blob_id AND bound.relation_key=source.relation_key
                         AND bound.module_path=source.module_path AND bound.side='{side}')
      UNION
      SELECT reach.blob_id, reach.relation_key, reach.module_path, reach.name,
             globs.target_crate_key, globs.target_module_path
      FROM reach
      CROSS JOIN cr_globs AS globs ON globs.module_path=reach.reached
      WHERE reach.crate_key=(SELECT crate_key FROM cr_identity)
        AND (reach.module_path=reach.reached
             OR substr(reach.module_path,1,length(reach.reached)+2)=reach.reached || '::')
    ),
    candidates(blob_id, relation_key, module_path, crate_key, export_module_path, export_name,
               declaration_blob_id, declaration_site) AS (
      SELECT reach.blob_id, reach.relation_key, reach.module_path,
             exports.crate_key, exports.module_path, exports.name,
             exports.declaration_blob_id, exports.declaration_site
      FROM reach
      CROSS JOIN cr_exports AS exports ON exports.crate_key=reach.crate_key
        AND exports.module_path=reach.reached
        AND exports.namespace='type' AND exports.name=reach.name
      UNION
      SELECT reach.blob_id, reach.relation_key, reach.module_path,
             exports.crate_key, exports.module_path, exports.name,
             exports.declaration_blob_id, exports.declaration_site
      FROM reach
      CROSS JOIN cr_imports AS imports ON imports.module_path=reach.reached
        AND imports.namespace='type' AND imports.bound_name=reach.name
      CROSS JOIN cr_exports AS exports ON exports.crate_key=imports.target_crate_key
        AND exports.module_path=imports.target_module_path
        AND exports.namespace='type' AND exports.name=imports.target_name
      WHERE reach.crate_key=(SELECT crate_key FROM cr_identity)
        AND (reach.module_path=reach.reached
             OR substr(reach.module_path,1,length(reach.reached)+2)=reach.reached || '::')
    )
    SELECT blob_id, relation_key, module_path, '{side}',
           crate_key, export_module_path, export_name
    FROM candidates
    GROUP BY blob_id, relation_key, module_path
    HAVING count(DISTINCT declaration_blob_id || ':' || declaration_site) = 1";
// A half of an impl header that bound nothing. The detail names which half
// failed, the name it spelled, and the container its route reached, read from
// the derived topology row rather than from the path text.
const IMPL_GAPS_SQL: &str = "INSERT INTO cr_gaps
    SELECT 'unresolved_trait_impl', source.module_path || '::' || source.{name},
           json_patch(
             json_object('side', '{side}', 'spelling', source.{name},
                         'impl_site', source.impl_site),
             COALESCE(
               (SELECT json_object('reason', 'bound_without_declaration',
                                   'bound_module_path', binding.target_module_path,
                                   'bound_name', binding.target_name)
                FROM cr_impl_bindings AS binding
                WHERE binding.blob_id=source.blob_id
                  AND binding.relation_key=source.relation_key
                  AND binding.module_path=source.module_path
                  AND binding.side='{side}'),
               json_patch(
                 json_object('reason', 'unbound'),
                 COALESCE((SELECT json_patch(
                              json_object('target_module_path', route.target_module_path),
                              COALESCE((SELECT json_object('target_crate', dependency.crate_name)
                                        FROM cr_foreign AS dependency
                                        WHERE dependency.crate_key=route.target_crate_key),
                                       json_object()))
                           FROM {routes} AS route
                           WHERE route.blob_id=source.blob_id
                             AND route.relation_key=source.relation_key
                             AND route.module_path=source.module_path), json_object()))))
    FROM cr_impl_sources AS source
    WHERE source.trait_name IS NOT NULL
      AND NOT EXISTS(SELECT 1 FROM cr_impl_declarations AS declaration
                     WHERE declaration.blob_id=source.blob_id
                       AND declaration.relation_key=source.relation_key
                       AND declaration.module_path=source.module_path
                       AND declaration.side='{side}')";
/// Every `impl Trait for Type` that did not become a `rust_crate_trait_impls`
/// row, spelled from both sides, as rows a query can seek.
///
/// The gap row `IMPL_GAPS_SQL` writes stays: it carries the whole evidence
/// array, including the bound name and target crate, and it is what a
/// diagnostic prints. This projection carries what a question asks by -- the
/// spelling -- so that "is anything spelled `Display` unbound?" is an index
/// seek instead of a scan that parses every gap's JSON.
///
/// Both sides are recorded whenever *either* side fails, which is what makes
/// the reader's question answerable. A trait whose impl resolved on the trait
/// side but not the subject side is still a trait whose implementations
/// cannot be enumerated, and that impl contributes no relation row to say so;
/// recording only the failing side would have spelled the subject and left
/// the trait invisible. `reason` says which of the two this row is.
const UNRESOLVED_IMPL_HALF_SQL: &str = "SELECT '{side}', source.{name}, source.blob_id,
           source.impl_site,
           member.rel_path,
           source.impl_declaration_id,
           CASE
             WHEN declared.declaration_blob_id IS NOT NULL
               THEN 'resolved'
             WHEN EXISTS(SELECT 1 FROM cr_impl_bindings AS binding
                         WHERE binding.blob_id=source.blob_id
                           AND binding.relation_key=source.relation_key
                           AND binding.module_path=source.module_path
                           AND binding.side='{side}')
               THEN 'bound_without_declaration'
             ELSE 'unbound'
           END,
           COALESCE(
             (SELECT binding.target_module_path FROM cr_impl_bindings AS binding
              WHERE binding.blob_id=source.blob_id
                AND binding.relation_key=source.relation_key
                AND binding.module_path=source.module_path
                AND binding.side='{side}'),
             (SELECT route.target_module_path FROM {routes} AS route
              WHERE route.blob_id=source.blob_id
                AND route.relation_key=source.relation_key
                AND route.module_path=source.module_path)),
           declared.declaration_blob_id, declared.declaration_site, declared.rel_path,
           source.module_path
    FROM cr_impl_sources AS source
    CROSS JOIN cr_members AS member
      ON member.module_path=source.module_path AND member.blob_id=source.blob_id
    LEFT JOIN cr_impl_declarations AS declared
      ON declared.blob_id=source.blob_id AND declared.relation_key=source.relation_key
     AND declared.module_path=source.module_path AND declared.side='{side}'
    WHERE source.trait_name IS NOT NULL
      AND (NOT EXISTS(SELECT 1 FROM cr_impl_declarations AS declaration
                     WHERE declaration.blob_id=source.blob_id
                       AND declaration.relation_key=source.relation_key
                       AND declaration.module_path=source.module_path
                       AND declaration.side='subject')
       OR NOT EXISTS(SELECT 1 FROM cr_impl_declarations AS declaration
                     WHERE declaration.blob_id=source.blob_id
                       AND declaration.relation_key=source.relation_key
                       AND declaration.module_path=source.module_path
                       AND declaration.side='trait'))";

/// Both halves, ordered so that one crate derives the same rows every time.
pub(super) static UNRESOLVED_IMPL_SELECT_SQL: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| {
        format!(
            "SELECT DISTINCT * FROM ({} UNION ALL {}) ORDER BY 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12",
            impl_half(
                UNRESOLVED_IMPL_HALF_SQL,
                "subject",
                "cr_impl_subject_routes"
            ),
            impl_half(UNRESOLVED_IMPL_HALF_SQL, "trait", "cr_impl_trait_routes"),
        )
    });
pub(super) const UNRESOLVED_IMPL_INSERT_SQL: &str = "INSERT OR IGNORE INTO rust_crate_unresolved_trait_impls VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)";

fn impl_half(template: &str, side: &str, routes: &str) -> String {
    template
        .replace("{side}", side)
        .replace("{routes}", routes)
        .replace("{name}", &format!("{side}_name"))
        .replace("{segments}", &format!("{side}_segments"))
}
pub(super) static IMPL_SUBJECT_BINDINGS_SQL: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| impl_half(IMPL_BINDINGS_SQL, "subject", "cr_impl_subject_routes"));
pub(super) static IMPL_TRAIT_BINDINGS_SQL: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| impl_half(IMPL_BINDINGS_SQL, "trait", "cr_impl_trait_routes"));
#[cfg(any(test, feature = "test-support"))]
pub(super) static IMPL_SUBJECT_GLOB_BINDINGS_SQL: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| {
        impl_half(IMPL_GLOB_BINDINGS_SQL, "subject", "cr_impl_subject_routes")
    });
#[cfg(any(test, feature = "test-support"))]
pub(super) static IMPL_TRAIT_GLOB_BINDINGS_SQL: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| impl_half(IMPL_GLOB_BINDINGS_SQL, "trait", "cr_impl_trait_routes"));
pub(super) static IMPL_SUBJECT_GAPS_SQL: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| impl_half(IMPL_GAPS_SQL, "subject", "cr_impl_subject_routes"));
pub(super) static IMPL_TRAIT_GAPS_SQL: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| impl_half(IMPL_GAPS_SQL, "trait", "cr_impl_trait_routes"));
pub(super) const IMPL_DECLARATIONS_SQL: &str =
    include_str!("rust_crate_trait_impl_declarations.sql");
pub(super) const IMPL_ROWS_SQL: &str = include_str!("rust_crate_trait_impls.sql");
const INHERENT_IMPL_SELECT_SQL: &str = include_str!("rust_crate_inherent_impls.sql");
const UNRESOLVED_INHERENT_IMPL_SELECT_SQL: &str =
    include_str!("rust_crate_unresolved_inherent_impls.sql");
const INHERENT_IMPL_INSERT_SQL: &str =
    "INSERT INTO rust_crate_inherent_impls VALUES(?1,?2,?3,?4,?5,?6,?7,?8)";
const UNRESOLVED_INHERENT_IMPL_INSERT_SQL: &str =
    "INSERT INTO rust_crate_unresolved_inherent_impls VALUES(?1,?2,?3,?4,?5,?6,?7,?8)";
pub(super) const TRAIT_IMPL_SELECT_SQL: &str = "SELECT * FROM cr_trait_impls";
pub(super) const TRAIT_IMPL_INSERT_SQL: &str =
    "INSERT INTO rust_crate_trait_impls VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)";
#[cfg(any(test, feature = "test-support"))]
pub(super) const FIXPOINT_SQL: &str = include_str!("rust_crate_export_fixpoint.sql");
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub const EXPORT_SOURCES_SQL: &str = include_str!("rust_crate_export_sources.sql");
#[cfg(any(test, feature = "test-support"))]
const LEGACY_FIXPOINT_SQL: &str = r#"
WITH candidates(module_path, namespace, name, origin, source_visibility,
                source_restricted_module_path, target_crate_key, target_module_path,
                target_visibility, target_restricted_module_path,
                declaration_blob_id, declaration_site) AS (
    SELECT source.module_path, target.namespace,
           CASE WHEN source.is_glob = 1 THEN target.name ELSE source.bound_name END,
           CASE WHEN source.is_glob = 1 THEN 'glob_reexport' ELSE 'reexport' END,
           source.visibility,
           (SELECT restricted_module_path FROM cr_restrictions
            WHERE module_path = source.module_path AND visibility = source.visibility),
           target.crate_key, target.module_path, target.visibility, target.restricted_module_path,
           target.declaration_blob_id, target.declaration_site
    FROM cr_module_imports AS source
    JOIN cr_routes AS route ON route.blob_id = source.blob_id AND route.import_ordinal = source.import_ordinal AND route.module_path = source.module_path
    JOIN cr_exports AS target ON target.crate_key = route.target_crate_key
      AND target.module_path = route.target_module_path
      AND (source.is_glob = 1 OR target.name = source.imported_name)
    WHERE (cr_visibility(source.visibility) <> 'restricted' OR EXISTS(
           SELECT 1 FROM cr_restrictions WHERE module_path = source.module_path
             AND visibility = source.visibility AND restricted_module_path IS NOT NULL))
      AND source.visibility <> 'private'
      AND (source.is_glob = 1 OR source.bound_name IS NOT NULL)
      AND (source.is_glob = 0 OR NOT EXISTS(
           SELECT 1 FROM cr_module_imports AS explicit
           WHERE explicit.module_path = source.module_path
             AND explicit.is_glob = 0 AND explicit.bound_name = target.name))
), domains AS (
    -- NULL is the public domain. All other paths are structured module
    -- identities, not source syntax. A restricted path must be resolved.
    SELECT candidate.*,
           CASE cr_visibility(source_visibility)
             WHEN 'public' THEN NULL
             WHEN 'private' THEN module_path
             WHEN 'crate' THEN 'crate'
             ELSE source_restricted_module_path END AS source_domain,
           CASE target_visibility
             WHEN 'public' THEN NULL
             WHEN 'private' THEN target_module_path
             WHEN 'crate' THEN 'crate'
             WHEN 'restricted' THEN target_restricted_module_path END AS target_domain
    FROM candidates AS candidate
), intersections AS (
    SELECT domains.*,
           CASE WHEN source_domain IS NULL THEN target_domain
                WHEN target_domain IS NULL THEN source_domain
                WHEN source_domain = target_domain
                  OR substr(source_domain, 1, length(target_domain) + 2) = target_domain || '::'
                  THEN source_domain
                WHEN substr(target_domain, 1, length(source_domain) + 2) = source_domain || '::'
                  THEN target_domain END AS domain_path
    FROM domains
    WHERE (cr_visibility(source_visibility) <> 'restricted' OR source_domain IS NOT NULL)
      -- A lexical module path alone cannot grant access across crate keys.
      -- Within this crate the importing module must lie in the target domain.
      AND (target_visibility = 'public'
           OR (target_crate_key = ?1 AND target_domain IS NOT NULL
               AND (module_path = target_domain
                    OR substr(module_path, 1, length(target_domain) + 2) = target_domain || '::')))
)
INSERT INTO cr_exports(crate_key, module_path, namespace, name, origin, visibility,
                       restricted_module_path, declaration_blob_id, declaration_site)
SELECT ?1, candidate.module_path, candidate.namespace, candidate.name, candidate.origin,
       CASE WHEN candidate.domain_path IS NULL THEN 'public'
            WHEN candidate.domain_path = 'crate' THEN 'crate'
            WHEN candidate.domain_path = candidate.module_path THEN 'private'
            ELSE 'restricted' END,
       CASE WHEN candidate.domain_path <> 'crate'
                  AND candidate.domain_path <> candidate.module_path
            THEN candidate.domain_path END,
       candidate.declaration_blob_id, candidate.declaration_site
FROM intersections AS candidate
-- Disjoint domains have no intersection, unlike two public domains.
WHERE (candidate.domain_path IS NOT NULL
       OR (candidate.source_domain IS NULL AND candidate.target_domain IS NULL))
  AND NOT EXISTS (
    SELECT 1 FROM cr_exports AS present
    WHERE present.crate_key = ?1
      AND present.module_path = candidate.module_path
      AND present.namespace = candidate.namespace
      AND present.name = candidate.name
      AND present.origin NOT IN ('glob_reexport', 'reexport')
)
ON CONFLICT(crate_key, module_path, namespace, name, declaration_blob_id, declaration_site) DO UPDATE SET
  origin = excluded.origin, visibility = excluded.visibility,
  restricted_module_path = excluded.restricted_module_path,
  declaration_blob_id = excluded.declaration_blob_id,
  declaration_site = excluded.declaration_site
WHERE (cr_exports.origin = 'glob_reexport' AND excluded.origin = 'reexport')
   OR (cr_exports.origin = excluded.origin
           AND cr_exports.origin IN ('glob_reexport', 'reexport')
           AND cr_exports.declaration_blob_id = excluded.declaration_blob_id
           AND cr_exports.declaration_site = excluded.declaration_site
           -- Accessible domains are ancestors of this same importing module.
           -- Their union is the broader domain; equal domains add no delta.
           AND ((excluded.visibility = 'public' AND cr_exports.visibility <> 'public')
                OR (excluded.visibility = 'crate' AND cr_exports.visibility IN ('private', 'restricted'))
                OR (excluded.visibility = 'restricted'
                    AND (cr_exports.visibility = 'private'
                         OR (cr_exports.visibility = 'restricted'
                             AND length(excluded.restricted_module_path)
                                 < length(cr_exports.restricted_module_path))))));
"#;

pub(super) struct ExportRows {
    containers: Vec<Vec<Value>>,
    public_module_reachability: Vec<Vec<Value>>,
    container_sources: Vec<Vec<Value>>,
    exports: Vec<Vec<Value>>,
    macro_items: Vec<Vec<Value>>,
    decided_item_macros: Vec<Vec<Value>>,
    reexports: Vec<Vec<Value>>,
    glob_reexports: Vec<Vec<Value>>,
    imports: Vec<Vec<Value>>,
    binding_provenance: Vec<Vec<Value>>,
    binding_owners: Vec<Vec<Value>>,
    binding_names: Vec<Vec<Value>>,
    binding_alternatives: Vec<Vec<Value>>,
    binding_blockers: Vec<Vec<Value>>,
    globs: Vec<Vec<Value>>,
    root_references: Vec<Vec<Value>>,
    trait_impls: Vec<Vec<Value>>,
    inherent_impls: Vec<Vec<Value>>,
    unresolved_inherent_impls: Vec<Vec<Value>>,
    unresolved_trait_impls: Vec<Vec<Value>>,
    gaps: Vec<Vec<Value>>,
    surface: CrateKey,
}

#[cfg(any(test, feature = "test-support"))]
#[derive(Clone, Debug)]
#[doc(hidden)]
pub struct RoutePassMetrics {
    #[doc(hidden)]
    pub pass: usize,
    #[doc(hidden)]
    pub source_import_rows_read: usize,
    #[doc(hidden)]
    pub reexport_step_rows_read: usize,
    #[doc(hidden)]
    pub glob_step_rows_read: usize,
    #[doc(hidden)]
    pub route_rows_written: usize,
    #[doc(hidden)]
    pub reexport_step_rows_written: usize,
    #[doc(hidden)]
    pub reexport_closure_rows_deleted: usize,
    #[doc(hidden)]
    pub reexport_closure_rows_written: usize,
    #[doc(hidden)]
    pub glob_step_rows_written: usize,
    #[doc(hidden)]
    pub glob_closure_rows_deleted: usize,
    #[doc(hidden)]
    pub glob_closure_rows_written: usize,
    #[doc(hidden)]
    pub sqlite_vm_steps: u64,
    pub(super) derive_elapsed_micros: u64,
}

#[cfg(any(test, feature = "test-support"))]
#[derive(Clone, Debug)]
#[doc(hidden)]
pub struct ExportFixpointPassMetrics {
    #[doc(hidden)]
    pub pass: usize,
    #[doc(hidden)]
    pub delta_rows_read: usize,
    #[doc(hidden)]
    pub source_rows: usize,
    #[doc(hidden)]
    pub rows_written: usize,
    #[doc(hidden)]
    pub sqlite_vm_steps: u64,
    #[doc(hidden)]
    pub elapsed_micros: u64,
    #[doc(hidden)]
    pub derive_elapsed_micros: u64,
}

#[cfg(any(test, feature = "test-support"))]
#[derive(Clone, Debug)]
#[doc(hidden)]
pub struct LegacyExportCompareMetrics {
    #[doc(hidden)]
    pub crate_name: String,
    #[doc(hidden)]
    pub legacy_passes: usize,
    #[doc(hidden)]
    pub export_rows: usize,
    #[doc(hidden)]
    pub exports_digest: String,
}

#[cfg(any(test, feature = "test-support"))]
static ROUTE_PASS_METRICS: std::sync::LazyLock<std::sync::Mutex<Vec<(String, RoutePassMetrics)>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(Vec::new()));

#[cfg(any(test, feature = "test-support"))]
static EXPORT_FIXPOINT_PASS_METRICS: std::sync::LazyLock<
    std::sync::Mutex<Vec<(String, ExportFixpointPassMetrics)>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(Vec::new()));

#[cfg(any(test, feature = "test-support"))]
static CAPTURE_ROUTE_PASS_METRICS: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[cfg(any(test, feature = "test-support"))]
static LEGACY_EXPORT_COMPARE_CRATES: std::sync::LazyLock<std::sync::Mutex<HashSet<String>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(HashSet::new()));

#[cfg(any(test, feature = "test-support"))]
static LEGACY_EXPORT_COMPARE_METRICS: std::sync::LazyLock<
    std::sync::Mutex<Vec<LegacyExportCompareMetrics>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(Vec::new()));

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn begin_route_pass_metric_capture() {
    ROUTE_PASS_METRICS
        .lock()
        .expect("Rust route-pass metrics lock")
        .clear();
    EXPORT_FIXPOINT_PASS_METRICS
        .lock()
        .expect("Rust export-fixpoint metrics lock")
        .clear();
    CAPTURE_ROUTE_PASS_METRICS.store(true, std::sync::atomic::Ordering::Relaxed);
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn begin_legacy_export_compare(crate_name: &str) {
    LEGACY_EXPORT_COMPARE_CRATES
        .lock()
        .expect("Rust legacy-export compare lock")
        .insert(crate_name.to_owned());
    LEGACY_EXPORT_COMPARE_METRICS
        .lock()
        .expect("Rust legacy-export compare metrics lock")
        .retain(|metrics| metrics.crate_name != crate_name);
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn take_legacy_export_compare_metrics(crate_name: &str) -> Vec<LegacyExportCompareMetrics> {
    LEGACY_EXPORT_COMPARE_CRATES
        .lock()
        .expect("Rust legacy-export compare lock")
        .remove(crate_name);
    let mut metrics = LEGACY_EXPORT_COMPARE_METRICS
        .lock()
        .expect("Rust legacy-export compare metrics lock");
    let previous = std::mem::take(&mut *metrics);
    let (selected, remaining): (Vec<_>, Vec<_>) = previous
        .into_iter()
        .partition(|metrics| metrics.crate_name == crate_name);
    *metrics = remaining;
    selected
}

#[cfg(any(test, feature = "test-support"))]
fn export_rows_digest(rows: &[Vec<Value>]) -> String {
    let mut digest = Sha256::new();
    for row in rows {
        digest.update(format!("{row:?}\n").as_bytes());
    }
    let digest: [u8; 32] = digest.finalize().into();
    crate::analyzer::canonical_hash::lower_hex_string(&digest)
}

#[cfg(any(test, feature = "test-support"))]
fn compare_legacy_export_fixpoint(
    conn: &Connection,
    crate_key: &[u8],
    crate_name: &str,
) -> Result<LegacyExportCompareMetrics> {
    let current_rows = query_values(
        conn,
        "SELECT crate_key, module_path, namespace, name, origin, visibility,
                restricted_module_path, declaration_blob_id, declaration_site
         FROM cr_exports ORDER BY crate_key, module_path, namespace, name",
    )?;
    let legacy_result = (|| -> Result<(Vec<Vec<Value>>, usize)> {
        conn.prepare_cached(
            "DELETE FROM cr_exports
             WHERE crate_key=(SELECT crate_key FROM cr_identity)
               AND origin IN ('reexport', 'glob_reexport')",
        )?
        .execute([])?;
        conn.execute_batch("DELETE FROM cr_export_delta; DELETE FROM cr_export_delta_next;")?;
        let mut passes = 0usize;
        loop {
            let source_rows = temp_table_rows(conn, "cr_source_imports")?;
            let route_rows = temp_table_rows(conn, "cr_routes")?;
            let export_rows = temp_table_rows(conn, "cr_exports")?;
            let (changed, vm_steps) =
                execute_with_vm_steps(conn, LEGACY_FIXPOINT_SQL, [crate_key])?;
            eprintln!(
                "legacy-export-pass crate={crate_name} pass={passes} source_rows_read={source_rows} route_rows_read={route_rows} export_rows_read={export_rows} rows_written={changed} vm_steps={vm_steps}"
            );
            passes += 1;
            if changed == 0 {
                break;
            }
        }
        let legacy_rows = query_values(
            conn,
            "SELECT crate_key, module_path, namespace, name, origin, visibility,
                    restricted_module_path, declaration_blob_id, declaration_site
             FROM cr_exports ORDER BY crate_key, module_path, namespace, name",
        )?;
        Ok((legacy_rows, passes))
    })();

    conn.prepare_cached("DELETE FROM cr_exports")?.execute([])?;
    {
        let mut insert =
            conn.prepare_cached("INSERT INTO cr_exports VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)")?;
        for row in &current_rows {
            insert.execute(rusqlite::params_from_iter(row.iter()))?;
        }
    }
    conn.execute_batch("DELETE FROM cr_export_delta; DELETE FROM cr_export_delta_next;")?;

    let (legacy_rows, legacy_passes) = legacy_result?;
    let current_digest = export_rows_digest(&current_rows);
    let legacy_digest = export_rows_digest(&legacy_rows);
    if current_rows != legacy_rows {
        return Err(StoreError::new(format!(
            "#4503 legacy export rows differ for {crate_name}: optimized rows={} digest={current_digest}, legacy rows={} digest={legacy_digest}",
            current_rows.len(),
            legacy_rows.len(),
        )));
    }
    Ok(LegacyExportCompareMetrics {
        crate_name: crate_name.to_owned(),
        legacy_passes,
        export_rows: current_rows.len(),
        exports_digest: current_digest,
    })
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn take_route_pass_metrics() -> Vec<(String, RoutePassMetrics)> {
    CAPTURE_ROUTE_PASS_METRICS.store(false, std::sync::atomic::Ordering::Relaxed);
    std::mem::take(
        &mut *ROUTE_PASS_METRICS
            .lock()
            .expect("Rust route-pass metrics lock"),
    )
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn take_export_fixpoint_pass_metrics() -> Vec<(String, ExportFixpointPassMetrics)> {
    CAPTURE_ROUTE_PASS_METRICS.store(false, std::sync::atomic::Ordering::Relaxed);
    std::mem::take(
        &mut *EXPORT_FIXPOINT_PASS_METRICS
            .lock()
            .expect("Rust export-fixpoint metrics lock"),
    )
}

fn execute_with_vm_steps<P: rusqlite::Params>(
    conn: &Connection,
    sql: &str,
    params: P,
) -> Result<(usize, u64)> {
    let mut statement = conn.prepare_cached(sql)?;
    // Cached statements retain VM counters across uses; each pass measures only
    // this execution, as it did when every statement was freshly prepared.
    #[cfg(any(test, feature = "test-support"))]
    statement.reset_status(rusqlite::StatementStatus::VmStep);
    let changed = statement.execute(params)?;
    #[cfg(any(test, feature = "test-support"))]
    let vm_steps = statement
        .get_status(rusqlite::StatementStatus::VmStep)
        .max(0) as u64;
    #[cfg(not(any(test, feature = "test-support")))]
    let vm_steps = 0;
    Ok((changed, vm_steps))
}

#[cfg(any(test, feature = "test-support"))]
fn temp_table_rows(conn: &Connection, table: &str) -> Result<usize> {
    let count = conn.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
        row.get::<_, i64>(0)
    })?;
    Ok(usize::try_from(count).expect("temporary row count is nonnegative"))
}

pub(super) fn derive_exports(
    conn: &Connection,
    item: &PreparedCrate,
    modules: &[Member],
    gate_decisions: &[super::ItemMacroDecision],
    cfg: &str,
) -> Result<ExportRows> {
    #[cfg(any(test, feature = "test-support"))]
    let derive_started = std::time::Instant::now();
    let stage = |statement: &str| {
        crate::profiling::scope_with(|| {
            format!(
                "rust_crates.derive name={} kind={} statement={statement}",
                item.target.name,
                target_kind(item.target.kind)
            )
        })
    };
    {
        let _timing = stage("prepare_tables");
        prepare_tables(conn)?;
        for member in modules {
            conn.prepare_cached(SQL_CR_MEMBERS_1)?.execute(params![
                member.module_path,
                member.blob_id,
                member.scope,
                member.rel_path,
                member.placement
            ])?;
        }
        conn.prepare_cached(SQL_CR_MEMBERS_2)?.execute([])?;
        for decision in gate_decisions.iter().filter(|decision| !decision.no_route) {
            conn.prepare_cached(INSERT_ITEM_MACRO_DECISION_SQL)?
                .execute(params![
                    decision.blob_id,
                    decision.invocation_occurrence_id,
                    decision.decoration_cfg
                ])?;
        }
        for decision in gate_decisions.iter().filter(|decision| decision.no_route) {
            conn.prepare_cached(INSERT_ITEM_MACRO_NO_ROUTE_SQL)?
                .execute(params![decision.blob_id, decision.invocation_occurrence_id])?;
        }
        conn.prepare_cached(POPULATE_MEMBER_BLOBS_SQL)?
            .execute([])?;
        conn.prepare_cached(POPULATE_SCOPES_SQL)?.execute([])?;
        conn.prepare_cached(INSERT_IDENTITY_SQL)?
            .execute([item.key.as_slice()])?;
        conn.prepare_cached(INSERT_FOREIGN_SQL)?.execute([])?;
        for (name, _, key) in &item.dependencies {
            conn.prepare_cached(SQL_CR_DEPENDENCIES_3)?
                .execute(params![
                    name,
                    key.map(|key| key.to_vec()),
                    key.map(|key| conn
                        .query_row(
                            "SELECT topology_id FROM temp.rust_schedule_live WHERE crate_key = ?1",
                            [key.as_slice()],
                            |row| row.get::<_, i64>(0)
                        )
                        .optional())
                        .transpose()?
                        .flatten()
                ])?;
        }
        conn.prepare_cached(EXTERN_CRATE_ALIAS_DEPENDENCIES_SQL)?
            .execute([cfg])?;
    }
    {
        let _timing = stage("export_declarations");
        conn.prepare_cached(SOURCE_DECLARATIONS_SQL)?
            .execute([cfg])?;
        conn.prepare_cached(RESTRICTION_INPUTS_SQL)?.execute([])?;
        conn.prepare_cached(RESTRICTIONS_SQL)?.execute([])?;
        conn.prepare_cached(RESTRICTION_GAPS_SQL)?.execute([])?;
        conn.prepare_cached(CONSTRUCTOR_VISIBILITIES_SQL)?
            .execute([])?;
        conn.prepare_cached(DECLARATIONS_SQL)?.execute([])?;
        conn.prepare_cached(MACRO_ITEMS_SQL)?.execute([cfg])?;
        conn.prepare_cached(MACRO_ITEM_ROWS_SQL)?.execute([])?;
        conn.prepare_cached(MACRO_ITEM_COVERAGE_SQL)?.execute([])?;
        conn.prepare_cached(SQL_CR_EXPORTS_4)?.execute([])?;
    }
    {
        let _timing = stage("enum_containers");
        conn.prepare_cached(ENUM_CONTAINERS_SQL)?.execute([])?;
    }
    {
        let _timing = stage("enum_variants");
        conn.prepare_cached(ENUM_VARIANTS_SQL)?.execute([])?;
    }
    {
        let _timing = stage("containers");
        conn.prepare_cached(CONTAINERS_SQL)?.execute([])?;
        conn.prepare_cached(FOREIGN_REEXPORT_STEPS_SQL)?
            .execute([])?;
        conn.prepare_cached(CLOSE_REEXPORT_STEPS_SQL)?.execute([])?;
        conn.prepare_cached(FOREIGN_GLOB_STEPS_SQL)?.execute([])?;
        conn.prepare_cached(CLOSE_GLOB_STEPS_SQL)?.execute([])?;
    }
    {
        let _timing = stage("determined_bindings");
        conn.prepare_cached(SQL_CR_SOURCE_IMPORTS_5)?
            .execute([cfg])?;
        conn.prepare_cached(UNKNOWN_EXPORTS_SQL)?.execute([cfg])?;
        conn.prepare_cached(OPEN_INVENTORY_SQL)?.execute( params![crate::analyzer::store::resolution_prepare::resolution_rows::gap_origin_code(
                crate::analyzer::resolution::LoweringGapOrigin::Extracted(
                    brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapKind::UnexpandedImplMacro,
                ),
            ), cfg])?;
        conn.prepare_cached(MODULE_DECLARATIONS_SQL)?.execute([])?;
        conn.prepare_cached(ROOT_SOURCES_SQL)?.execute([])?;
        conn.prepare_cached(&IMPL_SOURCES_SQL)?.execute([])?;
        conn.prepare_cached(&INHERENT_IMPL_SOURCES_SQL)?
            .execute([])?;
        binding_relation::derive(conn, edition(item.target.edition), &item.target.name, cfg)?;
        #[cfg(any(test, feature = "test-support"))]
        if LEGACY_EXPORT_COMPARE_CRATES
            .lock()
            .expect("legacy compare lock")
            .contains(item.target.name.as_str())
        {
            let metrics = compare_legacy_export_fixpoint(conn, &item.key, &item.target.name)?;
            LEGACY_EXPORT_COMPARE_METRICS
                .lock()
                .expect("legacy metrics lock")
                .push(metrics);
        }
        for routes in [
            ROUTES_SQL.as_str(),
            IMPL_SUBJECT_ROUTES_SQL.as_str(),
            IMPL_TRAIT_ROUTES_SQL.as_str(),
        ] {
            conn.prepare_cached(routes)?.execute([])?;
        }
    }
    {
        let _timing = stage("reexport_routes");
        conn.prepare_cached(LOCAL_REEXPORT_STEPS_SQL)?.execute([])?;
        conn.prepare_cached(CLEAR_REEXPORT_CLOSURE_SQL)?
            .execute([])?;
        conn.prepare_cached(CLOSE_REEXPORT_STEPS_SQL)?.execute([])?;
        conn.prepare_cached(SQL_CR_REEXPORTS_6)?.execute([])?;
        conn.prepare_cached(GLOB_REEXPORTS_SQL)?.execute([])?;
    }
    {
        let _timing = stage("import_publication_rows");
        conn.prepare_cached(SQL_CR_GLOBS_7)?.execute([])?;
        conn.prepare_cached(SQL_CR_IMPORTS_8)?.execute([])?;
        conn.prepare_cached(MACRO_USE_IMPORTS_SQL)?.execute([])?;
    }
    {
        let _timing = stage("gaps");
        conn.prepare_cached(IMPORT_CONFLICT_GAPS_SQL)?.execute([])?;

        conn.prepare_cached(SQL_CR_GAPS_9)?.execute([])?;
    }
    {
        let _timing = stage("root_references");
        conn.prepare_cached(&ROOT_ROUTES_SQL)?.execute([])?;
    }
    {
        let _timing = stage("trait_implementations");
        for bindings in [
            IMPL_SUBJECT_BINDINGS_SQL.as_str(),
            IMPL_TRAIT_BINDINGS_SQL.as_str(),
        ] {
            conn.prepare_cached(bindings)?.execute([])?;
        }
        conn.prepare_cached(CANONICAL_DEPENDENCY_DECLARATIONS_SQL)?
            .execute([])?;
        conn.prepare_cached(IMPL_DECLARATIONS_SQL)?.execute([])?;
        for gaps in [IMPL_SUBJECT_GAPS_SQL.as_str(), IMPL_TRAIT_GAPS_SQL.as_str()] {
            conn.prepare_cached(gaps)?.execute([])?;
        }
        conn.prepare_cached(IMPL_ROWS_SQL)?.execute([])?;
    }
    let authority_timing = stage("binding_authority");
    conn.execute_batch(
        "DELETE FROM cr_authority_blockers; DELETE FROM cr_authority_source_paths;",
    )?;
    // Only this crate's own members name a declaration's source path. A
    // foreign target's coordinate comes from a dependency's published rows,
    // which an unchanged facade retains across its own target's rederivation,
    // so mapping it through that target's current sources would make the
    // digest depend on derivation history. Foreign targets are hashed by their
    // symbolic endpoint, as foreign glob providers already are.
    conn.execute("INSERT INTO cr_authority_source_paths
 SELECT identity.crate_key,member.blob_id,MIN(member.rel_path) FROM cr_members member CROSS JOIN cr_identity identity GROUP BY member.blob_id", [])?;
    conn.execute(binding_authority::BLOCKERS_SQL, [])?;
    let binding_owners = query_values(conn, binding_authority::OWNERS_SQL)?;
    let binding_names = query_values(conn, binding_authority::NAMES_SQL)?;
    let binding_alternatives = query_values(conn, &binding_authority::ALTERNATIVES_SQL)?;
    let binding_blockers = query_values(conn, binding_authority::REASONS_SQL)?;
    drop(authority_timing);
    let mut digest = Sha256::new();
    binding_authority::hash_rows(&mut digest, &binding_owners, "binding-owners", &[4, 5]);
    binding_authority::hash_rows(&mut digest, &binding_names, "binding-names", &[]);
    binding_authority::hash_rows(
        &mut digest,
        &binding_alternatives,
        "binding-alternatives",
        &[10, 11, 12],
    );
    binding_authority::hash_rows(&mut digest, &binding_blockers, "binding-blockers", &[]);
    {
        let _timing = stage("public_module_surface");
        derive_public_module_surface(conn)?;
    }
    {
        let _timing = stage("surface_digest");
        for sql in [
            SQL_CR_EXPORTS_10,
            SQL_CR_REEXPORTS_11,
            GLOB_SURFACE_SQL,
            MACRO_ITEM_SURFACE_SQL,
            PUBLIC_SURFACE_SELECT_SQL,
            BINDING_PROVENANCE_SURFACE_SQL.as_str(),
            GAP_LEVEL_SURFACE_SQL,
        ] {
            for row in query_values(conn, sql)? {
                for value in row {
                    match value {
                        Value::Null => hash_cell(&mut digest, b"null"),
                        Value::Text(text) => hash_cell(&mut digest, text.as_bytes()),
                        Value::Blob(bytes) => hash_cell(&mut digest, &bytes),
                        _ => unreachable!("surface has only text and digests"),
                    }
                }
            }
        }
    }
    let result = {
        let _timing = stage("collect_rows");
        let collect = |statement: &str, sql: &str| {
            let _timing = stage(statement);
            query_values(conn, sql)
        };
        ExportRows {
            containers: collect("collect_rows.containers", ENUM_CONTAINER_ROWS_SQL)?,
            public_module_reachability: collect(
                "collect_rows.public_module_reachability",
                PUBLIC_SURFACE_REACHABILITY_SQL,
            )?,
            container_sources: collect("collect_rows.container_sources", ENUM_SOURCE_ROWS_SQL)?,
            exports: collect("collect_rows.exports", SQL_CR_EXPORTS_12)?,
            macro_items: collect("collect_rows.macro_items", SELECT_MACRO_ITEMS_SQL)?,
            decided_item_macros: collect(
                "collect_rows.decided_item_macros",
                SELECT_DECIDED_ITEM_MACROS_SQL,
            )?,
            reexports: collect("collect_rows.reexports", SQL_CR_REEXPORTS_13)?,
            glob_reexports: collect("collect_rows.glob_reexports", SELECT_GLOB_REEXPORTS_SQL)?,
            imports: collect("collect_rows.imports", SQL_CR_IMPORTS_14)?,
            binding_provenance: collect(
                "collect_rows.binding_provenance",
                BINDING_PROVENANCE_SELECT_SQL,
            )?,
            globs: collect("collect_rows.globs", SQL_CR_GLOBS_15)?,
            root_references: collect("collect_rows.root_references", ROOT_REFERENCES_SELECT_SQL)?,
            trait_impls: collect("collect_rows.trait_impls", TRAIT_IMPL_SELECT_SQL)?,
            inherent_impls: collect("collect_rows.inherent_impls", INHERENT_IMPL_SELECT_SQL)?,
            unresolved_inherent_impls: collect(
                "collect_rows.unresolved_inherent_impls",
                UNRESOLVED_INHERENT_IMPL_SELECT_SQL,
            )?,
            unresolved_trait_impls: collect(
                "collect_rows.unresolved_trait_impls",
                &UNRESOLVED_IMPL_SELECT_SQL,
            )?,
            gaps: collect("collect_rows.gaps", SQL_CR_GAPS_16)?,
            binding_owners,
            binding_names,
            binding_alternatives,
            binding_blockers,
            surface: digest.finalize().into(),
        }
    };
    #[cfg(any(test, feature = "test-support"))]
    if CAPTURE_ROUTE_PASS_METRICS.load(std::sync::atomic::Ordering::Relaxed) {
        let derive_elapsed_micros =
            u64::try_from(derive_started.elapsed().as_micros()).unwrap_or(u64::MAX);
        for (crate_name, metrics) in ROUTE_PASS_METRICS
            .lock()
            .expect("Rust route-pass metrics lock")
            .iter_mut()
        {
            if crate_name == &item.target.name {
                metrics.derive_elapsed_micros = derive_elapsed_micros;
            }
        }
        for (crate_name, metrics) in EXPORT_FIXPOINT_PASS_METRICS
            .lock()
            .expect("Rust export-fixpoint metrics lock")
            .iter_mut()
        {
            if crate_name == &item.target.name {
                metrics.derive_elapsed_micros = derive_elapsed_micros;
            }
        }
    }
    Ok(result)
}

/// Project the published module graph, not dependency digests or declaration
/// evidence. Nodes are canonical containers; alias paths never become nodes.
/// Both worklists live in SQLite and deduplicate finite keys, so public alias
/// cycles and glob diamonds need neither recursion nor a depth limit.
fn derive_public_module_surface(conn: &Connection) -> Result<()> {
    conn.prepare_cached(
        "INSERT INTO cr_surface_nodes SELECT crate_key, 'crate', 0 FROM cr_identity",
    )?
    .execute([])?;
    loop {
        conn.execute_batch(
            "DELETE FROM cr_surface_frontier;
             DELETE FROM cr_surface_bindings;
             DELETE FROM cr_surface_aliases;
             DELETE FROM cr_surface_requests;
             DELETE FROM cr_surface_candidates;",
        )?;
        if conn
            .prepare_cached(
                "INSERT INTO cr_surface_frontier
             SELECT crate_key, module_path FROM cr_surface_nodes WHERE visited = 0",
            )?
            .execute([])?
            == 0
        {
            break;
        }
        conn.prepare_cached("UPDATE cr_surface_nodes SET visited = 1 WHERE visited = 0")?
            .execute([])?;
        conn.prepare_cached(PUBLIC_SURFACE_BINDINGS_SQL)?
            .execute([])?;
        conn.prepare_cached(&PUBLIC_SURFACE_ALIASES_SQL)?
            .execute([])?;
        conn.prepare_cached(
            "INSERT OR IGNORE INTO cr_surface_bindings
             SELECT crate_key, module_path, 'type', name, 'reexport', 1 FROM cr_surface_aliases",
        )?
        .execute([])?;
        conn.prepare_cached(
            "INSERT INTO cr_surface_requests
             SELECT crate_key, module_path, namespace, name, crate_key, module_path, name, 0
             FROM cr_surface_bindings",
        )?
        .execute([])?;
        loop {
            conn.execute_batch(
                "DELETE FROM cr_surface_pending;
                 DELETE FROM cr_surface_lookup;",
            )?;
            if conn
                .prepare_cached(
                    "INSERT INTO cr_surface_pending
                 SELECT owner_crate_key, owner_module_path, owner_namespace, owner_name,
                        crate_key, module_path, name FROM cr_surface_requests WHERE visited = 0",
                )?
                .execute([])?
                == 0
            {
                break;
            }
            conn.prepare_cached("UPDATE cr_surface_requests SET visited = 1 WHERE visited = 0")?
                .execute([])?;
            conn.prepare_cached(PUBLIC_SURFACE_LOOKUP_SQL)?
                .execute([])?;
            conn.prepare_cached(&PUBLIC_SURFACE_LOOKUP_ALIASES_SQL)?
                .execute([])?;
            conn.prepare_cached(PUBLIC_SURFACE_CANDIDATES_SQL)?
                .execute([])?;
            conn.prepare_cached(PUBLIC_SURFACE_TERMINALS_SQL)?
                .execute([])?;
            conn.prepare_cached(PUBLIC_SURFACE_NAMED_REQUESTS_SQL)?
                .execute([])?;
            conn.prepare_cached(PUBLIC_SURFACE_GLOBS_SQL)?.execute([])?;
        }
        conn.prepare_cached(PUBLIC_SURFACE_PRUNE_TERMINALS_SQL)?
            .execute([])?;
        conn.prepare_cached(
            "UPDATE cr_surface_facts SET kind = 'public_module_terminal'
             WHERE kind = 'public_module_named_terminal'",
        )?
        .execute([])?;
        conn.prepare_cached(PUBLIC_SURFACE_FACTS_SQL)?.execute([])?;
        conn.prepare_cached(PUBLIC_SURFACE_INVENTORIES_SQL)?
            .execute([])?;
        conn.prepare_cached(
            "INSERT OR IGNORE INTO cr_surface_nodes
             SELECT target_crate_key, target_module_path, 0 FROM cr_surface_candidates",
        )?
        .execute([])?;
    }
    conn.prepare_cached(PUBLIC_SURFACE_GAPS_SQL)?.execute([])?;
    Ok(())
}

// Callers use fixed SQL literals or a finite set of LazyLock templates. Reuse
// their plans across crate derivations in the connection's bounded cache.
fn query_values(conn: &Connection, sql: &str) -> Result<Vec<Vec<Value>>> {
    let mut statement = conn.prepare_cached(sql)?;
    let columns = statement.column_count();
    Ok(statement
        .query_map([], |row| (0..columns).map(|index| row.get(index)).collect())?
        .collect::<std::result::Result<Vec<_>, _>>()?)
}

pub(super) fn register_export_functions(conn: &Connection) -> Result<()> {
    let flags = FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC;
    conn.create_scalar_function("cr_lookup_digest", 2, flags, |context| {
        use crate::analyzer::resolution::ResolutionLookupSemanticRecipe;
        use brokk_bifrost_core::analyzer::Language;
        use brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace;
        let namespace: String = context.get(0)?;
        let name: String = context.get(1)?;
        let namespace = match namespace.as_str() {
            "type" => ResolutionNamespace::Type,
            "value" => ResolutionNamespace::Value,
            "macro" => ResolutionNamespace::Macro,
            _ => panic!("invalid crate export namespace: {namespace}"),
        };
        Ok(
            ResolutionLookupSemanticRecipe::new(Language::Rust, namespace, &name)
                .name_digest()
                .to_vec(),
        )
    })?;
    conn.create_scalar_function("cr_visibility", 1, flags, |context| {
        let visibility: String = context.get(0)?;
        Ok(
            match decode_rust_visibility(&visibility).expect("valid persisted visibility") {
                RustVisibility::Public => "public",
                RustVisibility::Private => "private",
                RustVisibility::Crate => "crate",
                _ => "restricted",
            },
        )
    })?;
    conn.create_scalar_function("cr_visibility_segments", 1, flags, |context| {
        let visibility: String = context.get(0)?;
        let segments =
            match decode_rust_visibility(&visibility).expect("valid persisted visibility") {
                RustVisibility::SelfModule => vec!["self".to_owned()],
                RustVisibility::SuperModule => vec!["super".to_owned()],
                RustVisibility::InPath(segments) => segments,
                _ => Vec::new(),
            };
        Ok(serde_json::to_string(&segments).expect("visibility segments serialize"))
    })?;
    conn.create_scalar_function("cr_restriction", 3, flags, |context| {
        let visibility: String = context.get(0)?;
        let module: String = context.get(1)?;
        let parent: Option<String> = context.get(2)?;
        Ok(
            match decode_rust_visibility(&visibility).expect("valid persisted visibility") {
                RustVisibility::SelfModule => Some(module),
                RustVisibility::SuperModule => Some(parent.unwrap_or_else(|| "crate".into())),
                RustVisibility::InPath(segments) => Some(segments.join("::")),
                _ => None,
            },
        )
    })?;
    Ok(())
}

impl ExportRows {
    pub(super) fn inventory_complete(&self) -> bool {
        self.gaps
            .iter()
            .all(|row| row[0] != Value::Text("unplaced_module".into()))
    }

    pub(super) fn publish(
        self,
        tx: &rusqlite::Transaction<'_>,
        topology_id: i64,
    ) -> Result<CrateKey> {
        for (sql, rows) in [
            (INSERT_ENUM_CONTAINER_SQL, self.containers),
            (
                INSERT_PUBLIC_MODULE_REACHABILITY_SQL,
                self.public_module_reachability,
            ),
            (INSERT_ENUM_SOURCE_SQL, self.container_sources),
            (SQL_RUST_CRATE_EXPORTS_17, self.exports),
            (INSERT_MACRO_ITEMS_SQL, self.macro_items),
            (INSERT_DECIDED_ITEM_MACROS_SQL, self.decided_item_macros),
            (SQL_RUST_CRATE_REEXPORT_ROUTES_18, self.reexports),
            (INSERT_GLOB_REEXPORTS_SQL, self.glob_reexports),
            (SQL_RUST_CRATE_IMPORTS_19, self.imports),
            (BINDING_PROVENANCE_INSERT_SQL, self.binding_provenance),
            (binding_authority::NAMES_INSERT_SQL, self.binding_names),
            (
                binding_authority::ALTERNATIVES_INSERT_SQL,
                self.binding_alternatives,
            ),
            (binding_authority::REASONS_INSERT_SQL, self.binding_blockers),
            (SQL_RUST_CRATE_GLOB_IMPORTS_20, self.globs),
            (ROOT_REFERENCES_INSERT_SQL, self.root_references),
            (TRAIT_IMPL_INSERT_SQL, self.trait_impls),
            (INHERENT_IMPL_INSERT_SQL, self.inherent_impls),
            (
                UNRESOLVED_INHERENT_IMPL_INSERT_SQL,
                self.unresolved_inherent_impls,
            ),
            (UNRESOLVED_IMPL_INSERT_SQL, self.unresolved_trait_impls),
            (SQL_RUST_CRATE_GAPS_21, self.gaps),
        ] {
            if sql == binding_authority::NAMES_INSERT_SQL {
                // Logical parents may sort after children; wire them only after every
                // persistent owner id has been allocated by this publication.
                let owners = &self.binding_owners;
                for row in owners {
                    tx.execute(
                        binding_authority::OWNERS_INSERT_SQL,
                        rusqlite::params_from_iter(
                            std::iter::once(Value::Integer(topology_id)).chain(row.iter().cloned()),
                        ),
                    )?;
                }
                for row in owners {
                    tx.execute(
                        binding_authority::PARENTS_UPDATE_SQL,
                        rusqlite::params_from_iter(
                            std::iter::once(Value::Integer(topology_id))
                                .chain(row.iter().take(9).cloned()),
                        ),
                    )?;
                }
            }
            if sql == INSERT_ENUM_SOURCE_SQL {
                let mut member = tx.prepare_cached(SQL_RUST_CRATE_MEMBER_IDENTITY)?;
                for row in &rows {
                    member.execute(rusqlite::params_from_iter(
                        std::iter::once(Value::Integer(topology_id))
                            .chain(row.iter().take(2).cloned()),
                    ))?;
                }
            }
            let mut statement = tx.prepare_cached(sql)?;
            for mut row in rows {
                if sql == SQL_RUST_CRATE_GAPS_21 {
                    let (Value::Text(kind), Value::Text(detail)) = (&row[0], &row[2]) else {
                        unreachable!("gap publication has text kind and detail: {row:?}");
                    };
                    assert_gap_subject_level(kind, detail);
                }
                if sql == binding_authority::ALTERNATIVES_INSERT_SQL {
                    row.truncate(21);
                }
                statement.execute(rusqlite::params_from_iter(
                    std::iter::once(Value::Integer(topology_id)).chain(row),
                ))?;
            }
        }
        Ok(self.surface)
    }
}

/// Empties every temp table `prepare_tables` creates. Dropping and recreating
/// them per derivation changed the temp schema, and a schema change expires
/// the reader's prepared statements.
const CLEAR_SQL: &str = "DELETE FROM temp.cr_scopes;
DELETE FROM temp.cr_members;
DELETE FROM temp.cr_macro_items;
DELETE FROM temp.cr_item_macro_decisions;
DELETE FROM temp.cr_item_macro_no_routes;
DELETE FROM temp.cr_macro_item_candidates;
DELETE FROM temp.cr_macro_item_covered;
DELETE FROM temp.cr_member_blobs;
DELETE FROM temp.cr_source_declarations;
DELETE FROM temp.cr_constructor_visibilities;
DELETE FROM temp.cr_dependencies;
DELETE FROM temp.cr_identity;
DELETE FROM temp.cr_foreign;
DELETE FROM temp.cr_containers_all;
DELETE FROM temp.cr_reexport_steps;
DELETE FROM temp.cr_reexport_closure;
DELETE FROM temp.cr_glob_steps;
DELETE FROM temp.cr_glob_closure;
DELETE FROM temp.cr_surface_nodes;
DELETE FROM temp.cr_surface_frontier;
DELETE FROM temp.cr_surface_bindings;
DELETE FROM temp.cr_surface_aliases;
DELETE FROM temp.cr_surface_requests;
DELETE FROM temp.cr_surface_pending;
DELETE FROM temp.cr_surface_lookup;
DELETE FROM temp.cr_surface_candidates;
DELETE FROM temp.cr_surface_facts;
DELETE FROM temp.cr_restrictions;
DELETE FROM temp.cr_exports;
DELETE FROM temp.cr_export_sources;
DELETE FROM temp.cr_export_delta;
DELETE FROM temp.cr_export_delta_next;
DELETE FROM temp.cr_enums;
DELETE FROM temp.cr_source_imports;
DELETE FROM temp.cr_routes;
DELETE FROM temp.cr_root_sources;
DELETE FROM temp.cr_root_routes;
DELETE FROM temp.cr_module_declarations;
DELETE FROM temp.cr_reexports;
DELETE FROM temp.cr_glob_reexports;
DELETE FROM temp.cr_imports;
DELETE FROM temp.cr_globs;
DELETE FROM temp.cr_gaps;
DELETE FROM temp.cr_impl_sources;
DELETE FROM temp.cr_impl_subject_routes;
DELETE FROM temp.cr_impl_trait_routes;
DELETE FROM temp.cr_impl_bindings;
DELETE FROM temp.cr_impl_declarations;
DELETE FROM temp.cr_trait_impls;
";
/// Leaves this connection holding the derivation's temp tables, empty.
///
/// The tables are created on a connection's first derivation and emptied on
/// every later one. Emptying them before a derivation rather than after it
/// makes a derivation that failed part way harmless to the next one on the
/// reader; the memory temp store keeps a table's pages after a DELETE or a
/// DROP alike. `cr_trait_impls` is the last object the script creates.
#[doc(hidden)]
pub fn prepare_tables(conn: &Connection) -> Result<()> {
    let prepared = conn
        .prepare_cached(
            "SELECT 1 FROM temp.sqlite_schema WHERE type = 'table' AND name = 'cr_trait_impls'",
        )?
        .query_row([], |_| Ok(()))
        .optional()?
        .is_some();
    if prepared {
        conn.execute_batch(CLEAR_SQL)?;
        return Ok(());
    }
    conn.execute_batch("        CREATE TEMP TABLE IF NOT EXISTS cr_scopes(
            blob_id INTEGER NOT NULL, scope_ordinal INTEGER NOT NULL,
            start_byte INTEGER NOT NULL, end_byte INTEGER NOT NULL,
            PRIMARY KEY(blob_id, scope_ordinal)) WITHOUT ROWID;
        CREATE INDEX IF NOT EXISTS cr_scopes_range
            ON cr_scopes(blob_id, start_byte, end_byte, scope_ordinal);
        CREATE TEMP TABLE IF NOT EXISTS cr_members(module_path TEXT NOT NULL, blob_id INTEGER NOT NULL,
            scope_ordinal INTEGER NOT NULL, rel_path TEXT NOT NULL, placement TEXT NOT NULL,
            parent_module_path TEXT, start_byte INTEGER NOT NULL, end_byte INTEGER NOT NULL,
            PRIMARY KEY(module_path, blob_id, rel_path)) WITHOUT ROWID;
        CREATE INDEX IF NOT EXISTS cr_members_blob ON cr_members(blob_id, scope_ordinal);
        CREATE TEMP TABLE IF NOT EXISTS cr_macro_items(
            module_path TEXT NOT NULL, namespace TEXT NOT NULL, name TEXT NOT NULL,
            visibility TEXT NOT NULL, restricted_module_path TEXT, blob_id INTEGER NOT NULL,
            invocation_occurrence_id INTEGER NOT NULL, declaration_id INTEGER NOT NULL,
            module_item INTEGER NOT NULL,
            PRIMARY KEY(module_path, namespace, name, blob_id, declaration_id)) WITHOUT ROWID;
        CREATE TEMP TABLE IF NOT EXISTS cr_item_macro_decisions(
            blob_id INTEGER NOT NULL, invocation_occurrence_id INTEGER NOT NULL,
            decoration_cfg TEXT NOT NULL,
            PRIMARY KEY(blob_id, invocation_occurrence_id)) WITHOUT ROWID;
        CREATE TEMP TABLE IF NOT EXISTS cr_item_macro_no_routes(
            blob_id INTEGER NOT NULL, invocation_occurrence_id INTEGER NOT NULL,
            PRIMARY KEY(blob_id, invocation_occurrence_id)) WITHOUT ROWID;
        CREATE TEMP TABLE IF NOT EXISTS cr_macro_item_candidates(
            blob_id INTEGER NOT NULL, invocation_occurrence_id INTEGER NOT NULL,
            module_path TEXT NOT NULL, declaration_id INTEGER NOT NULL,
            declaration_kind INTEGER, value_constructor INTEGER NOT NULL, name TEXT,
            visibility TEXT NOT NULL, restricted_module_path TEXT,
            activation INTEGER NOT NULL, declarable INTEGER NOT NULL,
            PRIMARY KEY(blob_id, invocation_occurrence_id, declaration_id)) WITHOUT ROWID;
        CREATE TEMP TABLE IF NOT EXISTS cr_macro_item_covered(
            blob_id INTEGER NOT NULL, invocation_occurrence_id INTEGER NOT NULL,
            PRIMARY KEY(blob_id, invocation_occurrence_id)) WITHOUT ROWID;
        CREATE TEMP TABLE IF NOT EXISTS cr_member_blobs(
            blob_id INTEGER PRIMARY KEY) WITHOUT ROWID;
        CREATE TEMP TABLE IF NOT EXISTS cr_source_declarations(
            module_path TEXT NOT NULL, blob_id INTEGER NOT NULL,
            declaration_id INTEGER NOT NULL, visibility TEXT NOT NULL,
            cfg_condition TEXT NOT NULL, activation INTEGER NOT NULL,
            declaration_kind INTEGER, macro_exported INTEGER,
            nearest_declaration_boundary INTEGER, identifier TEXT NOT NULL,
            PRIMARY KEY(module_path, blob_id, declaration_id, identifier)) WITHOUT ROWID;
        CREATE INDEX IF NOT EXISTS cr_source_declarations_module
            ON cr_source_declarations(module_path, activation, nearest_declaration_boundary);
        CREATE INDEX IF NOT EXISTS cr_source_declarations_declaration
            ON cr_source_declarations(blob_id, declaration_id);
        -- Regular additional namespaces and item-macro constructors share this
        -- resolved domain. NULL visibility records an unresolved constraint.
        CREATE TEMP TABLE IF NOT EXISTS cr_constructor_visibilities(
            module_path TEXT NOT NULL, blob_id INTEGER NOT NULL,
            declaration_id INTEGER NOT NULL, visibility TEXT, restricted_module_path TEXT,
            PRIMARY KEY(module_path, blob_id, declaration_id)) WITHOUT ROWID;
        CREATE TEMP TABLE IF NOT EXISTS cr_dependencies(extern_name TEXT PRIMARY KEY, dependency_crate_key BLOB, topology_id INTEGER) WITHOUT ROWID;
        CREATE INDEX IF NOT EXISTS cr_dependencies_key ON cr_dependencies(dependency_crate_key);
        CREATE TEMP TABLE IF NOT EXISTS cr_identity(crate_key BLOB PRIMARY KEY) WITHOUT ROWID;
        CREATE TEMP TABLE IF NOT EXISTS cr_foreign(crate_key BLOB PRIMARY KEY,
            topology_id INTEGER NOT NULL, crate_name TEXT NOT NULL) WITHOUT ROWID;
        CREATE TEMP TABLE IF NOT EXISTS cr_containers_all(crate_key BLOB NOT NULL,
            container_path TEXT NOT NULL, PRIMARY KEY(crate_key, container_path)) WITHOUT ROWID;
        CREATE TEMP TABLE IF NOT EXISTS cr_reexport_steps(crate_key BLOB NOT NULL,
            module_path TEXT NOT NULL, bound_name TEXT NOT NULL, target_crate_key BLOB NOT NULL,
            target_module_path TEXT NOT NULL, target_name TEXT NOT NULL,
            PRIMARY KEY(crate_key, module_path, bound_name, target_crate_key, target_module_path, target_name)) WITHOUT ROWID;
        CREATE TEMP TABLE IF NOT EXISTS cr_reexport_closure(crate_key BLOB NOT NULL,
            module_path TEXT NOT NULL, bound_name TEXT NOT NULL, target_crate_key BLOB NOT NULL,
            target_container_path TEXT NOT NULL,
            PRIMARY KEY(crate_key, module_path, bound_name, target_crate_key, target_container_path)) WITHOUT ROWID;
        CREATE TEMP TABLE IF NOT EXISTS cr_glob_steps(crate_key BLOB NOT NULL,
            module_path TEXT NOT NULL, target_crate_key BLOB NOT NULL,
            target_module_path TEXT NOT NULL,
            PRIMARY KEY(crate_key, module_path, target_crate_key, target_module_path)) WITHOUT ROWID;
        CREATE TEMP TABLE IF NOT EXISTS cr_glob_closure(crate_key BLOB NOT NULL,
            module_path TEXT NOT NULL, target_crate_key BLOB NOT NULL,
            target_module_path TEXT NOT NULL,
            PRIMARY KEY(crate_key, module_path, target_crate_key, target_module_path)) WITHOUT ROWID;
        CREATE TEMP TABLE IF NOT EXISTS cr_restrictions(module_path TEXT NOT NULL,
            visibility TEXT NOT NULL, restricted_module_path TEXT,
            PRIMARY KEY(module_path, visibility)) WITHOUT ROWID;
        CREATE TEMP TABLE IF NOT EXISTS cr_surface_nodes(crate_key BLOB NOT NULL,
            module_path TEXT NOT NULL, visited INTEGER NOT NULL,
            PRIMARY KEY(crate_key, module_path)) WITHOUT ROWID;
        CREATE INDEX IF NOT EXISTS cr_surface_nodes_pending ON cr_surface_nodes(visited);
        CREATE TEMP TABLE IF NOT EXISTS cr_surface_frontier(crate_key BLOB NOT NULL,
            module_path TEXT NOT NULL, PRIMARY KEY(crate_key, module_path)) WITHOUT ROWID;
        CREATE TEMP TABLE IF NOT EXISTS cr_surface_bindings(crate_key BLOB NOT NULL,
            module_path TEXT NOT NULL, namespace TEXT NOT NULL, name TEXT NOT NULL,
            origin TEXT NOT NULL, module_expected INTEGER NOT NULL,
            PRIMARY KEY(crate_key, module_path, namespace, name)) WITHOUT ROWID;
        CREATE TEMP TABLE IF NOT EXISTS cr_surface_aliases(crate_key BLOB NOT NULL,
            module_path TEXT NOT NULL, name TEXT NOT NULL,
            PRIMARY KEY(crate_key, module_path, name)) WITHOUT ROWID;
        CREATE TEMP TABLE IF NOT EXISTS cr_surface_requests(owner_crate_key BLOB NOT NULL,
            owner_module_path TEXT NOT NULL, owner_namespace TEXT NOT NULL, owner_name TEXT NOT NULL,
            crate_key BLOB NOT NULL, module_path TEXT NOT NULL, name TEXT NOT NULL,
            visited INTEGER NOT NULL,
            PRIMARY KEY(owner_crate_key, owner_module_path, owner_namespace, owner_name,
                        crate_key, module_path, name)) WITHOUT ROWID;
        CREATE INDEX IF NOT EXISTS cr_surface_requests_pending ON cr_surface_requests(visited);
        CREATE TEMP TABLE IF NOT EXISTS cr_surface_pending(owner_crate_key BLOB NOT NULL,
            owner_module_path TEXT NOT NULL, owner_namespace TEXT NOT NULL, owner_name TEXT NOT NULL,
            crate_key BLOB NOT NULL, module_path TEXT NOT NULL, name TEXT NOT NULL,
            PRIMARY KEY(owner_crate_key, owner_module_path, owner_namespace, owner_name,
                        crate_key, module_path, name)) WITHOUT ROWID;
        CREATE TEMP TABLE IF NOT EXISTS cr_surface_lookup(owner_crate_key BLOB NOT NULL,
            owner_module_path TEXT NOT NULL, owner_namespace TEXT NOT NULL, owner_name TEXT NOT NULL,
            crate_key BLOB NOT NULL, module_path TEXT NOT NULL, name TEXT NOT NULL,
            origin TEXT NOT NULL,
            PRIMARY KEY(owner_crate_key, owner_module_path, owner_namespace, owner_name,
                        crate_key, module_path, name)) WITHOUT ROWID;
        CREATE TEMP TABLE IF NOT EXISTS cr_surface_candidates(crate_key BLOB NOT NULL,
            module_path TEXT NOT NULL, name TEXT NOT NULL, target_crate_key BLOB NOT NULL,
            target_module_path TEXT NOT NULL,
            PRIMARY KEY(crate_key, module_path, name,
                        target_crate_key, target_module_path)) WITHOUT ROWID;
        CREATE TEMP TABLE IF NOT EXISTS cr_surface_facts(kind TEXT NOT NULL,
            crate_key BLOB NOT NULL, module_path TEXT NOT NULL, namespace TEXT NOT NULL,
            name TEXT NOT NULL, target_crate_key BLOB NOT NULL, target_module_path TEXT NOT NULL,
            PRIMARY KEY(kind, crate_key, module_path, namespace, name,
                        target_crate_key, target_module_path)) WITHOUT ROWID;
        CREATE TEMP TABLE IF NOT EXISTS cr_exports(crate_key BLOB NOT NULL, module_path TEXT, namespace TEXT, name TEXT, origin TEXT,
            visibility TEXT, restricted_module_path TEXT, declaration_blob_id INTEGER,
            declaration_site INTEGER, PRIMARY KEY(crate_key, module_path, namespace, name, declaration_blob_id, declaration_site)) WITHOUT ROWID;
        CREATE TEMP TABLE IF NOT EXISTS cr_export_sources(
            module_path TEXT NOT NULL, blob_id INTEGER NOT NULL, import_ordinal INTEGER NOT NULL,
            bound_name TEXT, imported_name TEXT, is_glob INTEGER NOT NULL, visibility TEXT NOT NULL,
            restricted_module_path TEXT, target_crate_key BLOB NOT NULL, target_module_path TEXT NOT NULL,
            PRIMARY KEY(blob_id, import_ordinal, module_path)) WITHOUT ROWID;
        CREATE INDEX IF NOT EXISTS cr_export_sources_target
            ON cr_export_sources(target_crate_key, target_module_path, is_glob, imported_name);
        CREATE TEMP TABLE IF NOT EXISTS cr_export_delta(crate_key BLOB NOT NULL, module_path TEXT NOT NULL,
            namespace TEXT NOT NULL, name TEXT NOT NULL, origin TEXT NOT NULL, visibility TEXT NOT NULL,
            restricted_module_path TEXT, declaration_blob_id INTEGER, declaration_site INTEGER,
            PRIMARY KEY(crate_key, module_path, namespace, name)) WITHOUT ROWID;
        CREATE TEMP TABLE IF NOT EXISTS cr_export_delta_next(crate_key BLOB NOT NULL, module_path TEXT NOT NULL,
            namespace TEXT NOT NULL, name TEXT NOT NULL, origin TEXT NOT NULL, visibility TEXT NOT NULL,
            restricted_module_path TEXT, declaration_blob_id INTEGER, declaration_site INTEGER,
            PRIMARY KEY(crate_key, module_path, namespace, name)) WITHOUT ROWID;
        CREATE TEMP TRIGGER IF NOT EXISTS cr_exports_delta_insert AFTER INSERT ON cr_exports
        WHEN NEW.origin IN ('reexport', 'glob_reexport') BEGIN
            INSERT INTO cr_export_delta_next VALUES(NEW.crate_key, NEW.module_path, NEW.namespace, NEW.name,
                NEW.origin, NEW.visibility, NEW.restricted_module_path, NEW.declaration_blob_id, NEW.declaration_site)
            ON CONFLICT(crate_key, module_path, namespace, name) DO UPDATE SET
                origin=excluded.origin, visibility=excluded.visibility,
                restricted_module_path=excluded.restricted_module_path,
                declaration_blob_id=excluded.declaration_blob_id, declaration_site=excluded.declaration_site;
        END;
        CREATE TEMP TRIGGER IF NOT EXISTS cr_exports_delta_update AFTER UPDATE ON cr_exports
        WHEN NEW.origin IN ('reexport', 'glob_reexport') BEGIN
            INSERT INTO cr_export_delta_next VALUES(NEW.crate_key, NEW.module_path, NEW.namespace, NEW.name,
                NEW.origin, NEW.visibility, NEW.restricted_module_path, NEW.declaration_blob_id, NEW.declaration_site)
            ON CONFLICT(crate_key, module_path, namespace, name) DO UPDATE SET
                origin=excluded.origin, visibility=excluded.visibility,
                restricted_module_path=excluded.restricted_module_path,
                declaration_blob_id=excluded.declaration_blob_id, declaration_site=excluded.declaration_site;
        END;
        CREATE TEMP TABLE IF NOT EXISTS cr_enums(container_path TEXT PRIMARY KEY,
            blob_id INTEGER NOT NULL, definition_semantic_key INTEGER NOT NULL,
            scope_node_key INTEGER NOT NULL, rel_path TEXT NOT NULL,
            module_path TEXT NOT NULL) WITHOUT ROWID;
        CREATE INDEX IF NOT EXISTS cr_enums_definition ON cr_enums(blob_id, definition_semantic_key);
        CREATE INDEX IF NOT EXISTS cr_exports_definition ON cr_exports(declaration_blob_id, declaration_site, namespace, origin, crate_key);
        CREATE TEMP TABLE IF NOT EXISTS cr_source_imports(blob_id INTEGER, import_ordinal INTEGER,
            module_path TEXT, binder_scope INTEGER, bound_name TEXT, imported_name TEXT,
            is_glob INTEGER, visibility TEXT, head_segment TEXT, is_macro_use INTEGER,
            PRIMARY KEY(blob_id, import_ordinal, module_path)) WITHOUT ROWID;
        CREATE INDEX IF NOT EXISTS cr_source_imports_name ON cr_source_imports(module_path, bound_name, is_glob);
        -- Outer local extents can enclose a legal module. Its native scope,
        -- rather than the absence of a local extent, identifies module imports.
        CREATE TEMP VIEW IF NOT EXISTS cr_module_imports AS
            SELECT source.* FROM cr_source_imports AS source
            JOIN cr_members AS member
              ON member.module_path = source.module_path AND member.blob_id = source.blob_id
            JOIN main.source_rust_module_scopes AS scope
              ON scope.blob_id = member.blob_id AND scope.ordinal = member.scope_ordinal
             AND scope.resolution_scope = source.binder_scope;
        -- Share exact module ownership before cfg selection. Unknown imports
        -- cannot bind names, but must retain their conditional name surface.
        CREATE TEMP VIEW IF NOT EXISTS cr_member_imports AS
            SELECT imports.blob_id, imports.ordinal AS import_ordinal,
                   members.module_path, imports.native_scope AS binder_scope,
                   imports.bound_name, imports.imported_name, imports.is_glob,
                   imports.visibility, imports.cfg_condition, imports.is_macro_use,
                   imports.local_start
            FROM cr_members AS members
            CROSS JOIN source_rust_import_targets AS imports ON imports.blob_id=members.blob_id
            CROSS JOIN source_imports AS declaration
              ON declaration.blob_id=imports.blob_id AND declaration.import_id=imports.source_import_id
            WHERE imports.native_scope IS NOT NULL
              AND declaration.declaration_start_byte>=members.start_byte
              AND declaration.declaration_end_byte<=members.end_byte
              AND NOT EXISTS(SELECT 1 FROM cr_scopes AS inner_module
                  WHERE inner_module.blob_id=members.blob_id
                    AND inner_module.scope_ordinal<>members.scope_ordinal
                    AND inner_module.start_byte>=members.start_byte
                    AND inner_module.end_byte<=members.end_byte
                    AND declaration.declaration_start_byte>=inner_module.start_byte
                    AND declaration.declaration_end_byte<=inner_module.end_byte);
        CREATE TEMP TABLE IF NOT EXISTS cr_routes(blob_id INTEGER, import_ordinal INTEGER,
            module_path TEXT, target_crate_key BLOB, target_module_path TEXT,
            PRIMARY KEY(blob_id, import_ordinal, module_path, target_crate_key, target_module_path)) WITHOUT ROWID;
        CREATE TEMP TABLE IF NOT EXISTS cr_root_sources(blob_id INTEGER, route_key INTEGER,
            module_path TEXT, target_name TEXT, reference_source_site INTEGER,
            PRIMARY KEY(blob_id, route_key, module_path)) WITHOUT ROWID;
        CREATE TEMP TABLE IF NOT EXISTS cr_root_routes(blob_id INTEGER, route_key INTEGER,
            module_path TEXT, target_crate_key BLOB, target_module_path TEXT,
            PRIMARY KEY(blob_id, route_key, module_path, target_crate_key, target_module_path)) WITHOUT ROWID;
        CREATE TEMP VIEW IF NOT EXISTS cr_root_segments AS
            SELECT blob_id, path_key AS route_key, position AS ordinal, segment
            FROM resolution_root_route_segments WHERE segment IS NOT NULL;
        -- A container beside the `mod` item that declares it. A module anchor
        -- names the module its own route step reached, and the declaration
        -- that names that module is what a caret on the anchor stands on, so
        -- the anchor's target is read here rather than by splitting the
        -- container path. This is the inverse of the join the walk itself uses
        -- to admit a `mod` step. A crate root appears in no row: no `mod` item
        -- writes it. A table rather than a view: the root-reference select
        -- seeks it by module path once per reference, and a view has no key
        -- to seek, so every reference scanned every declaration (#3749).
        CREATE TEMP TABLE IF NOT EXISTS cr_module_declarations(
            module_path TEXT PRIMARY KEY, parent_module_path TEXT NOT NULL,
            module_name TEXT NOT NULL) WITHOUT ROWID;
        CREATE TEMP TABLE IF NOT EXISTS cr_reexports(module_path TEXT NOT NULL, bound_name TEXT NOT NULL,
            target_crate_key BLOB NOT NULL, target_module_path TEXT NOT NULL, target_name TEXT NOT NULL,
            visibility TEXT NOT NULL, restricted_module_path TEXT,
            PRIMARY KEY(module_path, bound_name, target_crate_key, target_module_path, target_name)) WITHOUT ROWID;
        CREATE TEMP TABLE IF NOT EXISTS cr_glob_reexports AS SELECT module_path, target_crate_key,
            target_module_path, visibility, restricted_module_path FROM rust_crate_glob_reexport_routes WHERE 0;
        CREATE INDEX IF NOT EXISTS cr_glob_reexports_module ON cr_glob_reexports(module_path);
        CREATE TEMP TABLE IF NOT EXISTS cr_imports AS SELECT module_path, namespace, bound_name, blob_id, import_ordinal,
            binder_scope, target_crate_key, target_module_path, target_name FROM rust_crate_imports WHERE 0;
        CREATE TEMP TABLE IF NOT EXISTS cr_globs AS SELECT module_path, blob_id, import_ordinal, binder_scope,
            target_crate_key, target_module_path FROM rust_crate_glob_imports WHERE 0;
        CREATE TEMP TABLE IF NOT EXISTS cr_gaps(gap_kind TEXT, subject TEXT, detail TEXT,
            CONSTRAINT cr_gap_subject_level CHECK(gap_kind NOT IN ('open_export_inventory','unknown_activation')
              OR COALESCE(json_extract(detail,'$.subject_level') IN ('module','binding','public_surface'),0)));
        CREATE INDEX IF NOT EXISTS cr_gaps_subject ON cr_gaps(gap_kind, subject);
        CREATE INDEX IF NOT EXISTS cr_imports_name ON cr_imports(module_path, namespace, bound_name);
        CREATE INDEX IF NOT EXISTS cr_globs_module ON cr_globs(module_path);
        CREATE TEMP TABLE IF NOT EXISTS cr_impl_sources(blob_id INTEGER NOT NULL,
            relation_key INTEGER NOT NULL, module_path TEXT NOT NULL, impl_site INTEGER NOT NULL,
            subject_name TEXT, subject_segments INTEGER NOT NULL,
            trait_name TEXT, trait_segments INTEGER,
            impl_declaration_id INTEGER,
            PRIMARY KEY(blob_id, relation_key, module_path)) WITHOUT ROWID;
        CREATE TEMP VIEW IF NOT EXISTS cr_impl_subject_segments AS
            SELECT blob_id, relation_key, position AS ordinal, segment
            FROM resolution_trait_implementations WHERE side='subject' AND segment IS NOT NULL
            UNION ALL SELECT blob_id, relation_key, position AS ordinal, segment
            FROM resolution_inherent_implementations WHERE segment IS NOT NULL;
        CREATE TEMP VIEW IF NOT EXISTS cr_impl_trait_segments AS
            SELECT blob_id, relation_key, position AS ordinal, segment
            FROM resolution_trait_implementations WHERE side='trait' AND segment IS NOT NULL;
        CREATE TEMP TABLE IF NOT EXISTS cr_impl_subject_routes(blob_id INTEGER,
            relation_key INTEGER, module_path TEXT, target_crate_key BLOB,
            target_module_path TEXT,
            PRIMARY KEY(blob_id, relation_key, module_path, target_crate_key, target_module_path)) WITHOUT ROWID;
        CREATE TEMP TABLE IF NOT EXISTS cr_impl_trait_routes(blob_id INTEGER,
            relation_key INTEGER, module_path TEXT, target_crate_key BLOB,
            target_module_path TEXT,
            PRIMARY KEY(blob_id, relation_key, module_path, target_crate_key, target_module_path)) WITHOUT ROWID;
        CREATE TEMP TABLE IF NOT EXISTS cr_impl_bindings(blob_id INTEGER NOT NULL,
            relation_key INTEGER NOT NULL, module_path TEXT NOT NULL, side TEXT NOT NULL,
            target_crate_key BLOB NOT NULL, target_module_path TEXT NOT NULL,
            target_name TEXT NOT NULL,
            PRIMARY KEY(blob_id, relation_key, module_path, side)) WITHOUT ROWID;
        CREATE TEMP TABLE IF NOT EXISTS cr_impl_declarations(blob_id INTEGER NOT NULL,
            relation_key INTEGER NOT NULL, module_path TEXT NOT NULL, side TEXT NOT NULL,
            declaration_blob_id INTEGER NOT NULL, declaration_site INTEGER NOT NULL,
            rel_path TEXT NOT NULL,
            PRIMARY KEY(blob_id, relation_key, module_path, side)) WITHOUT ROWID;
        CREATE TEMP TABLE IF NOT EXISTS cr_trait_impls(subject_declaration_blob_id INTEGER NOT NULL,
            subject_declaration_site INTEGER NOT NULL, subject_rel_path TEXT NOT NULL,
            trait_declaration_blob_id INTEGER NOT NULL, trait_declaration_site INTEGER NOT NULL,
            trait_rel_path TEXT NOT NULL,
            impl_blob_id INTEGER NOT NULL, impl_site INTEGER NOT NULL, impl_rel_path TEXT NOT NULL,
            impl_declaration_id INTEGER,
            PRIMARY KEY(subject_declaration_blob_id, subject_declaration_site, subject_rel_path,
                        trait_declaration_blob_id, trait_declaration_site, trait_rel_path,
                        impl_blob_id, impl_site, impl_rel_path)) WITHOUT ROWID;")?;
    conn.execute_batch(binding_relation::SCHEMA_SQL)?;
    conn.execute_batch(binding_authority::SCHEMA_SQL)?;
    Ok(())
}

#[doc(hidden)]
pub  const SQL_CR_MEMBERS_1: &str = "INSERT INTO cr_members
            SELECT ?1, ?2, ?3, ?4, ?5, NULL, COALESCE(declaration.body_start_byte, 0), COALESCE(declaration.body_end_byte, manifest.source_bytes)
            FROM source_fact_manifests AS manifest
            LEFT JOIN source_rust_module_scopes AS scope ON scope.blob_id = manifest.blob_id AND scope.ordinal = ?3
            LEFT JOIN source_rust_module_declarations AS declaration ON declaration.blob_id = scope.blob_id AND declaration.declaration_id = scope.declaration_id
            WHERE manifest.blob_id = ?2";
pub(super) const SQL_RUST_CRATE_MEMBER_IDENTITY: &str =
    "INSERT OR IGNORE INTO rust_crate_container_members VALUES(?1,?2,?3)";
#[doc(hidden)]
pub  const SQL_CR_MEMBERS_2: &str = "UPDATE cr_members AS child SET parent_module_path = (
        SELECT parent.module_path FROM cr_members AS parent
        -- The per-crate parent set is small; avoid scanning workspace declarations for each child.
        CROSS JOIN source_rust_module_declarations AS declaration ON declaration.blob_id = parent.blob_id
        CROSS JOIN source_rust_module_inventory AS inventory
          ON inventory.blob_id=declaration.blob_id
         AND inventory.declaration_id=declaration.declaration_id
         AND inventory.parent_scope_ordinal=parent.scope_ordinal
        WHERE child.module_path = parent.module_path || '::' || declaration.module_name
        LIMIT 1) WHERE child.module_path <> 'crate'";
pub(super) const INSERT_ITEM_MACRO_DECISION_SQL: &str =
    "INSERT INTO cr_item_macro_decisions VALUES(?1, ?2, ?3)";
pub(super) const INSERT_ITEM_MACRO_NO_ROUTE_SQL: &str =
    "INSERT INTO cr_item_macro_no_routes VALUES(?1, ?2)";
pub(super) const SELECT_DECIDED_ITEM_MACROS_SQL: &str = "SELECT blob_id, invocation_occurrence_id, decoration_cfg FROM cr_item_macro_decisions ORDER BY blob_id, invocation_occurrence_id";
pub(super) const INSERT_DECIDED_ITEM_MACROS_SQL: &str =
    "INSERT INTO rust_crate_decided_item_macros VALUES(?1, ?2, ?3, ?4)";
#[doc(hidden)]
pub const POPULATE_MEMBER_BLOBS_SQL: &str =
    "INSERT INTO cr_member_blobs SELECT DISTINCT blob_id FROM cr_members";
#[doc(hidden)]
pub  const POPULATE_SCOPES_SQL: &str = "INSERT OR IGNORE INTO cr_scopes
        SELECT scopes.blob_id, scopes.ordinal, declaration.body_start_byte, declaration.body_end_byte
        FROM cr_member_blobs AS selected
        CROSS JOIN source_rust_module_scopes AS scopes ON scopes.blob_id = selected.blob_id
        CROSS JOIN source_rust_module_declarations AS declaration
          ON declaration.blob_id = scopes.blob_id AND declaration.declaration_id = scopes.declaration_id
        WHERE declaration.body_start_byte IS NOT NULL";
pub(super) const SQL_CR_DEPENDENCIES_3: &str = "INSERT INTO cr_dependencies VALUES(?1, ?2, ?3)";
// `extern crate dep as alias;` at the crate root adds `alias` to the extern
// prelude of every module of the crate (Rust Reference, "Extern crate
// declarations"), so `use alias::m::Item;` in any module routes into `dep`.
// The alias names the same crate its manifest dependency does. It replaces a
// same-named manifest entry, as rustc lets it. The predicate is the one the
// point lookup's alias arm (`rust_crate_point_dependency.sql`) uses: an
// active crate-root declaration outside any function body.
pub(super) const EXTERN_CRATE_ALIAS_DEPENDENCIES_SQL: &str =
    "INSERT OR REPLACE INTO cr_dependencies
    SELECT import.bound_name, dependency.dependency_crate_key, dependency.topology_id
    FROM cr_members AS root
    CROSS JOIN source_rust_import_targets AS import ON import.blob_id = root.blob_id
    CROSS JOIN cr_dependencies AS dependency ON dependency.extern_name = import.imported_name
    WHERE root.module_path = 'crate' AND import.is_extern_crate = 1
      AND import.local_start IS NULL AND COALESCE(import.owner_module, '') = ''
      AND import.bound_name <> import.imported_name
      AND cr_cfg(import.cfg_condition, ?1) = 1";
#[doc(hidden)]
pub const INSERT_IDENTITY_SQL: &str = "INSERT INTO cr_identity VALUES(?1)";
// The crates whose derivation already finished in an earlier wave, with the
// topology whose rows they published. A route that leaves this crate names one
// of them; every crate it can reach is a dependency, so it is derived already.
pub(super) const INSERT_FOREIGN_SQL: &str = "INSERT INTO cr_foreign
    SELECT live.crate_key, live.topology_id, topologies.crate_name
    FROM temp.rust_schedule_live AS live JOIN rust_crate_topologies AS topologies USING(topology_id)";
// Every container a route may step into, this crate's pending ones and the
// derived crates' published ones, under the crate key that owns it.
#[doc(hidden)]
pub  const CONTAINERS_SQL: &str = "INSERT OR IGNORE INTO cr_containers_all
    SELECT identity.crate_key, member.module_path
      FROM cr_identity AS identity CROSS JOIN cr_members AS member
    UNION ALL
    SELECT identity.crate_key, enums.container_path
      FROM cr_identity AS identity CROSS JOIN cr_enums AS enums
    UNION ALL
    SELECT dependency.crate_key, containers.container_path
      FROM cr_foreign AS dependency
      CROSS JOIN rust_crate_containers AS containers ON containers.topology_id = dependency.topology_id";
// A name a derived crate re-exported, as the container that name reaches.
#[doc(hidden)]
pub const FOREIGN_REEXPORT_STEPS_SQL: &str = "INSERT OR IGNORE INTO cr_reexport_steps
    SELECT dependency.crate_key, routes.module_path, routes.bound_name,
           routes.target_crate_key, routes.target_module_path, routes.target_name
    FROM cr_foreign AS dependency
    CROSS JOIN rust_crate_reexport_routes AS routes ON routes.topology_id = dependency.topology_id";
// Legacy declaration-placement readers need the reached canonical declarations,
// not an alias or a chosen representative from a dependency's export surface.
pub(super) const CANONICAL_DEPENDENCY_DECLARATIONS_SQL: &str = "INSERT OR IGNORE INTO cr_exports
 SELECT foreign_crate.crate_key,declared.module_path,declared.namespace,declared.name,
 'declaration',declared.visibility,declared.restricted_module_path,
 declared.declaration_blob_id,declared.declaration_site
 FROM cr_binding_targets target CROSS JOIN cr_foreign foreign_crate ON foreign_crate.crate_key=target.target_crate_key
 CROSS JOIN rust_crate_exports declared ON declared.topology_id=foreign_crate.topology_id
 AND declared.module_path=target.target_module_path AND declared.namespace=target.namespace
 AND declared.name=target.target_name AND declared.origin='declaration'";

// The same relation for this crate's own `use` items, public or private: a
// private `use` in a module still names that module's path for its descendants.
//
// A `use` with no module segment whose name is a workspace dependency
// (`pub use dep;`, `pub use dep as alias;`, `pub use dep::{self as alias}`)
// binds the dependency's root module. Its target is spelled as that crate's
// `crate` module with the name `self`, the way Rust spells a module itself
// (`dep::{self}`); the closure below resolves `self` to the module.
#[doc(hidden)]
pub const LOCAL_REEXPORT_STEPS_SQL: &str = "INSERT OR IGNORE INTO cr_reexport_steps
 SELECT owner.crate_key,owner.module_path,target.name,target.target_crate_key,target.target_module_path,target.target_name
 FROM cr_binding_exact_targets target CROSS JOIN cr_binding_owners owner ON owner.owner=target.owner
 CROSS JOIN cr_identity identity ON identity.crate_key=owner.crate_key
 WHERE owner.blob_id=0 AND owner.binder_scope=0 AND target.namespace='type'
 AND target.origin='reexport'";
// A re-export can name another re-export: the umbrella crate binds `usages` to
// a dependency's `crate::usages`, which the dependency binds in turn to its own
// `crate::analyzer::usages`. The walk needs the container the chain ends on, so
// the steps are chased to their terminal here rather than one hop at a time.
// Each state is an original binding and its current target. UNION visits
// that finite pair once, so cycles terminate without limiting valid chains.
// A cyclic-only seed has no terminal and must retain incompleteness evidence.
#[doc(hidden)]
pub const CLOSE_REEXPORT_STEPS_SQL: &str = "INSERT OR IGNORE INTO cr_reexport_closure
    WITH RECURSIVE chase(crate_key, module_path, bound_name, target_crate_key,
                         target_module_path, target_name) AS (
      SELECT crate_key, module_path, bound_name, target_crate_key,
             target_module_path, target_name
      FROM cr_reexport_steps
      UNION
      SELECT chase.crate_key, chase.module_path, chase.bound_name,
             next_step.target_crate_key, next_step.target_module_path, next_step.target_name
      FROM chase
      CROSS JOIN cr_reexport_steps AS next_step
        ON next_step.crate_key = chase.target_crate_key
       AND next_step.module_path = chase.target_module_path
       AND next_step.bound_name = chase.target_name
      WHERE chase.target_name <> 'self'
        AND NOT EXISTS(SELECT 1 FROM cr_containers_all AS child
                       WHERE child.crate_key = chase.target_crate_key
                         AND child.container_path = chase.target_module_path || '::' || chase.target_name)
    )
    SELECT chase.crate_key, chase.module_path, chase.bound_name, chase.target_crate_key,
           CASE WHEN chase.target_name = 'self' THEN chase.target_module_path
                ELSE chase.target_module_path || '::' || chase.target_name END
    FROM chase
    WHERE chase.target_name = 'self'
       OR EXISTS(SELECT 1 FROM cr_containers_all AS child
                 WHERE child.crate_key = chase.target_crate_key
                   AND child.container_path = chase.target_module_path || '::' || chase.target_name)
       OR NOT EXISTS(SELECT 1 FROM cr_reexport_steps AS next_step
                     WHERE next_step.crate_key = chase.target_crate_key
                       AND next_step.module_path = chase.target_module_path
                       AND next_step.bound_name = chase.target_name)";
#[doc(hidden)]
pub const CLEAR_REEXPORT_CLOSURE_SQL: &str = "DELETE FROM cr_reexport_closure";
// One glob edge: the module a `use other::*;` writes it in, and the module that
// glob reaches. A derived crate contributes only the globs it published, which
// are its non-private ones, and only a public one crosses a crate boundary.
#[doc(hidden)]
pub const FOREIGN_GLOB_STEPS_SQL: &str = "INSERT OR IGNORE INTO cr_glob_steps
    SELECT dependency.crate_key, routes.module_path,
           routes.target_crate_key, routes.target_module_path
    FROM cr_foreign AS dependency
    CROSS JOIN rust_crate_glob_reexport_routes AS routes
      ON routes.topology_id = dependency.topology_id
    WHERE routes.visibility = 'public'";
// This crate's own glob imports, public or private: a private `use crate::*;`
// still binds names in the module that writes it, the same way a private named
// `use` does in LOCAL_REEXPORT_STEPS_SQL.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub const LOCAL_GLOB_STEPS_SQL: &str = "INSERT OR IGNORE INTO cr_glob_steps
    SELECT identity.crate_key, source.module_path,
           route.target_crate_key, route.target_module_path
    FROM cr_identity AS identity
    CROSS JOIN cr_source_imports AS source
    CROSS JOIN cr_routes AS route ON route.blob_id = source.blob_id
      AND route.import_ordinal = source.import_ordinal AND route.module_path = source.module_path
    WHERE source.is_glob = 1";
// A glob can reach a module that globs in turn: `use crate::*;` over a root
// that writes `pub use types::*;`. The walk needs every module a name can
// arrive from, so the edges are closed here rather than one hop at a time.
// `UNION` in the recursive term discards a pair already reached, so the chase
// visits each (source module, reached module) pair once and stops; the pair
// set is finite because both sides range over the derived crates' modules.
// A glob cycle is legal Rust; deduplication terminates the chase just as it
// does for the named re-export closure.
#[doc(hidden)]
pub const CLOSE_GLOB_STEPS_SQL: &str = "INSERT OR IGNORE INTO cr_glob_closure
    WITH RECURSIVE reach(crate_key, module_path, target_crate_key, target_module_path) AS (
      SELECT crate_key, module_path, target_crate_key, target_module_path FROM cr_glob_steps
      UNION
      SELECT reach.crate_key, reach.module_path, step.target_crate_key, step.target_module_path
      FROM reach
      CROSS JOIN cr_glob_steps AS step
        ON step.crate_key = reach.target_crate_key
       AND step.module_path = reach.target_module_path
    )
    SELECT crate_key, module_path, target_crate_key, target_module_path FROM reach";
// The dependency export rows this crate's routes actually reach, keyed by the
// dependency's crate key so the fixpoint and the binding statement read one
// relation. Only a public export crosses a crate boundary.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub const CLEAR_GLOB_CLOSURE_SQL: &str = "DELETE FROM cr_glob_closure";
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub const DEPENDENCY_EXPORTS_SQL: &str = "INSERT OR IGNORE INTO cr_exports
    SELECT route.target_crate_key, exports.module_path, exports.namespace, exports.name,
           exports.origin, exports.visibility, exports.restricted_module_path,
           exports.declaration_blob_id, exports.declaration_site
    FROM (SELECT DISTINCT target_crate_key, target_module_path FROM cr_routes WHERE target_crate_key <> ?1
          UNION SELECT DISTINCT target_crate_key, target_module_path FROM cr_impl_subject_routes WHERE target_crate_key <> ?1
          UNION SELECT DISTINCT target_crate_key, target_module_path FROM cr_impl_trait_routes WHERE target_crate_key <> ?1) AS route
    CROSS JOIN cr_foreign AS dependency ON dependency.crate_key = route.target_crate_key
    CROSS JOIN rust_crate_exports AS exports ON exports.topology_id = dependency.topology_id
      AND exports.module_path = route.target_module_path
    WHERE exports.visibility = 'public'";
#[doc(hidden)]
pub  const ENUM_CONTAINERS_SQL: &str = "INSERT OR IGNORE INTO cr_enums
 SELECT candidate.module_path || '::' || candidate.identifier, site.blob_id,
        site.semantic_key, scope.scope_head_node_key, member.rel_path,
        candidate.module_path
 FROM cr_source_declarations AS candidate
 CROSS JOIN source_native_declaration_bridges AS bridge
  ON bridge.blob_id=candidate.blob_id AND bridge.declaration_id=candidate.declaration_id
 CROSS JOIN resolution_semantic_sites AS site ON site.blob_id=bridge.blob_id
  AND site.source_site=bridge.source_site AND site.semantic_role='definition'
 CROSS JOIN resolution_member_scope_properties AS scope ON scope.blob_id=site.blob_id AND scope.definition_semantic_key=site.semantic_key AND scope.scope_kind='type_body'
 CROSS JOIN cr_members AS member
  ON member.blob_id=candidate.blob_id AND member.module_path=candidate.module_path
 WHERE candidate.declaration_kind=1
   AND candidate.nearest_declaration_boundary=0
   AND candidate.activation=1
   AND (cr_visibility(candidate.visibility)<>'restricted'
        OR EXISTS(SELECT 1 FROM cr_restrictions
                  WHERE module_path=candidate.module_path
                    AND visibility=candidate.visibility
                    AND restricted_module_path IS NOT NULL))";
// The crate export relation keeps the first row for each export key. Revisioned
// enum alternatives can author the same logical variant name, so retain every
// source bridge but group their exports to one definition-site representative.
// Ignore keys already written by declarations or an earlier enum candidate;
// invalid Rust can make distinct authored items share an export key.
#[doc(hidden)]
pub  const ENUM_VARIANTS_SQL: &str = "INSERT INTO cr_exports
 SELECT (SELECT crate_key FROM cr_identity), container.container_path, namespace.namespace, candidate.identifier,
        'declaration', 'public', NULL, container.blob_id, MIN(site.source_site)
 FROM cr_enums AS container
 CROSS JOIN resolution_member_owner_properties AS member ON member.blob_id=container.blob_id AND member.owner_definition_semantic_key=container.definition_semantic_key
 CROSS JOIN resolution_semantic_sites AS site ON site.blob_id=member.blob_id AND site.semantic_key=member.definition_semantic_key AND site.semantic_role='definition'
 CROSS JOIN source_native_declaration_bridges AS bridge ON bridge.blob_id=site.blob_id AND bridge.source_site=site.source_site
 CROSS JOIN cr_source_declarations AS candidate
  ON candidate.blob_id=bridge.blob_id AND candidate.declaration_id=bridge.declaration_id
  AND candidate.module_path=container.module_path
 CROSS JOIN resolution_additional_definition_namespaces AS namespace ON namespace.blob_id=site.blob_id AND namespace.definition_semantic_key=site.semantic_key
 WHERE candidate.declaration_kind=9 AND candidate.activation=1
 AND NOT EXISTS(SELECT 1 FROM cr_exports declared WHERE declared.crate_key=(SELECT crate_key FROM cr_identity)
 AND declared.module_path=container.container_path AND declared.namespace=namespace.namespace AND declared.name=candidate.identifier)
   AND namespace.namespace IN ('type','value')
 GROUP BY container.container_path, container.blob_id, namespace.namespace, candidate.identifier
 ON CONFLICT(crate_key, module_path, namespace, name, declaration_blob_id, declaration_site) DO NOTHING";
pub(super) const ENUM_CONTAINER_ROWS_SQL: &str = "SELECT DISTINCT container_path, 'enum', 'enum_declaration' FROM cr_enums ORDER BY container_path";
pub(super) const ENUM_SOURCE_ROWS_SQL: &str = "SELECT container.container_path, container.blob_id, NULL, member.rel_path, 'declared', container.scope_node_key, container.module_path FROM cr_enums AS container CROSS JOIN cr_members AS member ON member.module_path=container.module_path AND member.blob_id=container.blob_id ORDER BY container.container_path, member.rel_path";
// The module walk publishes its container/source rows before enum rows. Invalid
// Rust can give an enum and a module the same path; keep the first module rows.
pub(super) const INSERT_ENUM_CONTAINER_SQL: &str =
    "INSERT INTO rust_crate_containers VALUES(?1,?2,?3,?4)
     ON CONFLICT(topology_id, container_path) DO NOTHING";
pub(super) const INSERT_ENUM_SOURCE_SQL: &str =
    "INSERT INTO rust_crate_container_sources VALUES(?1,?2,?3,?4,?5,?6,?7,?8)
     ON CONFLICT(topology_id, container_path, blob_id, rel_path) DO NOTHING";

#[doc(hidden)]
pub  const SQL_CR_EXPORTS_4: &str = "INSERT OR IGNORE INTO cr_exports
        SELECT exports.crate_key, exports.module_path, CASE WHEN additional.namespace = 'macro' THEN 'macro'
               WHEN additional.namespace = 'type' THEN 'type' ELSE 'value' END,
               exports.name, exports.origin,
               CASE WHEN additional.namespace = 'value' AND constructor.declaration_id IS NOT NULL
                    THEN constructor.visibility ELSE exports.visibility END,
               CASE WHEN additional.namespace = 'value' AND constructor.declaration_id IS NOT NULL
                    THEN constructor.restricted_module_path ELSE exports.restricted_module_path END,
               exports.declaration_blob_id, exports.declaration_site
        FROM cr_exports AS exports
        -- Start from this crate's exports; workspace semantic facts must not drive the per-crate expansion.
        CROSS JOIN resolution_semantic_sites AS site ON site.blob_id = exports.declaration_blob_id AND site.source_site = exports.declaration_site
        CROSS JOIN resolution_additional_definition_namespaces AS additional ON additional.blob_id = site.blob_id AND additional.definition_semantic_key = site.semantic_key
        LEFT JOIN source_native_declaration_bridges AS bridge
          ON bridge.blob_id = site.blob_id AND bridge.source_site = site.source_site
        LEFT JOIN cr_constructor_visibilities AS constructor
          ON constructor.module_path = exports.module_path AND constructor.blob_id = bridge.blob_id
         AND constructor.declaration_id = bridge.declaration_id
        WHERE additional.namespace <> 'value' OR constructor.declaration_id IS NULL
           OR constructor.visibility IS NOT NULL";
#[doc(hidden)]
pub const SQL_CR_SOURCE_IMPORTS_5: &str = "INSERT INTO cr_source_imports
        SELECT DISTINCT imports.blob_id, imports.import_ordinal, imports.module_path,
               imports.binder_scope, imports.bound_name, imports.imported_name,
               imports.is_glob, imports.visibility,
               (SELECT segment.segment
                FROM source_rust_import_module_segments AS segment
                WHERE segment.blob_id=imports.blob_id
                  AND segment.import_ordinal=imports.import_ordinal
                  AND segment.ordinal=0),
               imports.is_macro_use
        FROM cr_member_imports AS imports
        WHERE cr_cfg(imports.cfg_condition, ?1) = 1";
pub(super) const SQL_CR_REEXPORTS_6: &str = "INSERT OR IGNORE INTO cr_reexports
 SELECT owner.module_path,target.name,target.target_crate_key,target.target_module_path,target.target_name,
 target.visibility,target.restricted_module_path
 FROM cr_binding_exact_targets target CROSS JOIN cr_binding_owners owner ON owner.owner=target.owner
 CROSS JOIN cr_identity identity ON identity.crate_key=owner.crate_key
 WHERE owner.blob_id=0 AND owner.binder_scope=0 AND (target.origin='reexport' OR (target.origin='glob_reexport' AND target.target_name='self'))
 AND target.visibility<>'private'";
// `#[macro_use] extern crate rocket;` names a crate in the extern prelude, not
// a member of the module that writes it, and it spells no module segment at
// all. The shared route walk's base row would therefore answer it with the
// writing module, so the route to the dependency's own root is stated here
// before the walk runs and the walk's `INSERT OR IGNORE` leaves it alone.
#[cfg(any(test, feature = "test-support"))]
pub(super) const MACRO_USE_ROUTES_SQL: &str = "INSERT OR IGNORE INTO cr_routes
        SELECT source.blob_id, source.import_ordinal, source.module_path,
               dependency.dependency_crate_key, 'crate'
        FROM cr_source_imports AS source
        CROSS JOIN cr_dependencies AS dependency ON dependency.extern_name = source.imported_name
        WHERE source.is_macro_use = 1 AND dependency.dependency_crate_key IS NOT NULL";
// The same declaration binds every macro that crate publishes, into the macro
// namespace of the module it is written in, which is the crate root. It is a
// glob in one namespace, and the names are a set the dependency already
// published, so one import row per macro states the binding exactly and no
// reader has to expand a glob while filtering a namespace. A crate's macro
// export surface is small, which is what makes enumerating it the cheaper
// shape. Value and type names are not imported: `#[macro_use]` imports macros.
pub(super) const MACRO_USE_IMPORTS_SQL: &str = "INSERT OR IGNORE INTO cr_imports
 SELECT source.module_path,'macro',exports.name,source.blob_id,source.import_ordinal,source.binder_scope,
 exports.target_crate_key,exports.target_module_path,exports.target_name
 FROM cr_source_imports source CROSS JOIN cr_dependencies dependency
 ON dependency.extern_name=source.imported_name
 CROSS JOIN cr_foreign foreign_crate ON foreign_crate.crate_key=dependency.dependency_crate_key
 CROSS JOIN rust_crate_exports exports ON exports.topology_id=foreign_crate.topology_id
 AND exports.module_path='crate' AND exports.namespace='macro' AND exports.visibility='public'
 WHERE source.is_macro_use=1";
pub(super) const SQL_CR_GLOBS_7: &str = "INSERT INTO cr_globs
        SELECT source.module_path, source.blob_id, source.import_ordinal, source.binder_scope, route.target_crate_key, route.target_module_path
        FROM cr_source_imports AS source JOIN cr_routes AS route USING(blob_id, import_ordinal, module_path)
        WHERE source.is_glob = 1";
pub(super) const SQL_CR_IMPORTS_8: &str = include_str!("rust_crate_import_bindings.sql");
// A path into this crate can name a private import of the module it reaches
// when the importing module is that module or one of its descendants:
// `use crate::{LibraryName};` in a child binds through the root's private
// `use crate::kernels::LibraryName;`, and `use super::Name;` through a
// parent's. SQL_CR_IMPORTS_8 binds only to the target module's exports, so
// this binds the rest to what the target module's own import binds. Only an
// import at the target module's module scope counts; a `use` inside one of
// its functions is not a module item. It runs until it binds nothing new, so
// a chain of such imports resolves.
#[cfg(any(test, feature = "test-support"))]
pub(super) const ANCESTOR_PRIVATE_IMPORT_BINDINGS_SQL: &str = "INSERT INTO cr_imports
    SELECT source.module_path, target_import.namespace, source.bound_name, source.blob_id,
           source.import_ordinal, source.binder_scope,
           target_import.target_crate_key, target_import.target_module_path, target_import.target_name
    FROM cr_source_imports AS source
    CROSS JOIN cr_routes AS route ON route.blob_id = source.blob_id
      AND route.import_ordinal = source.import_ordinal AND route.module_path = source.module_path
    CROSS JOIN cr_imports AS target_import ON target_import.module_path = route.target_module_path
      AND target_import.bound_name = source.imported_name
    CROSS JOIN cr_members AS owner ON owner.module_path = target_import.module_path
      AND owner.blob_id = target_import.blob_id
    CROSS JOIN source_rust_module_scopes AS scope ON scope.blob_id = owner.blob_id
      AND scope.ordinal = owner.scope_ordinal AND scope.resolution_scope = target_import.binder_scope
    WHERE route.target_crate_key = (SELECT crate_key FROM cr_identity)
      AND source.is_glob = 0 AND source.bound_name IS NOT NULL
      AND (source.module_path = route.target_module_path
           OR substr(source.module_path, 1, length(route.target_module_path) + 2)
              = route.target_module_path || '::')
      AND NOT EXISTS(SELECT 1 FROM cr_imports AS bound
                     WHERE bound.module_path = source.module_path AND bound.blob_id = source.blob_id
                       AND bound.import_ordinal = source.import_ordinal
                       AND bound.namespace = target_import.namespace)
    GROUP BY source.module_path, target_import.namespace, source.blob_id, source.import_ordinal";
pub(super) const UNKNOWN_EXPORTS_SQL: &str = include_str!("rust_crate_unknown_exports.sql");
pub(super) const OPEN_INVENTORY_SQL: &str = include_str!("rust_crate_open_inventory.sql");
// A `use` that names a workspace dependency's root (`pub use dep as alias;`)
// is resolved by its re-export step, not an export row, so it is no gap.
// A `pub use` that produced a route but no export row is a gap even though the
// route row survives: the route says where the name was looked for, not that it
// was found. When the route left this crate the detail names the crate it
// reached, read from the derived topology row, never from the path text.
pub(super) const SQL_CR_GAPS_9: &str = "INSERT INTO cr_gaps
        SELECT CASE WHEN (source.head_segment IS NULL OR NOT EXISTS(SELECT 1 FROM cr_routes AS route
                    WHERE route.blob_id=source.blob_id AND route.import_ordinal=source.import_ordinal
                      AND route.module_path=source.module_path))
                 AND NOT EXISTS(SELECT 1 FROM cr_exports AS local
                     WHERE local.crate_key=(SELECT crate_key FROM cr_identity)
                       AND local.module_path=source.module_path AND local.namespace='type'
                       AND local.name=COALESCE(source.head_segment, source.imported_name))
                 AND (COALESCE(source.head_segment, source.imported_name) IN ('std','core','alloc')
                      OR EXISTS(SELECT 1 FROM cr_dependencies AS dependency
                          WHERE dependency.extern_name=COALESCE(source.head_segment, source.imported_name)
                            AND dependency.dependency_crate_key IS NULL))
               THEN 'external_dependency'
               WHEN source.visibility = 'private' OR NOT EXISTS(SELECT 1 FROM cr_module_imports AS module_import
                     WHERE module_import.blob_id = source.blob_id
                       AND module_import.import_ordinal = source.import_ordinal
                       AND module_import.module_path = source.module_path) THEN 'unresolved_import' ELSE 'unresolved_reexport' END,
               source.module_path || '::' || COALESCE(source.bound_name, '*'),
               json_patch(
                 json_object('import_ordinal', source.import_ordinal, 'imported_name', source.imported_name),
                 COALESCE((SELECT json_object('target_crate', dependency.crate_name,
                                              'target_module_path', route.target_module_path)
                           FROM cr_routes AS route
                           CROSS JOIN cr_foreign AS dependency ON dependency.crate_key = route.target_crate_key
                           WHERE route.blob_id=source.blob_id AND route.import_ordinal=source.import_ordinal
                             AND route.module_path=source.module_path), json_object()))
        FROM cr_source_imports AS source
        WHERE NOT (source.head_segment IS NULL AND source.is_glob = 0 AND EXISTS(
               SELECT 1 FROM cr_dependencies AS root
               WHERE root.extern_name = source.imported_name AND root.dependency_crate_key IS NOT NULL))
          AND NOT (source.is_glob=0 AND EXISTS(SELECT 1 FROM cr_binding_import_present present
               WHERE present.blob_id=source.blob_id AND present.import_ordinal=source.import_ordinal
                 AND present.module_path=source.module_path))
          AND ((source.is_glob = 0 AND source.bound_name IS NULL)
           OR NOT EXISTS(SELECT 1 FROM cr_routes AS route WHERE route.blob_id = source.blob_id AND route.import_ordinal = source.import_ordinal AND route.module_path = source.module_path)
           OR (source.is_glob = 0 AND (source.visibility = 'private' OR NOT EXISTS(SELECT 1 FROM cr_module_imports AS module_import
                     WHERE module_import.blob_id = source.blob_id
                       AND module_import.import_ordinal = source.import_ordinal
                       AND module_import.module_path = source.module_path)) AND NOT EXISTS(
               SELECT 1 FROM cr_imports AS imports WHERE imports.module_path = source.module_path AND imports.blob_id = source.blob_id AND imports.import_ordinal = source.import_ordinal))
           OR (source.is_glob = 0 AND source.visibility <> 'private' AND EXISTS(SELECT 1 FROM cr_module_imports AS module_import
                     WHERE module_import.blob_id = source.blob_id
                       AND module_import.import_ordinal = source.import_ordinal
                       AND module_import.module_path = source.module_path) AND NOT EXISTS(
               SELECT 1 FROM cr_exports AS exports WHERE exports.crate_key = (SELECT crate_key FROM cr_identity)
                 AND exports.module_path = source.module_path AND exports.name = source.bound_name)))";
pub(super) const SQL_CR_EXPORTS_10: &str = "SELECT exports.module_path, exports.namespace, exports.name, exports.origin, definition.module_path, definition.name FROM cr_exports AS exports JOIN cr_exports AS definition ON definition.declaration_blob_id = exports.declaration_blob_id AND definition.declaration_site = exports.declaration_site AND definition.namespace = exports.namespace AND definition.origin = 'declaration' AND definition.crate_key = exports.crate_key WHERE exports.crate_key = (SELECT crate_key FROM cr_identity) AND exports.visibility = 'public' ORDER BY 1, 2, 3, 5, 6";
pub(super) const SQL_CR_REEXPORTS_11: &str = "SELECT module_path, bound_name, target_crate_key, target_module_path, target_name FROM cr_reexports WHERE visibility = 'public' ORDER BY 1, 2, 3, 4, 5";
pub(super) const SQL_CR_EXPORTS_12: &str = "SELECT owner.module_path,target.namespace,target.name,
 target.origin,target.visibility,target.restricted_module_path,target.declaration_blob_id,target.declaration_site,
 target.target_crate_key,target.target_module_path,target.target_name
 FROM cr_binding_exact_targets target CROSS JOIN cr_binding_owners owner ON owner.owner=target.owner
 CROSS JOIN cr_identity identity ON identity.crate_key=owner.crate_key
 WHERE owner.blob_id=0 AND owner.binder_scope=0 AND target.declaration_blob_id<>0
 AND (target.origin='declaration' OR target.visibility<>'private')
 ORDER BY owner.module_path,target.namespace,target.name,target.target_crate_key,target.target_module_path,target.target_name";
pub(super) const SQL_CR_REEXPORTS_13: &str = "SELECT * FROM cr_reexports";
// Import leaves can spell the same binding repeatedly. The durable relation
// owns canonical endpoints, while this ordinal is only a source locator.
// Retain a stable locator without conflating distinct canonical targets.
pub(super) const SQL_CR_IMPORTS_14: &str = "SELECT module_path,namespace,bound_name,blob_id,
 MIN(import_ordinal),binder_scope,target_crate_key,target_module_path,target_name
 FROM cr_imports GROUP BY module_path,namespace,bound_name,blob_id,binder_scope,
 target_crate_key,target_module_path,target_name";
// Only already admitted source/provider/endpoint tuples are retained. The
// namespace is preserved by an import, so it keys both sides of the edge.
pub(super) const BINDING_PROVENANCE_SELECT_SQL: &str = "WITH first_hops(
 blob_id,import_ordinal,module_path,provider,masked_owner,namespace) AS (
 SELECT source.blob_id,source.import_ordinal,source.module_path,lookup.owner,NULL,lookup.namespace
 FROM cr_binding_imports source
 CROSS JOIN cr_routes route USING(blob_id,import_ordinal,module_path)
 CROSS JOIN cr_binding_lookups lookup USING(blob_id,import_ordinal,module_path)
 CROSS JOIN cr_binding_owners owner ON owner.owner=lookup.owner
 AND owner.crate_key=route.target_crate_key AND owner.module_path=route.target_module_path
 WHERE source.import_ordinal>=0 AND source.is_glob=0 AND lookup.position=source.segments
 AND lookup.name=source.imported_name
 UNION
 SELECT source.blob_id,source.import_ordinal,source.module_path,path.owner,NULL,NULL
 FROM cr_binding_imports source
 CROSS JOIN cr_routes route USING(blob_id,import_ordinal,module_path)
 CROSS JOIN cr_binding_paths path USING(blob_id,import_ordinal,module_path)
 CROSS JOIN cr_binding_owners owner ON owner.owner=path.owner
 AND owner.crate_key=route.target_crate_key AND owner.module_path=route.target_module_path
 WHERE source.import_ordinal>=0 AND source.is_glob=1 AND path.position=source.segments
 UNION
 -- Self-masked source lookups retain their already admitted carried providers.
 SELECT source.blob_id,source.import_ordinal,source.module_path,
 carried.target_owner,lookup.owner,carried.namespace
 FROM cr_binding_imports source
 CROSS JOIN cr_routes route USING(blob_id,import_ordinal,module_path)
 CROSS JOIN cr_binding_lookups lookup USING(blob_id,import_ordinal,module_path)
 CROSS JOIN cr_binding_owners owner ON owner.owner=lookup.owner
 AND owner.crate_key=route.target_crate_key AND owner.module_path=route.target_module_path
 CROSS JOIN cr_binding_masks mask ON mask.owner=lookup.owner
 AND mask.blob_id=source.blob_id AND mask.import_ordinal=source.import_ordinal
 AND mask.module_path=source.module_path
 CROSS JOIN cr_binding_carries carried ON carried.owner=lookup.owner
 AND carried.name=lookup.name AND carried.namespace=lookup.namespace
 WHERE source.is_glob=0 AND source.import_ordinal>=0 AND lookup.position=source.segments
 AND lookup.name=source.imported_name
 ), partial AS MATERIALIZED (
 SELECT consumer,provider,namespace,name FROM cr_binding_visibility_reads
 GROUP BY consumer,provider,namespace,name HAVING MIN(accessible)=0 AND MAX(accessible)=1
 AND MIN(origin)='glob_reexport' AND MAX(origin)='glob_reexport'
 )
 SELECT DISTINCT source.module_path,original.blob_id,original.binder_scope,target.namespace,target.name,
 source.import_ordinal,provider.crate_key AS provider_crate_key,provider.module_path AS provider_module_path,
 provider.blob_id AS provider_blob_id,provider.binder_scope AS provider_binder_scope,provided.name AS provider_name,
 target.target_crate_key,target.target_module_path,target.target_name
 FROM first_hops hop
 CROSS JOIN cr_binding_imports source USING(blob_id,import_ordinal,module_path)
 CROSS JOIN cr_source_imports original USING(blob_id,import_ordinal,module_path)
 CROSS JOIN cr_binding_owners provider ON provider.owner=hop.provider
 CROSS JOIN cr_binding_exact_targets target ON target.owner=source.owner
 CROSS JOIN cr_binding_exact_targets provided ON provided.owner=provider.owner
 AND provided.namespace=target.namespace
 AND provided.name=CASE WHEN source.is_glob=1 OR original.is_macro_use=1
                       THEN target.name ELSE source.imported_name END
 AND provided.target_crate_key=target.target_crate_key
 AND provided.target_module_path=target.target_module_path AND provided.target_name=target.target_name
 WHERE (hop.namespace IS NULL OR hop.namespace=target.namespace)
 AND EXISTS(SELECT 1 FROM cr_binding_visibility_reads visible
 WHERE visible.consumer=COALESCE(hop.masked_owner,source.owner) AND visible.provider=provider.owner
 AND visible.namespace=provided.namespace AND visible.name=provided.name AND visible.accessible=1
 AND visible.target_crate_key=provided.target_crate_key AND visible.target_module_path=provided.target_module_path
 AND visible.target_name=provided.target_name)
 AND NOT EXISTS(SELECT 1 FROM partial WHERE partial.consumer=COALESCE(hop.masked_owner,source.owner)
 AND partial.provider=provider.owner AND partial.namespace=provided.namespace AND partial.name=provided.name)
 AND (hop.masked_owner IS NULL OR EXISTS(
 SELECT 1 FROM cr_binding_exact_targets masked WHERE masked.owner=hop.masked_owner
 AND masked.namespace=provided.namespace AND masked.name=provided.name AND masked.origin='glob_reexport'
 AND masked.target_crate_key=provided.target_crate_key AND masked.target_module_path=provided.target_module_path
 AND masked.target_name=provided.target_name)) AND (
 (source.is_glob=0 AND target.origin='reexport' AND source.bound_name=target.name)
 OR (source.is_glob=1 AND target.origin='glob_reexport')
 OR (original.is_macro_use=1 AND target.namespace='macro'))";
pub(super) const BINDING_PROVENANCE_INSERT_SQL: &str = "INSERT INTO rust_crate_binding_provenance VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)";
// Dependency readers consume these edges. They are therefore published output,
// even though point lookup continues to read canonical endpoints directly.
// Hash logical source paths, not blob ids: body edits retain the same surface.
pub(super) static BINDING_PROVENANCE_SURFACE_SQL: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| {
        format!(
            "SELECT DISTINCT
 edge.module_path,member.rel_path,'module',edge.namespace,
 edge.name,CAST(edge.import_ordinal AS TEXT),edge.provider_crate_key,
 edge.provider_module_path,CASE WHEN edge.provider_binder_scope < -1 THEN 'self-masked'
 ELSE CAST(edge.provider_binder_scope AS TEXT) END,edge.provider_name,
 edge.target_crate_key,edge.target_module_path,edge.target_name
 FROM ({BINDING_PROVENANCE_SELECT_SQL}) edge
 CROSS JOIN cr_members member ON member.module_path=edge.module_path AND member.blob_id=edge.blob_id
 WHERE EXISTS(SELECT 1 FROM cr_module_imports module WHERE module.blob_id=edge.blob_id
 AND module.import_ordinal=edge.import_ordinal AND module.module_path=edge.module_path)
 ORDER BY 1,2,3,4,5,6,7,8,9,10,11,12,13"
        )
    });
pub(super) const SQL_CR_GLOBS_15: &str = "SELECT * FROM cr_globs";
/// Every inventory writer must state which semantic level its subject names.
pub(super) fn assert_gap_subject_level(kind: &str, detail: &str) {
    if !matches!(kind, "open_export_inventory" | "unknown_activation") {
        return;
    }
    let detail: serde_json::Value = serde_json::from_str(detail).expect("gap detail is JSON");
    let evidence = match detail.get("evidence") {
        Some(evidence) => evidence
            .as_array()
            .expect("gap evidence is an array")
            .as_slice(),
        None => std::slice::from_ref(&detail),
    };
    assert!(
        !evidence.is_empty(),
        "inventory gap has evidence: {detail:?}"
    );
    assert!(
        evidence.iter().all(|item| matches!(
            item["subject_level"].as_str(),
            Some("module" | "binding" | "public_surface")
        )),
        "inventory gap must carry its subject level: {detail:?}"
    );
}

pub(super) const GAP_LEVEL_SURFACE_SQL: &str =
    "SELECT DISTINCT gap_kind,subject,json_extract(detail,'$.subject_level')
 FROM cr_gaps WHERE gap_kind IN ('open_export_inventory','unknown_activation') ORDER BY 1,2,3";

pub(super) const SQL_CR_GAPS_16: &str = "SELECT gap_kind, subject, json_object('evidence', json_group_array(json(detail))) FROM cr_gaps GROUP BY gap_kind, subject";
pub(super) const SQL_RUST_CRATE_EXPORTS_17: &str =
    "INSERT INTO rust_crate_exports VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)";
pub(super) const SQL_RUST_CRATE_REEXPORT_ROUTES_18: &str =
    "INSERT OR IGNORE INTO rust_crate_reexport_routes VALUES(?1,?2,?3,?4,?5,?6,?7,?8)";
pub(super) const SQL_RUST_CRATE_IMPORTS_19: &str =
    "INSERT INTO rust_crate_imports VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)";
pub(super) const SQL_RUST_CRATE_GLOB_IMPORTS_20: &str =
    "INSERT INTO rust_crate_glob_imports VALUES(?1,?2,?3,?4,?5,?6,?7)";
pub(super) const SQL_RUST_CRATE_GAPS_21: &str =
    "INSERT OR IGNORE INTO rust_crate_gaps VALUES(?1,?2,?3,jsonb(?4))";
// Every root reference's target, as the crate, module and name a reverse
// question seeks. An ordinary terminal names an export of the module its route
// reached. A module anchor (`crate`, `self`, `super`) names that module itself,
// because the producer ends an anchor occurrence's route on the anchor's own
// step, so its target is the module's own `mod` declaration: the parent that
// writes it and the name it writes. An anchor that reached a crate root has no
// such declaration and carries no target row.
// A route reaches a module independently of its terminal namespace. Keep a
// reverse root witness only for a binding admitted in the reference's namespace;
// an import's pending type/macro halves cannot nominate its final value endpoint.
// With no admitted terminal, retain the unresolved route as boundary evidence.
pub(super) const ROOT_REFERENCES_SELECT_SQL: &str = "SELECT source.module_path, source.blob_id,
 source.route_key, source.reference_source_site, route.target_crate_key,
 COALESCE(anchor.parent_module_path, route.target_module_path),
 COALESCE(anchor.module_name, source.target_name)
 FROM cr_root_sources AS source
 CROSS JOIN cr_root_routes AS route USING(blob_id,route_key,module_path)
 CROSS JOIN resolution_semantic_sites AS reference ON reference.blob_id=source.blob_id
 AND reference.source_site=source.reference_source_site
 LEFT JOIN cr_module_declarations AS anchor
 ON source.target_name IN ('crate','self','super') AND anchor.module_path=route.target_module_path
 WHERE (source.target_name IN ('crate','self','super') AND anchor.module_path IS NOT NULL)
 OR (source.target_name NOT IN ('crate','self','super') AND (NOT EXISTS(
 SELECT 1 FROM cr_binding_owners owner CROSS JOIN cr_binding_targets binding ON binding.owner=owner.owner
 WHERE owner.crate_key=route.target_crate_key AND owner.module_path=route.target_module_path
 AND owner.blob_id=0 AND owner.binder_scope=0 AND binding.name=source.target_name)
 OR EXISTS(
 SELECT 1 FROM cr_binding_owners owner CROSS JOIN cr_binding_targets binding ON binding.owner=owner.owner
 WHERE owner.crate_key=route.target_crate_key AND owner.module_path=route.target_module_path
 AND owner.blob_id=0 AND owner.binder_scope=0 AND binding.name=source.target_name
 AND (binding.namespace=CASE reference.namespace WHEN 'callable' THEN 'value'
 WHEN 'constant' THEN 'value' ELSE reference.namespace END
 OR (reference.namespace IN ('constructor','type_or_value') AND binding.namespace IN ('type','value'))))))";
// A module name is one identifier, so a module path names one parent and one
// name; a second pair behind the same path fails the primary key.
#[doc(hidden)]
pub const MODULE_DECLARATIONS_SQL: &str = "INSERT INTO cr_module_declarations SELECT DISTINCT parent.module_path || '::' || declaration.module_name, parent.module_path, declaration.module_name FROM cr_members AS parent CROSS JOIN source_rust_module_inventory AS inventory ON inventory.blob_id=parent.blob_id AND inventory.parent_scope_ordinal=parent.scope_ordinal CROSS JOIN source_rust_module_declarations AS declaration ON declaration.blob_id=inventory.blob_id AND declaration.declaration_id=inventory.declaration_id";
pub(super) const ROOT_REFERENCES_INSERT_SQL: &str =
    "INSERT INTO rust_crate_root_references VALUES(?1,?2,?3,?4,?5,?6,?7,?8)";
#[cfg(any(test, feature = "test-support"))]
pub(super) fn sql_pins() -> Vec<(&'static str, &'static str, usize)> {
    let mut statements = vec![
        (
            "rust_crate_public_surface_bindings",
            PUBLIC_SURFACE_BINDINGS_SQL,
            0,
        ),
        (
            "rust_crate_public_surface_aliases",
            PUBLIC_SURFACE_ALIASES_SQL.as_str(),
            0,
        ),
        (
            "rust_crate_public_surface_lookup",
            PUBLIC_SURFACE_LOOKUP_SQL,
            0,
        ),
        (
            "rust_crate_public_surface_lookup_aliases",
            PUBLIC_SURFACE_LOOKUP_ALIASES_SQL.as_str(),
            0,
        ),
        (
            "rust_crate_public_surface_candidates",
            PUBLIC_SURFACE_CANDIDATES_SQL,
            0,
        ),
        (
            "rust_crate_public_surface_globs",
            PUBLIC_SURFACE_GLOBS_SQL,
            0,
        ),
        (
            "rust_crate_public_surface_terminals",
            PUBLIC_SURFACE_TERMINALS_SQL,
            0,
        ),
        (
            "rust_crate_public_surface_named_requests",
            PUBLIC_SURFACE_NAMED_REQUESTS_SQL,
            0,
        ),
        (
            "rust_crate_public_surface_prune_terminals",
            PUBLIC_SURFACE_PRUNE_TERMINALS_SQL,
            0,
        ),
        (
            "rust_crate_public_surface_facts",
            PUBLIC_SURFACE_FACTS_SQL,
            0,
        ),
        (
            "rust_crate_public_surface_inventories",
            PUBLIC_SURFACE_INVENTORIES_SQL,
            0,
        ),
        ("rust_crate_public_surface_gaps", PUBLIC_SURFACE_GAPS_SQL, 0),
        (
            "rust_crate_public_surface_select",
            PUBLIC_SURFACE_SELECT_SQL,
            0,
        ),
        (
            "rust_crate_public_surface_reachability",
            PUBLIC_SURFACE_REACHABILITY_SQL,
            0,
        ),
        (
            "rust_crate_public_module_reachability_insert",
            INSERT_PUBLIC_MODULE_REACHABILITY_SQL,
            3,
        ),
        ("rust_crate_visibility_routes", RESTRICTIONS_SQL, 0),
        ("rust_crate_visibility_inputs", RESTRICTION_INPUTS_SQL, 0),
        (
            "rust_crate_constructor_visibility",
            CONSTRUCTOR_VISIBILITIES_SQL,
            0,
        ),
        ("rust_crate_visibility_gaps", RESTRICTION_GAPS_SQL, 0),
        ("rust_crate_glob_reexport_derive", GLOB_REEXPORTS_SQL, 0),
        ("rust_crate_glob_reexport_surface", GLOB_SURFACE_SQL, 0),
        (
            "rust_crate_glob_reexport_select",
            SELECT_GLOB_REEXPORTS_SQL,
            0,
        ),
        (
            "rust_crate_glob_reexport_insert",
            INSERT_GLOB_REEXPORTS_SQL,
            6,
        ),
        (
            "rust_crate_import_conflict_gaps",
            IMPORT_CONFLICT_GAPS_SQL,
            0,
        ),
        (
            "rust_crate_import_conflict_delete",
            DELETE_IMPORT_CONFLICTS_SQL,
            0,
        ),
        (
            "rust_crate_derivation_sql_cr_members_1",
            SQL_CR_MEMBERS_1,
            5,
        ),
        (
            "rust_crate_derivation_sql_cr_members_2",
            SQL_CR_MEMBERS_2,
            0,
        ),
        ("rust_crate_member_blobs", POPULATE_MEMBER_BLOBS_SQL, 0),
        ("rust_crate_member_scopes", POPULATE_SCOPES_SQL, 0),
        ("rust_crate_source_declarations", SOURCE_DECLARATIONS_SQL, 1),
        ("rust_crate_macro_items", MACRO_ITEMS_SQL, 1),
        ("rust_crate_macro_item_rows", MACRO_ITEM_ROWS_SQL, 0),
        ("rust_crate_macro_item_coverage", MACRO_ITEM_COVERAGE_SQL, 0),
        ("rust_crate_macro_items_select", SELECT_MACRO_ITEMS_SQL, 0),
        ("rust_crate_macro_items_surface", MACRO_ITEM_SURFACE_SQL, 0),
        (
            "rust_crate_derivation_sql_cr_dependencies_3",
            SQL_CR_DEPENDENCIES_3,
            3,
        ),
        (
            "rust_crate_extern_crate_alias_dependencies",
            EXTERN_CRATE_ALIAS_DEPENDENCIES_SQL,
            1,
        ),
        ("rust_crate_insert_identity", INSERT_IDENTITY_SQL, 1),
        ("rust_crate_insert_foreign", INSERT_FOREIGN_SQL, 0),
        ("rust_crate_containers_all", CONTAINERS_SQL, 0),
        (
            "rust_crate_foreign_reexport_steps",
            FOREIGN_REEXPORT_STEPS_SQL,
            0,
        ),
        (
            "rust_crate_canonical_dependency_declarations",
            CANONICAL_DEPENDENCY_DECLARATIONS_SQL,
            0,
        ),
        (
            "rust_crate_local_reexport_steps",
            LOCAL_REEXPORT_STEPS_SQL,
            0,
        ),
        (
            "rust_crate_close_reexport_steps",
            CLOSE_REEXPORT_STEPS_SQL,
            0,
        ),
        ("rust_crate_foreign_glob_steps", FOREIGN_GLOB_STEPS_SQL, 0),
        ("rust_crate_local_glob_steps", LOCAL_GLOB_STEPS_SQL, 0),
        ("rust_crate_close_glob_steps", CLOSE_GLOB_STEPS_SQL, 0),
        (
            "rust_crate_clear_reexport_closure",
            CLEAR_REEXPORT_CLOSURE_SQL,
            0,
        ),
        ("rust_crate_dependency_exports", DEPENDENCY_EXPORTS_SQL, 1),
        ("rust_crate_enum_containers", ENUM_CONTAINERS_SQL, 0),
        ("rust_crate_enum_variants", ENUM_VARIANTS_SQL, 0),
        ("rust_crate_enum_container_rows", ENUM_CONTAINER_ROWS_SQL, 0),
        ("rust_crate_enum_source_rows", ENUM_SOURCE_ROWS_SQL, 0),
        (
            "rust_crate_insert_enum_container",
            INSERT_ENUM_CONTAINER_SQL,
            4,
        ),
        ("rust_crate_insert_enum_source", INSERT_ENUM_SOURCE_SQL, 8),
        (
            "rust_crate_derivation_sql_cr_exports_4",
            SQL_CR_EXPORTS_4,
            0,
        ),
        (
            "rust_crate_derivation_sql_cr_source_imports_5",
            SQL_CR_SOURCE_IMPORTS_5,
            1,
        ),
        (
            "rust_crate_derivation_sql_cr_reexports_6",
            SQL_CR_REEXPORTS_6,
            0,
        ),
        ("rust_crate_macro_use_routes", MACRO_USE_ROUTES_SQL, 0),
        ("rust_crate_macro_use_imports", MACRO_USE_IMPORTS_SQL, 0),
        ("rust_crate_derivation_sql_cr_globs_7", SQL_CR_GLOBS_7, 0),
        (
            "rust_crate_derivation_sql_cr_imports_8",
            SQL_CR_IMPORTS_8,
            0,
        ),
        (
            "rust_crate_derivation_sql_cr_ancestor_private_imports",
            ANCESTOR_PRIVATE_IMPORT_BINDINGS_SQL,
            0,
        ),
        ("rust_crate_derivation_sql_cr_gaps_9", SQL_CR_GAPS_9, 0),
        ("rust_crate_open_export_inventory", OPEN_INVENTORY_SQL, 2),
        ("rust_crate_unknown_exports", UNKNOWN_EXPORTS_SQL, 1),
        (
            "rust_crate_derivation_sql_cr_exports_10",
            SQL_CR_EXPORTS_10,
            0,
        ),
        (
            "rust_crate_derivation_sql_cr_reexports_11",
            SQL_CR_REEXPORTS_11,
            0,
        ),
        (
            "rust_crate_derivation_sql_cr_exports_12",
            SQL_CR_EXPORTS_12,
            0,
        ),
        (
            "rust_crate_derivation_sql_cr_reexports_13",
            SQL_CR_REEXPORTS_13,
            0,
        ),
        (
            "rust_crate_derivation_sql_cr_imports_14",
            SQL_CR_IMPORTS_14,
            0,
        ),
        ("rust_crate_derivation_sql_cr_globs_15", SQL_CR_GLOBS_15, 0),
        ("rust_crate_derivation_sql_cr_gaps_16", SQL_CR_GAPS_16, 0),
        ("rust_crate_gap_levels_surface", GAP_LEVEL_SURFACE_SQL, 0),
        (
            "rust_crate_derivation_sql_rust_crate_exports_17",
            SQL_RUST_CRATE_EXPORTS_17,
            12,
        ),
        (
            "rust_crate_derivation_sql_rust_crate_reexport_routes_18",
            SQL_RUST_CRATE_REEXPORT_ROUTES_18,
            8,
        ),
        (
            "rust_crate_derivation_sql_rust_crate_imports_19",
            SQL_RUST_CRATE_IMPORTS_19,
            10,
        ),
        (
            "rust_crate_derivation_sql_rust_crate_glob_imports_20",
            SQL_RUST_CRATE_GLOB_IMPORTS_20,
            7,
        ),
        (
            "rust_crate_derivation_sql_rust_crate_gaps_21",
            SQL_RUST_CRATE_GAPS_21,
            4,
        ),
        ("rust_crate_module_declarations", MODULE_DECLARATIONS_SQL, 0),
        ("rust_crate_root_sources", ROOT_SOURCES_SQL, 0),
        ("rust_crate_root_routes", ROOT_ROUTES_SQL.as_str(), 0),
        (
            "rust_crate_root_references_select",
            ROOT_REFERENCES_SELECT_SQL,
            0,
        ),
        (
            "rust_crate_root_references_insert",
            ROOT_REFERENCES_INSERT_SQL,
            8,
        ),
        ("rust_crate_trait_impl_sources", &IMPL_SOURCES_SQL, 0),
        (
            "rust_crate_inherent_impl_sources",
            &INHERENT_IMPL_SOURCES_SQL,
            0,
        ),
        (
            "rust_crate_trait_impl_subject_routes",
            IMPL_SUBJECT_ROUTES_SQL.as_str(),
            0,
        ),
        (
            "rust_crate_trait_impl_trait_routes",
            IMPL_TRAIT_ROUTES_SQL.as_str(),
            0,
        ),
        (
            "rust_crate_trait_impl_subject_bindings",
            IMPL_SUBJECT_BINDINGS_SQL.as_str(),
            0,
        ),
        (
            "rust_crate_trait_impl_trait_bindings",
            IMPL_TRAIT_BINDINGS_SQL.as_str(),
            0,
        ),
        (
            "rust_crate_trait_impl_subject_glob_bindings",
            IMPL_SUBJECT_GLOB_BINDINGS_SQL.as_str(),
            0,
        ),
        (
            "rust_crate_trait_impl_trait_glob_bindings",
            IMPL_TRAIT_GLOB_BINDINGS_SQL.as_str(),
            0,
        ),
        (
            "rust_crate_trait_impl_subject_gaps",
            IMPL_SUBJECT_GAPS_SQL.as_str(),
            0,
        ),
        (
            "rust_crate_trait_impl_trait_gaps",
            IMPL_TRAIT_GAPS_SQL.as_str(),
            0,
        ),
        (
            "rust_crate_trait_impl_declarations",
            IMPL_DECLARATIONS_SQL,
            0,
        ),
        ("rust_crate_trait_impl_rows", IMPL_ROWS_SQL, 0),
        ("rust_crate_trait_impls_select", TRAIT_IMPL_SELECT_SQL, 0),
        ("rust_crate_trait_impls_insert", TRAIT_IMPL_INSERT_SQL, 11),
        (
            "rust_crate_inherent_impls_select",
            INHERENT_IMPL_SELECT_SQL,
            0,
        ),
        (
            "rust_crate_inherent_impls_insert",
            INHERENT_IMPL_INSERT_SQL,
            8,
        ),
        (
            "rust_crate_unresolved_inherent_impls_select",
            UNRESOLVED_INHERENT_IMPL_SELECT_SQL,
            0,
        ),
        (
            "rust_crate_unresolved_inherent_impls_insert",
            UNRESOLVED_INHERENT_IMPL_INSERT_SQL,
            8,
        ),
        (
            "rust_crate_decided_item_macros_select",
            SELECT_DECIDED_ITEM_MACROS_SQL,
            0,
        ),
        (
            "rust_crate_decided_item_macros_insert",
            INSERT_DECIDED_ITEM_MACROS_SQL,
            4,
        ),
        (
            "rust_crate_unresolved_trait_impls_select",
            UNRESOLVED_IMPL_SELECT_SQL.as_str(),
            0,
        ),
        (
            "rust_crate_unresolved_trait_impls_insert",
            UNRESOLVED_IMPL_INSERT_SQL,
            13,
        ),
    ];
    statements.extend([
        (
            "rust_crate_binding_provenance_select",
            BINDING_PROVENANCE_SELECT_SQL,
            0,
        ),
        (
            "rust_crate_binding_provenance_insert",
            BINDING_PROVENANCE_INSERT_SQL,
            15,
        ),
        (
            "rust_crate_binding_provenance_surface",
            BINDING_PROVENANCE_SURFACE_SQL.as_str(),
            0,
        ),
        (
            "rust_crate_binding_provenance_read",
            crate::analyzer::store::rust_unit_summaries::BINDING_PROVENANCE_READ_SQL,
            2,
        ),
    ]);
    statements.extend(binding_relation::query_registry());
    statements.extend([
        (
            "rust_binding_authority_local_owners",
            binding_authority::LOCAL_OWNERS_SQL,
            0,
        ),
        (
            "rust_binding_authority_local_parents",
            binding_authority::LOCAL_PARENTS_SQL,
            0,
        ),
        (
            "rust_binding_authority_local_declarations",
            binding_authority::LOCAL_DECLARATIONS_SQL,
            1,
        ),
        (
            "rust_binding_authority_blockers",
            binding_authority::BLOCKERS_SQL,
            0,
        ),
        (
            "rust_binding_authority_owners",
            binding_authority::OWNERS_SQL,
            0,
        ),
        (
            "rust_binding_authority_names",
            binding_authority::NAMES_SQL,
            0,
        ),
        (
            "rust_binding_authority_alternatives",
            binding_authority::ALTERNATIVES_SQL.as_str(),
            0,
        ),
        (
            "rust_binding_authority_reasons",
            binding_authority::REASONS_SQL,
            0,
        ),
    ]);
    statements
}

pub(super) const IMPORT_CONFLICT_GAPS_SQL: &str = "INSERT INTO cr_gaps
    SELECT 'unresolved_import', module_path || '::' || bound_name || ':' || namespace,
           json_object('reason', 'conflicting bindings in one lexical scope', 'imports', json_group_array(import_ordinal))
    FROM (SELECT module_path,blob_id,binder_scope,namespace,bound_name,
                 target_crate_key,target_module_path,target_name,MIN(import_ordinal) AS import_ordinal
          FROM cr_imports GROUP BY module_path,blob_id,binder_scope,namespace,bound_name,
                 target_crate_key,target_module_path,target_name)
    GROUP BY module_path,blob_id,binder_scope,namespace,bound_name HAVING count(*) > 1";
#[cfg(any(test, feature = "test-support"))]
pub(super) const DELETE_IMPORT_CONFLICTS_SQL: &str = "DELETE FROM cr_imports WHERE
    (module_path, blob_id, binder_scope, namespace, bound_name) IN
    (SELECT module_path, blob_id, binder_scope, namespace, bound_name FROM cr_imports GROUP BY module_path, blob_id, binder_scope, namespace, bound_name HAVING count(*) > 1)";

pub(super) const GLOB_REEXPORTS_SQL: &str = "INSERT INTO cr_glob_reexports
    SELECT source.module_path, route.target_crate_key, route.target_module_path,
           cr_visibility(source.visibility), (SELECT restricted_module_path FROM cr_restrictions WHERE module_path=source.module_path AND visibility=source.visibility)
    FROM cr_module_imports AS source JOIN cr_routes AS route USING(blob_id, import_ordinal, module_path)
    WHERE (cr_visibility(source.visibility)<>'restricted' OR EXISTS(SELECT 1 FROM cr_restrictions WHERE module_path=source.module_path AND visibility=source.visibility AND restricted_module_path IS NOT NULL)) AND source.visibility <> 'private' AND source.is_glob = 1";
pub(super) const GLOB_SURFACE_SQL: &str = "SELECT module_path, target_crate_key, target_module_path FROM cr_glob_reexports WHERE visibility = 'public' ORDER BY 1, 2, 3";
pub(super) const SELECT_GLOB_REEXPORTS_SQL: &str = "SELECT * FROM cr_glob_reexports";
pub(super) const INSERT_GLOB_REEXPORTS_SQL: &str =
    "INSERT OR IGNORE INTO rust_crate_glob_reexport_routes VALUES(?1,?2,?3,?4,?5,?6)";

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn derive_bindings_for_plan(conn: &Connection, edition: &str) -> Result<()> {
    binding_relation::derive(conn, edition, "plan-fixture", "[]")
}

#[cfg(test)]
mod public_surface_plan_tests {
    use super::*;
    use crate::analyzer::store::AnalyzerStore;
    use crate::analyzer::store::planner_statistics::pinned_plans::{explain_pin, pinned_queries};
    use brokk_bifrost_core::cache_gc::PlannerStatisticsState;
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    #[hardwon("#5133: forwarded module surfaces need bounded exact-topology reads")]
    fn public_module_surface_statements_seek_reached_keys_in_both_statistics_states() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let conn = store.conn.lock().unwrap();
        // This schema/SQL boundary fixture needs no source producer. Keep the
        // real table shapes and checks; unrelated manifest FKs are immaterial.
        conn.execute_batch("PRAGMA foreign_keys = OFF").unwrap();
        prepare_tables(&conn).unwrap();
        let local = [1_u8; 32];
        let foreign = [2_u8; 32];
        conn.execute("INSERT INTO cr_identity VALUES(?1)", [local.as_slice()])
            .unwrap();
        conn.execute(
            "INSERT INTO cr_foreign VALUES(?1, 10, 'foreign')",
            [foreign.as_slice()],
        )
        .unwrap();
        for key in [local, foreign] {
            conn.execute(
                "INSERT INTO cr_surface_frontier VALUES(?1, 'crate')",
                [key.as_slice()],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO cr_surface_pending VALUES(?1, 'crate', 'type', 'api', ?2, 'crate', 'api')",
                params![local.as_slice(), key.as_slice()],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO cr_surface_lookup VALUES(?1, 'crate', 'type', 'api', ?2, 'crate', 'api', 'glob_reexport')",
                params![local.as_slice(), key.as_slice()],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO cr_containers_all VALUES(?1, 'crate'), (?1, 'crate::api')",
                [key.as_slice()],
            )
            .unwrap();
        }
        conn.execute(
            "INSERT INTO cr_exports VALUES(?1, 'crate', 'type', 'api', 'glob_reexport', 'public', NULL, 1, 1)",
            [local.as_slice()],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO cr_glob_reexports VALUES('crate', ?1, 'crate', 'public', NULL)",
            [foreign.as_slice()],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO cr_reexports VALUES('crate', 'root_alias', ?1, 'crate', 'self', 'public', NULL)",
            [foreign.as_slice()],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO rust_crate_reexport_routes VALUES(10, 'crate', 'root_alias', ?1, 'crate', 'self', 'public', NULL)",
            [foreign.as_slice()],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO rust_crate_glob_reexport_routes VALUES(10, 'crate', ?1, 'crate', 'public', NULL)",
            [foreign.as_slice()],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO cr_reexport_closure VALUES(?1, 'crate', 'root_alias', ?2, 'crate')",
            params![local.as_slice(), foreign.as_slice()],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO cr_surface_lookup VALUES(?1, 'crate', 'type', 'root_alias', ?1, 'crate', 'root_alias', 'reexport')",
            [local.as_slice()],
        )
        .unwrap();
        conn.execute(
            "UPDATE cr_surface_lookup SET origin = 'declaration' WHERE crate_key = ?1 AND name = 'api'",
            [foreign.as_slice()],
        )
        .unwrap();
        conn.execute_batch(
            "INSERT INTO rust_crate_exports(topology_id,module_path,namespace,name,origin,visibility,restricted_module_path,declaration_blob_id,declaration_site) VALUES(10, 'crate', 'type', 'api', 'declaration', 'public', NULL, 2, 2);
             INSERT INTO source_fact_manifests(
               blob_id, facts_version, source_bytes, occurrence_count, declaration_count,
               declaration_unit_count, node_count, role_count, occurrence_role_count,
               logical_rows, payload_bytes, publication_state, native_bridge_count,
               rust_declaration_property_count)
             SELECT blob_id, 1, 0, 0, 1, 0, 0, 0, 0, 3, 0, 'building', 1, 1
             FROM (SELECT 1 AS blob_id UNION ALL SELECT 2);
             INSERT INTO source_native_declaration_bridges VALUES(1, 1, 1), (2, 2, 2);
             INSERT INTO source_rust_declaration_properties(blob_id, declaration_id, visibility, cfg_condition, declaration_kind)
               VALUES(1, 1, 'public', 'true', 4), (2, 2, 'public', 'true', 4);",
        )
        .unwrap();
        conn.execute(PUBLIC_SURFACE_BINDINGS_SQL, []).unwrap();
        conn.execute(PUBLIC_SURFACE_CANDIDATES_SQL, []).unwrap();
        conn.execute(PUBLIC_SURFACE_TERMINALS_SQL, []).unwrap();
        conn.execute(PUBLIC_SURFACE_FACTS_SQL, []).unwrap();
        for state in PlannerStatisticsState::BOTH {
            state.install(&conn);
            for pin in pinned_queries()
                .into_iter()
                .filter(|pin| pin.name.starts_with("rust_crate_public_surface_"))
            {
                // Parameters are finite, populated frontier rows, not NULLs.
                assert!(
                    pin.params.is_empty(),
                    "{}: unexpected SQL parameters",
                    pin.name
                );
                let plan = explain_pin(&conn, &pin);
                for forbidden in [
                    "AUTOMATIC",
                    "SCAN exports",
                    "SCAN foreign_crate",
                    "SCAN bridge",
                    "SCAN properties",
                    "SCAN routes",
                    "SCAN named",
                    "SCAN target",
                ] {
                    assert!(
                        !plan.iter().any(|row| row.contains(forbidden)),
                        "{state:?} {} must seek reached keys, not {forbidden}: {plan:?}",
                        pin.name
                    );
                }
                if matches!(
                    pin.name.as_str(),
                    "rust_crate_public_surface_bindings" | "rust_crate_public_surface_lookup"
                ) {
                    assert!(
                        plan.iter().any(|row| row.contains(
                            "SEARCH exports USING PRIMARY KEY (topology_id=? AND module_path=?"
                        )),
                        "{state:?} {} must seek the exact foreign topology/module: {plan:?}",
                        pin.name
                    );
                }
                if pin.name == "rust_crate_public_surface_reachability" {
                    for keyed_read in [
                        "SEARCH edge USING PRIMARY KEY (kind=? AND crate_key=? AND module_path=? AND namespace=?",
                        "SEARCH uncertainty USING PRIMARY KEY (kind=? AND crate_key=? AND module_path=? AND namespace=? AND name=?",
                    ] {
                        assert!(
                            plan.iter().any(|row| row.contains(keyed_read)),
                            "{state:?} {} must seek graph owner keys: {plan:?}",
                            pin.name
                        );
                    }
                    assert!(
                        !plan.iter().any(
                            |row| row.contains("SCAN edge") || row.contains("SCAN uncertainty")
                        ),
                        "{state:?} {} must not scan graph facts: {plan:?}",
                        pin.name
                    );
                }
                if pin.name == "rust_crate_public_surface_lookup" {
                    assert!(
                        plan.iter().any(|row| row.contains(
                            "topology_id=? AND module_path=? AND namespace=? AND name=?"
                        )),
                        "{state:?} {} must seek the selected foreign namespace/name: {plan:?}",
                        pin.name
                    );
                }
            }
        }
    }

    #[test]
    #[hardwon(
        "#5133: a module edge hid a competing glob-exported type and falsely proved membership"
    )]
    fn public_module_surface_preserves_mixed_type_ambiguity() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let conn = store.conn.lock().unwrap();
        conn.execute_batch("PRAGMA foreign_keys = OFF").unwrap();
        prepare_tables(&conn).unwrap();
        let local = [1_u8; 32];
        conn.execute("INSERT INTO cr_identity VALUES(?1)", [local.as_slice()])
            .unwrap();
        // Schema boundary: private a exports a module, private b exports a struct,
        // and the root globs both. Feed selected structured rows directly because
        // naming collision::Event in this surface is rejected by rustc (E0659).
        for path in ["crate", "crate::a", "crate::b", "crate::a::collision"] {
            conn.execute(
                "INSERT INTO cr_containers_all VALUES(?1, ?2)",
                params![local.as_slice(), path],
            )
            .unwrap();
        }
        for path in ["crate::a", "crate::b"] {
            conn.execute(
                "INSERT INTO cr_glob_reexports VALUES('crate', ?1, ?2, 'public', NULL)",
                params![local.as_slice(), path],
            )
            .unwrap();
        }
        for (module, name, origin, blob, site) in [
            ("crate", "collision", "glob_reexport", 1, 1),
            ("crate::a", "collision", "declaration", 1, 1),
            ("crate::b", "collision", "declaration", 2, 2),
            ("crate::a::collision", "Event", "declaration", 1, 3),
        ] {
            conn.execute(
                "INSERT INTO cr_exports VALUES(?1, ?2, 'type', ?3, ?4, 'public', NULL, ?5, ?6)",
                params![local.as_slice(), module, name, origin, blob, site],
            )
            .unwrap();
        }
        conn.execute_batch(
            "INSERT INTO source_fact_manifests(
               blob_id, facts_version, source_bytes, occurrence_count, declaration_count,
               declaration_unit_count, node_count, role_count, occurrence_role_count,
               logical_rows, payload_bytes, publication_state, native_bridge_count,
               rust_declaration_property_count)
             SELECT blob_id, 1, 0, 0, 2, 0, 0, 0, 0, 5, 0, 'building', 2, 2
             FROM (SELECT 1 AS blob_id UNION ALL SELECT 2);
             INSERT INTO source_native_declaration_bridges VALUES(1, 1, 1), (2, 2, 2), (1, 3, 3);
             INSERT INTO source_rust_declaration_properties(blob_id, declaration_id, visibility, cfg_condition, declaration_kind)
               VALUES(1, 1, 'public', 'true', 4), (2, 2, 'public', 'true', 0), (1, 3, 'public', 'true', 0);",
        )
        .unwrap();
        let project = || {
            conn.execute_batch(
                "DELETE FROM cr_surface_nodes; DELETE FROM cr_surface_facts; DELETE FROM cr_gaps;",
            )
            .unwrap();
            derive_public_module_surface(&conn).unwrap();
        };
        let surface_digest = || {
            let mut digest = Sha256::new();
            for row in query_values(&conn, PUBLIC_SURFACE_SELECT_SQL).unwrap() {
                for value in row {
                    match value {
                        Value::Text(text) => hash_cell(&mut digest, text.as_bytes()),
                        Value::Blob(bytes) => hash_cell(&mut digest, &bytes),
                        other => panic!("unexpected graph cell {other:?}"),
                    }
                }
            }
            <[u8; 32]>::from(digest.finalize())
        };
        let root = vec![Value::Blob(local.to_vec()), Value::Text("crate".into())];
        let module = vec![
            Value::Blob(local.to_vec()),
            Value::Text("crate::a::collision".into()),
        ];
        project();
        let ambiguous_digest = surface_digest();
        assert_eq!(
            query_values(&conn, PUBLIC_SURFACE_REACHABILITY_SQL).unwrap(),
            vec![root.clone()]
        );
        assert_eq!(
            query_values(
                &conn,
                "SELECT gap_kind, json_extract(detail, '$.reason') FROM cr_gaps",
            )
            .unwrap(),
            vec![vec![
                Value::Text("open_export_inventory".into()),
                Value::Text("public_module_ambiguous".into()),
            ]]
        );
        assert_eq!(
            query_values(
                &conn,
                "SELECT json_extract(candidate.value, '$.module_path')
                 FROM cr_gaps AS gap, json_each(gap.detail, '$.candidates') AS candidate ORDER BY 1",
            )
            .unwrap(),
            vec![
                vec![Value::Text("crate::a::collision".into())],
                vec![Value::Text("crate::b::collision".into())],
            ]
        );
        // Withdrawing only the competing declaration must change the graph digest
        // and permit the previously ambiguous first-hop membership proof.
        conn.execute("DELETE FROM cr_exports WHERE module_path = 'crate::b'", [])
            .unwrap();
        project();
        let unambiguous_digest = surface_digest();
        assert_ne!(ambiguous_digest, unambiguous_digest);
        assert_eq!(
            query_values(&conn, PUBLIC_SURFACE_REACHABILITY_SQL).unwrap(),
            vec![root.clone(), module.clone()]
        );
        assert!(
            query_values(&conn, "SELECT * FROM cr_gaps")
                .unwrap()
                .is_empty()
        );
        // Two public routes to the same canonical module are one candidate.
        conn.execute(
            "INSERT INTO cr_exports VALUES(?1, 'crate::b', 'type', 'collision', 'reexport', 'public', NULL, 1, 1)",
            [local.as_slice()],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO cr_reexport_steps VALUES(?1, 'crate::b', 'collision', ?1, 'crate::a', 'collision')",
            [local.as_slice()],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO cr_reexport_closure VALUES(?1, 'crate::b', 'collision', ?1, 'crate::a::collision')",
            [local.as_slice()],
        )
        .unwrap();
        project();
        assert_eq!(surface_digest(), unambiguous_digest);
        assert!(
            query_values(&conn, "SELECT * FROM cr_gaps")
                .unwrap()
                .is_empty()
        );
        // A same-spelling function occupies value, never the module's type key.
        conn.execute_batch(
            "UPDATE source_rust_declaration_properties SET declaration_kind = 6 WHERE blob_id = 2 AND declaration_id = 2;",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO cr_exports VALUES(?1, 'crate', 'value', 'collision', 'glob_reexport', 'public', NULL, 2, 2),
                                          (?1, 'crate::b', 'value', 'collision', 'declaration', 'public', NULL, 2, 2)",
            [local.as_slice()],
        )
        .unwrap();
        project();
        assert_eq!(
            query_values(&conn, PUBLIC_SURFACE_REACHABILITY_SQL).unwrap(),
            vec![root, module]
        );
        assert!(
            query_values(&conn, "SELECT * FROM cr_gaps")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    #[hardwon("#5133: ambiguous module candidates cannot prove first-hop membership")]
    fn public_module_membership_requires_a_proven_path_through_cycles_and_diamonds() {
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let conn = store.conn.lock().unwrap();
        conn.execute_batch("PRAGMA foreign_keys = OFF").unwrap();
        prepare_tables(&conn).unwrap();
        let local = [1_u8; 32];
        let foreign = [2_u8; 32];
        let remote = [3_u8; 32];
        conn.execute("INSERT INTO cr_identity VALUES(?1)", [local.as_slice()])
            .unwrap();
        // Both sides of the diamond reach one canonical module. The public
        // cycle returns to the root, so UNION must deduplicate whole nodes.
        for (owner, module, name, target, target_module) in [
            (local, "crate", "api", foreign, "crate::api"),
            (local, "crate", "left", local, "crate::left"),
            (local, "crate", "right", local, "crate::right"),
            (local, "crate::left", "shared", foreign, "crate::diamond"),
            (local, "crate::right", "shared", foreign, "crate::diamond"),
            (foreign, "crate::api", "back", local, "crate"),
            (local, "crate", "blocked", foreign, "crate::blocked_a"),
            (local, "crate", "blocked", foreign, "crate::blocked_b"),
            (foreign, "crate::blocked_a", "leak", foreign, "crate::leak"),
            (local, "crate", "uncertain", remote, "crate::rescued"),
            (local, "crate", "uncertain", remote, "crate::rejected"),
            // The same candidate has a different proven path outside its
            // physical subtree. Uncertainty belongs to a binding, not a node.
            (foreign, "crate::api", "alias", remote, "crate::rescued"),
            (
                remote,
                "crate::rescued",
                "child",
                remote,
                "crate::rescued::child",
            ),
            (local, "crate", "unavailable", foreign, "crate::unavailable"),
        ] {
            conn.execute(
                "INSERT INTO cr_surface_facts VALUES('public_module_edge', ?1, ?2, 'type', ?3, ?4, ?5)",
                params![owner.as_slice(), module, name, target.as_slice(), target_module],
            )
            .unwrap();
        }
        for (kind, owner, name) in [
            ("public_module_ambiguous", local, "blocked"),
            ("public_module_ambiguous", local, "uncertain"),
            ("public_module_unavailable", local, "unavailable"),
            // A marker on another owner must not poison the root's api edge.
            ("public_module_ambiguous", foreign, "api"),
        ] {
            conn.execute(
                "INSERT INTO cr_surface_facts VALUES(?1, ?2, 'crate', 'type', ?3, X'', '')",
                params![kind, owner.as_slice(), name],
            )
            .unwrap();
        }
        let rows = query_values(&conn, PUBLIC_SURFACE_REACHABILITY_SQL).unwrap();
        let expected = [
            (local, "crate"),
            (local, "crate::left"),
            (local, "crate::right"),
            (foreign, "crate::api"),
            (foreign, "crate::diamond"),
            (remote, "crate::rescued"),
            (remote, "crate::rescued::child"),
        ]
        .into_iter()
        .map(|(key, module)| vec![Value::Blob(key.to_vec()), Value::Text(module.into())])
        .collect::<Vec<_>>();
        assert_eq!(rows, expected);
        let tx = conn.unchecked_transaction().unwrap();
        for row in &rows {
            tx.execute(
                INSERT_PUBLIC_MODULE_REACHABILITY_SQL,
                params![10, row[0], row[1]],
            )
            .unwrap();
        }
        // Membership is selected by topology; unrelated publications coexist.
        tx.execute(
            INSERT_PUBLIC_MODULE_REACHABILITY_SQL,
            params![11, foreign.as_slice(), "crate::decoy"],
        )
        .unwrap();
        assert_eq!(
            query_values(
                &tx,
                "SELECT target_crate_key, target_module_path FROM rust_crate_public_module_reachability WHERE topology_id = 10 ORDER BY target_crate_key, target_module_path",
            )
            .unwrap(),
            expected
        );
        assert_eq!(
            tx.execute(
                INSERT_PUBLIC_MODULE_REACHABILITY_SQL,
                params![10, local.as_slice(), "crate"],
            )
            .unwrap_err()
            .sqlite_error_code(),
            Some(rusqlite::ErrorCode::ConstraintViolation)
        );
        tx.rollback().unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM rust_crate_public_module_reachability",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
    }
}
