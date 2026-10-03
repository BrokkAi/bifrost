//! SQL derivation of a single missing topology on its worker's reader.
use super::*;
use brokk_bifrost_core::analyzer::rust_facts::{RustVisibility, decode_rust_visibility};
use rusqlite::types::Value;

pub(super) const RESTRICTION_INPUTS_SQL: &str = include_str!("rust_crate_visibility_inputs.sql");
pub(super) const RESTRICTIONS_SQL: &str = include_str!("rust_crate_visibility_routes.sql");
pub(super) const RESTRICTION_GAPS_SQL: &str = "INSERT INTO cr_gaps
 SELECT 'unresolved_visibility', module_path,
 json_object('visibility', visibility, 'reason', 'UnresolvedVisibility')
 FROM cr_restrictions WHERE restricted_module_path IS NULL";

pub(super) const DECLARATIONS_SQL: &str = include_str!("rust_crate_export_declarations.sql");
pub(super) const SOURCE_DECLARATIONS_SQL: &str = include_str!("rust_crate_source_declarations.sql");
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
 SELECT module_path, 'value', name, visibility, restricted_module_path, blob_id,
        invocation_occurrence_id, declaration_id, 0
 FROM cr_macro_item_candidates
 WHERE declarable = 1 AND activation = 1 AND declaration_kind = 0 AND value_constructor = 1
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
pub(super) static ROUTES_SQL: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
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
pub(super) const ROOT_SOURCES_SQL: &str = include_str!("rust_crate_root_sources.sql");

// A type path in an impl header is lexical in every edition: Rust 2015's
// crate-root-relative rule governs `use` declarations, not paths written in an
// item. The shared walk takes the edition only to apply that rule, so the two
// impl-header walks pass the edition that leaves it off.
const IMPL_HEADER_ANCHOR_EDITION: &str = "2018";
pub(super) const IMPL_SOURCES_SQL: &str = include_str!("rust_crate_trait_impl_sources.sql");
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
    WHERE NOT EXISTS(SELECT 1 FROM cr_impl_declarations AS declaration
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
           (SELECT member.rel_path FROM cr_members AS member
            WHERE member.module_path=source.module_path AND member.blob_id=source.blob_id),
           source.impl_declaration_id,
           CASE
             WHEN EXISTS(SELECT 1 FROM cr_impl_declarations AS declaration
                         WHERE declaration.blob_id=source.blob_id
                           AND declaration.relation_key=source.relation_key
                           AND declaration.module_path=source.module_path
                           AND declaration.side='{side}')
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
                AND route.module_path=source.module_path))
    FROM cr_impl_sources AS source
    WHERE NOT EXISTS(SELECT 1 FROM cr_impl_declarations AS declaration
                     WHERE declaration.blob_id=source.blob_id
                       AND declaration.relation_key=source.relation_key
                       AND declaration.module_path=source.module_path
                       AND declaration.side='subject')
       OR NOT EXISTS(SELECT 1 FROM cr_impl_declarations AS declaration
                     WHERE declaration.blob_id=source.blob_id
                       AND declaration.relation_key=source.relation_key
                       AND declaration.module_path=source.module_path
                       AND declaration.side='trait')";

/// Both halves, ordered so that one crate derives the same rows every time.
pub(super) static UNRESOLVED_IMPL_SELECT_SQL: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| {
        format!(
            "SELECT DISTINCT * FROM ({} UNION ALL {}) ORDER BY 1, 2, 3, 4, 5, 6, 7, 8",
            impl_half(
                UNRESOLVED_IMPL_HALF_SQL,
                "subject",
                "cr_impl_subject_routes"
            ),
            impl_half(UNRESOLVED_IMPL_HALF_SQL, "trait", "cr_impl_trait_routes"),
        )
    });
pub(super) const UNRESOLVED_IMPL_INSERT_SQL: &str =
    "INSERT OR IGNORE INTO rust_crate_unresolved_trait_impls VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)";

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
pub(super) static IMPL_SUBJECT_GLOB_BINDINGS_SQL: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| {
        impl_half(IMPL_GLOB_BINDINGS_SQL, "subject", "cr_impl_subject_routes")
    });
pub(super) static IMPL_TRAIT_GLOB_BINDINGS_SQL: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| impl_half(IMPL_GLOB_BINDINGS_SQL, "trait", "cr_impl_trait_routes"));
pub(super) static IMPL_SUBJECT_GAPS_SQL: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| impl_half(IMPL_GAPS_SQL, "subject", "cr_impl_subject_routes"));
pub(super) static IMPL_TRAIT_GAPS_SQL: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| impl_half(IMPL_GAPS_SQL, "trait", "cr_impl_trait_routes"));
pub(super) const IMPL_DECLARATIONS_SQL: &str =
    include_str!("rust_crate_trait_impl_declarations.sql");
pub(super) const IMPL_ROWS_SQL: &str = include_str!("rust_crate_trait_impls.sql");
pub(super) const TRAIT_IMPL_SELECT_SQL: &str = "SELECT * FROM cr_trait_impls";
pub(super) const TRAIT_IMPL_INSERT_SQL: &str =
    "INSERT INTO rust_crate_trait_impls VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)";
pub(super) const FIXPOINT_SQL: &str = include_str!("rust_crate_export_fixpoint.sql");

pub(super) struct ExportRows {
    containers: Vec<Vec<Value>>,
    container_sources: Vec<Vec<Value>>,
    exports: Vec<Vec<Value>>,
    macro_items: Vec<Vec<Value>>,
    decided_item_macros: Vec<Vec<Value>>,
    reexports: Vec<Vec<Value>>,
    glob_reexports: Vec<Vec<Value>>,
    imports: Vec<Vec<Value>>,
    globs: Vec<Vec<Value>>,
    root_references: Vec<Vec<Value>>,
    trait_impls: Vec<Vec<Value>>,
    unresolved_trait_impls: Vec<Vec<Value>>,
    gaps: Vec<Vec<Value>>,
    surface: CrateKey,
}

pub(super) fn derive_exports(
    conn: &Connection,
    item: &PreparedCrate,
    modules: &[Member],
    gate_decisions: &[super::ItemMacroDecision],
    cfg: &str,
    complete: &HashMap<CrateKey, DerivedCrate>,
) -> Result<ExportRows> {
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
            conn.execute(
                SQL_CR_MEMBERS_1,
                params![
                    member.module_path,
                    member.blob_id,
                    member.scope,
                    member.rel_path,
                    member.placement
                ],
            )?;
        }
        conn.execute(SQL_CR_MEMBERS_2, [])?;
        for decision in gate_decisions.iter().filter(|decision| !decision.no_route) {
            conn.execute(
                INSERT_ITEM_MACRO_DECISION_SQL,
                params![
                    decision.blob_id,
                    decision.invocation_occurrence_id,
                    decision.decoration_cfg
                ],
            )?;
        }
        for decision in gate_decisions.iter().filter(|decision| decision.no_route) {
            conn.execute(
                INSERT_ITEM_MACRO_NO_ROUTE_SQL,
                params![decision.blob_id, decision.invocation_occurrence_id],
            )?;
        }
        conn.execute(POPULATE_MEMBER_BLOBS_SQL, [])?;
        conn.execute(POPULATE_SCOPES_SQL, [])?;
        conn.execute(INSERT_IDENTITY_SQL, [item.key.as_slice()])?;
        for (key, dependency) in complete {
            debug_assert_ne!(
                *key, item.key,
                "a crate is published only after its own derivation returns"
            );
            conn.execute(
                INSERT_FOREIGN_SQL,
                params![key.as_slice(), dependency.topology_id],
            )?;
        }
        for (name, _, key) in &item.dependencies {
            conn.execute(
                SQL_CR_DEPENDENCIES_3,
                params![
                    name,
                    key.map(|key| key.to_vec()),
                    key.and_then(|key| complete.get(&key))
                        .map(|dependency| dependency.topology_id)
                ],
            )?;
        }
        conn.execute(EXTERN_CRATE_ALIAS_DEPENDENCIES_SQL, [cfg])?;
    }
    {
        let _timing = stage("export_declarations");
        conn.execute(SOURCE_DECLARATIONS_SQL, [cfg])?;
        conn.execute(RESTRICTION_INPUTS_SQL, [])?;
        conn.execute(RESTRICTIONS_SQL, [])?;
        conn.execute(RESTRICTION_GAPS_SQL, [])?;
        conn.execute(DECLARATIONS_SQL, [])?;
        conn.execute(MACRO_ITEMS_SQL, [cfg])?;
        conn.execute(MACRO_ITEM_ROWS_SQL, [])?;
        conn.execute(MACRO_ITEM_COVERAGE_SQL, [])?;
        conn.execute(SQL_CR_EXPORTS_4, [])?;
    }
    {
        let _timing = stage("enum_containers");
        conn.execute(ENUM_CONTAINERS_SQL, [])?;
    }
    {
        let _timing = stage("enum_variants");
        conn.execute(ENUM_VARIANTS_SQL, [])?;
    }
    {
        let _timing = stage("containers");
        conn.execute(CONTAINERS_SQL, [])?;
        conn.execute(FOREIGN_REEXPORT_STEPS_SQL, [])?;
        conn.execute(CLOSE_REEXPORT_STEPS_SQL, [])?;
        conn.execute(FOREIGN_GLOB_STEPS_SQL, [])?;
        conn.execute(CLOSE_GLOB_STEPS_SQL, [])?;
    }
    {
        let _timing = stage("import_resolution");
        conn.execute(SQL_CR_SOURCE_IMPORTS_5, [cfg])?;
        conn.execute(MACRO_USE_ROUTES_SQL, [])?;
        // A `use crate::m::Name` whose `m` is a name this crate re-exported from
        // a dependency needs that re-export's own route, which the same walk
        // produces. A `use m::Name` whose `m` arrives through `use crate::*;`
        // needs that glob's own route for the same reason, and the glob edges
        // a pass discovers can let the next pass route an import that had no
        // route before. The walk therefore runs until it adds no route: each
        // pass publishes the routes it found as re-export steps and as glob
        // edges, and the next pass follows them. Every pass inserts at least
        // one route or ends the loop, and a route is inserted once, so the loop
        // is bounded by the crate's import count. The two derived relations are
        // monotone in `cr_routes`, so a later pass never withdraws a step an
        // earlier pass added and the walk sees a growing relation only.
        let mut pass = 0usize;
        loop {
            let added = {
                let _timing = crate::profiling::scope_with(|| {
                    format!(
                        "rust_crates.derive name={} kind={} statement=import_routes pass={pass}",
                        item.target.name,
                        target_kind(item.target.kind)
                    )
                });
                conn.execute(
                    ROUTES_SQL.as_str(),
                    params![item.key.as_slice(), edition(item.target.edition)],
                )?
            };
            pass += 1;
            if added == 0 {
                break;
            }
            conn.execute(LOCAL_REEXPORT_STEPS_SQL, [])?;
            conn.execute(CLEAR_REEXPORT_CLOSURE_SQL, [])?;
            conn.execute(CLOSE_REEXPORT_STEPS_SQL, [])?;
            conn.execute(LOCAL_GLOB_STEPS_SQL, [])?;
            conn.execute(CLEAR_GLOB_CLOSURE_SQL, [])?;
            conn.execute(CLOSE_GLOB_STEPS_SQL, [])?;
        }
    }
    {
        // An impl header's two paths walk the same module routes a `use` walks,
        // and they run here so a route that leaves this crate is one of the
        // routes the dependency-export load below reads.
        let _timing = stage("impl_header_routes");
        conn.execute(IMPL_SOURCES_SQL, [])?;
        for routes in [
            IMPL_SUBJECT_ROUTES_SQL.as_str(),
            IMPL_TRAIT_ROUTES_SQL.as_str(),
        ] {
            conn.execute(
                routes,
                params![item.key.as_slice(), IMPL_HEADER_ANCHOR_EDITION],
            )?;
        }
    }
    {
        let _timing = stage("dependency_exports");
        conn.execute(DEPENDENCY_EXPORTS_SQL, [item.key.as_slice()])?;
    }
    let mut iteration = 0usize;
    loop {
        let changed = {
            let _timing = crate::profiling::scope_with(|| {
                format!(
                    "rust_crates.derive name={} kind={} statement=export_fixpoint iteration={iteration}",
                    item.target.name,
                    target_kind(item.target.kind)
                )
            });
            conn.execute(FIXPOINT_SQL, [item.key.as_slice()])?
        };
        crate::profiling::note_with(|| {
            format!(
                "rust_crates.export_fixpoint name={} kind={} iteration={iteration} row_delta={changed}",
                item.target.name,
                target_kind(item.target.kind)
            )
        });
        iteration += 1;
        if changed == 0 {
            break;
        }
    }
    {
        let _timing = stage("reexport_routes");
        conn.execute(SQL_CR_REEXPORTS_6, [])?;
        conn.execute(GLOB_REEXPORTS_SQL, [])?;
    }
    {
        let _timing = stage("import_publication_rows");
        conn.execute(SQL_CR_GLOBS_7, [])?;
        conn.execute(SQL_CR_IMPORTS_8, [])?;
        while conn.execute(ANCESTOR_PRIVATE_IMPORT_BINDINGS_SQL, [])? > 0 {}
        conn.execute(MACRO_USE_IMPORTS_SQL, [])?;
    }
    {
        let _timing = stage("gaps");
        conn.execute(IMPORT_CONFLICT_GAPS_SQL, [])?;
        conn.execute(DELETE_IMPORT_CONFLICTS_SQL, [])?;
        conn.execute(SQL_CR_GAPS_9, [])?;
        conn.execute(
            OPEN_INVENTORY_SQL,
            [crate::analyzer::store::resolution_prepare::resolution_rows::gap_origin_code(
                crate::analyzer::resolution::LoweringGapOrigin::Extracted(
                    brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapKind::UnexpandedImplMacro,
                ),
            )],
        )?;
        conn.execute(UNKNOWN_EXPORTS_SQL, [])?;
    }
    {
        let _timing = stage("root_references");
        conn.execute(MODULE_DECLARATIONS_SQL, [])?;
        conn.execute(ROOT_SOURCES_SQL, [])?;
        conn.execute(
            &ROOT_ROUTES_SQL,
            params![item.key.as_slice(), edition(item.target.edition)],
        )?;
    }
    {
        let _timing = stage("trait_implementations");
        for (bindings, globs) in [
            (
                IMPL_SUBJECT_BINDINGS_SQL.as_str(),
                IMPL_SUBJECT_GLOB_BINDINGS_SQL.as_str(),
            ),
            (
                IMPL_TRAIT_BINDINGS_SQL.as_str(),
                IMPL_TRAIT_GLOB_BINDINGS_SQL.as_str(),
            ),
        ] {
            conn.execute(bindings, [])?;
            conn.execute(globs, [])?;
        }
        conn.execute(IMPL_DECLARATIONS_SQL, [])?;
        for gaps in [IMPL_SUBJECT_GAPS_SQL.as_str(), IMPL_TRAIT_GAPS_SQL.as_str()] {
            conn.execute(gaps, [])?;
        }
        conn.execute(IMPL_ROWS_SQL, [])?;
    }
    let mut digest = Sha256::new();
    {
        let _timing = stage("surface_digest");
        for sql in [
            SQL_CR_EXPORTS_10,
            SQL_CR_REEXPORTS_11,
            GLOB_SURFACE_SQL,
            MACRO_ITEM_SURFACE_SQL,
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
            globs: collect("collect_rows.globs", SQL_CR_GLOBS_15)?,
            root_references: collect("collect_rows.root_references", ROOT_REFERENCES_SELECT_SQL)?,
            trait_impls: collect("collect_rows.trait_impls", TRAIT_IMPL_SELECT_SQL)?,
            unresolved_trait_impls: collect(
                "collect_rows.unresolved_trait_impls",
                &UNRESOLVED_IMPL_SELECT_SQL,
            )?,
            gaps: collect("collect_rows.gaps", SQL_CR_GAPS_16)?,
            surface: digest.finalize().into(),
        }
    };
    Ok(result)
}

fn query_values(conn: &Connection, sql: &str) -> Result<Vec<Vec<Value>>> {
    let mut statement = conn.prepare(sql)?;
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
            (INSERT_ENUM_SOURCE_SQL, self.container_sources),
            (SQL_RUST_CRATE_EXPORTS_17, self.exports),
            (INSERT_MACRO_ITEMS_SQL, self.macro_items),
            (INSERT_DECIDED_ITEM_MACROS_SQL, self.decided_item_macros),
            (SQL_RUST_CRATE_REEXPORT_ROUTES_18, self.reexports),
            (INSERT_GLOB_REEXPORTS_SQL, self.glob_reexports),
            (SQL_RUST_CRATE_IMPORTS_19, self.imports),
            (SQL_RUST_CRATE_GLOB_IMPORTS_20, self.globs),
            (ROOT_REFERENCES_INSERT_SQL, self.root_references),
            (TRAIT_IMPL_INSERT_SQL, self.trait_impls),
            (UNRESOLVED_IMPL_INSERT_SQL, self.unresolved_trait_impls),
            (SQL_RUST_CRATE_GAPS_21, self.gaps),
        ] {
            let mut statement = tx.prepare(sql)?;
            for row in rows {
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
DELETE FROM temp.cr_dependencies;
DELETE FROM temp.cr_identity;
DELETE FROM temp.cr_foreign;
DELETE FROM temp.cr_containers_all;
DELETE FROM temp.cr_reexport_steps;
DELETE FROM temp.cr_reexport_closure;
DELETE FROM temp.cr_glob_steps;
DELETE FROM temp.cr_glob_closure;
DELETE FROM temp.cr_restrictions;
DELETE FROM temp.cr_exports;
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
pub(super) fn prepare_tables(conn: &Connection) -> Result<()> {
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
            parent_module_path TEXT, start_byte INTEGER NOT NULL, end_byte INTEGER NOT NULL, PRIMARY KEY(module_path, blob_id)) WITHOUT ROWID;
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
            nearest_declaration_boundary INTEGER, identifier TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS cr_source_declarations_module
            ON cr_source_declarations(module_path, activation, nearest_declaration_boundary);
        CREATE INDEX IF NOT EXISTS cr_source_declarations_declaration
            ON cr_source_declarations(blob_id, declaration_id);
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
            PRIMARY KEY(crate_key, module_path, bound_name)) WITHOUT ROWID;
        CREATE TEMP TABLE IF NOT EXISTS cr_reexport_closure(crate_key BLOB NOT NULL,
            module_path TEXT NOT NULL, bound_name TEXT NOT NULL, target_crate_key BLOB NOT NULL,
            target_container_path TEXT NOT NULL,
            PRIMARY KEY(crate_key, module_path, bound_name)) WITHOUT ROWID;
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
        CREATE TEMP TABLE IF NOT EXISTS cr_exports(crate_key BLOB NOT NULL, module_path TEXT, namespace TEXT, name TEXT, origin TEXT,
            visibility TEXT, restricted_module_path TEXT, declaration_blob_id INTEGER,
            declaration_site INTEGER, PRIMARY KEY(crate_key, module_path, namespace, name)) WITHOUT ROWID;
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
        CREATE TEMP TABLE IF NOT EXISTS cr_routes(blob_id INTEGER, import_ordinal INTEGER,
            module_path TEXT, target_crate_key BLOB, target_module_path TEXT,
            PRIMARY KEY(blob_id, import_ordinal, module_path)) WITHOUT ROWID;
        CREATE TEMP TABLE IF NOT EXISTS cr_root_sources(blob_id INTEGER, route_key INTEGER,
            module_path TEXT, target_name TEXT, reference_source_site INTEGER,
            PRIMARY KEY(blob_id, route_key, module_path)) WITHOUT ROWID;
        CREATE TEMP TABLE IF NOT EXISTS cr_root_routes(blob_id INTEGER, route_key INTEGER,
            module_path TEXT, target_crate_key BLOB, target_module_path TEXT,
            PRIMARY KEY(blob_id, route_key, module_path)) WITHOUT ROWID;
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
            PRIMARY KEY(module_path, bound_name)) WITHOUT ROWID;
        CREATE TEMP TABLE IF NOT EXISTS cr_glob_reexports AS SELECT module_path, target_crate_key,
            target_module_path, visibility, restricted_module_path FROM rust_crate_glob_reexport_routes WHERE 0;
        CREATE TEMP TABLE IF NOT EXISTS cr_imports AS SELECT module_path, namespace, bound_name, blob_id, import_ordinal,
            binder_scope, target_crate_key, target_module_path, target_name FROM rust_crate_imports WHERE 0;
        CREATE TEMP TABLE IF NOT EXISTS cr_globs AS SELECT module_path, blob_id, import_ordinal, binder_scope,
            target_crate_key, target_module_path FROM rust_crate_glob_imports WHERE 0;
        CREATE TEMP TABLE IF NOT EXISTS cr_gaps(gap_kind TEXT, subject TEXT, detail TEXT);
        CREATE INDEX IF NOT EXISTS cr_imports_name ON cr_imports(module_path, namespace, bound_name);
        CREATE INDEX IF NOT EXISTS cr_globs_module ON cr_globs(module_path);
        CREATE TEMP TABLE IF NOT EXISTS cr_impl_sources(blob_id INTEGER NOT NULL,
            relation_key INTEGER NOT NULL, module_path TEXT NOT NULL, impl_site INTEGER NOT NULL,
            subject_name TEXT NOT NULL, subject_segments INTEGER NOT NULL,
            trait_name TEXT NOT NULL, trait_segments INTEGER NOT NULL,
            impl_declaration_id INTEGER,
            PRIMARY KEY(blob_id, relation_key, module_path)) WITHOUT ROWID;
        CREATE TEMP VIEW IF NOT EXISTS cr_impl_subject_segments AS
            SELECT blob_id, relation_key, position AS ordinal, segment
            FROM resolution_trait_implementations WHERE side='subject' AND segment IS NOT NULL;
        CREATE TEMP VIEW IF NOT EXISTS cr_impl_trait_segments AS
            SELECT blob_id, relation_key, position AS ordinal, segment
            FROM resolution_trait_implementations WHERE side='trait' AND segment IS NOT NULL;
        CREATE TEMP TABLE IF NOT EXISTS cr_impl_subject_routes(blob_id INTEGER,
            relation_key INTEGER, module_path TEXT, target_crate_key BLOB,
            target_module_path TEXT,
            PRIMARY KEY(blob_id, relation_key, module_path)) WITHOUT ROWID;
        CREATE TEMP TABLE IF NOT EXISTS cr_impl_trait_routes(blob_id INTEGER,
            relation_key INTEGER, module_path TEXT, target_crate_key BLOB,
            target_module_path TEXT,
            PRIMARY KEY(blob_id, relation_key, module_path)) WITHOUT ROWID;
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
    Ok(())
}

pub(super) const SQL_CR_MEMBERS_1: &str = "INSERT INTO cr_members
            SELECT ?1, ?2, ?3, ?4, ?5, NULL, COALESCE(declaration.body_start_byte, 0), COALESCE(declaration.body_end_byte, manifest.source_bytes)
            FROM source_fact_manifests AS manifest
            LEFT JOIN source_rust_module_scopes AS scope ON scope.blob_id = manifest.blob_id AND scope.ordinal = ?3
            LEFT JOIN source_rust_module_declarations AS declaration ON declaration.blob_id = scope.blob_id AND declaration.declaration_id = scope.declaration_id
            WHERE manifest.blob_id = ?2";
pub(super) const SQL_CR_MEMBERS_2: &str = "UPDATE cr_members AS child SET parent_module_path = (
        SELECT parent.module_path FROM cr_members AS parent
        JOIN source_rust_module_declarations AS declaration ON declaration.blob_id = parent.blob_id
        WHERE child.module_path = parent.module_path || '::' || declaration.module_name
        LIMIT 1) WHERE child.module_path <> 'crate'";
pub(super) const INSERT_ITEM_MACRO_DECISION_SQL: &str =
    "INSERT INTO cr_item_macro_decisions VALUES(?1, ?2, ?3)";
pub(super) const INSERT_ITEM_MACRO_NO_ROUTE_SQL: &str =
    "INSERT INTO cr_item_macro_no_routes VALUES(?1, ?2)";
pub(super) const SELECT_DECIDED_ITEM_MACROS_SQL: &str = "SELECT blob_id, invocation_occurrence_id, decoration_cfg FROM cr_item_macro_decisions ORDER BY blob_id, invocation_occurrence_id";
pub(super) const INSERT_DECIDED_ITEM_MACROS_SQL: &str =
    "INSERT INTO rust_crate_decided_item_macros VALUES(?1, ?2, ?3, ?4)";
pub(super) const POPULATE_MEMBER_BLOBS_SQL: &str =
    "INSERT INTO cr_member_blobs SELECT DISTINCT blob_id FROM cr_members";
pub(super) const POPULATE_SCOPES_SQL: &str = "INSERT OR IGNORE INTO cr_scopes
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
pub(super) const INSERT_IDENTITY_SQL: &str = "INSERT INTO cr_identity VALUES(?1)";
// The crates whose derivation already finished in an earlier wave, with the
// topology whose rows they published. A route that leaves this crate names one
// of them; every crate it can reach is a dependency, so it is derived already.
pub(super) const INSERT_FOREIGN_SQL: &str = "INSERT INTO cr_foreign
    SELECT ?1, ?2, crate_name FROM rust_crate_topologies WHERE topology_id = ?2";
// Every container a route may step into, this crate's pending ones and the
// derived crates' published ones, under the crate key that owns it.
pub(super) const CONTAINERS_SQL: &str = "INSERT OR IGNORE INTO cr_containers_all
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
pub(super) const FOREIGN_REEXPORT_STEPS_SQL: &str = "INSERT OR IGNORE INTO cr_reexport_steps
    SELECT dependency.crate_key, routes.module_path, routes.bound_name,
           routes.target_crate_key, routes.target_module_path, routes.target_name
    FROM cr_foreign AS dependency
    CROSS JOIN rust_crate_reexport_routes AS routes ON routes.topology_id = dependency.topology_id";
// The same relation for this crate's own `use` items, public or private: a
// private `use` in a module still names that module's path for its descendants.
//
// A `use` with no module segment whose name is a workspace dependency
// (`pub use dep;`, `pub use dep as alias;`, `pub use dep::{self as alias}`)
// binds the dependency's root module. Its target is spelled as that crate's
// `crate` module with the name `self`, the way Rust spells a module itself
// (`dep::{self}`); the closure below resolves `self` to the module.
pub(super) const LOCAL_REEXPORT_STEPS_SQL: &str = "INSERT OR IGNORE INTO cr_reexport_steps
    SELECT identity.crate_key, source.module_path, source.bound_name,
           COALESCE(root.dependency_crate_key, route.target_crate_key),
           CASE WHEN root.dependency_crate_key IS NOT NULL THEN 'crate' ELSE route.target_module_path END,
           CASE WHEN root.dependency_crate_key IS NOT NULL THEN 'self' ELSE source.imported_name END
    FROM cr_identity AS identity
    CROSS JOIN cr_source_imports AS source
    CROSS JOIN cr_routes AS route ON route.blob_id = source.blob_id
      AND route.import_ordinal = source.import_ordinal AND route.module_path = source.module_path
    LEFT JOIN cr_dependencies AS root ON source.head_segment IS NULL
      AND root.extern_name = source.imported_name AND root.dependency_crate_key IS NOT NULL
    WHERE source.is_glob = 0 AND source.bound_name IS NOT NULL";
// A re-export can name another re-export: the umbrella crate binds `usages` to
// a dependency's `crate::usages`, which the dependency binds in turn to its own
// `crate::analyzer::usages`. The walk needs the container the chain ends on, so
// the steps are chased to their terminal here rather than one hop at a time.
// The chase stops at a real container, because a container always beats a
// re-export of the same name, and at a depth cap, because a re-export cycle is
// invalid Rust that must not spin. The relation is functional on its key, so a
// chain has one terminal; a chain that hits the cap has none and its name stays
// unresolved.
pub(super) const CLOSE_REEXPORT_STEPS_SQL: &str = "INSERT OR IGNORE INTO cr_reexport_closure
    WITH RECURSIVE chase(crate_key, module_path, bound_name, target_crate_key,
                         target_module_path, target_name, depth) AS (
      SELECT crate_key, module_path, bound_name, target_crate_key,
             target_module_path, target_name, 0
      FROM cr_reexport_steps
      UNION ALL
      SELECT chase.crate_key, chase.module_path, chase.bound_name,
             next_step.target_crate_key, next_step.target_module_path, next_step.target_name,
             chase.depth + 1
      FROM chase
      CROSS JOIN cr_reexport_steps AS next_step
        ON next_step.crate_key = chase.target_crate_key
       AND next_step.module_path = chase.target_module_path
       AND next_step.bound_name = chase.target_name
      WHERE chase.depth < 64
        AND chase.target_name <> 'self'
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
pub(super) const CLEAR_REEXPORT_CLOSURE_SQL: &str = "DELETE FROM cr_reexport_closure";
// One glob edge: the module a `use other::*;` writes it in, and the module that
// glob reaches. A derived crate contributes only the globs it published, which
// are its non-private ones, and only a public one crosses a crate boundary.
pub(super) const FOREIGN_GLOB_STEPS_SQL: &str = "INSERT OR IGNORE INTO cr_glob_steps
    SELECT dependency.crate_key, routes.module_path,
           routes.target_crate_key, routes.target_module_path
    FROM cr_foreign AS dependency
    CROSS JOIN rust_crate_glob_reexport_routes AS routes
      ON routes.topology_id = dependency.topology_id
    WHERE routes.visibility = 'public'";
// This crate's own glob imports, public or private: a private `use crate::*;`
// still binds names in the module that writes it, the same way a private named
// `use` does in LOCAL_REEXPORT_STEPS_SQL.
pub(super) const LOCAL_GLOB_STEPS_SQL: &str = "INSERT OR IGNORE INTO cr_glob_steps
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
// A glob cycle is legal Rust, so unlike CLOSE_REEXPORT_STEPS_SQL there is no
// depth cap to break one: deduplication already terminates the chase.
pub(super) const CLOSE_GLOB_STEPS_SQL: &str = "INSERT OR IGNORE INTO cr_glob_closure
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
pub(super) const CLEAR_GLOB_CLOSURE_SQL: &str = "DELETE FROM cr_glob_closure";
// The dependency export rows this crate's routes actually reach, keyed by the
// dependency's crate key so the fixpoint and the binding statement read one
// relation. Only a public export crosses a crate boundary.
pub(super) const DEPENDENCY_EXPORTS_SQL: &str = "INSERT OR IGNORE INTO cr_exports
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
pub(super) const ENUM_CONTAINERS_SQL: &str = "INSERT OR IGNORE INTO cr_enums
 SELECT candidate.module_path || '::' || candidate.identifier, site.blob_id,
        site.semantic_key, scope.scope_head_node_key, member.rel_path,
        candidate.module_path
 FROM cr_source_declarations AS candidate
 CROSS JOIN source_native_declaration_bridges AS bridge
  ON bridge.blob_id=candidate.blob_id AND bridge.declaration_id=candidate.declaration_id
 CROSS JOIN resolution_semantic_sites AS site ON site.blob_id=bridge.blob_id
  AND site.source_site=bridge.source_site AND site.semantic_role='definition'
 CROSS JOIN resolution_member_scope_properties AS scope ON scope.blob_id=site.blob_id AND scope.definition_semantic_key=site.semantic_key
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
pub(super) const ENUM_VARIANTS_SQL: &str = "INSERT INTO cr_exports
 SELECT (SELECT crate_key FROM cr_identity), container.container_path, namespace.namespace, candidate.identifier,
        'declaration', 'public', NULL, site.blob_id, site.source_site
 FROM cr_enums AS container
 CROSS JOIN resolution_member_owner_properties AS member ON member.blob_id=container.blob_id AND member.owner_definition_semantic_key=container.definition_semantic_key
 CROSS JOIN resolution_semantic_sites AS site ON site.blob_id=member.blob_id AND site.semantic_key=member.definition_semantic_key AND site.semantic_role='definition'
 CROSS JOIN source_native_declaration_bridges AS bridge ON bridge.blob_id=site.blob_id AND bridge.source_site=site.source_site
 CROSS JOIN cr_source_declarations AS candidate
  ON candidate.blob_id=bridge.blob_id AND candidate.declaration_id=bridge.declaration_id
  AND candidate.module_path=container.module_path
 CROSS JOIN resolution_additional_definition_namespaces AS namespace ON namespace.blob_id=site.blob_id AND namespace.definition_semantic_key=site.semantic_key
 WHERE candidate.declaration_kind=9 AND candidate.activation=1
   AND namespace.namespace IN ('type','value')";
pub(super) const ENUM_CONTAINER_ROWS_SQL: &str =
    "SELECT container_path, 'enum', 'enum_declaration' FROM cr_enums ORDER BY container_path";
pub(super) const ENUM_SOURCE_ROWS_SQL: &str = "SELECT container_path, blob_id, NULL, rel_path, 'declared', scope_node_key, module_path FROM cr_enums ORDER BY container_path";
pub(super) const INSERT_ENUM_CONTAINER_SQL: &str =
    "INSERT INTO rust_crate_containers VALUES(?1,?2,?3,?4)";
pub(super) const INSERT_ENUM_SOURCE_SQL: &str =
    "INSERT INTO rust_crate_container_sources VALUES(?1,?2,?3,?4,?5,?6,?7,?8)";

pub(super) const SQL_CR_EXPORTS_4: &str = "INSERT OR IGNORE INTO cr_exports
        SELECT exports.crate_key, exports.module_path, CASE WHEN additional.namespace = 'macro' THEN 'macro'
               WHEN additional.namespace = 'type' THEN 'type' ELSE 'value' END,
               exports.name, exports.origin, exports.visibility, exports.restricted_module_path,
               exports.declaration_blob_id, exports.declaration_site
        FROM cr_exports AS exports
        JOIN resolution_semantic_sites AS site ON site.blob_id = exports.declaration_blob_id AND site.source_site = exports.declaration_site
        JOIN resolution_additional_definition_namespaces AS additional ON additional.blob_id = site.blob_id AND additional.definition_semantic_key = site.semantic_key";
pub(super) const SQL_CR_SOURCE_IMPORTS_5: &str = "INSERT INTO cr_source_imports
        SELECT imports.blob_id, imports.ordinal, members.module_path,
               imports.native_scope, imports.bound_name, imports.imported_name,
               imports.is_glob, imports.visibility,
               (SELECT segment.segment
                FROM source_rust_import_module_segments AS segment
                WHERE segment.blob_id=imports.blob_id
                  AND segment.import_ordinal=imports.ordinal
                  AND segment.ordinal=0),
               imports.is_macro_use
        FROM cr_members AS members
        JOIN source_rust_import_targets AS imports ON imports.blob_id = members.blob_id
        JOIN source_imports AS declaration ON declaration.blob_id = imports.blob_id AND declaration.import_id = imports.source_import_id
        WHERE cr_cfg(imports.cfg_condition, ?1) = 1 AND imports.native_scope IS NOT NULL
          AND declaration.declaration_start_byte >= members.start_byte AND declaration.declaration_end_byte <= members.end_byte
          AND NOT EXISTS(SELECT 1 FROM cr_scopes AS inner_module WHERE inner_module.blob_id = members.blob_id
              AND inner_module.scope_ordinal <> members.scope_ordinal
              AND inner_module.start_byte >= members.start_byte AND inner_module.end_byte <= members.end_byte
              AND declaration.declaration_start_byte >= inner_module.start_byte AND declaration.declaration_end_byte <= inner_module.end_byte)";
pub(super) const SQL_CR_REEXPORTS_6: &str = "INSERT OR IGNORE INTO cr_reexports
        SELECT source.module_path, source.bound_name,
               COALESCE(root.dependency_crate_key, route.target_crate_key),
               CASE WHEN root.dependency_crate_key IS NOT NULL THEN 'crate' ELSE route.target_module_path END,
               CASE WHEN root.dependency_crate_key IS NOT NULL THEN 'self' ELSE source.imported_name END,
               cr_visibility(source.visibility), (SELECT restricted_module_path FROM cr_restrictions WHERE module_path=source.module_path AND visibility=source.visibility)
        FROM cr_source_imports AS source JOIN cr_routes AS route USING(blob_id, import_ordinal, module_path)
        JOIN cr_members AS member ON member.module_path = source.module_path AND member.blob_id = source.blob_id
        LEFT JOIN cr_dependencies AS root ON source.head_segment IS NULL
          AND root.extern_name = source.imported_name AND root.dependency_crate_key IS NOT NULL
        WHERE (cr_visibility(source.visibility)<>'restricted' OR EXISTS(SELECT 1 FROM cr_restrictions WHERE module_path=source.module_path AND visibility=source.visibility AND restricted_module_path IS NOT NULL)) AND source.visibility <> 'private' AND source.is_glob = 0 AND source.bound_name IS NOT NULL";
// `#[macro_use] extern crate rocket;` names a crate in the extern prelude, not
// a member of the module that writes it, and it spells no module segment at
// all. The shared route walk's base row would therefore answer it with the
// writing module, so the route to the dependency's own root is stated here
// before the walk runs and the walk's `INSERT OR IGNORE` leaves it alone.
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
        SELECT source.module_path, 'macro', exports.name, source.blob_id,
               source.import_ordinal, source.binder_scope,
               route.target_crate_key, route.target_module_path, exports.name
        FROM cr_source_imports AS source
        CROSS JOIN cr_routes AS route ON route.blob_id = source.blob_id
          AND route.import_ordinal = source.import_ordinal AND route.module_path = source.module_path
        CROSS JOIN cr_exports AS exports ON exports.crate_key = route.target_crate_key
          AND exports.module_path = route.target_module_path AND exports.namespace = 'macro'
        WHERE source.is_macro_use = 1";
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
               WHEN source.visibility = 'private' THEN 'unresolved_import' ELSE 'unresolved_reexport' END,
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
          AND ((source.is_glob = 0 AND source.bound_name IS NULL)
           OR NOT EXISTS(SELECT 1 FROM cr_routes AS route WHERE route.blob_id = source.blob_id AND route.import_ordinal = source.import_ordinal AND route.module_path = source.module_path)
           OR (source.is_glob = 0 AND source.visibility = 'private' AND NOT EXISTS(
               SELECT 1 FROM cr_imports AS imports WHERE imports.module_path = source.module_path AND imports.blob_id = source.blob_id AND imports.import_ordinal = source.import_ordinal))
           OR (source.is_glob = 0 AND source.visibility <> 'private' AND NOT EXISTS(
               SELECT 1 FROM cr_exports AS exports WHERE exports.crate_key = (SELECT crate_key FROM cr_identity)
                 AND exports.module_path = source.module_path AND exports.name = source.bound_name)))";
pub(super) const SQL_CR_EXPORTS_10: &str = "SELECT exports.module_path, exports.namespace, exports.name, exports.origin, definition.module_path, definition.name FROM cr_exports AS exports JOIN cr_exports AS definition ON definition.declaration_blob_id = exports.declaration_blob_id AND definition.declaration_site = exports.declaration_site AND definition.namespace = exports.namespace AND definition.origin = 'declaration' AND definition.crate_key = exports.crate_key WHERE exports.crate_key = (SELECT crate_key FROM cr_identity) AND exports.visibility = 'public' ORDER BY 1, 2, 3, 5, 6";
pub(super) const SQL_CR_REEXPORTS_11: &str = "SELECT module_path, bound_name, target_crate_key, target_module_path, target_name FROM cr_reexports WHERE visibility = 'public' ORDER BY 1, 2, 3, 4, 5";
pub(super) const SQL_CR_EXPORTS_12: &str =
    "SELECT module_path, namespace, name, origin, visibility, restricted_module_path,
            declaration_blob_id, declaration_site FROM cr_exports
     WHERE crate_key = (SELECT crate_key FROM cr_identity)
     ORDER BY module_path, namespace, name";
pub(super) const SQL_CR_REEXPORTS_13: &str = "SELECT * FROM cr_reexports";
pub(super) const SQL_CR_IMPORTS_14: &str = "SELECT * FROM cr_imports";
pub(super) const SQL_CR_GLOBS_15: &str = "SELECT * FROM cr_globs";
pub(super) const SQL_CR_GAPS_16: &str = "SELECT gap_kind, subject, json_object('evidence', json_group_array(json(detail))) FROM cr_gaps GROUP BY gap_kind, subject";
pub(super) const SQL_RUST_CRATE_EXPORTS_17: &str =
    "INSERT INTO rust_crate_exports VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)";
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
pub(super) const ROOT_REFERENCES_SELECT_SQL: &str = "SELECT source.module_path, source.blob_id, source.route_key, source.reference_source_site, route.target_crate_key, COALESCE(anchor.parent_module_path, route.target_module_path), COALESCE(anchor.module_name, source.target_name) FROM cr_root_sources AS source CROSS JOIN cr_root_routes AS route USING(blob_id,route_key,module_path) LEFT JOIN cr_module_declarations AS anchor ON source.target_name IN ('crate','self','super') AND anchor.module_path=route.target_module_path WHERE source.target_name NOT IN ('crate','self','super') OR anchor.module_path IS NOT NULL";
// A module name is one identifier, so a module path names one parent and one
// name; a second pair behind the same path fails the primary key.
pub(super) const MODULE_DECLARATIONS_SQL: &str = "INSERT INTO cr_module_declarations SELECT DISTINCT parent.module_path || '::' || declaration.module_name, parent.module_path, declaration.module_name FROM cr_members AS parent CROSS JOIN source_rust_module_declarations AS declaration ON declaration.blob_id = parent.blob_id";
pub(super) const ROOT_REFERENCES_INSERT_SQL: &str =
    "INSERT INTO rust_crate_root_references VALUES(?1,?2,?3,?4,?5,?6,?7,?8)";
#[cfg(any(test, feature = "test-support"))]
pub(super) fn sql_pins() -> Vec<(&'static str, &'static str, usize)> {
    vec![
        ("rust_crate_visibility_routes", RESTRICTIONS_SQL, 0),
        ("rust_crate_visibility_inputs", RESTRICTION_INPUTS_SQL, 0),
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
        ("rust_crate_insert_foreign", INSERT_FOREIGN_SQL, 2),
        ("rust_crate_containers_all", CONTAINERS_SQL, 0),
        (
            "rust_crate_foreign_reexport_steps",
            FOREIGN_REEXPORT_STEPS_SQL,
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
        ("rust_crate_open_export_inventory", OPEN_INVENTORY_SQL, 1),
        ("rust_crate_unknown_exports", UNKNOWN_EXPORTS_SQL, 0),
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
        (
            "rust_crate_derivation_sql_rust_crate_exports_17",
            SQL_RUST_CRATE_EXPORTS_17,
            9,
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
        ("rust_crate_root_routes", ROOT_ROUTES_SQL.as_str(), 2),
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
        ("rust_crate_trait_impl_sources", IMPL_SOURCES_SQL, 0),
        (
            "rust_crate_trait_impl_subject_routes",
            IMPL_SUBJECT_ROUTES_SQL.as_str(),
            2,
        ),
        (
            "rust_crate_trait_impl_trait_routes",
            IMPL_TRAIT_ROUTES_SQL.as_str(),
            2,
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
            9,
        ),
    ]
}

pub(super) const IMPORT_CONFLICT_GAPS_SQL: &str = "INSERT INTO cr_gaps
    SELECT 'unresolved_import', module_path || '::' || bound_name || ':' || namespace,
           json_object('reason', 'conflicting bindings in one lexical scope', 'imports', json_group_array(import_ordinal))
    FROM cr_imports GROUP BY module_path, blob_id, binder_scope, namespace, bound_name HAVING count(*) > 1";
pub(super) const DELETE_IMPORT_CONFLICTS_SQL: &str = "DELETE FROM cr_imports WHERE
    (module_path, blob_id, binder_scope, namespace, bound_name) IN
    (SELECT module_path, blob_id, binder_scope, namespace, bound_name FROM cr_imports GROUP BY module_path, blob_id, binder_scope, namespace, bound_name HAVING count(*) > 1)";

pub(super) const GLOB_REEXPORTS_SQL: &str = "INSERT INTO cr_glob_reexports
    SELECT source.module_path, route.target_crate_key, route.target_module_path,
           cr_visibility(source.visibility), (SELECT restricted_module_path FROM cr_restrictions WHERE module_path=source.module_path AND visibility=source.visibility)
    FROM cr_source_imports AS source JOIN cr_routes AS route USING(blob_id, import_ordinal, module_path)
    JOIN cr_members AS member ON member.module_path = source.module_path AND member.blob_id = source.blob_id
    WHERE (cr_visibility(source.visibility)<>'restricted' OR EXISTS(SELECT 1 FROM cr_restrictions WHERE module_path=source.module_path AND visibility=source.visibility AND restricted_module_path IS NOT NULL)) AND source.visibility <> 'private' AND source.is_glob = 1";
pub(super) const GLOB_SURFACE_SQL: &str = "SELECT module_path, target_crate_key, target_module_path FROM cr_glob_reexports WHERE visibility = 'public' ORDER BY 1, 2, 3";
pub(super) const SELECT_GLOB_REEXPORTS_SQL: &str = "SELECT * FROM cr_glob_reexports";
pub(super) const INSERT_GLOB_REEXPORTS_SQL: &str =
    "INSERT OR IGNORE INTO rust_crate_glob_reexport_routes VALUES(?1,?2,?3,?4,?5,?6)";
