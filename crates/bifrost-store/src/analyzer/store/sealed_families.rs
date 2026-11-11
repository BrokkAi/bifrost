//! Debug-only assertion that sealed derivation families are written by their owner.

use rusqlite::Connection;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Owner {
    Resolution,
    UnitSummary,
    CrateTopology,
    /// Blob facts written in the blob completion transaction.
    BlobRows,
}

#[cfg(any(debug_assertions, test, feature = "test-support"))]
pub(super) const RESOLUTION: &[&str] = &[
    "resolution_gap_reasons",
    "resolution_rust_declaration_authorities",
    "resolution_semantic_sites",
    "resolution_paths",
    "resolution_sites",
    "resolution_typed_fact_lookups",
    "resolution_gaps",
    "resolution_node_catalog",
    "resolution_qualified_routes",
    "resolution_semantic_catalog",
    "resolution_rust_reference_contexts",
    "resolution_member_scope_properties",
    "resolution_type_frontiers",
    "resolution_deferred_member_owners",
    "resolution_binding_projections",
    "resolution_type_transfers",
    "resolution_intrinsic_seeds",
    "resolution_member_owner_properties",
    "resolution_definition_property_gaps",
    "resolution_path_endpoint_headers",
    "resolution_callable_signatures",
    "resolution_root_import_segments",
    "resolution_root_import_demands",
    "resolution_root_imports",
    "resolution_call_obligations",
    "resolution_type_productions",
    "resolution_member_type_coverage",
    "resolution_declaration_types",
    "resolution_definition_unit_crosswalks",
    "resolution_type_arguments",
    "resolution_construction_requirements",
    "resolution_singleton_relations",
    "resolution_contract_references",
    "resolution_declared_type_arguments",
    "resolution_supertypes",
    "resolution_generic_formals",
    "resolution_generic_type_alias_parameters",
    "resolution_generic_formal_defaults",
    "resolution_type_components",
    "resolution_intrinsic_seed_identities",
    "legacy_resolution_declaration_visibility_properties",
    "resolution_fragment_interiors",
];

#[cfg(any(debug_assertions, test, feature = "test-support"))]
pub(super) const UNIT_SUMMARY: &[&str] = &[
    "resolution_unit_summary_members",
    "resolution_unit_summary_dependencies",
    "resolution_unit_summary_dependency_names",
    "resolution_unit_summary_containers",
    "resolution_unit_summary_placements",
    "rust_resolution_unit_summary_placement_attributes",
    "rust_resolution_unit_summary_contexts",
    "rust_resolution_unit_summary_gaps",
    "rust_resolution_unit_summary_exports",
    "rust_resolution_unit_summary_import_routes",
    "rust_resolution_unit_summary_glob_imports",
    "rust_resolution_unit_summary_trait_endpoints",
    "rust_resolution_unit_summary_generated_names",
    "rust_resolution_unit_summary_file_naming",
    "rust_resolution_unit_summary_container_attributes",
    "rust_resolution_unit_summary_reexport_routes",
    "rust_resolution_unit_summary_glob_reexport_routes",
    "rust_resolution_unit_summary_root_routes",
];

#[cfg(any(debug_assertions, test, feature = "test-support"))]
pub(super) const CRATE_TOPOLOGY: &[&str] = &[
    "rust_crate_binding_owners",
    "rust_crate_binding_alternatives",
    "rust_crate_binding_names",
    "rust_crate_binding_blockers",
    "rust_crate_gaps",
    "rust_crate_path_probes",
    "rust_crate_imports",
    "rust_crate_containers",
    "rust_crate_container_sources",
];

#[cfg(any(debug_assertions, test, feature = "test-support"))]
pub(super) const BLOB_ROWS: &[&str] = &["code_units"];

// Tables a derivation may read under a statement family without an owner
// scope here, each with the mechanism that pins its rows for an unchanged

/// The owner constants by owner, for the family partition test.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn owner_tables_for_test() -> [(&'static str, &'static [&'static str]); 4] {
    [
        ("Resolution", RESOLUTION),
        ("UnitSummary", UNIT_SUMMARY),
        ("CrateTopology", CRATE_TOPOLOGY),
        ("BlobRows", BLOB_ROWS),
    ]
}

#[cfg(any(debug_assertions, test, feature = "test-support"))]
mod enabled {
    use super::*;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
    use std::cell::{Cell, RefCell};

    thread_local! {
        static CURRENT: Cell<Option<Owner>> = const { Cell::new(None) };
        static CASCADE_DELETE: Cell<u32> = const { Cell::new(0) };
        static VIOLATION: RefCell<Option<String>> = const { RefCell::new(None) };
    }

    fn owner(table: &str) -> Option<Owner> {
        if RESOLUTION.contains(&table) {
            Some(Owner::Resolution)
        } else if UNIT_SUMMARY.contains(&table) {
            Some(Owner::UnitSummary)
        } else if CRATE_TOPOLOGY.contains(&table) {
            Some(Owner::CrateTopology)
        } else if BLOB_ROWS.contains(&table) {
            Some(Owner::BlobRows)
        } else {
            None
        }
    }

    pub(crate) fn install(conn: &Connection) {
        super::super::connection_authorizer::install_writer_guard(conn, writer_authorization);
    }

    pub(super) fn writer_authorization(ctx: AuthContext<'_>) -> Authorization {
        let (table, action) = match ctx.action {
            AuthAction::Insert { table_name } => (table_name, "INSERT"),
            AuthAction::Update { table_name, .. } => (table_name, "UPDATE"),
            AuthAction::Delete { table_name } => (table_name, "DELETE"),
            _ => return Authorization::Allow,
        };
        if let Some(expected) = owner(table) {
            let current = CURRENT.get();
            #[cfg(any(test, feature = "test-support"))]
            let fixture = FIXTURE.get() > 0;
            #[cfg(not(any(test, feature = "test-support")))]
            let fixture = false;
            if current != Some(expected)
                && !(action == "DELETE" && CASCADE_DELETE.get() > 0)
                && !fixture
            {
                VIOLATION.with_borrow_mut(|slot| {
                    *slot = Some(format!(
                        "sealed family {table} {action} under {current:?}, expected {expected:?}"
                    ));
                });
                return Authorization::Deny;
            }
        }
        Authorization::Allow
    }

    pub(crate) fn check() {
        if let Some(message) = VIOLATION.with_borrow_mut(Option::take) {
            panic!("{message}");
        }
    }

    /// Release builds do not install a hook or perform a per-statement check.
    pub(crate) struct Scope<'a> {
        conn: &'a Connection,
        previous: Option<Owner>,
    }
    impl<'a> Scope<'a> {
        pub(crate) fn new(conn: &'a Connection, kind: Owner) -> Self {
            let previous = CURRENT.get();
            assert!(
                previous.is_none() || previous == Some(kind),
                "nested sealed-family owners: {previous:?} then {kind:?}"
            );
            CURRENT.set(Some(kind));
            Self { conn, previous }
        }
    }
    impl Drop for Scope<'_> {
        fn drop(&mut self) {
            self.conn.flush_prepared_statement_cache();
            CURRENT.set(self.previous);
        }
    }

    /// Permits only cascaded deletes while a parent row is removed.
    pub(crate) struct CascadeDelete<'a>(&'a Connection);
    impl<'a> CascadeDelete<'a> {
        pub(crate) fn new(conn: &'a Connection) -> Self {
            CASCADE_DELETE.set(CASCADE_DELETE.get() + 1);
            Self(conn)
        }
    }
    impl Drop for CascadeDelete<'_> {
        fn drop(&mut self) {
            self.0.flush_prepared_statement_cache();
            CASCADE_DELETE.set(CASCADE_DELETE.get() - 1);
        }
    }

    /// Test fixture rows may be written without invoking a production owner.
    #[cfg(any(test, feature = "test-support"))]
    /// Allows writing fixture rows in tests only.
    #[doc(hidden)]
    pub struct Fixture<'a>(&'a Connection);
    #[cfg(any(test, feature = "test-support"))]
    impl<'a> Fixture<'a> {
        pub fn new(conn: &'a Connection) -> Self {
            FIXTURE.set(FIXTURE.get() + 1);
            Self(conn)
        }
    }
    #[cfg(any(test, feature = "test-support"))]
    thread_local! { static FIXTURE: Cell<u32> = const { Cell::new(0) }; }
    #[cfg(any(test, feature = "test-support"))]
    impl Drop for Fixture<'_> {
        fn drop(&mut self) {
            self.0.flush_prepared_statement_cache();
            FIXTURE.set(FIXTURE.get() - 1);
        }
    }

    /// Runs `job` with fixture writes allowed, for a job that needs the
    /// connection mutably (a transaction), then flushes the statement cache.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn fixture_rows<T>(conn: &mut Connection, job: impl FnOnce(&mut Connection) -> T) -> T {
        struct Allowed;
        impl Drop for Allowed {
            fn drop(&mut self) {
                FIXTURE.set(FIXTURE.get() - 1);
            }
        }
        FIXTURE.set(FIXTURE.get() + 1);
        let allowed = Allowed;
        let value = job(conn);
        drop(allowed);
        conn.flush_prepared_statement_cache();
        value
    }
}
#[cfg(any(debug_assertions, test, feature = "test-support"))]
pub(super) use enabled::{CascadeDelete, Scope, check, install};
#[cfg(any(test, feature = "test-support"))]
pub use enabled::{Fixture, fixture_rows};

#[cfg(not(any(debug_assertions, test, feature = "test-support")))]
pub(super) struct Scope;
#[cfg(not(any(debug_assertions, test, feature = "test-support")))]
pub(super) struct CascadeDelete;
#[cfg(not(any(debug_assertions, test, feature = "test-support")))]
impl CascadeDelete {
    pub(super) fn new(_: &Connection) -> Self {
        Self
    }
}
#[cfg(not(any(debug_assertions, test, feature = "test-support")))]
impl Scope {
    pub(super) fn new(_: &Connection, _: Owner) -> Self {
        Self
    }
}
#[cfg(not(any(debug_assertions, test, feature = "test-support")))]
pub(super) fn install(_: &Connection) {}
#[cfg(not(any(debug_assertions, test, feature = "test-support")))]
pub(super) fn check() {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::store::writer::StoreWriter;

    fn writer() -> StoreWriter {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys=ON;
            CREATE TABLE parent(id INTEGER PRIMARY KEY);
            CREATE TABLE resolution_paths(id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES parent(id) ON DELETE CASCADE);
            CREATE TABLE resolution_unit_summary_members(id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES parent(id) ON DELETE CASCADE);
            CREATE TABLE rust_crate_imports(id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES parent(id) ON DELETE CASCADE);
            CREATE TABLE code_units(id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES parent(id) ON DELETE CASCADE);").unwrap();
        StoreWriter::local(conn)
    }

    fn panic_text(value: Box<dyn std::any::Any + Send>) -> String {
        if let Some(text) = value.downcast_ref::<String>() {
            text.clone()
        } else if let Some(text) = value.downcast_ref::<&str>() {
            (*text).to_owned()
        } else {
            panic!("unexpected panic payload")
        }
    }

    #[test]
    fn sealed_family_tables_exist_and_are_disjoint() {
        let schema = include_str!("../../../../bifrost-core/migrations/cache/current-schema.sql");
        let mut names = std::collections::HashSet::new();
        for table in RESOLUTION
            .iter()
            .chain(UNIT_SUMMARY)
            .chain(CRATE_TOPOLOGY)
            .chain(BLOB_ROWS)
        {
            assert!(names.insert(*table), "duplicate sealed table: {table}");
            assert!(
                schema.contains(&format!("CREATE TABLE {table}"))
                    || schema.contains(&format!("CREATE TABLE \"{table}\"")),
                "missing table: {table}"
            );
        }
    }

    #[test]
    fn sealed_family_writes_require_their_owner() {
        let writer = writer();
        for table in [
            "resolution_paths",
            "resolution_unit_summary_members",
            "rust_crate_imports",
            "code_units",
        ] {
            let sql = format!("INSERT INTO {table}(id) VALUES (1)");
            let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                writer.execute(move |conn| conn.execute(&sql, []))
            }))
            .unwrap_err();
            assert!(panic_text(panic).contains(table));
        }
    }

    #[test]
    fn wrong_owner_and_cached_statement_are_denied() {
        let writer = writer();
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            writer.execute(|conn| {
                let _scope = Scope::new(conn, Owner::UnitSummary);
                conn.execute("INSERT INTO resolution_paths(id) VALUES (1)", [])
            })
        }))
        .unwrap_err();
        assert!(panic_text(panic).contains("resolution_paths"));
        writer.execute(|conn| {
            let _scope = Scope::new(conn, Owner::Resolution);
            conn.prepare_cached("INSERT INTO resolution_paths(id) VALUES (2)")
                .unwrap()
                .execute([])
                .unwrap();
        });
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            writer.execute(|conn| {
                conn.prepare_cached("INSERT INTO resolution_paths(id) VALUES (2)")
                    .unwrap()
                    .execute([])
            })
        }))
        .unwrap_err();
        assert!(panic_text(panic).contains("resolution_paths"));
    }

    #[test]
    fn parent_delete_cascades_outside_owner() {
        let writer = writer();
        for (id, table, owner) in [
            (1, "resolution_paths", Owner::Resolution),
            (2, "resolution_unit_summary_members", Owner::UnitSummary),
            (3, "rust_crate_imports", Owner::CrateTopology),
            (4, "code_units", Owner::BlobRows),
        ] {
            writer.execute(move |conn| {
                conn.execute("INSERT INTO parent(id) VALUES (?1)", [id])
                    .unwrap();
                let _scope = Scope::new(conn, owner);
                conn.execute(
                    &format!("INSERT INTO {table}(id,parent_id) VALUES (?1,?1)"),
                    [id],
                )
                .unwrap();
            });
            writer.execute(move |conn| {
                let _cascade = CascadeDelete::new(conn);
                conn.execute("DELETE FROM parent WHERE id=?1", [id])
                    .unwrap();
            });
        }
    }

    #[test]
    fn cascade_scope_does_not_allow_inserts_and_direct_deletes_need_scope() {
        let writer = writer();
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            writer.execute(|conn| {
                let _cascade = CascadeDelete::new(conn);
                conn.execute("INSERT INTO resolution_paths(id) VALUES (1)", [])
            })
        }))
        .unwrap_err();
        assert!(panic_text(panic).contains("resolution_paths"));
        writer.execute(|conn| {
            let _owner = Scope::new(conn, Owner::Resolution);
            conn.execute("INSERT INTO resolution_paths(id) VALUES (1)", [])
                .unwrap()
        });
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            writer.execute(|conn| conn.execute("DELETE FROM resolution_paths WHERE id=1", []))
        }))
        .unwrap_err();
        assert!(panic_text(panic).contains("resolution_paths"));
    }

    #[test]
    fn fixture_scope_writes_fixture_rows() {
        let writer = writer();
        writer.execute(|conn| {
            let _fixture = Fixture::new(conn);
            conn.execute("INSERT INTO resolution_paths(id) VALUES (1)", [])
                .unwrap();
        });
    }
}
