//! Sealed-family authorizer restoration and test read recording.
#[cfg(any(debug_assertions, test, feature = "test-support"))]
use brokk_bifrost_core::attribution::ConnectionTag;
#[cfg(any(debug_assertions, test, feature = "test-support"))]
use brokk_bifrost_core::cache_db::sql_profile::{connection_tag, on_connection_close};
#[cfg(any(debug_assertions, test, feature = "test-support"))]
use rusqlite::Connection;
#[cfg(test)]
use rusqlite::hooks::AuthAction;
#[cfg(any(debug_assertions, test, feature = "test-support"))]
use rusqlite::hooks::{AuthContext, Authorization};
#[cfg(test)]
use std::collections::BTreeSet;
#[cfg(any(debug_assertions, test, feature = "test-support"))]
use std::collections::HashMap;
#[cfg(test)]
use std::sync::Arc;
#[cfg(any(debug_assertions, test, feature = "test-support"))]
use std::sync::{Mutex, Once, OnceLock};

#[cfg(any(debug_assertions, test, feature = "test-support"))]
type Guard = for<'a> fn(AuthContext<'a>) -> Authorization;
#[cfg(any(debug_assertions, test, feature = "test-support"))]
#[derive(Default)]
struct State {
    guards: HashMap<ConnectionTag, Guard>,
}

#[cfg(any(debug_assertions, test, feature = "test-support"))]
static STATE: OnceLock<Mutex<State>> = OnceLock::new();
#[cfg(any(debug_assertions, test, feature = "test-support"))]
fn state() -> &'static Mutex<State> {
    STATE.get_or_init(|| Mutex::new(State::default()))
}

#[cfg(any(debug_assertions, test, feature = "test-support"))]
fn with_state<T>(f: impl FnOnce(&mut State) -> T) -> T {
    static REGISTER: Once = Once::new();
    REGISTER.call_once(|| on_connection_close(clear_connection));
    f(&mut state().lock().expect("authorizer state poisoned"))
}

#[cfg(any(debug_assertions, test, feature = "test-support"))]
fn clear_connection(tag: ConnectionTag) {
    let mut state = state().lock().expect("authorizer state poisoned");
    state.guards.remove(&tag);
}

#[cfg(any(debug_assertions, test, feature = "test-support"))]
pub(super) fn install_writer_guard(conn: &Connection, guard: Guard) {
    if let Some(tag) = connection_tag(conn) {
        with_state(|state| {
            state.guards.insert(tag, guard);
        });
    }
    conn.authorizer(Some(guard))
        .expect("install sealed-family authorizer");
}

/// Functions whose value is a function of their SQL arguments alone, so a
/// statement that calls them reads nothing beyond its recorded tables. Any
/// other function (`random()`, `changes()`, the date and time functions, which
/// accept `'now'`, a side-effecting or environment-reading function a
/// connection registers) makes the statement's read set invalid. The Bifrost
/// entries are the scalar functions the store registers as
/// `SQLITE_DETERMINISTIC` whose bodies read only their arguments; a function
/// registered later is refused until it is checked and listed here.
#[cfg(test)]
const DETERMINISTIC_FUNCTIONS: &[&str] = &[
    // SQLite core scalar functions.
    "abs",
    "char",
    "coalesce",
    "concat",
    "concat_ws",
    "format",
    "glob",
    "hex",
    "ifnull",
    "iif",
    "instr",
    "length",
    "like",
    "likelihood",
    "likely",
    "lower",
    "ltrim",
    "max",
    "min",
    "nullif",
    "octet_length",
    "printf",
    "quote",
    "replace",
    "round",
    "rtrim",
    "sign",
    "soundex",
    "substr",
    "substring",
    "trim",
    "typeof",
    "unhex",
    "unicode",
    "unlikely",
    "upper",
    "zeroblob",
    // SQLite aggregate and window functions.
    "avg",
    "count",
    "group_concat",
    "string_agg",
    "sum",
    "total",
    "row_number",
    "rank",
    "dense_rank",
    "percent_rank",
    "cume_dist",
    "ntile",
    "lag",
    "lead",
    "first_value",
    "last_value",
    "nth_value",
    // SQLite JSON functions and operators.
    "json",
    "jsonb",
    "json_array",
    "jsonb_array",
    "json_array_length",
    "json_error_position",
    "json_extract",
    "jsonb_extract",
    "json_insert",
    "jsonb_insert",
    "json_object",
    "jsonb_object",
    "json_patch",
    "jsonb_patch",
    "json_pretty",
    "json_quote",
    "json_remove",
    "jsonb_remove",
    "json_replace",
    "jsonb_replace",
    "json_set",
    "jsonb_set",
    "json_type",
    "json_valid",
    "json_group_array",
    "jsonb_group_array",
    "json_group_object",
    "jsonb_group_object",
    "json_each",
    "jsonb_each",
    "json_tree",
    "jsonb_tree",
    "->",
    "->>",
    // Bifrost scalar functions (rust_crates.rs, rust_crate_derivation.rs,
    // resolution_lexical.rs, go_unit_summaries.rs).
    "cr_parent",
    "cr_join",
    "cr_authority_namespace",
    "cr_authority_cfg",
    "cr_cfg",
    "cr_lookup_digest",
    "cr_visibility",
    "cr_visibility_segments",
    "cr_restriction",
    "resolution_node_identity",
    "bifrost_go_unit_key",
    "bifrost_go_profile_read_key",
];

#[cfg(test)]
fn with_read_recorder<T>(conn: &Connection, prepare: impl FnOnce(&Arc<Mutex<Reads>>) -> T) -> T {
    let tag = connection_tag(conn);
    let previous = tag.and_then(|tag| with_state(|state| state.guards.get(&tag).copied()));
    let reads = Arc::new(Mutex::new(Reads::default()));
    let sink = Arc::clone(&reads);
    // sqlite3_set_authorizer expires the connection's prepared statements, so
    // its next use re-prepares them. The read-set cache exists to avoid
    // repeating that for a statement text already classified.
    conn.authorizer(Some(move |ctx: AuthContext<'_>| {
        let mut reads = sink.lock().expect("read authorizer poisoned");
        if let Some(accessor) = ctx.accessor {
            reads.accessors.insert(accessor.to_owned());
        }
        match ctx.action {
            AuthAction::Read { table_name, .. } => {
                reads.tables.insert((
                    ctx.database_name.unwrap_or("").to_owned(),
                    table_name.to_owned(),
                ));
            }
            AuthAction::Select | AuthAction::Recursive => {}
            AuthAction::Function { function_name }
                if DETERMINISTIC_FUNCTIONS
                    .iter()
                    .any(|name| name.eq_ignore_ascii_case(function_name)) => {}
            // The read-only version PRAGMAs read no table. Their values only
            // key freshness checks and memos, and that is sound only while
            // every such memo lives no longer than one operation: a rollback
            // can bring a schema version back over a different TEMP schema,
            // so no value may be compared across one. The gap-detail memo key
            // takes its stamp once per stage read (reset at every stage
            // begin, end and pause) and the memo is owned by the selected
            // inventory, so it dies with the operation; the retained
            // selection's stamp is never current after a lost stage.
            AuthAction::Pragma {
                pragma_name,
                pragma_value,
            } if pragma_value.is_none()
                && matches!(
                    (ctx.database_name, pragma_name),
                    (Some("main"), "data_version" | "schema_version")
                        | (Some("temp"), "schema_version")
                ) => {}
            AuthAction::Insert { table_name } => {
                reads.writes.insert((
                    ctx.database_name.unwrap_or("").to_owned(),
                    table_name.to_owned(),
                ));
            }
            AuthAction::Update { table_name, .. } => {
                reads.writes.insert((
                    ctx.database_name.unwrap_or("").to_owned(),
                    table_name.to_owned(),
                ));
            }
            AuthAction::Delete { table_name } => {
                reads.writes.insert((
                    ctx.database_name.unwrap_or("").to_owned(),
                    table_name.to_owned(),
                ));
            }
            AuthAction::Transaction { .. } | AuthAction::Savepoint { .. } => {}
            _ => reads.invalid = true,
        }
        Authorization::Allow
    }))
    .expect("install read recorder");
    struct Restore<'a>(&'a Connection, Option<Guard>);
    impl Drop for Restore<'_> {
        fn drop(&mut self) {
            if let Some(guard) = self.1 {
                self.0
                    .authorizer(Some(guard))
                    .expect("restore writer guard");
            } else {
                self.0
                    .authorizer(None::<Guard>)
                    .expect("remove read recorder");
            }
        }
    }
    let restore = Restore(conn, previous);
    let value = prepare(&reads);
    drop(restore);
    value
}

#[cfg(test)]
#[derive(Default)]
struct Reads {
    tables: BTreeSet<(String, String)>,
    writes: BTreeSet<(String, String)>,
    /// The inner-most trigger or view each action came from.
    accessors: BTreeSet<String>,
    invalid: bool,
}

#[cfg(test)]
pub(super) fn record_accesses(
    conn: &Connection,
    sql: &str,
) -> (BTreeSet<String>, BTreeSet<String>) {
    with_read_recorder(conn, |sink| {
        conn.prepare(sql).unwrap();
        let reads = sink.lock().unwrap();
        (
            reads
                .tables
                .iter()
                .map(|(_, table)| table.clone())
                .collect(),
            reads
                .writes
                .iter()
                .map(|(_, table)| table.clone())
                .collect(),
        )
    })
}
