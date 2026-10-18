//! Plan the production SQL, including function-local constants, without keeping
//! a second copy of the statements. Syn reads Rust syntax; SQLite reads SQL.
use super::*;
use syn::visit::Visit;

#[derive(Default)]
struct Registry {
    statements: Vec<(String, String)>,
    file: PathBuf,
    scope: Vec<String>,
    dynamic: Vec<String>,
    schemas: Vec<String>,
    prepared: std::collections::HashSet<String>,
    referenced: std::collections::HashSet<String>,
}

impl Registry {
    fn record(&mut self, name: &str, expression: &syn::Expr) {
        let value = sql_value(expression, &self.file);
        if let Some(sql) = value {
            if sql.contains("CREATE TEMP") && !sql.contains('?') {
                self.schemas.push(sql.clone());
            }
            self.statements.push((
                format!("{}::{}::{name}", self.file.display(), self.scope.join("::")),
                sql,
            ));
        }
    }
}

fn sql_value(expression: &syn::Expr, file: &Path) -> Option<String> {
    match expression {
        syn::Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Str(value),
            ..
        }) => Some(value.value()),
        syn::Expr::Macro(value) if value.mac.path.is_ident("include_str") => {
            let path: syn::LitStr = syn::parse2(value.mac.tokens.clone()).unwrap();
            Some(std::fs::read_to_string(file.parent().unwrap().join(path.value())).unwrap())
        }
        syn::Expr::Macro(value) if value.mac.path.is_ident("concat") => {
            use syn::parse::Parser;
            let parts = syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated
                .parse2(value.mac.tokens.clone())
                .unwrap();
            parts
                .iter()
                .map(|part| sql_value(part, file))
                .collect::<Option<Vec<_>>>()
                .map(|parts| parts.concat())
        }
        _ => None,
    }
}

impl<'ast> Visit<'ast> for Registry {
    fn visit_expr_macro(&mut self, expression: &'ast syn::ExprMacro) {
        if expression.mac.path.is_ident("format") {
            use syn::parse::Parser;
            let arguments =
                syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated
                    .parse2(expression.mac.tokens.clone())
                    .unwrap();
            for argument in &arguments {
                syn::visit::visit_expr(self, argument);
            }
        }
        syn::visit::visit_expr_macro(self, expression);
    }

    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        if item.attrs.iter().any(|attr| {
            attr.path().is_ident("cfg")
                && attr
                    .parse_args::<syn::Path>()
                    .is_ok_and(|path| path.is_ident("test"))
        }) {
            return;
        }
        syn::visit::visit_item_mod(self, item);
    }

    fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
        self.referenced
            .insert(path.path.segments.last().unwrap().ident.to_string());
        syn::visit::visit_expr_path(self, path);
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        if item.attrs.iter().any(|attr| attr.path().is_ident("test")) {
            return;
        }
        self.scope.push(item.sig.ident.to_string());
        syn::visit::visit_item_fn(self, item);
        self.scope.pop();
    }

    fn visit_item_const(&mut self, item: &'ast syn::ItemConst) {
        self.record(&item.ident.to_string(), &item.expr);
        syn::visit::visit_item_const(self, item);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        if call.method == "execute_batch"
            && let Some(sql) = call.args.first()
        {
            self.record("schema", sql);
        }
        if (call.method == "execute" || call.method == "query_row")
            && let Some(sql) = call.args.first()
        {
            self.record(&call.method.to_string(), sql);
        }
        if call.method == "prepare_cached" || call.method == "prepare" {
            match call.args.first().unwrap() {
                syn::Expr::Lit(_) | syn::Expr::Macro(_) => {
                    self.record(&call.method.to_string(), &call.args[0])
                }
                syn::Expr::Path(path) => {
                    let name = path.path.segments.last().unwrap().ident.to_string();
                    if name.chars().any(|ch| ch.is_ascii_lowercase()) {
                        self.dynamic.push(format!(
                            "{}::{}: runtime SQL variable {name}",
                            self.file.display(),
                            self.scope.join("::")
                        ));
                    }
                    self.prepared.insert(name);
                } // The constant's declaration is registered above.
                other => self.dynamic.push(format!(
                    "{}::{:?}: {other:?}",
                    self.file.display(),
                    self.scope
                )),
            }
        }
        syn::visit::visit_expr_method_call(self, call);
    }
}

fn registry() -> Registry {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/analyzer/store");
    let mut files: Vec<_> = walkdir::WalkDir::new(root.join("resolution_operation"))
        .into_iter()
        .map(|entry| entry.unwrap().into_path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "rs"))
        .collect();
    files.push(root.join("source_facts.rs"));
    files.extend(
        ["unit_summaries.rs", "unit_schedule.rs", "rust_crates.rs"].map(|name| root.join(name)),
    );
    files.extend(
        std::fs::read_dir(&root)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                let name = path.file_name().unwrap().to_str().unwrap();
                name.ends_with("_package_context.rs") || name.ends_with("_unit_summaries.rs")
            }),
    );
    files.sort();
    let mut registry = Registry::default();
    for file in files {
        let syntax = syn::parse_file(&std::fs::read_to_string(&file).unwrap()).unwrap();
        registry.file = file;
        registry.visit_file(&syntax);
    }
    registry.statements.retain(|(name, sql)| {
        let constant = name.rsplit("::").next().unwrap();
        let first = sql
            .lines()
            .map(str::trim_start)
            .find(|line| !line.is_empty() && !line.starts_with("--"))
            .and_then(|line| line.split_whitespace().next());
        matches!(
            constant,
            "prepare_cached" | "prepare" | "execute" | "query_row"
        ) || registry.prepared.contains(constant)
            || (registry.referenced.contains(constant)
                // This fragment is registered through its compiled accessor.
                && constant != "TARGET_SCOPED_REFERENCE_INVENTORY_GAPS_SQL"
                && matches!(
                    first,
                    Some("SELECT" | "WITH" | "INSERT" | "UPDATE" | "DELETE")
                ))
    });
    // These production statements expand SQL macros or lazy compositions.
    // Read their compiled values rather than reimplementing Rust expansion.
    use super::super::{go_reverse_rows, rust_crate_context, rust_crate_rows, rust_reverse_rows};
    use crate::analyzer::store::{go_unit_summaries, rust_unit_summaries, selected_definition};
    for (name, sql) in [
        (
            "unit_summaries::LIVE_SUMMARY_SQL",
            crate::analyzer::store::unit_summaries::LIVE_SUMMARY_SQL,
        ),
        (
            "rust_crate_rows::IMPL_ITEM_TRAITS",
            rust_crate_rows::IMPL_ITEM_TRAITS,
        ),
        (
            "rust_crate_rows::TRAIT_IMPL_MEMBER_AT",
            rust_crate_rows::TRAIT_IMPL_MEMBER_AT,
        ),
        (
            "rust_crate_rows::TRAIT_VISIBLE_AT",
            rust_crate_rows::TRAIT_VISIBLE_AT,
        ),
        (
            "rust_crate_rows::TRAIT_IMPLS_VISIBLE_AT",
            rust_crate_rows::TRAIT_IMPLS_VISIBLE_AT,
        ),
        (
            "go_unit_summaries::GO_LIVE_SUMMARY_SQL",
            go_unit_summaries::GO_LIVE_SUMMARY_SQL,
        ),
        (
            "rust_unit_summaries::DEPENDENCY_REEXPORT_WITNESS_SQL",
            rust_unit_summaries::DEPENDENCY_REEXPORT_WITNESS_SQL,
        ),
        (
            "selected_definition::SELECTED_DEFINITION_BLOB_SQL",
            selected_definition::SELECTED_DEFINITION_BLOB_SQL,
        ),
        (
            "rust_crate_context::DEPENDENCY",
            rust_crate_context::DEPENDENCY.as_str(),
        ),
        (
            "rust_crate_context::CLOSURE_SCOPE_MOUNTS_PIN",
            rust_crate_context::sql_pins()
                .into_iter()
                .find(|(name, _, _)| *name == "rust_scope_closure_mounts")
                .unwrap()
                .1,
        ),
        (
            "rust_crate_rows::REFERENCE_NAMES_WORKSPACE_CRATE",
            rust_crate_rows::REFERENCE_NAMES_WORKSPACE_CRATE.as_str(),
        ),
        (
            "go_reverse_rows::GO_TARGET_DEFINITION_SEMANTICS_SQL",
            go_reverse_rows::GO_TARGET_DEFINITION_SEMANTICS_SQL.as_str(),
        ),
        (
            "rust_reverse_rows::target_scoped_reference_inventory_gaps_sql",
            rust_reverse_rows::target_scoped_reference_inventory_gaps_sql(),
        ),
    ] {
        registry.statements.push((name.to_owned(), sql.to_owned()));
    }
    let missing: Vec<_> = registry
        .prepared
        .iter()
        .filter(|name| {
            name.chars().all(|ch| ch.is_ascii_uppercase() || ch == '_')
                && !registry
                    .statements
                    .iter()
                    .any(|(registered, _)| registered.rsplit("::").next() == Some(name.as_str()))
        })
        .collect();
    assert!(
        missing.is_empty(),
        "production SQL constants missing from the plan registry: {missing:?}"
    );
    registry
}

fn unindexed_main_tables(
    conn: &rusqlite::Connection,
    sql: &str,
    tables: &std::collections::HashMap<i64, String>,
) -> Vec<String> {
    let mut bytecode = conn.prepare(&format!("EXPLAIN {sql}")).unwrap();
    let args = vec![rusqlite::types::Value::Null; bytecode.parameter_count()];
    let ops: Vec<(i64, String, i64, i64, i64)> = bytecode
        .query_map(rusqlite::params_from_iter(args), |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        })
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    let mut cursors = std::collections::HashMap::new();
    let mut scans = Vec::new();
    for (address, op, cursor, root, database) in ops {
        // Trigger subprograms and reopened cursors reuse cursor numbers. A
        // later main-table OpenRead must not relabel an earlier TEMP scan.
        if address == 0 {
            cursors.clear();
        }
        match op.as_str() {
            "OpenRead" | "ReopenIdx" => {
                cursors.remove(&cursor);
                if database == 0
                    && let Some(table) = tables.get(&root)
                {
                    cursors.insert(cursor, table);
                }
            }
            "OpenDup" => {
                if let Some(table) = cursors.get(&root).copied() {
                    cursors.insert(cursor, table);
                } else {
                    cursors.remove(&cursor);
                }
            }
            "OpenWrite" | "OpenEphemeral" | "OpenAutoindex" | "OpenPseudo" | "SorterOpen"
            | "VOpen" | "Close" => {
                cursors.remove(&cursor);
            }
            "Rewind" => {
                if let Some(table) = cursors.get(&cursor) {
                    scans.push((*table).clone());
                }
            }
            _ => {}
        }
    }
    scans
}

#[test]
#[hardwon("#5638+#5658: unbounded views and macro-hidden scheduler SQL escaped plan coverage")]
fn native_query_plan_registry() {
    let fixture = RustRootResolutionOperationFixture::new();
    let cancellation = CancellationToken::new();
    let operation = fixture.open_ready(&cancellation);
    let conn = operation.ready.inventory.connection();
    let registry = registry();
    assert!(
        registry
            .statements
            .iter()
            .any(|(_, sql)| { sql == crate::analyzer::store::unit_schedule::ORDER_SQL }),
        "the component-wave ordering query must be planned"
    );
    crate::analyzer::store::go_unit_summaries::register_go_summary_sql_functions(conn).unwrap();
    for schema in &registry.schemas {
        conn.execute_batch(schema).unwrap();
    }
    if let Some(path) = std::env::var_os("BIFROST_NATIVE_SQL_REPORT") {
        std::fs::write(
            path,
            serde_json::to_vec_pretty(&registry.statements).unwrap(),
        )
        .unwrap();
    }
    let views: Vec<String> = conn
        .prepare("SELECT name FROM main.sqlite_schema WHERE type='view' UNION SELECT name FROM temp.sqlite_schema WHERE type='view'")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    let tables: std::collections::HashMap<i64, String> = conn
        .prepare("SELECT rootpage, name FROM main.sqlite_schema WHERE type='table' AND rootpage>0")
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert!(
        unindexed_main_tables(
            conn,
            "SELECT blob_oid FROM blobs NOT INDEXED WHERE blob_oid = ?1",
            &tables,
        )
        .iter()
        .any(|table| table == "blobs"),
        "the injected unindexed blob read escaped the gate"
    );
    let injected: Vec<String> = conn
        .prepare(
            "EXPLAIN QUERY PLAN SELECT blob.id FROM blobs AS blob
         LEFT JOIN main.source_occurrences AS occurrence ON occurrence.blob_id=blob.id
         WHERE blob.id=?1",
        )
        .unwrap()
        .query_map([1], |row| row.get(3))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert!(
        injected.iter().any(
            |detail| detail.strip_prefix("MATERIALIZE ").is_some_and(|name| views
                .iter()
                .any(|view| view == name.strip_prefix("main.").unwrap_or(name)))
        ),
        "the injected unbounded view join escaped the gate: {injected:#?}"
    );
    let mut failures = Vec::new();
    let mut unavailable = Vec::new();
    let mut pending = std::collections::VecDeque::from(registry.statements.clone());
    let mut planned = 0;
    while let Some((name, sql)) = pending.pop_front() {
        let mut statement = match conn.prepare(&format!("EXPLAIN QUERY PLAN {sql}")) {
            Ok(statement) => statement,
            Err(rusqlite::Error::MultipleStatement) => {
                use rusqlite::fallible_iterator::FallibleIterator;
                let mut batch = rusqlite::Batch::new(conn, &sql);
                let mut statements = Vec::new();
                while let Some(statement) = batch.next().unwrap() {
                    // execute_batch has no parameter bindings. With no binds,
                    // SQLite's expanded SQL is the original statement text.
                    assert_eq!(statement.parameter_count(), 0, "bound SQL batch: {name}");
                    statements.push(statement.expanded_sql().unwrap());
                }
                assert!(!statements.is_empty(), "empty SQL batch: {name}");
                for (ordinal, sql) in statements.into_iter().enumerate().rev() {
                    pending.push_front((format!("{name}[{}]", ordinal + 1), sql));
                }
                continue;
            }
            Err(error) => {
                let message = error.to_string();
                let table = message
                    .strip_prefix("no such table: ")
                    .map(|table| table.strip_prefix("temp.").unwrap_or(table));
                if table.is_some_and(|table| {
                    table.starts_with("selected_")
                        || matches!(
                            table,
                            "go_unit_summary_units"
                                | "rust_unit_summary_units"
                                | "unit_summary_work"
                        )
                }) {
                    unavailable.push(format!("{name}: request TEMP family not initialized by this selected operation: {error}"));
                } else {
                    failures.push(format!("{name}: cannot plan production SQL: {error}"));
                }
                continue;
            }
        };
        let params = vec![rusqlite::types::Value::Null; statement.parameter_count()];
        let plan: Vec<String> = statement
            .query_map(rusqlite::params_from_iter(params), |row| row.get(3))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        planned += 1;
        // Bytecode identifies base-table cursors even when EQP renders an SQL
        // alias. CTEs, JSON virtual tables and request TEMP tables have no main
        // schema root page and cannot be mistaken for workspace table scans.
        let compact: String = sql.chars().filter(|ch| !ch.is_ascii_whitespace()).collect();
        if [
            "blob_id=?",
            "blob_oid=?",
            "mount_ordinal=?",
            "blob_idIN(?",
            "mount_ordinalIN(?",
        ]
        .iter()
        .any(|binding| compact.contains(binding))
        {
            for table in unindexed_main_tables(conn, &sql, &tables) {
                failures.push(format!(
                    "{name}: unindexed main table scan {table}: {plan:#?}"
                ));
            }
        }
        for detail in &plan {
            if let Some(materialized) = detail.strip_prefix("MATERIALIZE ") {
                let view = materialized
                    .strip_prefix("main.")
                    .or_else(|| materialized.strip_prefix("temp."))
                    .unwrap_or(materialized);
                // A scoped CTE may deliberately reuse a view's name.
                if views.iter().any(|name| name == view)
                    && !sql.contains(&format!("{view} AS MATERIALIZED"))
                {
                    failures.push(format!("{name}: {plan:#?}"));
                }
            }
        }
    }
    eprintln!(
        "registered={} planned={planned} dynamic={:#?} unavailable={unavailable:#?}",
        registry.statements.len(),
        registry.dynamic
    );
    assert!(
        failures.is_empty(),
        "native SQL plan regressions: {failures:#?}"
    );
}

#[test]
#[hardwon("#5658: Go alias summaries materialized occurrence arenas for unrelated blobs")]
fn native_query_plan_go_alias_rows_are_identical() {
    let fixture = GoRootResolutionOperationFixture::with_sources([
        "package consumer; import provider \"example.test/root/provider\"; type Alias = provider.Item; type Local = Alias; type Slice = []int; type Unknown = missing.Type",
        "package provider; type Item struct {}; type Alias = Item",
        "package provider; type Decoy struct {}; type Alias = Decoy",
    ]);
    let context = publish_go_root_fixture_context(&fixture, "example.test/root/provider");
    let cancellation = CancellationToken::new();
    let operation = fixture.open_ready(&cancellation);
    let conn = operation.ready.inventory.connection();
    let registry = registry();
    let sql = &registry
        .statements
        .iter()
        .find(|(name, _)| name.ends_with("::UNIT_ALIAS_EXPORTS_SQL"))
        .unwrap()
        .1;
    let begin = sql.find("     -- Filter the join view").unwrap();
    let end = sql.find("       ON target_occurrence.blob_id").unwrap();
    let old = format!(
        "{}     LEFT JOIN main.source_occurrences AS target_occurrence\n{}",
        &sql[..begin],
        &sql[end..]
    );
    let generation = fixture.snapshots["go"].generation.get();
    let epoch: String = conn
        .query_row(
            "SELECT producer_epoch FROM resolution_producer_epochs WHERE lang='go'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let packages: Vec<i64> = conn
        .prepare("SELECT package_id FROM go_package_instances WHERE context_id=?1")
        .unwrap()
        .query_map([context], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    let mut count = 0;
    for package in packages {
        let read = |sql: &str| {
            let mut statement = conn.prepare(sql).unwrap();
            let columns = statement.column_count();
            let mut rows: Vec<String> = statement
                .query_map(params![context, package, "go", generation, epoch], |row| {
                    let values = (0..columns)
                        .map(|column| row.get::<_, rusqlite::types::Value>(column))
                        .collect::<rusqlite::Result<Vec<_>>>()?;
                    Ok(format!("{values:?}"))
                })
                .unwrap()
                .collect::<rusqlite::Result<_>>()
                .unwrap();
            rows.sort();
            rows
        };
        let expected = read(&old);
        assert_eq!(expected, read(sql), "package {package}");
        count += expected.len();
        eprintln!("package {package}: {expected:#?}");
    }
    assert!(
        count >= 6,
        "expected populated local, qualified and unnamed aliases, found {count}"
    );
}
