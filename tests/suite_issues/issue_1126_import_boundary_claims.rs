//! Regression coverage for issue #1126: explicit imports of workspace-internal
//! modules/members must not draw a confident "not indexed" boundary claim when
//! the referenced name is actually a workspace-internal enum variant, associated
//! type, nested type, or enclosing type that merely shares its spelling with an
//! explicit import.
//!
//! Each shape is modelled on a fuzzer ledger row (m4-tier3):
//! - meilisearch `Error`          — `Error::Variant` owner vs `use thiserror::Error`
//! - nushell     `SqliteError`    — `Self::SqliteError(..)` variant vs `use rusqlite::Error as SqliteError`
//! - diesel      `Expression`     — `DefaultableColumnInsertValue::Expression` variant vs imported trait
//! - diesel      `TransactionManager` — `Self::TransactionManager` associated type vs imported trait
//! - twitter     `Activation`     — `import LocalScheduler.Activation` nested-object member (Scala)
//!
//! Negative controls prove the fix does not mask a genuinely-external import.

use crate::common::{InlineTestProject, call_search_tool_json};
use brokk_bifrost::Language;
use serde_json::{Value, json};

/// Resolve the reference at the `occ`-th occurrence of `needle` on the first
/// source line containing `line_marker`.
fn loc(
    root: &std::path::Path,
    path: &str,
    source: &str,
    line_marker: &str,
    occ: usize,
    needle: &str,
) -> Value {
    let line_index = source
        .lines()
        .position(|l| l.contains(line_marker))
        .unwrap_or_else(|| panic!("line not found: {line_marker:?}"));
    let line = source.lines().nth(line_index).unwrap();
    let mut idx = 0usize;
    let mut start = 0usize;
    for _ in 0..=occ {
        start = line[idx..]
            .find(needle)
            .map(|f| idx + f)
            .unwrap_or_else(|| panic!("needle {needle} occ {occ} not in {line}"));
        idx = start + 1;
    }
    let args = json!({"references":[{"path": path, "line": line_index + 1, "column": start + 1}]})
        .to_string();
    call_search_tool_json(root, "get_definitions_by_location", &args)
}

fn status(v: &Value) -> String {
    v["results"][0]["status"]
        .as_str()
        .unwrap_or("?")
        .to_string()
}

fn fqn(v: &Value) -> String {
    v["results"][0]["definitions"][0]["fqn"]
        .as_str()
        .unwrap_or("")
        .to_string()
}

fn assert_resolved(v: &Value, expected_fqn: &str, ctx: &str) {
    assert_eq!(status(v), "resolved", "{ctx}: expected resolved: {v}");
    assert_eq!(fqn(v), expected_fqn, "{ctx}: wrong fqn: {v}");
}

fn assert_boundary(v: &Value, ctx: &str) {
    assert_eq!(
        status(v),
        "unresolvable_import_boundary",
        "{ctx}: expected boundary claim: {v}"
    );
}

// ---------------------------------------------------------------------------
// Shape A — meilisearch: owner `Error::Variant` collides with `use thiserror::Error`
// ---------------------------------------------------------------------------
#[test]
fn meilisearch_error_owner_resolves_to_local_enum_not_import_boundary() {
    let src = "use thiserror::Error;\n\npub enum Error {\n    NotFound,\n    Bad,\n}\n\nimpl Error {\n    pub fn code(&self) -> u32 {\n        match self {\n            Error::NotFound => 1,\n            Error::Bad => 2,\n        }\n    }\n}\n";
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n",
        )
        .file("src/lib.rs", "pub mod error;\n")
        .file("src/error.rs", src)
        .build();
    let v = loc(
        project.root(),
        "src/error.rs",
        src,
        "Error::NotFound => 1",
        0,
        "Error",
    );
    assert_resolved(&v, "app.error.Error", "meilisearch Error owner");
}

// ---------------------------------------------------------------------------
// Shape B — nushell: `Self::SqliteError(..)` variant collides with `use rusqlite::Error as SqliteError`
// ---------------------------------------------------------------------------
#[test]
fn nushell_sqlite_variant_resolves_to_local_variant_not_import_boundary() {
    let src = "use rusqlite::Error as SqliteError;\n\npub enum SqliteOrShellError {\n    SqliteError(String),\n    Shell,\n}\n\nimpl From<String> for SqliteOrShellError {\n    fn from(e: String) -> Self {\n        Self::SqliteError(e)\n    }\n}\n\nimpl SqliteOrShellError {\n    fn is_sql(&self) -> bool {\n        matches!(self, SqliteOrShellError::SqliteError(_))\n    }\n}\n";
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n",
        )
        .file("src/lib.rs", "pub mod values;\n")
        .file("src/values.rs", src)
        .build();
    let want = "app.values.SqliteOrShellError.SqliteError";
    // tuple-variant construction (reads as a call)
    let v1 = loc(
        project.root(),
        "src/values.rs",
        src,
        "Self::SqliteError(e)",
        0,
        "SqliteError",
    );
    assert_resolved(&v1, want, "nushell Self::SqliteError(e)");
    // owner-qualified variant in a pattern
    let v2 = loc(
        project.root(),
        "src/values.rs",
        src,
        "matches!(self, SqliteOrShellError::SqliteError(_))",
        0,
        "SqliteError",
    );
    assert_resolved(&v2, want, "nushell SqliteOrShellError::SqliteError(_)");
    // the variant declaration itself
    let v3 = loc(
        project.root(),
        "src/values.rs",
        src,
        "    SqliteError(String),",
        0,
        "SqliteError",
    );
    assert_resolved(&v3, want, "nushell variant declaration");
}

// ---------------------------------------------------------------------------
// Shape C — diesel: enum variant `Expression` collides with imported in-workspace trait
// ---------------------------------------------------------------------------
#[test]
fn diesel_expression_variant_and_trait_bound_both_resolve() {
    let ins = "use crate::expression::{AppearsOnTable, Expression};\n\npub enum DefaultableColumnInsertValue<T> {\n    Expression(T),\n    Default,\n}\n\nimpl<T> DefaultableColumnInsertValue<T> {\n    fn peek(&self) -> bool {\n        matches!(self, Self::Expression(_))\n    }\n}\n\npub fn bound<E: Expression>(_e: E) {}\n\npub fn on<A: AppearsOnTable>(_a: A) {}\n";
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"diesel\"\nversion = \"0.1.0\"\n",
        )
        .file("src/lib.rs", "pub mod expression;\npub mod insertable;\n")
        .file(
            "src/expression/mod.rs",
            "pub trait Expression {\n    type SqlType;\n}\n\npub trait AppearsOnTable {}\n",
        )
        .file("src/insertable.rs", ins)
        .build();
    // trait bound must resolve to the imported trait, not the variant
    let bound = loc(
        project.root(),
        "src/insertable.rs",
        ins,
        "pub fn bound<E: Expression>(_e: E) {}",
        0,
        "Expression",
    );
    assert_resolved(
        &bound,
        "diesel.expression.Expression",
        "diesel trait bound Expression",
    );
    // variant use must resolve to the variant, not draw a boundary
    let variant = loc(
        project.root(),
        "src/insertable.rs",
        ins,
        "matches!(self, Self::Expression(_))",
        0,
        "Expression",
    );
    assert_resolved(
        &variant,
        "diesel.insertable.DefaultableColumnInsertValue.Expression",
        "diesel Self::Expression",
    );
    // variant declaration itself
    let decl = loc(
        project.root(),
        "src/insertable.rs",
        ins,
        "    Expression(T),",
        0,
        "Expression",
    );
    assert_resolved(
        &decl,
        "diesel.insertable.DefaultableColumnInsertValue.Expression",
        "diesel variant declaration",
    );
}

// ---------------------------------------------------------------------------
// Shape D — diesel: `Self::TransactionManager` associated type collides with imported trait
// ---------------------------------------------------------------------------
#[test]
fn diesel_transaction_manager_associated_type_resolves_not_import_boundary() {
    let conn = "pub use crate::transaction_manager::TransactionManager;\n\npub trait Connection {\n    type TransactionManager: TransactionManager<Self>;\n\n    fn begin(&mut self) {\n        Self::TransactionManager::run()\n    }\n}\n";
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"diesel\"\nversion = \"0.1.0\"\n",
        )
        .file(
            "src/lib.rs",
            "pub mod transaction_manager;\npub mod connection;\n",
        )
        .file(
            "src/transaction_manager.rs",
            "pub trait TransactionManager<C> {\n    fn run();\n}\n",
        )
        .file("src/connection/mod.rs", conn)
        .build();
    let v = loc(
        project.root(),
        "src/connection/mod.rs",
        conn,
        "Self::TransactionManager::run()",
        0,
        "TransactionManager",
    );
    assert_resolved(
        &v,
        "diesel.connection.Connection.TransactionManager",
        "diesel Self::TransactionManager",
    );
}

// ---------------------------------------------------------------------------
// Shape E — twitter (Scala): `import LocalScheduler.Activation` nested-object member
// ---------------------------------------------------------------------------
#[test]
fn twitter_scala_nested_object_member_import_resolves_not_import_boundary() {
    let src = "package com.twitter.concurrent\n\nobject LocalScheduler {\n  class Activation(lifo: Boolean) {\n    override def toString: String = \"a\"\n  }\n}\n\nclass LocalScheduler(lifo: Boolean) {\n  import LocalScheduler.Activation\n\n  private[this] val local = new ThreadLocal[Activation]()\n\n  def get(): Activation = {\n    new Activation(lifo)\n  }\n}\n";
    let project = InlineTestProject::with_language(Language::Scala)
        .file("src/main/scala/com/twitter/concurrent/Scheduler.scala", src)
        .build();
    let p = "src/main/scala/com/twitter/concurrent/Scheduler.scala";
    let want = "com.twitter.concurrent.LocalScheduler$.Activation";
    let type_ref = loc(
        project.root(),
        p,
        src,
        "new ThreadLocal[Activation]()",
        0,
        "Activation",
    );
    assert_resolved(&type_ref, want, "scala ThreadLocal[Activation]");
    let return_ty = loc(
        project.root(),
        p,
        src,
        "def get(): Activation = {",
        0,
        "Activation",
    );
    assert_resolved(&return_ty, want, "scala return type Activation");
}

// ---------------------------------------------------------------------------
// Negative controls: a genuinely-external import must STILL draw the boundary.
// ---------------------------------------------------------------------------
#[test]
fn genuinely_external_bare_import_still_draws_boundary() {
    // `SqliteError` here has NO local variant/type: the fallback must not fire.
    let src = "use rusqlite::Error as SqliteError;\n\npub fn probe() -> Result<(), SqliteError> {\n    Ok(())\n}\n";
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n",
        )
        .file("src/lib.rs", "pub mod db;\n")
        .file("src/db.rs", src)
        .build();
    let v = loc(
        project.root(),
        "src/db.rs",
        src,
        "Result<(), SqliteError>",
        0,
        "SqliteError",
    );
    assert_boundary(&v, "external bare SqliteError with no local target");
}

#[test]
fn genuinely_external_owner_import_still_draws_boundary() {
    // `Registry` here is external with NO local enum/type of that name.
    let src = "use other_crate::Registry;\n\npub fn probe() {\n    Registry::init();\n}\n";
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n",
        )
        .file("src/lib.rs", "pub mod reg;\n")
        .file("src/reg.rs", src)
        .build();
    let v = loc(
        project.root(),
        "src/reg.rs",
        src,
        "Registry::init();",
        0,
        "Registry",
    );
    assert_boundary(&v, "external owner Registry with no local target");
}

// #1125 stays green: a same-file trait shadowed by a derive re-export must
// resolve to the local trait (not draw a boundary, not regress into ambiguity).
#[test]
fn same_file_reexport_shadow_still_resolves_to_local_trait() {
    let src = "pub use diesel_derives::AsExpression;\n\npub trait AsExpression<T> {\n    type Expression;\n}\n\npub fn use_it<T, U>(_u: U)\nwhere\n    U: AsExpression<T>,\n{\n}\n";
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"diesel\"\nversion = \"0.1.0\"\n",
        )
        .file("src/lib.rs", "pub mod expression;\n")
        .file("src/expression/mod.rs", src)
        .build();
    let v = loc(
        project.root(),
        "src/expression/mod.rs",
        src,
        "U: AsExpression<T>,",
        0,
        "AsExpression",
    );
    assert_resolved(
        &v,
        "diesel.expression.AsExpression",
        "#1125 same-file re-export shadow",
    );
}
