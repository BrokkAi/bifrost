//! #13401: the per-blob import provenance index must answer exactly what the
//! per-token arena query it replaced answered. The old statement lives here as
//! the differential oracle; production no longer contains it.
#[cfg(test)]
mod rust_import_provenance_differential_tests {
    use brokk_bifrost_analysis::analyzer::store::AnalyzerStore;
    use brokk_bifrost_analysis::analyzer::store::js_ts_resolution_producer_support::persist_alias_fixture;
    use brokk_bifrost_analysis::analyzer::store::resolution_operation::rust_crate_access::build_rust_import_provenance_rows_for_test;
    use brokk_bifrost_analysis::analyzer::store::resolution_operation::rust_crate_access::take_rust_import_provenance_containment_checks_for_test;
    use brokk_bifrost_analysis::analyzer::store::test_blob_oid as oid;
    use brokk_bifrost_core::analyzer::rust_facts::{RustCfgCondition, decode_rust_cfg_condition};
    use brokk_bifrost_rust_analysis::analyzer::rust::adapter::RustAdapter;
    use rusqlite::{Connection, OptionalExtension};

    /// The pre-#13401 per-token statement, verbatim.
    const ORACLE_SQL: &str = "SELECT imports.cfg_condition, json_extract(route.body, '$[8][2][2]')
                 FROM resolution_semantic_catalog token
                 CROSS JOIN source_rust_import_targets imports ON imports.blob_id=token.blob_id
                 CROSS JOIN source_occurrence_arenas occurrence
                   ON occurrence.blob_id=imports.blob_id
                 CROSS JOIN resolution_node_catalog scope
                   ON scope.blob_id=imports.blob_id AND scope.source_scope=imports.native_scope
                 CROSS JOIN resolution_paths route
                   ON route.blob_id=scope.blob_id AND route.start_node=scope.local_key
                  AND route.end_node=-1 AND route.root_terminal IS NOT NULL
                  AND json_extract(route.body, '$[4][#-2]')=token.local_key
                 WHERE token.blob_id=?1 AND token.local_key=?2
                   AND token.import_source_site IS NOT NULL
                   AND json_extract(occurrence.spans, '$[' || imports.declaration_occurrence_id || '][0]')<=token.import_start_byte
                   AND json_extract(occurrence.spans, '$[' || imports.declaration_occurrence_id || '][1]')>=token.import_end_byte
                 LIMIT 1";

    /// Tests corrupt sealed rows to prove the builder does not trust them, so
    /// the seal triggers that would refuse the damage go first.
    fn unseal(conn: &Connection) {
        let triggers = conn
            .prepare(
                "SELECT name FROM sqlite_schema WHERE type='trigger' AND tbl_name IN
                 ('source_imports','source_rust_import_contexts','resolution_paths')",
            )
            .unwrap()
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        for trigger in triggers {
            conn.execute_batch(&format!("DROP TRIGGER \"{trigger}\""))
                .unwrap();
        }
    }

    type Rows = Vec<(u32, String)>;

    struct Fixture {
        store: AnalyzerStore,
        blob: i64,
    }

    impl Fixture {
        fn new(source: &str) -> Self {
            let store = AnalyzerStore::open_ephemeral().expect("ephemeral store");
            let content = oid(source);
            let snapshot = persist_alias_fixture(
                &store,
                content,
                "rust",
                &RustAdapter::for_tests(),
                "src/lib.rs",
                source,
            );
            assert_eq!(snapshot.publication_state, "complete");
            let blob = store.conn.execute(move |conn| {
                conn.query_row(
                    "SELECT id FROM blobs WHERE blob_oid=?1 AND lang='rust'",
                    [content.to_string()],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap()
            });
            Self { store, blob }
        }

        /// Runs `damage` on the sealed rows, then returns (index rows, oracle
        /// rows, token count), the last two as the old code would have them.
        fn compare(
            &self,
            damage: impl FnOnce(&Connection, i64) + Send + 'static,
        ) -> (Rows, Rows, usize) {
            let blob = self.blob;
            self.store.conn.execute(move |conn| {
                let _fixture =
                    brokk_bifrost_analysis::analyzer::store::sealed_families::Fixture::new(conn);
                unseal(conn);
                damage(conn, blob);
                let index = build_rust_import_provenance_rows_for_test(conn, blob).unwrap();
                let tokens = conn
                    .prepare(
                        "SELECT local_key FROM resolution_semantic_catalog
                         WHERE blob_id=?1 AND import_source_site IS NOT NULL ORDER BY local_key",
                    )
                    .unwrap()
                    .query_map([blob], |row| row.get::<_, u32>(0))
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap();
                let mut oracle = Vec::new();
                for token in &tokens {
                    let row: Option<(String, u32)> = conn
                        .prepare(ORACLE_SQL)
                        .unwrap()
                        .query_row(rusqlite::params![blob, token], |row| {
                            Ok((row.get(0)?, row.get(1)?))
                        })
                        .optional()
                        // The old reader failed on a non-integer choice key.
                        .ok()
                        .flatten();
                    let Some((cfg, choice)) = row else { continue };
                    let condition = decode_rust_cfg_condition(&cfg).unwrap();
                    if condition != RustCfgCondition::Always {
                        oracle.push((*token, format!("{condition:?} choice {choice}")));
                    }
                }
                (index, oracle, tokens.len())
            })
        }

        fn assert_equals_oracle(&self) -> (Rows, usize) {
            let (index, oracle, tokens) = self.compare(|_, _| {});
            assert_eq!(index, oracle, "the index answers what the old query did");
            (index, tokens)
        }
    }

    const FAMILY: &str = r#"
pub fn helper() -> u8 { 1 }
pub mod other { pub fn a() -> u8 { 1 } pub fn b() -> u8 { 2 } pub struct T; pub fn g() {} }
pub mod plain { pub fn p() -> u8 { 3 } }

#[cfg(test)]
use crate::helper;
#[cfg(unix)]
use crate::other::{a, b};
use crate::plain::p;
#[cfg(feature = "x")]
use crate::other::*;
#[cfg(all(unix, not(test)))]
use crate::other::T as Renamed;

#[cfg(windows)]
mod gated {
    #[cfg(test)]
    use crate::helper as h;
    use crate::plain::p as q;
    pub fn f() -> u8 { h() + q() }
}

pub fn spawn() -> u8 {
    let value = {
        #[cfg(test)]
        use crate::helper as inner;
        inner()
    };
    value + p()
}
"#;

    /// Every import token of a family covering conditional, grouped, glob,
    /// renamed, nested-module and block-scoped imports, in both namespaces
    /// (`T` is a type, the functions are values), equals the old query.
    #[test]
    fn index_equals_the_old_per_token_query_over_an_import_family() {
        let fixture = Fixture::new(FAMILY);
        let (index, tokens) = fixture.assert_equals_oracle();
        assert!(tokens >= 10, "the family has many import tokens: {tokens}");
        assert!(
            index.len() >= 6,
            "conditional tokens are indexed: {index:#?}"
        );
        assert!(index.iter().all(|(_, row)| row != "unestablished"));
    }

    /// SQLite VM steps `job` takes on `conn`.
    fn vm_steps(conn: &Connection, job: impl FnOnce()) -> u64 {
        use std::sync::atomic::{AtomicU64, Ordering};
        static STEPS: AtomicU64 = AtomicU64::new(0);
        STEPS.store(0, Ordering::Relaxed);
        conn.progress_handler(
            1,
            Some(|| {
                STEPS.fetch_add(1, Ordering::Relaxed);
                false
            }),
        )
        .unwrap();
        job();
        conn.progress_handler(1, None::<fn() -> bool>).unwrap();
        STEPS.load(Ordering::Relaxed)
    }

    #[test]
    fn one_build_costs_less_than_the_old_per_token_queries() {
        // The old statement parsed the whole occurrence arena for every
        // candidate token, so its cost grew with both tokens and file size.
        // One build serves every token of the blob and never reads the arena.
        for filler in [0usize, 400] {
            let mut source = FAMILY.to_owned();
            for index in 0..filler {
                source.push_str(&format!("pub fn filler_{index:04}() -> u8 {{ {index} }}\n"));
            }
            let fixture = Fixture::new(&source);
            let blob = fixture.blob;
            let (build, per_token, tokens) = fixture.store.conn.execute(move |conn| {
                let build = vm_steps(conn, || {
                    build_rust_import_provenance_rows_for_test(conn, blob).unwrap();
                });
                let tokens = conn
                    .prepare("SELECT local_key FROM resolution_semantic_catalog WHERE blob_id=?1 AND import_source_site IS NOT NULL")
                    .unwrap()
                    .query_map([blob], |row| row.get::<_, u32>(0))
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap();
                let per_token = vm_steps(conn, || {
                    for token in &tokens {
                        conn.prepare_cached(ORACLE_SQL)
                            .unwrap()
                            .query_row(rusqlite::params![blob, token], |row| row.get::<_, String>(0))
                            .optional()
                            .unwrap();
                    }
                });
                (build, per_token, tokens.len())
            });
            assert!(tokens >= 20, "{tokens}");
            assert!(
                build * 3 < per_token,
                "filler {filler}: one build took {build} VM steps, the old per-token queries {per_token}"
            );
        }
    }

    /// One conditional import among hundreds of unconditional ones in one
    /// scope: the build looked at every context for every route.
    #[test]
    fn one_scope_with_many_imports_builds_in_linear_containment_checks() {
        let mut source = String::from(
            "pub mod m {
",
        );
        for index in 0..150 {
            source.push_str(&format!("    pub fn f{index}() {{}}\n"));
        }
        source.push_str("}\n#[cfg(unix)]\nuse crate::m::f0 as cond;\n");
        for index in 1..150 {
            source.push_str(&format!("use crate::m::f{index};\n"));
        }
        let fixture = Fixture::new(&source);
        let blob = fixture.blob;
        let (routes, checks, index, oracle) = fixture.store.conn.execute(move |conn| {
            take_rust_import_provenance_containment_checks_for_test();
            let index = build_rust_import_provenance_rows_for_test(conn, blob).unwrap();
            let checks = take_rust_import_provenance_containment_checks_for_test();
            let routes: usize = conn
                .query_row(
                    "SELECT count(*) FROM resolution_paths WHERE blob_id=?1 AND end_node=-1 AND root_terminal IS NOT NULL",
                    [blob],
                    |row| row.get(0),
                )
                .unwrap();
            let tokens = conn
                .prepare(
                    "SELECT local_key FROM resolution_semantic_catalog
                     WHERE blob_id=?1 AND import_source_site IS NOT NULL ORDER BY local_key",
                )
                .unwrap()
                .query_map([blob], |row| row.get::<_, u32>(0))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            assert!(tokens.len() >= 150, "{}", tokens.len());
            let mut oracle = Vec::new();
            for token in &tokens {
                let row: Option<(String, u32)> = conn
                    .prepare_cached(ORACLE_SQL)
                    .unwrap()
                    .query_row(rusqlite::params![blob, token], |row| {
                        Ok((row.get(0)?, row.get(1)?))
                    })
                    .optional()
                    .unwrap();
                let Some((cfg, choice)) = row else { continue };
                let condition = decode_rust_cfg_condition(&cfg).unwrap();
                if condition != RustCfgCondition::Always {
                    oracle.push((*token, format!("{condition:?} choice {choice}")));
                }
            }
            (routes, checks, index, oracle)
        });
        assert!(!index.is_empty(), "the conditional import is indexed");
        assert_eq!(index, oracle, "the index answers what the old query did");
        assert!(
            checks <= routes + 16,
            "{checks} containment checks for {routes} routes"
        );
    }

    #[test]
    fn a_blob_of_unconditional_imports_has_an_empty_index() {
        let fixture =
            Fixture::new("pub mod m { pub fn f() {} }\nuse crate::m::f;\npub fn g() { f() }\n");
        let (index, tokens) = fixture.assert_equals_oracle();
        assert!(tokens >= 1);
        assert!(index.is_empty());
    }

    #[test]
    fn a_macro_embedded_import_equals_the_old_query() {
        let fixture = Fixture::new(
            "macro_rules! m { ($i:item) => { $i }; }\npub fn helper() {}\nm! {\n    #[cfg(test)]\n    use crate::helper as h;\n}\n#[cfg(unix)]\nuse crate::helper as k;\n",
        );
        fixture.assert_equals_oracle();
    }

    /// A NULL native scope never matched the old join, so the token stayed
    /// unconditional. The index preserves that.
    #[test]
    fn null_native_scope_matches_nothing_in_both() {
        let fixture = Fixture::new(FAMILY);
        let (index, oracle, _) = fixture.compare(|conn, blob| {
            conn.execute(
                "UPDATE source_rust_import_contexts SET native_scope=NULL WHERE blob_id=?1",
                [blob],
            )
            .unwrap();
        });
        assert!(oracle.is_empty());
        assert_eq!(index, oracle);
    }

    fn damaged_tokens(
        fixture: &Fixture,
        damage: impl FnOnce(&Connection, i64) + Send + 'static,
    ) -> (Rows, Rows) {
        let (index, oracle, _) = fixture.compare(damage);
        (index, oracle)
    }

    #[test]
    fn a_span_mismatch_is_unestablished() {
        let fixture = Fixture::new(FAMILY);
        let (index, _) = damaged_tokens(&fixture, |conn, blob| {
            conn.execute(
                "UPDATE source_imports SET declaration_end_byte=declaration_end_byte+1
                 WHERE blob_id=?1 AND declaration_occurrence_id IN (
                   SELECT declaration_occurrence_id FROM source_rust_import_contexts
                   WHERE blob_id=?1 AND cfg_condition<>'always')",
                [blob],
            )
            .unwrap();
        });
        assert!(
            index.iter().any(|(_, row)| row == "unestablished"),
            "{index:#?}"
        );
    }

    #[test]
    fn a_bad_choice_key_is_unestablished() {
        let fixture = Fixture::new(FAMILY);
        let (index, _) = damaged_tokens(&fixture, |conn, blob| {
            conn.execute(
                "UPDATE resolution_paths SET body=jsonb_set(body,'$[8][2][2]','x')
                 WHERE blob_id=?1 AND end_node=-1 AND root_terminal IS NOT NULL",
                [blob],
            )
            .unwrap();
        });
        assert!(!index.is_empty());
        assert!(
            index.iter().all(|(_, row)| row == "unestablished"),
            "{index:#?}"
        );
    }

    #[test]
    fn conflicting_contexts_are_unestablished() {
        let fixture = Fixture::new(FAMILY);
        let (index, _) = damaged_tokens(&fixture, |conn, blob| {
            // Widen the unconditional `use crate::plain::p` context, and its
            // source import so the spans still agree, over the whole file: the
            // conditional imports now sit inside two contexts with different cfg.
            conn.execute(
                "UPDATE source_rust_import_contexts
                 SET declaration_start_byte=0, declaration_end_byte=1000000
                 WHERE blob_id=?1 AND cfg_condition='always'
                   AND native_scope IN (SELECT native_scope FROM source_rust_import_contexts
                                        WHERE blob_id=?1 AND cfg_condition<>'always')",
                [blob],
            )
            .unwrap();
            conn.execute(
                "UPDATE source_imports SET declaration_start_byte=0, declaration_end_byte=1000000
                 WHERE blob_id=?1 AND declaration_occurrence_id IN (
                   SELECT declaration_occurrence_id FROM source_rust_import_contexts
                   WHERE blob_id=?1 AND declaration_end_byte=1000000)",
                [blob],
            )
            .unwrap();
        });
        assert!(
            index.iter().any(|(_, row)| row == "unestablished"),
            "{index:#?}"
        );
    }

    /// Legal one-line `use a::x;use a::y;` items have touching context spans.
    /// Touching is not overlapping: the index still equals the old query and
    /// nothing is unestablished.
    #[test]
    fn touching_one_line_imports_equal_the_old_query() {
        let fixture = Fixture::new(
            "pub mod m { pub fn f() {} pub fn g() {} pub fn h() {} }\n#[cfg(unix)]\nuse crate::m::f as cf;\nuse crate::m::g;use crate::m::h;\npub fn k() { g(); h(); cf() }\n",
        );
        let blob = fixture.blob;
        let spans: Vec<(i64, i64)> = fixture.store.conn.execute(move |conn| {
            conn.prepare(
                "SELECT declaration_start_byte, declaration_end_byte
                 FROM source_rust_import_contexts WHERE blob_id=?1
                 ORDER BY declaration_start_byte",
            )
            .unwrap()
            .query_map([blob], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap()
        });
        assert!(
            spans.windows(2).any(|pair| pair[0].1 == pair[1].0),
            "the producer's spans for one-line imports touch: {spans:?}"
        );
        let (index, _) = fixture.assert_equals_oracle();
        assert!(!index.is_empty());
        assert!(
            index.iter().all(|(_, row)| row != "unestablished"),
            "{index:#?}"
        );
    }

    /// Two contexts of one scope that overlap (here: every context stretched
    /// over the whole file) break the disjoint-spans invariant, so the
    /// conditional tokens of those scopes are unestablished, not trusted. A
    /// scope with one context stays disjoint and keeps its answer.
    #[test]
    fn overlapping_contexts_in_one_scope_are_unestablished() {
        let fixture = Fixture::new(FAMILY);
        let (healthy, _) = fixture.assert_equals_oracle();
        let (index, _) = damaged_tokens(&fixture, |conn, blob| {
            conn.execute(
                "UPDATE source_rust_import_contexts
                 SET declaration_start_byte=0, declaration_end_byte=1000000
                 WHERE blob_id=?1",
                [blob],
            )
            .unwrap();
            conn.execute(
                "UPDATE source_imports SET declaration_start_byte=0, declaration_end_byte=1000000
                 WHERE blob_id=?1 AND declaration_occurrence_id IN (
                   SELECT declaration_occurrence_id FROM source_rust_import_contexts
                   WHERE blob_id=?1)",
                [blob],
            )
            .unwrap();
        });
        let unestablished = |rows: &Rows| {
            rows.iter()
                .filter(|(_, row)| row == "unestablished")
                .count()
        };
        assert_eq!(unestablished(&healthy), 0);
        assert!(unestablished(&index) >= 3, "{index:#?}");
        // Damage only removes trust: a healthy answer is kept or unestablished.
        for (token, row) in &healthy {
            let damaged = index.iter().find(|(other, _)| other == token);
            assert!(
                damaged.is_some_and(|(_, d)| d == row || d == "unestablished"),
                "{token}: {row} became {damaged:?}"
            );
        }
    }
}
