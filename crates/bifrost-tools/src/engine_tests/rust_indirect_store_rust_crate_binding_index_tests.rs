#[cfg(test)]
mod index_tests {

    use brokk_bifrost_analysis::analyzer::store::rust_crates::derivation::binding_relation::EXTRA_COVERING_INDEX;
    use brokk_bifrost_test_macros::hardwon;

    // Two route-precedence cases kept inline so this public test carries its own
    // sources: a glob conflict reached from both a named import and a glob, and
    // globs whose conflicts mix private and public visibility.
    const GLOB_CONFLICT: &[(&str, &str)] = &[
        (
            "Cargo.toml",
            r#"[package]
name="out_line_glob_conflict"
version="0.0.0"
edition="2021"
[workspace]
"#,
        ),
        (
            "src/lib.rs",
            r#"pub mod a;
pub mod b;
pub use a::*;
pub use b::*;
pub use x::T;
pub fn probe() { let _ = x::T; let _ = T; let _ = crate::T; }
"#,
        ),
        (
            "src/a.rs",
            r#"// Distinct a module source.
pub mod x { pub struct T; }
"#,
        ),
        (
            "src/b.rs",
            r#"// Distinct b module source.
pub mod x { pub struct T; }
"#,
        ),
    ];

    const MIXED_VISIBILITY_GLOB_ORDER: &[(&str, &str)] = &[
        (
            "Cargo.toml",
            r#"[package]
name = "mixed_visibility_glob_order"
version = "0.1.0"
edition = "2021"
"#,
        ),
        (
            "src/lib.rs",
            r#"mod a { pub struct T; }
mod b { pub struct T; }
mod private_first { use crate::a::*; pub use crate::b::*; }
mod public_first { pub use crate::b::*; use crate::a::*; }
mod visible { pub struct T; }
mod left { use crate::private_first::*; use crate::visible::*; pub fn probe(_: T) { let _ = T; } }
mod right { use crate::public_first::*; use crate::visible::*; pub fn probe(_: T) { let _ = T; } }
mod lone { use crate::private_first::*; pub fn probe(_: T) { let _ = T; } }
mod named { use crate::private_first::T as Alias; pub fn probe(_: Alias) { let _ = Alias; } }
// rustc controls: left compiles to visible::T; right reports E0659.
// Without visible::T, private-first glob lookup reports E0425; a named
// private_first::T import reports E0659/E0603. Import resolution order is
// not modeled: partially visible conflict groups report UnsupportedSemantic.
mod downstream { use crate::lone::*; use crate::visible::*; pub fn probe(_: T) { let _ = T; } }
mod shared { use crate::private_first::*; use crate::a::*; pub fn probe(_: T) { let _ = T; } }
"#,
        ),
    ];

    fn snapshot(files: &[(&str, &str)], with_index: bool) -> Vec<String> {
        use crate::inline_project::InlineTestProject;
        let mut project = InlineTestProject::new();
        for (name, contents) in files {
            project = project.file(*name, *contents);
        }
        let project = project.build();
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                EXTRA_COVERING_INDEX.store(false, std::sync::atomic::Ordering::SeqCst);
            }
        }
        EXTRA_COVERING_INDEX.store(with_index, std::sync::atomic::Ordering::SeqCst);
        let _reset = Reset;
        let analyzer = project
            .workspace_analyzer(brokk_bifrost_core::analyzer::config::AnalyzerConfig::default());
        let conn = analyzer.store().unwrap().read_conn().unwrap();
        let mut output = Vec::new();
        for sql in [
        "SELECT json_array(owner.crate_name,export.module_path,export.namespace,export.name,export.origin,export.visibility,export.restricted_module_path,target.crate_name,export.target_module_path,export.target_name)
         FROM rust_crate_exports export JOIN rust_crate_topologies owner USING(topology_id)
         JOIN rust_crate_topologies target ON target.crate_key=export.target_crate_key ORDER BY 1",
        "SELECT json_array(module_path,binder_scope,namespace,bound_name,target_module_path,target_name) FROM rust_crate_imports ORDER BY 1",
        "SELECT json_array(module_path,path_key,target_module_path,target_name) FROM rust_crate_root_references ORDER BY 1",
        "SELECT json_array(gap_kind,subject,json(detail)) FROM rust_crate_gaps ORDER BY 1",
    ] {
        output.extend(conn.prepare(sql).unwrap().query_map([], |row| row.get::<_,String>(0))
            .unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap());
    }
        output
    }

    #[test]
    #[hardwon("#5780: a covering index changed the kept Rust import/export targets")]
    fn covering_index_preserves_canonical_bindings_routes_and_evidence() {
        for (case, files) in [
            ("glob-conflict", GLOB_CONFLICT),
            ("mixed-visibility-glob-order", MIXED_VISIBILITY_GLOB_ORDER),
        ] {
            let expected = snapshot(files, false);
            assert!(
                expected
                    .iter()
                    .any(|row| row.contains("InconsistentPrecedence")),
                "the fixture must exercise actual ambiguity: {case}: {expected:?}"
            );
            if case == "mixed-visibility-glob-order" {
                assert!(
                    expected
                        .iter()
                        .any(|row| row.contains("UnsupportedGlobConflictVisibility")),
                    "the fixture must retain mixed-visibility evidence: {expected:?}"
                );
            }
            assert_eq!(expected, snapshot(files, true), "{case}");
        }
    }
}
