// Test-only #11173 M5 replay. The source fixtures build through the analyzer;
// probes capture the actual TEMP inputs before each production reader runs.
#[test]
fn rust_summary_equality_reader_boundary() {
    use brokk_bifrost_analysis::analyzer::store::rust_crates::derivation::summary_equality_probes as probes;
    let mut comparisons = Vec::new();
    for (mid, top, kernel) in [
        (
            "pub use kernel as facade;",
            "pub use mid::*; pub use mid::facade::*;",
            "pub struct Item; pub enum Choice { A, B }",
        ),
        (
            "pub use kernel as namespace; pub use namespace::*;",
            "pub use mid as facade; pub use facade::*;",
            "pub struct Item; pub trait Marker {}",
        ),
        (
            "pub use kernel::*;",
            "pub use mid::*; pub struct Local; impl mid::Marker for Local {}",
            "#[path=\"event.rs\"] pub mod left; #[path=\"event.rs\"] pub mod right; pub use left::*; pub use right::*; pub trait Marker {}",
        ),
        (
            "pub use kernel::event; pub use event::*;",
            "pub use mid::event; pub use event::*;",
            "pub mod event { mod left { pub struct Event; } mod right { pub struct Event; } pub use left::*; pub use right::*; }",
        ),
        (
            "pub use kernel::*; pub use event::*;",
            "pub use mid::*; pub use event::*;",
            "pub mod event { mod left { pub struct Event; } mod right { pub struct Event; } pub use left::*; pub use right::*; }",
        ),
        (
            "#[macro_use] extern crate kernel; pub use kernel::*; pub use kernel::Item as Alias; pub struct Local; impl Marker for Local {}",
            "#[macro_use] extern crate mid; pub use mid::*; pub struct Top; impl mid::Marker for Top {} pub fn run() { let _ = ping!(); }",
            "#[macro_export] macro_rules! ping { () => {1}; } pub trait Marker {} pub struct Item;",
        ),
    ] {
        let fixture = walk_fixture(mid, top, kernel);
        let workspace = summary_equality_workspace(&fixture);
        let store = workspace.store().unwrap();
        let conn = store.read_conn().unwrap();
        comparisons.extend(probes::replay(&conn).unwrap());
    }
    // Preserve the route lane's shared member, inline impl, alias, glob and
    // inactive-placement fixture in the same capture/replay session design.
    let fixture=InlineTestProject::new()
        .file("Cargo.toml", "[package]\nname='consumer'\nversion='0.1.0'\nedition='2021'\n[dependencies]\nprovider={path='provider'}\n")
        .file("src/lib.rs", "pub use provider::*; pub fn use_it() { let _ = left::Item; }")
        .file("provider/Cargo.toml", "[package]\nname='provider'\nversion='0.1.0'\nedition='2021'\n")
        .file("provider/src/lib.rs", "#[path=\"shared.rs\"] pub mod left; #[path=\"shared.rs\"] pub mod right; #[cfg(feature=\"alt\")] #[path=\"shared.rs\"] pub mod alternative; pub use left as facade; pub use right::*;")
        .file("provider/src/shared.rs", "pub struct Item; pub trait Marker {} impl Marker for Item {}")
        .build();
    let workspace = summary_equality_workspace(&fixture);
    let store = workspace.store().unwrap();
    let conn = store.read_conn().unwrap();
    comparisons.extend(probes::replay(&conn).unwrap());
    drop(conn);
    drop(workspace);
    // Two byte-identical files place the same declaration in one module. The
    // binder rejects the ambiguous impl endpoint before chasing placements, so
    // compare the full placement relation as well as the reachable impl rows.
    let duplicate=InlineTestProject::new()
        .file("Cargo.toml", "[package]\nname=\"top\"\nversion=\"0.1.0\"\nedition=\"2021\"\n[workspace]\nmembers=[\"kernel\"]\n[dependencies]\nkernel={path=\"kernel\"}\n")
        .file("src/lib.rs", "pub use kernel::*; pub struct Own; impl kernel::Marker for Own {}")
        .file("kernel/Cargo.toml", "[package]\nname=\"kernel\"\nversion=\"0.1.0\"\nedition=\"2021\"\n")
        .file("kernel/src/lib.rs", "include!(\"event.rs\"); include!(\"twin.rs\"); pub trait Marker {}")
        .file("kernel/src/event.rs", "pub enum Event { Log, Metric }\n")
        .file("kernel/src/twin.rs", "pub enum Event { Log, Metric }\n")
        .build();
    let workspace = summary_equality_workspace(&duplicate);
    let store = workspace.store().unwrap();
    let conn = store.read_conn().unwrap();
    let captured = probes::replay(&conn).unwrap();
    let frontier = captured
        .iter()
        .flat_map(|comparison| comparison.frontier.iter().copied())
        .collect::<BTreeSet<_>>();
    assert!(!frontier.is_empty());
    conn.execute("DELETE FROM cr_foreign", []).unwrap();
    let mut selected = Vec::new();
    for (unit_key, topology_id, summary_id) in frontier {
        conn.execute("INSERT INTO cr_foreign SELECT ?1,topology_id,crate_name FROM rust_crate_topologies WHERE topology_id=?2",rusqlite::params![unit_key.as_slice(),topology_id]).unwrap();
        selected.push(probes::FrontierEntry {
            unit_key,
            topology_id,
            summary_id,
        });
    }
    let inventory = probes::pairs(&selected)
        .into_iter()
        .find(|pair| pair.name == "IMPL_FOREIGN_PLACEMENT_INVENTORY_SQL")
        .unwrap();
    let duplicate_groups:usize=conn.query_row(&format!("SELECT count(*) FROM (SELECT unit_key,container_path,blob_id FROM ({}) GROUP BY unit_key,container_path,blob_id HAVING count(DISTINCT rel_path)>1)",inventory.topology),[],|row|row.get(0)).unwrap();
    assert!(
        duplicate_groups > 0,
        "duplicate-placement fixture had no byte-identical files placed in the same module"
    );
    let inventory = inventory.compare(&conn).unwrap();
    assert!(inventory.topology_rows > 0 && inventory.summary_rows > 0);
    comparisons.extend(captured);
    comparisons.push(inventory);
    drop(conn);
    drop(workspace);
    // Synthetic Rust projects embedded here so this public test has no private fixture dependencies.
    for files in [
        &[
            ("Cargo.toml", "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[workspace]\n\n[dependencies]\nmany-dashes-for-normalized-crate-name = { path = \"dep\" }\n"),
            ("dep/Cargo.toml", "[package]\nname = \"many-dashes-for-normalized-crate-name\"\nversion = \"0.1.0\"\nedition = \"2021\"\n"),
            ("dep/src/lib.rs", "pub struct Item;\n"),
            ("src/lib.rs", "use many_dashes_for_normalized_crate_name::Item;\npub fn local_control() {}\npub fn probe(_: Item) { local_control(); }\n"),
        ][..],
        &[
            ("Cargo.toml", "[workspace]\nmembers = [\"core\", \"cli\"]\nresolver = \"2\"\n"),
            ("cli/Cargo.toml", "[package]\nname = \"cli\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\ncore_lib = { path = \"../core\" }\n"),
            ("cli/src/main.rs", "use core_lib::config::data_dir;\n\nfn main() {\n    let _ = data_dir();\n}\n"),
            ("core/Cargo.toml", "[package]\nname = \"core_lib\"\nversion = \"0.1.0\"\nedition = \"2021\"\n"),
            ("core/src/config/keys.rs", "macro_rules! key_actions {\n    ($($variant:ident),*) => {\n        pub enum KeyAction { $($variant),* }\n    };\n}\n\nkey_actions! { Quit, Help }\n"),
            ("core/src/config/loading.rs", "pub fn data_dir() -> u32 {\n    0\n}\n\npub fn unused_dir() -> u32 {\n    1\n}\n"),
            ("core/src/config.rs", "// Reduced from BrokkAi/mjolnir mj-core/src/config.rs (#6102): a module that\n// re-exports its submodules by glob, where one submodule's items come from a\n// macro the analyzer does not expand.\nmod keys;\nmod loading;\n\npub use keys::*;\npub use loading::*;\n"),
            ("core/src/lib.rs", "pub mod config;\n"),
        ][..],
        &[
            ("Cargo.toml", "[package]\nname = \"usage-graph-cases\"\nversion = \"0.1.0\"\nedition = \"2024\"\n"),
            ("src/lib.rs", "pub mod imports {\n    pub fn format_value() -> String {\n        String::new()\n    }\n\n    pub mod nested {\n        pub struct Config;\n\n        impl Config {\n            pub fn new() -> Self {\n                Self\n            }\n        }\n    }\n}\n\npub mod imported_calls {\n    use crate::imports::format_value;\n\n    pub fn run() {\n        format_value();\n    }\n\n    pub fn run_twice() {\n        format_value();\n        format_value();\n    }\n\n    pub fn parameter_shadows_import(format_value: fn()) {\n        format_value();\n    }\n\n    pub fn local_shadow_does_not_escape() {\n        let format_value = || {};\n        format_value();\n    }\n\n    pub fn after_shadow() {\n        format_value();\n    }\n\n    use crate::imports;\n\n    pub fn via_namespace() {\n        imports::format_value();\n    }\n\n    use crate::imports::nested::Config;\n\n    pub fn associated() {\n        Config::new();\n    }\n}\n\npub mod factories {\n    use std::sync::Arc;\n\n    pub struct Service;\n    pub struct Other;\n\n    impl Service {\n        pub fn new() -> Self {\n            Self\n        }\n\n        pub fn create() -> Self {\n            Self\n        }\n\n        pub fn wrapped() -> Arc<Self> {\n            Arc::new(Self)\n        }\n\n        pub fn run(&self) {}\n    }\n\n    impl Other {\n        pub fn new() -> Self {\n            Self\n        }\n\n        pub fn run(&self) {}\n    }\n\n    pub fn make_service() -> Service {\n        Service\n    }\n\n    pub fn via_free_factory() {\n        let service = make_service();\n        service.run();\n    }\n\n    pub fn via_associated_factory() {\n        let service = Service::new();\n        service.run();\n    }\n\n    pub fn via_static_factory() {\n        let service = Service::create();\n        service.run();\n    }\n\n    pub fn via_wrapped_self_factory() {\n        let service = Service::wrapped();\n        service.run();\n    }\n\n    pub mod hidden {\n        pub struct Service;\n\n        impl Service {\n            pub fn run(&self) {}\n        }\n    }\n\n    pub mod real {\n        pub struct Service;\n\n        impl Service {\n            pub fn run(&self) {}\n        }\n\n        pub fn make() -> Service {\n            Service\n        }\n    }\n\n    use self::real::make;\n\n    pub fn use_resolved_factory() {\n        let service = make();\n        service.run();\n    }\n\n    pub fn block_local_shadow(flag: bool) {\n        let service = Other::new();\n        if flag {\n            let service = Service::new();\n            let _ = service;\n        }\n        service.run();\n    }\n}\n\npub mod traits {\n    pub trait Runner {\n        fn run(&self);\n    }\n\n    pub trait OtherTrait {\n        fn run(&self);\n    }\n\n    pub struct Service;\n    pub struct Other;\n\n    impl Service {\n        pub fn run(&self) {}\n    }\n\n    impl Other {\n        pub fn run(&self) {}\n    }\n\n    pub fn dynamic(receiver: &dyn Runner) {\n        receiver.run();\n    }\n\n    pub fn opaque(receiver: impl Runner) {\n        receiver.run();\n    }\n\n    pub fn bounded_dynamic(receiver: &(dyn Runner + Send)) {\n        receiver.run();\n    }\n\n    pub fn bounded_opaque(receiver: impl Runner + Send) {\n        receiver.run();\n    }\n\n    pub fn higher_ranked(receiver: &dyn for<'a> Runner) {\n        receiver.run();\n    }\n\n    pub fn other_bounded(receiver: impl OtherTrait + Send) {\n        receiver.run();\n    }\n\n    pub fn other_higher_ranked(receiver: &dyn for<'a> OtherTrait) {\n        receiver.run();\n    }\n}\n\npub mod macros_and_recursion {\n    macro_rules! consume {\n        ($($tokens:tt)*) => { $($tokens)* };\n    }\n\n    pub mod wanted {\n        pub struct Owner;\n        pub type Alias = Owner;\n\n        impl Owner {\n            pub fn associated() {}\n        }\n\n        pub fn free() {}\n    }\n\n    pub mod decoy {\n        pub struct Owner;\n        pub type Alias = Owner;\n\n        impl Owner {\n            pub fn associated() {}\n        }\n\n        pub fn free() {}\n    }\n\n    pub fn invoke() {\n        consume!({ wanted::free(); });\n        consume!((wanted::Owner::associated()));\n        consume!((wanted::Alias));\n        consume!({ decoy::free(); });\n        consume!((decoy::Owner::associated()));\n        consume!((decoy::Alias));\n    }\n\n    pub fn recurse() {\n        recurse();\n    }\n\n    pub fn unused() {}\n}\n\npub mod same_owner {\n    pub struct Target;\n\n    impl Target {\n        pub fn method(&self) {}\n\n        pub fn caller(&self) {\n            self.method();\n        }\n    }\n}\n"),
        ][..],
        &[
            ("Cargo.toml", "[package]\nname = \"usage-completeness\"\nversion = \"0.1.0\"\nedition = \"2024\"\n"),
            ("src/lib.rs", "pub struct Number(pub u32);\nimpl Number {\n    pub fn leaf() -> u32 { 1 }\n}\npub fn chain() -> u32 { Number::leaf() }\nimpl PartialEq for Number {\n    fn eq(&self, other: &Self) -> bool { self.0 == other.0 }\n}\nimpl Clone for Number {\n    fn clone(&self) -> Self { Number(self.0) }\n}\npub struct Guard;\nimpl Drop for Guard {\n    fn drop(&mut self) {}\n}\npub trait Action { fn act(&self) -> u32; }\nimpl Action for Number {\n    fn act(&self) -> u32 { self.0 }\n}\npub fn generic<T: Action>(value: &T) -> u32 { value.act() }\n#[derive(Clone)]\npub struct Copyable(pub Number);\n#[test]\nfn explicit_chain() { let actual = chain(); assert_eq!(actual, 1); }\n#[test]\nfn equality_only() { assert!(Number(1) == Number(1)); }\n#[test]\nfn implicit_drop() { let _guard = Guard; }\n#[test]\nfn generic_dispatch() { assert_eq!(generic(&Number(1)), 1); }\n#[test]\nfn derived_clone() { let original = Copyable(Number(1)); let _copy = original.clone(); }\nimpl Number {\n    pub fn instance_leaf(&self) -> u32 { self.0 }\n    pub fn self_chain(&self) -> u32 { self.instance_leaf() }\n    pub fn self_loop(&self, n: u32) -> u32 { if n == 0 { self.0 } else { self.self_loop(n - 1) } }\n}\n#[test]\nfn same_owner_chain() { let actual = Number::self_chain(&Number(1)); assert_eq!(actual, 1); }\npub fn unresolved<T: std::ops::Deref<Target = Number>>(value: &T) {\n    value.instance_leaf();\n}\n"),
        ][..],
    ] {
        let mut fixture = InlineTestProject::new();
        for &(path, source) in files {
            fixture = fixture.file(path, source);
        }
        let fixture = fixture.build();
        let workspace = summary_equality_workspace(&fixture);
        let store = workspace.store().unwrap();
        let conn = store.read_conn().unwrap();
        comparisons.extend(probes::replay(&conn).unwrap());
    }
    let mut table = String::from(
        "| Reader | Topology rows | Summary rows | Equal | Categories (multiset row changes) |\n|---|---:|---:|---|---|\n",
    );
    let mut totals = BTreeMap::<_, (usize, usize, bool)>::new();
    let mut differences = Vec::new();
    let mut categories = BTreeMap::<_, BTreeMap<_, usize>>::new();
    let mut unexplained = Vec::new();
    let mut destinations = BTreeMap::<_, (usize, usize)>::new();
    for comparison in comparisons {
        categories.entry(comparison.reader).or_default();
        for (category, count) in &comparison.categories {
            *categories
                .entry(comparison.reader)
                .or_default()
                .entry(*category)
                .or_default() += count;
        }
        if !comparison.unexplained_topology.is_empty()
            || !comparison.unexplained_summary.is_empty()
            || comparison.unexplained_destination
        {
            unexplained.push(format!(
                "{}: topology={:?}, summary={:?}",
                comparison.reader, comparison.unexplained_topology, comparison.unexplained_summary
            ));
        }
        if let Some(summary) = &comparison.summary_destination {
            let stats = destinations.entry(comparison.reader).or_default();
            stats.0 +=
                usize::from(comparison.topology_destination != comparison.summary_destination);
            stats.1 += usize::from(matches!(summary, probes::Destination::Rejected(_)));
        }
        let equal = comparison.topology_only.is_empty() && comparison.summary_only.is_empty();
        if matches!(
            comparison.reader,
            "ALL_PLACEMENTS"
                | "CONTAINERS_SQL"
                | "FOREIGN_REEXPORT_STEPS_SQL"
                | "FOREIGN_ROOT_SQL"
                | "FOREIGN_GLOB_STEPS_SQL"
                | "PUBLIC_SURFACE_GLOBS_SQL"
                | "PUBLIC_SURFACE_ALIASES_ROUTES_SQL"
                | "PUBLIC_SURFACE_LOOKUP_ALIASES_ROUTES_SQL"
        ) && !equal
        {
            unexplained.push(format!(
                "route projection {} must remain exactly equal: topology={:?}, summary={:?}",
                comparison.reader, comparison.topology_only, comparison.summary_only
            ));
        }

        let entry = totals.entry(comparison.reader).or_insert((0, 0, true));
        entry.0 += comparison.topology_rows;
        entry.1 += comparison.summary_rows;
        entry.2 &= equal;
        if !equal {
            differences.push(comparison);
        }
    }
    for (name, (topology, summary, equal)) in &totals {
        table.push_str(&format!(
            "| {name} | {topology} | {summary} | {equal} | {:?} |\n",
            categories[name]
        ));
    }
    table.push_str(&format!(
        "\nPUBLIC_SURFACE_BINDINGS_SQL: BLOCKED: {}\n",
        probes::PUBLIC_SURFACE_BINDING_BLOCKED
    ));
    table.push_str(&format!(
        "\nDuplicate-placement groups: {duplicate_groups}\n"
    ));
    table.push_str(&format!("\nDestination differences/rejections (raw candidate): {destinations:?}\nUnexplained differences: {unexplained:?}\n"));
    table.push_str(&format!("\nRaw differences:\n{differences:#?}\n"));
    let output = std::env::temp_dir().join("11173-m5-probes/result.md");
    std::fs::create_dir_all(output.parent().unwrap()).unwrap();
    std::fs::write(&output, &table).unwrap();
    println!("{table}");
    for pair in probes::pairs(&[]) {
        assert!(
            totals
                .get(pair.name)
                .is_some_and(|entry| entry.0 > 0 || entry.1 > 0),
            "reader {} had no row coverage: {totals:?}",
            pair.name
        );
    }
    assert!(
        unexplained.is_empty(),
        "unclassified summary differences {unexplained:?}; see {}",
        output.display()
    );
}

fn summary_equality_workspace(fixture: &crate::inline_project::BuiltInlineTestProject) -> brokk_bifrost_analysis::analyzer::WorkspaceAnalyzer {
    use brokk_bifrost_analysis::analyzer::{WorkspaceAnalyzer, tree_sitter_analyzer::ephemeral_store_context};
    use brokk_bifrost_analysis::analyzer::store::rust_crates::derivation::summary_equality_probes as probes;
    let context = ephemeral_store_context(fixture.project_dyn().as_ref()).unwrap();
    probes::begin_capture(&context.store.read_conn().unwrap());
    WorkspaceAnalyzer::build_with_store_context_for_test(fixture.project_dyn(), AnalyzerConfig::default(), context).unwrap()
}

#[test]
#[hardwon("#11173: alias normalization accepted a different real declaration endpoint")]
fn rust_summary_equality_rejects_wrong_alias_endpoint() {
    use brokk_bifrost_analysis::analyzer::store::rust_crates::derivation::summary_equality_probes as probes;
    let fixture = walk_fixture("pub use kernel::Item as Alias;", "pub use mid::*;", "pub struct Item; pub struct Other;");
    let workspace = summary_equality_workspace(&fixture);
    let conn = workspace.store().unwrap().read_conn().unwrap();
    let writer = rusqlite::Connection::open(conn.path().unwrap()).unwrap();
    let changed = writer.execute("UPDATE rust_resolution_unit_summary_exports SET target_name='Other' WHERE rowid=(SELECT e.rowid FROM rust_resolution_unit_summary_exports e WHERE e.name='Alias' AND e.target_name='Item' LIMIT 1)", []).unwrap();
    assert_eq!(changed, 1);
    let comparisons = probes::replay(&conn).unwrap();
    assert!(comparisons.iter().any(|comparison| !comparison.unexplained_summary.is_empty()), "{comparisons:#?}");
}
