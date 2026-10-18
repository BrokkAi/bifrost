mod forwarded_surface_tests {
    use super::*;

    const NESTED_ITEMS: &str = "pub enum Event { Log, Metric }\n\
        pub struct Open(pub u8);\n\
        pub struct Closed(u8);\n\
        mod hidden { pub enum Secret { First } }\n";

    fn forwarded_fixture(
        facade: &str,
        consumer: &str,
    ) -> crate::inline_project::BuiltInlineTestProject {
        let fixture = vector_reexport_fixture();
        fixture
            .file("lib/vector-core/src/lib.rs")
            .write("pub mod event;\npub mod outside { pub enum Unrelated { First } }\n")
            .unwrap();
        fixture
            .file("lib/vector-core/src/event.rs")
            .write(format!("pub mod nested {{ {NESTED_ITEMS} }}\n"))
            .unwrap();
        fixture
            .file("lib/vector-lib/src/lib.rs")
            .write(facade)
            .unwrap();
        fixture.file("src/lib.rs").write(consumer).unwrap();
        fixture
    }

    fn topology_surface(workspace: &WorkspaceAnalyzer, unit: &str) -> Vec<u8> {
        workspace
            .store()
            .unwrap()
            .read_conn()
            .unwrap()
            .query_row(
                "SELECT export_surface_digest FROM rust_crate_topologies WHERE topology_id = ?1",
                [vector_topologies(workspace)[unit]],
                |row| row.get(0),
            )
            .unwrap()
    }

    fn consumer_names(workspace: &WorkspaceAnalyzer) -> BTreeSet<(String, String)> {
        vector_surface(workspace)
            .into_iter()
            .map(|(name, namespace, _, _)| (name, namespace))
            .collect()
    }

    #[test]
    #[hardwon("#5133: forwarded nested modules need descendant-sensitive published output")]
    fn nested_forwarding_routes_publish_descendants_and_legal_constructors() {
        // These are alternate public entrances to one source module, not
        // separate implementations of module traversal. The glob selects the
        // nested module binding; it does not recursively flatten its contents.
        for (route, facade, consumer) in [
            (
                "public child",
                "pub use vector_core::event;\n",
                "pub use vector_lib::event::nested::*;\n",
            ),
            (
                "module alias",
                "pub use vector_core::event as events;\n",
                "pub use vector_lib::events::nested::*;\n",
            ),
            (
                "crate root alias",
                "pub use vector_core as core;\n",
                "pub use vector_lib::core::event::nested::*;\n",
            ),
            (
                "selected glob binding",
                "pub mod api { pub use vector_core::event::*; }\n",
                "pub use vector_lib::api::nested::*;\n",
            ),
        ] {
            let fixture = forwarded_fixture(facade, consumer);
            let workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
            let before = live_summaries(&workspace);
            let before_topology = topology_surface(&workspace, "vector_lib");
            let expected = BTreeSet::from([
                ("Closed".to_owned(), "type".to_owned()),
                ("Event".to_owned(), "type".to_owned()),
                ("Open".to_owned(), "type".to_owned()),
                ("Open".to_owned(), "value".to_owned()),
            ]);
            assert_eq!(consumer_names(&workspace), expected, "{route}");
            assert_vector_event_export(
                &workspace,
                "vector",
                "lib/vector-core/src/event.rs",
                "vector_lib",
            );
            assert_vector_consumed_live_facade(&workspace);
            assert_vector_matches_fresh_store(&fixture, &workspace);

            // Add a descendant without changing the forwarding declarations.
            // The downstream glob must observe both namespaces of the new
            // legal constructor, while the existing private constructor stays
            // absent and the private child module stays inaccessible.
            let event = fixture.file("lib/vector-core/src/event.rs");
            event
                .write(format!(
                    "pub mod nested {{ {NESTED_ITEMS}pub struct Added(pub u8); }}\n"
                ))
                .unwrap();
            let updated = workspace.update(&BTreeSet::from([event]));
            let after = live_summaries(&updated);
            assert_ne!(
                before_topology,
                topology_surface(&updated, "vector_lib"),
                "topology publishes the changed forwarded module graph: {route}"
            );
            assert_ne!(before["vector_lib"].1, after["vector_lib"].1, "{route}");
            assert_ne!(before["vector"].0, after["vector"].0, "{route}");
            let mut expanded = expected;
            expanded.extend([
                ("Added".to_owned(), "type".to_owned()),
                ("Added".to_owned(), "value".to_owned()),
            ]);
            assert_eq!(consumer_names(&updated), expanded, "{route}");
            assert_vector_event_export(
                &updated,
                "vector",
                "lib/vector-core/src/event.rs",
                "vector_lib",
            );
            assert_vector_consumed_live_facade(&updated);
            assert_vector_matches_fresh_store(&fixture, &updated);

            // A private body edit keeps the facade publication and consumer
            // summary reusable even though the declaration blob changes.
            let core_event = fixture.file("lib/vector-core/src/event.rs");
            core_event
                .write(format!(
                    "pub mod nested {{ {NESTED_ITEMS}pub struct Added(pub u8); }}\nfn private_body() {{}}\n"
                ))
                .unwrap();
            let private_updated = updated.update(&BTreeSet::from([core_event]));
            let after_private_body = live_summaries(&private_updated);
            assert_eq!(
                after["vector_lib"].1, after_private_body["vector_lib"].1,
                "facade output cutoff after private core body edit: {route}"
            );
            assert_eq!(
                after["vector"], after_private_body["vector"],
                "consumer summary cutoff after private core body edit: {route}"
            );

            // Editing the consumer forces it to read the retained facade
            // publication again. Its glob export must still resolve to the
            // canonical core declaration, not the facade's older blob.
            let consumer_file = fixture.file("src/lib.rs");
            consumer_file
                .write(format!("{consumer}pub fn consumer_edit() {{}}\n"))
                .unwrap();
            let consumer_updated = private_updated.update(&BTreeSet::from([consumer_file]));
            let after_consumer_edit = live_summaries(&consumer_updated);
            eprintln!("forwarded route {route}: checking consumer rederivation");
            assert_vector_event_export(
                &consumer_updated,
                "vector",
                "lib/vector-core/src/event.rs",
                "vector_lib",
            );
            let mut with_consumer_edit = expanded;
            with_consumer_edit.insert(("consumer_edit".to_owned(), "value".to_owned()));
            assert_eq!(
                consumer_names(&consumer_updated),
                with_consumer_edit,
                "{route}"
            );
            assert_vector_consumed_live_facade(&consumer_updated);
            assert_vector_matches_fresh_store(&fixture, &consumer_updated);
            assert_ne!(after_private_body["vector"], after_consumer_edit["vector"]);
        }
    }

    #[test]
    #[hardwon(
        "#5133: private descendants and unrelated modules must retain forwarded-surface cutoff"
    )]
    fn forwarded_module_cutoff_excludes_private_descendants_bodies_and_other_modules() {
        let fixture = forwarded_fixture(
            "pub use vector_core::event as events;\n",
            "pub use vector_lib::events::nested::{Event, Open, Closed};\n",
        );
        let mut workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
        let mut previous = live_summaries(&workspace);
        let published_topology = topology_surface(&workspace, "vector_lib");
        let expected = consumer_names(&workspace);
        for (edit, path, source) in [
            (
                "private body",
                "lib/vector-core/src/event.rs",
                format!("pub mod nested {{ {NESTED_ITEMS} }}\nfn private_body() -> u8 {{ 2 }}\n"),
            ),
            (
                "private descendant",
                "lib/vector-core/src/event.rs",
                format!(
                    "pub mod nested {{ {NESTED_ITEMS}mod private_child {{ pub struct Hidden(pub u8); }} }}\n"
                ),
            ),
            (
                "unrelated public module",
                "lib/vector-core/src/lib.rs",
                "pub mod event;\npub mod outside { pub enum Unrelated { First } pub struct Added(pub u8); }\n"
                    .to_owned(),
            ),
        ] {
            let file = fixture.file(path);
            file.write(source).unwrap();
            workspace = workspace.update(&BTreeSet::from([file]));
            let after = live_summaries(&workspace);
            assert_eq!(
                published_topology,
                topology_surface(&workspace, "vector_lib"),
                "public forwarded topology is unchanged: {edit}"
            );
            assert_eq!(previous["vector_lib"].1, after["vector_lib"].1, "{edit}");
            assert_eq!(previous["vector"], after["vector"], "consumer cutoff: {edit}");
            assert_eq!(consumer_names(&workspace), expected, "{edit}");
            assert_vector_consumed_live_facade(&workspace);
            assert_vector_matches_fresh_store(&fixture, &workspace);
            previous = after;
        }
    }

    #[test]
    #[hardwon("#5133: cyclic module aliases and diamond entrances need a finite public surface")]
    fn forwarded_module_alias_cycle_and_diamond_terminate_and_match_fresh_store() {
        let fixture = forwarded_fixture(
            "pub use vector_core::event;\n",
            "pub use vector_lib::event::left::Event as LeftEvent;\n\
             pub use vector_lib::event::right::Event as RightEvent;\n",
        );
        let cyclic = format!(
            "pub mod nested {{ {NESTED_ITEMS} }}\npub use self::nested as left;\n\
             pub use self::nested as right;\n\
             pub mod cycle {{ pub use crate::event as again; }}\n"
        );
        let event = fixture.file("lib/vector-core/src/event.rs");
        event.write(&cyclic).unwrap();
        let workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
        let before = live_summaries(&workspace);
        let before_topology = topology_surface(&workspace, "vector_lib");
        let expected = BTreeSet::from([
            ("LeftEvent".to_owned(), "type".to_owned()),
            ("RightEvent".to_owned(), "type".to_owned()),
        ]);
        assert_eq!(consumer_names(&workspace), expected);
        assert_vector_matches_fresh_store(&fixture, &workspace);

        event
            .write(format!("{cyclic}pub struct Added(pub u8);\n"))
            .unwrap();
        let updated = workspace.update(&BTreeSet::from([event]));
        let after = live_summaries(&updated);
        assert_ne!(before_topology, topology_surface(&updated, "vector_lib"));
        assert_ne!(before["vector_lib"].1, after["vector_lib"].1);
        assert_ne!(before["vector"].0, after["vector"].0);
        assert_eq!(consumer_names(&updated), expected);
        assert_vector_consumed_live_facade(&updated);
        assert_vector_matches_fresh_store(&fixture, &updated);
    }

    #[test]
    #[hardwon("#5133: simultaneous producer and consumer edits must not consume a stale facade")]
    fn simultaneous_core_and_consumer_edits_match_fresh_forwarded_surface() {
        let fixture = vector_reexport_fixture();
        let workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
        let core = fixture.file("lib/vector-core/src/event.rs");
        let consumer = fixture.file("src/lib.rs");
        // This changes both seeds while the intermediate facade's source is
        // untouched. Replacing an enum with a public tuple struct adds a value
        // export, so stale topology cannot pass by retaining the old type name.
        core.write("pub struct Event(pub u8);\n").unwrap();
        consumer
            .write("pub use vector_lib::event::Event;\npub fn consumer_edit() {}\n")
            .unwrap();
        let updated = workspace.update(&BTreeSet::from([core, consumer]));
        assert_vector_matches_fresh_store(&fixture, &updated);
        assert_eq!(
            consumer_names(&updated),
            BTreeSet::from([
                ("Event".to_owned(), "type".to_owned()),
                ("Event".to_owned(), "value".to_owned()),
                ("consumer_edit".to_owned(), "value".to_owned()),
            ])
        );
        assert_vector_consumed_live_facade(&updated);
    }
}
