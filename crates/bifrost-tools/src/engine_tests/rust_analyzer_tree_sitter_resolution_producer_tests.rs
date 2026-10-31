#[cfg(test)]
mod rust_departing_root_tests {
    use brokk_bifrost_analysis::analyzer::QueryScope;

    use brokk_bifrost_test_macros::hardwon;
    use git2::ObjectType;
    use git2::Oid;
    use std::collections::BTreeSet;
    use std::sync::Arc;
    use std::sync::atomic::Ordering;

    use brokk_bifrost_rust_analysis::analyzer::rust::adapter::RustAdapter;

    use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerBuildTierAccess;

    use brokk_bifrost_core::analyzer::config::AnalyzerConfig;

    use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;

    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_analysis::analyzer::store::AnalyzerStore;

    use brokk_bifrost_core::cancellation::CancellationToken;

    use brokk_bifrost_core::analyzer::model::CodeUnit;

    use brokk_bifrost_core::analyzer::model::CodeUnitType;

    use brokk_bifrost_core::hash::HashSet;

    use brokk_bifrost_analysis::analyzer::store::resolution_publication::ResolutionContentPublicationOutcome;

    use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionContentMountRequest;

    use brokk_bifrost_analysis::analyzer::store::resolution_publication::SelectedResolutionOverlayInputsOutcome;

    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::TreeSitterAnalyzer;

    use brokk_bifrost_analysis::analyzer::store::WorkspaceFileRow;

    use brokk_bifrost_core::hash::map_with_capacity;

    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::revision_image_store_context;

    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::store_context_from_store;

    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::resolution_producer_tests::rust_root_test_support::parse_progress_counter as parse_progress_counter;

    #[test]
    fn embedded_rust_declarations_have_exact_mount_independent_source_ids() {
        use brokk_bifrost_core::analyzer::source_facts::SourceOccurrenceProvenance;

        let source = r#"
macro_rules! passthrough { ($($item:item)*) => { $($item)* }; }
passthrough! {
    pub mod generated {
        pub struct Item { pub field: usize }
        impl Item { pub fn method(&self) {} }
        pub enum Choice { Named { value: usize }, Empty }
        pub trait Trait { fn required(&self); type Associated; }
        pub type Alias = Item;
        pub const CONSTANT: usize = 1;
        unsafe extern "C" { fn foreign(); static FOREIGN: usize; }
        passthrough! { pub fn nested() {} }
    }
    pub fn repeated() {}
    pub fn repeated() {}
}
"#;
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file("src/first.rs", source)
            .file("src/second.rs", source)
            .build();
        let parse = |path| {
            let mut parser = tree_sitter::Parser::new();
            parser
                .set_language(&tree_sitter_rust::LANGUAGE.into())
                .unwrap();
            let tree = parser.parse(source, None).unwrap();
            brokk_bifrost_rust::declarations::parse_rust_file(&fixture.file(path), source, &tree)
        };
        let first = parse("src/first.rs");
        let second = parse("src/second.rs");
        let facts = first.source_facts.as_ref().unwrap();
        assert_eq!(
            facts.occurrences,
            second.source_facts.as_ref().unwrap().occurrences
        );
        assert_eq!(
            facts.rust_declaration_properties,
            second
                .source_facts
                .as_ref()
                .unwrap()
                .rust_declaration_properties,
            "declaration properties belong to content, not the mount"
        );
        let expected_names = [
            "generated",
            "Item",
            "field",
            "method",
            "Choice",
            "Named",
            "value",
            "Empty",
            "Trait",
            "required",
            "Associated",
            "Alias",
            "CONSTANT",
            "foreign",
            "FOREIGN",
            "nested",
            "repeated",
            "repeated",
        ];
        let embedded_names = first
            .source_declaration_units
            .iter()
            .filter(|(id, _)| {
                let declaration = facts.occurrences.declaration(*id);
                facts
                    .occurrences
                    .occurrence(declaration.occurrence)
                    .provenance
                    == SourceOccurrenceProvenance::Embedded
            })
            .map(|(_, unit)| unit.identifier())
            .collect::<Vec<_>>();
        assert_eq!(
            embedded_names, expected_names,
            "nested replay must retain depth-first source order"
        );
        for name in expected_names.into_iter().collect::<BTreeSet<_>>() {
            let matches = first
                .source_declaration_units
                .iter()
                .filter(|(_, unit)| unit.identifier() == name)
                .collect::<Vec<_>>();
            assert_eq!(
                matches.len(),
                if name == "repeated" { 2 } else { 1 },
                "every supported embedded declaration must retain its own source identity: {name}"
            );
            for (id, unit) in matches {
                let declaration = facts.occurrences.declaration(*id);
                let occurrence = facts.occurrences.occurrence(declaration.occurrence);
                assert_eq!(occurrence.provenance, SourceOccurrenceProvenance::Embedded);
                let name_occurrence = facts.occurrences.occurrence(declaration.name.unwrap());
                assert_eq!(
                    name_occurrence.provenance,
                    SourceOccurrenceProvenance::Embedded
                );
                assert_eq!(
                    &source[name_occurrence.range.start_byte..name_occurrence.range.end_byte],
                    name
                );
                let second_unit = &second
                    .source_declaration_units
                    .iter()
                    .find(|(other_id, _)| other_id == id)
                    .unwrap()
                    .1;
                assert_eq!(unit.identifier(), second_unit.identifier());
                assert_ne!(unit.source(), second_unit.source());
            }
        }
    }

    #[test]
    fn hydrated_rust_overlay_is_not_an_empty_native_replacement() {
        let source = "pub fn target() {}\npub fn caller() { target(); }\n";
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file("src/lib.rs", source)
            .build();
        let disk = TreeSitterAnalyzer::new(fixture.project_dyn(), RustAdapter);
        let file = fixture.file("src/lib.rs");
        let overlay = Arc::new(brokk_bifrost_core::analyzer::project::OverlayProject::new(
            fixture.project_dyn(),
        ));
        assert!(overlay.set(file.abs_path(), source.to_owned()));
        let mut analyzer = disk.clone_with_project(Arc::new(overlay.snapshot()));
        // Model a reopened cache or eviction of the bounded producer snapshot.
        analyzer.source_snapshot_file_states = Arc::new(map_with_capacity(0));
        let state = analyzer
            .fetch_file_state(&file)
            .expect("persisted display rows");
        assert!(!state.declarations.is_empty());
        assert!(state.source_facts.is_none());
        let snapshots = analyzer.selected_workspace_snapshots();
        let SelectedResolutionOverlayInputsOutcome::Ready {
            masks,
            content_mounts,
        } = analyzer
            .selected_rust_resolution_overlay_inputs(
                snapshots.as_ref(),
                &CancellationToken::default(),
            )
            .unwrap()
        else {
            panic!("hydrated overlay publication must be ready");
        };
        assert_eq!(masks.len(), 1);
        assert_eq!(content_mounts.len(), 1);
        assert_eq!(content_mounts[0].persisted_relative_path(), "src/lib.rs");
        assert_eq!(content_mounts[0].publication().owner(), &snapshots["rust"]);
    }

    #[test]
    #[hardwon(
        "#4289: an interior self in a bare path produced a root route with a qualifier and panicked lowering"
    )]
    fn rust_interior_path_anchors_gap_without_panicking_workspace_index() {
        use brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapKind;

        let source = r#"
pub mod z { pub struct T; pub struct Other; pub struct Imported; pub fn f() {} }
pub type G = z::self::self;
pub type BadSuper = z::super::Other;
pub type BadCrate = z::crate::Other;
pub type BadSelfType = z::Self::Other;
pub fn calls() {
    z::self::f();
    let _ = z::super::T;
    let _ = z::crate::T;
    let _ = z::Self::T;
}
mod outer { pub fn caller() { super::self::target(); } }
use z::self::Imported as BadUseSelf;
use z::super::Imported as BadUseSuper;
use z::crate::Imported as BadUseCrate;
use z::self as z_alias;
use z::{self as z_module};
use z::self::*;
mod import_self { use super::z::self; }
pub type LeadingSelf = self::z::T;
mod first { mod second { pub type LeadingSuper = super::super::z::T; } }
mod third { pub type SelfSuper = self::super::z::T; }
"#;
        let fixture = InlineTestProject::with_language(Language::Rust)
        .file(
            "Cargo.toml",
            "[package]\nname = \"interior-path-anchor\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .file("src/lib.rs", source)
        .build();
        let file = fixture.file("src/lib.rs");

        let workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
        assert!(
            workspace
                .analyzer()
                .declarations(&file)
                .iter()
                .any(|declaration| declaration.identifier() == "G"),
            "workspace indexing should retain the type alias"
        );

        let analyzer = TreeSitterAnalyzer::new(fixture.project_dyn(), RustAdapter);
        let parsed = analyzer
            .fetch_file_state(&file)
            .expect("indexed Rust file state");
        let facts = &parsed.resolution_facts;
        let unsupported_routes = facts
            .gaps
            .iter()
            .filter(|gap| gap.kind == ResolutionGapKind::UnsupportedRoute)
            .map(|gap| {
                let site = facts.sites[gap.site.index()];
                (
                    site.start_byte,
                    site.end_byte,
                    &source[site.start_byte..site.end_byte],
                )
            })
            .collect::<Vec<_>>();
        let root_routes = facts
            .root_references
            .iter()
            .map(|route| {
                let site = facts.sites[route.reference.index()];
                let segments = facts
                    .root_reference_segments
                    .iter()
                    .filter(|segment| segment.reference == route.reference)
                    .map(|segment| {
                        (
                            segment.position,
                            facts.names[segment.name.index()].spelling.as_str(),
                        )
                    })
                    .collect::<Vec<_>>();
                (
                    route.reference,
                    site.start_byte,
                    site.end_byte,
                    route.anchor,
                    route.prefix_reference,
                    segments,
                )
            })
            .collect::<Vec<_>>();
        for malformed in [
            "z::self::self",
            "z::super::T",
            "z::crate::T",
            "z::Self::T",
            "z::super::Other",
            "z::crate::Other",
            "z::Self::Other",
            "z::self::f",
            "z::self::Imported",
            "z::super::Imported",
            "z::crate::Imported",
            "super::self::target",
        ] {
            assert!(
                unsupported_routes
                    .iter()
                    .any(|(_, _, route)| route.contains(malformed)),
                "missing UnsupportedRoute gap for {malformed}: {unsupported_routes:?}"
            );
        }
        for (start, end, _) in &unsupported_routes {
            assert!(
                facts.root_references.iter().all(|route| {
                    let site = facts.sites[route.reference.index()];
                    site.end_byte <= *start || site.start_byte >= *end
                }),
                "malformed path emitted a root route: {unsupported_routes:?}; root routes: {root_routes:?}"
            );
            assert!(
                facts.identifiers.iter().all(|identifier| {
                    identifier.qualifier.is_none_or(|_| {
                        let site = facts.sites[identifier.site.index()];
                        site.end_byte <= *start || site.start_byte >= *end
                    })
                }),
                "malformed path emitted a receiver qualifier: {unsupported_routes:?}"
            );
        }
        assert!(
            unsupported_routes.iter().all(|(_, _, route)| {
                !route.contains("use z::{self as z_module}")
                    && !route.contains("use z::self as z_alias")
                    && !route.contains("use z::self::*")
                    && !route.contains("use super::z::self")
                    && !route.contains("super::super::z::T")
                    && !route.contains("self::super::z::T")
                    && !route.contains("self::z::T")
            }),
            "valid leading and use-list paths must remain supported: {unsupported_routes:?}"
        );
    }

    #[test]
    fn rust_m6a_fixture_exposes_usage_inputs_and_fail_closed_resolution_facts() {
        let fixture = brokk_bifrost_rust::resolution_spike_fixture::M6A_RUST_WORKSPACE_FILES
            .iter()
            .fold(InlineTestProject::new(), |project, (path, source)| {
                project.file(*path, *source)
            })
            .build();
        assert_eq!(fixture.languages(), BTreeSet::from([Language::Rust]));

        let analyzer = TreeSitterAnalyzer::new(fixture.project_dyn(), RustAdapter);
        assert_eq!(
            analyzer.state.persistence_stats.failed_blobs,
            0,
            "Rust resolution fixture persistence failures: {:?}",
            analyzer.state.dirty_snapshot()
        );
        let mut declaration_kinds = BTreeSet::new();
        let mut saw_named_alias_export = false;
        let mut saw_glob_export = false;
        let mut saw_named_alias_import = false;
        let mut saw_model_glob_import = false;
        let mut saw_crate_glob_import = false;
        let mut selected_module_count = 0;
        let mut saw_model_route = false;
        let mut saw_test_only_route = false;
        let mut saw_local_item_macro = false;
        let mut saw_exported_item_macro = false;
        let mut saw_exported_macro_route_marker = false;
        let mut selected_cfg_conditions = BTreeSet::new();
        let mut saw_include_edge = false;
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("configure Rust parser");
        for (path, source) in brokk_bifrost_rust::resolution_spike_fixture::M6A_RUST_WORKSPACE_FILES
            .iter()
            .filter(|(path, _)| path.ends_with(".rs"))
        {
            let file = fixture.file(path);
            let state = analyzer
                .fetch_file_state(&file)
                .unwrap_or_else(|| panic!("Rust fixture state is available for {path}"));
            let tree = parser.parse(source, None).expect("parse Rust spike file");
            let parsed = brokk_bifrost_rust::declarations::parse_rust_file(&file, source, &tree);
            assert!(!parsed.resolution_facts.is_empty());
            assert!(!parsed.resolution_facts.scopes.is_empty());
            // `app/src/tests.rs` is `assert_ne!(super::selected::VALUE, 0)` and
            // nothing else. Both argument groups parse as expressions, so the
            // producer enumerates them and the file has no enumeration gap.
            // `engine/src/model.rs` declares two associated constants, in a trait
            // and in a trait impl, and nothing else it cannot read. Both are
            // members now rather than unsupported member scopes, so it has none
            // either.
            if matches!(
                *path,
                "app/src/included.rs"
                    | "engine/src/lib.rs"
                    | "app/src/tests.rs"
                    | "engine/src/model.rs"
            ) {
                assert!(
                    parsed
                        .resolution_facts
                        .reference_enumeration_gaps
                        .is_empty(),
                    "supported source {path} should have no enumeration gaps: {:?}",
                    parsed.resolution_facts.reference_enumeration_gaps
                );
            } else {
                assert!(
                    !parsed
                        .resolution_facts
                        .reference_enumeration_gaps
                        .is_empty(),
                    "the bounded Rust producer must not claim complete reference enumeration for {path}"
                );
            }
            declaration_kinds.extend(state.declarations.iter().map(CodeUnit::kind));
            let oid =
                Oid::hash_object(ObjectType::Blob, source.as_bytes()).expect("fixture blob OID");
            let persisted_usage = analyzer
                .store_context
                .store
                .rust_usage_facts(&brokk_bifrost_core::gitblob::BlobKey::unvaried(oid, "rust"))
                .expect("read persisted Rust usage facts");
            assert_eq!(persisted_usage, parsed.rust_usage_facts);
            saw_named_alias_export |= persisted_usage.exports.iter().any(|export| {
                export.exported_name.as_deref() == Some("PublicWidget")
                    && export.source_path == "model"
                    && export.imported_name.as_deref() == Some("Widget")
                    && !export.is_glob
            });
            saw_glob_export |= persisted_usage.exports.iter().any(|export| {
                export.exported_name.is_none()
                    && export.source_path == "model"
                    && export.imported_name.is_none()
                    && export.is_glob
            });
            saw_named_alias_import |= persisted_usage.import_targets.iter().any(|import| {
                import.module_path == ["engine"]
                    && import.bound_name.as_deref() == Some("WidgetAlias")
                    && import.imported_name.as_deref() == Some("PublicWidget")
                    && !import.is_glob
            });
            saw_model_glob_import |= persisted_usage.import_targets.iter().any(|import| {
                import.module_path == ["engine", "model"]
                    && import.bound_name.is_none()
                    && import.imported_name.is_none()
                    && import.is_glob
            });
            saw_crate_glob_import |= persisted_usage.import_targets.iter().any(|import| {
                import.module_path == ["engine"]
                    && import.bound_name.is_none()
                    && import.imported_name.is_none()
                    && import.is_glob
            });
            selected_module_count += persisted_usage
                .modules
                .iter()
                .filter(|module| module.module_name == "selected" && module.is_inline)
                .count();
            selected_cfg_conditions.extend(
                persisted_usage
                    .modules
                    .iter()
                    .filter(|module| module.module_name == "selected" && module.is_inline)
                    .map(|module| {
                        brokk_bifrost_core::analyzer::rust_facts::encode_rust_cfg_condition(
                            &module.cfg_condition,
                        )
                    }),
            );
            saw_model_route |= persisted_usage
                .module_routes
                .routes
                .iter()
                .any(|route| route.module_name == "model" && !route.test_gated);
            saw_test_only_route |= persisted_usage
                .module_routes
                .routes
                .iter()
                .any(|route| route.module_name == "tests" && route.test_gated);
            saw_local_item_macro |= persisted_usage
                .module_routes
                .item_macros
                .iter()
                .any(|item_macro| item_macro.name == "local_value");
            saw_exported_item_macro |= persisted_usage
                .module_routes
                .item_macros
                .iter()
                .any(|item_macro| item_macro.name == "exported_value");
            saw_exported_macro_route_marker |= persisted_usage
                .module_routes
                .item_macros
                .iter()
                .any(|item_macro| item_macro.name == "exported_value" && item_macro.exported);
            saw_include_edge |= persisted_usage
                .include_edges
                .iter()
                .any(|edge| edge.relative_path == "included.rs" && edge.file_name == "included.rs");
        }
        assert!(declaration_kinds.contains(&CodeUnitType::Class));
        assert!(declaration_kinds.contains(&CodeUnitType::Function));
        assert!(declaration_kinds.contains(&CodeUnitType::Field));
        assert!(declaration_kinds.contains(&CodeUnitType::Module));
        assert!(declaration_kinds.contains(&CodeUnitType::Macro));
        assert!(saw_named_alias_export);
        assert!(saw_glob_export);
        assert!(saw_named_alias_import);
        assert!(saw_model_glob_import);
        assert!(saw_crate_glob_import);
        assert_eq!(selected_module_count, 2);
        assert_eq!(
            selected_cfg_conditions,
            BTreeSet::from([
                "atom feature = \"left\"".to_string(),
                "not feature = \"left\"".to_string(),
            ])
        );
        assert!(saw_model_route);
        assert!(saw_test_only_route);
        assert!(saw_local_item_macro);
        assert!(saw_exported_item_macro);
        assert!(saw_exported_macro_route_marker);
        assert!(saw_include_edge);
    }

    #[test]
    fn rust_generic_import_source_ids_survive_reopen_without_reparse() {
        const SOURCE: &str = "\
macro_rules! passthrough { ($($item:item)*) => { $($item)* }; }

use crate::root::{Root as RootAlias, *};
extern crate ext as ext_alias;

fn local_before_module() {
    use crate::local::Local;
    mod inner {
        use crate::inside::Inside;
    }
}

mod nested {
    use super::{Nested as NestedAlias, *};
}

use crate::after::After;

passthrough! {
    use crate::generated::{Generated as GeneratedAlias, *};
    pub fn generated() {}
}
";
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file("src/lib.rs", SOURCE)
            .build();
        let project = fixture.project_dyn();
        let oid = Oid::hash_object(ObjectType::Blob, SOURCE.as_bytes()).expect("fixture blob OID");
        let db_path = fixture.root().join("canonical-import-reopen.db");
        let mut cold_context = store_context_from_store(
            project.as_ref(),
            AnalyzerStore::open_persistent(&db_path).expect("persistent import store"),
            false,
        );
        let (cold_parses, cold_progress) = parse_progress_counter();
        cold_context.build_tier_access = Arc::new(AnalyzerBuildTierAccess::new_active());
        let cold = TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
            Arc::clone(&project),
            RustAdapter,
            AnalyzerConfig {
                parallelism: Some(1),
                ..AnalyzerConfig::default()
            },
            cold_context,
            Some(cold_progress),
        )
        .expect("cold Rust analyzer");
        assert!(
            cold_parses.load(Ordering::Relaxed) >= 1,
            "the cold producer must parse the Rust source"
        );

        let file = fixture.file("src/lib.rs");
        let cold_state = cold
            .source_snapshot_file_state(&file)
            .expect("cold producer state");
        let cold_rust_facts = cold_state.rust_usage_facts.clone();
        let source_facts = cold_state
            .source_facts
            .as_ref()
            .expect("canonical source facts from the Rust producer");
        let cold_scope = AnalyzerQueryScope::new(&cold);
        let cold_imports = cold.import_info_of(cold_scope.token(), &file);
        drop(cold_scope);

        let expected_raw = [
            "use crate::root::Root as RootAlias;",
            "use crate::root::*;",
            "extern crate ext as ext_alias;",
            "use super::Nested as NestedAlias;",
            "use super::*;",
            "use crate::after::After;",
            "use crate::generated::Generated as GeneratedAlias;",
            "use crate::generated::*;",
        ];
        assert_eq!(cold_imports.len(), expected_raw.len());
        assert_eq!(
            cold_imports
                .iter()
                .map(|import| import.raw_snippet.as_str())
                .collect::<Vec<_>>(),
            expected_raw
        );
        assert!(
            cold_imports
                .iter()
                .all(|import| !import.raw_snippet.contains("local::Local")),
            "local imports remain usage facts, not the generic module import projection"
        );
        assert_eq!(cold_imports, cold_state.imports);
        assert_eq!(source_facts.generic_imports.len(), cold_imports.len());
        assert_eq!(source_facts.imports.len(), 10);
        assert_eq!(
            source_facts.rust_import_contexts.len(),
            7,
            "one context per authoritative import declaration, including the local-only use"
        );
        let context_for = |statement: &str| {
            let import = source_facts
                .imports
                .iter()
                .find(|import| import.statement.contains(statement))
                .unwrap_or_else(|| panic!("missing canonical import {statement}"));
            source_facts
                .rust_import_contexts
                .iter()
                .find(|context| context.declaration == import.declaration)
                .unwrap_or_else(|| panic!("missing Rust import context for {statement}"))
        };
        let root_context = context_for("use crate::root");
        assert_eq!(root_context.owner_module, "");
        assert!(root_context.owner_scope.is_none());
        assert!(root_context.local_scope.is_none());
        let root_declaration = source_facts
            .occurrences
            .occurrence(root_context.declaration);
        assert_eq!(
            root_declaration.range.start_byte,
            SOURCE.find("use crate::root").unwrap()
        );
        assert!(root_declaration.range.end_byte <= SOURCE.len());
        let local_context = context_for("use crate::local::Local");
        assert_eq!(local_context.owner_module, "");
        assert!(local_context.owner_scope.is_none());
        let local_scope = local_context
            .local_scope
            .expect("function-local import has a local scope occurrence");
        let local_scope_range = source_facts.occurrences.occurrence(local_scope).range;
        let local_declaration = source_facts
            .occurrences
            .occurrence(local_context.declaration);
        assert!(local_scope_range.start_byte <= local_declaration.range.start_byte);
        assert!(local_declaration.range.end_byte <= local_scope_range.end_byte);
        assert!(
            SOURCE[local_scope_range.start_byte..local_scope_range.end_byte]
                .contains("local::Local")
        );
        let nested_context = context_for("use super::Nested");
        assert_eq!(nested_context.owner_module, "nested");
        assert!(nested_context.local_scope.is_none());
        let nested_scope = nested_context
            .owner_scope
            .expect("nested import has its module owner scope occurrence");
        let nested_scope_range = source_facts.occurrences.occurrence(nested_scope).range;
        let nested_declaration = source_facts
            .occurrences
            .occurrence(nested_context.declaration);
        assert!(nested_scope_range.start_byte <= nested_declaration.range.start_byte);
        assert!(nested_declaration.range.end_byte <= nested_scope_range.end_byte);
        assert!(
            SOURCE[nested_scope_range.start_byte..nested_scope_range.end_byte].contains("Nested")
        );
        let inner_context = context_for("use crate::inside::Inside");
        assert_eq!(inner_context.owner_module, "inner");
        let inner_owner_scope = inner_context
            .owner_scope
            .expect("function-nested module has an owner scope occurrence");
        let inner_local_scope = inner_context
            .local_scope
            .expect("function-nested module retains its outer local scope occurrence");
        let inner_owner_range = source_facts.occurrences.occurrence(inner_owner_scope).range;
        let inner_local_range = source_facts.occurrences.occurrence(inner_local_scope).range;
        let inner_declaration = source_facts
            .occurrences
            .occurrence(inner_context.declaration);
        assert!(inner_owner_range.start_byte <= inner_declaration.range.start_byte);
        assert!(inner_declaration.range.end_byte <= inner_owner_range.end_byte);
        assert!(inner_local_range.start_byte <= inner_declaration.range.start_byte);
        assert!(inner_declaration.range.end_byte <= inner_local_range.end_byte);
        assert!(
            SOURCE[inner_owner_range.start_byte..inner_owner_range.end_byte].contains("Inside")
        );
        let generated_context = context_for("use crate::generated");
        assert_eq!(generated_context.owner_module, "");
        assert!(generated_context.owner_scope.is_none());
        assert!(generated_context.local_scope.is_none());
        assert!(generated_context.native_scope.is_some());
        for target in &cold_state.rust_usage_facts.import_targets {
            if let Some(source_import_id) = target.source_import_id {
                let source_import = &source_facts.imports[source_import_id.index()];
                let declaration = source_import.declaration;
                assert!(
                    source_facts
                        .rust_import_contexts
                        .iter()
                        .any(|context| context.declaration == declaration),
                    "authoritative Rust target must link to its declaration context"
                );
            }
        }
        assert_eq!(
            source_facts
                .generic_imports
                .iter()
                .map(|id| {
                    source_facts
                        .occurrences
                        .occurrence(source_facts.imports[id.index()].declaration)
                        .provenance
                })
                .collect::<Vec<_>>(),
            vec![
                brokk_bifrost_core::analyzer::source_facts::SourceOccurrenceProvenance::PrimaryNode;
                6
            ]
            .into_iter()
            .chain([
                brokk_bifrost_core::analyzer::source_facts::SourceOccurrenceProvenance::Embedded,
                brokk_bifrost_core::analyzer::source_facts::SourceOccurrenceProvenance::Embedded,
            ])
            .collect::<Vec<_>>(),
            "generic ids retain primary module imports before embedded imports"
        );

        for (ordinal, (import, source_import)) in cold_imports
            .iter()
            .zip(&source_facts.generic_imports)
            .enumerate()
        {
            let source_import = &source_facts.imports[source_import.index()];
            let path = import
                .path
                .as_ref()
                .expect("Rust import has structured path");
            let declaration = source_facts
                .occurrences
                .occurrence(source_import.declaration);
            assert_eq!(
                source_import.import_info(&source_facts.occurrences),
                *import,
                "generic import {ordinal} dereferences its canonical source-import id"
            );
            assert_eq!(
                declaration.range.start_byte, path.declaration_start_byte,
                "import {ordinal} declaration start is source-linked"
            );
            match (
                source_import.alias_occurrence.or(source_import.target),
                import.binder_span,
            ) {
                (Some(binder), Some(expected)) => {
                    let range = source_facts.occurrences.occurrence(binder).range;
                    assert_eq!(
                        (range.start_byte, range.end_byte),
                        (expected.start_byte, expected.end_byte)
                    );
                }
                (None, None) => {}
                other => panic!("import {ordinal} binder mismatch: {other:?}"),
            }
            let actual_scopes = source_import
                .path
                .as_ref()
                .expect("Rust source import has a structured path")
                .lexical_scopes
                .iter()
                .map(|id| {
                    let range = source_facts.occurrences.occurrence(*id).range;
                    (range.start_byte, range.end_byte)
                })
                .collect::<Vec<_>>();
            let expected_scopes = path
                .lexical_scopes
                .iter()
                .map(|scope| (scope.start_byte, scope.end_byte))
                .collect::<Vec<_>>();
            assert_eq!(
                actual_scopes, expected_scopes,
                "import {ordinal} lexical scopes"
            );
            let expected_provenance = if ordinal < 6 {
                brokk_bifrost_core::analyzer::source_facts::SourceOccurrenceProvenance::PrimaryNode
            } else {
                brokk_bifrost_core::analyzer::source_facts::SourceOccurrenceProvenance::Embedded
            };
            assert_eq!(declaration.provenance, expected_provenance);
        }
        let local_index = source_facts
            .imports
            .iter()
            .position(|import| import.statement.contains("local::Local"))
            .expect("local-only import has a canonical source-import row");
        assert!(
            !source_facts
                .generic_imports
                .iter()
                .any(|id| id.index() == local_index),
            "local-only import has no generic projection id"
        );
        assert!(
            cold_state
                .rust_usage_facts
                .import_targets
                .iter()
                .any(|target| target
                    .source_import_id
                    .is_some_and(|id| id.index() == local_index)),
            "local-only import retains its Rust target source-import id"
        );
        for id in source_facts.generic_imports.iter().filter(|id| {
            source_facts
                .occurrences
                .occurrence(source_facts.imports[id.index()].declaration)
                .provenance
                == brokk_bifrost_core::analyzer::source_facts::SourceOccurrenceProvenance::Embedded
        }) {
            let embedded_declaration = source_facts.imports[id.index()].declaration;
            assert!(
                source_facts
                    .rust_import_contexts
                    .iter()
                    .any(|context| context.declaration == embedded_declaration),
                "proven source-preserving import has a Rust context projection"
            );
            assert!(
                cold_state
                    .rust_usage_facts
                    .import_targets
                    .iter()
                    .any(|target| target
                        .source_import_id
                        .is_some_and(|target_id| target_id == *id)),
                "proven source-preserving import has a Rust target projection"
            );
        }
        // Grouped leaves share a declaration identity within either live tree.
        assert_eq!(
            source_facts.imports[source_facts.generic_imports[0].index()].declaration,
            source_facts.imports[source_facts.generic_imports[1].index()].declaration
        );
        assert_eq!(
            source_facts.imports[source_facts.generic_imports[3].index()].declaration,
            source_facts.imports[source_facts.generic_imports[4].index()].declaration
        );
        assert_eq!(
            source_facts.imports[source_facts.generic_imports[6].index()].declaration,
            source_facts.imports[source_facts.generic_imports[7].index()].declaration
        );
        assert!(
            !cold_imports[3]
                .path
                .as_ref()
                .expect("nested import path")
                .lexical_scopes
                .is_empty()
        );
        assert_eq!(
            cold_imports[2]
                .path
                .as_ref()
                .expect("extern crate path")
                .kind,
            Some(brokk_bifrost_core::analyzer::model::StructuredImportPathKind::ExternCrate)
        );

        drop(cold_state);
        drop(cold);
        let mut warm_context = store_context_from_store(
            project.as_ref(),
            AnalyzerStore::open_persistent(&db_path).expect("reopen persistent import store"),
            false,
        );
        let (warm_parses, warm_progress) = parse_progress_counter();
        warm_context.build_tier_access = Arc::new(AnalyzerBuildTierAccess::new_active());
        let mut warm = TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
            Arc::clone(&project),
            RustAdapter,
            AnalyzerConfig {
                parallelism: Some(1),
                ..AnalyzerConfig::default()
            },
            warm_context,
            Some(warm_progress),
        )
        .expect("warm Rust analyzer");
        assert_eq!(warm_parses.load(Ordering::Relaxed), 0);
        warm.source_snapshot_file_states = Arc::new(map_with_capacity(0));
        warm.reset_prepared_syntax_parse_counts_for_test();
        let warm_scope = AnalyzerQueryScope::new(&warm);
        let warm_imports = warm.import_info_of(warm_scope.token(), &file);
        drop(warm_scope);
        assert_eq!(warm_imports, cold_imports);
        assert_eq!(
            warm.store_context
                .store
                .rust_usage_facts(&brokk_bifrost_core::gitblob::BlobKey::unvaried(oid, "rust"))
                .expect("reopened Rust usage facts"),
            cold_rust_facts,
            "reopened context ids and owner semantics remain source-identical"
        );
        assert_eq!(warm.prepared_syntax_parse_count_for_test(&file), 0);
        assert_eq!(warm_parses.load(Ordering::Relaxed), 0);
    }

    #[brokk_bifrost_test_macros::hardwon(
        "ed7fac57fe6b: hydrated cache authority rejected an explicit rename counterfactual source"
    )]
    #[test]
    fn explicit_counterfactual_source_supersedes_hydrated_missing_or_incomplete_content() {
        let original = "pub fn target() {}\npub fn caller() { target(); }\n";
        let hypothetical = "pub fn renamed() {}\npub fn caller() { renamed(); }\n";
        for damage in ["missing", "incomplete"] {
            let fixture = InlineTestProject::with_language(Language::Rust)
                .file("src/lib.rs", original)
                .build();
            let db = fixture.root().join("override-precedence.db");
            let store = Arc::new(AnalyzerStore::open_persistent(&db).unwrap());
            let project = fixture.project_dyn();
            let context = revision_image_store_context(project.as_ref(), Arc::clone(&store));
            let disk = TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
                project,
                RustAdapter,
                AnalyzerConfig::default(),
                context,
                None,
            )
            .unwrap();
            let file = fixture.file("src/lib.rs");
            let overlay = Arc::new(brokk_bifrost_core::analyzer::project::OverlayProject::new(
                fixture.project_dyn(),
            ));
            assert!(overlay.set(file.abs_path(), original.to_owned()));
            let mut analyzer = disk.clone_with_project(Arc::new(overlay.snapshot()));
            analyzer.source_snapshot_file_states = Arc::new(map_with_capacity(0));
            let state = analyzer.fetch_file_state(&file).unwrap();
            assert!(
                state.source_facts.is_none(),
                "fixture must use hydrated display state"
            );
            let snapshots = analyzer.selected_workspace_snapshots();
            let cancellation = CancellationToken::default();
            let original_oid = Oid::hash_object(ObjectType::Blob, original.as_bytes()).unwrap();
            let conn = brokk_bifrost_core::cache_db::open_unified_connection(&db).unwrap();
            let original_blob: i64 = conn
                .query_row(
                    "SELECT id FROM blobs WHERE blob_oid=?1 AND lang='rust'",
                    [original_oid.to_string()],
                    |row| row.get(0),
                )
                .unwrap();
            match damage {
                "missing" => {
                    // Withdraw native publication, retaining the parsed blob and
                    // its live crate ownership. Those owners prohibit blob deletion.
                    assert_eq!(
                        conn.execute(
                            "DELETE FROM resolution_fragment_interiors WHERE blob_id=?1",
                            [original_blob],
                        )
                        .unwrap(),
                        1
                    );
                    assert!(!conn.query_row(
                    "SELECT EXISTS(SELECT 1 FROM resolution_fragment_interiors WHERE blob_id=?1)",
                    [original_blob], |row| row.get::<_, bool>(0),
                ).unwrap());
                    assert!(
                        conn.query_row(
                            "SELECT EXISTS(SELECT 1 FROM blobs WHERE id=?1)",
                            [original_blob],
                            |row| row.get::<_, bool>(0),
                        )
                        .unwrap()
                    );
                }
                "incomplete" => {
                    assert_eq!(
                        conn.execute(
                            "UPDATE blob_meta SET is_complete=0 WHERE blob_id=?1",
                            [original_blob],
                        )
                        .unwrap(),
                        1
                    );
                }
                _ => unreachable!(),
            };

            assert!(
                matches!(
                    analyzer
                        .selected_rust_resolution_overlay_inputs(snapshots.as_ref(), &cancellation)
                        .unwrap(),
                    SelectedResolutionOverlayInputsOutcome::Unavailable(_)
                ),
                "selected hydrated {damage} content remains unavailable without an override"
            );
            let overridden = HashSet::from_iter([&file]);
            let SelectedResolutionOverlayInputsOutcome::Ready {
                masks,
                content_mounts,
            } = analyzer
                .selected_rust_resolution_overlay_inputs_excluding(
                    snapshots.as_ref(),
                    &overridden,
                    &cancellation,
                )
                .unwrap()
            else {
                panic!(
                    "an explicit supplied source supersedes the covered hydrated {damage} input"
                );
            };
            assert!(masks.is_empty() && content_mounts.is_empty());
            let file_versions = || {
                conn.prepare("SELECT file_version_id,blob_oid,projection_digest,valid_from,valid_until FROM workspace_file_versions ORDER BY file_version_id")
            .unwrap().query_map([],|row|Ok((row.get::<_,i64>(0)?,row.get::<_,String>(1)?,row.get::<_,Option<String>>(2)?,
                row.get::<_,i64>(3)?,row.get::<_,Option<i64>>(4)?))).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap()
            };
            let before = file_versions();
            // The hypothetical world goes first; it cannot depend on original-world repair.
            for source in [hypothetical, original] {
                let outcome = analyzer
                    .selected_rust_counterfactual_publication(
                        &snapshots["rust"],
                        &file,
                        source.to_owned(),
                        &cancellation,
                    )
                    .unwrap();
                let ResolutionContentPublicationOutcome::Ready(content) = outcome else {
                    panic!("supplied {damage} counterfactual source: {outcome:?}");
                };
                let witness = content.into_parts().0;
                let oid = Oid::hash_object(ObjectType::Blob, source.as_bytes()).unwrap();
                assert_eq!(witness.blob_oid(), oid);
                let digest =
                    brokk_bifrost_core::analyzer::canonical_hash::sha256_bytes(original.as_bytes());
                let request = SelectedResolutionContentMountRequest::new(
                    witness,
                    WorkspaceFileRow {
                        rel_path: "src/lib.rs".to_owned(),
                        blob_oid: oid,
                    },
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                )
                .with_counterfactual_base_content_digest(digest);
                assert!(
                    matches!(request.overlay_authority(),Some(crate::analyzer::store::resolution_selection::SelectedResolutionOverlayAuthority::Counterfactual {base_content_digest}) if *base_content_digest==digest)
                );
                assert_eq!(
                    file_versions(),
                    before,
                    "counterfactual publication never changes live file versions"
                );
            }
        }
    }
}
