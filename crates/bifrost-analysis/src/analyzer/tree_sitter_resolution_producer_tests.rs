use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use git2::{ObjectType, Oid};

use crate::analyzer::go::GoAdapter;
use crate::analyzer::java::JavaAdapter;
use crate::analyzer::rust::RustAdapter;
use crate::analyzer::store::resolution_selection::{
    SelectedResolutionLanguage, SelectedResolutionMountInventoryOutcome,
};
use crate::analyzer::{
    AnalyzerBuildTierAccess, AnalyzerConfig, AnalyzerQueryScope, InformationTier, Language,
};
use crate::inline_project::InlineTestProject;

use super::*;

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
    let overlay = Arc::new(crate::OverlayProject::new(fixture.project_dyn()));
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
        .selected_rust_resolution_overlay_inputs(snapshots.as_ref(), &CancellationToken::default())
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
        let oid = Oid::hash_object(ObjectType::Blob, source.as_bytes()).expect("fixture blob OID");
        let persisted_usage = analyzer
            .store_context
            .store
            .rust_usage_facts(oid, "rust")
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

fn declaration_names(analyzer: &TreeSitterAnalyzer<JavaAdapter>) -> BTreeSet<String> {
    analyzer
        .get_all_declarations()
        .into_iter()
        .map(|unit| unit.fq_name())
        .collect()
}

fn parse_progress_counter() -> (Arc<AtomicUsize>, BuildProgress) {
    let count = Arc::new(AtomicUsize::new(0));
    let progress_count = Arc::clone(&count);
    let progress: BuildProgress = Arc::new(move |event| {
        if event.phase == BuildProgressPhase::Parse {
            progress_count.fetch_add(1, Ordering::Relaxed);
        }
    });
    (count, progress)
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
        6,
        "one context per primary import declaration, including the local-only use"
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
        SOURCE[local_scope_range.start_byte..local_scope_range.end_byte].contains("local::Local")
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
    assert!(SOURCE[nested_scope_range.start_byte..nested_scope_range.end_byte].contains("Nested"));
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
    assert!(SOURCE[inner_owner_range.start_byte..inner_owner_range.end_byte].contains("Inside"));
    for target in &cold_state.rust_usage_facts.import_targets {
        if let Some(source_import_id) = target.source_import_id {
            let source_import = &source_facts.imports[source_import_id.index()];
            let declaration = source_import.declaration;
            if source_facts
                .occurrences
                .occurrence(declaration)
                .provenance
                == brokk_bifrost_core::analyzer::source_facts::SourceOccurrenceProvenance::PrimaryNode
            {
                assert!(
                    source_facts
                        .rust_import_contexts
                        .iter()
                        .any(|context| context.declaration == declaration),
                    "primary Rust target must link to its declaration context"
                );
            }
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
            !source_facts
                .rust_import_contexts
                .iter()
                .any(|context| context.declaration == embedded_declaration),
            "embedded generic import has no Rust context projection"
        );
        assert!(
            !cold_state
                .rust_usage_facts
                .import_targets
                .iter()
                .any(|target| target
                    .source_import_id
                    .is_some_and(|target_id| target_id == *id)),
            "embedded generic import has no Rust target projection"
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
            .rust_usage_facts(oid, "rust")
            .expect("reopened Rust usage facts"),
        cold_rust_facts,
        "reopened context ids and owner semantics remain source-identical"
    );
    assert_eq!(warm.prepared_syntax_parse_count_for_test(&file), 0);
    assert_eq!(warm_parses.load(Ordering::Relaxed), 0);
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct JavaInteriorSnapshot {
    blob_oid: Oid,
    interior_digest: [u8; 32],
    semantic_sites: u64,
    path_endpoint_headers: u64,
}

fn java_interior_snapshots(
    analyzer: &TreeSitterAnalyzer<JavaAdapter>,
) -> BTreeMap<String, JavaInteriorSnapshot> {
    let snapshots = analyzer.selected_workspace_snapshots();
    let languages = [SelectedResolutionLanguage::new("java", Language::Java)];
    let ready = match analyzer
        .store_context
        .store
        .open_selected_resolution_mount_inventory(
            &analyzer.store_context.workspace_id,
            snapshots.as_ref(),
            &languages,
            &[],
            &CancellationToken::default(),
        )
        .expect("open persisted Java resolution inventory")
    {
        SelectedResolutionMountInventoryOutcome::Ready(ready) => ready,
        SelectedResolutionMountInventoryOutcome::Unavailable(reason) => {
            panic!("published Java resolution inventory unavailable: {reason:?}")
        }
        SelectedResolutionMountInventoryOutcome::Cancelled => {
            panic!("uncancelled Java resolution inventory was cancelled")
        }
        SelectedResolutionMountInventoryOutcome::Stale(reason) => {
            panic!("newly captured Java resolution inventory was stale: {reason:?}")
        }
    };
    ready
        .mounts()
        .unwrap()
        .iter()
        .map(|mount| {
            (
                mount.persisted_relative_path().to_owned(),
                JavaInteriorSnapshot {
                    blob_oid: mount.blob_oid(),
                    interior_digest: mount.interior_digest(),
                    semantic_sites: mount.manifest_counts().semantic_sites(),
                    path_endpoint_headers: mount.manifest_counts().path_endpoint_headers(),
                },
            )
        })
        .collect()
}

#[test]
fn producer_analyzes_each_cold_file_once_is_warm_zero_and_file_local_after_change() {
    const MODEL: &str = "package demo; class Model { int value; }\n";
    const CHANGED_MODEL: &str = "package demo; class Model { int value; } class Added {}\n";
    const HELPER: &str = "package demo; class Helper {}\n";
    let fixture = InlineTestProject::with_language(Language::Java)
        .file("src/Model.java", MODEL)
        .file("src/Helper.java", HELPER)
        .build();
    let project = fixture.project_dyn();
    let mut cold_context = ephemeral_store_context(project.as_ref()).expect("ephemeral context");
    let store = Arc::clone(&cold_context.store);
    let cold_tiers = Arc::new(AnalyzerBuildTierAccess::new_active());
    cold_context.build_tier_access = Arc::clone(&cold_tiers);
    let (cold_parses, cold_progress) = parse_progress_counter();
    let cold = TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
        Arc::clone(&project),
        JavaAdapter,
        AnalyzerConfig {
            parallelism: Some(1),
            ..AnalyzerConfig::default()
        },
        cold_context,
        Some(cold_progress),
    )
    .expect("cold analyzer");
    assert_eq!(cold_parses.load(Ordering::Relaxed), 2);
    assert_eq!(cold.state.persistence_stats.committed_blobs, 2);
    assert_eq!(cold.state.persistence_stats.committed_fragments, 2);
    assert_eq!(cold_tiers.tier_access_count(InformationTier::Syntax), 2);
    assert_eq!(cold_tiers.tier_access_count(InformationTier::UsageGraph), 0);
    let cold_names = declaration_names(&cold);
    let cold_interiors = java_interior_snapshots(&cold);
    assert_eq!(
        cold_interiors
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        vec!["src/Helper.java", "src/Model.java"]
    );
    assert_eq!(
        cold_interiors["src/Helper.java"].blob_oid,
        Oid::hash_object(ObjectType::Blob, HELPER.as_bytes()).expect("helper OID")
    );
    assert_eq!(
        cold_interiors["src/Model.java"].blob_oid,
        Oid::hash_object(ObjectType::Blob, MODEL.as_bytes()).expect("model OID")
    );
    for interior in cold_interiors.values() {
        assert!(interior.semantic_sites > 0);
        assert!(interior.path_endpoint_headers > 0);
    }
    let cold_transactions = store.parsed_blob_transaction_starts_for_test();

    let mut warm_context = cold.store_context.clone();
    let warm_tiers = Arc::new(AnalyzerBuildTierAccess::new_active());
    warm_context.build_tier_access = Arc::clone(&warm_tiers);
    let (warm_parses, warm_progress) = parse_progress_counter();
    let warm = TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
        Arc::clone(&project),
        JavaAdapter,
        AnalyzerConfig {
            parallelism: Some(1),
            ..AnalyzerConfig::default()
        },
        warm_context,
        Some(warm_progress),
    )
    .expect("warm analyzer");
    assert_eq!(warm_parses.load(Ordering::Relaxed), 0);
    assert_eq!(warm.state.persistence_stats, PersistBatchStats::default());
    assert_eq!(
        store.parsed_blob_transaction_starts_for_test(),
        cold_transactions
    );
    assert_eq!(declaration_names(&warm), cold_names);
    assert_eq!(java_interior_snapshots(&warm), cold_interiors);
    assert_eq!(warm_tiers.tier_access_count(InformationTier::Syntax), 0);
    assert_eq!(warm_tiers.tier_access_count(InformationTier::UsageGraph), 0);

    fixture
        .file("src/Model.java")
        .write(CHANGED_MODEL)
        .expect("update Java source");
    let mut incremental_context = warm.store_context.clone();
    let incremental_tiers = Arc::new(AnalyzerBuildTierAccess::new_active());
    incremental_context.build_tier_access = Arc::clone(&incremental_tiers);
    let (incremental_parses, incremental_progress) = parse_progress_counter();
    let incremental = TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
        Arc::clone(&project),
        JavaAdapter,
        AnalyzerConfig {
            parallelism: Some(1),
            ..AnalyzerConfig::default()
        },
        incremental_context,
        Some(incremental_progress),
    )
    .expect("incremental analyzer");
    assert_eq!(incremental_parses.load(Ordering::Relaxed), 1);
    assert_eq!(incremental.state.persistence_stats.committed_blobs, 1);
    assert_eq!(incremental.state.persistence_stats.committed_fragments, 1);
    assert_eq!(
        store.parsed_blob_transaction_starts_for_test(),
        cold_transactions + 1
    );
    assert_eq!(
        incremental_tiers.tier_access_count(InformationTier::Syntax),
        1
    );
    assert_eq!(
        incremental_tiers.tier_access_count(InformationTier::UsageGraph),
        0
    );
    let incremental_interiors = java_interior_snapshots(&incremental);
    assert_eq!(incremental_interiors.len(), 2);
    assert_eq!(
        incremental_interiors["src/Helper.java"],
        cold_interiors["src/Helper.java"]
    );
    let changed = &incremental_interiors["src/Model.java"];
    assert_eq!(
        changed.blob_oid,
        Oid::hash_object(ObjectType::Blob, CHANGED_MODEL.as_bytes()).expect("changed model OID")
    );
    assert_ne!(
        changed.interior_digest,
        cold_interiors["src/Model.java"].interior_digest
    );
    assert!(
        changed.semantic_sites > cold_interiors["src/Model.java"].semantic_sites,
        "the added top-level type must add a declaration site"
    );
    assert!(
        changed.path_endpoint_headers > cold_interiors["src/Model.java"].path_endpoint_headers,
        "the added top-level type must add lexical and root-export paths"
    );

    let fresh = TreeSitterAnalyzer::new(fixture.project_dyn(), JavaAdapter);
    assert_eq!(declaration_names(&incremental), declaration_names(&fresh));
}

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
        let overlay = Arc::new(crate::OverlayProject::new(fixture.project_dyn()));
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
            panic!("an explicit supplied source supersedes the covered hydrated {damage} input");
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
            let digest = crate::analyzer::canonical_hash::sha256_bytes(original.as_bytes());
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

fn assert_native_overlay_publication<A: LanguageAdapter>(
    adapter: A,
    path: &str,
    disk_source: &str,
    overlay_source: &str,
    reference_name: &str,
) {
    use crate::analyzer::resolution::{
        LoweredSemanticRole, ResolutionCompletion, SelectedSemanticLocator,
    };
    use crate::analyzer::store::resolution_operation::{
        SelectedResolutionContextMetrics, SelectedResolutionLocated,
        SelectedResolutionOperationInput, SelectedResolutionOperationOpenOutcome,
        SelectedResolutionOperationOutcome,
    };
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionIdentifierRole;
    let language = adapter.language();
    let storage = language.config_label();
    let fixture = InlineTestProject::with_language(language)
        .file(path, disk_source)
        .build();
    let disk = TreeSitterAnalyzer::new(fixture.project_dyn(), adapter);
    let file = fixture.file(path);
    let overlay = Arc::new(crate::OverlayProject::new(fixture.project_dyn()));
    assert!(overlay.set(file.abs_path(), overlay_source.to_owned()));
    let mut analyzer = disk.clone_with_project(Arc::new(overlay.snapshot()));
    let parsed = analyzer
        .fetch_file_state(&file)
        .expect("live parsed content");
    let facts = parsed.resolution_facts.clone();
    let name = facts
        .names
        .iter()
        .find(|name| name.spelling == reference_name)
        .unwrap()
        .id;
    let site = facts
        .identifiers
        .iter()
        .find(|identifier| {
            identifier.name == name && identifier.role == ResolutionIdentifierRole::Reference
        })
        .unwrap()
        .site;
    // Exercise publication after eviction, not just the in-memory producer.
    analyzer.source_snapshot_file_states = Arc::new(map_with_capacity(0));
    analyzer.query_file_state_snapshot.store(None);
    analyzer.transient_file_states.lock().unwrap().clear();
    analyzer
        .query_read_cache_lock()
        .file_states
        .write()
        .unwrap()
        .clear();
    let hydrated = analyzer
        .fetch_file_state(&file)
        .expect("hydrated display rows");
    assert!(!hydrated.declarations.is_empty());
    assert!(hydrated.source_facts.is_none());
    let snapshots = analyzer.selected_workspace_snapshots();
    let cancellation = CancellationToken::new();
    let SelectedResolutionOverlayInputsOutcome::Ready {
        masks,
        content_mounts,
    } = analyzer
        .selected_resolution_overlay_inputs(snapshots.as_ref(), &cancellation)
        .unwrap()
    else {
        panic!("hydrated {language:?} overlay publication must be ready");
    };
    assert_eq!(masks.len(), 1);
    assert_eq!(content_mounts.len(), 1);
    assert_eq!(content_mounts[0].persisted_relative_path(), path);
    assert_eq!(content_mounts[0].publication().owner(), &snapshots[storage]);
    assert_eq!(
        content_mounts[0].publication().blob_oid(),
        Oid::hash_object(ObjectType::Blob, overlay_source.as_bytes()).unwrap()
    );
    assert_eq!(
        std::fs::read_to_string(file.abs_path()).unwrap(),
        disk_source
    );
    let languages = [SelectedResolutionLanguage::new(storage, language)];
    let input = SelectedResolutionOperationInput::new(
        analyzer.project(),
        analyzer.workspace_id(),
        snapshots.as_ref(),
        &languages,
        &masks,
    )
    .with_content_mounts(content_mounts);
    let SelectedResolutionOperationOpenOutcome::Ready(operation) = analyzer
        .analyzer_store()
        .open_selected_resolution_operation(input, &cancellation)
        .unwrap()
    else {
        panic!("published {language:?} overlay operation must be ready");
    };
    let context = operation
        .empty_contexts(&ResolutionCompletion::Complete)
        .unwrap();
    let result = operation
        .resolve_reference(
            context,
            &SelectedSemanticLocator::new(storage, path, site, LoweredSemanticRole::Reference),
            &cancellation,
            &mut SelectedResolutionContextMetrics,
        )
        .unwrap();
    let SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(answer)) =
        result
    else {
        panic!("overlay reference must remain natively located");
    };
    assert_eq!(answer.binding().targets().len(), 1, "{answer:?}");
    cancellation.cancel();
    assert!(matches!(
        analyzer
            .selected_resolution_overlay_inputs(snapshots.as_ref(), &cancellation)
            .unwrap(),
        SelectedResolutionOverlayInputsOutcome::Cancelled
    ));
}

#[test]
fn hydrated_java_overlays_publish_same_and_changed_native_content() {
    let original =
        "class Sample { static void original() {} static void caller() { original(); } }";
    assert_native_overlay_publication(JavaAdapter, "Sample.java", original, original, "original");
    assert_native_overlay_publication(
        JavaAdapter,
        "Sample.java",
        original,
        "class Sample { static void changed() {} static void caller() { changed(); } }",
        "changed",
    );
}

#[test]
fn hydrated_go_overlays_publish_same_and_changed_native_content() {
    use crate::analyzer::go::GoAdapter;
    let original = "package sample; func original() {}\nfunc caller() { original() }\n";
    assert_native_overlay_publication(GoAdapter, "sample.go", original, original, "original");
    assert_native_overlay_publication(
        GoAdapter,
        "sample.go",
        original,
        "package sample; func changed() {}\nfunc caller() { changed() }\n",
        "changed",
    );
}

#[test]
fn java_overlay_packages_follow_selected_caller_and_provider_content() {
    use crate::analyzer::resolution::{LoweredSemanticRole, SelectedSemanticLocator};
    use crate::analyzer::store::resolution_operation::JavaImportContext;
    use crate::analyzer::store::resolution_operation::{
        SelectedResolutionContextMetrics, SelectedResolutionLocated,
        SelectedResolutionOperationInput, SelectedResolutionOperationOpenOutcome,
        SelectedResolutionOperationOutcome,
    };
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionIdentifierRole;

    const OLD_CALLER: &str = "package oldpkg; class Use { Target field; }";
    const NEW_CALLER: &str = "package newpkg; class Use { Target field; }";
    const OLD_PROVIDER: &str = "package oldpkg; class Target {}";
    const NEW_PROVIDER: &str = "package newpkg; class Target {}";
    for (caller, provider, provider_overlay, expected) in [
        (NEW_CALLER, OLD_PROVIDER, None, 0),
        (NEW_CALLER, NEW_PROVIDER, None, 1),
        (OLD_CALLER, OLD_PROVIDER, Some(NEW_PROVIDER), 0),
        (NEW_CALLER, OLD_PROVIDER, Some(NEW_PROVIDER), 1),
    ] {
        let fixture = InlineTestProject::with_language(Language::Java)
            .file("Use.java", OLD_CALLER)
            .file("Target.java", provider)
            .build();
        let disk = TreeSitterAnalyzer::new(fixture.project_dyn(), JavaAdapter);
        let overlay = Arc::new(crate::OverlayProject::new(fixture.project_dyn()));
        assert!(overlay.set(fixture.file("Use.java").abs_path(), caller.to_owned()));
        if let Some(source) = provider_overlay {
            assert!(overlay.set(fixture.file("Target.java").abs_path(), source.to_owned()));
        }
        let analyzer = disk.clone_with_project(Arc::new(overlay.snapshot()));
        let caller_state = analyzer
            .fetch_file_state(&fixture.file("Use.java"))
            .unwrap();
        analyzer
            .fetch_file_state(&fixture.file("Target.java"))
            .unwrap();
        let facts = &caller_state.resolution_facts;
        let name = facts
            .names
            .iter()
            .find(|name| name.spelling == "Target")
            .unwrap()
            .id;
        let site = facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.name == name && identifier.role == ResolutionIdentifierRole::Reference
            })
            .unwrap()
            .site;
        let cancellation = CancellationToken::new();
        let snapshots = analyzer.selected_workspace_snapshots();
        let SelectedResolutionOverlayInputsOutcome::Ready {
            masks,
            content_mounts,
        } = analyzer
            .selected_resolution_overlay_inputs(snapshots.as_ref(), &cancellation)
            .unwrap()
        else {
            panic!("Java source overlay publication must be ready");
        };
        let languages = [SelectedResolutionLanguage::new("java", Language::Java)];
        let input = SelectedResolutionOperationInput::new(
            analyzer.project(),
            analyzer.workspace_id(),
            snapshots.as_ref(),
            &languages,
            &masks,
        )
        .with_content_mounts(content_mounts);
        let SelectedResolutionOperationOpenOutcome::Ready(operation) = analyzer
            .analyzer_store()
            .open_selected_resolution_operation(input, &cancellation)
            .unwrap()
        else {
            panic!("Java overlay operation must open");
        };
        let JavaImportContext::Ready { context, .. } = operation
            .java_import_context("Use.java", &cancellation)
            .unwrap()
        else {
            panic!("selected Java overlay packages must compose");
        };
        let result = operation
            .resolve_reference(
                *context,
                &SelectedSemanticLocator::new(
                    "java",
                    "Use.java",
                    site,
                    LoweredSemanticRole::Reference,
                ),
                &cancellation,
                &mut SelectedResolutionContextMetrics,
            )
            .unwrap();
        let SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(answer)) =
            result
        else {
            panic!("Java overlay type reference must be located");
        };
        assert_eq!(
            answer.binding().targets().len(),
            expected,
            "caller={caller:?}, provider={provider:?}, provider_overlay={provider_overlay:?}, answer={answer:?}"
        );
        assert_eq!(
            std::fs::read_to_string(fixture.file("Use.java").abs_path()).unwrap(),
            OLD_CALLER
        );
        assert_eq!(
            std::fs::read_to_string(fixture.file("Target.java").abs_path()).unwrap(),
            provider
        );
    }
}

fn assert_native_unit_projection<A: LanguageAdapter>(
    fixture: &crate::inline_project::BuiltInlineTestProject,
    adapter: A,
    path: &str,
    source: &str,
    after_open: impl FnOnce(),
) {
    use crate::analyzer::resolution::{
        LoweredSemanticRole, ResolutionCompletion, SelectedSemanticLocator,
    };
    use crate::analyzer::store::resolution_operation::{
        SelectedNativeDefinition, SelectedNativeDefinitions, SelectedResolutionContextMetrics,
        SelectedResolutionLocated, SelectedResolutionOperationInput,
        SelectedResolutionOperationOpenOutcome, SelectedResolutionOperationOutcome,
    };
    use crate::analyzer::usages::get_definition::BoundedResolution;
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionIdentifierRole;
    use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget;

    let file = fixture.file(path);
    let language = adapter.language();
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&adapter.parser_language_for_file(&file))
        .unwrap();
    let tree = parser.parse(source, None).unwrap();
    let parsed = adapter.parse_file(&file, source, &tree);
    let expected = parsed
        .declarations()
        .iter()
        .find(|unit| unit.terminal_name() == "target")
        .unwrap()
        .clone();
    let facts = &parsed.resolution_facts;
    let name = facts
        .names
        .iter()
        .find(|name| name.spelling == "target")
        .unwrap()
        .id;
    let site = facts
        .identifiers
        .iter()
        .find(|identifier| {
            identifier.name == name && identifier.role == ResolutionIdentifierRole::Reference
        })
        .unwrap()
        .site;
    let analyzer = TreeSitterAnalyzer::new(fixture.project_dyn(), adapter);
    let snapshots = analyzer.selected_workspace_snapshots();
    let languages = [SelectedResolutionLanguage::new(
        language.config_label(),
        language,
    )];
    let cancellation = CancellationToken::new();
    let input = SelectedResolutionOperationInput::new(
        analyzer.project(),
        analyzer.workspace_id(),
        snapshots.as_ref(),
        &languages,
        &[],
    );
    let SelectedResolutionOperationOpenOutcome::Ready(operation) = analyzer
        .analyzer_store()
        .open_selected_resolution_operation(input, &cancellation)
        .unwrap()
    else {
        panic!("ordinary native operation must open");
    };
    let context = operation
        .empty_contexts(&ResolutionCompletion::Complete)
        .unwrap();
    after_open();
    let result = operation
        .resolve_native_reference_units_bounded(
            context,
            &SelectedSemanticLocator::new(
                language.config_label(),
                path,
                site,
                LoweredSemanticRole::Reference,
            ),
            ReceiverAnalysisBudget::default(),
            &cancellation,
            &mut SelectedResolutionContextMetrics,
        )
        .unwrap();
    let BoundedResolution::Complete {
        value: result,
        work,
    } = result
    else {
        panic!("ordinary native projection must fit the default budget");
    };
    assert!(work.scope_nodes > 0);
    let SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(answer)) =
        result
    else {
        panic!("native reference and projection must publish together");
    };
    assert_eq!(answer.answer.binding().targets().len(), 1);
    let SelectedNativeDefinitions::Ready(units) = answer.definitions else {
        panic!("ordinary declaration must project to its parser unit");
    };
    assert_eq!(
        units,
        vec![(
            answer.answer.binding().targets()[0],
            SelectedNativeDefinition::Unit(expected)
        )]
    );
    for (budget, cancelled) in [
        (ReceiverAnalysisBudget::tiny(), false),
        (ReceiverAnalysisBudget::default(), true),
    ] {
        let token = CancellationToken::new();
        let input = SelectedResolutionOperationInput::new(
            analyzer.project(),
            analyzer.workspace_id(),
            snapshots.as_ref(),
            &languages,
            &[],
        );
        let SelectedResolutionOperationOpenOutcome::Ready(operation) = analyzer
            .analyzer_store()
            .open_selected_resolution_operation(input, &token)
            .unwrap()
        else {
            panic!("retry must open before stopping");
        };
        let context = operation
            .empty_contexts(&ResolutionCompletion::Complete)
            .unwrap();
        if cancelled {
            token.cancel();
        }
        let stopped = operation
            .resolve_native_reference_units_bounded(
                context,
                &SelectedSemanticLocator::new(
                    language.config_label(),
                    path,
                    site,
                    LoweredSemanticRole::Reference,
                ),
                budget,
                &token,
                &mut SelectedResolutionContextMetrics,
            )
            .unwrap();
        if cancelled {
            assert!(matches!(stopped, BoundedResolution::Cancelled { .. }));
        } else {
            assert!(matches!(stopped, BoundedResolution::Exceeded { .. }));
        }
    }
}

#[test]
fn java_native_definition_projection_matches_parser_identity() {
    let source = "package example; class Sample { static void target() {} static void caller() { target(); } }";
    let fixture = InlineTestProject::with_language(Language::Java)
        .file("Sample.java", source)
        .build();
    assert_native_unit_projection(&fixture, JavaAdapter, "Sample.java", source, || {});
}

#[test]
fn go_native_definition_projection_uses_selected_package_anchor_after_disk_change() {
    let source = "package sample; func target() {}\nfunc caller() { target() }\n";
    let fixture = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.com/original\n")
        .file("sample.go", source)
        .build();
    assert_native_unit_projection(
        &fixture,
        crate::analyzer::go::GoAdapter,
        "sample.go",
        source,
        || {
            std::fs::write(
                fixture.file("go.mod").abs_path(),
                "module example.com/changed\n",
            )
            .unwrap();
        },
    );
}

fn native_type_projection<A: LanguageAdapter>(
    fixture: &crate::inline_project::BuiltInlineTestProject,
    adapter: A,
    path: &str,
    source: &str,
) -> crate::analyzer::store::resolution_operation::SelectedNativeReferenceTypes {
    use crate::analyzer::resolution::{ResolutionCompletion, SelectedSemanticLocator};
    use crate::analyzer::store::resolution_operation::{
        SelectedResolutionContextMetrics, SelectedResolutionLocated,
        SelectedResolutionOperationInput, SelectedResolutionOperationOpenOutcome,
        SelectedResolutionOperationOutcome,
    };
    use crate::analyzer::usages::get_definition::BoundedResolution;
    use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget;
    let language = adapter.language();
    let analyzer = TreeSitterAnalyzer::new(fixture.project_dyn(), adapter);
    let snapshots = analyzer.selected_workspace_snapshots();
    let languages = [SelectedResolutionLanguage::new(
        language.config_label(),
        language,
    )];
    let cancellation = CancellationToken::new();
    let input = SelectedResolutionOperationInput::new(
        analyzer.project(),
        analyzer.workspace_id(),
        snapshots.as_ref(),
        &languages,
        &[],
    );
    let SelectedResolutionOperationOpenOutcome::Ready(operation) = analyzer
        .analyzer_store()
        .open_selected_resolution_operation(input, &cancellation)
        .unwrap()
    else {
        panic!("selected type fixture must open")
    };
    let context = operation
        .empty_contexts(&ResolutionCompletion::Complete)
        .unwrap();
    let start = source.rfind("target").expect("fixture reference");
    let result = operation
        .resolve_native_reference_types_bounded(
            context,
            &SelectedSemanticLocator::for_reference_range(
                language.config_label(),
                path,
                start,
                start + "target".len(),
            ),
            ReceiverAnalysisBudget::default(),
            &cancellation,
            &mut SelectedResolutionContextMetrics,
        )
        .unwrap();
    let BoundedResolution::Complete {
        value: SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(answer)),
        work,
    } = result
    else {
        panic!("selected type projection must finish")
    };
    assert!(work.scope_nodes > 0);
    answer
}

#[test]
fn native_java_types_project_intrinsic_descriptors_from_selected_rows() {
    use crate::analyzer::store::resolution_operation::SelectedNativeTypes;
    let java = "class Use { int f(int target) { return target; } }";
    let java_fixture = InlineTestProject::with_language(Language::Java)
        .file("Use.java", java)
        .build();
    let answer = native_type_projection(&java_fixture, JavaAdapter, "Use.java", java);
    {
        let SelectedNativeTypes::Ready { nominal, intrinsic } = answer.types else {
            panic!("primitive type must project without a parser unit");
        };
        assert!(nominal.is_empty());
        assert_eq!(
            intrinsic.len(),
            1,
            "{:?}: {:?}",
            answer.named_reasons,
            answer.answer
        );
        assert_eq!(intrinsic[0].spelling(), "int");
        assert!(answer.answer.projected_frontiers().iter().any(|frontier| {
            frontier
                .possible_values()
                .iter()
                .any(|value| value.ty().identity() == intrinsic[0].identity())
        }));
    }
}

#[test]
fn native_go_type_without_universe_context_preserves_bound_parameter_and_incomplete_type() {
    use crate::analyzer::resolution::ResolutionCompletion;
    use crate::analyzer::store::resolution_operation::SelectedNativeTypes;
    let source = "package sample; func f(target int) int { return target }";
    let fixture = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.test/types\n\ngo 1.22\n")
        .file("source.go", source)
        .build();
    let answer = native_type_projection(&fixture, GoAdapter, "source.go", source);
    assert_eq!(
        answer.answer.binding().targets().len(),
        1,
        "{:?}",
        answer.answer
    );
    assert_eq!(
        answer.answer.binding().completion(),
        &ResolutionCompletion::Complete
    );
    assert!(matches!(
        answer.answer.completion(),
        ResolutionCompletion::Incomplete(_)
    ));
    let SelectedNativeTypes::Ready { nominal, intrinsic } = answer.types else {
        panic!("empty incomplete frontier must retain its completion");
    };
    assert!(nominal.is_empty() && intrinsic.is_empty());
}

#[test]
fn native_java_and_go_types_project_nominal_source_identities() {
    use crate::analyzer::store::resolution_operation::{
        SelectedNativeDefinition, SelectedNativeTypes,
    };
    let java = "class Target {} class Use { Target f(Target target) { return target; } }";
    let java_fixture = InlineTestProject::with_language(Language::Java)
        .file("Use.java", java)
        .build();
    let go =
        "package sample; type Target struct {}; func f(target Target) Target { return target }";
    let go_fixture = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.test/types\n\ngo 1.22\n")
        .file("source.go", go)
        .build();
    for (answer, file) in [
        (
            native_type_projection(&java_fixture, JavaAdapter, "Use.java", java),
            java_fixture.file("Use.java"),
        ),
        (
            native_type_projection(&go_fixture, GoAdapter, "source.go", go),
            go_fixture.file("source.go"),
        ),
    ] {
        let SelectedNativeTypes::Ready { nominal, intrinsic } = answer.types else {
            panic!("nominal type must project to its selected declaration");
        };
        assert!(intrinsic.is_empty());
        assert_eq!(
            nominal.len(),
            1,
            "{file:?}: {:?}: {:?}",
            answer.named_reasons,
            answer.answer
        );
        let (identity, SelectedNativeDefinition::Unit(unit)) = &nominal[0] else {
            panic!("nominal type must have a parser unit");
        };
        assert_eq!(unit.terminal_name(), "Target");
        assert_eq!(unit.source(), &file);
        assert!(answer.answer.projected_frontiers().iter().any(|frontier| {
            frontier
                .possible_values()
                .iter()
                .any(|value| value.ty().identity() == *identity)
        }));
    }
}
