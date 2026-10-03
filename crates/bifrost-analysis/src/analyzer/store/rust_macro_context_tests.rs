//! Canonical macro-definition contexts through persistence and reopen.

use brokk_bifrost_core::analyzer::parsed_file::ParsedSourceFacts;
use brokk_bifrost_core::analyzer::rust_facts::{
    RustItemMacroExpansion, RustMacroDefinitionSourceFact, RustSourceContextFact,
    RustSourceContextKind,
};
use brokk_bifrost_core::analyzer::source_facts::{
    SourceDeclarationId, SourceOccurrenceId, SourceOccurrenceProvenance,
};

use crate::analyzer::rust::RustAdapter;
use crate::inline_project::InlineTestProject;

use super::tests::{oid_for, parse_state};
use super::*;

const MACRO_CONTEXT_SOURCE: &str = r#"
macro_rules! root_macro {
    () => {};
}

mod nested {
    macro_rules! module_macro {
        () => {};
    }

    fn owner() {
        macro_rules! function_macro {
            () => {};
        }
    }
}

macro_rules! passthrough {
    ($($item:item)*) => { $($item)* };
}

passthrough! {
    macro_rules! embedded_macro {
        () => {};
    }
}
"#;

fn declaration_name(
    facts: &ParsedSourceFacts,
    source: &str,
    declaration: SourceDeclarationId,
) -> Option<String> {
    let name = facts.occurrences.declaration(declaration).name?;
    let range = facts.occurrences.occurrence(name).range;
    Some(source[range.start_byte..range.end_byte].to_owned())
}

fn macro_definition<'a>(
    facts: &'a ParsedSourceFacts,
    source: &str,
    name: &str,
) -> &'a RustMacroDefinitionSourceFact {
    facts
        .rust_items
        .macro_definitions
        .iter()
        .find(|definition| {
            declaration_name(facts, source, definition.declaration).as_deref() == Some(name)
        })
        .unwrap_or_else(|| {
            panic!(
                "missing macro definition {name:?}: {:?}",
                facts.rust_items.macro_definitions
            )
        })
}

fn context_for(facts: &ParsedSourceFacts, context: SourceOccurrenceId) -> &RustSourceContextFact {
    facts
        .rust_items
        .contexts
        .iter()
        .find(|row| row.context == context)
        .unwrap_or_else(|| panic!("missing source context {context:?}"))
}

fn assert_macro_context<'a>(
    facts: &'a ParsedSourceFacts,
    source: &str,
    name: &str,
    kind: RustSourceContextKind,
    provenance: SourceOccurrenceProvenance,
) -> &'a RustMacroDefinitionSourceFact {
    let definition = macro_definition(facts, source, name);
    let context = context_for(facts, definition.context);
    assert_eq!(context.kind, kind, "{name}: {context:?}");
    assert_eq!(
        facts.occurrences.occurrence(context.context).provenance,
        provenance,
        "{name}: {context:?}"
    );
    definition
}

fn context_chain_contains(
    facts: &ParsedSourceFacts,
    start: SourceOccurrenceId,
    wanted: RustSourceContextKind,
) -> bool {
    let mut current = Some(start);
    while let Some(context) = current {
        let row = context_for(facts, context);
        if row.kind == wanted {
            return true;
        }
        current = row.parent;
    }
    false
}

fn clear_macro_context_marker(store: &AnalyzerStore) {
    store.conn.execute(|connection| {
        connection
            .execute_batch(
                "DROP TRIGGER source_fact_manifests_no_reopen;
                 UPDATE source_fact_manifests SET publication_state = 'building';
                 UPDATE source_rust_item_manifests SET macro_contexts_version = NULL;
                 UPDATE source_fact_manifests SET publication_state = 'complete';",
            )
            .unwrap();
    });
}

#[test]
fn rust_macro_definition_contexts_reopen_with_primary_and_embedded_provenance() {
    let fixture = InlineTestProject::new()
        .file("src/lib.rs", MACRO_CONTEXT_SOURCE)
        .build();
    let file = fixture.file("src/lib.rs");
    let state = parse_state(&RustAdapter, &file);
    let parsed = state.source_facts.as_ref().expect("Rust source facts");

    let root = assert_macro_context(
        parsed,
        MACRO_CONTEXT_SOURCE,
        "root_macro",
        RustSourceContextKind::FileRoot,
        SourceOccurrenceProvenance::PrimaryNode,
    );
    assert!(root.arms.iter().all(|arm| arm.pattern.is_some()));
    let module = assert_macro_context(
        parsed,
        MACRO_CONTEXT_SOURCE,
        "module_macro",
        RustSourceContextKind::DeclarationBody,
        SourceOccurrenceProvenance::PrimaryNode,
    );
    assert!(context_chain_contains(
        parsed,
        module.context,
        RustSourceContextKind::Module
    ));
    let function = assert_macro_context(
        parsed,
        MACRO_CONTEXT_SOURCE,
        "function_macro",
        RustSourceContextKind::Block,
        SourceOccurrenceProvenance::PrimaryNode,
    );
    assert!(context_chain_contains(
        parsed,
        function.context,
        RustSourceContextKind::Function
    ));
    let embedded = assert_macro_context(
        parsed,
        MACRO_CONTEXT_SOURCE,
        "embedded_macro",
        RustSourceContextKind::FileRoot,
        SourceOccurrenceProvenance::Embedded,
    );
    assert!(parsed.rust_items.macros.iter().any(|macro_fact| {
        macro_fact.expansion == RustItemMacroExpansion::Parsed(embedded.context)
    }));

    let expected_contexts = parsed.rust_items.contexts.clone();
    let expected_definitions = parsed.rust_items.macro_definitions.clone();
    let passthrough_declaration =
        macro_definition(parsed, MACRO_CONTEXT_SOURCE, "passthrough").declaration;
    let expected_inputs = parsed.rust_items.macro_inputs.clone();
    assert!(!expected_inputs.is_empty());
    let expected_primary_at_module: Vec<_> = parsed
        .rust_items
        .contexts
        .iter()
        .filter(|context| {
            let occurrence = parsed.occurrences.occurrence(context.context);
            occurrence.provenance == SourceOccurrenceProvenance::PrimaryNode
                && occurrence.range.start_byte <= MACRO_CONTEXT_SOURCE.find("module_macro").unwrap()
                && MACRO_CONTEXT_SOURCE.find("module_macro").unwrap() < occurrence.range.end_byte
        })
        .map(|context| context.context)
        .collect();
    assert!(!expected_primary_at_module.is_empty());

    let oid = oid_for(MACRO_CONTEXT_SOURCE.as_bytes());
    let path = fixture.root().join("rust-macro-contexts.db");
    let store = AnalyzerStore::open_persistent(&path).expect("persistent macro context store");
    store
        .write_parsed_blob(oid, "rust", &RustAdapter, &state)
        .expect("publish macro context fixture");
    let generation = store.current_generation("rust").unwrap();
    drop(state);
    drop(store);
    std::fs::remove_file(file.abs_path()).expect("remove source before reopen");

    let reopened = AnalyzerStore::open_persistent(&path).expect("reopen macro context store");
    let actual = reopened
        .rust_hierarchy_source_facts(oid, generation, &RustAdapter, &file, &|| true)
        .unwrap()
        .unwrap();
    assert_eq!(actual.items.contexts, expected_contexts);
    assert_eq!(actual.items.macro_definitions, expected_definitions);
    assert_eq!(actual.items.macro_inputs, expected_inputs);
    let definition = actual
        .items
        .macro_definitions
        .iter()
        .find(|definition| definition.declaration == passthrough_declaration)
        .unwrap();
    let input = actual
        .items
        .macro_inputs
        .first()
        .expect("persisted invocation input");
    let matched = brokk_bifrost_rust::macro_matcher::match_captured_macro_rules(
        definition,
        &input.tree,
        &|| true,
    )
    .expect("replay after source removal");
    assert_eq!(matched.arm_index, 0);
    assert_eq!(matched.bindings.len(), 1);
    assert_eq!(
        matched.bindings[0].fragment,
        brokk_bifrost_rust::macro_matcher::MacroFragmentKind::Item
    );

    let actual_primary = reopened
        .rust_primary_contexts_at(
            oid,
            generation,
            MACRO_CONTEXT_SOURCE.find("module_macro").unwrap(),
            &|| true,
        )
        .unwrap()
        .unwrap();
    assert_eq!(actual_primary, expected_primary_at_module);
}

#[test]
fn stale_macro_context_marker_rejects_hierarchy_and_primary_reads_then_repairs() {
    let fixture = InlineTestProject::new()
        .file("src/lib.rs", MACRO_CONTEXT_SOURCE)
        .build();
    let file = fixture.file("src/lib.rs");
    let state = parse_state(&RustAdapter, &file);
    let oid = oid_for(MACRO_CONTEXT_SOURCE.as_bytes());
    let store = AnalyzerStore::open_ephemeral().unwrap();
    store
        .write_parsed_blob(oid, "rust", &RustAdapter, &state)
        .unwrap();
    let generation = store.current_generation("rust").unwrap();
    let point = MACRO_CONTEXT_SOURCE.find("module_macro").unwrap();
    clear_macro_context_marker(&store);

    assert!(
        store
            .rust_hierarchy_source_facts(oid, generation, &RustAdapter, &file, &|| true)
            .is_err(),
        "stale macro context marker must block hierarchy hydration"
    );
    assert!(
        store
            .rust_primary_contexts_at(oid, generation, point, &|| true)
            .is_err(),
        "stale macro context marker must block primary context selection"
    );

    store
        .write_parsed_blob(oid, "rust", &RustAdapter, &state)
        .unwrap();
    let repaired = store
        .rust_hierarchy_source_facts(oid, generation, &RustAdapter, &file, &|| true)
        .unwrap()
        .unwrap();
    assert!(!repaired.items.macro_definitions.is_empty());
    assert!(
        !store
            .rust_primary_contexts_at(oid, generation, point, &|| true)
            .unwrap()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn empty_macro_context_product_reopens_and_repairs_after_stale_marker() {
    let fixture = InlineTestProject::new().file("src/lib.rs", "").build();
    let file = fixture.file("src/lib.rs");
    let state = parse_state(&RustAdapter, &file);
    let oid = oid_for(b"");
    let store = AnalyzerStore::open_ephemeral().unwrap();
    store
        .write_parsed_blob(oid, "rust", &RustAdapter, &state)
        .unwrap();
    let generation = store.current_generation("rust").unwrap();
    let fresh = store
        .rust_hierarchy_source_facts(oid, generation, &RustAdapter, &file, &|| true)
        .unwrap()
        .unwrap();
    assert!(fresh.items.macro_definitions.is_empty());

    clear_macro_context_marker(&store);
    assert!(
        store
            .rust_hierarchy_source_facts(oid, generation, &RustAdapter, &file, &|| true)
            .is_err()
    );
    store
        .write_parsed_blob(oid, "rust", &RustAdapter, &state)
        .unwrap();
    let repaired = store
        .rust_hierarchy_source_facts(oid, generation, &RustAdapter, &file, &|| true)
        .unwrap()
        .unwrap();
    assert!(repaired.items.macro_definitions.is_empty());
}
