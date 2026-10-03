use super::RustDeclarationTypeIndex;
use crate::declarations::parse_rust_file;
use crate::graph_support::RustCargoRouteError;
use crate::hierarchy::RustHierarchySourceFacts;
use brokk_bifrost_core::analyzer::ProjectFile;
use brokk_bifrost_core::analyzer::rust_facts::{RustSourceContextKind, RustTypeSourceShape};
use brokk_bifrost_core::analyzer::source_facts::SourceDeclarationId;
use std::cell::Cell;
use std::sync::Arc;

const FIXTURE: &str = r#"
struct Plain;
struct Holder<T> { field: Vec<Option<T>> }
enum Values { Unit }
const VALUE: Option<u8> = None;
fn callable() -> Result<u8, u8> { Err(0) }
type Alias<T> = Holder<Vec<Option<T>>>;
impl<T> SomeTrait for Holder<T> {}
wrap! { fn same() -> Option<u8> { None } }
wrap! { fn same() -> Option<u8> { None } }
wrap! { type EmbeddedAlias = Option<u8>; }
"#;

const SCOPE_FIXTURE: &str = r#"
type RootAlias = u8;
trait Service { type TraitAlias; }
mod outer {
    type NestedAlias = u8;
    struct Owner;
    impl Owner { type AssociatedAlias = u8; }
    fn local() {
        type LocalAlias = u8;
        const LOCAL_VALUE: u8 = 0;
    }
}
wrap! { type EmbeddedAlias = Option<u8>; }
"#;

const MACRO_SCOPE_FIXTURE: &str = r#"
macro_rules! RootMacro { ($name:ident) => {}; }
mod outer {
    macro_rules! ModuleMacro { ($name:ident) => {}; }
    fn local() {
        macro_rules! FunctionMacro { ($name:ident) => {}; }
    }
}
macro_rules! passthrough { ($($item:item)*) => { $($item)* }; }
passthrough! { macro_rules! EmbeddedMacro { ($name:ident) => {}; } }
"#;

fn fixture_facts(source: &str) -> Arc<RustHierarchySourceFacts> {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .expect("Rust parser language");
    let tree = parser.parse(source, None).expect("Rust fixture tree");
    let root = tempfile::tempdir().expect("fixture root");
    let file = ProjectFile::new(
        root.path().canonicalize().expect("canonical fixture root"),
        "src/lib.rs",
    );
    let parsed = parse_rust_file(&file, source, &tree);
    let canonical = parsed.source_facts.as_ref().expect("canonical Rust facts");
    let module_names = canonical
        .rust_modules
        .as_ref()
        .expect("canonical module facts")
        .declarations
        .iter()
        .map(|module| (module.declaration, module.name.clone()))
        .collect();
    Arc::new(RustHierarchySourceFacts {
        items: canonical.rust_items.clone(),
        types: canonical.rust_types.clone(),
        declarations: canonical.occurrences.declarations().to_vec(),
        declaration_units: parsed.source_declaration_units.clone(),
        module_names,
        imports: canonical.imports.clone(),
    })
}

fn declaration_named(facts: &RustHierarchySourceFacts, name: &str) -> SourceDeclarationId {
    facts
        .declaration_units
        .iter()
        .find(|(_, unit)| unit.identifier() == name)
        .map(|(declaration, _)| *declaration)
        .unwrap_or_else(|| panic!("missing declaration unit {name}"))
}

fn alias_named(facts: &RustHierarchySourceFacts, name: &str) -> SourceDeclarationId {
    facts
        .items
        .aliases
        .iter()
        .find(|alias| {
            facts.declaration_units.iter().any(|(declaration, unit)| {
                *declaration == alias.declaration && unit.identifier() == name
            })
        })
        .map(|alias| alias.declaration)
        .unwrap_or_else(|| panic!("missing alias declaration unit {name}"))
}

fn alias_with_ancestor_kind(
    facts: &RustHierarchySourceFacts,
    kind: RustSourceContextKind,
) -> SourceDeclarationId {
    for alias in &facts.items.aliases {
        let mut current = Some(alias.context);
        while let Some(context) = current {
            let row = facts
                .items
                .contexts
                .iter()
                .find(|row| row.context == context)
                .expect("alias context row");
            if row.kind == kind {
                return alias.declaration;
            }
            if row.kind == RustSourceContextKind::FileRoot {
                break;
            }
            current = row.parent;
        }
    }
    panic!("missing alias under context kind {kind:?}");
}

fn macro_named(facts: &RustHierarchySourceFacts, name: &str) -> SourceDeclarationId {
    facts
        .items
        .macro_definitions
        .iter()
        .find(|macro_definition| {
            facts.declaration_units.iter().any(|(declaration, unit)| {
                *declaration == macro_definition.declaration && unit.identifier() == name
            })
        })
        .map(|macro_definition| macro_definition.declaration)
        .unwrap_or_else(|| panic!("missing macro definition unit {name}"))
}

fn context_kind(
    facts: &RustHierarchySourceFacts,
    context: brokk_bifrost_core::analyzer::source_facts::SourceOccurrenceId,
) -> RustSourceContextKind {
    facts
        .items
        .contexts
        .iter()
        .find(|row| row.context == context)
        .expect("source context row")
        .kind
}

fn assert_type_links(
    index: &RustDeclarationTypeIndex,
    occurrence: brokk_bifrost_core::analyzer::source_facts::SourceOccurrenceId,
) {
    let mut pending = vec![occurrence];
    while let Some(current) = pending.pop() {
        let fact = index.type_fact(current);
        assert_eq!(fact.occurrence, current);
        let RustTypeSourceShape::Path { segments, .. } = &fact.shape else {
            continue;
        };
        for segment in segments {
            let Some(arguments) = &segment.generic_arguments else {
                continue;
            };
            for argument in &arguments.arguments {
                assert_eq!(index.type_fact(*argument).occurrence, *argument);
                pending.push(*argument);
            }
        }
    }
}

#[test]
fn public_lookups_follow_parsed_annotation_type_generic_and_impl_links() {
    let facts = fixture_facts(FIXTURE);
    let index = RustDeclarationTypeIndex::new(Arc::clone(&facts), &|| true)
        .expect("declaration type index");

    for value in &facts.items.values {
        let annotation = index
            .annotation(value.declaration)
            .expect("value annotation");
        assert_eq!(annotation.declaration, value.declaration);
        assert_eq!(annotation.context, value.context);
        assert_eq!(annotation.type_occurrence, value.declared_type);
        if let Some(occurrence) = value.declared_type {
            assert_type_links(&index, occurrence);
        }
    }
    for callable in &facts.items.callables {
        let annotation = index
            .annotation(callable.declaration)
            .expect("callable annotation");
        assert_eq!(annotation.declaration, callable.declaration);
        assert_eq!(annotation.context, callable.context);
        assert_eq!(annotation.type_occurrence, callable.return_type);
        if let Some(occurrence) = callable.return_type {
            assert_type_links(&index, occurrence);
        }
    }
    for alias in &facts.items.aliases {
        let annotation = index
            .annotation(alias.declaration)
            .expect("alias annotation");
        assert_eq!(annotation.declaration, alias.declaration);
        assert_eq!(annotation.context, alias.context);
        assert_eq!(annotation.type_occurrence, alias.target_type);
        if let Some(occurrence) = alias.target_type {
            assert_type_links(&index, occurrence);
        }
    }
    let nested_alias = facts
        .items
        .aliases
        .iter()
        .find(|alias| alias.target_type.is_some())
        .expect("generic alias with a target type");
    let target = index.type_fact(nested_alias.target_type.expect("alias target type"));
    let outer_arguments = match &target.shape {
        RustTypeSourceShape::Path { segments, .. } => segments
            .last()
            .and_then(|segment| segment.generic_arguments.as_ref())
            .expect("outer generic arguments"),
        RustTypeSourceShape::Unsupported { .. } => panic!("generic alias target is a path"),
        RustTypeSourceShape::Compound { .. } => panic!("generic alias target is a path"),
    };
    assert_eq!(outer_arguments.arguments.len(), 1);
    let nested = index.type_fact(outer_arguments.arguments[0]);
    match &nested.shape {
        RustTypeSourceShape::Path { segments, .. } => assert!(
            segments
                .last()
                .and_then(|segment| segment.generic_arguments.as_ref())
                .is_some_and(|arguments| !arguments.arguments.is_empty()),
            "nested generic argument retains its own exact type links"
        ),
        RustTypeSourceShape::Unsupported { .. } => panic!("nested generic argument is a path"),
        RustTypeSourceShape::Compound { .. } => panic!("nested generic argument is a path"),
    }

    let unannotated_value = facts
        .items
        .values
        .iter()
        .find(|value| value.declared_type.is_none())
        .expect("an enum unit value without a type annotation");
    assert_eq!(
        index
            .annotation(unannotated_value.declaration)
            .expect("value family remains present without annotation")
            .type_occurrence,
        None
    );

    let plain = declaration_named(&facts, "Plain");
    assert!(index.annotation(plain).is_none());
    assert!(index.generic_parameters(plain).is_empty());
    assert!(index.impl_fact(plain).is_none());

    for generic in &facts.items.generics {
        assert_eq!(
            index.generic_parameters(generic.declaration),
            generic.parameters.as_slice()
        );
    }
    for implementation in &facts.items.impls {
        assert_eq!(
            index.impl_fact(implementation.declaration),
            Some(implementation)
        );
        if let Some(occurrence) = implementation.trait_type {
            assert_type_links(&index, occurrence);
        }
        if let Some(occurrence) = implementation.target_type {
            assert_type_links(&index, occurrence);
        }
    }

    assert!(Arc::ptr_eq(index.facts(), &facts));
}

#[test]
fn declarations_for_retains_all_embedded_same_name_alternatives() {
    let facts = fixture_facts(FIXTURE);
    let index = RustDeclarationTypeIndex::new(Arc::clone(&facts), &|| true)
        .expect("declaration type index");
    let repeated_unit = facts
        .declaration_units
        .iter()
        .find(|(_, unit)| unit.identifier() == "same")
        .map(|(_, unit)| unit.clone())
        .expect("repeated embedded declaration unit");
    let expected = facts
        .declaration_units
        .iter()
        .filter(|(_, unit)| unit == &repeated_unit)
        .map(|(declaration, _)| *declaration)
        .collect::<Vec<_>>();
    assert!(
        expected.len() >= 2,
        "fixture must produce repeated alternatives"
    );
    assert_eq!(index.declarations_for(&repeated_unit), expected.as_slice());

    for declaration in expected {
        let units = index.units_for(declaration).collect::<Vec<_>>();
        assert_eq!(units, vec![&repeated_unit]);
        assert!(index.annotation(declaration).is_some());
    }
}

#[test]
fn declaration_scope_projects_primary_alias_contexts() {
    let facts = fixture_facts(SCOPE_FIXTURE);
    let index = RustDeclarationTypeIndex::new(Arc::clone(&facts), &|| true)
        .expect("declaration type index");

    let root = index
        .declaration_scope(alias_named(&facts, "RootAlias"), &|| true)
        .expect("root alias scope")
        .expect("primary declaration");
    assert_eq!(root.local_scope, None);
    assert_eq!(root.module, None);

    let nested = index
        .declaration_scope(alias_named(&facts, "NestedAlias"), &|| true)
        .expect("nested alias scope")
        .expect("primary declaration");
    let nested_local = nested.local_scope.expect("nested module scope");
    assert_eq!(
        context_kind(&facts, nested_local),
        RustSourceContextKind::Module
    );
    assert_eq!(nested.module, Some(nested_local));

    let associated = index
        .declaration_scope(alias_named(&facts, "AssociatedAlias"), &|| true)
        .expect("associated alias scope")
        .expect("primary declaration");
    assert_eq!(
        context_kind(
            &facts,
            associated
                .local_scope
                .expect("impl scope for associated alias")
        ),
        RustSourceContextKind::Impl
    );
    assert_eq!(
        context_kind(
            &facts,
            associated.module.expect("module for associated alias")
        ),
        RustSourceContextKind::Module
    );

    let local = index
        .declaration_scope(
            alias_with_ancestor_kind(&facts, RustSourceContextKind::Function),
            &|| true,
        )
        .expect("local alias scope")
        .expect("primary declaration");
    assert_eq!(
        context_kind(
            &facts,
            local.local_scope.expect("block scope for local alias")
        ),
        RustSourceContextKind::Block
    );
    assert_eq!(
        context_kind(&facts, local.module.expect("module for local alias")),
        RustSourceContextKind::Module
    );

    let trait_alias = index
        .declaration_scope(
            alias_with_ancestor_kind(&facts, RustSourceContextKind::Trait),
            &|| true,
        )
        .expect("trait alias scope")
        .expect("primary declaration");
    assert_eq!(
        context_kind(&facts, trait_alias.local_scope.expect("trait scope")),
        RustSourceContextKind::Trait
    );
    assert_eq!(trait_alias.module, None);
}

#[test]
fn declaration_scope_projects_owned_contexts_and_value_annotations() {
    let facts = fixture_facts(SCOPE_FIXTURE);
    let index = RustDeclarationTypeIndex::new(Arc::clone(&facts), &|| true)
        .expect("declaration type index");

    let function = index
        .declaration_scope(declaration_named(&facts, "local"), &|| true)
        .expect("function scope")
        .expect("primary function");
    assert_eq!(
        context_kind(&facts, function.local_scope.expect("function parent scope")),
        RustSourceContextKind::Module
    );
    assert_eq!(function.module, function.local_scope);

    let owner = index
        .declaration_scope(declaration_named(&facts, "Owner"), &|| true)
        .expect("type scope")
        .expect("primary type");
    assert_eq!(owner.local_scope, function.local_scope);

    let service = index
        .declaration_scope(declaration_named(&facts, "Service"), &|| true)
        .expect("trait scope")
        .expect("primary trait");
    assert_eq!(service.local_scope, None);
    assert_eq!(service.module, None);

    let module = index
        .declaration_scope(declaration_named(&facts, "outer"), &|| true)
        .expect("module scope")
        .expect("primary module");
    assert_eq!(module.local_scope, None);
    assert_eq!(module.module, None);

    // Function-local declarations are canonical source facts, not display units.
    let [local_value] = facts.items.values.as_slice() else {
        panic!("one local value in this fixture: {:?}", facts.items.values);
    };
    let value = index
        .declaration_scope(local_value.declaration, &|| true)
        .expect("value scope")
        .expect("primary value");
    assert_eq!(
        context_kind(&facts, value.local_scope.expect("value block scope")),
        RustSourceContextKind::Block
    );
    assert_eq!(value.module, function.module);
}

#[test]
fn declaration_scope_excludes_embedded_aliases() {
    let facts = fixture_facts(SCOPE_FIXTURE);
    let index = RustDeclarationTypeIndex::new(Arc::clone(&facts), &|| true)
        .expect("declaration type index");
    let embedded = facts
        .items
        .aliases
        .iter()
        .find(|alias| {
            index
                .contexts
                .owner_context(alias.declaration)
                .map(|context| {
                    !index
                        .contexts
                        .is_primary(&facts, context)
                        .expect("primary state")
                })
                .unwrap_or(false)
        })
        .map(|alias| alias.declaration)
        .expect("embedded alias declaration");

    assert_eq!(
        index
            .declaration_scope(embedded, &|| true)
            .expect("embedded alias scope"),
        None
    );
}

#[test]
fn declaration_scope_projects_primary_macro_contexts_and_excludes_embedded() {
    let facts = fixture_facts(MACRO_SCOPE_FIXTURE);
    let index = RustDeclarationTypeIndex::new(Arc::clone(&facts), &|| true)
        .expect("declaration type index");

    let root = index
        .declaration_scope(macro_named(&facts, "RootMacro"), &|| true)
        .expect("root macro scope")
        .expect("root macro is primary");
    assert_eq!(root.local_scope, None);
    assert_eq!(root.module, None);

    let module = index
        .declaration_scope(macro_named(&facts, "ModuleMacro"), &|| true)
        .expect("module macro scope")
        .expect("module macro is primary");
    let module_scope = module.local_scope.expect("module macro local scope");
    assert_eq!(
        context_kind(&facts, module_scope),
        RustSourceContextKind::Module
    );
    assert_eq!(module.module, Some(module_scope));

    let local_macros = facts
        .items
        .macro_definitions
        .iter()
        .filter(|definition| {
            context_kind(&facts, definition.context) == RustSourceContextKind::Block
        })
        .collect::<Vec<_>>();
    let [local_macro] = local_macros.as_slice() else {
        panic!("one function-local macro in this fixture: {local_macros:?}");
    };
    let function = index
        .declaration_scope(local_macro.declaration, &|| true)
        .expect("function macro scope")
        .expect("function macro is primary");
    assert_eq!(
        context_kind(
            &facts,
            function.local_scope.expect("function macro local scope")
        ),
        RustSourceContextKind::Block
    );
    assert_eq!(
        context_kind(&facts, function.module.expect("function macro module")),
        RustSourceContextKind::Module
    );

    let embedded = facts
        .items
        .macro_definitions
        .iter()
        .find(|macro_definition| {
            !index
                .contexts
                .is_primary(&facts, macro_definition.context)
                .expect("macro context primary state")
        })
        .expect("embedded macro definition");
    assert_eq!(
        index
            .declaration_scope(embedded.declaration, &|| true)
            .expect("embedded macro scope"),
        None
    );
}

#[test]
fn declaration_scope_honors_early_and_mid_walk_cancellation() {
    let facts = fixture_facts(SCOPE_FIXTURE);
    let index = RustDeclarationTypeIndex::new(Arc::clone(&facts), &|| true)
        .expect("declaration type index");
    let local = alias_with_ancestor_kind(&facts, RustSourceContextKind::Function);

    assert!(matches!(
        index.declaration_scope(local, &|| false),
        Err(RustCargoRouteError::Cancelled)
    ));

    let calls = Cell::new(0usize);
    let result = index.declaration_scope(local, &|| {
        let call = calls.get();
        calls.set(call + 1);
        call < 2
    });
    assert!(matches!(result, Err(RustCargoRouteError::Cancelled)));
    assert!(calls.get() > 1, "walk must make progress before cancelling");
}

#[test]
fn constructor_honors_early_and_mid_loop_cancellation() {
    let facts = fixture_facts(FIXTURE);
    assert!(matches!(
        RustDeclarationTypeIndex::new(Arc::clone(&facts), &|| false),
        Err(RustCargoRouteError::Cancelled)
    ));

    let context_rows = facts.items.contexts.len();
    let calls = Cell::new(0usize);
    let result = RustDeclarationTypeIndex::new(Arc::clone(&facts), &|| {
        let call = calls.get();
        calls.set(call + 1);
        call <= context_rows
    });
    assert!(matches!(result, Err(RustCargoRouteError::Cancelled)));
    assert!(
        calls.get() > context_rows,
        "cancellation must occur after progress"
    );
}
