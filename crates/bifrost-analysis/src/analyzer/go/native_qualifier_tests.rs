use super::GoAdapter;
use crate::CancellationToken;
use crate::analyzer::resolution::{
    BindingFragmentId, CandidatePathIdentity, CatalogRootImportAnchors, SelectedRootPathHalf,
    classify_selected_root_path_half, lower_for_test,
};
use crate::analyzer::{Language, LanguageAdapter, ProjectFile};

#[test]
fn parsed_go_qualifiers_lower_to_selected_root_halves_and_typed_receivers() {
    let source = r#"package consumer
import pkg "example.test/provider"
var Value *pkg.Item
type Local struct { Member string }
func use(local Local) { _ = pkg.Member; pkg.Call(); _ = local.Member }
"#;
    // Parsing needs a logical absolute source identity, not an on-disk project.
    let file = ProjectFile::new(std::env::temp_dir(), "qualifier.go");
    let adapter = GoAdapter;
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&adapter.parser_language_for_file(&file))
        .unwrap();
    let tree = parser.parse(source, None).unwrap();
    let parsed = adapter.parse_file(&file, source, &tree);
    assert_eq!(parsed.resolution_facts.root_references.len(), 4);
    let fragment = BindingFragmentId::for_test(b"go-positioned-package-qualifiers");
    let artifact = lower_for_test(fragment, Language::Go, &parsed.resolution_facts);
    for reference in &parsed.resolution_facts.root_references {
        let prefix = reference.prefix_reference.unwrap();
        let metadata = artifact
            .lexical()
            .semantics()
            .iter()
            .find(|site| site.site() == prefix)
            .unwrap()
            .site_metadata()
            .unwrap();
        assert!(metadata.go_package_qualifier());
        assert_eq!(
            metadata.go_spelling_namespace(),
            Some(brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace::TypeOrValue)
        );
        let terminal = artifact
            .lexical()
            .semantics()
            .iter()
            .find(|site| site.site() == reference.reference)
            .unwrap()
            .site_metadata()
            .unwrap();
        assert!(!terminal.go_package_qualifier());
    }
    let cancellation = CancellationToken::default();
    let halves = artifact
        .lexical()
        .paths()
        .iter()
        .filter_map(|(id, path)| {
            classify_selected_root_path_half(
                &CatalogRootImportAnchors::new(artifact.identities()),
                CandidatePathIdentity::new(fragment, *id),
                path,
                &cancellation,
            )
            .unwrap()
        })
        .filter_map(|half| match half {
            SelectedRootPathHalf::Reference {
                prefix_reference,
                lexical_scope_head,
                route,
                ..
            } => Some((prefix_reference, lexical_scope_head, route)),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(halves.len(), 4);
    for (prefix, scope, route) in halves {
        assert!(prefix.is_some());
        assert!(scope.is_some());
        assert!(
            route.is_empty(),
            "the positioned qualifier is consumed once"
        );
    }
    assert_eq!(
        artifact.typed().qualified_routes().len(),
        3,
        "the two value selectors and call retain runtime receiver obligations; pkg.Item is a package type route"
    );
}

#[test]
fn parsed_go_function_value_reference_reaches_original_callable_identity() {
    use crate::analyzer::resolution::{
        BatchResolutionEngine, LoweredSemanticRole, PreloadedFragmentSource, ResolutionQuery,
        lower_lexical_for_test,
    };
    use brokk_bifrost_core::analyzer::resolution_facts::{
        ResolutionIdentifierRole, ResolutionNamespace,
    };
    let source = "package p\nfunc F() {}\nfunc use() { f := F; f() }\n";
    let file = ProjectFile::new(std::env::temp_dir(), "function_value.go");
    let adapter = GoAdapter;
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&adapter.parser_language_for_file(&file))
        .unwrap();
    let tree = parser.parse(source, None).unwrap();
    let parsed = adapter.parse_file(&file, source, &tree);
    let facts = &parsed.resolution_facts;
    let site = |role| {
        facts
            .identifiers
            .iter()
            .find(|id| facts.names[id.name.index()].spelling == "F" && id.role == role)
            .unwrap()
    };
    let reference = site(ResolutionIdentifierRole::Reference);
    assert_eq!(reference.namespace, ResolutionNamespace::Value);
    let declaration = site(ResolutionIdentifierRole::Declaration);
    let (lowered, _) = lower_lexical_for_test(
        BindingFragmentId::for_test(b"go-function-value"),
        Language::Go,
        facts,
    );
    let semantic = |site, role| {
        lowered
            .semantics()
            .iter()
            .find(|s| s.site() == site && s.role() == role)
            .unwrap()
            .semantic()
    };
    let target = semantic(declaration.site, LoweredSemanticRole::Definition);
    let reference = semantic(reference.site, LoweredSemanticRole::Reference);
    let source = PreloadedFragmentSource::from_lowered_fragments([lowered]);
    let answer = BatchResolutionEngine::new(&source)
        .resolve_reference(
            ResolutionQuery::new(reference),
            &CancellationToken::default(),
        )
        .unwrap();
    assert_eq!(answer.targets(), &[target]);
}

#[test]
fn parsed_go_local_type_activation_preserves_outer_and_recursive_bindings() {
    use crate::analyzer::resolution::{
        BatchResolutionEngine, LoweredSemanticRole, PreloadedFragmentSource, ResolutionQuery,
        lower_lexical_for_test,
    };
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionIdentifierRole;
    let source = "package p\ntype T struct{}\nfunc use() { var before *T; type T struct { Next *T }; var after *T }\n";
    let file = ProjectFile::new(std::env::temp_dir(), "type_activation.go");
    let adapter = GoAdapter;
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&adapter.parser_language_for_file(&file))
        .unwrap();
    let tree = parser.parse(source, None).unwrap();
    let parsed = adapter.parse_file(&file, source, &tree);
    let facts = &parsed.resolution_facts;
    let (lowered, _) = lower_lexical_for_test(
        BindingFragmentId::for_test(b"go-type-activation"),
        Language::Go,
        facts,
    );
    let semantic = |site, role| {
        lowered
            .semantics()
            .iter()
            .find(|s| s.site() == site && s.role() == role)
            .unwrap()
            .semantic()
    };
    let declarations = facts
        .identifiers
        .iter()
        .filter(|id| {
            facts.names[id.name.index()].spelling == "T"
                && id.role == ResolutionIdentifierRole::Declaration
        })
        .map(|id| semantic(id.site, LoweredSemanticRole::Definition))
        .collect::<Vec<_>>();
    let references = facts
        .identifiers
        .iter()
        .filter(|id| {
            facts.names[id.name.index()].spelling == "T"
                && id.role == ResolutionIdentifierRole::Reference
        })
        .map(|id| semantic(id.site, LoweredSemanticRole::Reference))
        .collect::<Vec<_>>();
    assert_eq!(declarations.len(), 2);
    assert_eq!(references.len(), 3);
    let source = PreloadedFragmentSource::from_lowered_fragments([lowered]);
    let engine = BatchResolutionEngine::new(&source);
    for (reference, target) in
        references
            .into_iter()
            .zip([declarations[0], declarations[1], declarations[1]])
    {
        let answer = engine
            .resolve_reference(
                ResolutionQuery::new(reference),
                &CancellationToken::default(),
            )
            .unwrap();
        assert_eq!(answer.targets(), &[target]);
    }
}

fn parse_go_spelling_facts(
    source: &str,
) -> brokk_bifrost_core::analyzer::resolution_facts::FileResolutionFacts {
    let file = ProjectFile::new(std::env::temp_dir(), "spelling.go");
    let adapter = GoAdapter;
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&adapter.parser_language_for_file(&file))
        .unwrap();
    let tree = parser.parse(source, None).unwrap();
    adapter.parse_file(&file, source, &tree).resolution_facts
}

#[test]
fn parsed_go_spelling_union_respects_scope_activation_and_wrong_namespace_blockers() {
    use crate::analyzer::resolution::{
        BatchResolutionEngine, LoweredSemanticRole, PreloadedFragmentSource, ResolutionQuery,
    };
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionIdentifierRole;
    let facts = parse_go_spelling_facts(
        r#"package p
        type Outer struct{}
        func (Outer) Method() {}
        type Inner struct{}
        func (Inner) Method() {}
        var X Outer
        func innerType() { _ = X.Method; type X struct{}; _ = X.Method }
        func innerValue() { type X struct{}; { var X Inner; _ = X.Method } }
        func invalidValue() { type X int; _ = X }
    "#,
    );
    let artifact = lower_for_test(
        BindingFragmentId::for_test(b"go-spelling-union"),
        Language::Go,
        &facts,
    );
    assert!(!artifact.identities().go_spelling_choices().is_empty());
    let lexical = artifact.lexical();
    let semantic = |site, role| {
        lexical
            .semantics()
            .iter()
            .find(|s| s.site() == site && s.role() == role)
            .unwrap()
            .semantic()
    };
    let declarations = facts
        .identifiers
        .iter()
        .filter(|id| {
            facts.names[id.name.index()].spelling == "X"
                && id.role == ResolutionIdentifierRole::Declaration
        })
        .map(|id| semantic(id.site, LoweredSemanticRole::Definition))
        .collect::<Vec<_>>();
    let references = facts
        .identifiers
        .iter()
        .filter(|id| {
            facts.names[id.name.index()].spelling == "X"
                && id.role == ResolutionIdentifierRole::Reference
        })
        .map(|id| semantic(id.site, LoweredSemanticRole::Reference))
        .collect::<Vec<_>>();
    assert_eq!(declarations.len(), 5);
    assert_eq!(references.len(), 4);
    for method in facts.identifiers.iter().filter(|id| {
        facts.names[id.name.index()].spelling == "Method"
            && id.role == ResolutionIdentifierRole::Declaration
    }) {
        assert!(
            lexical
                .semantics()
                .iter()
                .find(|s| s.site() == method.site)
                .unwrap()
                .go_definition_namespaces()
                .is_none()
        );
    }
    let source = PreloadedFragmentSource::from_lowered_fragments([lexical.clone()]);
    let engine = BatchResolutionEngine::new(&source);
    for (reference, expected) in references.into_iter().zip([
        Some(declarations[0]),
        Some(declarations[1]),
        Some(declarations[3]),
        None,
    ]) {
        let answer = engine
            .resolve_reference(
                ResolutionQuery::new(reference),
                &CancellationToken::default(),
            )
            .unwrap();
        assert_eq!(answer.targets(), expected.as_slice());
    }
}

#[test]
fn parsed_go_spelling_union_drives_runtime_and_type_object_projection() {
    use crate::analyzer::resolution::{
        LoweredSemanticRole, PreloadedFactResolutionService, ResolutionSlotValue,
    };
    use brokk_bifrost_core::analyzer::resolution_facts::{
        ResolutionIdentifierRole, ResolutionNamespace,
    };
    let facts = parse_go_spelling_facts(
        r#"package p
        type Outer struct { Member string }
        var X Outer
        func use() { _ = X.Member; type X struct { Member int }; _ = X.Member }
        func innerValue() { type X struct{}; { var X Outer; _ = X.Member } }
    "#,
    );
    let artifact = lower_for_test(
        BindingFragmentId::for_test(b"go-spelling-typed"),
        Language::Go,
        &facts,
    );
    let semantic = |site, role| {
        artifact
            .lexical()
            .semantics()
            .iter()
            .find(|s| s.site() == site && s.role() == role)
            .unwrap()
            .semantic()
    };
    let prefix_references = facts
        .identifiers
        .iter()
        .filter(|id| {
            facts.names[id.name.index()].spelling == "X"
                && id.namespace == ResolutionNamespace::TypeOrValue
        })
        .map(|id| semantic(id.site, LoweredSemanticRole::Reference))
        .collect::<Vec<_>>();
    let type_definitions = facts
        .identifiers
        .iter()
        .filter(|id| {
            id.role == ResolutionIdentifierRole::Declaration
                && id.namespace == ResolutionNamespace::Type
        })
        .map(|id| semantic(id.site, LoweredSemanticRole::Definition))
        .collect::<Vec<_>>();
    assert_eq!(prefix_references.len(), 3);
    assert_eq!(type_definitions.len(), 3);
    let members = facts
        .identifiers
        .iter()
        .filter(|id| {
            facts.names[id.name.index()].spelling == "Member"
                && id.role == ResolutionIdentifierRole::Reference
        })
        .map(|id| semantic(id.site, LoweredSemanticRole::Reference))
        .collect::<Vec<_>>();
    let outer_field = facts
        .identifiers
        .iter()
        .find(|id| {
            facts.names[id.name.index()].spelling == "Member"
                && id.role == ResolutionIdentifierRole::Declaration
        })
        .unwrap();
    let outer_field = semantic(outer_field.site, LoweredSemanticRole::Definition);
    let service = PreloadedFactResolutionService::from_lowered_fragments(
        [artifact.lexical().clone()],
        [artifact.typed().clone()],
    );
    let before = service
        .resolve_reference(prefix_references[0], &CancellationToken::default())
        .unwrap();
    let after = service
        .resolve_reference(prefix_references[1], &CancellationToken::default())
        .unwrap();
    let inner_value = service
        .resolve_reference(prefix_references[2], &CancellationToken::default())
        .unwrap();
    let values = |answer: &crate::analyzer::resolution::FactResolutionAnswer| {
        answer
            .projected_frontiers()
            .iter()
            .flat_map(|frontier| frontier.possible_values().iter().copied())
            .collect::<Vec<_>>()
    };
    assert!(
        matches!(values(&before).as_slice(), [ResolutionSlotValue::Runtime { ty, addressable: true }] if ty.identity() == type_definitions[0])
    );
    assert!(
        matches!(values(&after).as_slice(), [ResolutionSlotValue::TypeObject(ty)] if ty.identity() == type_definitions[1])
    );
    assert!(
        matches!(values(&inner_value).as_slice(), [ResolutionSlotValue::Runtime { ty, addressable: true }] if ty.identity() == type_definitions[0])
    );
    assert_eq!(members.len(), 3);
    for (member, expected) in members
        .into_iter()
        .zip([Some(outer_field), None, Some(outer_field)])
    {
        let answer = service
            .resolve_reference(member, &CancellationToken::default())
            .unwrap();
        assert_eq!(answer.binding().targets(), expected.as_slice());
    }
}

#[test]
fn parsed_go_aliases_forward_target_identity_without_nominal_alias_types() {
    use crate::analyzer::resolution::{
        LoweredSemanticRole, PreloadedFactResolutionService, ResolutionSlotValue,
    };
    use brokk_bifrost_core::analyzer::resolution_facts::{
        ResolutionIdentifierRole, ResolutionNamespace,
    };
    let facts = parse_go_spelling_facts(
        r#"package p
        type Original struct { Member int }
        type Alias = Original
        type Pointer = *Alias
        var X Alias
        var P Pointer
        func use() { _ = X.Member; _ = P.Member; type Local = Alias; var Y Local; _ = Y.Member; _ = Alias.Member }
    "#,
    );
    let artifact = lower_for_test(
        BindingFragmentId::for_test(b"go-transparent-alias"),
        Language::Go,
        &facts,
    );
    let semantic = |site, role| {
        artifact
            .lexical()
            .semantics()
            .iter()
            .find(|s| s.site() == site && s.role() == role)
            .unwrap()
            .semantic()
    };
    let definition = |name: &str| {
        let site = facts
            .identifiers
            .iter()
            .find(|id| {
                facts.names[id.name.index()].spelling == name
                    && id.role == ResolutionIdentifierRole::Declaration
            })
            .unwrap()
            .site;
        semantic(site, LoweredSemanticRole::Definition)
    };
    let original = definition("Original");
    let member = definition("Member");
    let service = PreloadedFactResolutionService::from_lowered_fragments(
        [artifact.lexical().clone()],
        [artifact.typed().clone()],
    );
    let prefixes = facts
        .identifiers
        .iter()
        .filter(|id| id.namespace == ResolutionNamespace::TypeOrValue)
        .collect::<Vec<_>>();
    assert_eq!(prefixes.len(), 4);
    for (prefix, depth) in prefixes.iter().zip([0, 1, 0, 0]) {
        let answer = service
            .resolve_reference(
                semantic(prefix.site, LoweredSemanticRole::Reference),
                &CancellationToken::default(),
            )
            .unwrap();
        let values = answer
            .projected_frontiers()
            .iter()
            .flat_map(|frontier| frontier.possible_values().iter().copied())
            .collect::<Vec<_>>();
        let spelling = &facts.names[prefix.name.index()].spelling;
        let ty = if spelling == "Alias" {
            assert_eq!(answer.binding().targets(), &[definition("Alias")]);
            let [ResolutionSlotValue::TypeObject(ty)] = values.as_slice() else {
                panic!("alias prefix must be a type object: {values:?}")
            };
            *ty
        } else {
            let [
                ResolutionSlotValue::Runtime {
                    ty,
                    addressable: true,
                },
            ] = values.as_slice()
            else {
                panic!("alias variable must have target runtime type: {values:?}")
            };
            *ty
        };
        assert_eq!(ty.identity(), original);
        assert_eq!(ty.indirection(), depth);
    }
    let members = facts
        .identifiers
        .iter()
        .filter(|id| {
            facts.names[id.name.index()].spelling == "Member"
                && id.role == ResolutionIdentifierRole::Reference
        })
        .collect::<Vec<_>>();
    assert_eq!(members.len(), 4);
    for (reference, expected) in
        members
            .into_iter()
            .zip([Some(member), Some(member), Some(member), None])
    {
        let answer = service
            .resolve_reference(
                semantic(reference.site, LoweredSemanticRole::Reference),
                &CancellationToken::default(),
            )
            .unwrap();
        assert_eq!(answer.binding().targets(), expected.as_slice());
    }
}
