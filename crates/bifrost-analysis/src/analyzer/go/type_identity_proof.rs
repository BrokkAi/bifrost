//! Exact Go assignment-conversion type identity from source and model facts.
//!
//! Go's semantic IR deliberately marks writes into already-declared bindings
//! as conversions when lowering cannot prove their source and target types are
//! identical. This module owns the bounded positive proof that can recover
//! identity later: one exact modeled result type, one explicit binding type,
//! and one parser/import/shadow resolution. Any missing fact abstains.

use super::package_identity::GoOverlayPackages;
use crate::analyzer::semantic_model::{SemanticModelCallableKey, SemanticModelOverlay, TypeRef};
use crate::analyzer::usages::get_definition::parse_go_tree;
use crate::analyzer::usages::reference_site::smallest_named_node_covering;
use crate::analyzer::{
    AnalyzerQueryScope, CodeUnitIndex, CodeUnitType, GoAnalyzer, IAnalyzer, ProjectFile,
    QueryScope, Range, StructuredTypeIdentity, resolve_analyzer,
};
use crate::hash::HashMap;
use brokk_bifrost_core::analyzer::model::{StructuredTypeNodeId, StructuredTypeNodeView};
use brokk_bifrost_go::declarations::{go_structured_type_identity, is_predeclared_go_type};
use brokk_bifrost_go::graph::reference::go_name_shadowed_at_with_scope;
use tree_sitter::Node;

/// Exact source larger than this is outside the bounded result-binding proof.
pub const GO_MODELED_RESULT_BINDING_TYPE_PROOF_MAX_SOURCE_BYTES: usize = 1024 * 1024;

/// Maximum syntax work the lexical-shadow half of one proof may consume.
pub const GO_MODELED_RESULT_BINDING_TYPE_PROOF_MAX_STEPS: usize = 100_000;

/// Conservative query work to charge before a proof-cache miss.
///
/// The charge includes the exact source bytes consumed by parsing plus the
/// explicit capped allowance admitted by the lexical-shadow walk. `None`
/// means the source is outside the proof's supported size boundary.
pub fn go_modeled_result_binding_type_identity_proof_work(source: &str) -> Option<usize> {
    (source.len() <= GO_MODELED_RESULT_BINDING_TYPE_PROOF_MAX_SOURCE_BYTES)
        .then(|| source.len().saturating_add(go_shadow_step_limit(source)))
}

fn go_shadow_step_limit(source: &str) -> usize {
    source
        .len()
        .saturating_mul(4)
        .clamp(1, GO_MODELED_RESULT_BINDING_TYPE_PROOF_MAX_STEPS)
}

/// Whether one modeled Go result and one explicitly typed binding have the
/// same exact type at the binding's source declaration.
///
/// `binding` is the source range of the binding identifier, not an assignment
/// occurrence. The model target is already the oracle's typed callable key;
/// this function never reconstructs it from a rendered signature. A partial
/// declaration pack may prove a callable it positively publishes, but model
/// conflicts, ambiguous facts, inferred bindings, unresolved imports,
/// shadowed predeclared names, and unsupported type shapes all return `false`.
#[allow(clippy::too_many_arguments)]
pub fn go_modeled_result_binding_type_identity_is_exact(
    analyzer: &dyn IAnalyzer,
    overlay: &SemanticModelOverlay,
    file: &ProjectFile,
    source: &str,
    binding: Range,
    target: SemanticModelCallableKey<'_>,
    result_ordinal: usize,
) -> bool {
    if target.language != "go"
        || go_modeled_result_binding_type_identity_proof_work(source).is_none()
    {
        return false;
    }
    let Some(parameter_count) = usize::try_from(target.parameter_count).ok() else {
        return false;
    };
    let packages = GoOverlayPackages::new(Some(overlay));
    let Some(result_type) = packages.callable_result_type_ref(
        target.owner,
        target.member,
        target.has_receiver,
        parameter_count,
        result_ordinal,
    ) else {
        return false;
    };
    go_explicit_binding_matches_modeled_result(
        analyzer,
        &packages,
        file,
        source,
        binding,
        result_type,
    )
}

#[allow(clippy::too_many_arguments)]
fn go_explicit_binding_matches_modeled_result(
    analyzer: &dyn IAnalyzer,
    packages: &GoOverlayPackages<'_>,
    file: &ProjectFile,
    source: &str,
    binding: Range,
    result_type: &TypeRef,
) -> bool {
    let Some(go) = resolve_analyzer::<GoAnalyzer>(analyzer) else {
        return false;
    };
    let Some(tree) = parse_go_tree(source) else {
        return false;
    };
    let root = tree.root_node();
    if root.has_error() {
        return false;
    }
    let Some(type_node) = explicit_binding_type_node(root, binding) else {
        return false;
    };
    let Some(target_type) = go_structured_type_identity(type_node, source) else {
        return false;
    };

    let scope = AnalyzerQueryScope::new(analyzer);
    let (imports, _dot_imports) = go.definition_import_namespaces(scope.token(), file);
    let package = go.go_package_of(file);
    let mut context = GoTypeIdentityContext {
        go,
        packages,
        source,
        root,
        type_byte: type_node.start_byte(),
        imports,
        package,
        remaining_shadow_steps: go_shadow_step_limit(source),
    };
    modeled_result_matches_target(result_type, &target_type, &mut context)
}

fn explicit_binding_type_node(root: Node<'_>, binding: Range) -> Option<Node<'_>> {
    if binding.start_byte >= binding.end_byte {
        return None;
    }
    let name = smallest_named_node_covering(root, binding.start_byte, binding.end_byte)?;
    if name.start_byte() != binding.start_byte
        || name.end_byte() != binding.end_byte
        || name.kind() != "identifier"
    {
        return None;
    }
    let declaration = name.parent()?;
    if !matches!(declaration.kind(), "var_spec" | "parameter_declaration")
        || !node_has_field_child(declaration, "name", name)
        || (declaration.kind() == "parameter_declaration"
            && parameter_has_generic_callable_context(declaration))
    {
        return None;
    }
    let type_node = declaration.child_by_field_name("type")?;
    (name.end_byte() <= type_node.start_byte()).then_some(type_node)
}

fn parameter_has_generic_callable_context(parameter: Node<'_>) -> bool {
    let mut owner = parameter.parent();
    while let Some(node) = owner {
        if matches!(
            node.kind(),
            "func_literal" | "function_declaration" | "method_declaration"
        ) {
            if node.child_by_field_name("type_parameters").is_some() {
                return true;
            }
            let Some(receiver) = node.child_by_field_name("receiver") else {
                return false;
            };
            let mut stack = vec![receiver];
            while let Some(current) = stack.pop() {
                if current.kind() == "type_arguments" {
                    return true;
                }
                let mut cursor = current.walk();
                stack.extend(current.named_children(&mut cursor));
            }
            return false;
        }
        owner = node.parent();
    }
    true
}

fn node_has_field_child(parent: Node<'_>, field: &str, target: Node<'_>) -> bool {
    (0..parent.child_count()).any(|index| {
        parent
            .child(index)
            .is_some_and(|child| child.id() == target.id())
            && parent.field_name_for_child(index as u32) == Some(field)
    })
}

struct GoTypeIdentityContext<'tree, 'source, 'context, 'overlay> {
    go: &'context GoAnalyzer,
    packages: &'context GoOverlayPackages<'overlay>,
    source: &'source str,
    root: Node<'tree>,
    type_byte: usize,
    imports: HashMap<String, Vec<String>>,
    package: Option<String>,
    remaining_shadow_steps: usize,
}

enum TypeMatchFrame<'a> {
    Type(&'a TypeRef, StructuredTypeNodeId),
    DeclaredName(&'a str, StructuredTypeNodeId),
    PredeclaredName(&'a str, StructuredTypeNodeId),
}

fn modeled_result_matches_target(
    modeled: &TypeRef,
    target: &StructuredTypeIdentity,
    context: &mut GoTypeIdentityContext<'_, '_, '_, '_>,
) -> bool {
    let mut frames = vec![TypeMatchFrame::Type(modeled, target.root_id())];
    while let Some(frame) = frames.pop() {
        match frame {
            TypeMatchFrame::Type(modeled, target_id) => match modeled {
                TypeRef::Named {
                    name,
                    arguments,
                    nullable,
                } => {
                    if *nullable || !arguments.is_empty() {
                        return false;
                    }
                    frames.push(TypeMatchFrame::PredeclaredName(name, target_id));
                }
                TypeRef::Declared {
                    id,
                    arguments,
                    nullable,
                } => {
                    if *nullable {
                        return false;
                    }
                    if arguments.is_empty() {
                        frames.push(TypeMatchFrame::DeclaredName(id, target_id));
                        continue;
                    }
                    let Some(StructuredTypeNodeView::Generic {
                        base,
                        arguments: target_arguments,
                    }) = target.view(target_id)
                    else {
                        return false;
                    };
                    if arguments.len() != target_arguments.len() {
                        return false;
                    }
                    frames.push(TypeMatchFrame::DeclaredName(id, base));
                    frames.extend(
                        arguments
                            .iter()
                            .zip(target_arguments)
                            .rev()
                            .map(|(argument, target)| TypeMatchFrame::Type(argument, *target)),
                    );
                }
                TypeRef::Pointer { element } => {
                    let Some(StructuredTypeNodeView::Pointer(target)) = target.view(target_id)
                    else {
                        return false;
                    };
                    frames.push(TypeMatchFrame::Type(element, target));
                }
                TypeRef::Slice { element } => {
                    let Some(StructuredTypeNodeView::Slice(target)) = target.view(target_id) else {
                        return false;
                    };
                    frames.push(TypeMatchFrame::Type(element, target));
                }
                TypeRef::Map { key, value } => {
                    let Some(StructuredTypeNodeView::Map {
                        key: target_key,
                        value: target_value,
                    }) = target.view(target_id)
                    else {
                        return false;
                    };
                    frames.push(TypeMatchFrame::Type(value, target_value));
                    frames.push(TypeMatchFrame::Type(key, target_key));
                }
                // StructuredTypeIdentity deliberately does not retain array
                // lengths, channel directions, function layouts, or language
                // model substitutions. Those shapes cannot establish exact Go
                // identity at this boundary.
                TypeRef::TypeParameter { .. }
                | TypeRef::Array { .. }
                | TypeRef::ByRef { .. }
                | TypeRef::FixedArray { .. }
                | TypeRef::Channel { .. }
                | TypeRef::Wildcard { .. }
                | TypeRef::Tuple { .. }
                | TypeRef::Function { .. } => return false,
            },
            TypeMatchFrame::DeclaredName(declaration_id, target_id) => {
                let Some(qualified_name) = context
                    .packages
                    .declared_type_qualified_name(declaration_id)
                else {
                    return false;
                };
                let Some(StructuredTypeNodeView::Named(target_name)) = target.view(target_id)
                else {
                    return false;
                };
                if target_name.is_absolute()
                    || !target_name.lexical_scope().is_empty()
                    || !context.declared_name_matches(target_name.path(), qualified_name)
                {
                    return false;
                }
            }
            TypeMatchFrame::PredeclaredName(name, target_id) => {
                let Some(StructuredTypeNodeView::Named(target_name)) = target.view(target_id)
                else {
                    return false;
                };
                if target_name.is_absolute() || !target_name.lexical_scope().is_empty() {
                    return false;
                }
                let [target_component] = target_name.path() else {
                    return false;
                };
                if target_component != name || !context.predeclared_name_is_exact(name) {
                    return false;
                }
            }
        }
    }
    true
}

impl GoTypeIdentityContext<'_, '_, '_, '_> {
    fn declared_name_matches(&mut self, path: &[String], modeled_name: &str) -> bool {
        match path {
            [name] => {
                !self.lexically_shadowed(name)
                    && self.package.as_ref().is_some_and(|package| {
                        let candidate = format!("{package}.{name}");
                        candidate == modeled_name
                            && self.same_package_declared_type_is_exact(&candidate)
                    })
            }
            [qualifier, name] => {
                if self.lexically_shadowed(qualifier) {
                    return false;
                }
                let Some([import_path]) = self.imports.get(qualifier).map(Vec::as_slice) else {
                    return false;
                };
                format!("{import_path}.{name}") == modeled_name
            }
            _ => false,
        }
    }

    fn same_package_declared_type_is_exact(&self, candidate: &str) -> bool {
        if !self.go.workspace_declaration_identities_authoritative() {
            return false;
        }
        let mut definitions = self.go.definitions(candidate);
        let Some(declaration) = definitions.next() else {
            return false;
        };
        declaration.kind() == CodeUnitType::Class && definitions.next().is_none()
    }

    fn predeclared_name_is_exact(&mut self, name: &str) -> bool {
        if !is_predeclared_go_type(name)
            || self.lexically_shadowed(name)
            || self.imports.contains_key(name)
            || !self.go.workspace_declaration_identities_authoritative()
        {
            return false;
        }
        self.package.as_ref().is_some_and(|package| {
            self.go
                .definitions(&format!("{package}.{name}"))
                .next()
                .is_none()
        })
    }

    fn lexically_shadowed(&mut self, name: &str) -> bool {
        go_name_shadowed_at_with_scope(self.root, self.source, self.type_byte, name, || {
            let admitted = self.remaining_shadow_steps > 0;
            self.remaining_shadow_steps = self.remaining_shadow_steps.saturating_sub(1);
            admitted
        })
        .unwrap_or(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::{Language, ProjectFile};
    use crate::test_support::AnalyzerFixture;

    fn named(name: &str) -> TypeRef {
        TypeRef::Named {
            name: name.to_owned(),
            arguments: Vec::new(),
            nullable: false,
        }
    }

    fn binding_range(source: &str, name: &str) -> Range {
        let start_byte = source.find(name).expect("binding name");
        Range {
            start_byte,
            end_byte: start_byte + name.len(),
            start_line: 0,
            end_line: 0,
        }
    }

    fn binding_matches(
        fixture: &AnalyzerFixture,
        source: &str,
        binding: &str,
        result: &TypeRef,
    ) -> bool {
        let file = ProjectFile::new(fixture.project_root(), "main.go");
        let packages = GoOverlayPackages::new(None);
        go_explicit_binding_matches_modeled_result(
            fixture.analyzer.analyzer(),
            &packages,
            &file,
            source,
            binding_range(source, binding),
            result,
        )
    }

    #[test]
    fn explicit_unshadowed_error_is_exact_but_inference_and_wrapper_changes_abstain() {
        let source = r#"package main

func run() {
    var exact error
    var inferred = exact
    var boxed any
}
"#;
        let fixture = AnalyzerFixture::new_for_language(
            Language::Go,
            &[("go.mod", "module example.com/app\n"), ("main.go", source)],
        );

        assert!(binding_matches(&fixture, source, "exact", &named("error")));
        assert!(!binding_matches(
            &fixture,
            source,
            "inferred",
            &named("error")
        ));
        assert!(!binding_matches(&fixture, source, "boxed", &named("error")));
        assert!(!binding_matches(
            &fixture,
            source,
            "boxed",
            &TypeRef::Pointer {
                element: Box::new(named("error")),
            }
        ));
    }

    #[test]
    fn lexical_type_const_and_parameter_shadows_keep_predeclared_error_open() {
        for (source, label) in [
            (
                r#"package main
func run() {
    type error struct{}
    var typed error
}
"#,
                "local type",
            ),
            (
                r#"package main
func run() {
    const error = 1
    var typed error
}
"#,
                "local const",
            ),
            (
                r#"package main
func run(error int) {
    var typed error
}
"#,
                "parameter",
            ),
        ] {
            let fixture = AnalyzerFixture::new_for_language(
                Language::Go,
                &[("go.mod", "module example.com/app\n"), ("main.go", source)],
            );
            assert!(
                !binding_matches(&fixture, source, "typed", &named("error")),
                "{label} must shadow the universe type"
            );
        }
    }

    #[test]
    fn expression_case_type_shadow_ends_before_sibling_and_post_switch_bindings() {
        let source = r#"package main
func run(choice int) {
    switch choice {
    case 0:
        type error struct{}
        var shadowed error
        _ = shadowed
    case 1:
        var sibling error
        _ = sibling
    }
    var after error
    _ = after
}
"#;
        let fixture = AnalyzerFixture::new_for_language(
            Language::Go,
            &[("go.mod", "module example.com/app\n"), ("main.go", source)],
        );

        assert!(
            !binding_matches(&fixture, source, "shadowed", &named("error")),
            "a case-local type must shadow the universe error type within its own clause"
        );
        assert!(
            binding_matches(&fixture, source, "sibling", &named("error")),
            "a case-local type must not poison a sibling clause's exact type proof"
        );
        assert!(
            binding_matches(&fixture, source, "after", &named("error")),
            "a case-local type must not poison the post-switch exact type proof"
        );
    }

    #[test]
    fn package_declaration_in_another_file_and_import_binding_shadow_error() {
        let package_source = r#"package main
func run() {
    var typed error
}
"#;
        let package_fixture = AnalyzerFixture::new_for_language(
            Language::Go,
            &[
                ("go.mod", "module example.com/app\n"),
                ("main.go", package_source),
                ("shadow.go", "package main\ntype error struct{}\n"),
            ],
        );
        assert!(!binding_matches(
            &package_fixture,
            package_source,
            "typed",
            &named("error")
        ));

        let import_source = r#"package main
import error "net"
func run() {
    var typed error
}
"#;
        let import_fixture = AnalyzerFixture::new_for_language(
            Language::Go,
            &[
                ("go.mod", "module example.com/app\n"),
                ("main.go", import_source),
            ],
        );
        assert!(!binding_matches(
            &import_fixture,
            import_source,
            "typed",
            &named("error")
        ));
    }

    #[test]
    fn variadic_and_generic_parameter_bindings_abstain() {
        for (source, label) in [
            (
                r#"package main
func run(typed ...error) {}
"#,
                "variadic parameter",
            ),
            (
                r#"package main
func run[error interface{ ~int }](typed error) {}
"#,
                "generic parameter",
            ),
        ] {
            let fixture = AnalyzerFixture::new_for_language(
                Language::Go,
                &[("go.mod", "module example.com/app\n"), ("main.go", source)],
            );
            assert!(
                !binding_matches(&fixture, source, "typed", &named("error")),
                "{label} must stay outside the exact binding proof"
            );
        }
    }

    #[test]
    fn declared_name_resolution_uses_exact_import_alias_and_rejects_shadowing() {
        fn resolved(source: &str, extra_file: Option<(&str, &str)>, modeled_name: &str) -> bool {
            let mut files = vec![("go.mod", "module example.com/app\n"), ("main.go", source)];
            files.extend(extra_file);
            let fixture = AnalyzerFixture::new_for_language(Language::Go, &files);
            let analyzer = fixture.analyzer.analyzer();
            let go = resolve_analyzer::<GoAnalyzer>(analyzer).expect("Go analyzer");
            let file = ProjectFile::new(fixture.project_root(), "main.go");
            let binding = binding_range(source, "conn");
            let tree = parse_go_tree(source).expect("Go tree");
            let root = tree.root_node();
            let type_node = explicit_binding_type_node(root, binding).expect("explicit type");
            let identity = go_structured_type_identity(type_node, source).expect("type identity");
            let StructuredTypeNodeView::Named(name) =
                identity.view(identity.root_id()).expect("identity root")
            else {
                panic!("qualified type is named")
            };
            let scope = AnalyzerQueryScope::new(analyzer);
            let (imports, _) = go.definition_import_namespaces(scope.token(), &file);
            let packages = GoOverlayPackages::new(None);
            GoTypeIdentityContext {
                go,
                packages: &packages,
                source,
                root,
                type_byte: type_node.start_byte(),
                imports,
                package: go.go_package_of(&file),
                remaining_shadow_steps: go_shadow_step_limit(source),
            }
            .declared_name_matches(name.path(), modeled_name)
        }

        assert!(resolved(
            r#"package main
import network "net"
func run() {
    var conn network.Listener
}
"#,
            None,
            "net.Listener",
        ));
        assert!(!resolved(
            r#"package main
import network "net"
func run(network int) {
    var conn network.Listener
}
"#,
            None,
            "net.Listener",
        ));
        assert!(resolved(
            r#"package main
type Name struct{}
func run() {
    var conn Name
}
"#,
            None,
            "example.com/app.Name",
        ));
        assert!(!resolved(
            r#"package main
func Name() {}
func run() {
    var conn Name
}
"#,
            None,
            "example.com/app.Name",
        ));
        assert!(!resolved(
            r#"package main
type Name struct{}
func run() {
    var conn Name
}
"#,
            Some(("duplicate.go", "package main\ntype Name int\n")),
            "example.com/app.Name",
        ));
    }
}
