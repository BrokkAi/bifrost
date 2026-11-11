//! Source-backed alias expansion shared by conversion and outer-route consumers.
//! These nodes retain lexical provenance; canonical identities remain RustConversionType.
use brokk_bifrost_analysis::analyzer::structural::provider::StructuralSyntaxLimitedOutcome;
use brokk_bifrost_analysis::analyzer::usages::get_definition::{
    DefinitionLookupRequest, DefinitionLookupStatus, UnindexedClaimKind,
    resolve_definition_batch_with_source_and_cancellation,
};
use brokk_bifrost_analysis::analyzer::{IAnalyzer, Language, ProjectFile};
use std::{collections::HashMap, sync::Arc};
use tree_sitter::Node;

#[derive(Clone)]
pub(crate) struct TypeSite {
    pub(crate) file: ProjectFile,
    pub(crate) source: Arc<str>,
    pub(crate) kind: String,
    pub(crate) start: usize,
    pub(crate) end: usize,
}

impl TypeSite {
    fn new(node: Node<'_>, file: &ProjectFile, source: &Arc<str>) -> Self {
        Self {
            file: file.clone(),
            source: Arc::clone(source),
            kind: node.kind().to_owned(),
            start: node.start_byte(),
            end: node.end_byte(),
        }
    }

    fn simple_name(&self) -> Option<&str> {
        (matches!(self.kind.as_str(), "type_identifier" | "identifier"))
            .then(|| self.source.get(self.start..self.end))
            .flatten()
            .map(|name| name.strip_prefix("r#").unwrap_or(name))
    }
}

#[derive(Clone)]
pub(crate) enum AliasTypeExpr {
    Constructor {
        site: TypeSite,
        arguments: Vec<Self>,
    },
    Shape {
        site: TypeSite,
        arguments: Vec<Self>,
    },
    Indirect,
    Lifetime,
    Other,
    Reference {
        mutable: bool,
        referent: Box<Self>,
    },
}

// A bounded, source-backed type syntax tree. Only the outer constructor is
// admitted; arguments are retained so aliases such as Identity<T> = T can
// substitute their exact supplied instance before constructor selection.
//
// The budget bounds the node count, not the stack: a formal nested to the
// budget is as deep as the budget, so every walk over these trees uses an
// explicit stack. Each node is charged in pre-order, before its children.
pub(crate) fn alias_type_expr(
    node: Node<'_>,
    file: &ProjectFile,
    source: &Arc<str>,
    remaining: &mut usize,
) -> Option<AliasTypeExpr> {
    let mut pending = vec![AliasStep::Visit(node)];
    let mut built = Vec::new();
    while let Some(step) = pending.pop() {
        let node = match step {
            AliasStep::Visit(node) => node,
            AliasStep::Assemble(assemble) => {
                assemble.finish(&mut built);
                continue;
            }
        };
        *remaining = remaining.checked_sub(1)?;
        match node.kind() {
            "reference_type" => {
                let referent = brokk_bifrost_rust::ownership::rust_reference_type_referent(node)?;
                pending.push(AliasStep::Assemble(AliasAssemble::Reference {
                    mutable: brokk_bifrost_rust::ownership::rust_reference_is_mutable(node),
                }));
                pending.push(AliasStep::Visit(referent));
            }
            "unit_type" | "tuple_type" | "array_type" => {
                let children = if node.kind() == "array_type" {
                    vec![node.child_by_field_name("element")?]
                } else {
                    node.named_children(&mut node.walk())
                        .filter(|child| !child.is_extra())
                        .collect()
                };
                pending.push(AliasStep::Assemble(AliasAssemble::Shape {
                    site: TypeSite::new(node, file, source),
                    arity: children.len(),
                }));
                pending.extend(children.into_iter().rev().map(AliasStep::Visit));
            }
            "pointer_type" => built.push(AliasTypeExpr::Indirect),
            "lifetime" => built.push(AliasTypeExpr::Lifetime),
            "primitive_type"
            | "type_identifier"
            | "identifier"
            | "scoped_type_identifier"
            | "scoped_identifier" => built.push(AliasTypeExpr::Constructor {
                site: TypeSite::new(node, file, source),
                arguments: Vec::new(),
            }),
            "generic_type" | "generic_type_with_turbofish" => {
                let head = node.child_by_field_name("type").or_else(|| {
                    let mut cursor = node.walk();
                    node.named_children(&mut cursor).next()
                })?;
                if !matches!(
                    head.kind(),
                    "type_identifier"
                        | "identifier"
                        | "scoped_type_identifier"
                        | "scoped_identifier"
                ) {
                    built.push(AliasTypeExpr::Other);
                    continue;
                }
                let arguments_node = node.child_by_field_name("type_arguments")?;
                let mut cursor = arguments_node.walk();
                let arguments = arguments_node
                    .named_children(&mut cursor)
                    .filter(|argument| !argument.is_extra())
                    .collect::<Vec<_>>();
                pending.push(AliasStep::Assemble(AliasAssemble::Constructor {
                    site: TypeSite::new(head, file, source),
                    arity: arguments.len(),
                }));
                pending.extend(arguments.into_iter().rev().map(AliasStep::Visit));
            }
            _ => built.push(AliasTypeExpr::Other),
        }
    }
    let expression = built.pop();
    assert!(built.is_empty(), "alias type walk leaves one root");
    expression
}

// One step of an explicit-stack walk: visit an input node, or assemble a
// visited node from the results its children left on the output stack.
enum AliasStep<T> {
    Visit(T),
    Assemble(AliasAssemble),
}

enum AliasAssemble {
    Constructor { site: TypeSite, arity: usize },
    Shape { site: TypeSite, arity: usize },
    Reference { mutable: bool },
}

impl AliasAssemble {
    fn finish(self, built: &mut Vec<AliasTypeExpr>) {
        let expression = match self {
            Self::Constructor { site, arity } => AliasTypeExpr::Constructor {
                site,
                arguments: built.split_off(built.len() - arity),
            },
            Self::Shape { site, arity } => AliasTypeExpr::Shape {
                site,
                arguments: built.split_off(built.len() - arity),
            },
            Self::Reference { mutable } => AliasTypeExpr::Reference {
                mutable,
                referent: Box::new(built.pop().expect("a reference has a built referent")),
            },
        };
        built.push(expression);
    }
}

fn substitute_alias_type(
    expression: &AliasTypeExpr,
    bindings: &HashMap<String, AliasTypeExpr>,
    remaining: &mut usize,
) -> Option<AliasTypeExpr> {
    // A replacement is copied as written: its own parameter names belong to
    // the caller's scope and are not substituted again.
    let unbound = HashMap::new();
    let mut pending = vec![AliasStep::Visit((expression, bindings))];
    let mut built = Vec::new();
    while let Some(step) = pending.pop() {
        let (expression, bindings) = match step {
            AliasStep::Visit(visit) => visit,
            AliasStep::Assemble(assemble) => {
                assemble.finish(&mut built);
                continue;
            }
        };
        *remaining = remaining.checked_sub(1)?;
        match expression {
            AliasTypeExpr::Constructor { site, arguments } => {
                if arguments.is_empty()
                    && let Some(replacement) =
                        site.simple_name().and_then(|name| bindings.get(name))
                {
                    pending.push(AliasStep::Visit((replacement, &unbound)));
                    continue;
                }
                pending.push(AliasStep::Assemble(AliasAssemble::Constructor {
                    site: site.clone(),
                    arity: arguments.len(),
                }));
                pending.extend(
                    arguments
                        .iter()
                        .rev()
                        .map(|argument| AliasStep::Visit((argument, bindings))),
                );
            }
            AliasTypeExpr::Shape { site, arguments } => {
                pending.push(AliasStep::Assemble(AliasAssemble::Shape {
                    site: site.clone(),
                    arity: arguments.len(),
                }));
                pending.extend(
                    arguments
                        .iter()
                        .rev()
                        .map(|argument| AliasStep::Visit((argument, bindings))),
                );
            }
            AliasTypeExpr::Reference { mutable, referent } => {
                pending.push(AliasStep::Assemble(AliasAssemble::Reference {
                    mutable: *mutable,
                }));
                pending.push(AliasStep::Visit((referent, bindings)));
            }
            AliasTypeExpr::Indirect => built.push(AliasTypeExpr::Indirect),
            AliasTypeExpr::Lifetime => built.push(AliasTypeExpr::Lifetime),
            AliasTypeExpr::Other => built.push(AliasTypeExpr::Other),
        }
    }
    let expression = built.pop();
    assert!(built.is_empty(), "alias type rebuild leaves one root");
    expression
}

fn clone_alias_type(expression: &AliasTypeExpr, remaining: &mut usize) -> Option<AliasTypeExpr> {
    substitute_alias_type(expression, &HashMap::new(), remaining)
}

pub(crate) fn expand_alias_head(
    analyzer: &dyn IAnalyzer,
    expression: AliasTypeExpr,
    cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
    depth: usize,
    strict: bool,
) -> Result<AliasTypeExpr, ExternalRoute> {
    expand_alias_head_with_work(analyzer, expression, cancellation, depth, strict, None)
}

// Both consumers use this walk. The outer-route contract retains its per-hop
// syntax bound; canonical projection supplies one operation-wide work budget.
pub(super) fn expand_alias_head_with_work(
    analyzer: &dyn IAnalyzer,
    expression: AliasTypeExpr,
    cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
    depth: usize,
    strict: bool,
    mut work: Option<&mut usize>,
) -> Result<AliasTypeExpr, ExternalRoute> {
    if cancellation.is_cancelled() {
        return Err(ExternalRoute::Unavailable);
    }
    let AliasTypeExpr::Constructor { site, arguments } = expression else {
        return Ok(expression);
    };
    let prepared = analyzer
        .structural_fact_providers()
        .into_iter()
        .find(|provider| provider.structural_language() == Language::Rust)
        .map(|provider| {
            provider.structural_syntax_limited(&site.file, 1_048_576, Some(cancellation))
        });
    let prepared = match prepared {
        Some(StructuralSyntaxLimitedOutcome::Available(syntax)) => syntax.into_inner(),
        Some(
            StructuralSyntaxLimitedOutcome::Cancelled
            | StructuralSyntaxLimitedOutcome::Exceeded { .. },
        ) => return Err(ExternalRoute::Unavailable),
        _ => return Err(ExternalRoute::Rejected),
    };
    if prepared.source() != site.source.as_ref() {
        return Err(ExternalRoute::Rejected);
    }
    let node = match exact_node(
        prepared.tree().root_node(),
        &site.kind,
        site.start,
        site.end,
    ) {
        Ok(Some(node)) => node,
        Ok(None) => return Err(ExternalRoute::Rejected),
        Err(()) => return Err(ExternalRoute::Unavailable),
    };
    match selected_external_route(analyzer, &site.file, &site.source, node, cancellation) {
        ExternalRoute::LocalDefinition(definition) => {
            let alias_file = definition.source().clone();
            let prepared = analyzer
                .structural_fact_providers()
                .into_iter()
                .find(|provider| provider.structural_language() == Language::Rust)
                .map(|provider| {
                    provider.structural_syntax_limited(&alias_file, 1_048_576, Some(cancellation))
                });
            let prepared = match prepared {
                Some(StructuralSyntaxLimitedOutcome::Available(syntax)) => syntax.into_inner(),
                Some(
                    StructuralSyntaxLimitedOutcome::Cancelled
                    | StructuralSyntaxLimitedOutcome::Exceeded { .. },
                ) => return Err(ExternalRoute::Unavailable),
                _ => return Err(ExternalRoute::Rejected),
            };
            if alias_file == site.file && prepared.source() != site.source.as_ref() {
                return Err(ExternalRoute::Rejected);
            }
            let (ranges, _, incomplete) = analyzer.ranges_with_limit(&definition, 8, cancellation);
            if cancellation.is_cancelled() {
                return Err(ExternalRoute::Unavailable);
            }
            if incomplete {
                return Err(ExternalRoute::Unavailable);
            }
            if ranges.len() != 1 {
                return Err(ExternalRoute::Rejected);
            }
            let range = ranges[0];
            let Some(mut alias) = prepared
                .tree()
                .root_node()
                .named_descendant_for_byte_range(range.start_byte, range.end_byte)
            else {
                return Err(ExternalRoute::Rejected);
            };
            let nominal = matches!(alias.kind(), "struct_item" | "enum_item" | "union_item");
            while !nominal && alias.kind() != "type_item" {
                let Some(parent) = alias.parent() else {
                    return Err(ExternalRoute::Rejected);
                };
                alias = parent;
            }
            if !nominal {
                // The selected declaration and its syntax are recorded reads.
                // Further alias-specific target/import lookups can consult
                // unrecorded inventories (#10952); keep those products out of
                // retained caches without changing plain nominal reuse.
                analyzer.refuse_read_reuse();
                // Count actual alias steps, independently of conversion depth.
                if depth >= 8 {
                    return Err(ExternalRoute::Unavailable);
                }
            }
            let Some(name) = alias.child_by_field_name("name") else {
                return Err(ExternalRoute::Rejected);
            };
            if prepared.source().get(name.start_byte()..name.end_byte())
                != Some(definition.terminal_name())
            {
                return Err(ExternalRoute::Rejected);
            }
            let alias_source = Arc::<str>::from(prepared.source());
            let mut local_remaining = 256;
            let remaining = work.as_deref_mut().unwrap_or(&mut local_remaining);
            let mut bindings = HashMap::new();
            let mut supplied = arguments.into_iter().peekable();
            let mut instantiated = Vec::new();
            if let Some(parameter_list) = alias.child_by_field_name("type_parameters") {
                let mut cursor = parameter_list.walk();
                for parameter in parameter_list
                    .named_children(&mut cursor)
                    .filter(|parameter| !parameter.is_extra() && parameter.kind() != "attributes")
                {
                    match parameter.kind() {
                        "type_parameter" => {
                            let Some(name) = parameter.child_by_field_name("name") else {
                                return Err(ExternalRoute::Rejected);
                            };
                            let Some(spelling) =
                                alias_source.get(name.start_byte()..name.end_byte())
                            else {
                                return Err(ExternalRoute::Rejected);
                            };
                            let spelling = spelling.strip_prefix("r#").unwrap_or(spelling);
                            let argument = match supplied.next() {
                                Some(AliasTypeExpr::Lifetime) => {
                                    return Err(ExternalRoute::Rejected);
                                }
                                Some(argument) => argument,
                                None => {
                                    let Some(default) =
                                        parameter.child_by_field_name("default_type")
                                    else {
                                        return Err(ExternalRoute::Rejected);
                                    };
                                    let Some(default) = alias_type_expr(
                                        default,
                                        &alias_file,
                                        &alias_source,
                                        remaining,
                                    ) else {
                                        return Err(ExternalRoute::Unavailable);
                                    };
                                    let Some(expanded) =
                                        substitute_alias_type(&default, &bindings, remaining)
                                    else {
                                        return Err(ExternalRoute::Unavailable);
                                    };
                                    expanded
                                }
                            };
                            if nominal {
                                let instance = if strict {
                                    clone_alias_type(&argument, remaining)
                                        .ok_or(ExternalRoute::Unavailable)?
                                } else {
                                    argument.clone()
                                };
                                instantiated.push(instance);
                            }
                            if bindings.insert(spelling.to_owned(), argument).is_some() {
                                return Err(ExternalRoute::Rejected);
                            }
                        }
                        "lifetime" | "lifetime_parameter" => {
                            // Rust elides lifetime arguments at a type use.
                            // Consume one only when the next supplied syntax
                            // is actually a lifetime.
                            if matches!(supplied.peek(), Some(AliasTypeExpr::Lifetime)) {
                                supplied.next();
                            }
                        }
                        "const_parameter" => {
                            if strict {
                                return Err(ExternalRoute::Rejected);
                            }
                            let has_default = parameter.child_by_field_name("value").is_some();
                            match supplied.next() {
                                Some(AliasTypeExpr::Lifetime) => {
                                    return Err(ExternalRoute::Rejected);
                                }
                                Some(_) => {}
                                None if !has_default => return Err(ExternalRoute::Rejected),
                                None => {}
                            }
                        }
                        _ => return Err(ExternalRoute::Rejected),
                    }
                }
            }
            if supplied.next().is_some() {
                return Err(ExternalRoute::Rejected);
            }
            if nominal {
                return Ok(AliasTypeExpr::Constructor {
                    site,
                    arguments: instantiated,
                });
            }
            let Some(target) = alias.child_by_field_name("type") else {
                return Err(ExternalRoute::Rejected);
            };
            let Some(target) = alias_type_expr(target, &alias_file, &alias_source, remaining)
            else {
                return Err(ExternalRoute::Unavailable);
            };
            let Some(expanded) = substitute_alias_type(&target, &bindings, remaining) else {
                return Err(ExternalRoute::Unavailable);
            };
            expand_alias_head_with_work(analyzer, expanded, cancellation, depth + 1, strict, work)
        }
        ExternalRoute::Unavailable => Err(ExternalRoute::Unavailable),
        _ => Ok(AliasTypeExpr::Constructor { site, arguments }),
    }
}

pub(crate) fn selected_formal_route(
    analyzer: &dyn IAnalyzer,
    expression: AliasTypeExpr,
    cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
    depth: usize,
) -> ExternalRoute {
    let expression = match expand_alias_head(analyzer, expression, cancellation, depth, false) {
        Ok(expression) => expression,
        Err(route) => return route,
    };
    let AliasTypeExpr::Constructor { site, .. } = expression else {
        return ExternalRoute::Rejected;
    };
    let prepared = analyzer
        .structural_fact_providers()
        .into_iter()
        .find(|provider| provider.structural_language() == Language::Rust)
        .map(|provider| {
            provider.structural_syntax_limited(&site.file, 1_048_576, Some(cancellation))
        });
    let Some(StructuralSyntaxLimitedOutcome::Available(prepared)) = prepared else {
        return ExternalRoute::Unavailable;
    };
    let prepared = prepared.into_inner();
    if prepared.source() != site.source.as_ref() {
        return ExternalRoute::Rejected;
    }
    match exact_node(
        prepared.tree().root_node(),
        &site.kind,
        site.start,
        site.end,
    ) {
        Ok(Some(node)) => {
            selected_external_route(analyzer, &site.file, &site.source, node, cancellation)
        }
        Ok(None) => ExternalRoute::Rejected,
        Err(()) => ExternalRoute::Unavailable,
    }
}
pub(crate) fn exact_node<'tree>(
    root: Node<'tree>,
    kind: &str,
    start: usize,
    end: usize,
) -> Result<Option<Node<'tree>>, ()> {
    let mut pending = vec![root];
    let mut inspected = 0;
    while let Some(node) = pending.pop() {
        inspected += 1;
        if inspected > 100_000 {
            return Err(());
        }
        if node.start_byte() == start && node.end_byte() == end && node.kind() == kind {
            return Ok(Some(node));
        }
        if node.start_byte() > start || node.end_byte() < end {
            continue;
        }
        let mut cursor = node.walk();
        pending.extend(node.named_children(&mut cursor));
    }
    Ok(None)
}

pub(crate) enum ExternalRoute {
    Selected(String),
    LocalDefinition(brokk_bifrost_analysis::analyzer::CodeUnit),
    Rejected,
    Unavailable,
}

pub(crate) fn selected_external_route(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &Arc<str>,
    node: Node<'_>,
    cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
) -> ExternalRoute {
    let Some(leaf) = lookup_leaf(node) else {
        return ExternalRoute::Rejected;
    };
    let answers = resolve_definition_batch_with_source_and_cancellation(
        analyzer,
        vec![DefinitionLookupRequest {
            file: file.clone(),
            line: None,
            column: None,
            start_byte: Some(leaf.start_byte()),
            end_byte: Some(leaf.end_byte()),
        }],
        file.clone(),
        Arc::clone(source),
        cancellation,
    );
    let Some(answer) = answers.first() else {
        return ExternalRoute::Unavailable;
    };
    if matches!(
        answer.status,
        DefinitionLookupStatus::Cancelled | DefinitionLookupStatus::ExceededBudget(_)
    ) {
        return ExternalRoute::Unavailable;
    }
    if answer.status == DefinitionLookupStatus::Resolved
        && answer.definitions.len() == 1
        && answer.modeled_definitions.is_empty()
        && answer.lexical_definition.is_none()
    {
        return ExternalRoute::LocalDefinition(answer.definitions[0].clone());
    }
    if answer.status != DefinitionLookupStatus::UnresolvableImportBoundary
        || !answer.definitions.is_empty()
        || !answer.modeled_definitions.is_empty()
    {
        return ExternalRoute::Rejected;
    }
    let [diagnostic] = answer.diagnostics.as_slice() else {
        return ExternalRoute::Rejected;
    };
    if diagnostic.kind != "unindexed_import_boundary" {
        return ExternalRoute::Rejected;
    }
    let Some(claim) = diagnostic.claim.as_ref() else {
        // Explicit scoped paths can reach an unindexed declared dependency
        // without an import claim. The resolver still proves that no local or
        // modeled declaration won. Use only the exact parsed route text.
        if answer.reference.as_ref().is_some_and(|reference| {
            source.get(node.start_byte()..node.end_byte()) == Some(reference.text.as_str())
                || reference_selects_owner(node, source, reference)
        }) && let Some(parts) = structured_route(node, source)
            && parts.len() >= 2
        {
            // An unindexed boundary is not proof that a block-local item or
            // import did not shadow the external root. Reuse the shared lexical
            // inventory; only native resolution may establish a local identity.
            let rust = brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer::<
                super::super::RustAnalyzer,
            >(analyzer)
            .expect("Rust selected types require a Rust analyzer");
            let caches = rust.inner.adapter().lexical_caches();
            let root = brokk_bifrost_core::analyzer::tree_walk::root_node(node);
            let scope = brokk_bifrost_rust::lexical_scope::rust_lexical_scope_index_with(
                caches, root, source,
            );
            // Parent-module items are not inherited by child modules. The
            // index compares the stored module identity as well as block bounds.
            // Globs are omitted by the import helper: under the #11036 compiling-
            // code assumption, a glob competing with an extern-prelude root is
            // an E0659 ambiguity in Rust 2018 and later.
            if scope.item_bound_at(&parts[0], node.start_byte())
                || !brokk_bifrost_rust::lexical_scope::visible_import_declarations_in_tree_with(
                    caches,
                    root,
                    source,
                    node.start_byte(),
                    &parts[0],
                )
                .is_empty()
            {
                return ExternalRoute::Rejected;
            }
            return ExternalRoute::Selected(
                super::super::crate_identity::RustOverlayCrates::pack_name(&parts),
            );
        }
        return ExternalRoute::Rejected;
    };
    let [subject] = claim.subjects.as_slice() else {
        return ExternalRoute::Rejected;
    };
    if claim.kind == UnindexedClaimKind::ExternalBoundary && subject.contains('.') {
        ExternalRoute::Selected(subject.clone())
    } else {
        ExternalRoute::Rejected
    }
}

pub(crate) fn structured_route(node: Node<'_>, source: &str) -> Option<Vec<String>> {
    use brokk_bifrost_rust::graph_support::{rust_path_is_leading_absolute, rust_path_segments};
    if rust_path_is_leading_absolute(node) {
        return None;
    }
    rust_path_segments(node)?
        .into_iter()
        .map(|segment| {
            if !matches!(segment.kind(), "identifier" | "type_identifier") {
                return None;
            }
            let written = source.get(segment.start_byte()..segment.end_byte())?;
            let name = written.strip_prefix("r#").unwrap_or(written);
            (!name.is_empty()).then(|| name.to_owned())
        })
        .collect()
}

pub(crate) fn lookup_leaf(mut node: Node<'_>) -> Option<Node<'_>> {
    while matches!(node.kind(), "scoped_identifier" | "scoped_type_identifier") {
        node = node.child_by_field_name("name")?;
    }
    matches!(node.kind(), "identifier" | "type_identifier").then_some(node)
}

// A qualifier can be the owner of the resolver's whole scoped expression
// (`rabbit::Rabbit` inside `rabbit::Rabbit::new`). Accept that evidence only
// through AST path edges and the exact selected leaf; text prefixes cannot
// establish which owner the resolver selected.
fn reference_selects_owner(
    qualifier: Node<'_>,
    source: &str,
    reference: &brokk_bifrost_core::analyzer::usages::reference_site::ResolvedReferenceSite,
) -> bool {
    let Some(leaf) = lookup_leaf(qualifier) else {
        return false;
    };
    if reference.focus_start_byte != leaf.start_byte()
        || reference.focus_end_byte != leaf.end_byte()
    {
        return false;
    }
    let mut owner = qualifier;
    while let Some(parent) = owner.parent() {
        let owner_edge = match parent.kind() {
            "generic_type" | "generic_type_with_turbofish" => {
                parent.child_by_field_name("type") == Some(owner)
            }
            "scoped_identifier" | "scoped_type_identifier" => {
                parent.child_by_field_name("path") == Some(owner)
            }
            _ => false,
        };
        if !owner_edge {
            return false;
        }
        if parent.byte_range() == (reference.range.start_byte..reference.range.end_byte)
            && source.get(parent.start_byte()..parent.end_byte()) == Some(reference.text.as_str())
        {
            return true;
        }
        owner = parent;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_core::analyzer::{Range, usages::reference_site::ResolvedReferenceSite};

    #[test]
    fn enclosing_external_reference_requires_exact_owner_and_focus() {
        let source = "fn run() { rabbit::Rabbit::new(); rc5::RC5_32_12_16::new(); rabbit::RabbitX::new(); cbc::Encryptor::<des::Des>::new(); }";
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let expression = |text: &str| {
            let start = source.find(text).unwrap();
            tree.root_node()
                .named_descendant_for_byte_range(start, start + text.len())
                .unwrap()
        };
        let make_reference = |node: Node<'_>| {
            let owner = node.child_by_field_name("path").unwrap();
            let owner = owner.child_by_field_name("type").unwrap_or(owner);
            let leaf = lookup_leaf(owner).unwrap();
            ResolvedReferenceSite {
                path: "src/lib.rs".into(),
                text: source[node.byte_range()].into(),
                range: Range {
                    start_byte: node.start_byte(),
                    end_byte: node.end_byte(),
                    start_line: 1,
                    end_line: 1,
                },
                focus_start_byte: leaf.start_byte(),
                focus_end_byte: leaf.end_byte(),
            }
        };
        for spelling in [
            "rabbit::Rabbit::new",
            "rc5::RC5_32_12_16::new",
            "cbc::Encryptor::<des::Des>::new",
        ] {
            let scoped = expression(spelling);
            let owner = scoped.child_by_field_name("path").unwrap();
            let owner = owner.child_by_field_name("type").unwrap_or(owner);
            assert!(reference_selects_owner(
                owner,
                source,
                &make_reference(scoped)
            ));
        }
        let generic = expression("cbc::Encryptor::<des::Des>::new");
        let generic_owner = generic.child_by_field_name("path").unwrap();
        let head = generic_owner.child_by_field_name("type").unwrap();
        let mut argument_focus = make_reference(generic);
        let argument = expression("des::Des");
        let argument_leaf = lookup_leaf(argument).unwrap();
        argument_focus.focus_start_byte = argument_leaf.start_byte();
        argument_focus.focus_end_byte = argument_leaf.end_byte();
        assert!(!reference_selects_owner(head, source, &argument_focus));
        let scoped = expression("rabbit::Rabbit::new");
        let owner = scoped.child_by_field_name("path").unwrap();
        let reference = make_reference(scoped);
        let mut different_focus = reference.clone();
        let root = owner.child_by_field_name("path").unwrap();
        different_focus.focus_start_byte = root.start_byte();
        different_focus.focus_end_byte = root.end_byte();
        assert!(!reference_selects_owner(owner, source, &different_focus));
        let mut not_an_ancestor = make_reference(expression("rabbit::RabbitX::new"));
        not_an_ancestor.focus_start_byte = reference.focus_start_byte;
        not_an_ancestor.focus_end_byte = reference.focus_end_byte;
        assert!(!reference_selects_owner(owner, source, &not_an_ancestor));
        let mut textual_near_miss = reference;
        textual_near_miss.text = "rabbit::RabbitX::new".into();
        assert!(!reference_selects_owner(owner, source, &textual_near_miss));
    }
}
