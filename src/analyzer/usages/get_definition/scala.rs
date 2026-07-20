use super::*;
use crate::analyzer::ImportInfo;
use crate::analyzer::scala::{ScalaSupertypeLookupPath, scala_type_lookup_segments};
use crate::analyzer::usages::scala_graph::syntax::{
    call_arities_for_reference, call_arity_for_reference, scala_source_facts,
};
use crate::analyzer::usages::scala_graph::{
    method_call_arity_applies, method_signature_arity, resolved_extension_receiver_type,
};
use crate::analyzer::usages::target_kind::TypeLookupTargetKind;
use std::collections::VecDeque;

struct ForwardScalaExtensionMethod {
    fqn: String,
    receiver_type: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ScalaOwnerKind {
    Class,
    SingletonObject,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ScalaOwnerIdentity {
    fqn: String,
    kind: ScalaOwnerKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ScalaNameResolution {
    Resolved(ScalaOwnerIdentity),
    MissingExplicitImport,
    Ambiguous,
    Unresolved,
}

/// Request-scoped, candidate-query replacement for Scala's global inverted
/// graph resolver.  It resolves only names visible from one file and never
/// enumerates a package or builds `ProjectTypes`.
struct ForwardScalaNameResolver<'a> {
    scala: &'a ScalaAnalyzer,
    support: &'a dyn BoundedDefinitionLookup,
    package: Arc<str>,
    imports: Arc<Vec<ImportInfo>>,
}

type ScalaNameResolver<'a> = ForwardScalaNameResolver<'a>;

impl<'a> ForwardScalaNameResolver<'a> {
    fn for_file(
        scala: &'a ScalaAnalyzer,
        support: &'a dyn BoundedDefinitionLookup,
        file: &ProjectFile,
    ) -> Self {
        Self::for_batch(
            scala,
            support,
            &ScalaDefinitionContext {
                package: Arc::from(scala_package_name_of(scala, file).unwrap_or_default()),
                imports: Arc::new(scala.import_info_of(file)),
            },
        )
    }

    fn for_batch(
        scala: &'a ScalaAnalyzer,
        support: &'a dyn BoundedDefinitionLookup,
        batch: &ScalaDefinitionContext,
    ) -> Self {
        Self {
            scala,
            support,
            package: Arc::clone(&batch.package),
            imports: Arc::clone(&batch.imports),
        }
    }

    fn resolve(&self, raw: &str) -> Option<String> {
        match self.resolve_owner(raw, ScalaOwnerKind::Class) {
            ScalaNameResolution::Resolved(owner) => Some(owner.fqn),
            ScalaNameResolution::MissingExplicitImport
            | ScalaNameResolution::Ambiguous
            | ScalaNameResolution::Unresolved => None,
        }
    }

    fn resolve_singleton(&self, raw: &str) -> Option<String> {
        match self.resolve_owner(raw, ScalaOwnerKind::SingletonObject) {
            ScalaNameResolution::Resolved(owner) => Some(owner.fqn),
            ScalaNameResolution::MissingExplicitImport
            | ScalaNameResolution::Ambiguous
            | ScalaNameResolution::Unresolved => None,
        }
    }

    fn resolve_owner(&self, raw: &str, kind: ScalaOwnerKind) -> ScalaNameResolution {
        let Some(simple) = scala_forward_simple_name(raw) else {
            return ScalaNameResolution::Unresolved;
        };
        self.resolve_owner_segments(&[simple.to_string()], kind)
    }

    fn resolve_lookup_path(
        &self,
        path: &ScalaSupertypeLookupPath,
        kind: ScalaOwnerKind,
    ) -> ScalaNameResolution {
        self.resolve_owner_segments(path.segments(), kind)
    }

    fn resolve_owner_segments(
        &self,
        segments: &[String],
        kind: ScalaOwnerKind,
    ) -> ScalaNameResolution {
        let Some(simple) = segments.last().map(String::as_str) else {
            return ScalaNameResolution::Unresolved;
        };
        let binding = if segments.len() > 1 {
            segments[0].as_str()
        } else {
            simple
        };
        let mut matching_explicit_import = false;
        let mut explicit_candidates = Vec::new();
        for import in self.imports.iter() {
            let Some(path) = scala_import_path(import) else {
                continue;
            };
            if !import.is_wildcard
                && import
                    .identifier
                    .as_deref()
                    .unwrap_or_else(|| path.rsplit('.').next().unwrap_or(&path))
                    == binding
            {
                matching_explicit_import = true;
                let tail = &segments[1..];
                explicit_candidates.extend(
                    import_candidate_fq_names(&path, &self.package)
                        .into_iter()
                        .flat_map(|candidate| scala_nested_type_candidates(candidate, tail, true)),
                );
            }
        }
        match self.resolve_candidate_tier(explicit_candidates, kind) {
            ScalaNameResolution::Unresolved if matching_explicit_import => {
                return ScalaNameResolution::MissingExplicitImport;
            }
            ScalaNameResolution::Unresolved => {}
            outcome => return outcome,
        }

        let mut wildcard_candidates = Vec::new();
        for import in self.imports.iter() {
            let Some(path) = scala_import_path(import) else {
                continue;
            };
            if import.is_wildcard {
                wildcard_candidates.extend(
                    import_candidate_fq_names(&path, &self.package)
                        .into_iter()
                        .flat_map(|package| scala_nested_type_candidates(package, segments, false)),
                );
            }
        }
        let wildcard = self.resolve_candidate_tier(wildcard_candidates, kind);
        if wildcard != ScalaNameResolution::Unresolved {
            return wildcard;
        }

        let mut local_candidates = Vec::new();
        if segments.len() > 1 || self.package.is_empty() {
            local_candidates.extend(scala_nested_type_candidates(String::new(), segments, false));
        }
        if !self.package.is_empty() {
            local_candidates.extend(scala_nested_type_candidates(
                self.package.to_string(),
                segments,
                false,
            ));
        }
        self.resolve_candidate_tier(local_candidates, kind)
    }

    fn resolve_candidate_tier(
        &self,
        mut candidates: Vec<String>,
        kind: ScalaOwnerKind,
    ) -> ScalaNameResolution {
        candidates.sort();
        candidates.dedup();
        let mut owners = Vec::new();
        for candidate in candidates {
            let exact = match kind {
                ScalaOwnerKind::Class => candidate.trim_end_matches('$').to_string(),
                ScalaOwnerKind::SingletonObject => {
                    if candidate.ends_with('$') {
                        candidate
                    } else {
                        format!("{candidate}$")
                    }
                }
            };
            owners.extend(
                self.support
                    .fqn(&exact)
                    .into_iter()
                    .chain(
                        (kind == ScalaOwnerKind::Class)
                            .then(|| self.support.fqn_in_language(&exact, Language::Java))
                            .into_iter()
                            .flatten(),
                    )
                    .filter(|unit| unit.is_class() && unit.fq_name() == exact)
                    .map(|unit| ScalaOwnerIdentity {
                        fqn: unit.fq_name(),
                        kind,
                    }),
            );
        }
        owners.sort();
        owners.dedup();
        match owners.as_slice() {
            [] => ScalaNameResolution::Unresolved,
            [owner] => ScalaNameResolution::Resolved(owner.clone()),
            _ => ScalaNameResolution::Ambiguous,
        }
    }

    fn resolve_member(&self, raw: &str) -> Option<String> {
        let simple = scala_forward_simple_name(raw)?;
        self.imports
            .iter()
            .filter(|import| !import.is_wildcard)
            .find_map(|import| {
                let path = scala_import_path(import)?;
                (import
                    .identifier
                    .as_deref()
                    .unwrap_or_else(|| path.rsplit('.').next().unwrap_or(&path))
                    == simple)
                    .then(|| import_candidate_fq_names(&path, &self.package))
                    .and_then(|candidates| {
                        candidates.into_iter().find_map(|candidate| {
                            self.support
                                .fqn(&candidate)
                                .into_iter()
                                .find(|unit| unit.is_function() || unit.is_field())
                                .map(|unit| unit.fq_name())
                        })
                    })
            })
    }

    fn visible_extension_methods(&self, member: &str) -> Vec<ForwardScalaExtensionMethod> {
        let mut units = Vec::new();
        for import in self.imports.iter() {
            let Some(path) = scala_import_path(import) else {
                continue;
            };
            if import.is_wildcard {
                for owner in import_candidate_owner_fq_names(&path, &self.package) {
                    units.extend(
                        self.support
                            .fqn_direct_children(&owner)
                            .into_iter()
                            .filter(|unit| unit.identifier() == member),
                    );
                }
            } else if import
                .identifier
                .as_deref()
                .unwrap_or_else(|| path.rsplit('.').next().unwrap_or(&path))
                == member
            {
                for candidate in import_candidate_fq_names(&path, &self.package) {
                    units.extend(self.support.fqn(&candidate));
                }
            }
        }
        units.sort();
        units.dedup();
        units
            .into_iter()
            .filter(|unit| unit.is_function() || unit.is_field())
            .filter_map(|unit| {
                let signature = unit
                    .signature()
                    .map(str::to_string)
                    .or_else(|| self.scala.signatures(&unit).into_iter().next())?;
                signature
                    .starts_with("extension ")
                    .then(|| ForwardScalaExtensionMethod {
                        fqn: unit.fq_name(),
                        receiver_type: resolved_extension_receiver_type(
                            self.scala, &unit, &signature,
                        ),
                    })
            })
            .collect()
    }
}

fn scala_nested_type_candidates(
    prefix: String,
    segments: &[String],
    prefix_is_owner: bool,
) -> Vec<String> {
    let mut direct = prefix.clone();
    for segment in segments {
        if !direct.is_empty() {
            direct.push('.');
        }
        direct.push_str(segment);
    }
    if segments.is_empty() {
        return vec![direct];
    }

    let mut singleton_qualified = prefix;
    if prefix_is_owner {
        singleton_qualified.push('$');
    }
    for (index, segment) in segments.iter().enumerate() {
        if !singleton_qualified.is_empty() {
            singleton_qualified.push('.');
        }
        singleton_qualified.push_str(segment);
        if index + 1 < segments.len() {
            singleton_qualified.push('$');
        }
    }
    if singleton_qualified == direct {
        vec![direct]
    } else {
        vec![direct, singleton_qualified]
    }
}

fn scala_forward_simple_name(raw: &str) -> Option<&str> {
    raw.trim()
        .split(['[', '(', '{', '.', ' ', '<'])
        .next()
        .map(str::trim)
        .filter(|name| !name.is_empty())
}

pub(crate) enum ScalaTypeLookupResolution {
    Type {
        fqn: String,
        target_kind: TypeLookupTargetKind,
    },
    InappropriateSymbolContext,
}

pub(crate) fn scala_type_lookup_resolution(
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    site: &ResolvedReferenceSite,
) -> Option<ScalaTypeLookupResolution> {
    let scala = resolve_analyzer::<ScalaAnalyzer>(analyzer)?;
    let resolver = ScalaNameResolver::for_file(scala, support, file);
    let ctx = ScalaLookupCtx {
        scala,
        analyzer,
        support,
        file,
        source,
    };
    let node = smallest_named_node_covering(root, site.focus_start_byte, site.focus_end_byte)?;
    scala_type_lookup_node_fqn(ctx, &resolver, root, node)
}

pub(super) fn resolve_scala(
    analyzer: &dyn IAnalyzer,
    context: &mut DefinitionBatchContext<'_>,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
) -> DefinitionLookupOutcome {
    let Some(scala) = resolve_analyzer::<ScalaAnalyzer>(analyzer) else {
        return no_definition(
            "scala_analyzer_unavailable",
            "Scala analyzer is unavailable",
        );
    };
    let Some(tree) = tree else {
        return no_definition("scala_parse_failed", "Scala source could not be parsed");
    };
    let batch = context.scala_context(scala, file);
    let support = context.bounded_support();
    let root = tree.root_node();
    let Some(node) = smallest_named_node_covering(root, site.focus_start_byte, site.focus_end_byte)
    else {
        return no_definition(
            "no_indexed_definition",
            format!(
                "`{}` did not resolve to an indexed Scala definition",
                site.text
            ),
        );
    };
    if scala_is_declaration_name(node) {
        return no_definition(
            "declaration_or_import_site",
            format!("`{}` is not a Scala reference site", site.text),
        );
    }

    if let Some(outcome) =
        resolve_scala_bare_apply_fast_path(scala, analyzer, support, file, source, root, node)
    {
        return outcome;
    }

    let resolver = ScalaNameResolver::for_batch(scala, support, &batch);
    let ctx = ScalaLookupCtx {
        scala,
        analyzer,
        support,
        file,
        source,
    };

    match scala_reference_node(node) {
        Some(ScalaReferenceNode::Type(type_node)) => {
            resolve_scala_type(ctx, &resolver, root, type_node)
        }
        Some(ScalaReferenceNode::Constructor(constructor)) => {
            resolve_scala_constructor(ctx, &resolver, constructor)
        }
        Some(ScalaReferenceNode::Call(call)) => resolve_scala_call(ctx, &resolver, root, call),
        Some(ScalaReferenceNode::NamedArgument { call, name }) => {
            resolve_scala_named_argument(ctx, &resolver, call, name)
        }
        Some(ScalaReferenceNode::InfixCall(call)) => {
            resolve_scala_infix_call(ctx, &resolver, root, call)
        }
        Some(ScalaReferenceNode::PostfixCall(call)) => {
            resolve_scala_postfix_call(ctx, &resolver, root, call)
        }
        Some(ScalaReferenceNode::Field(field)) => resolve_scala_field(ctx, &resolver, root, field),
        Some(ScalaReferenceNode::StableIdentifier(identifier)) => {
            resolve_scala_stable_identifier(ctx, &resolver, root, identifier)
        }
        Some(ScalaReferenceNode::Identifier(identifier)) => {
            let text = scala_node_text(identifier, source).trim();
            if text.is_empty() {
                return no_definition("no_reference_text", "Scala identifier is blank");
            }
            if scala_lexical_binding_declares_name_before(
                root,
                source,
                text,
                identifier.start_byte(),
            ) {
                return no_definition(
                    "local_variable_reference",
                    format!("`{text}` is a local Scala value"),
                );
            }
            if let Some(fqn) = resolver.resolve_member(text) {
                return scala_fqn_outcome(support, &fqn, text);
            }
            if let Some(fqn) = scala_resolve_visible_term(ctx, &resolver, identifier, text) {
                return scala_fqn_outcome(support, &fqn, text);
            }
            if let Some(owner) =
                scala_enclosing_class(ctx.analyzer, ctx.support, ctx.file, identifier.start_byte())
            {
                let candidates = scala_member_candidate_units(ctx, &owner.fq_name(), text, false);
                if !candidates.is_empty() {
                    return candidates_outcome(candidates);
                }
            }
            if let Some(imported_member) = scala_wildcard_imported_member_outcome(ctx, text, None) {
                return imported_member;
            }
            if scala_import_boundary_for_name(scala, support, file, text) {
                return boundary(format!(
                    "`{text}` appears to cross a Scala import boundary not indexed in this workspace"
                ));
            }
            no_definition(
                "no_indexed_definition",
                format!("`{text}` did not resolve to an indexed Scala definition"),
            )
        }
        None => no_definition(
            "unsupported_scala_reference_shape",
            format!(
                "`{}` is a Scala `{}` reference shape that get_definition does not resolve yet",
                site.text,
                node.kind()
            ),
        ),
    }
}

fn resolve_scala_bare_apply_fast_path(
    scala: &ScalaAnalyzer,
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    node: Node<'_>,
) -> Option<DefinitionLookupOutcome> {
    let Some(ScalaReferenceNode::Call(call)) = scala_reference_node(node) else {
        return None;
    };
    let function = call.child_by_field_name("function")?;
    if !matches!(function.kind(), "identifier" | "type_identifier") {
        return None;
    }
    let name = scala_node_text(function, source).trim();
    if name.is_empty() {
        return None;
    }
    let call_arity = call_arity_for_reference(function);
    if scala_active_path_declares_name_before(root, source, name, function.start_byte())
        || scala_enclosing_member_shadows_bare_call(
            scala,
            analyzer,
            support,
            file,
            function.start_byte(),
            name,
        )
        || scala_imported_member_shadows_bare_call(scala, support, file, name, call_arity)
    {
        return None;
    }

    let resolver = ScalaNameResolver::for_file(scala, support, file);
    let owner_fqn = resolver
        .resolve_singleton(name)
        .or_else(|| resolver.resolve(name))?;
    Some(scala_apply_or_type_outcome(support, &owner_fqn, name))
}

fn scala_apply_or_type_outcome(
    support: &dyn BoundedDefinitionLookup,
    owner_fqn: &str,
    reference: &str,
) -> DefinitionLookupOutcome {
    let companion_base = owner_fqn.trim_end_matches('$');
    let mut apply_candidates = support.fqn(&format!("{companion_base}$.apply"));
    if apply_candidates.is_empty() {
        apply_candidates = support.fqn(&format!("{owner_fqn}.apply"));
    }
    if !apply_candidates.is_empty() {
        return candidates_outcome(apply_candidates);
    }
    scala_fqn_outcome(support, owner_fqn, reference)
}

fn scala_type_lookup_node_fqn(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    root: Node<'_>,
    node: Node<'_>,
) -> Option<ScalaTypeLookupResolution> {
    if matches!(
        node.kind(),
        "type_identifier" | "stable_type_identifier" | "generic_type"
    ) && scala_is_type_position(node)
    {
        return scala_resolve_visible_type_annotation(
            ctx,
            resolver,
            scala_node_text(node, ctx.source),
            node.start_byte(),
        )
        .map(|fqn| ScalaTypeLookupResolution::Type {
            fqn,
            target_kind: TypeLookupTargetKind::TypeReference,
        });
    }

    if matches!(node.kind(), "instance_expression" | "call_expression") {
        return scala_constructed_type(ctx, node, resolver).map(|fqn| {
            ScalaTypeLookupResolution::Type {
                fqn,
                target_kind: TypeLookupTargetKind::ValueExpression,
            }
        });
    }

    if let Some(parent) = node.parent() {
        if parent.kind() == "field_expression" && parent.child_by_field_name("object") == Some(node)
        {
            return scala_receiver_type_fqn(ctx, resolver, root, node, node.start_byte()).map(
                |fqn| ScalaTypeLookupResolution::Type {
                    fqn,
                    target_kind: TypeLookupTargetKind::ValueExpression,
                },
            );
        }
        if scala_is_callable_declaration_name(parent, node) {
            return Some(ScalaTypeLookupResolution::InappropriateSymbolContext);
        }
        if let Some(fqn) = scala_declaration_name_type_fqn(ctx, resolver, root, parent, node) {
            return Some(ScalaTypeLookupResolution::Type {
                fqn,
                target_kind: TypeLookupTargetKind::ValueExpression,
            });
        }
    }

    if !matches!(
        node.kind(),
        "identifier" | "operator_identifier" | "type_identifier"
    ) {
        return None;
    }

    let name = scala_node_text(node, ctx.source).trim();
    let bindings = scala_bindings_before(ctx, resolver, root, node.start_byte());
    first_precise(&bindings, name).map(|fqn| ScalaTypeLookupResolution::Type {
        fqn,
        target_kind: TypeLookupTargetKind::ValueExpression,
    })
}

fn scala_declaration_name_type_fqn(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    root: Node<'_>,
    parent: Node<'_>,
    name: Node<'_>,
) -> Option<String> {
    match parent.kind() {
        "parameter" | "class_parameter" if parent.child_by_field_name("name") == Some(name) => {
            parent.child_by_field_name("type").and_then(|type_node| {
                scala_resolve_visible_type_annotation(
                    ctx,
                    resolver,
                    scala_node_text(type_node, ctx.source),
                    type_node.start_byte(),
                )
            })
        }
        "val_definition" | "var_definition"
            if parent
                .child_by_field_name("pattern")
                .is_some_and(|pattern| {
                    pattern.start_byte() <= name.start_byte()
                        && name.end_byte() <= pattern.end_byte()
                }) =>
        {
            parent.child_by_field_name("type").and_then(|type_node| {
                scala_resolve_visible_type_annotation(
                    ctx,
                    resolver,
                    scala_node_text(type_node, ctx.source),
                    type_node.start_byte(),
                )
            })
        }
        "function_definition" if parent.child_by_field_name("name") == Some(name) => parent
            .child_by_field_name("return_type")
            .and_then(|type_node| {
                scala_resolve_visible_type_annotation(
                    ctx,
                    resolver,
                    scala_node_text(type_node, ctx.source),
                    type_node.start_byte(),
                )
            }),
        _ => {
            let name_text = scala_node_text(name, ctx.source).trim();
            let bindings = scala_bindings_before(ctx, resolver, root, name.end_byte());
            first_precise(&bindings, name_text)
        }
    }
}

fn scala_is_callable_declaration_name(parent: Node<'_>, name: Node<'_>) -> bool {
    parent.child_by_field_name("name") == Some(name)
        && matches!(parent.kind(), "function_definition")
}

pub(super) fn parse_scala_tree(source: &str) -> Option<Tree> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_scala::LANGUAGE.into())
        .ok()?;
    parser.parse(source, None)
}

enum ScalaReferenceNode<'tree> {
    Type(Node<'tree>),
    Constructor(Node<'tree>),
    Call(Node<'tree>),
    InfixCall(Node<'tree>),
    PostfixCall(Node<'tree>),
    Field(Node<'tree>),
    StableIdentifier(Node<'tree>),
    Identifier(Node<'tree>),
    /// A named argument `name = value` in a call `Callee(name = ..)`: `name`
    /// resolves to the callee type's member/parameter, not a name in scope.
    NamedArgument {
        call: Node<'tree>,
        name: Node<'tree>,
    },
}

/// A named-argument identifier (`a` in `Foo(a = 3)`): the LHS of an
/// `assignment_expression` directly inside a call's `arguments`.
fn scala_named_argument(node: Node<'_>) -> Option<ScalaReferenceNode<'_>> {
    if node.kind() != "identifier" {
        return None;
    }
    let assignment = node
        .parent()
        .filter(|parent| parent.kind() == "assignment_expression")?;
    let is_lhs = assignment
        .child_by_field_name("left")
        .or_else(|| assignment.named_child(0))
        == Some(node);
    if !is_lhs {
        return None;
    }
    let arguments = assignment
        .parent()
        .filter(|parent| parent.kind() == "arguments")?;
    let call = arguments
        .parent()
        .filter(|parent| parent.kind() == "call_expression")?;
    Some(ScalaReferenceNode::NamedArgument { call, name: node })
}

fn scala_reference_node(node: Node<'_>) -> Option<ScalaReferenceNode<'_>> {
    if let Some(named) = scala_named_argument(node) {
        return Some(named);
    }
    let mut current = node;
    while let Some(parent) = current.parent() {
        if parent.kind() == "field_expression"
            && parent.child_by_field_name("field") == Some(current)
        {
            current = parent;
            continue;
        }
        if parent.kind() == "call_expression"
            && parent.child_by_field_name("function") == Some(current)
        {
            current = parent;
            continue;
        }
        if parent.kind() == "generic_function"
            && parent.child_by_field_name("function") == Some(current)
        {
            current = parent;
            continue;
        }
        if parent.kind() == "infix_expression"
            && parent.child_by_field_name("operator") == Some(current)
        {
            current = parent;
            continue;
        }
        if parent.kind() == "postfix_expression"
            && scala_postfix_method_node(parent) == Some(current)
        {
            current = parent;
            continue;
        }
        if parent.kind() == "instance_expression"
            && parent.start_byte() <= current.start_byte()
            && parent.end_byte() >= current.end_byte()
        {
            current = parent;
            continue;
        }
        if matches!(
            parent.kind(),
            "stable_identifier"
                | "stable_type_identifier"
                | "generic_type"
                | "annotated_type"
                | "applied_constructor_type"
                | "projected_type"
        ) {
            current = parent;
            continue;
        }
        break;
    }

    match current.kind() {
        "call_expression" => Some(ScalaReferenceNode::Call(current)),
        "infix_expression" => Some(ScalaReferenceNode::InfixCall(current)),
        "postfix_expression" => Some(ScalaReferenceNode::PostfixCall(current)),
        "instance_expression" => Some(ScalaReferenceNode::Constructor(current)),
        "generic_function" => scala_unapplied_generic_reference(current),
        "field_expression" => Some(ScalaReferenceNode::Field(current)),
        "stable_identifier" => Some(ScalaReferenceNode::StableIdentifier(current)),
        "type_identifier"
        | "stable_type_identifier"
        | "generic_type"
        | "annotated_type"
        | "applied_constructor_type"
        | "projected_type" => Some(ScalaReferenceNode::Type(current)),
        "identifier" | "operator_identifier" => Some(ScalaReferenceNode::Identifier(current)),
        _ => None,
    }
}

fn scala_unapplied_generic_reference(mut node: Node<'_>) -> Option<ScalaReferenceNode<'_>> {
    while node.kind() == "generic_function" {
        node = node.child_by_field_name("function")?;
    }
    match node.kind() {
        "call_expression" => Some(ScalaReferenceNode::Call(node)),
        "infix_expression" => Some(ScalaReferenceNode::InfixCall(node)),
        "postfix_expression" => Some(ScalaReferenceNode::PostfixCall(node)),
        "field_expression" => Some(ScalaReferenceNode::Field(node)),
        "stable_identifier" => Some(ScalaReferenceNode::StableIdentifier(node)),
        "identifier" | "operator_identifier" => Some(ScalaReferenceNode::Identifier(node)),
        _ => None,
    }
}

fn scala_is_declaration_name(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    parent.child_by_field_name("name") == Some(node)
        && matches!(
            parent.kind(),
            "class_definition"
                | "object_definition"
                | "trait_definition"
                | "enum_definition"
                | "function_definition"
                | "parameter"
                | "val_definition"
                | "var_definition"
        )
}

fn scala_is_type_position(node: Node<'_>) -> bool {
    let mut current = node;
    while let Some(parent) = current.parent() {
        if parent.child_by_field_name("type") == Some(current)
            || parent.child_by_field_name("return_type") == Some(current)
        {
            return true;
        }
        if matches!(parent.kind(), "generic_type" | "stable_type_identifier") {
            current = parent;
            continue;
        }
        return false;
    }
    false
}

#[derive(Clone, Copy)]
struct ScalaLookupCtx<'a> {
    scala: &'a ScalaAnalyzer,
    analyzer: &'a dyn IAnalyzer,
    support: &'a dyn BoundedDefinitionLookup,
    file: &'a ProjectFile,
    source: &'a str,
}

fn resolve_scala_type(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    root: Node<'_>,
    node: Node<'_>,
) -> DefinitionLookupOutcome {
    let text = scala_node_text(node, ctx.source).trim();
    if text.is_empty() {
        return no_definition("no_reference_text", "Scala type reference is blank");
    }
    if !scala_is_type_position(node)
        && scala_lexical_binding_declares_name_before(root, ctx.source, text, node.start_byte())
    {
        return no_definition(
            "local_variable_reference",
            format!("`{text}` is a local Scala value"),
        );
    }
    let structured_path = scala_type_lookup_segments(node, ctx.source);
    if let ScalaNameResolution::Resolved(owner) =
        resolver.resolve_owner_segments(&structured_path, ScalaOwnerKind::Class)
    {
        return scala_fqn_outcome(ctx.support, &owner.fqn, text);
    }
    if let Some(fqn) = scala_resolve_visible_type_annotation(ctx, resolver, text, node.start_byte())
    {
        return scala_fqn_outcome(ctx.support, &fqn, text);
    }
    if scala_import_boundary_for_name(ctx.scala, ctx.support, ctx.file, scala_simple_name(text)) {
        return boundary(format!(
            "`{text}` appears to cross a Scala import boundary not indexed in this workspace"
        ));
    }
    no_definition(
        "no_indexed_definition",
        format!("`{text}` did not resolve to an indexed Scala type"),
    )
}

/// Resolve a named argument (`Foo(a = 3)`, caret on `a`) to the callee type's
/// member `a` — case-class parameters are members (`Foo.a`).
fn resolve_scala_named_argument(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    call: Node<'_>,
    name_node: Node<'_>,
) -> DefinitionLookupOutcome {
    let arg_name = scala_node_text(name_node, ctx.source).trim();
    if arg_name.is_empty() {
        return no_definition("no_reference_text", "Scala named argument is blank");
    }
    let owner_fqn = call
        .child_by_field_name("function")
        .filter(|function| matches!(function.kind(), "identifier" | "type_identifier"))
        .map(|function| scala_node_text(function, ctx.source).trim())
        .filter(|callee| !callee.is_empty())
        .and_then(|callee| resolver.resolve(callee));
    let Some(owner_fqn) = owner_fqn else {
        return no_definition(
            "no_indexed_definition",
            format!("named argument `{arg_name}` receiver could not be typed"),
        );
    };
    let candidates = scala_member_candidate_units(ctx, &owner_fqn, arg_name, false);
    if candidates.is_empty() {
        return no_definition(
            "no_indexed_definition",
            format!("named argument `{arg_name}` is not a member of `{owner_fqn}`"),
        );
    }
    candidates_outcome(candidates)
}

fn resolve_scala_call(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    root: Node<'_>,
    call: Node<'_>,
) -> DefinitionLookupOutcome {
    let Some(function) = call.child_by_field_name("function") else {
        return no_definition("no_function_name", "Scala call expression has no function");
    };
    let Some(function) = scala_direct_application_target(function) else {
        return no_definition(
            SCALA_UNSUPPORTED_CALL_TARGET_SHAPE,
            "Scala direct application chain has no structured terminal callable",
        );
    };
    let call_arities = call_arities_for_reference(function);
    match function.kind() {
        "instance_expression" => resolve_scala_constructor(ctx, resolver, function),
        "field_expression" => resolve_scala_field(ctx, resolver, root, function),
        "identifier" | "type_identifier" => {
            let name = scala_node_text(function, ctx.source).trim();
            if name.is_empty() {
                return no_definition("no_function_name", "Scala call name is blank");
            }
            if scala_lexical_binding_declares_name_before(
                root,
                ctx.source,
                name,
                function.start_byte(),
            ) {
                return no_definition(
                    "local_variable_reference",
                    format!("`{name}` is a local Scala value"),
                );
            }
            if let Some(fqn) = resolver.resolve_member(name) {
                let candidates = ctx
                    .support
                    .fqn(&fqn)
                    .into_iter()
                    .filter(|unit| {
                        scala_callable_unit_accepts_arities(
                            ctx.scala,
                            unit,
                            call_arities.as_deref(),
                        )
                    })
                    .collect::<Vec<_>>();
                if !candidates.is_empty() {
                    return candidates_outcome(candidates);
                }
            }
            if let Some(unit) = resolve_in_enclosing_scopes(
                ctx.analyzer,
                ctx.file,
                name,
                function.start_byte(),
                |unit| unit.is_function(),
            ) && scala_callable_unit_accepts_arities(ctx.scala, &unit, call_arities.as_deref())
            {
                return candidates_outcome(vec![unit]);
            }
            if function.kind() == "identifier"
                && let Some(owner) = scala_enclosing_class(
                    ctx.analyzer,
                    ctx.support,
                    ctx.file,
                    function.start_byte(),
                )
                && owner.identifier() != name
            {
                let mut candidates =
                    scala_member_candidate_units(ctx, &owner.fq_name(), name, false)
                        .into_iter()
                        .filter(|unit| {
                            scala_callable_unit_accepts_arities(
                                ctx.scala,
                                unit,
                                call_arities.as_deref(),
                            )
                        })
                        .collect::<Vec<_>>();
                if candidates.is_empty() {
                    candidates = scala_source_ancestor_member_units(ctx, resolver, function, name)
                        .into_iter()
                        .filter(|unit| {
                            scala_callable_unit_accepts_arities(
                                ctx.scala,
                                unit,
                                call_arities.as_deref(),
                            )
                        })
                        .collect();
                }
                if !candidates.is_empty() {
                    return candidates_outcome(candidates);
                }
            }
            if let Some(imported_member) =
                scala_wildcard_imported_member_outcome(ctx, name, call_arities.as_deref())
            {
                return imported_member;
            }
            if let Some(owner_fqn) = resolver.resolve_singleton(name).or_else(|| {
                scala_resolve_visible_type_annotation(ctx, resolver, name, function.start_byte())
            }) {
                return scala_apply_or_type_outcome(ctx.support, &owner_fqn, name);
            }
            if scala_import_boundary_for_name(ctx.scala, ctx.support, ctx.file, name) {
                return boundary(format!(
                    "`{name}` appears to cross a Scala import boundary not indexed in this workspace"
                ));
            }
            no_definition(
                "no_indexed_definition",
                format!("`{name}` did not resolve to an indexed Scala callable"),
            )
        }
        _ => no_definition(
            SCALA_UNSUPPORTED_CALL_TARGET_SHAPE,
            format!(
                "Scala `{}` call targets are not resolved by get_definition yet",
                function.kind()
            ),
        ),
    }
}

fn scala_direct_application_target(mut function: Node<'_>) -> Option<Node<'_>> {
    loop {
        function = match function.kind() {
            "call_expression" | "generic_function" => function.child_by_field_name("function")?,
            _ => return Some(function),
        };
    }
}

fn resolve_scala_infix_call(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    root: Node<'_>,
    call: Node<'_>,
) -> DefinitionLookupOutcome {
    let Some(operator) = call.child_by_field_name("operator") else {
        return no_definition("no_function_name", "Scala infix expression has no operator");
    };
    let name = scala_node_text(operator, ctx.source).trim();
    if name.is_empty() {
        return no_definition("no_function_name", "Scala infix operator is blank");
    }
    if scala_is_compound_infix_call(call) {
        return no_definition(
            SCALA_UNSUPPORTED_RECEIVER,
            format!(
                "compound Scala infix member `{name}` requires precedence-aware receiver reconstruction"
            ),
        );
    }
    let receiver_field = if name.ends_with(':') { "right" } else { "left" };
    let Some(receiver) = call.child_by_field_name(receiver_field) else {
        return no_definition(
            SCALA_UNSUPPORTED_RECEIVER,
            "Scala infix expression has no semantic receiver",
        );
    };
    if let Some(owner) =
        scala_receiver_type_fqn(ctx, resolver, root, receiver, operator.start_byte())
    {
        let candidates = scala_member_candidate_units(ctx, &owner, name, false);
        if !candidates.is_empty() {
            return candidates_outcome(candidates);
        }
        return scala_extension_candidates(ctx, resolver, name, Some(&owner));
    }
    let extension_candidates = scala_extension_candidate_units(ctx, resolver, name, None);
    if !extension_candidates.is_empty() {
        return candidates_outcome(extension_candidates);
    }
    no_definition(
        SCALA_UNSUPPORTED_RECEIVER,
        format!("receiver for Scala infix member `{name}` is not resolved"),
    )
}

fn scala_is_compound_infix_call(call: Node<'_>) -> bool {
    call.child_by_field_name("left")
        .is_some_and(|left| left.kind() == "infix_expression")
        || call.parent().is_some_and(|parent| {
            parent.kind() == "infix_expression" && parent.child_by_field_name("left") == Some(call)
        })
}

fn resolve_scala_postfix_call(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    root: Node<'_>,
    call: Node<'_>,
) -> DefinitionLookupOutcome {
    let Some(method) = scala_postfix_method_node(call) else {
        return no_definition("no_function_name", "Scala postfix expression has no method");
    };
    let Some(receiver) = scala_postfix_receiver_node(call, method) else {
        return no_definition(
            SCALA_UNSUPPORTED_RECEIVER,
            "Scala postfix expression has no receiver",
        );
    };
    let name = scala_node_text(method, ctx.source).trim();
    if name.is_empty() {
        return no_definition("no_function_name", "Scala postfix method is blank");
    }
    if let Some(owner) = scala_receiver_type_fqn(ctx, resolver, root, receiver, method.start_byte())
    {
        let candidates = scala_member_candidate_units(ctx, &owner, name, false);
        if !candidates.is_empty() {
            return candidates_outcome(candidates);
        }
        return scala_extension_candidates(ctx, resolver, name, Some(&owner));
    }
    let extension_candidates = scala_extension_candidate_units(ctx, resolver, name, None);
    if !extension_candidates.is_empty() {
        return candidates_outcome(extension_candidates);
    }
    no_definition(
        SCALA_UNSUPPORTED_RECEIVER,
        format!("receiver for Scala postfix member `{name}` is not resolved"),
    )
}

pub(super) fn scala_postfix_method_node(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    let mut method = None;
    for child in node.named_children(&mut cursor) {
        if matches!(child.kind(), "identifier" | "operator_identifier") {
            method = Some(child);
        }
    }
    method
}

fn scala_postfix_receiver_node<'tree>(
    node: Node<'tree>,
    method: Node<'tree>,
) -> Option<Node<'tree>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| child.end_byte() <= method.start_byte())
}

fn resolve_scala_constructor(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    constructor: Node<'_>,
) -> DefinitionLookupOutcome {
    let Some(owner_fqn) = scala_constructed_type(ctx, constructor, resolver) else {
        return no_definition(
            "no_indexed_definition",
            "Scala constructor call did not resolve to an indexed type",
        );
    };
    let member = scala_constructor_member_name(&owner_fqn);
    let call_arities =
        scala_constructor_type_node(constructor).and_then(call_arities_for_reference);
    let constructor_candidates = ctx.support.fqn(&format!("{owner_fqn}.{member}"));
    let had_constructor_candidates = !constructor_candidates.is_empty();
    let candidates = constructor_candidates
        .into_iter()
        .filter(|unit| {
            scala_callable_unit_accepts_arities(ctx.scala, unit, call_arities.as_deref())
        })
        .collect::<Vec<_>>();
    if !candidates.is_empty() {
        return candidates_outcome(candidates);
    }
    if had_constructor_candidates && let Some(call_arities) = call_arities.as_deref() {
        return no_definition(
            "scala_constructor_arity_mismatch",
            format!(
                "Scala constructor `{owner_fqn}` has no indexed overload accepting argument-list arities {call_arities:?}"
            ),
        );
    }
    scala_fqn_outcome(ctx.support, &owner_fqn, member)
}

fn scala_constructor_type_node(node: Node<'_>) -> Option<Node<'_>> {
    if node.kind() != "instance_expression" {
        return None;
    }
    let arguments = node.child_by_field_name("arguments");
    let mut cursor = node.walk();
    node.named_children(&mut cursor).find(|child| {
        Some(*child) != arguments && !matches!(child.kind(), "arguments" | "template_body")
    })
}

fn scala_constructor_member_name(owner_fqn: &str) -> &str {
    owner_fqn
        .trim_end_matches('$')
        .rsplit('.')
        .next()
        .unwrap_or(owner_fqn)
}

fn resolve_scala_field(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    root: Node<'_>,
    field: Node<'_>,
) -> DefinitionLookupOutcome {
    let Some(field_node) = field.child_by_field_name("field") else {
        return no_definition(
            "no_member_name",
            "Scala field expression has no member name",
        );
    };
    let member = scala_node_text(field_node, ctx.source).trim();
    let Some(receiver) = field.child_by_field_name("value") else {
        return no_definition(
            "no_member_receiver",
            "Scala field expression has no receiver",
        );
    };
    if let Some(owner) = scala_receiver_type_fqn(ctx, resolver, root, receiver, field.start_byte())
    {
        let include_companion = scala_receiver_allows_companion_lookup(
            ctx,
            resolver,
            root,
            receiver,
            field.start_byte(),
            &owner,
        );
        let call_arities = call_arities_for_reference(field_node);
        let candidates = scala_applicable_member_candidate_units(
            ctx,
            &owner,
            member,
            include_companion,
            call_arities
                .as_deref()
                .and_then(|arities| arities.first().copied()),
        )
        .into_iter()
        .filter(|unit| {
            scala_callable_unit_accepts_arities(ctx.scala, unit, call_arities.as_deref())
        })
        .collect::<Vec<_>>();
        if !candidates.is_empty() {
            return candidates_outcome(candidates);
        }
        return scala_extension_candidates(ctx, resolver, member, Some(&owner));
    }
    let extension_candidates = scala_extension_candidate_units(ctx, resolver, member, None);
    if !extension_candidates.is_empty() {
        return candidates_outcome(extension_candidates);
    }
    no_definition(
        SCALA_UNSUPPORTED_RECEIVER,
        format!("receiver for Scala member `{member}` is not resolved"),
    )
}

fn scala_receiver_allows_companion_lookup(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    root: Node<'_>,
    receiver: Node<'_>,
    cutoff_start: usize,
    owner_fqn: &str,
) -> bool {
    if !matches!(receiver.kind(), "identifier" | "type_identifier") {
        return false;
    }
    let name = scala_node_text(receiver, ctx.source).trim();
    if name == "this" {
        return false;
    }
    let bindings = scala_bindings_before(ctx, resolver, root, cutoff_start);
    if first_precise(&bindings, name).is_some()
        || bindings.is_shadowed(name)
        || scala_lexical_binding_declares_name_before(root, ctx.source, name, cutoff_start)
        || scala_enclosing_class_parameter_type(ctx, receiver, name, resolver).is_some()
    {
        return false;
    }
    resolver
        .resolve(name)
        .is_some_and(|resolved| resolved == owner_fqn)
}

fn resolve_scala_stable_identifier(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    root: Node<'_>,
    identifier: Node<'_>,
) -> DefinitionLookupOutcome {
    let text = scala_node_text(identifier, ctx.source).trim();
    let Some((owner_text, member)) = text.rsplit_once('.') else {
        return resolve_scala_type(ctx, resolver, root, identifier);
    };
    if owner_text.is_empty() || member.is_empty() {
        return no_definition("no_reference_text", "Scala stable identifier is blank");
    }
    let bindings = scala_bindings_before(ctx, resolver, root, identifier.start_byte());
    let bound_owner = first_precise(&bindings, owner_text);
    let parameter_owner =
        scala_enclosing_class_parameter_type(ctx, identifier, owner_text, resolver);
    let owner = bound_owner.clone().or(parameter_owner.clone()).or_else(|| {
        (!bindings.is_shadowed(owner_text))
            .then(|| scala_resolve_visible_term_owner(ctx, resolver, root, identifier, owner_text))
            .flatten()
    });
    if let Some(owner) = owner {
        return scala_member_candidates(ctx, &owner, member, false);
    }
    if scala_import_boundary_for_name(ctx.scala, ctx.support, ctx.file, owner_text) {
        return boundary(format!(
            "`{owner_text}` appears to cross a Scala import boundary not indexed in this workspace"
        ));
    }
    no_definition(
        "no_indexed_definition",
        format!("`{text}` did not resolve to an indexed Scala definition"),
    )
}

fn scala_member_candidates(
    ctx: ScalaLookupCtx<'_>,
    owner_fqn: &str,
    member: &str,
    include_companion: bool,
) -> DefinitionLookupOutcome {
    let candidates = scala_member_candidate_units(ctx, owner_fqn, member, include_companion);
    if !candidates.is_empty() {
        return candidates_outcome(candidates);
    }

    scala_member_not_found(ctx, owner_fqn, member)
}

fn scala_member_candidate_units(
    ctx: ScalaLookupCtx<'_>,
    owner_fqn: &str,
    member: &str,
    include_companion: bool,
) -> Vec<CodeUnit> {
    let candidates = scala_direct_member_candidate_units(ctx.support, owner_fqn, member);
    if !candidates.is_empty() {
        return candidates;
    }

    let inherited = scala_ancestor_member_candidate_units(ctx, owner_fqn, member);
    if !inherited.is_empty() {
        return inherited;
    }

    if include_companion && !owner_fqn.ends_with('$') {
        return scala_direct_member_candidate_units(ctx.support, &format!("{owner_fqn}$"), member);
    }

    Vec::new()
}

fn scala_applicable_member_candidate_units(
    ctx: ScalaLookupCtx<'_>,
    owner_fqn: &str,
    member: &str,
    include_companion: bool,
    call_arity: Option<usize>,
) -> Vec<CodeUnit> {
    scala_member_candidate_units(ctx, owner_fqn, member, include_companion)
        .into_iter()
        .filter(|unit| scala_member_candidate_applies(ctx, unit, call_arity))
        .collect()
}

fn scala_member_candidate_applies(
    ctx: ScalaLookupCtx<'_>,
    unit: &CodeUnit,
    call_arity: Option<usize>,
) -> bool {
    scala_member_unit_applies(ctx.scala, unit, call_arity)
}

fn scala_member_unit_applies(
    scala: &ScalaAnalyzer,
    unit: &CodeUnit,
    call_arity: Option<usize>,
) -> bool {
    if unit.is_field() {
        return true;
    }
    if !unit.is_function() {
        return false;
    }
    match call_arity {
        Some(call_arity) => method_call_arity_applies(scala, unit, call_arity),
        None => method_signature_arity(scala, unit).is_none_or(|arity| arity == 0),
    }
}

fn scala_callable_unit_accepts_arities(
    scala: &ScalaAnalyzer,
    unit: &CodeUnit,
    call_arities: Option<&[usize]>,
) -> bool {
    if unit.is_field() {
        return true;
    }
    if !unit.is_callable() {
        return false;
    }
    let Some(call_arities) = call_arities else {
        return scala_member_unit_applies(scala, unit, None);
    };

    let source_facts = scala
        .indexed_source(unit.source())
        .as_deref()
        .and_then(scala_source_facts);
    let mut found_structured_shape = false;
    if let Some(source_facts) = source_facts {
        let mut declaration_ranges = scala.ranges_of(unit);
        if let Some(owner_fqn) = scala_constructor_owner_fqn(unit) {
            declaration_ranges.extend(
                scala
                    .definitions(&owner_fqn)
                    .filter(|owner| owner.is_class() && owner.source() == unit.source())
                    .flat_map(|owner| scala.ranges_of(&owner)),
            );
        }
        for range in declaration_ranges {
            let Some(alternative) = source_facts
                .callable_alternatives_by_range
                .get(&(range.start_byte, range.end_byte))
            else {
                continue;
            };
            found_structured_shape = true;
            if call_arities.len() <= alternative.shape.len()
                && call_arities
                    .iter()
                    .zip(&alternative.shape)
                    .all(|(actual, declared)| declared.accepts(*actual))
            {
                return true;
            }
        }
    }
    if found_structured_shape {
        return false;
    }

    let [call_arity] = call_arities else {
        return false;
    };
    scala_member_unit_applies(scala, unit, Some(*call_arity))
}

fn scala_constructor_owner_fqn(unit: &CodeUnit) -> Option<String> {
    let fqn = unit.fq_name();
    let (owner, member) = fqn.rsplit_once('.')?;
    (scala_constructor_member_name(owner) == member).then(|| owner.to_string())
}

fn scala_extension_candidates(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    member: &str,
    receiver_owner: Option<&str>,
) -> DefinitionLookupOutcome {
    let candidates = scala_extension_candidate_units(ctx, resolver, member, receiver_owner);
    if !candidates.is_empty() {
        return candidates_outcome(candidates);
    }
    no_definition(
        SCALA_UNSUPPORTED_RECEIVER,
        format!("receiver for Scala extension member `{member}` is not resolved"),
    )
}

fn scala_extension_candidate_units(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    member: &str,
    receiver_owner: Option<&str>,
) -> Vec<CodeUnit> {
    let mut candidates = Vec::new();
    for method in resolver.visible_extension_methods(member) {
        if !scala_extension_receiver_matches(
            resolver,
            method.receiver_type.as_deref(),
            receiver_owner,
        ) {
            continue;
        }
        candidates.extend(ctx.support.fqn(&method.fqn));
    }
    sort_units(&mut candidates);
    candidates.dedup();
    candidates
}

fn scala_extension_receiver_matches(
    resolver: &ScalaNameResolver,
    extension_receiver_type: Option<&str>,
    receiver_owner: Option<&str>,
) -> bool {
    scala_extension_receiver_matches_resolved(
        extension_receiver_type,
        receiver_owner,
        |type_text| resolver.resolve(type_text),
    )
}

fn scala_wildcard_imported_member_outcome(
    ctx: ScalaLookupCtx<'_>,
    member: &str,
    call_arities: Option<&[usize]>,
) -> Option<DefinitionLookupOutcome> {
    let file_package = scala_package_name_of(ctx.scala, ctx.file).unwrap_or_default();
    let mut contributing_imports = 0_usize;
    let mut candidates = Vec::new();
    for import in ctx.scala.import_info_of(ctx.file) {
        if !import.is_wildcard {
            continue;
        }
        let Some(path) = scala_import_path(&import) else {
            continue;
        };
        let import_candidates =
            scala_wildcard_imported_member_units(ctx.support, &path, &file_package, member)
                .into_iter()
                .filter(|unit| scala_callable_unit_accepts_arities(ctx.scala, unit, call_arities))
                .collect::<Vec<_>>();
        if !import_candidates.is_empty() {
            contributing_imports += 1;
            candidates.extend(import_candidates);
        }
        if contributing_imports > 1 {
            return Some(no_definition(
                "ambiguous_scala_wildcard_import",
                format!("Scala wildcard imports expose multiple `{member}` definitions"),
            ));
        }
    }
    sort_units(&mut candidates);
    candidates.dedup();
    if candidates.is_empty() {
        None
    } else {
        Some(candidates_outcome(candidates))
    }
}

fn scala_wildcard_imported_member_units(
    support: &dyn BoundedDefinitionLookup,
    path: &str,
    file_package: &str,
    member: &str,
) -> Vec<CodeUnit> {
    let mut candidates = Vec::new();
    for imported_fqn in import_candidate_fq_names(path, file_package) {
        candidates.extend(
            support
                .fqn(&format!("{imported_fqn}.{member}"))
                .into_iter()
                .filter(|unit| unit.identifier() == member),
        );
    }
    for owner_fqn in import_candidate_owner_fq_names(path, file_package) {
        candidates.extend(
            support
                .fqn_direct_children(&owner_fqn)
                .into_iter()
                .filter(|unit| unit.identifier() == member),
        );
    }
    sort_units(&mut candidates);
    candidates.dedup();
    candidates
}

fn scala_ancestor_member_candidate_units(
    ctx: ScalaLookupCtx<'_>,
    owner_fqn: &str,
    member: &str,
) -> Vec<CodeUnit> {
    let owners = ctx
        .support
        .fqn(owner_fqn)
        .into_iter()
        .filter(|unit| unit.is_class() && unit.fq_name() == owner_fqn);
    let mut matching_depth = None;
    let mut matches = Vec::new();
    for owner in owners {
        for (ancestor, depth) in scala_ancestor_owners(ctx.scala, ctx.support, owner) {
            if matching_depth.is_some_and(|found| depth > found) {
                break;
            }
            let direct =
                scala_direct_member_candidate_units(ctx.support, &ancestor.fq_name(), member);
            if !direct.is_empty() {
                matching_depth = Some(depth);
                matches.extend(direct);
            }
        }
    }
    sort_units(&mut matches);
    matches.dedup();
    matches
}

fn scala_ancestor_owners(
    scala: &ScalaAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    owner: CodeUnit,
) -> Vec<(CodeUnit, usize)> {
    let mut queue = VecDeque::from([(owner.clone(), 0_usize)]);
    let mut discovered = HashSet::from_iter([owner.fq_name()]);
    let mut ancestors = Vec::new();
    while let Some((current, depth)) = queue.pop_front() {
        let Some(facts) = scala.forward_owner_facts(&current) else {
            continue;
        };
        let resolver = ScalaNameResolver::for_file(scala, support, current.source());
        for lookup_path in facts.supertype_lookup_paths {
            let ScalaNameResolution::Resolved(identity) =
                resolver.resolve_lookup_path(&lookup_path, ScalaOwnerKind::Class)
            else {
                continue;
            };
            for ancestor in support
                .fqn(&identity.fqn)
                .into_iter()
                .filter(|unit| unit.is_class() && unit.fq_name() == identity.fqn)
            {
                if discovered.insert(ancestor.fq_name()) {
                    let ancestor_depth = depth + 1;
                    ancestors.push((ancestor.clone(), ancestor_depth));
                    queue.push_back((ancestor, ancestor_depth));
                }
            }
        }
    }
    ancestors
}

fn scala_direct_member_candidate_units(
    support: &dyn BoundedDefinitionLookup,
    owner_fqn: &str,
    member: &str,
) -> Vec<CodeUnit> {
    let exact_fqn = format!("{owner_fqn}.{member}");
    let mut candidates = support
        .fqn(&exact_fqn)
        .into_iter()
        .filter(|unit| unit.fq_name() == exact_fqn)
        .collect::<Vec<_>>();
    sort_units(&mut candidates);
    candidates.dedup();
    candidates
}

fn scala_source_ancestor_member_units(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    node: Node<'_>,
    member: &str,
) -> Vec<CodeUnit> {
    let Some(owner_node) = scala_enclosing_definition_node(node) else {
        return Vec::new();
    };
    let mut ancestor_types = Vec::new();
    scala_collect_extends_type_text(owner_node, ctx.source, &mut ancestor_types);
    for ancestor_type in ancestor_types {
        let Some(owner_fqn) = resolver.resolve(&ancestor_type) else {
            continue;
        };
        let candidates = scala_member_candidate_units(ctx, &owner_fqn, member, false);
        if !candidates.is_empty() {
            return candidates;
        }
    }
    Vec::new()
}

fn scala_enclosing_definition_node(mut node: Node<'_>) -> Option<Node<'_>> {
    while let Some(parent) = node.parent() {
        if matches!(
            parent.kind(),
            "class_definition" | "object_definition" | "trait_definition" | "enum_definition"
        ) {
            return Some(parent);
        }
        node = parent;
    }
    None
}

fn scala_collect_extends_type_text(node: Node<'_>, source: &str, out: &mut Vec<String>) {
    scala_collect_extends_type_text_inner(node, source, out, true);
}

fn scala_collect_extends_type_text_inner(
    node: Node<'_>,
    source: &str,
    out: &mut Vec<String>,
    is_root: bool,
) {
    if !is_root
        && matches!(
            node.kind(),
            "class_definition" | "object_definition" | "trait_definition" | "enum_definition"
        )
    {
        return;
    }
    let in_extends = node.kind() == "extends_clause";
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if in_extends
            && matches!(
                child.kind(),
                "type_identifier" | "stable_type_identifier" | "generic_type"
            )
        {
            let text = scala_node_text(child, source).trim();
            if !text.is_empty() {
                out.push(text.to_string());
            }
            continue;
        }
        scala_collect_extends_type_text_inner(child, source, out, false);
    }
}

fn scala_member_not_found(
    _ctx: ScalaLookupCtx<'_>,
    owner_fqn: &str,
    member: &str,
) -> DefinitionLookupOutcome {
    no_definition(
        SCALA_UNSUPPORTED_RECEIVER,
        format!(
            "receiver for Scala member `{member}` resolved to `{owner_fqn}`, but `{owner_fqn}.{member}` was not indexed"
        ),
    )
}

fn scala_receiver_type_fqn(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    root: Node<'_>,
    receiver: Node<'_>,
    cutoff_start: usize,
) -> Option<String> {
    match receiver.kind() {
        "identifier" | "type_identifier" => {
            let name = scala_node_text(receiver, ctx.source).trim();
            if name == "this" {
                return ClassRangeIndex::build(ctx.analyzer, ctx.file)
                    .enclosing(receiver.start_byte())
                    .map(str::to_string);
            }
            let bindings = scala_bindings_before(ctx, resolver, root, cutoff_start);
            first_precise(&bindings, name).or_else(|| {
                scala_enclosing_class_parameter_type(ctx, receiver, name, resolver).or_else(|| {
                    if !bindings.is_shadowed(name)
                        && let Some(imported_member) = resolver.resolve_member(name)
                        && let Some(return_type) =
                            scala_imported_member_return_type(ctx, resolver, &imported_member)
                    {
                        return Some(return_type);
                    }
                    (!bindings.is_shadowed(name))
                        .then(|| {
                            resolver
                                .resolve_singleton(name)
                                .or_else(|| resolver.resolve(name))
                        })
                        .flatten()
                })
            })
        }
        // `new Foo().member` — the receiver is typed by the constructed class.
        "instance_expression" => {
            let name = scala_first_type_name(receiver, ctx.source)?;
            resolver.resolve(name)
        }
        kind => scala_literal_type_name(kind).map(str::to_string),
    }
}

fn scala_imported_member_return_type(
    ctx: ScalaLookupCtx<'_>,
    _resolver: &ScalaNameResolver,
    member_fqn: &str,
) -> Option<String> {
    let unit = ctx
        .support
        .fqn(member_fqn)
        .into_iter()
        .find(|unit| unit.is_function())?;
    let signature = unit
        .signature()
        .map(str::to_string)
        .or_else(|| ctx.scala.signatures(&unit).into_iter().next())?;
    let return_type = scala_signature_return_type(&signature)?;
    let factory_resolver = ScalaNameResolver::for_file(ctx.scala, ctx.support, unit.source());
    scala_resolve_type_annotation(&factory_resolver, return_type).or_else(|| {
        scala_package_type_fqn(unit.package_name(), return_type)
            .filter(|fqn| !ctx.support.fqn(fqn).is_empty())
    })
}

fn scala_signature_return_type(signature: &str) -> Option<&str> {
    let (_, after_colon) = signature.rsplit_once(':')?;
    let end = after_colon.find(['=', '{']).unwrap_or(after_colon.len());
    let return_type = after_colon[..end].trim();
    (!return_type.is_empty()).then_some(return_type)
}

/// The first `type_identifier` (else `identifier`) in a pre-order walk — the
/// constructed type of a `new Foo(...)` instance expression.
fn scala_first_type_name<'a>(node: Node<'_>, source: &'a str) -> Option<&'a str> {
    let mut fallback = None;
    let mut stack = vec![node];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "type_identifier" => return Some(scala_node_text(node, source).trim()),
            "identifier" if fallback.is_none() => {
                fallback = Some(scala_node_text(node, source).trim());
            }
            _ => {}
        }
        let mut cursor = node.walk();
        let children: Vec<_> = node.named_children(&mut cursor).collect();
        for child in children.into_iter().rev() {
            stack.push(child);
        }
    }
    fallback
}

fn scala_enclosing_class_parameter_type(
    ctx: ScalaLookupCtx<'_>,
    node: Node<'_>,
    name: &str,
    resolver: &ScalaNameResolver,
) -> Option<String> {
    let mut current = node.parent();
    while let Some(parent) = current {
        if parent.kind() == "class_definition" {
            let parameters = parent.child_by_field_name("class_parameters")?;
            let mut cursor = parameters.walk();
            for parameter in parameters.named_children(&mut cursor) {
                if !matches!(parameter.kind(), "parameter" | "class_parameter") {
                    continue;
                }
                let Some(param_name) = parameter.child_by_field_name("name") else {
                    continue;
                };
                if scala_node_text(param_name, ctx.source).trim() != name {
                    continue;
                }
                if scala_active_path_declares_name_after(
                    parent,
                    ctx.source,
                    name,
                    parameter.end_byte(),
                    node.start_byte(),
                ) {
                    return None;
                }
                return parameter.child_by_field_name("type").and_then(|type_node| {
                    let type_text = scala_node_text(type_node, ctx.source);
                    scala_resolve_receiver_type_annotation(
                        ctx,
                        resolver,
                        type_text,
                        type_node.start_byte(),
                    )
                });
            }
            return None;
        }
        current = parent.parent();
    }
    None
}

fn scala_active_path_declares_name_before(
    root: Node<'_>,
    source: &str,
    name: &str,
    cutoff_start: usize,
) -> bool {
    scala_active_path_declares_name_before_mode(root, source, name, cutoff_start, true)
}

fn scala_lexical_binding_declares_name_before(
    root: Node<'_>,
    source: &str,
    name: &str,
    cutoff_start: usize,
) -> bool {
    scala_active_path_declares_name_before_mode(root, source, name, cutoff_start, false)
}

fn scala_active_path_declares_name_before_mode(
    root: Node<'_>,
    source: &str,
    name: &str,
    cutoff_start: usize,
    include_callable_names: bool,
) -> bool {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.start_byte() >= cutoff_start {
            continue;
        }
        let enters_scope = SCALA_SCOPE_NODES.contains(&node.kind());
        let contains_cutoff = node.start_byte() <= cutoff_start && cutoff_start < node.end_byte();
        if enters_scope && !contains_cutoff {
            if include_callable_names
                && node.kind() == "function_definition"
                && scala_node_declares_name_before(node, source, name, 0, cutoff_start)
            {
                return true;
            }
            continue;
        }

        match node.kind() {
            "class_definition" | "function_definition" => {
                if scala_parameters_declare_name_before(node, source, name, cutoff_start) {
                    return true;
                }
            }
            "val_definition" | "var_definition"
                if !scala_is_direct_member_value_definition(node)
                    && scala_node_declares_name_before(node, source, name, 0, cutoff_start) =>
            {
                return true;
            }
            _ => {}
        }

        let mut cursor = node.walk();
        let mut children: Vec<_> = node
            .named_children(&mut cursor)
            .take_while(|child| child.start_byte() < cutoff_start)
            .collect();
        children.reverse();
        stack.extend(children);
    }
    false
}

fn scala_parameters_declare_name_before(
    node: Node<'_>,
    source: &str,
    name: &str,
    cutoff_start: usize,
) -> bool {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .filter(|child| matches!(child.kind(), "parameters" | "class_parameters"))
        .filter(|child| child.start_byte() < cutoff_start)
        .any(|child| scala_node_declares_name_before(child, source, name, 0, cutoff_start))
}

fn scala_active_path_declares_name_after(
    node: Node<'_>,
    source: &str,
    name: &str,
    lower_bound: usize,
    target_byte: usize,
) -> bool {
    if target_byte < node.start_byte() || node.end_byte() <= target_byte {
        return false;
    }

    let mut containing_child = None;
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.start_byte() <= target_byte && target_byte < child.end_byte() {
            containing_child = Some(child);
        }
        if child.start_byte() >= target_byte || child.end_byte() <= lower_bound {
            continue;
        }
        if scala_node_declares_name_before(child, source, name, lower_bound, target_byte) {
            return true;
        }
    }

    containing_child.is_some_and(|child| {
        scala_active_path_declares_name_after(child, source, name, lower_bound, target_byte)
    })
}

fn scala_node_declares_name_before(
    node: Node<'_>,
    source: &str,
    name: &str,
    lower_bound: usize,
    target_byte: usize,
) -> bool {
    match node.kind() {
        "parameter" | "class_parameter" => {
            node.child_by_field_name("name").is_some_and(|name_node| {
                lower_bound <= name_node.start_byte()
                    && name_node.start_byte() < target_byte
                    && scala_node_text(name_node, source).trim() == name
            })
        }
        "parameters" | "class_parameters" => {
            let mut cursor = node.walk();
            node.named_children(&mut cursor).any(|child| {
                scala_node_declares_name_before(child, source, name, lower_bound, target_byte)
            })
        }
        "val_definition" | "var_definition" => {
            if node.start_byte() >= target_byte {
                return false;
            }
            node.child_by_field_name("pattern").is_some_and(|pattern| {
                lower_bound <= pattern.start_byte()
                    && scala_pattern_names(pattern, source).contains(&name)
            })
        }
        "function_definition" => node.child_by_field_name("name").is_some_and(|name_node| {
            lower_bound <= name_node.start_byte()
                && name_node.start_byte() < target_byte
                && scala_node_text(name_node, source).trim() == name
        }),
        _ => false,
    }
}

fn scala_existing_package_type_fqn(
    support: &dyn BoundedDefinitionLookup,
    package: &str,
    type_text: &str,
) -> Option<String> {
    let fqn = scala_package_type_fqn(package, type_text)?;
    support
        .fqn(&fqn)
        .into_iter()
        .any(|unit| unit.is_class() && unit.fq_name() == fqn)
        .then_some(fqn)
}

fn scala_package_type_fqn(package: &str, type_text: &str) -> Option<String> {
    let simple = scala_simple_name(type_text);
    if simple.is_empty() || simple.contains('.') {
        return None;
    }
    if package.is_empty() {
        Some(simple.to_string())
    } else {
        Some(format!("{package}.{simple}"))
    }
}

fn scala_resolve_type_annotation(resolver: &ScalaNameResolver, type_text: &str) -> Option<String> {
    let trimmed = type_text.trim();
    if let Some(base_type) = trimmed.strip_suffix(".type") {
        return resolver.resolve_singleton(base_type);
    }
    let fqn = resolver
        .resolve(type_text)
        .or_else(|| scala_type_base_text(trimmed).and_then(|base| resolver.resolve(base)))?;
    Some(fqn.trim_end_matches('$').to_string())
}

fn scala_resolve_visible_type_annotation(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    type_text: &str,
    reference_byte: usize,
) -> Option<String> {
    if let Some(base) = type_text.trim().strip_suffix(".type") {
        return match resolver.resolve_owner(base, ScalaOwnerKind::SingletonObject) {
            ScalaNameResolution::Resolved(owner) => Some(owner.fqn),
            ScalaNameResolution::MissingExplicitImport
            | ScalaNameResolution::Ambiguous
            | ScalaNameResolution::Unresolved => None,
        };
    }
    let base = scala_type_base_text(type_text.trim()).unwrap_or(type_text);
    match resolver.resolve_owner(base, ScalaOwnerKind::Class) {
        ScalaNameResolution::Resolved(owner) => return Some(owner.fqn),
        ScalaNameResolution::MissingExplicitImport | ScalaNameResolution::Ambiguous => return None,
        ScalaNameResolution::Unresolved => {}
    }
    if scala_type_annotation_has_explicit_import(ctx, type_text) {
        return None;
    }
    scala_package_name_of(ctx.scala, ctx.file)
        .and_then(|package| scala_existing_package_type_fqn(ctx.support, &package, type_text))
        .or_else(|| scala_enclosing_type_fqn(ctx, type_text, reference_byte))
        .or_else(|| scala_builtin_type_name(type_text).map(str::to_string))
}

fn scala_resolve_receiver_type_annotation(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    type_text: &str,
    reference_byte: usize,
) -> Option<String> {
    scala_resolve_visible_type_annotation(ctx, resolver, type_text, reference_byte)
}

fn scala_enclosing_type_fqn(
    ctx: ScalaLookupCtx<'_>,
    type_text: &str,
    reference_byte: usize,
) -> Option<String> {
    let simple = scala_simple_name(type_text);
    if simple.is_empty() || simple.contains('.') {
        return None;
    }
    let owner = scala_enclosing_class(ctx.analyzer, ctx.support, ctx.file, reference_byte)?;
    let candidate = format!("{}.{simple}", owner.fq_name());
    ctx.analyzer
        .definitions(&candidate)
        .any(|unit| unit.is_class())
        .then_some(candidate)
}

fn scala_resolve_visible_term(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    node: Node<'_>,
    name: &str,
) -> Option<String> {
    if let Some(singleton) = resolver.resolve_singleton(name) {
        return Some(singleton);
    }
    let owner = scala_resolve_visible_type_annotation(ctx, resolver, name, node.start_byte())?;
    if owner.ends_with('$') {
        return Some(owner);
    }
    let companion = format!("{owner}$");
    (!ctx.support.fqn(&companion).is_empty()).then_some(companion)
}

fn scala_resolve_visible_term_owner(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    root: Node<'_>,
    node: Node<'_>,
    name: &str,
) -> Option<String> {
    let bindings = scala_bindings_before(ctx, resolver, root, node.start_byte());
    if bindings.is_shadowed(name) {
        return first_precise(&bindings, name);
    }
    scala_resolve_visible_term(ctx, resolver, node, name)
}

fn scala_type_annotation_has_explicit_import(ctx: ScalaLookupCtx<'_>, type_text: &str) -> bool {
    let simple = scala_simple_name(type_text);
    ctx.scala
        .import_info_of(ctx.file)
        .into_iter()
        .any(|import| {
            if import.is_wildcard {
                return false;
            }
            let Some(path) = scala_import_path(&import) else {
                return false;
            };
            let local_name = import
                .identifier
                .as_deref()
                .unwrap_or_else(|| path.rsplit('.').next().unwrap_or(path.as_str()));
            local_name == simple
        })
}

fn scala_type_base_text(type_text: &str) -> Option<&str> {
    let base = type_text
        .split(['[', '<'])
        .next()
        .unwrap_or(type_text)
        .trim();
    (!base.is_empty() && base != type_text.trim()).then_some(base)
}

fn scala_fqn_outcome(
    support: &dyn BoundedDefinitionLookup,
    fqn: &str,
    reference: &str,
) -> DefinitionLookupOutcome {
    let mut candidates = support.fqn(fqn);
    if candidates.is_empty() {
        candidates = support.fqn_in_language(fqn, Language::Java);
    }
    if candidates.is_empty() {
        no_definition(
            "no_indexed_definition",
            format!("`{reference}` resolved to `{fqn}`, but no indexed definition was found"),
        )
    } else {
        candidates_outcome(candidates)
    }
}

fn scala_enclosing_class(
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    byte: usize,
) -> Option<CodeUnit> {
    let fqn = ClassRangeIndex::build(analyzer, file)
        .enclosing(byte)?
        .to_string();
    support
        .fqn(&fqn)
        .into_iter()
        .find(|unit| unit.fq_name() == fqn)
}

fn scala_enclosing_member_shadows_bare_call(
    scala: &ScalaAnalyzer,
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    byte: usize,
    name: &str,
) -> bool {
    let Some(owner) = scala_enclosing_class(analyzer, support, file, byte) else {
        return false;
    };
    if owner.identifier().trim_end_matches('$') == name {
        return false;
    }
    if scala_owner_declares_member(support, &owner, name) {
        return true;
    }
    scala_ancestor_owners(scala, support, owner)
        .into_iter()
        .any(|(ancestor, _)| scala_owner_declares_member(support, &ancestor, name))
}

fn scala_owner_declares_member(
    support: &dyn BoundedDefinitionLookup,
    owner: &CodeUnit,
    name: &str,
) -> bool {
    scala_direct_member_candidate_units(support, &owner.fq_name(), name)
        .into_iter()
        .any(|unit| !unit.is_synthetic() && (unit.is_function() || unit.is_field()))
}

fn scala_imported_member_shadows_bare_call(
    scala: &ScalaAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    name: &str,
    call_arity: Option<usize>,
) -> bool {
    let file_package = scala_package_name_of(scala, file).unwrap_or_default();
    for import in scala.import_info_of(file) {
        let Some(path) = scala_import_path(&import) else {
            continue;
        };
        if import.is_wildcard {
            if scala_wildcard_imported_member_units(support, &path, &file_package, name)
                .into_iter()
                .any(|unit| scala_member_unit_applies(scala, &unit, call_arity))
            {
                return true;
            }
            continue;
        }

        let local_name = import
            .identifier
            .as_deref()
            .unwrap_or_else(|| path.rsplit('.').next().unwrap_or(path.as_str()));
        if local_name != name {
            continue;
        }
        for candidate in import_candidate_fq_names(&path, &file_package) {
            let normalized = scala_normalized_fq_name(&candidate);
            if support
                .fqn(&candidate)
                .into_iter()
                .chain(support.fqn(&normalized))
                .chain(support.fqn(&format!("{candidate}$")))
                .any(|unit| unit.is_function() || unit.is_field())
            {
                return true;
            }
        }
    }
    false
}

const SCALA_SCOPE_NODES: &[&str] = &[
    "class_definition",
    "object_definition",
    "trait_definition",
    "enum_definition",
    "function_definition",
    "block",
    "indented_block",
    "case_clause",
    "lambda_expression",
];

fn scala_bindings_before(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    root: Node<'_>,
    cutoff_start: usize,
) -> LocalInferenceEngine<String> {
    let mut bindings = LocalInferenceEngine::new(LocalInferenceConfig::default());
    scala_seed_active_path(ctx, resolver, root, cutoff_start, &mut bindings);
    bindings
}

fn scala_seed_active_path(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    node: Node<'_>,
    cutoff_start: usize,
    bindings: &mut LocalInferenceEngine<String>,
) {
    let root = node;
    let mut stack = vec![node];
    while let Some(node) = stack.pop() {
        if node.start_byte() >= cutoff_start {
            continue;
        }
        let enters_scope = SCALA_SCOPE_NODES.contains(&node.kind());
        if enters_scope && !(node.start_byte() <= cutoff_start && cutoff_start < node.end_byte()) {
            continue;
        }
        if enters_scope {
            bindings.enter_scope();
        }
        match node.kind() {
            "class_definition" | "function_definition" => {
                scala_seed_parameters(ctx, resolver, node, cutoff_start, bindings)
            }
            "val_definition" | "var_definition" if node.start_byte() < cutoff_start => {
                scala_seed_value_definition(ctx, resolver, root, node, cutoff_start, bindings)
            }
            _ => {}
        }

        let mut cursor = node.walk();
        let mut children: Vec<_> = node
            .named_children(&mut cursor)
            .take_while(|child| child.start_byte() < cutoff_start)
            .collect();
        children.reverse();
        stack.extend(children);
    }
}

fn scala_seed_parameters(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    node: Node<'_>,
    cutoff_start: usize,
    bindings: &mut LocalInferenceEngine<String>,
) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if !matches!(child.kind(), "parameters" | "class_parameters")
            || child.start_byte() >= cutoff_start
        {
            continue;
        }
        let mut inner = child.walk();
        for parameter in child.named_children(&mut inner) {
            if matches!(parameter.kind(), "parameter" | "class_parameter")
                && parameter.start_byte() < cutoff_start
            {
                scala_seed_parameter(ctx, resolver, parameter, cutoff_start, bindings);
            }
        }
    }
}

fn scala_seed_parameter(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    parameter: Node<'_>,
    cutoff_start: usize,
    bindings: &mut LocalInferenceEngine<String>,
) {
    let Some(name) = parameter.child_by_field_name("name") else {
        return;
    };
    if name.start_byte() >= cutoff_start {
        return;
    }
    let binding_name = scala_node_text(name, ctx.source).trim();
    if binding_name.is_empty() {
        return;
    }
    let resolved = parameter
        .child_by_field_name("type")
        .filter(|type_node| type_node.end_byte() <= cutoff_start)
        .and_then(|type_node| {
            let type_text = scala_node_text(type_node, ctx.source);
            scala_resolve_receiver_type_annotation(ctx, resolver, type_text, type_node.start_byte())
        });
    scala_seed_typed(binding_name, resolved, false, bindings);
}

fn scala_seed_value_definition(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    root: Node<'_>,
    node: Node<'_>,
    cutoff_start: usize,
    bindings: &mut LocalInferenceEngine<String>,
) {
    let resolved = node
        .child_by_field_name("type")
        .filter(|type_node| type_node.end_byte() <= cutoff_start)
        .and_then(|type_node| {
            scala_resolve_receiver_type_annotation(
                ctx,
                resolver,
                scala_node_text(type_node, ctx.source),
                type_node.start_byte(),
            )
        })
        .or_else(|| {
            node.child_by_field_name("value")
                .filter(|value| value.end_byte() <= cutoff_start)
                .and_then(|value| scala_constructed_type(ctx, value, resolver))
                .or_else(|| {
                    node.child_by_field_name("value")
                        .filter(|value| value.end_byte() <= cutoff_start)
                        .and_then(|value| {
                            scala_call_result_type(ctx, resolver, root, value, value.start_byte())
                        })
                })
                .or_else(|| {
                    scala_constructor_type_text(scala_node_text(node, ctx.source)).and_then(
                        |type_text| {
                            scala_resolve_visible_type_annotation(
                                ctx,
                                resolver,
                                type_text,
                                node.start_byte(),
                            )
                        },
                    )
                })
        });
    let Some(pattern) = node.child_by_field_name("pattern") else {
        return;
    };
    if pattern.start_byte() >= cutoff_start {
        return;
    }
    let is_direct_member = scala_is_direct_member_value_definition(node);
    for name in scala_pattern_names(pattern, ctx.source) {
        scala_seed_typed(name, resolved.clone(), is_direct_member, bindings);
    }
}

fn scala_call_result_type(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    root: Node<'_>,
    value: Node<'_>,
    cutoff_start: usize,
) -> Option<String> {
    if value.kind() != "call_expression" {
        return None;
    }
    let function = value.child_by_field_name("function")?;
    match function.kind() {
        "field_expression" => {
            let receiver = function.child_by_field_name("value")?;
            let field = function.child_by_field_name("field")?;
            let member = scala_node_text(field, ctx.source).trim();
            if member.is_empty() {
                return None;
            }
            let owner = scala_receiver_type_fqn(ctx, resolver, root, receiver, cutoff_start)?;
            let include_companion = scala_receiver_allows_companion_lookup(
                ctx,
                resolver,
                root,
                receiver,
                cutoff_start,
                &owner,
            );
            scala_member_candidate_units(ctx, &owner, member, include_companion)
                .into_iter()
                .filter(|unit| unit.is_function())
                .find_map(|unit| scala_function_return_type(ctx, &unit))
        }
        "identifier" => {
            let name = scala_node_text(function, ctx.source).trim();
            if name.is_empty() {
                return None;
            }
            if let Some(member_fqn) = resolver.resolve_member(name)
                && let Some(return_type) =
                    scala_imported_member_return_type(ctx, resolver, &member_fqn)
            {
                return Some(return_type);
            }
            if let Some(unit) = resolve_in_enclosing_scopes(
                ctx.analyzer,
                ctx.file,
                name,
                function.start_byte(),
                |unit| unit.is_function(),
            ) {
                return scala_function_return_type(ctx, &unit);
            }
            let owner =
                scala_enclosing_class(ctx.analyzer, ctx.support, ctx.file, function.start_byte())?;
            scala_member_candidate_units(ctx, &owner.fq_name(), name, false)
                .into_iter()
                .filter(|unit| unit.is_function())
                .find_map(|unit| scala_function_return_type(ctx, &unit))
        }
        _ => None,
    }
}

fn scala_function_return_type(ctx: ScalaLookupCtx<'_>, unit: &CodeUnit) -> Option<String> {
    scala_imported_member_return_type(
        ctx,
        &ScalaNameResolver::for_file(ctx.scala, ctx.support, unit.source()),
        &unit.fq_name(),
    )
}

fn scala_constructed_type(
    ctx: ScalaLookupCtx<'_>,
    node: Node<'_>,
    resolver: &ScalaNameResolver,
) -> Option<String> {
    if node.kind() == "call_expression"
        && let Some(function) = node
            .child_by_field_name("function")
            .or_else(|| node.named_child(0))
    {
        return scala_constructed_type(ctx, function, resolver);
    }
    if !matches!(
        node.kind(),
        "instance_expression" | "generic_type" | "type_identifier" | "identifier"
    ) {
        return None;
    }
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| child.kind() == "type_identifier" || child.kind() == "generic_type")
        .or_else(|| {
            matches!(
                node.kind(),
                "type_identifier" | "generic_type" | "identifier"
            )
            .then_some(node)
        })
        .and_then(|type_node| {
            let type_text = scala_node_text(type_node, ctx.source);
            resolve_in_enclosing_scopes(
                ctx.analyzer,
                ctx.file,
                scala_simple_name(type_text),
                type_node.start_byte(),
                |unit| unit.is_class(),
            )
            .map(|unit| unit.fq_name())
            .or_else(|| {
                scala_resolve_visible_type_annotation(
                    ctx,
                    resolver,
                    type_text,
                    type_node.start_byte(),
                )
            })
        })
}

fn scala_constructor_type_text(value_text: &str) -> Option<&str> {
    let trimmed = value_text.trim_start();
    let value = if let Some(after_keyword) = trimmed
        .strip_prefix("val ")
        .or_else(|| trimmed.strip_prefix("var "))
    {
        after_keyword.split_once('=')?.1.trim_start()
    } else {
        trimmed
    };
    let value = value.strip_prefix("new ").unwrap_or(value).trim_start();
    let end = value
        .find(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_' || ch == '.'))
        .unwrap_or(value.len());
    if end == 0 {
        return None;
    }
    let type_text = &value[..end];
    let simple_name = type_text.rsplit('.').next().unwrap_or(type_text);
    simple_name
        .chars()
        .next()
        .is_some_and(|ch| ch.is_ascii_uppercase())
        .then_some(type_text)
}

fn scala_pattern_names<'a>(node: Node<'_>, source: &'a str) -> Vec<&'a str> {
    match node.kind() {
        "identifier" | "operator_identifier" => {
            let name = scala_node_text(node, source).trim();
            if name.is_empty() {
                Vec::new()
            } else {
                vec![name]
            }
        }
        _ => {
            let mut names = Vec::new();
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                names.extend(scala_pattern_names(child, source));
            }
            names
        }
    }
}

fn scala_seed_typed(
    name: &str,
    resolved: Option<String>,
    is_direct_member: bool,
    bindings: &mut LocalInferenceEngine<String>,
) {
    match resolved {
        Some(fqn) => bindings.seed_symbol(name.to_string(), fqn),
        None if !is_direct_member => bindings.declare_shadow(name.to_string()),
        None => {}
    }
}

fn scala_is_direct_member_value_definition(node: Node<'_>) -> bool {
    let mut current = node.parent();
    while let Some(ancestor) = current {
        match ancestor.kind() {
            "function_definition"
            | "block"
            | "block_expression"
            | "indented_block"
            | "case_clause"
            | "lambda_expression" => return false,
            "class_definition" | "object_definition" | "trait_definition" | "enum_definition" => {
                return true;
            }
            _ => current = ancestor.parent(),
        }
    }
    false
}

fn scala_import_boundary_for_name(
    scala: &ScalaAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    name: &str,
) -> bool {
    let simple = scala_simple_name(name);
    for import in scala.import_info_of(file) {
        let Some(path) = scala_import_path(&import) else {
            continue;
        };
        if import.is_wildcard {
            if simple.chars().next().is_some_and(char::is_uppercase)
                && !scala_workspace_package_exists(support, &path)
            {
                return true;
            }
            continue;
        }
        let local_name = import
            .identifier
            .as_deref()
            .unwrap_or_else(|| path.rsplit('.').next().unwrap_or(path.as_str()));
        if local_name == simple && supportless_scala_import_target_missing(support, &path) {
            return true;
        }
    }
    false
}

fn supportless_scala_import_target_missing(
    support: &dyn BoundedDefinitionLookup,
    path: &str,
) -> bool {
    let normalized = path.replace("$.", ".").trim_end_matches('$').to_string();
    !support.fqn_exists(path) && !support.fqn_exists(&normalized)
}

fn scala_workspace_package_exists(support: &dyn BoundedDefinitionLookup, package: &str) -> bool {
    support.package_exists(package)
}

fn scala_simple_name(name: &str) -> &str {
    name.split(['[', '(', '{', '.', ' ', '<'])
        .next()
        .unwrap_or(name)
        .trim()
}
