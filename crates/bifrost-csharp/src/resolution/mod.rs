//! File-local C# lexical facts. Selected compilations and typed lookup own targets.
use crate::preprocessor::PreprocessorScan;
use crate::syntax::{csharp_has_modifier, csharp_identifier_text};
use brokk_bifrost_core::analyzer::resolution_facts::*;
use brokk_bifrost_core::analyzer::source_facts::{
    PrimarySourceFactCollector, SourceDeclarationId, SourceOccurrenceId, SourceOccurrenceProvenance,
};
use brokk_bifrost_core::analyzer::structural::resolution::{DeclaredVisibility, HoistingClass};
use brokk_bifrost_core::analyzer::tree_walk::ParentIndex;
use brokk_bifrost_core::analyzer::tree_walk::{
    children_by_field_name, first_named_child_of_kind, named_children, single_named_child_matching,
};
use brokk_bifrost_core::hash::{HashMap, HashSet};
use tree_sitter::{Node, Tree};

mod imports;
mod names;
mod types;
mod values;

#[derive(Default)]
pub struct SourceBridges {
    pub occurrences: Vec<SourceOccurrenceId>,
    pub declarations: Vec<(ResolutionSiteId, SourceDeclarationId)>,
}

#[derive(Clone, Copy)]
struct Context {
    scope: ResolutionScopeId,
    package: ResolutionScopeId,
    owner: Option<ResolutionSiteId>,
    type_parameters: Option<ResolutionScopeId>,
    owner_has_type_parameters: bool,
    unsupported_enclosing_application: bool,
}

struct Producer<'a, 's> {
    source: &'s str,
    collector: &'a mut PrimarySourceFactCollector<'s>,
    bridges: &'a mut SourceBridges,
    facts: FileResolutionFacts,
    names: HashMap<String, ResolutionNameId>,
    claimed: HashSet<usize>,
    declared_types:
        HashMap<(usize, ResolutionScopeId), (ResolutionTypeSlotId, Option<ResolutionSiteId>)>,
    owner_applications: HashMap<ResolutionSiteId, ResolutionTypeSlotId>,
    member_expression_outputs: HashMap<usize, ResolutionTypeSlotId>,
    namespace_paths: HashMap<ResolutionScopeId, Vec<ResolutionNameId>>,
    imports: Vec<(ResolutionSiteId, bool, Option<ResolutionNameId>)>,
    excluded: Vec<(usize, usize)>,
    directive_ends: HashMap<ResolutionScopeId, usize>,
}

/// Lower one primary tree using the declaration extractor's canonical collector.
pub fn produce<'s>(
    tree: &Tree,
    source: &'s str,
    preprocessor: &PreprocessorScan,
    collector: &mut PrimarySourceFactCollector<'s>,
    bridges: &mut SourceBridges,
) -> FileResolutionFacts {
    // The parser may expose disabled nodes despite included ranges (#7386).
    // Merge the scan's branch/directive intervals once per file, then seek them.
    let mut intervals = Vec::new();
    for branch in &preprocessor.branches {
        intervals.push((branch.directive_start, branch.directive_end));
        if !branch.kept {
            intervals.push((branch.directive_end, branch.end_byte));
        }
        if let Some(closing) = branch.closing_directive {
            intervals.push(closing);
        }
    }
    let excluded = merged_intervals(intervals);
    let root = ResolutionScopeId::try_from_index(0).unwrap();
    let mut p = Producer {
        source,
        collector,
        bridges,
        facts: FileResolutionFacts::default(),
        names: HashMap::default(),
        claimed: HashSet::default(),
        declared_types: HashMap::default(),
        owner_applications: HashMap::default(),
        member_expression_outputs: HashMap::default(),
        namespace_paths: HashMap::default(),
        imports: Vec::new(),
        excluded,
        directive_ends: HashMap::default(),
    };
    p.facts.scopes.push(ResolutionScopeFact {
        id: root,
        parent: None,
        owner: None,
        kind: ResolutionScopeKind::CompilationUnit,
        inheritance: ResolutionScopeInheritance::Lexical,
        start_byte: 0,
        end_byte: source.len(),
    });
    let site = p.facts.add_site(
        root,
        ResolutionSiteKind::PackageDeclaration,
        0,
        source.len(),
    );
    p.bridges.occurrences.push(p.collector.intern_subspan_bytes(
        0,
        source.len(),
        SourceOccurrenceProvenance::Embedded,
    ));
    p.package(root, None, site, Vec::new());
    // M5 attaches the selected compilation's global/SDK implicit usings.
    // These usings add lexical type, value and callable candidates, not exports.
    for namespace in [
        ResolutionNamespace::Type,
        ResolutionNamespace::Value,
        ResolutionNamespace::Callable,
    ] {
        p.facts.add_route_gap(
            site,
            ResolutionRouteGap::UnknownBinder {
                scope: root,
                name: None,
                namespace: Some(namespace),
                may_publish: false,
            },
        );
    }
    let context = Context {
        scope: root,
        package: root,
        owner: None,
        type_parameters: None,
        owner_has_type_parameters: false,
        unsupported_enclosing_application: false,
    };
    // #10342: recovery can attach a damaged directive to a following declaration.
    let mut directive_nodes = named_children(tree.root_node());
    directive_nodes.reverse();
    let mut directive_end = source.len();
    while let Some(node) = directive_nodes.pop() {
        if matches!(node.kind(), "preproc_if" | "preproc_elif" | "preproc_else") {
            directive_nodes.extend(named_children(node).into_iter().rev());
        } else if (!matches!(
            node.kind(),
            "using_directive"
                | "extern_alias_directive"
                | "ERROR"
                | "comment"
                | "shebang_directive"
        ) && !node.kind().starts_with("preproc_")
            && node
                .parent()
                .is_some_and(|parent| parent.kind() == "compilation_unit"))
            || matches!(
                node.kind(),
                "namespace_declaration"
                    | "file_scoped_namespace_declaration"
                    | "class_declaration"
                    | "struct_declaration"
                    | "interface_declaration"
                    | "enum_declaration"
                    | "record_declaration"
                    | "record_struct_declaration"
                    | "delegate_declaration"
                    | "global_statement"
                    | "global_attribute"
            )
        {
            directive_end = node.start_byte();
            break;
        }
    }
    // Some handlers claim their whole subtree, so inspect recovery nodes before dispatch.
    let mut error_sites = HashMap::default();
    let mut pending = vec![tree.root_node()];
    while let Some(node) = pending.pop() {
        if node.kind() == "ERROR"
            && !p.is_excluded(node)
            && (node.start_byte() < directive_end
                || node
                    .parent()
                    .is_some_and(|parent| parent.kind() == "compilation_unit"))
        {
            let site = p.site(node, root, ResolutionSiteKind::UnsupportedRoute);
            p.facts.add_reference_enumeration_gap(
                site,
                ResolutionGapKind::CompilationImportsUnenumerated,
            );
            error_sites.insert(node.id(), site);
        }
        pending.extend(named_children(node));
    }
    let mut file_namespace: Option<(usize, Context)> = None;
    let mut stack = vec![(tree.root_node(), context)];
    while let Some((node, mut ctx)) = stack.pop() {
        if p.is_excluded(node)
            || (node.kind().starts_with("preproc_")
                && !matches!(node.kind(), "preproc_if" | "preproc_elif" | "preproc_else"))
        {
            continue;
        }
        if ctx.scope == root
            && let Some((start, namespace)) = file_namespace
            && node.start_byte() >= start
        {
            ctx = namespace;
        }
        if matches!(node.kind(), "using_directive" | "extern_alias_directive") {
            let end = p.directive_ends.entry(ctx.scope).or_default();
            *end = (*end).max(node.end_byte());
        }
        if node.kind() == "generic_name"
            && first_named_child_of_kind(node, "identifier").is_some_and(|name| p.is_excluded(name))
        {
            let site = p.omit(node, ctx.scope, ResolutionGapKind::UnsupportedTypeSyntax);
            p.compilation_omission(node, site);
            continue;
        }
        if node
            .child_by_field_name("name")
            .is_some_and(|name| p.is_excluded(name))
        {
            let site = p.omit(node, ctx.scope, ResolutionGapKind::UnsupportedScopeOrBinder);
            p.compilation_omission(node, site);
            continue;
        }
        if node.is_missing()
            || (node.kind() == "generic_name"
                && first_named_child_of_kind(node, "identifier")
                    .is_none_or(|name| name.is_missing()))
            || node
                .child_by_field_name("name")
                .is_some_and(|n| n.is_missing())
        {
            let site = p.omit(node, ctx.scope, ResolutionGapKind::MalformedSyntax);
            p.compilation_omission(node, site);
            continue;
        }
        if first_named_child_of_kind(node, "explicit_interface_specifier").is_some() {
            p.omit(node, ctx.scope, ResolutionGapKind::UnsupportedMemberScope);
            continue;
        }
        let mut skip = false;
        let mut field_initializer_declaration = None;
        match node.kind() {
            "namespace_declaration" | "file_scoped_namespace_declaration" => {
                let Some(name) = node.child_by_field_name("name") else {
                    p.omit(node, ctx.scope, ResolutionGapKind::MalformedSyntax);
                    continue;
                };
                let Some(parts) = p.path(name) else {
                    p.omit(node, ctx.scope, ResolutionGapKind::UnsupportedRoute);
                    continue;
                };
                let Some(part_names) = parts
                    .iter()
                    .map(|&part| p.name(part))
                    .collect::<Option<Vec<_>>>()
                else {
                    p.omit(node, ctx.scope, ResolutionGapKind::MalformedSyntax);
                    continue;
                };
                let mut path = p.namespace_paths[&ctx.package].clone();
                let end = if node.kind() == "file_scoped_namespace_declaration" {
                    source.len()
                } else {
                    node.end_byte()
                };
                // Nested declarations and dotted namespaces lower identically:
                // C# resolves each level separately (ECMA-334 14.5 and 7.6),
                // so A.B.X and A.X must belong to different scope choices.
                for (index, part) in parts.into_iter().enumerate() {
                    // Preserve the whole-declaration sites for existing readers.
                    // Later segments have their own AST occurrences and scopes.
                    let site_node = if index == 0 { node } else { part };
                    let owner = p.site(site_node, ctx.scope, ResolutionSiteKind::ModuleDeclaration);
                    let declaration =
                        p.site(site_node, ctx.scope, ResolutionSiteKind::PackageDeclaration);
                    path.push(part_names[index]);
                    let scope = p.facts.allocate_lexical_scope(
                        ctx.scope,
                        Some(owner),
                        ResolutionScopeKind::Package,
                        node.start_byte(),
                        end,
                    );
                    p.package(scope, Some(declaration), declaration, path.clone());
                    ctx.scope = scope;
                    ctx.package = scope;
                }
                p.claim_tree(name);
                if node.kind() == "file_scoped_namespace_declaration" {
                    // File namespaces extend beyond a transparent preprocessor
                    // container too, not only direct compilation-unit siblings.
                    file_namespace = Some((node.end_byte(), ctx));
                }
            }
            "using_directive" => {
                p.using(node, ctx);
                skip = true;
            }
            "class_declaration"
            | "struct_declaration"
            | "interface_declaration"
            | "record_declaration"
            | "record_struct_declaration"
            | "enum_declaration"
            | "delegate_declaration" => {
                if let Some(name) = node.child_by_field_name("name") {
                    let site = p.declare(
                        node,
                        name,
                        ctx,
                        ResolutionSiteKind::TypeDeclaration,
                        ResolutionNamespace::Type,
                        ResolutionBinderKind::Type,
                    );
                    if let Some(owner) = ctx.owner {
                        p.member(site, owner, ResolutionMemberKind::NestedType, true);
                    } else {
                        p.facts.package_members.push(ResolutionPackageMemberFact {
                            root_scope: ctx.package,
                            declaration: site,
                            namespace: ResolutionNamespace::Type,
                        });
                        p.facts.root_exports.push(ResolutionRootExportFact {
                            root_scope: ctx.package,
                            declaration: site,
                            namespace: ResolutionNamespace::Type,
                        });
                    }
                    // A nested declaration keeps its own formals. The current
                    // source application has no enclosing instantiation relation.
                    ctx.unsupported_enclosing_application |= ctx.owner_has_type_parameters;
                    ctx.owner_has_type_parameters =
                        first_named_child_of_kind(node, "type_parameter_list").is_some();
                    ctx.owner = Some(site);
                    ctx.type_parameters = None;
                    if first_named_child_of_kind(node, "type_parameter_list").is_some() {
                        ctx.scope = p.facts.allocate_lexical_scope(
                            ctx.scope,
                            Some(site),
                            ResolutionScopeKind::Block,
                            node.start_byte(),
                            node.end_byte(),
                        );
                        ctx.type_parameters = Some(ctx.scope);
                    }
                    // C# 7.7.2: declaration type parameters are visible in
                    // the header, but the current/inherited nested-type tier
                    // applies only within the body. Keep outer scopes intact.
                    p.authored_parents(node, site, ctx);
                    ctx.scope = p.facts.allocate_lexical_scope(
                        ctx.scope,
                        Some(site),
                        ResolutionScopeKind::TypeBody,
                        node.start_byte(),
                        node.end_byte(),
                    );
                    p.root_candidate(node, site, ctx);
                    p.owner_application(node, site, ctx);
                    if csharp_has_modifier(source, node, "partial") {
                        // Other parts in this compilation can publish members.
                        let gap = p.site(node, ctx.scope, ResolutionSiteKind::UnsupportedRoute);
                        p.facts.add_route_gap(
                            gap,
                            ResolutionRouteGap::UnknownBinder {
                                scope: ctx.scope,
                                name: None,
                                namespace: None,
                                may_publish: true,
                            },
                        );
                    }
                }
            }
            "method_declaration" | "constructor_declaration" | "local_function_statement" => {
                if let Some(name) = node.child_by_field_name("name") {
                    let constructor = node.kind() == "constructor_declaration";
                    let site = p.declare(
                        node,
                        name,
                        ctx,
                        if constructor {
                            ResolutionSiteKind::ConstructorDeclaration
                        } else {
                            ResolutionSiteKind::CallableDeclaration
                        },
                        if constructor {
                            ResolutionNamespace::Constructor
                        } else {
                            ResolutionNamespace::Callable
                        },
                        if constructor {
                            ResolutionBinderKind::Constructor
                        } else {
                            ResolutionBinderKind::Callable
                        },
                    );
                    let type_parameter_count =
                        first_named_child_of_kind(node, "type_parameter_list")
                            .map_or(0, crate::declarations::count_type_parameters);
                    p.facts
                        .callable_signatures
                        .push(ResolutionCallableSignatureFact {
                            callable: site,
                            type_parameter_count: dense_ordinal(
                                type_parameter_count,
                                "callable type parameter",
                            ),
                            result_types: Vec::new(),
                        });
                    // This lexical milestone retains the required signature
                    // header; M6 supplies parameter/result types and applicability.
                    p.facts
                        .add_gap(site, ResolutionGapKind::UnsupportedCallApplicability);
                    if node.kind() != "local_function_statement"
                        && let Some(owner) = ctx.owner
                    {
                        p.member(
                            site,
                            owner,
                            if constructor {
                                ResolutionMemberKind::Constructor
                            } else {
                                ResolutionMemberKind::Method
                            },
                            csharp_has_modifier(source, node, "static"),
                        );
                    }
                    ctx.type_parameters = None;
                    if first_named_child_of_kind(node, "type_parameter_list").is_some() {
                        ctx.scope = p.facts.allocate_lexical_scope(
                            ctx.scope,
                            Some(site),
                            ResolutionScopeKind::Block,
                            node.start_byte(),
                            node.end_byte(),
                        );
                        ctx.type_parameters = Some(ctx.scope);
                    }
                    // ECMA-334 7.7.1: method type parameters are in scope
                    // in the return type as well as in the parameter list.
                    if let Some(returns) = crate::declarations::csharp_declared_type_node(node)
                        && !p.is_excluded(returns)
                    {
                        let input = p.declared_type(returns, ctx);
                        let slot = p.attach_declared_type(
                            site,
                            input,
                            returns,
                            DeclarationTypeRole::Return,
                        );
                        p.facts
                            .callable_signatures
                            .last_mut()
                            .expect("callable signature exists")
                            .result_types
                            .push(ResolutionCallableResultTypeFact {
                                ordinal: 0,
                                value_type: slot,
                            });
                    }
                    ctx.scope = p.facts.allocate_lexical_scope(
                        ctx.scope,
                        Some(site),
                        ResolutionScopeKind::Executable,
                        node.start_byte(),
                        node.end_byte(),
                    );
                }
            }
            "accessor_declaration" | "lambda_expression" | "anonymous_method_expression" => {
                ctx.type_parameters = None;
                ctx.scope = p.facts.allocate_lexical_scope(
                    ctx.scope,
                    None,
                    ResolutionScopeKind::Executable,
                    node.start_byte(),
                    node.end_byte(),
                );
                if node.kind() == "accessor_declaration"
                    && let Some(keyword) = node.child_by_field_name("name")
                    && matches!(keyword.kind(), "set" | "init" | "add" | "remove")
                {
                    // Like Kotlin's synthetic valueOf parameter, anchor the
                    // implicit declaration to its owner syntax without claiming
                    // a source declaration token or source-declaration bridge.
                    let site = p.site(keyword, ctx.scope, ResolutionSiteKind::ValueDeclaration);
                    let name = p
                        .facts
                        .intern_name(&mut p.names, "value")
                        .expect("static non-empty literal");
                    p.facts.identifiers.push(PositionedIdentifierFact {
                        site,
                        name,
                        role: ResolutionIdentifierRole::Declaration,
                        namespace: ResolutionNamespace::Value,
                        qualifier: None,
                    });
                    p.facts.binders.push(ResolutionBinderFact::scope_wide(
                        site,
                        ResolutionBinderKind::Parameter,
                        *p.facts.scope(ctx.scope),
                    ));
                }
            }
            "property_declaration" | "event_declaration" | "enum_member_declaration" => {
                if let Some(name) = node.child_by_field_name("name") {
                    let site = p.declare(
                        node,
                        name,
                        ctx,
                        ResolutionSiteKind::ValueDeclaration,
                        ResolutionNamespace::Value,
                        ResolutionBinderKind::Field,
                    );
                    if let Some(owner) = ctx.owner {
                        p.member(
                            site,
                            owner,
                            ResolutionMemberKind::Field,
                            csharp_has_modifier(source, node, "static")
                                || node.kind() == "enum_member_declaration",
                        );
                    }
                }
            }
            "variable_declaration" => {
                // Lower a shared head before the ordinary source-order walk
                // reaches it. Each following declarator reuses this syntax slot.
                if let Some(ty) = node.child_by_field_name("type")
                    && ty.kind() != "implicit_type"
                    && !p.is_excluded(ty)
                {
                    p.declared_type(ty, ctx);
                }
            }
            "parameter"
            | "implicit_parameter"
            | "type_parameter"
            | "variable_declarator"
            | "declaration_expression"
            | "declaration_pattern"
            | "var_pattern"
            | "recursive_pattern"
            | "list_pattern"
            | "catch_declaration"
                if node.kind() != "type_parameter" || !p.claimed.contains(&node.id()) =>
            {
                let name = node
                    .child_by_field_name("name")
                    .or_else(|| (node.kind() == "implicit_parameter").then_some(node));
                if let Some(name) = name
                    && (name.kind() == "identifier" || node.kind() == "implicit_parameter")
                    && (node.kind() != "declaration_expression"
                        || crate::syntax::csharp_local_binder_name(name))
                {
                    let type_parameter = node.kind() == "type_parameter";
                    let field = node.parent().and_then(|n| n.parent()).is_some_and(|n| {
                        matches!(n.kind(), "field_declaration" | "event_field_declaration")
                    });
                    let parameter = matches!(node.kind(), "parameter" | "implicit_parameter");
                    let kind = if type_parameter {
                        ResolutionBinderKind::Type
                    } else if field {
                        ResolutionBinderKind::Field
                    } else if parameter {
                        ResolutionBinderKind::Parameter
                    } else if node.kind().ends_with("pattern") {
                        ResolutionBinderKind::Pattern
                    } else {
                        ResolutionBinderKind::Local
                    };
                    let binding_scope = if type_parameter {
                        let Some(scope) = ctx.type_parameters else {
                            p.omit(node, ctx.scope, ResolutionGapKind::UnsupportedScopeOrBinder);
                            continue;
                        };
                        scope
                    } else {
                        ctx.scope
                    };
                    let site = p.declare(
                        node,
                        name,
                        Context {
                            scope: binding_scope,
                            ..ctx
                        },
                        if type_parameter {
                            ResolutionSiteKind::TypeDeclaration
                        } else {
                            ResolutionSiteKind::ValueDeclaration
                        },
                        if type_parameter {
                            ResolutionNamespace::Type
                        } else {
                            ResolutionNamespace::Value
                        },
                        kind,
                    );
                    if node.kind() == "variable_declarator" {
                        if field {
                            field_initializer_declaration = Some(site);
                        } else {
                            p.initialize_value(node, site, ctx);
                        }
                    }
                    if field && let Some(owner) = ctx.owner {
                        let declaration = node.parent().and_then(|n| n.parent()).unwrap();
                        p.member(
                            site,
                            owner,
                            ResolutionMemberKind::Field,
                            csharp_has_modifier(source, declaration, "static")
                                || csharp_has_modifier(source, declaration, "const"),
                        );
                    }
                }
            }
            "block"
            | "for_statement"
            | "foreach_statement"
            | "using_statement"
            | "catch_clause"
            | "switch_body"
            | "switch_expression_arm" => {
                ctx.scope = p.facts.allocate_lexical_scope(
                    ctx.scope,
                    None,
                    ResolutionScopeKind::Block,
                    node.start_byte(),
                    node.end_byte(),
                );
                if node.kind() == "foreach_statement"
                    && let Some(name) = node.child_by_field_name("left")
                    && name.kind() == "identifier"
                    && !p.is_excluded(name)
                {
                    p.declare(
                        node,
                        name,
                        ctx,
                        ResolutionSiteKind::ValueDeclaration,
                        ResolutionNamespace::Value,
                        ResolutionBinderKind::Local,
                    );
                }
            }
            "tuple_pattern" | "parenthesized_variable_designation" => {
                for name in children_by_field_name(node, "name")
                    .into_iter()
                    .filter(|n| n.kind() == "identifier")
                {
                    if p.is_excluded(name) {
                        continue;
                    }
                    p.declare(
                        name,
                        name,
                        ctx,
                        ResolutionSiteKind::ValueDeclaration,
                        ResolutionNamespace::Value,
                        ResolutionBinderKind::Local,
                    );
                }
            }
            "shebang_directive"
                if node
                    .parent()
                    .is_some_and(|p| p.kind() == "compilation_unit") =>
            {
                let site = p.site(node, ctx.scope, ResolutionSiteKind::UnsupportedRoute);
                p.facts
                    .add_gap(site, ResolutionGapKind::FileProgramEvidence);
            }
            "extern_alias_directive" => {
                let name = node
                    .child_by_field_name("name")
                    .expect("extern alias has a name");
                let Some(name) = p.name(name) else {
                    p.omit(node, ctx.scope, ResolutionGapKind::MalformedSyntax);
                    continue;
                };
                let site = p.site(node, ctx.scope, ResolutionSiteKind::ImportDeclaration);
                p.facts.extern_aliases.push(ResolutionExternAliasFact {
                    site,
                    scope: ctx.scope,
                    name,
                });
                skip = true;
            }
            "attribute"
            | "indexer_declaration"
            | "operator_declaration"
            | "conversion_operator_declaration"
            | "explicit_interface_specifier"
            | "query_expression"
            | "global_statement" => {
                let kind = match node.kind() {
                    "attribute" => ResolutionGapKind::UnsupportedTypeSyntax,
                    "query_expression" | "global_statement" => {
                        ResolutionGapKind::UnsupportedScopeOrBinder
                    }
                    _ => ResolutionGapKind::UnsupportedMemberScope,
                };
                let site = p.omit(node, ctx.scope, kind);
                if node.kind() == "attribute" {
                    p.collect_friend_attribute(node, ctx.scope, site);
                }
                skip = true;
            }
            "qualified_name" | "alias_qualified_name" | "member_access_expression"
                if !p.claimed.contains(&node.id()) =>
            {
                if node.kind() == "member_access_expression"
                    && p.member_expression(node, ctx).is_some()
                {
                    // The expression publisher claimed its exact member spine.
                } else if p.path(node).is_some() {
                    p.reference_path(node, ctx);
                } else {
                    let site = p.site(node, ctx.scope, ResolutionSiteKind::UnsupportedExpression);
                    p.facts
                        .add_gap(site, ResolutionGapKind::UnsupportedExpression);
                    p.facts.add_reference_enumeration_gap(
                        site,
                        ResolutionGapKind::UnsupportedExpression,
                    );
                    // A selected member on an expression receiver is not a free
                    // lexical name. Keep walking its receiver, but leave the
                    // selected member to M6's typed path.
                    if let Some(name) = node.child_by_field_name("name") {
                        p.claim_tree(name);
                    }
                }
            }
            "identifier" | "generic_name" if !p.claimed.contains(&node.id()) => {
                if brokk_bifrost_core::analyzer::common::node_source_text(node, source) == "dynamic"
                    && crate::syntax::csharp_type_reference_root(node).is_some()
                {
                    p.omit(node, ctx.scope, ResolutionGapKind::UnsupportedTypeSyntax);
                } else {
                    p.reference_path(node, ctx);
                }
            }
            "assignment_expression" => {
                if let (Some(left), Some(right)) = (
                    node.child_by_field_name("left"),
                    node.child_by_field_name("right"),
                ) {
                    if left.kind() == "identifier" {
                        let simple_assignment = {
                            let mut cursor = node.walk();
                            node.children(&mut cursor).any(|child| child.kind() == "=")
                        };
                        let target = p.value_reference(left, ctx);
                        let value =
                            p.expression_value(if simple_assignment { right } else { node }, ctx);
                        p.facts
                            .local_writes
                            .push(ResolutionLocalWriteFact { target, value });
                    } else {
                        let site =
                            p.site(node, ctx.scope, ResolutionSiteKind::UnsupportedExpression);
                        p.facts
                            .add_gap(site, ResolutionGapKind::UnsupportedExpression);
                    }
                }
            }
            "ERROR" => {
                if let Some(&site) = error_sites.get(&node.id()) {
                    // Preserve the ordinary omission's lexical scope (including file namespaces).
                    p.facts.sites[site.index()].scope = ctx.scope;
                    p.omit_site(node, ctx.scope, ResolutionGapKind::MalformedSyntax, site);
                } else {
                    p.omit(node, ctx.scope, ResolutionGapKind::MalformedSyntax);
                }
                skip = true;
            }
            "constructor_initializer" | "element_access_expression" => {
                // The implicit constructor/indexer target is unenumerated, but
                // arguments and receivers still contain independently known references.
                let site = p.site(node, ctx.scope, ResolutionSiteKind::UnsupportedRoute);
                p.facts
                    .add_gap(site, ResolutionGapKind::UnsupportedExpression);
                p.facts
                    .add_reference_enumeration_gap(site, ResolutionGapKind::UnsupportedExpression);
                if node.kind() == "constructor_initializer" {
                    for child in named_children(node) {
                        if matches!(child.kind(), "this" | "base") {
                            p.claim_tree(child);
                        }
                    }
                }
            }
            // These paths were already published or claimed by declaration/type lowering.
            // Descend anyway: a generic path can still contain unclaimed arguments.
            "identifier"
            | "generic_name"
            | "qualified_name"
            | "alias_qualified_name"
            | "member_access_expression" => {}
            "boolean_literal" => {} // Boolean value cannot name a declaration.
            "integer_literal" => {} // Numeric value cannot name a declaration.
            "real_literal" => {}    // Numeric value cannot name a declaration.
            "character_literal" => {} // Character value cannot name a declaration.
            "string_literal" => {}  // String value cannot name a declaration.
            "verbatim_string_literal" => {} // String value cannot name a declaration.
            "raw_string_literal" => {} // String value cannot name a declaration.
            "null_literal" => {}    // Null value cannot name a declaration.
            "modifier" => {}        // Declaration modifier keyword does not name a declaration.
            "implicit_type" => {}   // Inferred type keyword has no explicit target.
            "predefined_type" => {} // Intrinsic type keyword has no source declaration target.
            "break_statement" => {} // Control transfer has no declaration target.
            "continue_statement" => {} // Control transfer has no declaration target.
            "empty_statement" => {} // Empty statement contains no reference.
            "comment" => {}         // Comment is not executable syntax.
            "string_content" => {}  // Literal content cannot name a declaration.
            "string_literal_content" => {} // Literal content cannot name a declaration.
            "escape_sequence" => {} // Escaped literal content cannot name a declaration.
            "interpolation_format_clause" => {} // Format text cannot name a declaration.
            "string_literal_encoding" => {} // Encoding suffix cannot name a declaration.
            "interpolation_start" => {} // String delimiter cannot name a declaration.
            "interpolation_quote" => {} // String delimiter cannot name a declaration.
            "interpolation_brace" => {} // String delimiter cannot name a declaration.
            "raw_string_start" => {} // String delimiter cannot name a declaration.
            "raw_string_end" => {}  // String delimiter cannot name a declaration.
            "raw_string_content" => {} // Literal content cannot name a declaration.
            "character_literal_content" => {} // Literal content cannot name a declaration.
            "discard" => {}         // Discard has no declaration target.
            "constructor_constraint" => {} // Constructor constraint keyword has no selected constructor.
            // Containers delegate reference enumeration to their named children.
            "array_type"
            | "global_attribute"
            | "switch_section"
            | "when_clause"
            | "throw_expression"
            | "typeof_expression"
            | "sizeof_expression"
            | "default_expression"
            | "type_pattern"
            | "subpattern"
            | "property_pattern_clause"
            | "positional_pattern_clause"
            | "ref_expression"
            | "range_expression"
            | "unary_expression"
            | "accessor_list"
            | "argument"
            | "argument_list"
            | "array_rank_specifier"
            | "arrow_expression_clause"
            | "attribute_list"
            | "base_list"
            | "bracketed_argument_list"
            | "bracketed_parameter_list"
            | "catch_filter_clause"
            | "compilation_unit"
            | "declaration_list"
            | "enum_member_declaration_list"
            | "expression_statement"
            | "field_declaration"
            | "event_field_declaration"
            | "finally_clause"
            | "if_statement"
            | "do_statement"
            | "while_statement"
            | "return_statement"
            | "throw_statement"
            | "try_statement"
            | "local_declaration_statement"
            | "parameter_list"
            | "type_argument_list"
            | "type_parameter_list"
            | "type_parameter_constraints_clause"
            | "type_parameter_constraint"
            | "parenthesized_expression"
            | "conditional_expression"
            | "invocation_expression"
            | "object_creation_expression"
            | "array_creation_expression"
            | "implicit_array_creation_expression"
            | "initializer_expression"
            | "binary_expression"
            | "prefix_unary_expression"
            | "postfix_unary_expression"
            | "cast_expression"
            | "as_expression"
            | "is_expression"
            | "is_pattern_expression"
            | "await_expression"
            | "checked_expression"
            | "checked_statement"
            | "lock_statement"
            | "unsafe_statement"
            | "yield_statement"
            | "tuple_expression"
            | "tuple_element"
            | "constant_pattern"
            | "and_pattern"
            | "or_pattern"
            | "negated_pattern"
            | "parenthesized_pattern"
            | "relational_pattern"
            | "switch_expression"
            | "switch_statement"
            | "expression_element"
            | "collection_element"
            | "interpolation"
            | "interpolation_alignment_clause"
            | "interpolated_string_expression"
            | "preproc_if"
            | "preproc_elif"
            | "preproc_else" => {}
            _ if p.claimed.contains(&node.id()) => {}
            _ => {
                p.omit(node, ctx.scope, ResolutionGapKind::UnsupportedExpression);
                skip = true;
            }
        }
        if !skip {
            // ECMA-334 7.3: the constructor body's declaration space is
            // nested inside its initializer's, so expression variables survive
            // into the body. Parameters remain in the enclosing Executable.
            let constructor_scope = (node.kind() == "constructor_declaration")
                .then(|| first_named_child_of_kind(node, "constructor_initializer"))
                .flatten()
                .filter(|initializer| !p.is_excluded(*initializer))
                .map(|initializer| {
                    let scope = p.facts.allocate_lexical_scope(
                        ctx.scope,
                        None,
                        ResolutionScopeKind::Block,
                        initializer.start_byte(),
                        node.child_by_field_name("body")
                            .map_or(node.end_byte(), |body| body.end_byte()),
                    );
                    (initializer.id(), scope)
                });
            for child in named_children(node).into_iter().rev() {
                let mut child_ctx = ctx;
                if let Some((initializer, scope)) = constructor_scope
                    && (child.id() == initializer
                        || node
                            .child_by_field_name("body")
                            .is_some_and(|body| body.id() == child.id()))
                {
                    child_ctx.scope = scope;
                }
                let initializer = if node.kind() == "variable_declarator"
                    && node.parent().and_then(|n| n.parent()).is_some_and(|owner| {
                        matches!(
                            owner.kind(),
                            "field_declaration" | "event_field_declaration"
                        )
                    }) {
                    crate::syntax::variable_declarator_initializer(node)
                } else if node.kind() == "property_declaration" {
                    node.child_by_field_name("value")
                } else {
                    None
                };
                if initializer.is_some_and(|initializer| initializer.id() == child.id())
                    && !p.is_excluded(child)
                {
                    // Expression variables belong to this initializer, never
                    // to other initializers or the surrounding type body.
                    child_ctx.scope = p.facts.allocate_lexical_scope(
                        ctx.scope,
                        None,
                        ResolutionScopeKind::Block,
                        child.start_byte(),
                        child.end_byte(),
                    );
                }
                if initializer.is_some_and(|initializer| initializer.id() == child.id())
                    && !p.is_excluded(child)
                    && let Some(declaration) = field_initializer_declaration
                {
                    p.initialize_value(node, declaration, child_ctx);
                }
                stack.push((child, child_ctx));
            }
        }
    }
    // Keep native activation and query-time body classification on one rule.
    let chain_conditions = preprocessor.chain_activations();
    let decided_disabled = merged_intervals(
        preprocessor
            .branches
            .iter()
            .filter(|branch| !branch.kept && !chain_conditions[branch.chain].uncertain)
            .map(|branch| (branch.directive_start, branch.end_byte))
            .collect(),
    );
    let uncertain_kept = merged_intervals(
        preprocessor
            .branches
            .iter()
            .filter(|branch| branch.kept && chain_conditions[branch.chain].uncertain)
            .map(|branch| (branch.directive_end, branch.end_byte))
            .collect(),
    );
    let mut activation_sites = p
        .facts
        .identifiers
        .iter()
        .map(|identifier| identifier.site)
        .collect::<HashSet<_>>();
    activation_sites.extend(p.facts.root_imports.iter().map(|import| import.site));
    let uncertain_sites = p
        .facts
        .sites
        .iter()
        .filter(|site| {
            activation_sites.contains(&site.id)
                && span_is_contained(&uncertain_kept, site.start_byte, site.end_byte)
        })
        .map(|site| site.id)
        .collect::<Vec<_>>();
    for site in uncertain_sites {
        // The authored inventory is retained; only its activation is unproven.
        p.facts.add_gap(site, ResolutionGapKind::UnprovenActivation);
    }
    let mut chain_starts: HashMap<usize, usize> = HashMap::default();
    for branch in &preprocessor.branches {
        chain_starts
            .entry(branch.chain)
            .and_modify(|start| *start = (*start).min(branch.directive_start))
            .or_insert(branch.directive_start);
    }
    for branch in &preprocessor.branches {
        if !branch.kept
            && chain_conditions[branch.chain].uncertain
            && !span_is_contained(&decided_disabled, branch.directive_start, branch.end_byte)
        {
            let scope = p
                .facts
                .scopes
                .iter()
                .filter(|s| {
                    s.start_byte <= chain_starts[&branch.chain] && branch.end_byte <= s.end_byte
                })
                .min_by_key(|s| s.end_byte - s.start_byte)
                .unwrap()
                .id;
            let site = p.facts.add_site(
                scope,
                ResolutionSiteKind::UnsupportedRoute,
                branch.directive_start,
                branch.end_byte,
            );
            let occurrence = p.collector.intern_subspan_bytes(
                branch.directive_start,
                branch.end_byte,
                SourceOccurrenceProvenance::Embedded,
            );
            p.bridges.occurrences.push(occurrence);
            p.facts.add_route_gap(
                site,
                ResolutionRouteGap::UnknownBinder {
                    scope,
                    name: None,
                    namespace: None,
                    may_publish: true,
                },
            );
            p.facts.add_route_gap(
                site,
                ResolutionRouteGap::OmittedReference {
                    scope,
                    terminal: None,
                    namespace: None,
                },
            );
            p.facts
                .add_reference_enumeration_gap(site, ResolutionGapKind::UnsupportedRoute);
            // A namespace at EOF can have exactly the compilation unit's range.
            // Preserve the ordinary omission scope, but do not call that tie root-only.
            if scope == root
                && !p.facts.scopes.iter().any(|candidate| {
                    candidate.id != root
                        && candidate.start_byte <= chain_starts[&branch.chain]
                        && branch.end_byte <= candidate.end_byte
                })
            {
                p.facts.add_reference_enumeration_gap(
                    site,
                    ResolutionGapKind::CompilationImportsUnenumerated,
                );
            }
        }
    }
    p.finish_imports();
    p.facts
}

fn merged_intervals(mut intervals: Vec<(usize, usize)>) -> Vec<(usize, usize)> {
    intervals.sort_unstable();
    let mut merged: Vec<(usize, usize)> = Vec::new();
    for (start, end) in intervals {
        if let Some(last) = merged.last_mut()
            && start <= last.1
        {
            last.1 = last.1.max(end);
        } else {
            merged.push((start, end));
        }
    }
    merged
}

fn span_is_contained(intervals: &[(usize, usize)], start: usize, end: usize) -> bool {
    let index = intervals.partition_point(|&(_, interval_end)| interval_end <= start);
    intervals
        .get(index)
        .is_some_and(|&(interval_start, interval_end)| {
            interval_start <= start && end <= interval_end
        })
}

impl Producer<'_, '_> {
    fn is_excluded(&self, node: Node<'_>) -> bool {
        span_is_contained(&self.excluded, node.start_byte(), node.end_byte())
    }

    /// A MISSING or zero-width identifier has no spelling and so no name.
    fn name(&mut self, node: Node<'_>) -> Option<ResolutionNameId> {
        let spelling = names::spelling(node, self.source);
        self.facts.intern_name(&mut self.names, &spelling)
    }
    fn site(
        &mut self,
        node: Node<'_>,
        scope: ResolutionScopeId,
        kind: ResolutionSiteKind,
    ) -> ResolutionSiteId {
        assert!(
            !self.is_excluded(node),
            "native sites never originate in a disabled branch"
        );
        let id = self
            .facts
            .add_site(scope, kind, node.start_byte(), node.end_byte());
        self.bridges
            .occurrences
            .push(self.collector.intern_node(node));
        id
    }
    fn package(
        &mut self,
        scope: ResolutionScopeId,
        declaration: Option<ResolutionSiteId>,
        site: ResolutionSiteId,
        path: Vec<ResolutionNameId>,
    ) {
        self.facts.packages.push(ResolutionPackageFact {
            root_scope: scope,
            declaration,
            placement_gap_site: site,
        });
        for (ordinal, &name) in path.iter().enumerate() {
            self.facts
                .package_segments
                .push(ResolutionPackageSegmentFact {
                    root_scope: scope,
                    ordinal: dense_ordinal(ordinal, "namespace segment"),
                    name,
                });
        }
        self.namespace_paths.insert(scope, path);
    }
    fn declare(
        &mut self,
        node: Node<'_>,
        name: Node<'_>,
        ctx: Context,
        site_kind: ResolutionSiteKind,
        namespace: ResolutionNamespace,
        kind: ResolutionBinderKind,
    ) -> ResolutionSiteId {
        let scope = ctx.scope;
        let site = self.site(name, scope, site_kind);
        let spelling = if site_kind == ResolutionSiteKind::TypeDeclaration
            && node.kind() != "type_parameter"
        {
            names::declaration_spelling(node, name, self.source)
        } else {
            crate::syntax::csharp_lookup_identifier(csharp_identifier_text(name, self.source))
        };
        let Some(name_id) = self.facts.intern_name(&mut self.names, &spelling) else {
            self.facts.add_gap(site, ResolutionGapKind::MalformedSyntax);
            return site;
        };
        self.facts.identifiers.push(PositionedIdentifierFact {
            site,
            name: name_id,
            role: ResolutionIdentifierRole::Declaration,
            namespace,
            qualifier: None,
        });
        let mut binder = ResolutionBinderFact::scope_wide(site, kind, *self.facts.scope(scope));
        // ECMA-334 7.7 / 13.6.2: a local cannot be used before its declarator.
        if matches!(
            kind,
            ResolutionBinderKind::Local | ResolutionBinderKind::Pattern
        ) {
            binder.hoisting = HoistingClass::SourceOrder;
            binder.activation_start = name.end_byte();
            // ECMA-334 13.9.5: an iteration variable's scope is the
            // embedded statement, excluding its collection expression.
            let mut ancestor = Some(node);
            while let Some(current) = ancestor {
                if current.kind() == "foreach_statement" {
                    if let Some(body) = current.child_by_field_name("body") {
                        binder.activation_start = body.start_byte();
                    }
                    break;
                }
                if matches!(
                    current.kind(),
                    "block" | "lambda_expression" | "local_function_statement"
                ) {
                    break;
                }
                ancestor = current.parent();
            }
        }
        if matches!(
            kind,
            ResolutionBinderKind::Local | ResolutionBinderKind::Pattern
        ) {
            // ECMA-334 13.8.3: switch statements share one declaration space,
            // but variables introduced by a case label/guard end at its section.
            // Statement locals retain SourceOrder through the switch block.
            let mut current = node;
            while let Some(parent) = current.parent() {
                if current.kind().ends_with("statement")
                    || matches!(
                        current.kind(),
                        "block"
                            | "switch_body"
                            | "switch_expression_arm"
                            | "lambda_expression"
                            | "anonymous_method_expression"
                    )
                {
                    break;
                }
                if parent.kind() == "switch_section" {
                    binder.hoisting = HoistingClass::DeclaredHead;
                    binder.activation_start = name.end_byte();
                    binder.activation_end = parent.end_byte();
                    break;
                }
                current = parent;
            }
        }
        self.facts.binders.push(binder);
        // ECMA-334 8.2, 15.5, 15.6 and 15.7: declared types belong to
        // the declaration, independently of initializer/call inference.
        let type_node = if node.kind() == "variable_declarator" {
            node.parent()
                .and_then(|parent| parent.child_by_field_name("type"))
        } else {
            node.child_by_field_name("type")
                .or_else(|| node.child_by_field_name("returns"))
        };
        let role = match kind {
            ResolutionBinderKind::Parameter => Some(DeclarationTypeRole::Parameter),
            ResolutionBinderKind::Field | ResolutionBinderKind::Local => {
                Some(DeclarationTypeRole::Value)
            }
            _ => None,
        };
        if let (Some(type_node), Some(role)) = (type_node, role)
            && type_node.kind() != "implicit_type"
            && !self.is_excluded(type_node)
        {
            let slot = self.declared_type(type_node, ctx);
            self.attach_declared_type(site, slot, type_node, role);
        }
        if (site_kind == ResolutionSiteKind::TypeDeclaration && node.kind() != "type_parameter")
            || site_kind == ResolutionSiteKind::ConstructorDeclaration
            || (site_kind == ResolutionSiteKind::CallableDeclaration
                && node.kind() != "local_function_statement")
            || kind == ResolutionBinderKind::Field
        {
            let modifier_owner = if node.kind() == "variable_declarator" {
                node.parent()
                    .and_then(|parent| parent.parent())
                    .expect("field declaration owner")
            } else {
                node
            };
            let default = if site_kind == ResolutionSiteKind::TypeDeclaration
                && matches!(
                    self.facts.scope(scope).kind,
                    ResolutionScopeKind::CompilationUnit | ResolutionScopeKind::Package
                ) {
                DeclaredVisibility::Internal
            } else if node.kind() == "enum_member_declaration" {
                DeclaredVisibility::Public
            } else {
                crate::syntax::csharp_default_member_visibility(
                    modifier_owner,
                    &ParentIndex::unindexed(),
                )
            };
            let modifier_count = ["public", "private", "protected", "internal"]
                .into_iter()
                .filter(|modifier| csharp_has_modifier(self.source, modifier_owner, modifier))
                .count();
            let visibility = if csharp_has_modifier(self.source, modifier_owner, "file") {
                DeclaredVisibility::Unknown
            } else if modifier_count == 2
                && csharp_has_modifier(self.source, modifier_owner, "protected")
                && csharp_has_modifier(self.source, modifier_owner, "internal")
            {
                DeclaredVisibility::ProtectedInternal
            } else if modifier_count == 2
                && csharp_has_modifier(self.source, modifier_owner, "private")
                && csharp_has_modifier(self.source, modifier_owner, "protected")
            {
                DeclaredVisibility::PrivateProtected
            } else if modifier_count > 1 {
                DeclaredVisibility::Unknown
            } else {
                crate::declarations::csharp_declared_visibility(
                    modifier_owner,
                    self.source,
                    default,
                )
            };
            self.facts
                .visibility_eligibilities
                .push(ResolutionVisibilityEligibilityFact { declaration: site });
            self.facts
                .declaration_visibilities
                .push(ResolutionDeclarationVisibilityFact {
                    declaration: site,
                    visibility,
                });
            if visibility != DeclaredVisibility::Public {
                self.facts
                    .add_gap(site, ResolutionGapKind::UnsupportedVisibility);
            }
        }
        let declaration = self.collector.declare_node(node, Some(name));
        use brokk_bifrost_core::analyzer::model::DeclarationKind;
        let lexical_kind = match kind {
            ResolutionBinderKind::Parameter => Some(DeclarationKind::Parameter),
            ResolutionBinderKind::Type if node.kind() == "type_parameter" => {
                Some(DeclarationKind::Parameter)
            }
            ResolutionBinderKind::Pattern => Some(DeclarationKind::PatternVariable),
            ResolutionBinderKind::Local => Some(DeclarationKind::LocalVariable),
            ResolutionBinderKind::Callable if node.kind() == "local_function_statement" => {
                Some(DeclarationKind::BlockLocalItem)
            }
            _ => None,
        };
        if let Some(kind) = lexical_kind {
            self.collector.mark_lexical(declaration, kind);
        }
        self.bridges.declarations.push((site, declaration));
        self.claim_tree(name);
        site
    }
    fn member(
        &mut self,
        member: ResolutionSiteId,
        owner: ResolutionSiteId,
        kind: ResolutionMemberKind,
        is_static: bool,
    ) {
        let type_access = is_static || kind == ResolutionMemberKind::NestedType;
        self.facts.member_owners.push(ResolutionMemberOwnerFact {
            member,
            owner,
            kind,
            access: if type_access {
                ResolutionMemberAccess::Type
            } else {
                ResolutionMemberAccess::Instance
            },
            qualifier_compatibility: if type_access {
                ResolutionMemberQualifierCompatibility::TypeOnly
            } else {
                ResolutionMemberQualifierCompatibility::RuntimeOnly
            },
        });
    }
    fn collect_friend_attribute(
        &mut self,
        node: Node<'_>,
        scope: ResolutionScopeId,
        site: ResolutionSiteId,
    ) {
        let Some(parent) = node
            .parent()
            .filter(|parent| parent.kind() == "global_attribute")
        else {
            return;
        };
        let mut cursor = parent.walk();
        if !parent
            .children(&mut cursor)
            .any(|child| child.kind() == "assembly")
        {
            return;
        }
        let name_segments = node
            .child_by_field_name("name")
            .map(|name| crate::syntax::csharp_type_node_segments(name, self.source))
            .unwrap_or_default();
        let argument = first_named_child_of_kind(node, "attribute_argument_list")
            .and_then(|list| single_named_child_matching(list, |child| !child.is_extra()))
            .filter(|argument| {
                argument.kind() == "attribute_argument"
                    && argument.child_by_field_name("name").is_none()
            })
            .and_then(|argument| single_named_child_matching(argument, |child| !child.is_extra()))
            .and_then(|value| match value.kind() {
                "string_literal" | "verbatim_string_literal" => {
                    crate::structural::csharp_string_literal_value(value, self.source)
                }
                _ => None,
            });
        let mut parse_state = CSharpFriendArgumentState::NonConstant;
        let mut friend_name = None;
        let mut has_public_key = false;
        if let Some(argument) = &argument {
            (friend_name, has_public_key) = friend_display_name(argument.trim());
            parse_state = if friend_name.is_some() {
                CSharpFriendArgumentState::Complete
            } else {
                CSharpFriendArgumentState::InvalidDisplayName
            };
        }

        self.facts
            .csharp_friend_attributes
            .push(ResolutionCSharpFriendAttributeFact {
                site,
                scope,
                name_segments,
                argument,
                parse_state,
                friend_name,
                has_public_key,
            });
    }

    fn claim_tree(&mut self, node: Node<'_>) {
        let mut stack = vec![node];
        while let Some(n) = stack.pop() {
            self.claimed.insert(n.id());
            stack.extend(named_children(n));
        }
    }
    fn compilation_omission(&mut self, node: Node<'_>, site: ResolutionSiteId) {
        if node
            .parent()
            .is_some_and(|parent| parent.kind() == "compilation_unit")
            && !(node.kind() == "using_directive"
                && !crate::syntax::csharp_using_directive_is_global(node))
        {
            self.facts.add_reference_enumeration_gap(
                site,
                ResolutionGapKind::CompilationImportsUnenumerated,
            );
        }
    }
    fn omit(
        &mut self,
        node: Node<'_>,
        scope: ResolutionScopeId,
        kind: ResolutionGapKind,
    ) -> ResolutionSiteId {
        let site = self.site(node, scope, ResolutionSiteKind::UnsupportedRoute);
        self.omit_site(node, scope, kind, site);
        site
    }
    fn omit_site(
        &mut self,
        node: Node<'_>,
        scope: ResolutionScopeId,
        kind: ResolutionGapKind,
        site: ResolutionSiteId,
    ) {
        if kind == ResolutionGapKind::UnsupportedRoute {
            self.facts.add_route_gap(
                site,
                ResolutionRouteGap::UnknownBinder {
                    scope,
                    name: None,
                    namespace: None,
                    may_publish: false,
                },
            );
        } else {
            self.facts.add_gap(site, kind);
        }
        self.facts.add_reference_enumeration_gap(site, kind);
        if node.kind() == "global_statement"
            && node
                .parent()
                .is_some_and(|p| p.kind() == "compilation_unit")
        {
            self.facts
                .add_reference_enumeration_gap(site, ResolutionGapKind::FileProgramEvidence);
        }
        self.claim_tree(node);
    }
}

// Parse the already-decoded assembly display-name value, not C# source.
// Token quoting and escaping follow AssemblyIdentity.DisplayName.cs in Roslyn.
fn friend_display_name(value: &str) -> (Option<String>, bool) {
    fn token(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) -> Option<String> {
        while chars
            .peek()
            .is_some_and(|ch| matches!(ch, ' ' | '\t' | '\r' | '\n'))
        {
            chars.next();
        }
        let quote = chars.peek().copied().filter(|ch| matches!(ch, '\'' | '"'));
        if quote.is_some() {
            chars.next();
        }
        let mut result = String::new();
        let mut closed = quote.is_none();
        while let Some(ch) = chars.peek().copied() {
            if quote == Some(ch) {
                chars.next();
                closed = true;
                while chars
                    .peek()
                    .is_some_and(|ch| matches!(ch, ' ' | '\t' | '\r' | '\n'))
                {
                    chars.next();
                }
                if chars.peek().is_some_and(|ch| !matches!(ch, ',' | '=')) {
                    return None;
                }
                break;
            }
            if quote.is_none() && matches!(ch, ',' | '=') {
                break;
            }
            chars.next();
            if ch == '\0' || (quote.is_none() && matches!(ch, '\'' | '"')) {
                return None;
            }
            if ch != '\\' {
                result.push(ch);
                continue;
            }
            let escaped = match chars.next()? {
                ch @ (',' | '=' | '\\' | '/' | '\'' | '"') => ch,
                't' => '\t',
                'r' => '\r',
                'n' => '\n',
                'u' => {
                    let mut hex = String::new();
                    loop {
                        let ch = chars.next()?;
                        if ch == ';' {
                            break;
                        }
                        if !ch.is_ascii_hexdigit() {
                            return None;
                        }
                        hex.push(ch);
                    }
                    let ch = char::from_u32(u32::from_str_radix(&hex, 16).ok()?)?;
                    if ch == '\0' {
                        return None;
                    }
                    ch
                }
                _ => return None,
            };
            result.push(escaped);
        }
        if quote.is_none() {
            result.truncate(result.trim_end_matches([' ', '\t', '\r', '\n']).len());
        }
        (closed && !result.is_empty()).then_some(result)
    }
    let mut chars = value.chars().peekable();
    let Some(name) = token(&mut chars) else {
        return (None, false);
    };
    let mut valid = true;
    let mut has_public_key = false;
    while let Some(separator) = chars.next() {
        if separator != ',' {
            return (None, has_public_key);
        }
        let Some(property) = token(&mut chars) else {
            return (None, has_public_key);
        };
        let is_public_key = property.eq_ignore_ascii_case("PublicKey");
        let duplicate_key = is_public_key && has_public_key;
        has_public_key |= is_public_key;
        if chars.next() != Some('=') {
            return (None, has_public_key);
        }
        let Some(value) = token(&mut chars) else {
            return (None, has_public_key);
        };
        // Version, Culture, PublicKeyToken and ProcessorArchitecture cannot
        // occur in a friend grant. Unknown properties also remain open.
        valid &= is_public_key && !duplicate_key && friend_public_key_is_valid(&value);
    }
    (valid.then_some(name), has_public_key)
}

// Roslyn's AssemblyIdentity.TryParsePublicKey validates this strong-name
// envelope, including the ECMA neutral key; it does not prove caller identity.
// https://github.com/dotnet/roslyn/blob/main/src/Compilers/Core/Portable/StrongName/CryptoBlobParser.cs
fn friend_public_key_is_valid(value: &str) -> bool {
    const ECMA_KEY: &str = "00000000000000000400000000000000";
    if value.len() < 26
        || !value.len().is_multiple_of(2)
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return false;
    }
    let mut header = [0_u8; 13];
    for (byte, pair) in header.iter_mut().zip(value.as_bytes().as_chunks::<2>().0) {
        let high = char::from(pair[0])
            .to_digit(16)
            .expect("validated hex digit");
        let low = char::from(pair[1])
            .to_digit(16)
            .expect("validated hex digit");
        *byte = ((high << 4) | low) as u8;
    }
    let signature = u32::from_le_bytes(header[0..4].try_into().expect("fixed header range"));
    let hash = u32::from_le_bytes(header[4..8].try_into().expect("fixed header range"));
    let data_size = u32::from_le_bytes(header[8..12].try_into().expect("fixed header range"));
    if data_size as usize != value.len() / 2 - 12 {
        return false;
    }
    value.eq_ignore_ascii_case(ECMA_KEY)
        || (header[12] == 0x06
            && (signature == 0 || (signature >> 13) & 7 == 1)
            && (hash == 0 || ((hash >> 13) & 7 == 4 && hash & 0x1ff >= 4)))
}

#[cfg(test)]
mod grammar_boundary {
    use super::*;

    #[test]
    fn contextual_identifier_grammar_boundary() {
        let source = "class C { int F(int from) { int var = from; return var; } }";
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_c_sharp::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        assert!(
            !tree.root_node().has_error(),
            "{}",
            tree.root_node().to_sexp()
        );
        let mut parameters = Vec::new();
        let mut variables = Vec::new();
        let mut references = Vec::new();
        let mut pending = vec![tree.root_node()];
        while let Some(node) = pending.pop() {
            if matches!(node.kind(), "parameter" | "variable_declarator") {
                let name = node
                    .child_by_field_name("name")
                    .expect("grammar declaration has its name field");
                let item = (name.kind(), csharp_identifier_text(name, source));
                if node.kind() == "parameter" {
                    parameters.push(item);
                } else {
                    variables.push(item);
                }
            } else if node.kind() == "identifier"
                && node
                    .parent()
                    .is_none_or(|parent| parent.child_by_field_name("name") != Some(node))
            {
                references.push((node.kind(), csharp_identifier_text(node, source)));
            }
            pending.extend(named_children(node).into_iter().rev());
        }
        assert_eq!(parameters, [("identifier", "from")]);
        assert_eq!(variables, [("identifier", "var")]);
        assert_eq!(references, [("identifier", "from"), ("identifier", "var")]);
    }
}

#[cfg(test)]
mod missing_names {
    use super::*;
    use brokk_bifrost_core::analyzer::ProjectFile;

    /// A MISSING or zero-width identifier leaves a gap and no empty spelling
    /// (C# counterpart of Rust's `missing_names_leave_gaps_not_empty_spellings`,
    /// #4286). A malformed type path projects no type at all: its last named
    /// part is a prefix, not the declared type.
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#13682: a MISSING type-path part made `A.<int> f` project f's type as A"
    )]
    fn missing_names_leave_gaps_not_empty_spellings() {
        let mut saw_missing = false;
        for source in [
            "namespace { class C {} }\n",
            "namespace A. { class C {} }\n",
            "extern alias ;\n",
            "class C { A. f; }\n",
            "class C { A.<int> f; }\n",
        ] {
            let (tree, scan) = crate::preprocessor::parse_csharp_scanned(source).expect("C# tree");
            saw_missing |= tree.root_node().to_sexp().contains("MISSING");
            let file = ProjectFile::new(std::env::temp_dir(), "Fixture.cs");
            let parsed = crate::declarations::parse_csharp_file_with_native_facts(
                &file, source, &tree, &scan,
            );
            let facts = &parsed.resolution_facts;
            assert!(
                facts.names.iter().all(|name| !name.spelling.is_empty()),
                "no empty spelling is interned for {source:?}"
            );
            assert!(
                facts
                    .gaps
                    .iter()
                    .any(|gap| gap.kind == ResolutionGapKind::MalformedSyntax),
                "the recovered tree keeps malformed-syntax evidence for {source:?}"
            );
            let prefix_sites = facts
                .identifiers
                .iter()
                .filter(|identifier| {
                    facts
                        .names
                        .iter()
                        .any(|name| name.id == identifier.name && name.spelling == "A")
                })
                .map(|identifier| identifier.site)
                .collect::<Vec<_>>();
            assert!(
                facts.binding_projections.iter().all(|projection| {
                    projection.kind != BindingProjectionKind::TargetTypeIdentity
                        || !prefix_sites.contains(&projection.reference)
                }),
                "no path prefix becomes the declared type for {source:?}: {:?}",
                facts.binding_projections
            );
        }
        assert!(saw_missing, "recovery inserts a MISSING node in this table");
    }
}
