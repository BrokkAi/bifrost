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
    children_by_field_name, first_named_child_of_kind, named_children,
};
use brokk_bifrost_core::hash::{HashMap, HashSet};
use tree_sitter::{Node, Tree};

mod imports;
mod names;

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
}

struct Producer<'a, 's> {
    source: &'s str,
    collector: &'a mut PrimarySourceFactCollector<'s>,
    bridges: &'a mut SourceBridges,
    facts: FileResolutionFacts,
    names: HashMap<String, ResolutionNameId>,
    claimed: HashSet<usize>,
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
    // Static usings can publish types, values and callables in other files.
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
                may_publish: true,
            },
        );
    }
    let context = Context {
        scope: root,
        package: root,
        owner: None,
        type_parameters: None,
    };
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
            p.omit(node, ctx.scope, ResolutionGapKind::UnsupportedTypeSyntax);
            continue;
        }
        if node
            .child_by_field_name("name")
            .is_some_and(|name| p.is_excluded(name))
        {
            p.omit(node, ctx.scope, ResolutionGapKind::UnsupportedScopeOrBinder);
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
            p.omit(node, ctx.scope, ResolutionGapKind::MalformedSyntax);
            continue;
        }
        if first_named_child_of_kind(node, "explicit_interface_specifier").is_some() {
            p.omit(node, ctx.scope, ResolutionGapKind::UnsupportedMemberScope);
            continue;
        }
        let mut skip = false;
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
                    path.push(p.name(part));
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
            | "enum_declaration"
            | "delegate_declaration" => {
                if let Some(name) = node.child_by_field_name("name") {
                    let site = p.declare(
                        node,
                        name,
                        ctx.scope,
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
                    ctx.scope = p.facts.allocate_lexical_scope(
                        ctx.scope,
                        Some(site),
                        ResolutionScopeKind::TypeBody,
                        node.start_byte(),
                        node.end_byte(),
                    );
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
                        ctx.scope,
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
                    let name = p.facts.intern_name(&mut p.names, "value");
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
                        ctx.scope,
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
            "parameter"
            | "implicit_parameter"
            | "type_parameter"
            | "variable_declarator"
            | "declaration_expression"
            | "declaration_pattern"
            | "var_pattern"
            | "recursive_pattern"
            | "list_pattern"
            | "catch_declaration" => {
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
                        binding_scope,
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
                        ctx.scope,
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
                        ctx.scope,
                        ResolutionSiteKind::ValueDeclaration,
                        ResolutionNamespace::Value,
                        ResolutionBinderKind::Local,
                    );
                }
            }
            "extern_alias_directive"
            | "attribute"
            | "indexer_declaration"
            | "operator_declaration"
            | "conversion_operator_declaration"
            | "explicit_interface_specifier"
            | "query_expression"
            | "global_statement" => {
                let kind = match node.kind() {
                    "extern_alias_directive" => ResolutionGapKind::UnsupportedRoute,
                    "attribute" => ResolutionGapKind::UnsupportedTypeSyntax,
                    "query_expression" | "global_statement" => {
                        ResolutionGapKind::UnsupportedScopeOrBinder
                    }
                    _ => ResolutionGapKind::UnsupportedMemberScope,
                };
                p.omit(node, ctx.scope, kind);
                skip = true;
            }
            "alias_qualified_name"
                if node.child_by_field_name("alias").is_some_and(|n| {
                    crate::syntax::csharp_lookup_identifier(csharp_identifier_text(n, source))
                        != "global"
                }) =>
            {
                p.omit(node, ctx.scope, ResolutionGapKind::UnsupportedRoute);
                skip = true;
            }
            "qualified_name" | "alias_qualified_name" | "member_access_expression"
                if !p.claimed.contains(&node.id()) =>
            {
                if p.path(node).is_some() {
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
            "ERROR" => {
                p.omit(node, ctx.scope, ResolutionGapKind::MalformedSyntax);
                skip = true;
            }
            _ => {}
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

    fn name(&mut self, node: Node<'_>) -> ResolutionNameId {
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
        scope: ResolutionScopeId,
        site_kind: ResolutionSiteKind,
        namespace: ResolutionNamespace,
        kind: ResolutionBinderKind,
    ) -> ResolutionSiteId {
        let site = self.site(name, scope, site_kind);
        let spelling = if site_kind == ResolutionSiteKind::TypeDeclaration
            && node.kind() != "type_parameter"
        {
            names::declaration_spelling(node, name, self.source)
        } else {
            crate::syntax::csharp_lookup_identifier(csharp_identifier_text(name, self.source))
        };
        let name_id = self.facts.intern_name(&mut self.names, &spelling);
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
            // The vocabulary has no protected-internal/private-protected union
            // or intersection, nor file access. Preserve these as Unknown.
            let visibility =
                if modifier_count > 1 || csharp_has_modifier(self.source, modifier_owner, "file") {
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
    fn claim_tree(&mut self, node: Node<'_>) {
        let mut stack = vec![node];
        while let Some(n) = stack.pop() {
            self.claimed.insert(n.id());
            stack.extend(named_children(n));
        }
    }
    fn omit(&mut self, node: Node<'_>, scope: ResolutionScopeId, kind: ResolutionGapKind) {
        let site = self.site(node, scope, ResolutionSiteKind::UnsupportedRoute);
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
        self.claim_tree(node);
    }
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
