//! Query-scoped Python unsafe-import-cycle checks over persisted file edges.

use super::python_import_cycles::{
    PythonImportCycleCache, PythonImportCycleContext, PythonReverseImportReachability,
};
use super::python_imports::PythonImportSiteCache;
use super::python_rule_facts::{PythonRuleFactValue, make_row, row_range};
use super::results::{CodeQueryPythonImportLeaf, CodeQueryPythonImportSite, CodeQueryRange};
use super::*;
use brokk_bifrost_analysis::analyzer::structural::lexical_environment::BindingRow;
use brokk_bifrost_core::analyzer::structural::kinds::{NormalizedKind, Role};
use brokk_bifrost_core::analyzer::structural::resolution::EnvironmentAxis;

const RELATION: &str = "unsafe_cyclic_import";
const INCOMPLETE_REASON: &str = "python_unsafe_cyclic_import_incomplete";
type PythonImportSites = Vec<(usize, CodeQueryPythonImportSite)>;

#[derive(Clone, Copy, PartialEq, Eq)]
enum ModuleExecution {
    Module,
    Guarded,
    Deferred,
    ClassBody,
}

struct UseCandidate {
    target: Option<ProjectFile>,
    member: String,
    anchor: std::ops::Range<usize>,
    execution: ModuleExecution,
}

#[derive(Clone, Copy)]
enum DefinitionState {
    Static,
    Unknown,
}

struct ModuleDefinition {
    order: usize,
    state: DefinitionState,
    source_order: u32,
}

#[derive(Default)]
struct RouteEdges {
    direct: HashMap<ProjectFile, Vec<(ProjectFile, usize)>>,
    complete: bool,
}

pub(super) fn unsafe_cyclic_import_expansions(
    cycle_context: &mut PythonImportCycleContext<'_>,
    token: QueryToken<'_>,
    environment_cache: &mut EnvironmentTraversalCache,
    import_site_cache: &mut PythonImportSiteCache,
    cycle_cache: &mut PythonImportCycleCache,
    seed: &SeedMatch,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> Vec<PythonRuleFactValue> {
    if seed.language != Language::Python {
        return Vec::new();
    }

    let candidates = match seed.facts.node(seed.fact_match.node).kind {
        NormalizedKind::FieldAccess => member_use_candidates(
            cycle_context.analyzer,
            environment_cache,
            import_site_cache,
            token,
            seed,
            cycle_context.cancellation,
            diagnostics,
        ),
        NormalizedKind::Import => from_import_candidates(
            cycle_context.analyzer,
            environment_cache,
            import_site_cache,
            token,
            seed,
            cycle_context.cancellation,
            diagnostics,
        ),
        _ => return Vec::new(),
    };

    let mut results = Vec::new();
    for candidate in candidates {
        if candidate.execution == ModuleExecution::Deferred {
            continue;
        }
        let Some(target) = candidate.target.as_ref() else {
            results.push(rule_fact(
                seed,
                candidate.anchor,
                "open",
                "none",
                false,
                Some("candidate module import target is unresolved"),
            ));
            continue;
        };
        if candidate.execution != ModuleExecution::Module {
            results.push(rule_fact(
                seed,
                candidate.anchor,
                "open",
                "none",
                false,
                Some("the candidate use is conditional or outside module scope"),
            ));
            continue;
        }
        if python_import_cycles::module_identity_is_limited(target.rel_path()) {
            python_import_cycles::report_incomplete(
                diagnostics,
                "Python package module identity is path-derived and remains incomplete until #3673 supplies snapshot-consistent source roots.",
            );
            results.push(rule_fact(
                seed,
                candidate.anchor,
                "open",
                "none",
                false,
                Some("path-derived Python module identity is limited by #3673"),
            ));
            continue;
        }
        let reachability = python_import_cycles::reverse_import_reachability(
            cycle_context,
            &seed.file,
            cycle_cache,
            diagnostics,
        );
        if !reachability.files.contains(target) {
            results.push(rule_fact(
                seed,
                candidate.anchor,
                "open",
                "none",
                false,
                Some("no complete persisted path closes the candidate import cycle"),
            ));
            continue;
        }
        let route_edges = collect_route_edges(
            cycle_context.analyzer,
            environment_cache,
            token,
            cycle_context.cancellation,
            import_site_cache,
            &reachability,
        );
        let (target_facts, target_sites) = match module_facts_and_imports(
            cycle_context.analyzer,
            environment_cache,
            token,
            cycle_context.cancellation,
            import_site_cache,
            target,
        ) {
            Some(value) => value,
            None => {
                results.push(rule_fact(
                    seed,
                    candidate.anchor,
                    "open",
                    "none",
                    false,
                    Some("target module binding or import facts are unavailable"),
                ));
                continue;
            }
        };
        let target_environment = environment_cache.environment_for(cycle_context.analyzer, target);
        if !target_environment
            .completeness
            .covers(EnvironmentAxis::Scopes)
            || !target_environment
                .completeness
                .covers(EnvironmentAxis::BindingIntervals)
            || !target_environment
                .completeness
                .covers(EnvironmentAxis::ImportBinders)
        {
            results.push(rule_fact(
                seed,
                candidate.anchor,
                "open",
                "none",
                false,
                Some("target module binding environment is incomplete"),
            ));
            continue;
        }
        if module_has_dynamic_attributes(&target_facts, &target_environment, &target_sites) {
            results.push(rule_fact(
                seed,
                candidate.anchor,
                "open",
                "none",
                false,
                Some("target module has a dynamic attribute source"),
            ));
            continue;
        }

        let direct_reaches_a = reverse_route_reachable(&route_edges.direct, &seed.file);
        let candidate_first_edges = route_edges
            .direct
            .get(target)
            .into_iter()
            .flatten()
            .filter(|(target, _)| direct_reaches_a.contains(target))
            .map(|(_, order)| *order)
            .collect::<Vec<_>>();
        if candidate_first_edges.is_empty() {
            results.push(rule_fact(
                seed,
                candidate.anchor,
                "open",
                "none",
                false,
                Some("persisted cycle route contains guarded or unsupported import sites"),
            ));
            continue;
        }

        let mut saw_unsafe_path = false;
        let mut order_open = false;
        for import_order in candidate_first_edges {
            match definition_timing(
                &candidate.member,
                import_order,
                &target_environment,
                &target_facts,
                &target_sites,
            ) {
                DefinitionTiming::DefinedBefore | DefinitionTiming::NoDefinition => {}
                DefinitionTiming::DefinedAfter => saw_unsafe_path = true,
                DefinitionTiming::Unknown => order_open = true,
            }
        }
        if saw_unsafe_path {
            results.push(rule_fact(
                seed,
                candidate.anchor,
                "issue",
                "proven",
                true,
                None,
            ));
        } else if order_open || !route_edges.complete || !reachability.complete {
            results.push(rule_fact(
                seed,
                candidate.anchor,
                "open",
                "none",
                false,
                Some("cycle route or module definition order is only partially known"),
            ));
        } else {
            results.push(rule_fact(
                seed,
                candidate.anchor,
                "no_issue",
                "proven",
                true,
                None,
            ));
        }
    }
    results
}

enum DefinitionTiming {
    DefinedBefore,
    DefinedAfter,
    NoDefinition,
    Unknown,
}

fn member_use_candidates(
    analyzer: &dyn IAnalyzer,
    environment_cache: &mut EnvironmentTraversalCache,
    import_site_cache: &mut PythonImportSiteCache,
    token: QueryToken<'_>,
    seed: &SeedMatch,
    cancellation: Option<&CancellationToken>,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> Vec<UseCandidate> {
    let facts = &seed.facts;
    let access_id = seed.fact_match.node;
    let (Some(receiver_id), Some(member_id)) = (
        exactly_one_role_node(facts, access_id, Role::Object),
        exactly_one_role_node(facts, access_id, Role::Field),
    ) else {
        return vec![unknown_member_candidate(seed)];
    };
    if facts.node(receiver_id).kind != NormalizedKind::Identifier
        || facts.node(member_id).kind != NormalizedKind::Identifier
    {
        return vec![unknown_member_candidate(seed)];
    }
    let receiver_range = facts.node(receiver_id).range;
    let member_range = facts.node(member_id).range;
    let Some(receiver_name) = facts
        .source()
        .get(receiver_range.start_byte..receiver_range.end_byte)
    else {
        return vec![unknown_member_candidate(seed)];
    };
    let Some(member_name) = facts
        .source()
        .get(member_range.start_byte..member_range.end_byte)
    else {
        return vec![unknown_member_candidate(seed)];
    };
    let execution = module_execution(facts, access_id);
    if execution == ModuleExecution::Deferred {
        return Vec::new();
    }
    let environment = environment_cache.environment_for(analyzer, &seed.file);
    if !environment.completeness.covers(EnvironmentAxis::Scopes)
        || !environment
            .completeness
            .covers(EnvironmentAxis::BindingIntervals)
        || !environment
            .completeness
            .covers(EnvironmentAxis::ImportBinders)
    {
        diagnostics.push(python_rule_incomplete_diagnostic(
            "Python module receiver binding rows are incomplete.",
        ));
        return vec![UseCandidate {
            target: None,
            member: member_name.to_owned(),
            anchor: facts.node(access_id).range.start_byte..facts.node(access_id).range.end_byte,
            execution,
        }];
    }
    let binding = environment
        .bindings_named(receiver_name)
        .iter()
        .map(|&index| &environment.bindings[index])
        .filter(|binding| {
            binding.declaring_scope == 0
                && binding.range.start_byte <= facts.node(access_id).range.start_byte
        })
        .max_by_key(|binding| (binding.range.start_byte, binding.source_order));
    let Some(binding) = binding.filter(|binding| binding.import.is_some()) else {
        return Vec::new();
    };
    let Some((site, leaf)) = leaf_for_binding(
        import_site_cache,
        analyzer,
        environment_cache,
        token,
        seed,
        cancellation,
        binding,
    ) else {
        return vec![unknown_member_candidate(seed)];
    };
    if !site.complete || leaf.module_scope != Some(true) {
        return vec![UseCandidate {
            target: None,
            member: member_name.to_owned(),
            anchor: facts.node(access_id).range.start_byte..facts.node(access_id).range.end_byte,
            execution: ModuleExecution::Guarded,
        }];
    }
    let import_node = import_node_at(facts, leaf.source_order as usize);
    if import_node.is_none_or(|node| module_execution(facts, node) != ModuleExecution::Module) {
        return vec![UseCandidate {
            target: None,
            member: member_name.to_owned(),
            anchor: facts.node(access_id).range.start_byte..facts.node(access_id).range.end_byte,
            execution: ModuleExecution::Guarded,
        }];
    }
    let Some(target) = unique_target(&seed.file, &leaf) else {
        return vec![UseCandidate {
            target: None,
            member: member_name.to_owned(),
            anchor: facts.node(access_id).range.start_byte..facts.node(access_id).range.end_byte,
            execution,
        }];
    };
    if leaf.source_order >= facts.node(access_id).range.start_byte as u64 {
        return Vec::new();
    }
    vec![UseCandidate {
        target: Some(target),
        member: member_name.to_owned(),
        anchor: facts.node(access_id).range.start_byte..facts.node(access_id).range.end_byte,
        execution,
    }]
}

fn from_import_candidates(
    analyzer: &dyn IAnalyzer,
    environment_cache: &mut EnvironmentTraversalCache,
    import_site_cache: &mut PythonImportSiteCache,
    token: QueryToken<'_>,
    seed: &SeedMatch,
    cancellation: Option<&CancellationToken>,
    _diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> Vec<UseCandidate> {
    let Some(site) =
        import_site_cache.site_for_match(analyzer, environment_cache, token, seed, cancellation)
    else {
        return vec![UseCandidate {
            target: None,
            member: String::new(),
            anchor: seed.facts.node(seed.fact_match.node).range.start_byte
                ..seed.facts.node(seed.fact_match.node).range.end_byte,
            execution: ModuleExecution::Guarded,
        }];
    };
    let execution = module_execution(&seed.facts, seed.fact_match.node);
    if execution == ModuleExecution::Deferred {
        return Vec::new();
    }
    let environment = environment_cache.environment_for(analyzer, &seed.file);
    let binding_environment_complete = environment.completeness.covers(EnvironmentAxis::Scopes)
        && environment
            .completeness
            .covers(EnvironmentAxis::BindingIntervals)
        && environment
            .completeness
            .covers(EnvironmentAxis::ImportBinders);
    site.sites
        .iter()
        .filter(|leaf| leaf.form == "from" && !leaf.wildcard)
        .map(|leaf| {
            let local_name = leaf
                .alias
                .as_deref()
                .or(leaf.name.as_deref())
                .unwrap_or_default();
            let binder = binding_environment_complete
                .then(|| {
                    environment
                        .bindings_named(local_name)
                        .iter()
                        .map(|&index| &environment.bindings[index])
                        .find(|binding| {
                            binding.declaring_scope == 0
                                && binding.import.as_ref().is_some_and(|detail| {
                                    detail.imported_name.as_deref() == leaf.name.as_deref()
                                        && detail.alias.as_deref() == leaf.alias.as_deref()
                                })
                                && leaf.binder_range.as_ref().is_some_and(|range| {
                                    same_rendered_range(
                                        range,
                                        &row_range(
                                            seed.facts.source(),
                                            binding.range.start_byte..binding.range.end_byte,
                                        ),
                                    )
                                })
                        })
                })
                .flatten();
            let statement = seed.facts.node(seed.fact_match.node).range;
            let anchor = binder.map_or(statement.start_byte..statement.end_byte, |binding| {
                binding.range.start_byte..binding.range.end_byte
            });
            UseCandidate {
                target: unique_target(&seed.file, leaf),
                member: leaf.name.clone().unwrap_or_default(),
                anchor,
                execution: if !binding_environment_complete
                    || binder.is_none()
                    || !site.complete
                    || leaf.module_scope != Some(true)
                {
                    ModuleExecution::Guarded
                } else {
                    execution
                },
            }
        })
        .collect()
}

fn leaf_for_binding(
    cache: &mut PythonImportSiteCache,
    analyzer: &dyn IAnalyzer,
    environment_cache: &mut EnvironmentTraversalCache,
    token: QueryToken<'_>,
    seed: &SeedMatch,
    cancellation: Option<&CancellationToken>,
    binding: &BindingRow,
) -> Option<(CodeQueryPythonImportSite, CodeQueryPythonImportLeaf)> {
    let sites = cache.sites_for_file(
        analyzer,
        token,
        &seed.file,
        &seed.facts,
        environment_cache,
        cancellation,
    )?;
    sites.into_iter().find_map(|(_, site)| {
        site.sites
            .iter()
            .find(|leaf| {
                leaf.binder_range.as_ref().is_some_and(|range| {
                    same_rendered_range(
                        range,
                        &row_range(
                            seed.facts.source(),
                            binding.range.start_byte..binding.range.end_byte,
                        ),
                    )
                })
            })
            .cloned()
            .map(|leaf| (site, leaf))
    })
}

fn unknown_member_candidate(seed: &SeedMatch) -> UseCandidate {
    let node = seed.facts.node(seed.fact_match.node);
    UseCandidate {
        target: None,
        member: String::new(),
        anchor: node.range.start_byte..node.range.end_byte,
        execution: ModuleExecution::Guarded,
    }
}

fn unique_target(importer: &ProjectFile, leaf: &CodeQueryPythonImportLeaf) -> Option<ProjectFile> {
    if leaf.target_status != "resolved_local" || leaf.target_paths.len() != 1 {
        return None;
    }
    let target = importer.with_rel_path(leaf.target_paths[0].as_str());
    (target.language() == Language::Python).then_some(target)
}

fn same_rendered_range(left: &CodeQueryRange, right: &CodeQueryRange) -> bool {
    left.start_line == right.start_line
        && left.start_column == right.start_column
        && left.end_line == right.end_line
        && left.end_column == right.end_column
}

fn exactly_one_role_node(facts: &FileFacts, node: u32, role: Role) -> Option<u32> {
    let mut targets = facts.role_targets(node, role);
    let first = targets.next()?.node?;
    targets.next().is_none().then_some(first)
}

fn import_node_at(facts: &FileFacts, source_order: usize) -> Option<u32> {
    facts
        .nodes()
        .iter()
        .enumerate()
        .find(|(_, node)| {
            node.kind == NormalizedKind::Import && node.range.start_byte == source_order
        })
        .map(|(index, _)| u32::try_from(index).expect("normalized node ids fit in u32"))
}

fn module_execution(facts: &FileFacts, node: u32) -> ModuleExecution {
    let mut current = facts.node(node).parent;
    let mut guarded = false;
    let mut class_body = false;
    while let Some(parent) = current {
        match facts.node(parent).kind {
            NormalizedKind::Function
            | NormalizedKind::Method
            | NormalizedKind::Constructor
            | NormalizedKind::Lambda => return ModuleExecution::Deferred,
            NormalizedKind::Class => class_body = true,
            NormalizedKind::If
            | NormalizedKind::Loop
            | NormalizedKind::ForLoop
            | NormalizedKind::WhileLoop
            | NormalizedKind::Catch
            | NormalizedKind::ResourceRelease
            | NormalizedKind::Block => guarded = true,
            _ => {}
        }
        current = facts.node(parent).parent;
    }
    if class_body {
        ModuleExecution::ClassBody
    } else if guarded {
        ModuleExecution::Guarded
    } else {
        ModuleExecution::Module
    }
}

fn module_facts_and_imports(
    analyzer: &dyn IAnalyzer,
    environment_cache: &mut EnvironmentTraversalCache,
    token: QueryToken<'_>,
    cancellation: Option<&CancellationToken>,
    cache: &mut PythonImportSiteCache,
    file: &ProjectFile,
) -> Option<(Arc<FileFacts>, PythonImportSites)> {
    let facts = analyzer
        .structural_fact_providers()
        .into_iter()
        .find(|provider| provider.structural_language() == Language::Python)?
        .structural_facts(file)?;
    let sites = cache.sites_for_file(
        analyzer,
        token,
        file,
        &facts,
        environment_cache,
        cancellation,
    )?;
    Some((facts, sites))
}

fn collect_route_edges(
    analyzer: &dyn IAnalyzer,
    environment_cache: &mut EnvironmentTraversalCache,
    token: QueryToken<'_>,
    cancellation: Option<&CancellationToken>,
    import_site_cache: &mut PythonImportSiteCache,
    reachability: &PythonReverseImportReachability,
) -> RouteEdges {
    let mut result = RouteEdges {
        complete: reachability.complete,
        ..RouteEdges::default()
    };
    for (source, targets) in &reachability.outgoing {
        let Some((facts, sites)) = module_facts_and_imports(
            analyzer,
            environment_cache,
            token,
            cancellation,
            import_site_cache,
            source,
        ) else {
            result.complete = false;
            continue;
        };
        for target in targets {
            let expected_path = crate::path_utils::rel_path_string(target);
            let matching = sites
                .iter()
                .flat_map(|(start, site)| site.sites.iter().map(move |leaf| (*start, site, leaf)))
                .filter(|(_, _, leaf)| {
                    leaf.target_status == "resolved_local"
                        && leaf.target_paths.len() == 1
                        && leaf.target_paths.first() == Some(&expected_path)
                })
                .collect::<Vec<_>>();
            if matching.is_empty() {
                result.complete = false;
                continue;
            }
            for (site_start, site, leaf) in matching {
                let Some(node) = import_node_at(&facts, site_start) else {
                    result.complete = false;
                    continue;
                };
                let order = leaf.source_order as usize;
                match module_execution(&facts, node) {
                    ModuleExecution::Module if site.complete && leaf.module_scope == Some(true) => {
                        result
                            .direct
                            .entry(source.clone())
                            .or_default()
                            .push((target.clone(), order));
                    }
                    ModuleExecution::Deferred => result.complete = false,
                    ModuleExecution::Guarded | ModuleExecution::ClassBody => {
                        result.complete = false;
                    }
                    ModuleExecution::Module => result.complete = false,
                }
            }
        }
        if sites.iter().any(|(_, site)| !site.complete) {
            result.complete = false;
        }
    }
    result
}

fn reverse_route_reachable(
    outgoing: &HashMap<ProjectFile, Vec<(ProjectFile, usize)>>,
    target: &ProjectFile,
) -> HashSet<ProjectFile> {
    let mut incoming: HashMap<ProjectFile, Vec<ProjectFile>> = HashMap::default();
    for (source, edges) in outgoing {
        for (edge_target, _) in edges {
            incoming
                .entry(edge_target.clone())
                .or_default()
                .push(source.clone());
        }
    }
    let mut reached = HashSet::default();
    let mut frontier = vec![target.clone()];
    reached.insert(target.clone());
    while let Some(current) = frontier.pop() {
        if let Some(importers) = incoming.get(&current) {
            for importer in importers {
                if reached.insert(importer.clone()) {
                    frontier.push(importer.clone());
                }
            }
        }
    }
    reached
}

fn definition_timing(
    name: &str,
    import_order: usize,
    environment: &brokk_bifrost_analysis::analyzer::structural::lexical_environment::EnvironmentFileResult,
    facts: &FileFacts,
    sites: &[(usize, CodeQueryPythonImportSite)],
) -> DefinitionTiming {
    let mut definitions = environment
        .bindings_named(name)
        .iter()
        .map(|&index| &environment.bindings[index])
        .filter(|binding| binding.declaring_scope == 0)
        .map(|binding| classify_definition(binding, facts, sites))
        .collect::<Vec<_>>();
    if definitions.is_empty() {
        return DefinitionTiming::NoDefinition;
    }
    definitions.sort_by_key(|definition| (definition.order, definition.source_order));
    let prior = definitions
        .iter()
        .rfind(|definition| definition.order < import_order);
    if let Some(prior) = prior {
        return match prior.state {
            DefinitionState::Static => DefinitionTiming::DefinedBefore,
            DefinitionState::Unknown => DefinitionTiming::Unknown,
        };
    }
    match definitions.first().expect("nonempty definitions").state {
        DefinitionState::Static => DefinitionTiming::DefinedAfter,
        DefinitionState::Unknown => DefinitionTiming::Unknown,
    }
}

fn classify_definition(
    binding: &BindingRow,
    facts: &FileFacts,
    sites: &[(usize, CodeQueryPythonImportSite)],
) -> ModuleDefinition {
    if binding.import.is_some() {
        let matched = sites.iter().find_map(|(start, site)| {
            site.sites
                .iter()
                .find(|leaf| {
                    leaf.binder_range.as_ref().is_some_and(|range| {
                        same_rendered_range(
                            range,
                            &row_range(
                                facts.source(),
                                binding.range.start_byte..binding.range.end_byte,
                            ),
                        )
                    })
                })
                .map(|leaf| (*start, site, leaf))
        });
        let Some((start, site, leaf)) = matched else {
            return unknown_definition(binding);
        };
        let direct = import_node_at(facts, start).is_some_and(|node| {
            module_execution(facts, node) == ModuleExecution::Module
                && leaf.module_scope == Some(true)
                && site.complete
                && leaf.target_status == "resolved_local"
        });
        return ModuleDefinition {
            order: start,
            state: if direct {
                DefinitionState::Static
            } else {
                DefinitionState::Unknown
            },
            source_order: binding.source_order,
        };
    }
    let Some(binding_node) = binding.node else {
        return unknown_definition(binding);
    };
    let mut current = Some(binding_node);
    let mut statement = None;
    while let Some(node) = current {
        let fact = facts.node(node);
        if matches!(
            fact.kind,
            NormalizedKind::Assignment | NormalizedKind::Function | NormalizedKind::Class
        ) {
            statement = Some(node);
            break;
        }
        current = fact.parent;
    }
    let Some(statement) = statement else {
        return unknown_definition(binding);
    };
    let fact = facts.node(statement);
    let direct = match fact.kind {
        NormalizedKind::Assignment => {
            let simple_target = facts
                .role_targets(statement, Role::Left)
                .any(|target| target.node == Some(binding_node));
            let value_exists = facts.role_targets(statement, Role::Right).next().is_some();
            simple_target && value_exists
        }
        NormalizedKind::Function | NormalizedKind::Class => fact.name.is_some_and(|span| {
            span.start_byte == binding.range.start_byte && span.end_byte == binding.range.end_byte
        }),
        _ => false,
    } && module_execution(facts, statement) == ModuleExecution::Module;
    ModuleDefinition {
        order: fact.range.start_byte,
        state: if direct {
            DefinitionState::Static
        } else {
            DefinitionState::Unknown
        },
        source_order: binding.source_order,
    }
}

fn unknown_definition(binding: &BindingRow) -> ModuleDefinition {
    ModuleDefinition {
        order: binding.range.start_byte,
        state: DefinitionState::Unknown,
        source_order: binding.source_order,
    }
}

fn module_has_dynamic_attributes(
    facts: &FileFacts,
    environment: &brokk_bifrost_analysis::analyzer::structural::lexical_environment::EnvironmentFileResult,
    sites: &[(usize, CodeQueryPythonImportSite)],
) -> bool {
    if sites.iter().any(|(start, site)| {
        site.sites.iter().any(|leaf| {
            leaf.wildcard
                && import_node_at(facts, *start).is_some_and(|node| {
                    !matches!(
                        module_execution(facts, node),
                        ModuleExecution::Deferred | ModuleExecution::ClassBody
                    )
                })
        })
    }) {
        return true;
    }
    if facts.nodes().iter().enumerate().any(|(index, node)| {
        if node.kind != NormalizedKind::Function {
            return false;
        }
        let function = u32::try_from(index).expect("normalized node ids fit in u32");
        module_execution(facts, function) == ModuleExecution::Module
            && node.name.is_some_and(|name| {
                facts
                    .source()
                    .get(name.start_byte..name.end_byte)
                    .is_some_and(|spelling| spelling == "__getattr__")
            })
    }) {
        return true;
    }
    if environment
        .bindings_named("__getattr__")
        .iter()
        .any(|&index| environment.bindings[index].declaring_scope == 0)
    {
        return true;
    }
    facts.nodes().iter().enumerate().any(|(index, node)| {
        if node.kind != NormalizedKind::Call {
            return false;
        }
        let call = u32::try_from(index).expect("normalized node ids fit in u32");
        if module_execution(facts, call) == ModuleExecution::Deferred
            || facts.role_targets(call, Role::Receiver).next().is_some()
        {
            return false;
        }
        facts
            .role_targets(call, Role::Callee)
            .filter_map(|target| target.node)
            .any(|callee| {
                if facts.node(callee).kind != NormalizedKind::Identifier {
                    return false;
                }
                facts.node(callee).name.is_some_and(|name| {
                    facts
                        .source()
                        .get(name.start_byte..name.end_byte)
                        .is_some_and(|spelling| {
                            matches!(spelling, "setattr" | "exec" | "globals" | "locals")
                        })
                })
            })
    })
}

fn rule_fact(
    seed: &SeedMatch,
    anchor: std::ops::Range<usize>,
    outcome: &'static str,
    proof: &'static str,
    complete: bool,
    detail: Option<&str>,
) -> PythonRuleFactValue {
    let range = row_range(seed.facts.source(), anchor.clone());
    make_row(
        RELATION,
        &seed.file,
        anchor,
        range,
        None,
        outcome,
        proof,
        complete,
        detail.map(|_| INCOMPLETE_REASON.to_owned()),
    )
}

fn python_rule_incomplete_diagnostic(message: &str) -> CodeQueryDiagnostic {
    CodeQueryDiagnostic {
        related: Vec::new(),
        source: None,
        code: CodeQueryDiagnosticCode::SemanticAnalysisPartial,
        impact: CodeQueryDiagnosticImpact::Incomplete,
        branch: Vec::new(),
        language: Language::Python.config_label(),
        message: message.to_owned(),
        exhausted_roots: Vec::new(),
        withheld_rows_path: None,
    }
}
