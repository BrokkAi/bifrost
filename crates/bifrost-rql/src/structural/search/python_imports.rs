//! Query-scoped Python import-site facts over the canonical per-file import
//! rows. This does not retain an import graph or infer module identity from
//! workspace paths.

use super::super::provider::StructuralSyntaxLimitedOutcome;
use super::results::{CodeQueryPythonImportLeaf, CodeQueryPythonImportSite};
use super::*;
use brokk_bifrost_analysis::analyzer::workspace_authority::{CaptureScopedMemo, memo_attribution};
use brokk_bifrost_core::analyzer::capabilities::ImportAnalysisProvider;
use brokk_bifrost_core::analyzer::model::ImportInfo;
use brokk_bifrost_core::analyzer::query_token::QueryToken;
use brokk_bifrost_core::analyzer::structural::routes::CuratedExportSurface;
use brokk_bifrost_core::analyzer::structural::spec::StructuralSpec;
use brokk_bifrost_python::imports::{PythonImportDetails, python_import_details};
use brokk_bifrost_python::structural::PYTHON_STRUCTURAL_SPEC;

const MAX_IMPORT_SITE_SOURCE_BYTES: usize = 1024 * 1024;

#[derive(Default)]
pub(super) struct PythonImportSiteCache {
    files: CaptureScopedMemo<HashMap<ProjectFile, PythonImportFileFacts>>,
    export_surfaces: CaptureScopedMemo<HashMap<ProjectFile, ExportSurfaceFacts>>,
}

enum PythonImportFileFacts {
    Available(HashMap<usize, CodeQueryPythonImportSite>),
    Unavailable,
}

#[derive(Clone, Copy)]
struct ExportSurfaceFacts {
    state: &'static str,
    polluting: Option<bool>,
}

struct ImportInterpretation {
    form: &'static str,
    module: String,
    name: Option<String>,
    alias: Option<String>,
    wildcard: bool,
    module_scope: Option<bool>,
    source_order: usize,
    scope: Option<Vec<(usize, usize)>>,
}

struct ImportRelationFacts {
    count: usize,
    has_import: bool,
    has_from: bool,
}

#[derive(Clone, Copy)]
struct ImportContexts {
    in_import_error_handler: Option<bool>,
    in_main_guard: Option<bool>,
}

impl PythonImportSiteCache {
    pub(super) fn site_for_match(
        &mut self,
        analyzer: &dyn IAnalyzer,
        environment_cache: &mut super::environment::EnvironmentTraversalCache,
        token: QueryToken<'_>,
        seed: &SeedMatch,
        cancellation: Option<&CancellationToken>,
    ) -> Option<CodeQueryPythonImportSite> {
        let Self {
            files,
            export_surfaces,
        } = self;
        let attribution = memo_attribution(analyzer);
        files.read_mut(&attribution, |files| {
            export_surfaces.read_mut(&attribution, |export_surfaces| {
                if seed.language != Language::Python
                    || seed.facts.node(seed.fact_match.node).kind != NormalizedKind::Import
                {
                    return None;
                }

                let start_byte = seed.facts.node(seed.fact_match.node).range.start_byte;
                if !files.contains_key(&seed.file) {
                    let facts = build_file_import_facts(
                        analyzer,
                        token,
                        &seed.file,
                        &seed.facts,
                        environment_cache,
                        cancellation,
                        export_surfaces,
                    );
                    files.insert(seed.file.clone(), facts);
                }
                match files.get(&seed.file).expect("Python import facts cached") {
                    PythonImportFileFacts::Available(sites) => sites
                        .get(&start_byte)
                        .cloned()
                        .or_else(|| Some(incomplete_site(start_byte, "unavailable"))),
                    PythonImportFileFacts::Unavailable => {
                        Some(incomplete_site(start_byte, "unavailable"))
                    }
                }
            })
        })
    }

    pub(super) fn sites_for_file(
        &mut self,
        analyzer: &dyn IAnalyzer,
        token: QueryToken<'_>,
        file: &ProjectFile,
        facts: &FileFacts,
        environment_cache: &mut super::environment::EnvironmentTraversalCache,
        cancellation: Option<&CancellationToken>,
    ) -> Option<Vec<(usize, CodeQueryPythonImportSite)>> {
        let Self {
            files,
            export_surfaces,
        } = self;
        let attribution = memo_attribution(analyzer);
        files.read_mut(&attribution, |files| {
            export_surfaces.read_mut(&attribution, |export_surfaces| {
                if !files.contains_key(file) {
                    let file_facts = build_file_import_facts(
                        analyzer,
                        token,
                        file,
                        facts,
                        environment_cache,
                        cancellation,
                        export_surfaces,
                    );
                    files.insert(file.clone(), file_facts);
                }
                match files.get(file).expect("Python import facts cached") {
                    PythonImportFileFacts::Available(sites) => Some(
                        sites
                            .iter()
                            .map(|(&start, site)| (start, site.clone()))
                            .collect(),
                    ),
                    PythonImportFileFacts::Unavailable => None,
                }
            })
        })
    }
}

fn build_file_import_facts(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    file: &ProjectFile,
    facts: &FileFacts,
    environment_cache: &mut super::environment::EnvironmentTraversalCache,
    cancellation: Option<&CancellationToken>,
    export_surfaces: &mut HashMap<ProjectFile, ExportSurfaceFacts>,
) -> PythonImportFileFacts {
    let Some(import_provider) = analyzer.import_analysis_provider_for_file(file) else {
        return PythonImportFileFacts::Unavailable;
    };
    let Some(imports) = import_provider.import_info_of_checked(token, file) else {
        return PythonImportFileFacts::Unavailable;
    };
    if imports.is_empty() {
        return PythonImportFileFacts::Available(HashMap::default());
    }

    let statement_scopes = import_statement_scopes(facts);
    let interpretations: Vec<_> = imports
        .iter()
        .map(|import| {
            let statement_start = import.path.as_ref().map(|path| path.declaration_start_byte);
            interpret_import(
                import,
                statement_start.and_then(|start| statement_scopes.get(&start).cloned()),
            )
        })
        .collect();
    let mut relations: HashMap<(String, Vec<(usize, usize)>), ImportRelationFacts> =
        HashMap::default();
    let mut statement_imports: HashMap<usize, Vec<usize>> = HashMap::default();
    for (index, interpretation) in interpretations.iter().enumerate() {
        if let Some(interpretation) = interpretation
            && let Some(scope) = interpretation.scope.as_ref()
        {
            let relation = relations
                .entry((interpretation.module.clone(), scope.clone()))
                .or_insert(ImportRelationFacts {
                    count: 0,
                    has_import: false,
                    has_from: false,
                });
            relation.count += 1;
            relation.has_import |= interpretation.form == "import";
            relation.has_from |= interpretation.form == "from";
        }
        if let Some(path) = imports[index].path.as_ref() {
            statement_imports
                .entry(path.declaration_start_byte)
                .or_default()
                .push(index);
        }
    }

    let duplicate_statements =
        later_duplicate_import_statements(&imports, &interpretations, &statement_imports);
    let import_contexts = import_contexts(analyzer, environment_cache, file, facts, cancellation);

    let mut sites = HashMap::default();
    for (statement_start, import_indexes) in statement_imports {
        let site_records: Vec<_> = import_indexes
            .iter()
            .map(|&index| {
                let info = &imports[index];
                let interpretation = interpretations[index].as_ref();
                let (repeated, mixed_form) = interpretation.map_or((false, false), |item| {
                    item.scope
                        .as_ref()
                        .and_then(|scope| relations.get(&(item.module.clone(), scope.clone())))
                        .map_or((false, false), |relation| {
                            (relation.count > 1, relation.has_import && relation.has_from)
                        })
                });
                let (target_files, target_status, own_module) =
                    resolve_import_target(import_provider, file, info);
                let target_paths = target_files
                    .iter()
                    .map(crate::path_utils::rel_path_string)
                    .collect::<Vec<_>>();
                let (export_state, polluting) = if interpretation.is_some_and(|item| item.wildcard)
                {
                    export_facts_for_import(
                        analyzer,
                        &target_files,
                        target_status,
                        cancellation,
                        export_surfaces,
                    )
                } else {
                    ("not_wildcard", Some(false))
                };
                let (form, module, name, alias, wildcard, module_scope, source_order) =
                    interpretation.map_or(
                        (
                            "unknown",
                            String::new(),
                            None,
                            info.alias.clone(),
                            info.is_wildcard,
                            info.path.as_ref().and_then(|path| {
                                if path.lexical_scopes.is_empty() {
                                    statement_scopes
                                        .get(&path.declaration_start_byte)
                                        .map(Vec::is_empty)
                                } else {
                                    Some(false)
                                }
                            }),
                            info.path
                                .as_ref()
                                .map_or(statement_start, |path| path.declaration_start_byte),
                        ),
                        |item| {
                            (
                                item.form,
                                item.module.clone(),
                                item.name.clone(),
                                item.alias.clone(),
                                item.wildcard,
                                item.module_scope,
                                item.source_order,
                            )
                        },
                    );
                let binder_range = info
                    .binder_span
                    .map(|span| super::render::range_for_span(facts, span));
                CodeQueryPythonImportLeaf {
                    form,
                    module,
                    name,
                    alias,
                    wildcard,
                    module_scope,
                    source_order: source_order_u64(source_order),
                    binder_range,
                    target_paths,
                    target_status,
                    repeated,
                    mixed_form,
                    own_module,
                    polluting,
                    export_state,
                    cycle_state: None,
                }
            })
            .collect();
        let malformed_leaf = site_records.iter().any(|leaf| leaf.form == "unknown");
        let contexts = import_contexts
            .as_ref()
            .and_then(|contexts| contexts.get(&statement_start).copied());
        let in_import_error_handler =
            contexts.and_then(|contexts| contexts.in_import_error_handler);
        let in_main_guard = contexts.and_then(|contexts| contexts.in_main_guard);
        let complete = in_import_error_handler.is_some()
            && in_main_guard.is_some()
            && !malformed_leaf
            && site_records.iter().all(|leaf| {
                leaf.module_scope.is_some()
                    && leaf.target_status == "resolved_local"
                    && (!leaf.wildcard || matches!(leaf.export_state, "absent" | "listed"))
            });
        sites.insert(
            statement_start,
            summarize_import_site(
                site_records,
                complete,
                duplicate_statements.contains(&statement_start),
                in_import_error_handler,
                in_main_guard,
            ),
        );
    }
    PythonImportFileFacts::Available(sites)
}

fn import_contexts(
    analyzer: &dyn IAnalyzer,
    environment_cache: &mut super::environment::EnvironmentTraversalCache,
    file: &ProjectFile,
    facts: &FileFacts,
    cancellation: Option<&CancellationToken>,
) -> Option<HashMap<usize, ImportContexts>> {
    let source = facts.source();
    let tree = environment_cache
        .python_syntax_tree_for(analyzer, file, facts.source_identity(), source)
        .ok()?;
    let mut contexts = HashMap::default();
    let mut pending = vec![(tree.root_node(), Some(false), false)];
    while let Some((node, inherited_handler, inherited_main_guard)) = pending.pop() {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return None;
        }
        let handler_context = match node.kind() {
            "function_definition" | "lambda" => Some(false),
            "except_clause" => {
                match super::python_rule_facts::python_except_clause_catches_builtin(
                    analyzer,
                    environment_cache,
                    file,
                    source,
                    node,
                    "ImportError",
                    cancellation,
                ) {
                    Some(true) => Some(true),
                    Some(false) => inherited_handler,
                    None if inherited_handler == Some(true) => Some(true),
                    None => None,
                }
            }
            _ => inherited_handler,
        };
        let main_guard_context = inherited_main_guard || python_if_is_name_eq_main(node, source);
        if matches!(node.kind(), "import_statement" | "import_from_statement") {
            contexts.insert(
                node.start_byte(),
                ImportContexts {
                    in_import_error_handler: handler_context,
                    in_main_guard: Some(main_guard_context),
                },
            );
        }
        for index in (0..node.named_child_count()).rev() {
            if let Some(child) = node.named_child(index) {
                pending.push((child, handler_context, main_guard_context));
            }
        }
    }
    Some(contexts)
}

fn python_if_is_name_eq_main(node: tree_sitter::Node<'_>, source: &str) -> bool {
    if node.kind() != "if_statement" {
        return false;
    }
    let Some(condition) = node.child_by_field_name("condition") else {
        return false;
    };
    if condition.kind() != "comparison_operator" {
        return false;
    }
    let mut cursor = condition.walk();
    let operators = condition
        .children_by_field_name("operators", &mut cursor)
        .map(|operator| operator.kind())
        .collect::<Vec<_>>();
    let operands = super::python_rule_facts::named_children(condition);
    if operators.as_slice() != ["=="] || operands.len() != 2 {
        return false;
    }
    let (left, right) = (operands[0], operands[1]);
    (super::python_rule_facts::node_text(source, left) == Some("__name__")
        && brokk_bifrost_python::syntax::python_plain_string_literal(right, source)
            == Some("__main__"))
        || (super::python_rule_facts::node_text(source, right) == Some("__name__")
            && brokk_bifrost_python::syntax::python_plain_string_literal(left, source)
                == Some("__main__"))
}

/// Find later simple imports that repeat an earlier module-scope import with
/// the same parsed module and local binding name. The input contains one
/// source file, and the result is used only by this query's import-site rows.
fn later_duplicate_import_statements(
    imports: &[ImportInfo],
    interpretations: &[Option<ImportInterpretation>],
    statement_imports: &HashMap<usize, Vec<usize>>,
) -> std::collections::HashSet<usize> {
    let mut statement_starts = statement_imports.keys().copied().collect::<Vec<_>>();
    statement_starts.sort_unstable();

    let mut earlier_module_bindings = std::collections::HashSet::<(String, String)>::new();
    let mut duplicates = std::collections::HashSet::new();
    for statement_start in statement_starts {
        let mut module_scope_bindings = Vec::new();
        for &index in &statement_imports[&statement_start] {
            let Some(interpretation) = interpretations[index].as_ref() else {
                continue;
            };
            if interpretation.form != "import" {
                continue;
            }
            let Some(local_name) = imports[index].local_name() else {
                continue;
            };
            let key = (interpretation.module.clone(), local_name.to_owned());
            if earlier_module_bindings.contains(&key) {
                duplicates.insert(statement_start);
            }
            if interpretation.module_scope == Some(true) {
                module_scope_bindings.push(key);
            }
        }
        earlier_module_bindings.extend(module_scope_bindings);
    }
    duplicates
}

fn import_statement_scopes(facts: &FileFacts) -> HashMap<usize, Vec<(usize, usize)>> {
    let mut scopes = HashMap::default();
    for node in facts
        .nodes()
        .iter()
        .filter(|node| node.kind == NormalizedKind::Import)
    {
        let mut parent = node.parent;
        let scope = loop {
            let Some(parent_id) = parent else {
                break Vec::new();
            };
            let parent_node = facts.node(parent_id);
            if matches!(
                parent_node.kind,
                NormalizedKind::Function
                    | NormalizedKind::Method
                    | NormalizedKind::Constructor
                    | NormalizedKind::Class
                    | NormalizedKind::Lambda
            ) {
                break vec![(parent_node.range.start_byte, parent_node.range.end_byte)];
            }
            parent = parent_node.parent;
        };
        scopes.insert(node.range.start_byte, scope);
    }
    scopes
}

fn interpret_import(
    import: &ImportInfo,
    statement_scope: Option<Vec<(usize, usize)>>,
) -> Option<ImportInterpretation> {
    let path = import.path.as_ref()?;
    let (form, module, name, alias, wildcard) = match python_import_details(import)? {
        PythonImportDetails::Import { module, alias } => ("import", module, None, alias, false),
        PythonImportDetails::FromImport {
            module,
            name,
            alias,
            wildcard,
        } => ("from", module, Some(name), alias, wildcard),
    };
    let scope = if path.lexical_scopes.is_empty() {
        statement_scope
    } else {
        Some(
            path.lexical_scopes
                .iter()
                .map(|scope| (scope.start_byte, scope.end_byte))
                .collect(),
        )
    };
    Some(ImportInterpretation {
        form,
        module,
        name,
        alias,
        wildcard,
        module_scope: scope.as_ref().map(Vec::is_empty),
        source_order: path.declaration_start_byte,
        scope,
    })
}

fn resolve_import_target(
    import_provider: &dyn ImportAnalysisProvider,
    importing_file: &ProjectFile,
    import: &ImportInfo,
) -> (Vec<ProjectFile>, &'static str, Option<bool>) {
    let Some(targets) =
        import_provider.imported_files_from_infos(importing_file, std::slice::from_ref(import))
    else {
        return (Vec::new(), "unavailable", None);
    };
    let mut targets: Vec<_> = targets.into_iter().collect();
    targets.sort_by_key(crate::path_utils::rel_path_string);
    match targets.len() {
        0 => (targets, "no_workspace_target", None),
        1 => (
            targets.clone(),
            "resolved_local",
            Some(
                targets
                    .first()
                    .is_some_and(|target| target == importing_file),
            ),
        ),
        _ => (targets, "ambiguous", None),
    }
}

fn export_facts_for_import(
    analyzer: &dyn IAnalyzer,
    target_files: &[ProjectFile],
    target_status: &'static str,
    cancellation: Option<&CancellationToken>,
    cache: &mut HashMap<ProjectFile, ExportSurfaceFacts>,
) -> (&'static str, Option<bool>) {
    if target_status == "unavailable" {
        return ("unavailable", None);
    }
    if target_status == "no_workspace_target" {
        return ("unresolved", None);
    }
    if target_status == "ambiguous" {
        return ("ambiguous", None);
    }
    let Some(target_file) = target_files.first() else {
        return ("unavailable", None);
    };
    if !cache.contains_key(target_file) {
        let surface = analyzer
            .structural_fact_providers()
            .into_iter()
            .find(|provider| provider.structural_language() == Language::Python)
            .map_or(StructuralSyntaxLimitedOutcome::Unavailable, |provider| {
                provider.structural_syntax_limited(
                    target_file,
                    MAX_IMPORT_SITE_SOURCE_BYTES,
                    cancellation,
                )
            });
        let facts = match surface {
            StructuralSyntaxLimitedOutcome::Available(syntax) => {
                let prepared = syntax.prepared();
                let surface = PYTHON_STRUCTURAL_SPEC
                    .curated_export_surface(prepared.tree().root_node(), prepared.source());
                match surface {
                    CuratedExportSurface::Absent => ExportSurfaceFacts {
                        state: "absent",
                        polluting: Some(true),
                    },
                    CuratedExportSurface::Listed(_) => ExportSurfaceFacts {
                        state: "listed",
                        polluting: Some(false),
                    },
                    CuratedExportSurface::Unreadable => ExportSurfaceFacts {
                        state: "unreadable",
                        polluting: None,
                    },
                }
            }
            StructuralSyntaxLimitedOutcome::Cancelled
            | StructuralSyntaxLimitedOutcome::Exceeded { .. }
            | StructuralSyntaxLimitedOutcome::Unavailable => ExportSurfaceFacts {
                state: "unavailable",
                polluting: None,
            },
        };
        cache.insert(target_file.clone(), facts);
    }
    let facts = cache.get(target_file).expect("export surface cached");
    (facts.state, facts.polluting)
}

fn summarize_import_site(
    sites: Vec<CodeQueryPythonImportLeaf>,
    complete: bool,
    duplicate: bool,
    in_import_error_handler: Option<bool>,
    in_main_guard: Option<bool>,
) -> CodeQueryPythonImportSite {
    let form = unique_values(sites.iter().map(|site| site.form));
    let export_state = summarize_label(sites.iter().map(|site| site.export_state), "unavailable");
    let target_status = summarize_label(sites.iter().map(|site| site.target_status), "unavailable");
    let modules = unique_values(sites.iter().map(|site| site.module.as_str()));
    let names = unique_values(sites.iter().filter_map(|site| site.name.as_deref()));
    let aliases = unique_values(sites.iter().filter_map(|site| site.alias.as_deref()));
    let mut target_paths = unique_values(
        sites
            .iter()
            .flat_map(|site| site.target_paths.iter().map(String::as_str)),
    )
    .into_iter()
    .map(str::to_string)
    .collect::<Vec<_>>();
    target_paths.sort();
    let source_order = sites
        .iter()
        .map(|site| site.source_order)
        .min()
        .unwrap_or_default();
    let own_module = if sites.iter().any(|site| site.own_module == Some(true)) {
        Some(true)
    } else if sites.iter().all(|site| site.own_module.is_some()) {
        Some(false)
    } else {
        None
    };
    let polluting = if sites.iter().any(|site| site.polluting == Some(true)) {
        Some(true)
    } else if sites
        .iter()
        .all(|site| !site.wildcard || site.polluting == Some(false))
    {
        Some(false)
    } else {
        None
    };
    CodeQueryPythonImportSite {
        complete,
        form: (form.len() == 1 && matches!(form[0], "import" | "from")).then(|| form[0]),
        module: (modules.len() == 1).then(|| modules[0].to_string()),
        name: (names.len() == 1).then(|| names[0].to_string()),
        alias: (aliases.len() == 1).then(|| aliases[0].to_string()),
        modules: modules.into_iter().map(str::to_string).collect(),
        names: names.into_iter().map(str::to_string).collect(),
        aliases: aliases.into_iter().map(str::to_string).collect(),
        wildcard: sites.iter().any(|site| site.wildcard),
        module_scope: (!sites.is_empty() && sites.iter().all(|site| site.module_scope.is_some()))
            .then(|| sites.iter().all(|site| site.module_scope == Some(true))),
        source_order,
        target_paths,
        target_status,
        repeated: sites.iter().any(|site| site.repeated),
        duplicate: duplicate.then_some(true),
        in_import_error_handler,
        in_main_guard,
        mixed_form: sites.iter().any(|site| site.mixed_form),
        own_module,
        polluting,
        export_state,
        cycle_state: None,
        sites,
    }
}

fn unique_values<'a>(values: impl IntoIterator<Item = &'a str>) -> Vec<&'a str> {
    let mut unique = Vec::new();
    for value in values {
        if !unique.contains(&value) {
            unique.push(value);
        }
    }
    unique
}

fn summarize_label(
    values: impl IntoIterator<Item = &'static str>,
    empty: &'static str,
) -> &'static str {
    let mut unique = values.into_iter();
    let Some(first) = unique.next() else {
        return empty;
    };
    if unique.any(|value| value != first) {
        "mixed"
    } else {
        first
    }
}

fn incomplete_site(source_order: usize, target_status: &'static str) -> CodeQueryPythonImportSite {
    CodeQueryPythonImportSite {
        complete: false,
        form: None,
        module: None,
        name: None,
        alias: None,
        modules: Vec::new(),
        names: Vec::new(),
        aliases: Vec::new(),
        wildcard: false,
        module_scope: None,
        source_order: source_order_u64(source_order),
        target_paths: Vec::new(),
        target_status,
        repeated: false,
        duplicate: None,
        in_import_error_handler: None,
        in_main_guard: None,
        mixed_form: false,
        own_module: None,
        polluting: None,
        export_state: "unavailable",
        cycle_state: None,
        sites: Vec::new(),
    }
}

fn source_order_u64(source_order: usize) -> u64 {
    u64::try_from(source_order).expect("source byte offset fits in u64")
}
