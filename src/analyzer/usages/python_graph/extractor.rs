use crate::analyzer::usages::graph_core::{ImportEdge, ImportEdgeKind, ProjectUsageGraph};
use crate::analyzer::usages::local_inference::{
    LocalBindingsSnapshot, LocalInferenceConfig, LocalInferenceEngine, SymbolResolution,
};
use crate::analyzer::usages::model::{ExportIndex, ImportBinder, UsageHit};
use crate::analyzer::usages::python_graph::hits::record_hit;
use crate::analyzer::usages::python_graph::resolver::{
    member_name, normalized_receiver_type, python_module_name, receiver_annotation_matches_target,
    resolve_python_relative_module, resolve_receiver_type, target_owner_code_unit,
    top_level_identifier,
};
use crate::analyzer::{CodeUnit, IAnalyzer, Language, ProjectFile, PythonAnalyzer, Range};
use crate::hash::{HashMap, HashSet};
use crate::text_utils::compute_line_starts;
use rayon::prelude::*;
use regex::Regex;
use std::collections::{BTreeSet, VecDeque};
use std::sync::{Arc, LazyLock, Mutex};
use tree_sitter::{Node, Parser, Tree};

struct ParsedFile {
    source: Arc<String>,
    tree: Tree,
}

pub(super) struct PythonProjectGraph {
    parsed: HashMap<ProjectFile, ParsedFile>,
    pub(super) usage_graph: ProjectUsageGraph,
    scoped_files: HashSet<ProjectFile>,
}

impl PythonProjectGraph {
    pub(super) fn scan_files(
        &self,
        candidate_files: &HashSet<ProjectFile>,
        target_file: &ProjectFile,
    ) -> HashSet<ProjectFile> {
        candidate_files
            .iter()
            .filter(|file| self.scoped_files.contains(*file))
            .cloned()
            .chain(std::iter::once(target_file.clone()))
            .collect()
    }
}

struct PythonGraphAdapter<'a> {
    analyzer: &'a PythonAnalyzer,
    module_index: HashMap<String, Vec<ProjectFile>>,
}

impl<'a> PythonGraphAdapter<'a> {
    fn new(analyzer: &'a PythonAnalyzer) -> Self {
        let python_files = collect_python_files(analyzer);
        let mut module_index: HashMap<String, Vec<ProjectFile>> = HashMap::default();
        for file in python_files {
            module_index
                .entry(python_module_name(&file))
                .or_default()
                .push(file);
        }
        for files in module_index.values_mut() {
            files.sort();
            files.dedup();
        }

        Self {
            analyzer,
            module_index,
        }
    }

    fn build_graph(
        &self,
        candidate_files: &HashSet<ProjectFile>,
        target_file: &ProjectFile,
    ) -> PythonProjectGraph {
        let parser_language = tree_sitter_python::LANGUAGE.into();
        let mut scoped_files: HashSet<ProjectFile> = candidate_files.iter().cloned().collect();
        scoped_files.insert(target_file.clone());

        let mut frontier: VecDeque<ProjectFile> = scoped_files.iter().cloned().collect();
        let mut parsed: HashMap<ProjectFile, ParsedFile> = HashMap::default();
        let mut exports_by_file: HashMap<ProjectFile, ExportIndex> = HashMap::default();
        let mut binders_by_file: HashMap<ProjectFile, ImportBinder> = HashMap::default();

        while let Some(file) = frontier.pop_front() {
            if parsed.contains_key(&file) {
                continue;
            }

            let Ok(source) = file.read_to_string() else {
                continue;
            };
            if source.is_empty() {
                continue;
            }

            let mut parser = Parser::new();
            if parser.set_language(&parser_language).is_err() {
                continue;
            }
            let Some(tree) = parser.parse(source.as_str(), None) else {
                continue;
            };

            let exports = self.analyzer.export_index_of(&file);
            let binder = self.analyzer.import_binder_of(&file);
            self.enqueue_frontier_files(&file, &exports, &binder, &mut scoped_files, &mut frontier);

            parsed.insert(
                file.clone(),
                ParsedFile {
                    source: Arc::new(source),
                    tree,
                },
            );
            exports_by_file.insert(file.clone(), exports);
            binders_by_file.insert(file, binder);
        }

        let files: Vec<ProjectFile> = parsed.keys().cloned().collect();
        let usage_graph =
            ProjectUsageGraph::build(files, exports_by_file, &binders_by_file, |file, module| {
                self.resolve_module(file, module)
            });

        PythonProjectGraph {
            parsed,
            usage_graph,
            scoped_files,
        }
    }

    fn enqueue_frontier_files(
        &self,
        file: &ProjectFile,
        exports: &ExportIndex,
        binder: &ImportBinder,
        scoped_files: &mut HashSet<ProjectFile>,
        frontier: &mut VecDeque<ProjectFile>,
    ) {
        for entry in exports.exports_by_name.values() {
            if let crate::analyzer::usages::ExportEntry::ReexportedNamed {
                module_specifier, ..
            } = entry
            {
                self.extend_scope(file, module_specifier, scoped_files, frontier);
            }
        }
        for star in &exports.reexport_stars {
            self.extend_scope(file, &star.module_specifier, scoped_files, frontier);
        }
        for binding in binder.bindings.values() {
            self.extend_scope(file, &binding.module_specifier, scoped_files, frontier);
        }
    }

    fn extend_scope(
        &self,
        importing_file: &ProjectFile,
        module_specifier: &str,
        scoped_files: &mut HashSet<ProjectFile>,
        frontier: &mut VecDeque<ProjectFile>,
    ) {
        for resolved in self.resolve_module(importing_file, module_specifier) {
            if scoped_files.insert(resolved.clone()) {
                frontier.push_back(resolved);
            }
        }
    }

    fn resolve_module(
        &self,
        importing_file: &ProjectFile,
        module_specifier: &str,
    ) -> Vec<ProjectFile> {
        let resolved_module = if module_specifier.starts_with('.') {
            resolve_python_relative_module(importing_file, module_specifier)
        } else {
            Some(module_specifier.to_string())
        };
        let Some(resolved_module) = resolved_module else {
            return Vec::new();
        };
        self.module_index
            .get(&resolved_module)
            .cloned()
            .unwrap_or_default()
    }
}

pub(super) fn build_python_graph(
    analyzer: &PythonAnalyzer,
    candidate_files: &HashSet<ProjectFile>,
    target_file: &ProjectFile,
) -> PythonProjectGraph {
    PythonGraphAdapter::new(analyzer).build_graph(candidate_files, target_file)
}

fn collect_python_files(analyzer: &PythonAnalyzer) -> Vec<ProjectFile> {
    let mut files: Vec<ProjectFile> = analyzer
        .project()
        .analyzable_files(Language::Python)
        .map(|set| set.into_iter().collect())
        .unwrap_or_default();
    files.sort();
    files.dedup();
    files
}

pub(super) fn scan_files_for_seeds(
    analyzer: &dyn IAnalyzer,
    graph: &PythonProjectGraph,
    files: &HashSet<ProjectFile>,
    target: &CodeUnit,
    seeds: &BTreeSet<(ProjectFile, String)>,
) -> BTreeSet<UsageHit> {
    let collected: Mutex<BTreeSet<UsageHit>> = Mutex::new(BTreeSet::new());
    let target_short = top_level_identifier(target).to_string();
    let target_member = member_name(target);
    let target_owner = target_owner_code_unit(analyzer, target);
    let files_vec: Vec<&ProjectFile> = files.iter().collect();
    let parser_language = tree_sitter_python::LANGUAGE.into();

    files_vec.par_iter().for_each(|file| {
        let owned_source: Option<Arc<String>>;
        let owned_tree: Option<Tree>;
        let (source_str, tree_ref) = if let Some(parsed) = graph.parsed.get(*file) {
            (parsed.source.as_str(), &parsed.tree)
        } else {
            let Ok(source) = file.read_to_string() else {
                return;
            };
            if source.is_empty() {
                return;
            }
            let mut parser = Parser::new();
            if parser.set_language(&parser_language).is_err() {
                return;
            }
            let Some(tree) = parser.parse(source.as_str(), None) else {
                return;
            };
            owned_source = Some(Arc::new(source));
            owned_tree = Some(tree);
            (
                owned_source.as_deref().unwrap().as_str(),
                owned_tree.as_ref().unwrap(),
            )
        };

        let edges = graph.usage_graph.matching_edges_for_importer(file, seeds);
        let local_conflicts = collect_top_level_conflicts(tree_ref.root_node(), source_str);
        let target_self_file = *file == target.source();
        let scope_facts = collect_scope_facts(
            analyzer,
            file,
            &edges,
            target_short.as_str(),
            target_self_file,
        );

        let mut local_hits = BTreeSet::new();
        let line_starts = compute_line_starts(source_str);

        let mut scan_ctx = ScanCtx {
            file,
            source: source_str,
            line_starts: &line_starts,
            analyzer,
            target_short: &target_short,
            target_member: target_member.as_deref(),
            target_owner: target_owner.clone(),
            edges: &edges,
            target_self_file,
            local_conflicts: &local_conflicts,
            scope_facts: &scope_facts,
            hits: &mut local_hits,
        };

        scan_node(tree_ref.root_node(), &mut scan_ctx);

        if !local_hits.is_empty() {
            let mut sink = collected
                .lock()
                .expect("usage hit collector mutex poisoned");
            sink.extend(local_hits);
        }
    });

    collected
        .into_inner()
        .expect("usage hit collector mutex poisoned")
}

pub(super) struct ScanCtx<'a> {
    pub(super) file: &'a ProjectFile,
    pub(super) source: &'a str,
    pub(super) line_starts: &'a [usize],
    pub(super) analyzer: &'a dyn IAnalyzer,
    target_short: &'a str,
    target_member: Option<&'a str>,
    target_owner: Option<CodeUnit>,
    edges: &'a [ImportEdge],
    target_self_file: bool,
    local_conflicts: &'a HashSet<String>,
    scope_facts: &'a HashMap<CodeUnit, LocalBindingsSnapshot<String>>,
    pub(super) hits: &'a mut BTreeSet<UsageHit>,
}

impl ScanCtx<'_> {
    fn scope_facts_for_node(&self, node: Node<'_>) -> Option<&LocalBindingsSnapshot<String>> {
        let range = Range {
            start_byte: node.start_byte(),
            end_byte: node.end_byte(),
            start_line: 0,
            end_line: 0,
        };
        let enclosing = self.analyzer.enclosing_code_unit(self.file, &range)?;
        self.scope_facts.get(&enclosing)
    }

    fn binds_target(&self, ident: &str, node: Node<'_>) -> bool {
        if let Some(scope_facts) = self.scope_facts_for_node(node)
            && scope_facts.is_shadowed(ident)
        {
            return false;
        }
        if !self.target_self_file && self.local_conflicts.contains(ident) {
            return false;
        }
        if self.edges.iter().any(|edge| edge.local_name == ident) {
            return true;
        }
        self.target_self_file && ident == self.target_short
    }

    fn receiver_binds_target(&self, expr: &str, node: Node<'_>) -> bool {
        if self.binds_target(expr, node) {
            return true;
        }

        let Some(scope_facts) = self.scope_facts_for_node(node) else {
            return false;
        };
        let resolution = scope_facts.resolution_for(expr);
        let Some(raw_type) = resolution
            .as_precise()
            .and_then(|targets| targets.iter().next())
        else {
            return false;
        };
        self.receiver_type_matches_target(raw_type)
    }

    fn receiver_type_matches_target(&self, raw_type: &str) -> bool {
        if receiver_annotation_matches_target(
            raw_type,
            self.edges,
            self.target_short,
            self.target_self_file,
        ) {
            return true;
        }

        let Some(target_owner) = self.target_owner.as_ref() else {
            return false;
        };
        let Some(receiver_type) =
            resolve_receiver_type(self.analyzer, self.file, raw_type, self.target_self_file)
        else {
            return false;
        };
        if &receiver_type == target_owner {
            return true;
        }
        self.analyzer
            .type_hierarchy_provider()
            .map(|provider| provider.get_ancestors(&receiver_type))
            .unwrap_or_default()
            .into_iter()
            .any(|ancestor| ancestor == *target_owner)
    }
}

fn scan_node(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let mut stack = vec![node];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "import_statement" | "import_from_statement" => continue,
            "identifier" => handle_identifier_candidate(node, ctx),
            "attribute" => handle_attribute_candidate(node, ctx),
            _ => {}
        }

        let mut cursor = node.walk();
        let mut children: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
        children.reverse();
        stack.extend(children);
    }
}

fn handle_identifier_candidate(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if ctx.target_member.is_some() {
        return;
    }
    if node
        .parent()
        .is_some_and(|parent| parent.kind() == "attribute")
    {
        return;
    }
    let text = slice(node, ctx.source);
    if text.is_empty() || !ctx.binds_target(text, node) || is_declaration_identifier(node) {
        return;
    }
    record_hit(node, ctx);
}

fn handle_attribute_candidate(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let Some(object) = node.child_by_field_name("object") else {
        return;
    };
    let Some(attribute) = node.child_by_field_name("attribute") else {
        return;
    };
    let object_text = slice(object, ctx.source);
    let attribute_text = slice(attribute, ctx.source);
    if let Some(member) = ctx.target_member
        && ctx.receiver_binds_target(object_text, node)
        && attribute_text == member
    {
        record_hit(attribute, ctx);
    }

    let namespace_match = ctx.edges.iter().any(|edge| {
        matches!(edge.kind, ImportEdgeKind::Namespace)
            && (edge.local_name == object_text
                || object_text.ends_with(&format!(".{}", edge.local_name)))
    });
    if ctx.target_member.is_none() && namespace_match && attribute_text == ctx.target_short {
        record_hit(attribute, ctx);
    }
}

pub(super) fn slice<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    source.get(node.start_byte()..node.end_byte()).unwrap_or("")
}

fn is_declaration_identifier(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    let parent_kind = parent.kind();
    if matches!(
        parent_kind,
        "class_definition" | "function_definition" | "parameters"
    ) && parent
        .child_by_field_name("name")
        .map(|name| name.id() == node.id())
        .unwrap_or(false)
    {
        return true;
    }

    if matches!(
        parent_kind,
        "aliased_import" | "import_from_statement" | "import_statement"
    ) {
        return true;
    }

    parent_kind == "assignment"
        && parent
            .child_by_field_name("left")
            .map(|left| {
                left.start_byte() <= node.start_byte() && node.end_byte() <= left.end_byte()
            })
            .unwrap_or(false)
}

fn collect_top_level_conflicts(root: Node<'_>, source: &str) -> HashSet<String> {
    let mut conflicts = HashSet::default();
    let mut cursor = root.walk();
    for child in root.named_children(&mut cursor) {
        match child.kind() {
            "class_definition" | "function_definition" => {
                if let Some(name) = child.child_by_field_name("name") {
                    let text = slice(name, source).trim();
                    if !text.is_empty() {
                        conflicts.insert(text.to_string());
                    }
                }
            }
            "expression_statement" => {
                if let Some(assignment) = child.named_child(0)
                    && assignment.kind() == "assignment"
                    && let Some(left) = assignment.child_by_field_name("left")
                {
                    collect_assigned_identifiers(left, source, &mut conflicts);
                }
            }
            _ => {}
        }
    }
    conflicts
}

fn collect_assigned_identifiers(node: Node<'_>, source: &str, out: &mut HashSet<String>) {
    let mut stack = vec![node];
    while let Some(node) = stack.pop() {
        if node.kind() == "identifier" {
            let text = slice(node, source).trim();
            if !text.is_empty() {
                out.insert(text.to_string());
            }
            continue;
        }

        let mut cursor = node.walk();
        let mut children: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
        children.reverse();
        stack.extend(children);
    }
}

fn collect_scope_facts(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    edges: &[ImportEdge],
    target_short: &str,
    target_self_file: bool,
) -> HashMap<CodeUnit, LocalBindingsSnapshot<String>> {
    let declarations = analyzer.get_declarations(file);
    let mut class_facts_by_name: HashMap<String, LocalBindingsSnapshot<String>> =
        HashMap::default();
    for declaration in declarations
        .iter()
        .filter(|declaration| declaration.is_class())
    {
        let Some(source) = analyzer.get_source(declaration, false) else {
            continue;
        };
        let facts =
            collect_scope_facts_from_source(&source, edges, target_short, target_self_file, true);
        class_facts_by_name.insert(
            declaration.short_name().to_string(),
            facts.filtered_visible_bindings(|symbol, _| symbol.starts_with("self.")),
        );
    }

    let mut scope_facts = HashMap::default();
    for declaration in declarations
        .iter()
        .filter(|declaration| declaration.is_function())
    {
        let Some(source) = analyzer.get_source(declaration, false) else {
            continue;
        };
        let mut facts =
            collect_scope_facts_from_source(&source, edges, target_short, target_self_file, false);
        if let Some((owner, _)) = declaration.short_name().rsplit_once('.')
            && let Some(class_facts) = class_facts_by_name.get(owner)
        {
            facts = facts.merged_with_visible(class_facts);
        }
        scope_facts.insert(declaration.clone(), facts);
    }
    scope_facts
}

fn collect_scope_facts_from_source(
    source: &str,
    _edges: &[ImportEdge],
    _target_short: &str,
    _target_self_file: bool,
    allow_self_receivers: bool,
) -> LocalBindingsSnapshot<String> {
    static PARAM_ANNOTATION_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"([A-Za-z_][A-Za-z0-9_\.]*)\s*:\s*([^=,\)\n]+)").unwrap());
    static PARAM_NAME_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"def\s+[A-Za-z_][A-Za-z0-9_]*\s*\((?P<params>[^)]*)\)").unwrap()
    });
    static ASSIGNMENT_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^\s*([A-Za-z_][A-Za-z0-9_\.]*)\s*=\s*([A-Za-z_][A-Za-z0-9_\.()]*)\s*$")
            .unwrap()
    });

    let mut engine = LocalInferenceEngine::new(LocalInferenceConfig::default());
    for captures in PARAM_NAME_RE.captures_iter(source) {
        let params = captures
            .name("params")
            .map(|m| m.as_str())
            .unwrap_or_default();
        for param in params.split(',') {
            let param = param.trim();
            if param.is_empty() || matches!(param, "self" | "cls" | "/") {
                continue;
            }
            let param_name = param
                .split(':')
                .next()
                .unwrap_or(param)
                .split('=')
                .next()
                .unwrap_or(param)
                .trim();
            if !param_name.is_empty() && !engine.is_shadowed(param_name) {
                engine.declare_shadow(param_name.to_string());
            }
        }
    }

    let mut changed = true;
    while changed {
        changed = false;
        let mut aliases = Vec::new();
        for line in source.lines() {
            for captures in PARAM_ANNOTATION_RE.captures_iter(line) {
                let lhs = captures.get(1).map(|m| m.as_str()).unwrap_or_default();
                let annotation = captures.get(2).map(|m| m.as_str()).unwrap_or_default();
                if lhs.starts_with("self.") && !allow_self_receivers {
                    continue;
                }
                if let Some(receiver_type) = normalized_receiver_type(annotation)
                    && engine.resolve_symbol(lhs).is_unknown()
                {
                    engine.seed_symbol(lhs.to_string(), receiver_type);
                    changed = true;
                }
            }

            let Some(captures) = ASSIGNMENT_RE.captures(line) else {
                continue;
            };
            let lhs = captures.get(1).map(|m| m.as_str()).unwrap_or_default();
            let rhs = captures.get(2).map(|m| m.as_str()).unwrap_or_default();
            if lhs.is_empty() || rhs.is_empty() {
                continue;
            }
            let rhs_symbol = rhs.strip_suffix("()").unwrap_or(rhs).trim();
            if !engine.is_shadowed(lhs) {
                engine.declare_shadow(lhs.to_string());
            }
            if lhs.starts_with("self.") && !allow_self_receivers {
                continue;
            }

            if !engine.is_shadowed(rhs_symbol)
                && let Some(receiver_type) = normalized_receiver_type(rhs_symbol)
                && engine.resolve_symbol(lhs).is_unknown()
            {
                engine.seed_symbol(lhs.to_string(), receiver_type);
                changed = true;
                continue;
            }

            match engine.resolve_symbol(rhs_symbol) {
                SymbolResolution::Precise(targets) if !targets.is_empty() => {
                    aliases.push((lhs.to_string(), rhs_symbol.to_string()));
                }
                SymbolResolution::Unknown
                | SymbolResolution::Ambiguous
                | SymbolResolution::Precise(_) => {}
            }
        }
        let before = engine.snapshot();
        engine.apply_aliases_until_stable(aliases);
        if engine.snapshot() != before {
            changed = true;
        }
    }

    engine.snapshot()
}
