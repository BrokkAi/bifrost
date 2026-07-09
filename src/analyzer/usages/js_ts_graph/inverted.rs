//! Whole-workspace inverted edge builder for JavaScript / TypeScript.
//!
//! The per-symbol path scans every importer of a symbol once per symbol; this
//! walks each file once and resolves every reference to the callee it names, via
//! the shared [`build_edges`] driver. JS/TS node fqns are bare names (`Anchor`,
//! `AxisDomain.constructor`), so resolving a reference means finding the exported
//! name it binds to:
//!
//! - a bare identifier bound by a named import resolves to the import's *exported*
//!   name; bound by a same-file declaration, to that name;
//! - `ns.member` where `ns` is a namespace import resolves to `member`;
//! - `Class.member` where `Class` is an imported/same-file class resolves to
//!   `Class.member`.
//!
//! Local variables and parameters shadow imports/declarations and are skipped.
//! Default-import and instance-typed-receiver resolution are not handled yet (they
//! need module/default-export and type inference); those references are simply not
//! emitted, mirroring a recall gap rather than a wrong edge.

use super::extractor::rightmost_jsx_identifier;
use super::receiver_analysis::JsTsReceiverFactProvider;
use super::resolver::{JsTsUsageIndex, collect_jsts_files, tree_sitter_language_for};
use crate::analyzer::js_ts::syntax::{
    compute_import_binder, is_declaration_identifier, is_object_in_member_expression,
    is_property_key_in_member, slice,
};
use crate::analyzer::usages::common::{TreeWalkAction, walk_tree_iterative};
use crate::analyzer::usages::inverted_edges::{
    EdgeCollector, UsageEdgeWeights, UsageEdges, UsageNodeKey, build_edge_weights, build_edges,
    collect_file_edges, parse_and_collect,
};
use crate::analyzer::usages::local_inference::{LocalInferenceConfig, LocalInferenceEngine};
use crate::analyzer::usages::model::{ExportEntry, ImportKind};
use crate::analyzer::usages::parsed_tree::{
    js_ts_tree_sitter_language_for_file, parse_tree_sitter_file,
};
use crate::analyzer::usages::receiver_analysis::{ReceiverAnalysisBudget, ReceiverAnalysisOutcome};
use crate::analyzer::{IAnalyzer, Language, ProjectFile};
use crate::hash::{HashMap, HashSet};
use std::collections::{BTreeMap, BTreeSet};
use tree_sitter::Node;

/// Build every JS/TS `caller -> callee` edge in one parse-on-demand pass over the
/// workspace files, using the shared [`build_edges`] driver for all the
/// language-agnostic accounting.
pub(super) fn build_jsts_edges<F>(
    analyzer: &dyn IAnalyzer,
    language: Language,
    nodes: &HashSet<String>,
    keep_file: F,
) -> UsageEdges
where
    F: Fn(&ProjectFile) -> bool + Sync,
{
    if tree_sitter_language_for(language).is_none() {
        return UsageEdges::default();
    }
    let _index = super::cached_jsts_index(analyzer, language);
    let files = collect_jsts_files(analyzer, language);
    build_edges(&files, keep_file, |file| {
        // The non-scoped scan needs only the file's own tree for its main binder +
        // declaration pass. Receiver analysis can consult the analyzer-cached
        // resolution index, so it is pre-materialized before this parallel scan.
        let parser_language = js_ts_tree_sitter_language_for_file(file, language)?;
        parse_and_collect(
            analyzer,
            file,
            nodes,
            &parser_language,
            |parsed, collector| {
                let source = parsed.source.as_str();

                // Per-file resolution context: which bare names resolve to which
                // exported name, and which locals are namespace imports.
                let binder = compute_import_binder(source, &parsed.tree);
                let mut named_imports: HashMap<String, String> = HashMap::default();
                let mut namespace_locals: HashSet<String> = HashSet::default();
                for (local, binding) in &binder.bindings {
                    match binding.kind {
                        ImportKind::Named => {
                            named_imports.insert(
                                local.clone(),
                                binding
                                    .imported_name
                                    .clone()
                                    .unwrap_or_else(|| local.clone()),
                            );
                        }
                        ImportKind::Namespace | ImportKind::CommonJsRequire | ImportKind::Glob => {
                            namespace_locals.insert(local.clone());
                        }
                        // Default imports need the target module's default-export name.
                        ImportKind::Default => {}
                    }
                }
                let same_file: HashSet<String> = analyzer
                    .declarations(file)
                    .map(|unit| unit.identifier().to_string())
                    .collect();

                let mut ctx = TsScan {
                    source,
                    receiver_provider: JsTsReceiverFactProvider::new(
                        analyzer,
                        analyzer.definition_lookup_index(),
                        language,
                        file,
                        source,
                        parsed.tree.root_node(),
                        binder.clone(),
                    ),
                    named_imports,
                    namespace_locals,
                    same_file,
                    nodes,
                    collector,
                };
                let mut locals = LocalInferenceEngine::new(LocalInferenceConfig::default());
                scan_node(parsed.tree.root_node(), &mut ctx, &mut locals);
            },
        )
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum JsTsScopedNodeStatus {
    Resolved,
    Ambiguous,
    Unseedable,
}

pub(crate) struct JsTsScopedUsageEdges {
    pub(crate) edges: UsageEdgeWeights<UsageNodeKey>,
    pub(crate) node_status: BTreeMap<UsageNodeKey, JsTsScopedNodeStatus>,
}

pub(super) fn build_jsts_scoped_edges<F>(
    analyzer: &dyn IAnalyzer,
    index: &JsTsUsageIndex,
    language: Language,
    nodes: &HashSet<UsageNodeKey>,
    keep_file: F,
) -> JsTsScopedUsageEdges
where
    F: Fn(&ProjectFile) -> bool + Sync,
{
    if tree_sitter_language_for(language).is_none() {
        return JsTsScopedUsageEdges {
            edges: UsageEdgeWeights::default(),
            node_status: BTreeMap::new(),
        };
    }
    let files = collect_jsts_files(analyzer, language);
    let declarations = scoped_declarations_by_file_and_name(analyzer, language);
    let node_status = scoped_node_status(index, nodes, &declarations);
    let imports_by_file = scoped_import_bindings_by_file(index, &declarations);
    let edges = build_edge_weights(&files, keep_file, |file| {
        // Parse on demand and drop the tree when this closure returns; cross-file
        // resolution comes from the analyzer-cached `index`, not retained trees.
        let parser_language = js_ts_tree_sitter_language_for_file(file, language)?;
        let parsed = parse_tree_sitter_file(file, &parser_language)?;
        let imports = imports_by_file.get(file).cloned().unwrap_or_default();
        let same_file = scoped_same_file_declarations(analyzer, file, language);
        Some(collect_file_edges(
            analyzer,
            file,
            nodes,
            &parsed.line_starts,
            |collector| {
                let mut ctx = ScopedTsScan {
                    source: parsed.source.as_str(),
                    receiver_provider: JsTsReceiverFactProvider::new(
                        analyzer,
                        analyzer.definition_lookup_index(),
                        language,
                        file,
                        parsed.source.as_str(),
                        parsed.tree.root_node(),
                        compute_import_binder(parsed.source.as_str(), &parsed.tree),
                    ),
                    index,
                    declarations: &declarations,
                    imports,
                    same_file,
                    collector,
                };
                let mut locals = LocalInferenceEngine::new(LocalInferenceConfig::default());
                scan_scoped_node(parsed.tree.root_node(), &mut ctx, &mut locals);
            },
        ))
    });
    JsTsScopedUsageEdges { edges, node_status }
}

#[derive(Clone, Default)]
struct ScopedImportBindings {
    named: HashMap<String, UsageNodeKey>,
    namespace: HashMap<String, ProjectFile>,
}

struct ScopedTsScan<'a, 'b> {
    source: &'a str,
    receiver_provider: JsTsReceiverFactProvider<'a, 'a>,
    index: &'a JsTsUsageIndex,
    declarations: &'a HashMap<(ProjectFile, String), BTreeSet<UsageNodeKey>>,
    imports: ScopedImportBindings,
    same_file: HashMap<String, UsageNodeKey>,
    collector: &'a mut EdgeCollector<'b, UsageNodeKey>,
}

impl<'a> ScopedTsScan<'a, '_> {
    fn bare_callee(&self, text: &str) -> Option<UsageNodeKey> {
        if let Some(key) = self.imports.named.get(text) {
            return Some(key.clone());
        }
        if let Some(key) = self.same_file.get(text) {
            return Some(key.clone());
        }
        None
    }

    fn namespace_member_callee(&self, namespace: &str, member: &str) -> Option<UsageNodeKey> {
        let target_file = self.imports.namespace.get(namespace)?;
        single_key(canonical_export_keys(
            self.index,
            self.declarations,
            target_file,
            member,
        ))
    }

    fn scoped_member_declaration_keys(
        &self,
        owner: &UsageNodeKey,
        member: &str,
    ) -> Vec<UsageNodeKey> {
        let static_key = UsageNodeKey::new(
            owner.file.clone(),
            format!("{}.{}$static", owner.fqn, member),
        );
        if self
            .declarations
            .get(&(owner.file.clone(), format!("{member}$static")))
            .is_some_and(|keys| keys.contains(&static_key))
        {
            return vec![static_key];
        }

        let plain_key = UsageNodeKey::new(owner.file.clone(), format!("{}.{}", owner.fqn, member));
        if self
            .declarations
            .get(&(owner.file.clone(), member.to_string()))
            .is_some_and(|keys| keys.contains(&plain_key))
        {
            return vec![plain_key];
        }

        Vec::new()
    }

    fn record(&mut self, callee: UsageNodeKey, node: Node<'_>) {
        self.collector
            .record(callee, node.start_byte(), node.end_byte());
    }
}

struct TsScan<'a, 'b> {
    source: &'a str,
    receiver_provider: JsTsReceiverFactProvider<'a, 'a>,
    named_imports: HashMap<String, String>,
    namespace_locals: HashSet<String>,
    same_file: HashSet<String>,
    nodes: &'a HashSet<String>,
    collector: &'a mut EdgeCollector<'b>,
}

impl TsScan<'_, '_> {
    fn member_declaration_keys(&self, owner: &str, member: &str) -> Vec<String> {
        let static_key = format!("{owner}.{member}$static");
        if self.nodes.contains(&static_key) {
            return vec![static_key];
        }

        let plain_key = format!("{owner}.{member}");
        if self.nodes.contains(&plain_key) {
            return vec![plain_key];
        }

        Vec::new()
    }
}

fn scoped_declarations_by_file_and_name(
    analyzer: &dyn IAnalyzer,
    language: Language,
) -> HashMap<(ProjectFile, String), BTreeSet<UsageNodeKey>> {
    let mut out: HashMap<(ProjectFile, String), BTreeSet<UsageNodeKey>> = HashMap::default();
    for declaration in analyzer
        .all_declarations()
        .filter(|unit| crate::analyzer::common::language_for_file(unit.source()) == language)
    {
        out.entry((
            declaration.source().clone(),
            declaration.identifier().to_string(),
        ))
        .or_default()
        .insert(UsageNodeKey::new(
            declaration.source().clone(),
            declaration.fq_name(),
        ));
    }
    out
}

fn scoped_same_file_declarations(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    language: Language,
) -> HashMap<String, UsageNodeKey> {
    let mut grouped: HashMap<String, BTreeSet<UsageNodeKey>> = HashMap::default();
    for declaration in analyzer
        .declarations(file)
        .filter(|unit| crate::analyzer::common::language_for_file(unit.source()) == language)
    {
        let key = UsageNodeKey::new(declaration.source().clone(), declaration.fq_name());
        grouped
            .entry(declaration.identifier().to_string())
            .or_default()
            .insert(key);
    }
    grouped
        .into_iter()
        .filter_map(|(name, keys)| single_key(keys).map(|key| (name, key)))
        .collect()
}

fn scoped_import_bindings_by_file(
    index: &JsTsUsageIndex,
    declarations: &HashMap<(ProjectFile, String), BTreeSet<UsageNodeKey>>,
) -> HashMap<ProjectFile, ScopedImportBindings> {
    let mut grouped_named: HashMap<ProjectFile, HashMap<String, BTreeSet<UsageNodeKey>>> =
        HashMap::default();
    let mut grouped_namespace: HashMap<ProjectFile, HashMap<String, BTreeSet<ProjectFile>>> =
        HashMap::default();
    for edges in index.importer_reverse.values() {
        for edge in edges {
            match &edge.kind {
                crate::analyzer::usages::ImportEdgeKind::Named(name) => {
                    let keys = canonical_export_keys(index, declarations, &edge.target_file, name);
                    grouped_named
                        .entry(edge.importer.clone())
                        .or_default()
                        .entry(edge.local_name.clone())
                        .or_default()
                        .extend(keys);
                }
                crate::analyzer::usages::ImportEdgeKind::Default => {
                    let keys =
                        canonical_export_keys(index, declarations, &edge.target_file, "default");
                    grouped_named
                        .entry(edge.importer.clone())
                        .or_default()
                        .entry(edge.local_name.clone())
                        .or_default()
                        .extend(keys);
                }
                crate::analyzer::usages::ImportEdgeKind::Namespace
                | crate::analyzer::usages::ImportEdgeKind::CommonJsRequire(_) => {
                    grouped_namespace
                        .entry(edge.importer.clone())
                        .or_default()
                        .entry(edge.local_name.clone())
                        .or_default()
                        .insert(edge.target_file.clone());
                }
            }
        }
    }

    let mut out: HashMap<ProjectFile, ScopedImportBindings> = HashMap::default();
    for (file, named) in grouped_named {
        out.entry(file).or_default().named = named
            .into_iter()
            .filter_map(|(name, keys)| single_key(keys).map(|key| (name, key)))
            .collect();
    }
    for (file, namespace) in grouped_namespace {
        out.entry(file).or_default().namespace = namespace
            .into_iter()
            .filter_map(|(name, files)| single_project_file(files).map(|file| (name, file)))
            .collect();
    }
    out
}

fn scoped_node_status(
    index: &JsTsUsageIndex,
    nodes: &HashSet<UsageNodeKey>,
    declarations: &HashMap<(ProjectFile, String), BTreeSet<UsageNodeKey>>,
) -> BTreeMap<UsageNodeKey, JsTsScopedNodeStatus> {
    nodes
        .iter()
        .map(|node| {
            let seed_names = export_seed_names_for_node(declarations, node);
            let mut keys = BTreeSet::new();
            let mut ambiguous = false;
            for seed_name in &seed_names {
                keys.extend(canonical_export_keys(
                    index,
                    declarations,
                    &node.file,
                    seed_name,
                ));
                ambiguous |= ambiguous_alias_for_node(index, declarations, node, seed_name);
            }
            let status = if keys.is_empty() {
                JsTsScopedNodeStatus::Unseedable
            } else if ambiguous {
                JsTsScopedNodeStatus::Ambiguous
            } else if keys
                .iter()
                .any(|key| key == node || node.fqn.starts_with(&format!("{}.", key.fqn)))
            {
                JsTsScopedNodeStatus::Resolved
            } else {
                JsTsScopedNodeStatus::Ambiguous
            };
            (node.clone(), status)
        })
        .collect()
}

fn export_seed_names_for_node(
    declarations: &HashMap<(ProjectFile, String), BTreeSet<UsageNodeKey>>,
    node: &UsageNodeKey,
) -> BTreeSet<String> {
    let mut best_len = usize::MAX;
    let mut out = BTreeSet::new();
    for ((file, identifier), keys) in declarations {
        if file != &node.file {
            continue;
        }
        if keys
            .iter()
            .any(|key| node.fqn == key.fqn || node.fqn.starts_with(&format!("{}.", key.fqn)))
        {
            let len = keys
                .iter()
                .map(|key| key.fqn.len())
                .min()
                .unwrap_or(usize::MAX);
            if len < best_len {
                best_len = len;
                out.clear();
            }
            if len == best_len {
                out.insert(identifier.clone());
            }
        }
    }

    if out.is_empty() {
        out.insert(top_level_name(&node.fqn));
    }
    out
}

fn ambiguous_alias_for_node(
    index: &JsTsUsageIndex,
    declarations: &HashMap<(ProjectFile, String), BTreeSet<UsageNodeKey>>,
    node: &UsageNodeKey,
    export_name: &str,
) -> bool {
    let direct_key = (node.file.clone(), export_name.to_string());
    if let Some(aliases) = index.reexport_edges.get(&direct_key) {
        for (alias_file, alias_name) in aliases {
            let keys = canonical_export_keys(index, declarations, alias_file, alias_name);
            if keys.len() > 1 {
                return true;
            }
        }
    }
    if let Some(star_files) = index.star_reexports.get(&node.file) {
        for star_file in star_files {
            let keys = canonical_export_keys(index, declarations, star_file, export_name);
            if keys.len() > 1 {
                return true;
            }
        }
    }
    false
}

fn canonical_export_keys(
    index: &JsTsUsageIndex,
    declarations: &HashMap<(ProjectFile, String), BTreeSet<UsageNodeKey>>,
    file: &ProjectFile,
    export_name: &str,
) -> BTreeSet<UsageNodeKey> {
    canonical_export_keys_inner(index, declarations, file, export_name, &mut BTreeSet::new())
}

fn canonical_export_keys_inner(
    index: &JsTsUsageIndex,
    declarations: &HashMap<(ProjectFile, String), BTreeSet<UsageNodeKey>>,
    file: &ProjectFile,
    export_name: &str,
    seen: &mut BTreeSet<(ProjectFile, String)>,
) -> BTreeSet<UsageNodeKey> {
    let current = (file.clone(), export_name.to_string());
    if !seen.insert(current.clone()) {
        return BTreeSet::new();
    }

    if let Some(exports) = index.exports_by_file.get(file)
        && let Some(entry) = exports.exports_by_name.get(export_name)
    {
        match entry {
            ExportEntry::Local { local_name } => {
                if let Some(keys) = declarations.get(&(file.clone(), local_name.clone())) {
                    return keys.clone();
                }
            }
            ExportEntry::Default {
                local_name: Some(local_name),
            } => {
                if let Some(keys) = declarations.get(&(file.clone(), local_name.clone())) {
                    return keys.clone();
                }
            }
            ExportEntry::Default { local_name: None } => return BTreeSet::new(),
            ExportEntry::ReexportedNamed { .. } => {}
        }
    }

    let mut out = BTreeSet::new();
    if let Some(targets) = index.direct_reexport_edges.get(&current) {
        for (target_file, target_name) in targets {
            out.extend(canonical_export_keys_inner(
                index,
                declarations,
                target_file,
                target_name,
                seen,
            ));
        }
    }
    if out.is_empty()
        && let Some(target_files) = index.direct_star_reexports.get(file)
    {
        for target_file in target_files {
            out.extend(canonical_export_keys_inner(
                index,
                declarations,
                target_file,
                export_name,
                seen,
            ));
        }
    }
    out
}

fn single_key(keys: BTreeSet<UsageNodeKey>) -> Option<UsageNodeKey> {
    let mut iter = keys.into_iter();
    let first = iter.next()?;
    iter.next().is_none().then_some(first)
}

fn single_project_file(files: BTreeSet<ProjectFile>) -> Option<ProjectFile> {
    let mut iter = files.into_iter();
    let first = iter.next()?;
    iter.next().is_none().then_some(first)
}

fn top_level_name(fqn: &str) -> String {
    fqn.split('.').next().unwrap_or(fqn).to_string()
}

impl TsScan<'_, '_> {
    /// The callee fqn a bare name refers to: a named import's exported name, or a
    /// same-file declaration's own name. `None` when the name is neither.
    fn bare_callee(&self, text: &str) -> Option<String> {
        if let Some(exported) = self.named_imports.get(text) {
            return Some(exported.clone());
        }
        if self.same_file.contains(text) {
            return Some(text.to_string());
        }
        None
    }

    fn record(&mut self, callee: String, node: Node<'_>) {
        self.collector
            .record(callee, node.start_byte(), node.end_byte());
    }
}

fn scan_node(node: Node<'_>, ctx: &mut TsScan<'_, '_>, locals: &mut LocalInferenceEngine<String>) {
    let mut state = (ctx, locals);
    walk_tree_iterative(
        node,
        &mut state,
        |node, (ctx, locals)| match scan_node_enter(node, ctx, locals) {
            Some(true) => TreeWalkAction::DescendWithExit,
            Some(false) => TreeWalkAction::Descend,
            None => TreeWalkAction::Skip,
        },
        |(_, locals)| locals.exit_scope(),
    );
}

fn scan_node_enter(
    node: Node<'_>,
    ctx: &mut TsScan<'_, '_>,
    locals: &mut LocalInferenceEngine<String>,
) -> Option<bool> {
    let kind = node.kind();
    let introduces_scope = introduces_js_ts_scope(kind);
    if introduces_scope {
        locals.enter_scope();
        if let Some(parameters) = node.child_by_field_name("parameters") {
            declare_pattern_shadows(parameters, ctx.source, locals);
        }
    }

    // Bindings declared in import/export clauses are not usages.
    if matches!(
        kind,
        "import_statement"
            | "import_clause"
            | "import_specifier"
            | "namespace_import"
            | "export_clause"
            | "export_specifier"
    ) {
        if introduces_scope {
            locals.exit_scope();
        }
        return None;
    }

    if kind == "variable_declarator"
        && let Some(name) = node.child_by_field_name("name")
    {
        declare_pattern_shadows(name, ctx.source, locals);
    }

    match kind {
        "identifier" | "type_identifier" | "shorthand_property_identifier" => {
            handle_identifier(node, ctx, locals)
        }
        "property_identifier" | "pair" => handle_contextual_object_key(node, ctx),
        "object" => handle_contextual_object_literal(node, ctx),
        "member_expression" => handle_member(node, ctx, locals),
        "jsx_opening_element" | "jsx_self_closing_element" => handle_jsx(node, ctx, locals),
        _ => {}
    }
    Some(introduces_scope)
}

fn scan_scoped_node(
    node: Node<'_>,
    ctx: &mut ScopedTsScan<'_, '_>,
    locals: &mut LocalInferenceEngine<String>,
) {
    let mut state = (ctx, locals);
    walk_tree_iterative(
        node,
        &mut state,
        |node, (ctx, locals)| match scan_scoped_node_enter(node, ctx, locals) {
            Some(true) => TreeWalkAction::DescendWithExit,
            Some(false) => TreeWalkAction::Descend,
            None => TreeWalkAction::Skip,
        },
        |(_, locals)| locals.exit_scope(),
    );
}

fn scan_scoped_node_enter(
    node: Node<'_>,
    ctx: &mut ScopedTsScan<'_, '_>,
    locals: &mut LocalInferenceEngine<String>,
) -> Option<bool> {
    let kind = node.kind();
    let introduces_scope = introduces_js_ts_scope(kind);
    if introduces_scope {
        locals.enter_scope();
        if let Some(parameters) = node.child_by_field_name("parameters") {
            declare_pattern_shadows(parameters, ctx.source, locals);
        }
    }

    if matches!(
        kind,
        "import_statement"
            | "import_clause"
            | "import_specifier"
            | "namespace_import"
            | "export_clause"
            | "export_specifier"
    ) {
        if introduces_scope {
            locals.exit_scope();
        }
        return None;
    }

    if kind == "variable_declarator"
        && let Some(name) = node.child_by_field_name("name")
    {
        declare_pattern_shadows(name, ctx.source, locals);
    }

    match kind {
        "identifier" | "type_identifier" | "shorthand_property_identifier" => {
            handle_scoped_identifier(node, ctx, locals)
        }
        "property_identifier" | "pair" => handle_scoped_contextual_object_key(node, ctx),
        "object" => handle_scoped_contextual_object_literal(node, ctx),
        "member_expression" => handle_scoped_member(node, ctx, locals),
        "jsx_opening_element" | "jsx_self_closing_element" => handle_scoped_jsx(node, ctx, locals),
        _ => {}
    }
    Some(introduces_scope)
}

fn introduces_js_ts_scope(kind: &str) -> bool {
    matches!(
        kind,
        "statement_block"
            | "arrow_function"
            | "function_expression"
            | "generator_function"
            | "function_declaration"
            | "method_definition"
    )
}

/// Declare every identifier bound by a parameter / declaration pattern as a local
/// shadow, so later references to those names are not mistaken for imports.
fn declare_pattern_shadows(
    node: Node<'_>,
    source: &str,
    locals: &mut LocalInferenceEngine<String>,
) {
    let mut stack = vec![node];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "identifier" | "shorthand_property_identifier_pattern" => {
                let text = slice(node, source);
                if !text.is_empty() {
                    locals.declare_shadow(text.to_string());
                }
            }
            _ => {
                for index in (0..node.named_child_count()).rev() {
                    if let Some(child) = node.named_child(index) {
                        stack.push(child);
                    }
                }
            }
        }
    }
}

fn handle_identifier(
    node: Node<'_>,
    ctx: &mut TsScan<'_, '_>,
    locals: &LocalInferenceEngine<String>,
) {
    let text = slice(node, ctx.source);
    if text.is_empty() || locals.is_shadowed(text) {
        return;
    }
    if is_declaration_identifier(node)
        || is_property_key_in_member(node)
        || is_object_in_member_expression(node)
    {
        return;
    }
    if let Some(callee) = ctx.bare_callee(text) {
        ctx.record(callee, node);
    }
}

fn handle_scoped_identifier(
    node: Node<'_>,
    ctx: &mut ScopedTsScan<'_, '_>,
    locals: &LocalInferenceEngine<String>,
) {
    let text = slice(node, ctx.source);
    if text.is_empty() || locals.is_shadowed(text) {
        return;
    }
    if is_declaration_identifier(node)
        || is_property_key_in_member(node)
        || is_object_in_member_expression(node)
    {
        return;
    }
    if let Some(callee) = ctx.bare_callee(text) {
        ctx.record(callee, node);
    }
}

fn handle_member(node: Node<'_>, ctx: &mut TsScan<'_, '_>, locals: &LocalInferenceEngine<String>) {
    let (Some(object), Some(property)) = (
        node.child_by_field_name("object"),
        node.child_by_field_name("property"),
    ) else {
        return;
    };
    let object_text = slice(object, ctx.source);
    let property_text = slice(property, ctx.source);
    if property_text.is_empty() {
        return;
    }

    if (object.kind() != "identifier" || locals.is_shadowed(object_text))
        && record_receiver_member(node, object, property, property_text, ctx)
    {
        return;
    }

    if object.kind() != "identifier" {
        return;
    }
    if object_text.is_empty() || locals.is_shadowed(object_text) {
        return;
    }

    // `ns.member` — namespace import access resolves to the exported member.
    if ctx.namespace_locals.contains(object_text) {
        ctx.record(property_text.to_string(), property);
        return;
    }
    // `Class.member` — static access on an imported / same-file class resolves to
    // the member's `Owner.member` fqn.
    if let Some(class) = ctx.bare_callee(object_text) {
        for member in ctx.member_declaration_keys(&class, property_text) {
            ctx.record(member, property);
        }
    }
}

fn handle_contextual_object_key(node: Node<'_>, ctx: &mut TsScan<'_, '_>) {
    for target in ctx
        .receiver_provider
        .resolve_contextual_object_literal_key_targets(node, ReceiverAnalysisBudget::default())
    {
        ctx.record(target.fq_name(), node);
    }
}

fn handle_contextual_object_literal(node: Node<'_>, ctx: &mut TsScan<'_, '_>) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        handle_contextual_object_key(child, ctx);
    }
}

fn handle_scoped_member(
    node: Node<'_>,
    ctx: &mut ScopedTsScan<'_, '_>,
    locals: &LocalInferenceEngine<String>,
) {
    let (Some(object), Some(property)) = (
        node.child_by_field_name("object"),
        node.child_by_field_name("property"),
    ) else {
        return;
    };
    let property_text = slice(property, ctx.source);
    if property_text.is_empty() {
        return;
    }

    if object.kind() != "identifier"
        && record_scoped_receiver_member(node, object, property, property_text, ctx)
    {
        return;
    }

    if object.kind() == "identifier" {
        let object_text = slice(object, ctx.source);
        if object_text.is_empty() {
            return;
        }

        if locals.is_shadowed(object_text) {
            record_scoped_receiver_member(node, object, property, property_text, ctx);
            return;
        }

        if let Some(callee) = ctx.namespace_member_callee(object_text, property_text) {
            ctx.record(callee, property);
            return;
        }
        if let Some(class) = ctx.bare_callee(object_text) {
            for member in ctx.scoped_member_declaration_keys(&class, property_text) {
                ctx.record(member, property);
            }
        }
        return;
    }

    if object.kind() == "member_expression"
        && let Some(class) = scoped_namespace_member_class(object, ctx, locals)
    {
        for member in ctx.scoped_member_declaration_keys(&class, property_text) {
            ctx.record(member, property);
        }
    }
}

fn handle_scoped_contextual_object_key(node: Node<'_>, ctx: &mut ScopedTsScan<'_, '_>) {
    for target in ctx
        .receiver_provider
        .resolve_contextual_object_literal_key_targets(node, ReceiverAnalysisBudget::default())
    {
        ctx.record(
            UsageNodeKey::new(target.source().clone(), target.fq_name()),
            node,
        );
    }
}

fn handle_scoped_contextual_object_literal(node: Node<'_>, ctx: &mut ScopedTsScan<'_, '_>) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        handle_scoped_contextual_object_key(child, ctx);
    }
}

fn record_receiver_member(
    node: Node<'_>,
    object: Node<'_>,
    property: Node<'_>,
    property_text: &str,
    ctx: &mut TsScan<'_, '_>,
) -> bool {
    if object.kind() == "this" {
        return true;
    }
    match ctx.receiver_provider.resolve_member_targets(
        object,
        property_text,
        node.start_byte(),
        ReceiverAnalysisBudget::default(),
    ) {
        ReceiverAnalysisOutcome::Precise(targets) => {
            for target in targets {
                ctx.record(target.fq_name(), property);
            }
            true
        }
        ReceiverAnalysisOutcome::Ambiguous(_)
        | ReceiverAnalysisOutcome::Unsupported { .. }
        | ReceiverAnalysisOutcome::ExceededBudget { .. } => true,
        ReceiverAnalysisOutcome::Unknown => false,
    }
}

fn record_scoped_receiver_member(
    node: Node<'_>,
    object: Node<'_>,
    property: Node<'_>,
    property_text: &str,
    ctx: &mut ScopedTsScan<'_, '_>,
) -> bool {
    if object.kind() == "this" {
        return true;
    }
    match ctx.receiver_provider.resolve_member_targets(
        object,
        property_text,
        node.start_byte(),
        ReceiverAnalysisBudget::default(),
    ) {
        ReceiverAnalysisOutcome::Precise(targets) => {
            for target in targets {
                ctx.record(
                    UsageNodeKey::new(target.source().clone(), target.fq_name()),
                    property,
                );
            }
            true
        }
        ReceiverAnalysisOutcome::Ambiguous(targets) => {
            for target in targets {
                ctx.collector.record_unproven(
                    UsageNodeKey::new(target.source().clone(), target.fq_name()),
                    property.start_byte(),
                    property.end_byte(),
                );
            }
            true
        }
        ReceiverAnalysisOutcome::Unsupported { .. }
        | ReceiverAnalysisOutcome::ExceededBudget { .. } => {
            ctx.collector.record_unproven_name(
                property_text,
                property.start_byte(),
                property.end_byte(),
            );
            true
        }
        ReceiverAnalysisOutcome::Unknown => {
            ctx.collector.record_unproven_name(
                property_text,
                property.start_byte(),
                property.end_byte(),
            );
            false
        }
    }
}

fn scoped_namespace_member_class(
    node: Node<'_>,
    ctx: &ScopedTsScan<'_, '_>,
    locals: &LocalInferenceEngine<String>,
) -> Option<UsageNodeKey> {
    let object = node.child_by_field_name("object")?;
    let property = node.child_by_field_name("property")?;
    if object.kind() != "identifier" {
        return None;
    }
    let namespace = slice(object, ctx.source);
    if namespace.is_empty() || locals.is_shadowed(namespace) {
        return None;
    }
    let class_name = slice(property, ctx.source);
    if class_name.is_empty() {
        return None;
    }
    ctx.namespace_member_callee(namespace, class_name)
}

fn handle_jsx(node: Node<'_>, ctx: &mut TsScan<'_, '_>, locals: &LocalInferenceEngine<String>) {
    let Some(name_node) = node.child_by_field_name("name") else {
        return;
    };
    let Some((rightmost, leaf_text)) = rightmost_jsx_identifier(name_node, ctx.source) else {
        return;
    };
    if leaf_text.is_empty() || locals.is_shadowed(leaf_text) {
        return;
    }
    if let Some(callee) = ctx.bare_callee(leaf_text) {
        ctx.record(callee, rightmost);
    }
}

fn handle_scoped_jsx(
    node: Node<'_>,
    ctx: &mut ScopedTsScan<'_, '_>,
    locals: &LocalInferenceEngine<String>,
) {
    let Some(name_node) = node.child_by_field_name("name") else {
        return;
    };
    let Some((rightmost, leaf_text)) = rightmost_jsx_identifier(name_node, ctx.source) else {
        return;
    };
    if leaf_text.is_empty() || locals.is_shadowed(leaf_text) {
        return;
    }
    if let Some(callee) = ctx.bare_callee(leaf_text) {
        ctx.record(callee, rightmost);
    }
}
