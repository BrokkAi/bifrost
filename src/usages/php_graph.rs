use crate::analyzer::{
    AnalyzerDelegate, CodeUnit, IAnalyzer, Language, MultiAnalyzer, PhpAnalyzer, ProjectFile,
    Range, parse_php_use_aliases, php_namespace_to_fq,
};
use crate::hash::{HashMap, HashSet};
use crate::text_utils::{compute_line_starts, find_line_index_for_offset};
use crate::usages::model::{FuzzyResult, UsageHit};
use crate::usages::traits::UsageAnalyzer;
use regex::Regex;
use std::collections::BTreeSet;
use std::sync::LazyLock;
use tree_sitter::{Node, Parser};

const GRAPH_HIT_CONFIDENCE: f64 = 1.0;
const SNIPPET_CONTEXT_LINES: usize = 3;

#[derive(Default)]
pub struct PhpUsageGraphStrategy {
    _private: (),
}

impl PhpUsageGraphStrategy {
    pub fn new() -> Self {
        Self { _private: () }
    }

    pub fn can_handle(target: &CodeUnit) -> bool {
        target_language(target) == Language::Php
    }
}

impl UsageAnalyzer for PhpUsageGraphStrategy {
    fn find_usages(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        candidate_files: &HashSet<ProjectFile>,
        max_usages: usize,
    ) -> FuzzyResult {
        if overloads.is_empty() {
            return FuzzyResult::empty_success();
        }

        let target = &overloads[0];
        if target_language(target) != Language::Php {
            return FuzzyResult::Failure {
                fq_name: target.fq_name(),
                reason: "PhpUsageGraphStrategy: target is not PHP".to_string(),
            };
        }

        let Some(php) = resolve_php_analyzer(analyzer) else {
            return FuzzyResult::Failure {
                fq_name: target.fq_name(),
                reason: "PhpUsageGraphStrategy: analyzer does not expose PhpAnalyzer".to_string(),
            };
        };

        let Some(spec) = TargetSpec::from_target(php, target) else {
            return FuzzyResult::Failure {
                fq_name: target.fq_name(),
                reason: "PhpUsageGraphStrategy: unsupported target shape".to_string(),
            };
        };

        let files: HashSet<ProjectFile> = candidate_files
            .iter()
            .filter(|file| target_language_for_file(file) == Language::Php)
            .cloned()
            .chain(std::iter::once(target.source().clone()))
            .collect();

        let mut hits = BTreeSet::new();
        let hierarchy = PhpHierarchyIndex::build(php);
        for file in files {
            scan_file(php, analyzer, &file, &spec, &hierarchy, &mut hits);
            if hits.len() > max_usages {
                return FuzzyResult::TooManyCallsites {
                    short_name: target.short_name().to_string(),
                    total_callsites: hits.len(),
                    limit: max_usages,
                };
            }
        }

        FuzzyResult::success(target.clone(), hits)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum TargetKind {
    Type,
    Constructor,
    Method,
    Field,
    Constant,
    Function,
}

struct TargetSpec {
    target: CodeUnit,
    kind: TargetKind,
    owner_fq_name: Option<String>,
    target_fq_name: String,
    member_name: String,
}

impl TargetSpec {
    fn from_target(php: &PhpAnalyzer, target: &CodeUnit) -> Option<Self> {
        if target.is_class() {
            return Some(Self {
                target: target.clone(),
                kind: TargetKind::Type,
                owner_fq_name: None,
                target_fq_name: target.fq_name(),
                member_name: target.identifier().to_string(),
            });
        }

        let parent = php.parent_of(target);
        let kind = if target.is_function() {
            if parent.is_some() && target.identifier() == "__construct" {
                TargetKind::Constructor
            } else if parent.is_some() {
                TargetKind::Method
            } else {
                TargetKind::Function
            }
        } else if target.is_field() {
            if parent.is_some() {
                TargetKind::Field
            } else {
                TargetKind::Constant
            }
        } else {
            return None;
        };

        Some(Self {
            target: target.clone(),
            kind,
            owner_fq_name: parent.map(|owner| owner.fq_name()),
            target_fq_name: target.fq_name(),
            member_name: target.identifier().to_string(),
        })
    }
}

fn resolve_php_analyzer(analyzer: &dyn IAnalyzer) -> Option<&PhpAnalyzer> {
    if let Some(php) = (analyzer as &dyn std::any::Any).downcast_ref::<PhpAnalyzer>() {
        return Some(php);
    }

    let multi = (analyzer as &dyn std::any::Any).downcast_ref::<MultiAnalyzer>()?;
    match multi.delegates().get(&Language::Php) {
        Some(AnalyzerDelegate::Php(php)) => Some(php),
        _ => None,
    }
}

fn target_language(target: &CodeUnit) -> Language {
    target_language_for_file(target.source())
}

fn target_language_for_file(file: &ProjectFile) -> Language {
    file.rel_path()
        .extension()
        .and_then(|ext| ext.to_str())
        .map(Language::from_extension)
        .unwrap_or(Language::None)
}

struct FileContext {
    namespace: String,
    aliases: HashMap<String, String>,
}

fn scan_file(
    php: &PhpAnalyzer,
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    spec: &TargetSpec,
    hierarchy: &PhpHierarchyIndex,
    hits: &mut BTreeSet<UsageHit>,
) {
    let Ok(source) = file.read_to_string() else {
        return;
    };
    if source.is_empty() {
        return;
    }

    let mut parser = Parser::new();
    if parser
        .set_language(&tree_sitter_php::LANGUAGE_PHP.into())
        .is_err()
    {
        return;
    }
    let Some(tree) = parser.parse(source.as_str(), None) else {
        return;
    };

    let mut ctx = FileContext {
        namespace: php.namespace_of_file(file),
        aliases: php.use_aliases_of(file),
    };
    ctx.aliases.extend(source_use_aliases(&source));

    let line_starts = compute_line_starts(&source);
    scan_node(
        tree.root_node(),
        analyzer,
        file,
        &source,
        &line_starts,
        &ctx,
        spec,
        hits,
    );
    scan_member_patterns(
        tree.root_node(),
        analyzer,
        file,
        &source,
        &line_starts,
        &ctx,
        hierarchy,
        spec,
        hits,
    );
    scan_resolved_text_patterns(analyzer, file, &source, &line_starts, &ctx, spec, hits);
}

fn scoped_variable_types(source: &str, ctx: &FileContext) -> HashMap<String, String> {
    let mut variables = HashMap::default();

    for captures in TYPED_VARIABLE_RE.captures_iter(source) {
        let Some(type_match) = captures.name("type") else {
            continue;
        };
        let Some(var_match) = captures.name("var") else {
            continue;
        };
        if let Some(fq) = resolve_php_type(type_match.as_str(), ctx) {
            variables.insert(var_match.as_str().to_string(), fq);
        }
    }

    for captures in PARAMETER_VARIABLE_RE.captures_iter(source) {
        let Some(type_match) = captures.name("type") else {
            continue;
        };
        let Some(var_match) = captures.name("var") else {
            continue;
        };
        if let Some(fq) = resolve_php_type(type_match.as_str(), ctx) {
            variables.insert(var_match.as_str().to_string(), fq);
        }
    }

    for captures in ASSIGNMENT_RE.captures_iter(source) {
        let Some(lhs_match) = captures.name("lhs") else {
            continue;
        };
        let Some(rhs_match) = captures.name("rhs") else {
            continue;
        };
        let lhs = lhs_match.as_str().to_string();
        let rhs = rhs_match.as_str().trim();
        if let Some(type_name) = rhs.strip_prefix("new ").and_then(read_leading_type_name) {
            if let Some(fq) = resolve_php_type(type_name, ctx) {
                variables.insert(lhs, fq);
            } else {
                variables.remove(&lhs);
            }
        } else if let Some(rhs_var) = rhs.strip_prefix('$').and_then(read_leading_variable_name) {
            if let Some(fq) = variables.get(rhs_var).cloned() {
                variables.insert(lhs, fq);
            } else {
                variables.remove(&lhs);
            }
        } else {
            variables.remove(&lhs);
        }
    }

    variables
}

static TYPED_VARIABLE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?P<type>\\?[A-Za-z_][A-Za-z0-9_\\]*(?:\|\\?[A-Za-z_][A-Za-z0-9_\\]*)?)\s+\$(?P<var>[A-Za-z_][A-Za-z0-9_]*)",
    )
    .expect("valid PHP typed-variable regex")
});

static PARAMETER_VARIABLE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"[(,]\s*(?P<type>\\?[A-Za-z_][A-Za-z0-9_\\]*(?:\|\\?[A-Za-z_][A-Za-z0-9_\\]*)?)\s+\$(?P<var>[A-Za-z_][A-Za-z0-9_]*)",
    )
    .expect("valid PHP parameter-variable regex")
});

static ASSIGNMENT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\$(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<rhs>[^;]+);")
        .expect("valid PHP assignment regex")
});

static PHP_USE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)^use\s+[^;]+;").expect("valid PHP use regex"));

fn source_use_aliases(source: &str) -> HashMap<String, String> {
    let mut aliases = HashMap::default();
    for matched in PHP_USE_RE.find_iter(source) {
        aliases.extend(parse_php_use_aliases(matched.as_str()));
    }
    aliases
}

#[allow(clippy::too_many_arguments)]
fn scan_node(
    node: Node<'_>,
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    line_starts: &[usize],
    ctx: &FileContext,
    spec: &TargetSpec,
    hits: &mut BTreeSet<UsageHit>,
) {
    if node.kind() == "namespace_use_declaration" || node.kind() == "comment" {
        return;
    }

    if matches!(node.kind(), "name" | "namespace_name" | "variable_name") {
        handle_candidate(node, analyzer, file, source, line_starts, ctx, spec, hits);
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        scan_node(child, analyzer, file, source, line_starts, ctx, spec, hits);
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_candidate(
    node: Node<'_>,
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    line_starts: &[usize],
    ctx: &FileContext,
    spec: &TargetSpec,
    hits: &mut BTreeSet<UsageHit>,
) {
    match spec.kind {
        TargetKind::Type => {
            if candidate_resolves_to_type(node, source, ctx, &spec.target_fq_name) {
                push_hit(node, analyzer, file, source, line_starts, spec, hits);
            }
        }
        TargetKind::Constructor => {
            if is_constructor_reference(node, source, ctx, spec) {
                push_hit(node, analyzer, file, source, line_starts, spec, hits);
            }
        }
        TargetKind::Method | TargetKind::Field => {}
        TargetKind::Constant => {}
        TargetKind::Function => {
            if node.kind() != "namespace_name" && is_function_reference(node, source, ctx, spec) {
                push_hit(node, analyzer, file, source, line_starts, spec, hits);
            }
        }
    }
}

fn candidate_resolves_to_type(
    node: Node<'_>,
    source: &str,
    ctx: &FileContext,
    target_fq_name: &str,
) -> bool {
    if !is_reference_context(node) {
        return false;
    }
    let raw = qualified_candidate_text(node, source);
    resolve_php_type(&raw, ctx).is_some_and(|fq| fq == target_fq_name)
}

fn is_constructor_reference(
    node: Node<'_>,
    source: &str,
    ctx: &FileContext,
    spec: &TargetSpec,
) -> bool {
    let Some(owner) = spec.owner_fq_name.as_deref() else {
        return false;
    };
    if !has_token_before(node.start_byte(), source, "new") {
        return false;
    }
    let raw = qualified_candidate_text(node, source);
    resolve_php_type(&raw, ctx).is_some_and(|fq| fq == owner)
}

fn is_function_reference(
    node: Node<'_>,
    source: &str,
    ctx: &FileContext,
    spec: &TargetSpec,
) -> bool {
    let raw = qualified_candidate_text(node, source);
    if !has_open_paren_after(node.end_byte(), source) {
        return false;
    }
    if has_operator_before(node.start_byte(), source, "->")
        || has_operator_before(node.start_byte(), source, "::")
        || has_token_before(node.start_byte(), source, "function")
    {
        return false;
    }
    resolve_php_function(&raw, ctx).is_some_and(|fq| fq == spec.target_fq_name)
}

fn is_reference_context(node: Node<'_>) -> bool {
    let mut parent = node.parent();
    while let Some(current) = parent {
        if current.kind() == "namespace_use_declaration" {
            return false;
        }
        parent = current.parent();
    }
    true
}

fn push_hit(
    node: Node<'_>,
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    line_starts: &[usize],
    spec: &TargetSpec,
    hits: &mut BTreeSet<UsageHit>,
) {
    let range = Range {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: find_line_index_for_offset(line_starts, node.start_byte()),
        end_line: find_line_index_for_offset(line_starts, node.end_byte()),
    };
    let Some(enclosing) = analyzer.enclosing_code_unit(file, &range) else {
        return;
    };
    if enclosing == spec.target {
        return;
    }
    let line_idx = range.start_line;
    hits.insert(UsageHit::new(
        file.clone(),
        line_idx + 1,
        node.start_byte(),
        node.end_byte(),
        enclosing,
        GRAPH_HIT_CONFIDENCE,
        build_snippet(source, line_starts, line_idx),
    ));
}

#[allow(clippy::too_many_arguments)]
fn push_hit_range(
    start: usize,
    end: usize,
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    line_starts: &[usize],
    spec: &TargetSpec,
    hits: &mut BTreeSet<UsageHit>,
) {
    let range = Range {
        start_byte: start,
        end_byte: end,
        start_line: find_line_index_for_offset(line_starts, start),
        end_line: find_line_index_for_offset(line_starts, end),
    };
    let Some(enclosing) = analyzer.enclosing_code_unit(file, &range) else {
        return;
    };
    if enclosing == spec.target {
        return;
    }
    hits.insert(UsageHit::new(
        file.clone(),
        range.start_line + 1,
        start,
        end,
        enclosing,
        GRAPH_HIT_CONFIDENCE,
        build_snippet(source, line_starts, range.start_line),
    ));
}

#[allow(clippy::too_many_arguments)]
fn scan_member_patterns(
    root: Node<'_>,
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    line_starts: &[usize],
    ctx: &FileContext,
    hierarchy: &PhpHierarchyIndex,
    spec: &TargetSpec,
    hits: &mut BTreeSet<UsageHit>,
) {
    if !matches!(spec.kind, TargetKind::Method | TargetKind::Field) {
        return;
    }
    let Some(owner) = spec.owner_fq_name.as_deref() else {
        return;
    };
    let escaped_member = regex::escape(&spec.member_name);
    let instance = Regex::new(&format!(
        r"\$(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s*->\s*(?P<member>{escaped_member})\b"
    ))
    .expect("valid PHP instance member regex");
    for (scope_start, scope_end) in member_scope_ranges(root) {
        let Some(scope_source) = source.get(scope_start..scope_end) else {
            continue;
        };
        let variables = scoped_variable_types(scope_source, ctx);
        for captures in instance.captures_iter(scope_source) {
            let Some(var_match) = captures.name("var") else {
                continue;
            };
            let receiver = var_match.as_str();
            let member = captures.name("member").expect("member capture");
            let member_start = scope_start + member.start();
            let member_end = scope_start + member.end();
            let receiver_matches = if receiver == "this" {
                receiver_is_enclosing_subtype(
                    analyzer,
                    file,
                    member_start,
                    member_end,
                    line_starts,
                    owner,
                    hierarchy,
                )
            } else {
                variables
                    .get(receiver)
                    .is_some_and(|fq| receiver_type_matches(fq, owner, hierarchy))
            };
            if !receiver_matches {
                continue;
            }
            push_hit_range(
                member_start,
                member_end,
                analyzer,
                file,
                source,
                line_starts,
                spec,
                hits,
            );
        }
    }

    let static_member = Regex::new(&format!(
        r"(?P<recv>\\?[A-Za-z_][A-Za-z0-9_\\]*)\s*::\s*\$?(?P<member>{escaped_member})\b"
    ))
    .expect("valid PHP static member regex");
    for captures in static_member.captures_iter(source) {
        let Some(receiver) = captures.name("recv") else {
            continue;
        };
        let member = captures.name("member").expect("member capture");
        if !static_receiver_matches(
            analyzer,
            file,
            member.start(),
            member.end(),
            line_starts,
            receiver.as_str(),
            owner,
            ctx,
            hierarchy,
        ) {
            continue;
        }
        push_hit_range(
            member.start(),
            member.end(),
            analyzer,
            file,
            source,
            line_starts,
            spec,
            hits,
        );
    }
}

fn member_scope_ranges(root: Node<'_>) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    collect_member_scope_ranges(root, &mut ranges);
    ranges.sort_unstable();

    let mut scoped = Vec::new();
    let mut cursor = 0;
    for (start, end) in ranges {
        if cursor < start {
            scoped.push((cursor, start));
        }
        scoped.push((start, end));
        cursor = cursor.max(end);
    }
    if cursor < root.end_byte() {
        scoped.push((cursor, root.end_byte()));
    }
    scoped
}

fn collect_member_scope_ranges(node: Node<'_>, ranges: &mut Vec<(usize, usize)>) {
    match node.kind() {
        "function_definition" | "method_declaration" | "anonymous_function_creation" => {
            ranges.push((node.start_byte(), node.end_byte()));
            return;
        }
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_member_scope_ranges(child, ranges);
    }
}

fn read_leading_type_name(value: &str) -> Option<&str> {
    let end = value
        .char_indices()
        .take_while(|(_, ch)| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '\\'))
        .map(|(idx, ch)| idx + ch.len_utf8())
        .last()
        .unwrap_or(0);
    (end > 0).then(|| &value[..end])
}

fn read_leading_variable_name(value: &str) -> Option<&str> {
    let end = value
        .char_indices()
        .take_while(|(_, ch)| ch.is_ascii_alphanumeric() || *ch == '_')
        .map(|(idx, ch)| idx + ch.len_utf8())
        .last()
        .unwrap_or(0);
    (end > 0).then(|| &value[..end])
}

#[derive(Default)]
struct PhpHierarchyIndex {
    ancestors: HashMap<String, HashSet<String>>,
    interfaces: HashSet<String>,
}

impl PhpHierarchyIndex {
    fn build(php: &PhpAnalyzer) -> Self {
        let mut hierarchy = Self::default();
        for file in php.analyzed_files() {
            if target_language_for_file(file) != Language::Php {
                continue;
            }
            let Ok(source) = file.read_to_string() else {
                continue;
            };
            let mut ctx = FileContext {
                namespace: php.namespace_of_file(file),
                aliases: php.use_aliases_of(file),
            };
            ctx.aliases.extend(source_use_aliases(&source));
            hierarchy.extend_file(&source, &ctx);
        }
        hierarchy.close_transitively();
        hierarchy
    }

    fn extend_file(&mut self, source: &str, ctx: &FileContext) {
        for captures in TYPE_DECLARATION_RE.captures_iter(source) {
            let Some(kind) = captures.name("kind") else {
                continue;
            };
            let Some(name) = captures.name("name") else {
                continue;
            };
            let Some(type_name) = resolve_php_type(name.as_str(), ctx) else {
                continue;
            };
            if kind.as_str() == "interface" {
                self.interfaces.insert(type_name.clone());
            }
            let parents = self.ancestors.entry(type_name).or_default();
            if let Some(extends) = captures.name("extends") {
                parents.extend(resolve_type_list(extends.as_str(), ctx));
            }
            if let Some(implements) = captures.name("implements") {
                parents.extend(resolve_type_list(implements.as_str(), ctx));
            }
        }
    }

    fn close_transitively(&mut self) {
        loop {
            let snapshot = self.ancestors.clone();
            let mut changed = false;
            for parents in self.ancestors.values_mut() {
                let current: Vec<String> = parents.iter().cloned().collect();
                for parent in current {
                    if let Some(grandparents) = snapshot.get(&parent) {
                        for grandparent in grandparents {
                            changed |= parents.insert(grandparent.clone());
                        }
                    }
                }
            }
            if !changed {
                break;
            }
        }
    }
}

static TYPE_DECLARATION_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\b(?P<kind>class|interface|trait)\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)(?:\s+extends\s+(?P<extends>[^ {]+(?:\s*,\s*[^ {]+)*))?(?:\s+implements\s+(?P<implements>[^ {]+(?:\s*,\s*[^ {]+)*))?",
    )
    .expect("valid PHP type declaration regex")
});

fn resolve_type_list(raw: &str, ctx: &FileContext) -> Vec<String> {
    raw.split(',')
        .filter_map(|name| resolve_php_type(name.trim(), ctx))
        .collect()
}

fn receiver_type_matches(
    receiver_fq_name: &str,
    owner: &str,
    hierarchy: &PhpHierarchyIndex,
) -> bool {
    if receiver_fq_name == owner {
        return !hierarchy.interfaces.contains(owner);
    }
    hierarchy
        .ancestors
        .get(receiver_fq_name)
        .is_some_and(|ancestors| ancestors.contains(owner))
}

#[allow(clippy::too_many_arguments)]
fn static_receiver_matches(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    start: usize,
    end: usize,
    line_starts: &[usize],
    receiver: &str,
    owner: &str,
    ctx: &FileContext,
    hierarchy: &PhpHierarchyIndex,
) -> bool {
    match receiver {
        "self" | "static" => {
            receiver_is_enclosing_subtype(analyzer, file, start, end, line_starts, owner, hierarchy)
        }
        "parent" => enclosing_owner_at(analyzer, file, start, end, line_starts).is_some_and(
            |enclosing_owner| {
                hierarchy
                    .ancestors
                    .get(&enclosing_owner)
                    .is_some_and(|ancestors| ancestors.contains(owner))
            },
        ),
        _ => resolve_php_type(receiver, ctx)
            .is_some_and(|fq| receiver_type_matches(&fq, owner, hierarchy)),
    }
}

fn scan_resolved_text_patterns(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    line_starts: &[usize],
    ctx: &FileContext,
    spec: &TargetSpec,
    hits: &mut BTreeSet<UsageHit>,
) {
    match spec.kind {
        TargetKind::Type => {
            for alias in target_aliases(ctx, &spec.target_fq_name) {
                let pattern = Regex::new(&format!(
                    r"(^|[^A-Za-z0-9_\\$])({})([^A-Za-z0-9_\\]|$)",
                    regex::escape(&alias)
                ))
                .expect("valid PHP type alias regex");
                for captures in pattern.captures_iter(source) {
                    let matched = captures.get(2).expect("type alias capture");
                    if is_import_or_declaration_context(
                        matched.start(),
                        source,
                        &["use", "class", "interface", "trait"],
                    ) {
                        continue;
                    }
                    push_hit_range(
                        matched.start(),
                        matched.end(),
                        analyzer,
                        file,
                        source,
                        line_starts,
                        spec,
                        hits,
                    );
                }
            }
        }
        TargetKind::Constructor => {
            let Some(owner) = spec.owner_fq_name.as_deref() else {
                return;
            };
            for alias in target_aliases(ctx, owner) {
                let pattern = Regex::new(&format!(r"\bnew\s+({})\b", regex::escape(&alias)))
                    .expect("valid PHP constructor regex");
                for captures in pattern.captures_iter(source) {
                    let matched = captures.get(1).expect("constructor target capture");
                    push_hit_range(
                        matched.start(),
                        matched.end(),
                        analyzer,
                        file,
                        source,
                        line_starts,
                        spec,
                        hits,
                    );
                }
            }
        }
        TargetKind::Constant => {
            for alias in target_aliases(ctx, &spec.target_fq_name) {
                let pattern = Regex::new(&format!(
                    r"(^|[^A-Za-z0-9_\\$>:])({})([^A-Za-z0-9_\\]|$)",
                    regex::escape(&alias)
                ))
                .expect("valid PHP constant regex");
                for captures in pattern.captures_iter(source) {
                    let matched = captures.get(2).expect("constant alias capture");
                    if is_import_or_declaration_context(matched.start(), source, &["const", "use"])
                    {
                        continue;
                    }
                    push_hit_range(
                        matched.start(),
                        matched.end(),
                        analyzer,
                        file,
                        source,
                        line_starts,
                        spec,
                        hits,
                    );
                }
            }
        }
        TargetKind::Function => {
            for alias in target_aliases(ctx, &spec.target_fq_name) {
                let pattern = Regex::new(&format!(
                    r"(^|[^A-Za-z0-9_\\$>:])({})\s*\(",
                    regex::escape(&alias)
                ))
                .expect("valid PHP function regex");
                for captures in pattern.captures_iter(source) {
                    let matched = captures.get(2).expect("function alias capture");
                    if is_import_or_declaration_context(
                        matched.start(),
                        source,
                        &["function", "use"],
                    ) {
                        continue;
                    }
                    push_hit_range(
                        matched.start(),
                        matched.end(),
                        analyzer,
                        file,
                        source,
                        line_starts,
                        spec,
                        hits,
                    );
                }
            }
        }
        TargetKind::Method | TargetKind::Field => {}
    }
}

fn target_aliases(ctx: &FileContext, target_fq_name: &str) -> BTreeSet<String> {
    let mut aliases = BTreeSet::new();
    let lookup_fq_name = public_php_fq_name(target_fq_name);
    let php_path = lookup_fq_name.replace('.', "\\");
    aliases.insert(format!("\\{php_path}"));

    let short = lookup_fq_name
        .rsplit('.')
        .next()
        .unwrap_or(lookup_fq_name.as_str())
        .to_string();
    if namespace_of_fq(&lookup_fq_name) == ctx.namespace {
        aliases.insert(short);
    }
    for (alias, imported) in &ctx.aliases {
        if imported == &lookup_fq_name || imported == target_fq_name {
            aliases.insert(alias.clone());
        } else if let Some(suffix) = lookup_fq_name
            .strip_prefix(imported)
            .and_then(|suffix| suffix.strip_prefix('.'))
        {
            aliases.insert(format!("{alias}\\{}", suffix.replace('.', "\\")));
        }
    }
    aliases
}

fn public_php_fq_name(fq_name: &str) -> String {
    fq_name.replace("._module_.", ".")
}

fn receiver_is_enclosing_subtype(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    start: usize,
    end: usize,
    line_starts: &[usize],
    owner: &str,
    hierarchy: &PhpHierarchyIndex,
) -> bool {
    enclosing_owner_at(analyzer, file, start, end, line_starts)
        .is_some_and(|receiver| receiver_type_matches(&receiver, owner, hierarchy))
}

fn enclosing_owner_at(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    start: usize,
    end: usize,
    line_starts: &[usize],
) -> Option<String> {
    let range = Range {
        start_byte: start,
        end_byte: end,
        start_line: find_line_index_for_offset(line_starts, start),
        end_line: find_line_index_for_offset(line_starts, end),
    };
    analyzer
        .enclosing_code_unit(file, &range)
        .and_then(|enclosing| analyzer.parent_of(&enclosing).or(Some(enclosing)))
        .map(|enclosing_owner| enclosing_owner.fq_name())
}

fn namespace_of_fq(fq_name: &str) -> String {
    fq_name
        .rsplit_once('.')
        .map(|(namespace, _)| namespace.to_string())
        .unwrap_or_default()
}

fn is_import_or_declaration_context(start: usize, source: &str, keywords: &[&str]) -> bool {
    let line_start = source[..start].rfind('\n').map(|idx| idx + 1).unwrap_or(0);
    let before = source[line_start..start].trim_start();
    keywords
        .iter()
        .any(|keyword| before.starts_with(keyword) || before.ends_with(keyword))
}

fn qualified_candidate_text(node: Node<'_>, source: &str) -> String {
    let (start, text) = if node.kind() == "namespace_name" {
        (node.start_byte(), node_text(node, source).to_string())
    } else if let Some(parent) = node.parent()
        && parent.kind() == "namespace_name"
        && node.end_byte() == parent.end_byte()
    {
        (parent.start_byte(), node_text(parent, source).to_string())
    } else {
        (node.start_byte(), node_text(node, source).to_string())
    };
    if source.get(..start).unwrap_or_default().ends_with('\\') {
        format!("\\{text}")
    } else {
        text
    }
}

fn resolve_php_type(raw: &str, ctx: &FileContext) -> Option<String> {
    let first = raw.split('|').next().unwrap_or(raw).trim();
    if first.is_empty() || matches!(first, "self" | "static" | "parent") {
        return None;
    }
    if first.starts_with('\\') {
        return Some(php_namespace_to_fq(first));
    }
    let normalized = php_namespace_to_fq(first);
    let local = normalized.split('.').next().unwrap_or(normalized.as_str());
    if let Some(imported) = ctx.aliases.get(local) {
        if normalized == local {
            return Some(imported.clone());
        }
        let suffix = normalized
            .strip_prefix(local)
            .unwrap_or("")
            .trim_start_matches('.');
        return Some(if suffix.is_empty() {
            imported.clone()
        } else {
            format!("{imported}.{suffix}")
        });
    }
    Some(join_namespace(&ctx.namespace, &normalized))
}

fn resolve_php_function(raw: &str, ctx: &FileContext) -> Option<String> {
    if raw.starts_with('\\') {
        return Some(php_namespace_to_fq(raw));
    }
    let normalized = php_namespace_to_fq(raw);
    Some(join_namespace(&ctx.namespace, &normalized))
}

fn join_namespace(namespace: &str, name: &str) -> String {
    if namespace.is_empty() {
        name.to_string()
    } else if name.is_empty() {
        namespace.to_string()
    } else {
        format!("{namespace}.{name}")
    }
}

fn has_token_before(start: usize, source: &str, token: &str) -> bool {
    source
        .get(..start)
        .unwrap_or_default()
        .trim_end()
        .ends_with(token)
}

fn has_operator_before(start: usize, source: &str, op: &str) -> bool {
    source
        .get(..start)
        .unwrap_or_default()
        .trim_end()
        .ends_with(op)
}

fn has_open_paren_after(end: usize, source: &str) -> bool {
    source
        .get(end..)
        .unwrap_or_default()
        .trim_start()
        .starts_with('(')
}

fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    source.get(node.start_byte()..node.end_byte()).unwrap_or("")
}

fn build_snippet(source: &str, line_starts: &[usize], line_idx: usize) -> String {
    if line_starts.is_empty() {
        return String::new();
    }
    let snippet_start = line_idx.saturating_sub(SNIPPET_CONTEXT_LINES);
    let snippet_end = line_idx
        .saturating_add(SNIPPET_CONTEXT_LINES)
        .min(line_starts.len().saturating_sub(1));

    let mut snippet = String::new();
    for idx in snippet_start..=snippet_end {
        let start = line_starts[idx];
        let end = line_starts.get(idx + 1).copied().unwrap_or(source.len());
        snippet.push_str(source.get(start..end).unwrap_or_default());
    }
    snippet
}
