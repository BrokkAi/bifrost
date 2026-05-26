use crate::analyzer::common::{language_for_file, language_for_target};
use crate::analyzer::usages::common::{SNIPPET_CONTEXT_LINES, usage_hit};
use crate::analyzer::usages::local_inference::{LocalInferenceEngine, SymbolResolution};
use crate::analyzer::usages::model::{FuzzyResult, UsageHit};
use crate::analyzer::usages::outcome::{GraphFailureReason, GraphUsageOutcome};
use crate::analyzer::usages::traits::UsageAnalyzer;
use crate::analyzer::{
    AnalyzerDelegate, CodeUnit, IAnalyzer, Language, MultiAnalyzer, PhpAnalyzer, PhpUseAliases,
    ProjectFile, Range, parse_php_use_aliases_from_source, php_namespace_to_fq,
};
use crate::hash::{HashMap, HashSet};
use crate::text_utils::{compute_line_starts, find_line_index_for_offset, snippet_around_line};
use regex::Regex;
use std::collections::BTreeSet;
use std::sync::LazyLock;
use tree_sitter::{Node, Parser};

#[derive(Default)]
pub struct PhpUsageGraphStrategy {
    _private: (),
}

impl PhpUsageGraphStrategy {
    pub fn new() -> Self {
        Self { _private: () }
    }

    pub fn can_handle(target: &CodeUnit) -> bool {
        language_for_target(target) == Language::Php
    }

    pub(crate) fn find_graph_usages(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        candidate_files: &HashSet<ProjectFile>,
        max_usages: usize,
    ) -> GraphUsageOutcome {
        if overloads.is_empty() {
            return GraphUsageOutcome::Resolved(FuzzyResult::empty_success());
        }

        let target = &overloads[0];
        if language_for_target(target) != Language::Php {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::UnsupportedTargetLanguage("target is not PHP"),
                "PhpUsageGraphStrategy",
            );
        }

        let Some(php) = resolve_php_analyzer(analyzer) else {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::MissingAnalyzerCapability(
                    "analyzer does not expose PhpAnalyzer",
                ),
                "PhpUsageGraphStrategy",
            );
        };

        let Some(spec) = TargetSpec::from_target(php, target) else {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::UnsupportedTargetShape("unsupported target shape"),
                "PhpUsageGraphStrategy",
            );
        };

        let files: HashSet<ProjectFile> = candidate_files
            .iter()
            .filter(|file| language_for_file(file) == Language::Php)
            .cloned()
            .chain(std::iter::once(target.source().clone()))
            .collect();

        let hierarchy = matches!(spec.kind, TargetKind::Method | TargetKind::Field)
            .then(|| PhpHierarchyIndex::build(php, &files));
        let empty_hierarchy = PhpHierarchyIndex::default();
        let hierarchy = hierarchy.as_ref().unwrap_or(&empty_hierarchy);
        let mut hits = BTreeSet::new();
        for file in files {
            scan_file(php, analyzer, &file, &spec, hierarchy, &mut hits);
            if hits.len() > max_usages {
                return GraphUsageOutcome::Resolved(FuzzyResult::TooManyCallsites {
                    short_name: target.short_name().to_string(),
                    total_callsites: hits.len(),
                    limit: max_usages,
                });
            }
        }

        GraphUsageOutcome::Resolved(FuzzyResult::success(target.clone(), hits))
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
        self.find_graph_usages(analyzer, overloads, candidate_files, max_usages)
            .into_fuzzy_result()
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

struct FileContext {
    namespace: String,
    aliases: PhpUseAliases,
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

    let ctx = FileContext {
        namespace: php.namespace_of_file(file),
        aliases: parse_php_use_aliases_from_source(&source),
    };

    let line_starts = compute_line_starts(&source);
    if matches!(spec.kind, TargetKind::Method | TargetKind::Field) {
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
    } else {
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
    }
}

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

static INSTANCE_MEMBER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\$(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s*->\s*(?P<member>[A-Za-z_][A-Za-z0-9_]*)\b")
        .expect("valid PHP instance member regex")
});

static STATIC_MEMBER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?P<recv>\\?[A-Za-z_][A-Za-z0-9_\\]*)\s*::\s*\$?(?P<member>[A-Za-z_][A-Za-z0-9_]*)\b",
    )
    .expect("valid PHP static member regex")
});

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

    if matches!(node.kind(), "namespace_name" | "qualified_name") {
        handle_candidate(node, analyzer, file, source, line_starts, ctx, spec, hits);
        return;
    }

    if matches!(node.kind(), "name" | "variable_name") {
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
        TargetKind::Constant => {
            if node.kind() != "namespace_name" && is_constant_reference(node, source, ctx, spec) {
                push_hit(node, analyzer, file, source, line_starts, spec, hits);
            }
        }
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
    if !is_reference_context(node) {
        return false;
    }
    if !has_token_before(node.start_byte(), source, "new") {
        return false;
    }
    let raw = qualified_candidate_text(node, source);
    resolve_php_type(&raw, ctx).is_some_and(|fq| fq == owner)
}

fn is_constant_reference(
    node: Node<'_>,
    source: &str,
    ctx: &FileContext,
    spec: &TargetSpec,
) -> bool {
    if !is_reference_context(node) {
        return false;
    }
    let raw = qualified_candidate_text(node, source);
    if has_open_paren_after(node.end_byte(), source)
        || has_operator_before(node.start_byte(), source, "->")
        || has_operator_before(node.start_byte(), source, "::")
        || has_token_before(node.start_byte(), source, "const")
    {
        return false;
    }
    resolve_php_constant(&raw, ctx).is_some_and(|fq| fq == spec.target_fq_name)
}

fn is_function_reference(
    node: Node<'_>,
    source: &str,
    ctx: &FileContext,
    spec: &TargetSpec,
) -> bool {
    if !is_reference_context(node) {
        return false;
    }
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
        if matches!(
            current.kind(),
            "namespace_use_declaration"
                | "comment"
                | "string"
                | "encapsed_string"
                | "string_value"
                | "heredoc"
                | "nowdoc"
        ) {
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
    push_hit_range(
        node.start_byte(),
        node.end_byte(),
        analyzer,
        file,
        source,
        line_starts,
        spec,
        hits,
    );
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
    hits.insert(usage_hit(
        file,
        range.start_line,
        start,
        end,
        enclosing,
        snippet_around_line(source, line_starts, range.start_line, SNIPPET_CONTEXT_LINES),
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
    for (scope_start, scope_end) in member_scope_ranges(root) {
        let Some(scope_source) = source.get(scope_start..scope_end) else {
            continue;
        };
        scan_instance_members_in_order(
            scope_start,
            scope_source,
            analyzer,
            file,
            source,
            line_starts,
            ctx,
            hierarchy,
            owner,
            spec,
            hits,
        );
    }

    for captures in STATIC_MEMBER_RE.captures_iter(source) {
        let Some(receiver) = captures.name("recv") else {
            continue;
        };
        let member = captures.name("member").expect("member capture");
        if member.as_str() != spec.member_name {
            continue;
        }
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

#[allow(clippy::too_many_arguments)]
fn scan_instance_members_in_order(
    scope_start: usize,
    scope_source: &str,
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    full_source: &str,
    line_starts: &[usize],
    ctx: &FileContext,
    hierarchy: &PhpHierarchyIndex,
    owner: &str,
    spec: &TargetSpec,
    hits: &mut BTreeSet<UsageHit>,
) {
    let mut engine = LocalInferenceEngine::default();
    let header = scope_source
        .split_once('{')
        .map(|(header, _)| header)
        .unwrap_or(scope_source);
    seed_parameter_receivers(header, ctx, &mut engine);

    let mut events = Vec::new();
    for captures in ASSIGNMENT_RE.captures_iter(scope_source) {
        let Some(whole) = captures.get(0) else {
            continue;
        };
        let Some(lhs) = captures.name("lhs") else {
            continue;
        };
        let Some(rhs) = captures.name("rhs") else {
            continue;
        };
        events.push(MemberScanEvent::Assignment {
            start: whole.start(),
            lhs_start: lhs.start(),
            lhs_end: lhs.end(),
            rhs_start: rhs.start(),
            rhs_end: rhs.end(),
        });
    }
    for captures in INSTANCE_MEMBER_RE.captures_iter(scope_source) {
        let Some(whole) = captures.get(0) else {
            continue;
        };
        let Some(var) = captures.name("var") else {
            continue;
        };
        let Some(member) = captures.name("member") else {
            continue;
        };
        if member.as_str() != spec.member_name {
            continue;
        }
        events.push(MemberScanEvent::InstanceMember {
            start: whole.start(),
            receiver_start: var.start(),
            receiver_end: var.end(),
            member_start: member.start(),
            member_end: member.end(),
        });
    }
    events.sort_by_key(MemberScanEvent::start);

    for event in events {
        match event {
            MemberScanEvent::Assignment {
                lhs_start,
                lhs_end,
                rhs_start,
                rhs_end,
                ..
            } => {
                let Some(lhs) = scope_source.get(lhs_start..lhs_end) else {
                    continue;
                };
                let Some(rhs) = scope_source.get(rhs_start..rhs_end) else {
                    continue;
                };
                apply_receiver_assignment(lhs, rhs.trim(), ctx, &mut engine);
            }
            MemberScanEvent::InstanceMember {
                receiver_start,
                receiver_end,
                member_start,
                member_end,
                ..
            } => {
                let absolute_start = scope_start + member_start;
                let absolute_end = scope_start + member_end;
                let Some(receiver) = scope_source.get(receiver_start..receiver_end) else {
                    continue;
                };
                let receiver_matches = if receiver == "this" {
                    receiver_is_enclosing_subtype(
                        analyzer,
                        file,
                        absolute_start,
                        absolute_end,
                        line_starts,
                        owner,
                        hierarchy,
                    )
                } else {
                    precise_receiver_type(&engine, receiver)
                        .is_some_and(|fq| receiver_type_matches(&fq, owner, hierarchy))
                };
                if receiver_matches {
                    push_hit_range(
                        absolute_start,
                        absolute_end,
                        analyzer,
                        file,
                        full_source,
                        line_starts,
                        spec,
                        hits,
                    );
                }
            }
        }
    }
}

enum MemberScanEvent {
    Assignment {
        start: usize,
        lhs_start: usize,
        lhs_end: usize,
        rhs_start: usize,
        rhs_end: usize,
    },
    InstanceMember {
        start: usize,
        receiver_start: usize,
        receiver_end: usize,
        member_start: usize,
        member_end: usize,
    },
}

impl MemberScanEvent {
    fn start(&self) -> usize {
        match self {
            Self::Assignment { start, .. } | Self::InstanceMember { start, .. } => *start,
        }
    }
}

fn seed_parameter_receivers(
    header: &str,
    ctx: &FileContext,
    engine: &mut LocalInferenceEngine<String>,
) {
    for captures in PARAMETER_VARIABLE_RE.captures_iter(header) {
        let Some(type_match) = captures.name("type") else {
            continue;
        };
        let Some(var_match) = captures.name("var") else {
            continue;
        };
        if let Some(fq) = resolve_php_type(type_match.as_str(), ctx) {
            engine.seed_symbol(var_match.as_str(), fq);
        }
    }
}

fn apply_receiver_assignment(
    lhs: &str,
    rhs: &str,
    ctx: &FileContext,
    engine: &mut LocalInferenceEngine<String>,
) {
    if let Some(type_name) = rhs.strip_prefix("new ").and_then(read_leading_type_name)
        && let Some(fq) = resolve_php_type(type_name, ctx)
    {
        engine.seed_symbol(lhs, fq);
        return;
    }
    if let Some(rhs_var) = rhs.strip_prefix('$').and_then(read_leading_variable_name) {
        engine.alias_symbol(lhs, rhs_var);
        return;
    }
    engine.declare_shadow(lhs);
}

fn precise_receiver_type(engine: &LocalInferenceEngine<String>, receiver: &str) -> Option<String> {
    match engine.resolve_symbol(receiver) {
        SymbolResolution::Precise(targets) if targets.len() == 1 => targets.into_iter().next(),
        SymbolResolution::Unknown | SymbolResolution::Ambiguous | SymbolResolution::Precise(_) => {
            None
        }
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
    fn build(php: &PhpAnalyzer, files: &HashSet<ProjectFile>) -> Self {
        let mut hierarchy = Self::default();
        for file in files {
            if language_for_file(file) != Language::Php {
                continue;
            }
            let Ok(source) = file.read_to_string() else {
                continue;
            };
            let ctx = FileContext {
                namespace: php.namespace_of_file(file),
                aliases: parse_php_use_aliases_from_source(&source),
            };
            hierarchy.extend_file(&source, &ctx);
        }
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

    fn is_subtype(&self, receiver_fq_name: &str, owner: &str) -> bool {
        let mut stack: Vec<&str> = self
            .ancestors
            .get(receiver_fq_name)
            .map(|ancestors| ancestors.iter().map(String::as_str).collect())
            .unwrap_or_default();
        let mut visited: HashSet<&str> = HashSet::default();
        while let Some(candidate) = stack.pop() {
            if candidate == owner {
                return true;
            }
            if !visited.insert(candidate) {
                continue;
            }
            if let Some(ancestors) = self.ancestors.get(candidate) {
                stack.extend(ancestors.iter().map(String::as_str));
            }
        }
        false
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
    hierarchy.is_subtype(receiver_fq_name, owner)
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
        "parent" => enclosing_owner_at(analyzer, file, start, end, line_starts)
            .is_some_and(|enclosing_owner| hierarchy.is_subtype(&enclosing_owner, owner)),
        _ => resolve_php_type(receiver, ctx)
            .is_some_and(|fq| receiver_type_matches(&fq, owner, hierarchy)),
    }
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

fn qualified_candidate_text(node: Node<'_>, source: &str) -> String {
    let mut candidate = node;
    let mut parent = node.parent();
    while let Some(ancestor) = parent {
        let text = node_text(ancestor, source).trim();
        if is_php_qualified_name_text(text) {
            candidate = ancestor;
            parent = ancestor.parent();
        } else {
            break;
        }
    }
    let start = candidate.start_byte();
    let text = node_text(candidate, source).trim().to_string();
    if source.get(..start).unwrap_or_default().ends_with('\\') {
        format!("\\{text}")
    } else {
        text
    }
}

fn is_php_qualified_name_text(text: &str) -> bool {
    !text.is_empty()
        && text
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '\\'))
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
    if let Some(imported) = ctx.aliases.type_aliases.get(local) {
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
    if let Some(imported) = ctx.aliases.function_aliases.get(&normalized) {
        return Some(imported.clone());
    }
    Some(join_namespace(&ctx.namespace, &normalized))
}

fn resolve_php_constant(raw: &str, ctx: &FileContext) -> Option<String> {
    if raw.starts_with('\\') {
        return Some(module_constant_fq(&php_namespace_to_fq(raw)));
    }
    let normalized = php_namespace_to_fq(raw);
    if let Some(imported) = ctx.aliases.const_aliases.get(&normalized) {
        return Some(module_constant_fq(imported));
    }
    Some(join_namespace(
        &ctx.namespace,
        &format!("_module_.{normalized}"),
    ))
}

fn module_constant_fq(fq_name: &str) -> String {
    if fq_name.contains("._module_.") {
        return fq_name.to_string();
    }
    let public = public_php_fq_name(fq_name);
    if let Some((namespace, name)) = public.rsplit_once('.') {
        format!("{namespace}._module_.{name}")
    } else {
        format!("_module_.{public}")
    }
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
