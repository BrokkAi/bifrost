use crate::analyzer::{
    AnalyzerDelegate, CodeUnit, CodeUnitType, CppAnalyzer, IAnalyzer, Language, MultiAnalyzer,
    ProjectFile, Range, cpp_node_text as node_text, normalize_cpp_whitespace, parse_quoted_include,
    resolve_include_targets,
};
use crate::hash::{HashMap, HashSet};
use crate::text_utils::{compute_line_starts, find_line_index_for_offset};
use crate::usages::local_inference::{LocalInferenceConfig, LocalInferenceEngine};
use crate::usages::model::{FuzzyResult, UsageHit};
use crate::usages::traits::UsageAnalyzer;
use std::collections::BTreeSet;
use tree_sitter::{Node, Parser};

const GRAPH_HIT_CONFIDENCE: f64 = 1.0;
const SNIPPET_CONTEXT_LINES: usize = 3;

#[derive(Default)]
pub struct CppUsageGraphStrategy {
    _private: (),
}

impl CppUsageGraphStrategy {
    pub fn new() -> Self {
        Self { _private: () }
    }

    pub fn can_handle(target: &CodeUnit) -> bool {
        target_language(target) == Language::Cpp
    }
}

impl UsageAnalyzer for CppUsageGraphStrategy {
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
        if target_language(target) != Language::Cpp {
            return FuzzyResult::Failure {
                fq_name: target.fq_name(),
                reason: "CppUsageGraphStrategy: target is not C/C++".to_string(),
            };
        }

        let Some(cpp) = resolve_cpp_analyzer(analyzer) else {
            return FuzzyResult::Failure {
                fq_name: target.fq_name(),
                reason: "CppUsageGraphStrategy: analyzer does not expose CppAnalyzer".to_string(),
            };
        };

        let Some(spec) = TargetSpec::from_target(analyzer, target) else {
            return FuzzyResult::Failure {
                fq_name: target.fq_name(),
                reason: "CppUsageGraphStrategy: target shape is unsupported".to_string(),
            };
        };

        let visibility = VisibilityIndex::build(cpp, analyzer);
        let files: HashSet<ProjectFile> = candidate_files
            .iter()
            .filter(|file| file_language(file) == Language::Cpp)
            .cloned()
            .chain(std::iter::once(target.source().clone()))
            .collect();

        let mut hits = BTreeSet::new();
        let mut saw_unproven_match = false;
        let mut raw_match_count = 0usize;
        let mut limit_exceeded = false;
        let mut state = ScanState {
            max_usages,
            hits: &mut hits,
            saw_unproven_match: &mut saw_unproven_match,
            raw_match_count: &mut raw_match_count,
            limit_exceeded: &mut limit_exceeded,
        };

        for file in files {
            scan_file(analyzer, &visibility, &file, &spec, &mut state);
            if *state.limit_exceeded {
                break;
            }
        }

        if hits.is_empty() && saw_unproven_match {
            return FuzzyResult::Failure {
                fq_name: target.fq_name(),
                reason: "CppUsageGraphStrategy: no proven structured hits".to_string(),
            };
        }

        if limit_exceeded || hits.len() > max_usages {
            return FuzzyResult::TooManyCallsites {
                short_name: target.short_name().to_string(),
                total_callsites: hits.len(),
                limit: max_usages,
            };
        }

        FuzzyResult::success(target.clone(), hits)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum TargetKind {
    Type,
    Constructor,
    FreeFunction,
    Method,
    GlobalField,
    MemberField,
}

struct TargetSpec {
    target: CodeUnit,
    kind: TargetKind,
    owner: Option<CodeUnit>,
    member_name: String,
    owner_fq_name: Option<String>,
    owner_cpp_name: Option<String>,
    method_arity: Option<usize>,
}

impl TargetSpec {
    fn from_target(analyzer: &dyn IAnalyzer, target: &CodeUnit) -> Option<Self> {
        if target.is_class() {
            return Some(Self::new(
                target.clone(),
                TargetKind::Type,
                Some(target.clone()),
                target.identifier().to_string(),
                None,
            ));
        }

        if target.is_field() {
            let owner = analyzer.parent_of(target);
            let kind = if owner.is_some() {
                TargetKind::MemberField
            } else {
                TargetKind::GlobalField
            };
            return Some(Self::new(
                target.clone(),
                kind,
                owner,
                target.identifier().to_string(),
                None,
            ));
        }

        if target.is_function() {
            let owner = analyzer.parent_of(target);
            let kind = if owner
                .as_ref()
                .is_some_and(|owner| target.identifier() == owner.identifier())
            {
                TargetKind::Constructor
            } else if owner.is_some() {
                TargetKind::Method
            } else {
                TargetKind::FreeFunction
            };
            return Some(Self::new(
                target.clone(),
                kind,
                owner,
                target.identifier().to_string(),
                Some(signature_arity(target.signature())),
            ));
        }

        None
    }

    fn new(
        target: CodeUnit,
        kind: TargetKind,
        owner: Option<CodeUnit>,
        member_name: String,
        method_arity: Option<usize>,
    ) -> Self {
        let owner_fq_name = owner.as_ref().map(CodeUnit::fq_name);
        let owner_cpp_name = owner.as_ref().map(cpp_name_for);
        Self {
            target,
            kind,
            owner,
            member_name,
            owner_fq_name,
            owner_cpp_name,
            method_arity,
        }
    }
}

struct VisibilityIndex {
    visible_by_file: HashMap<ProjectFile, HashSet<CodeUnit>>,
}

impl VisibilityIndex {
    fn build(cpp: &CppAnalyzer, analyzer: &dyn IAnalyzer) -> Self {
        let files: Vec<ProjectFile> = analyzer
            .project()
            .analyzable_files(Language::Cpp)
            .map(|files| files.into_iter().collect())
            .unwrap_or_default();
        let declarations_by_file: HashMap<ProjectFile, BTreeSet<CodeUnit>> = files
            .iter()
            .map(|file| (file.clone(), analyzer.get_declarations(file)))
            .collect();
        let mut visible_by_file = HashMap::default();
        for file in files {
            let mut visited = HashSet::default();
            let mut visible = HashSet::default();
            collect_visible_declarations(
                cpp,
                analyzer,
                &declarations_by_file,
                &file,
                &mut visited,
                &mut visible,
            );
            visible_by_file.insert(file, visible);
        }
        Self { visible_by_file }
    }

    fn is_visible(&self, file: &ProjectFile, target: &CodeUnit) -> bool {
        file == target.source()
            || self
                .visible_by_file
                .get(file)
                .is_some_and(|visible| visible.iter().any(|unit| same_symbol(unit, target)))
    }

    fn resolve_type(&self, file: &ProjectFile, raw_name: &str) -> Option<CodeUnit> {
        let normalized = normalize_reference_name(raw_name)?;
        self.visible_by_file
            .get(file)?
            .iter()
            .filter(|unit| unit.kind() == CodeUnitType::Class || is_type_alias(unit))
            .find(|unit| reference_matches_unit(&normalized, unit))
            .cloned()
    }

    fn resolve_named(
        &self,
        file: &ProjectFile,
        raw_name: &str,
        kind: TargetKind,
    ) -> Option<CodeUnit> {
        let normalized = normalize_reference_name(raw_name)?;
        self.visible_by_file
            .get(file)?
            .iter()
            .find(|unit| {
                matches_kind_for_lookup(unit, kind) && reference_matches_unit(&normalized, unit)
            })
            .cloned()
    }
}

fn collect_visible_declarations(
    cpp: &CppAnalyzer,
    analyzer: &dyn IAnalyzer,
    declarations_by_file: &HashMap<ProjectFile, BTreeSet<CodeUnit>>,
    file: &ProjectFile,
    visited: &mut HashSet<ProjectFile>,
    out: &mut HashSet<CodeUnit>,
) {
    if !visited.insert(file.clone()) {
        return;
    }
    if let Some(declarations) = declarations_by_file.get(file) {
        out.extend(declarations.iter().cloned());
    }
    for line in analyzer.import_statements(file) {
        let Some(include) = parse_quoted_include(line) else {
            continue;
        };
        for target in resolve_include_targets(cpp.project(), file, &include) {
            collect_visible_declarations(
                cpp,
                analyzer,
                declarations_by_file,
                &target,
                visited,
                out,
            );
        }
    }
}

struct ScanState<'a> {
    max_usages: usize,
    hits: &'a mut BTreeSet<UsageHit>,
    saw_unproven_match: &'a mut bool,
    raw_match_count: &'a mut usize,
    limit_exceeded: &'a mut bool,
}

struct ScanCtx<'a> {
    analyzer: &'a dyn IAnalyzer,
    visibility: &'a VisibilityIndex,
    file: &'a ProjectFile,
    source: &'a str,
    line_starts: &'a [usize],
    spec: &'a TargetSpec,
    bindings: LocalInferenceEngine<String>,
    hits: &'a mut BTreeSet<UsageHit>,
    saw_unproven_match: &'a mut bool,
    raw_match_count: &'a mut usize,
    max_usages: usize,
    limit_exceeded: &'a mut bool,
    enclosing_cache: HashMap<(usize, usize), EnclosingContext>,
}

#[derive(Clone, Default)]
struct EnclosingContext {
    enclosing: Option<CodeUnit>,
    owner: Option<CodeUnit>,
}

fn scan_file(
    analyzer: &dyn IAnalyzer,
    visibility: &VisibilityIndex,
    file: &ProjectFile,
    spec: &TargetSpec,
    state: &mut ScanState<'_>,
) {
    if *state.limit_exceeded || file_language(file) != Language::Cpp {
        return;
    }
    let Ok(source) = file.read_to_string() else {
        return;
    };
    if source.is_empty() {
        return;
    }
    let mut parser = Parser::new();
    if parser
        .set_language(&tree_sitter_cpp::LANGUAGE.into())
        .is_err()
    {
        return;
    }
    let Some(tree) = parser.parse(source.as_str(), None) else {
        return;
    };
    let line_starts = compute_line_starts(&source);
    let mut ctx = ScanCtx {
        analyzer,
        visibility,
        file,
        source: &source,
        line_starts: &line_starts,
        spec,
        bindings: LocalInferenceEngine::new(LocalInferenceConfig::default()),
        hits: state.hits,
        saw_unproven_match: state.saw_unproven_match,
        raw_match_count: state.raw_match_count,
        max_usages: state.max_usages,
        limit_exceeded: state.limit_exceeded,
        enclosing_cache: HashMap::default(),
    };
    scan_node(tree.root_node(), &mut ctx);
    if matches!(
        ctx.spec.kind,
        TargetKind::GlobalField | TargetKind::MemberField
    ) && ctx.hits.is_empty()
    {
        scan_text_symbol_hits(&mut ctx);
    }
}

fn scan_node(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if *ctx.limit_exceeded {
        return;
    }
    let enters_scope = matches!(
        node.kind(),
        "compound_statement"
            | "function_definition"
            | "lambda_expression"
            | "for_statement"
            | "while_statement"
            | "if_statement"
    );
    if enters_scope {
        ctx.bindings.enter_scope();
    }

    seed_declarations(node, ctx);
    maybe_record_hit(node, ctx);

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        scan_node(child, ctx);
        if *ctx.limit_exceeded {
            break;
        }
    }

    if enters_scope {
        ctx.bindings.exit_scope();
    }
}

fn seed_declarations(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    match node.kind() {
        "parameter_declaration" | "optional_parameter_declaration" => seed_typed_binding(node, ctx),
        "declaration" | "field_declaration" => seed_variable_declaration(node, ctx),
        _ => {}
    }
}

fn seed_variable_declaration(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let type_text = node
        .child_by_field_name("type")
        .map(|node| normalize_type_text(node_text(node, ctx.source)));
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        let declarator = if child.kind() == "init_declarator" {
            child.child_by_field_name("declarator")
        } else if is_declarator_node(child) {
            Some(child)
        } else {
            None
        };
        let Some(declarator) = declarator else {
            continue;
        };
        if declarator.kind() == "function_declarator" {
            continue;
        }
        let Some(name) = extract_variable_name(declarator, ctx.source) else {
            continue;
        };
        let value = child.child_by_field_name("value");
        seed_binding_from_type_or_value(&name, type_text.as_deref(), value, ctx);
    }
}

fn seed_typed_binding(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let Some(declarator) = node.child_by_field_name("declarator") else {
        return;
    };
    let Some(name) = extract_variable_name(declarator, ctx.source) else {
        return;
    };
    let type_text = node
        .child_by_field_name("type")
        .map(|node| normalize_type_text(node_text(node, ctx.source)));
    seed_binding_from_type_or_value(&name, type_text.as_deref(), None, ctx);
}

fn seed_binding_from_type_or_value(
    name: &str,
    type_text: Option<&str>,
    value: Option<Node<'_>>,
    ctx: &mut ScanCtx<'_>,
) {
    if name.is_empty() {
        return;
    }
    let resolved = type_text
        .filter(|text| *text != "auto")
        .and_then(|text| ctx.visibility.resolve_type(ctx.file, text))
        .or_else(|| value.and_then(|value| infer_type_from_value(value, ctx)));

    if let Some(resolved) = resolved
        && ctx
            .spec
            .owner
            .as_ref()
            .is_some_and(|owner| same_symbol(&resolved, owner))
    {
        ctx.bindings
            .seed_symbol(name.to_string(), resolved.fq_name());
    } else if let Some(value) = value
        && value.kind() == "identifier"
    {
        ctx.bindings
            .alias_symbol(name.to_string(), node_text(value, ctx.source));
    } else {
        ctx.bindings.declare_shadow(name.to_string());
    }
}

fn infer_type_from_value(node: Node<'_>, ctx: &ScanCtx<'_>) -> Option<CodeUnit> {
    match node.kind() {
        "new_expression" => {
            let text = normalize_cpp_whitespace(node_text(node, ctx.source));
            let rest = text.strip_prefix("new ").unwrap_or(text.as_str());
            ctx.visibility
                .resolve_type(ctx.file, rest.split(['(', '{']).next().unwrap_or(rest))
        }
        "call_expression" => node.child_by_field_name("function").and_then(|function| {
            ctx.visibility
                .resolve_type(ctx.file, node_text(function, ctx.source))
        }),
        "initializer_list" => None,
        "identifier" => {
            let resolved = ctx.bindings.resolve_symbol(node_text(node, ctx.source));
            let fq_name = resolved.as_precise()?.iter().next()?;
            ctx.analyzer
                .get_definitions(fq_name)
                .into_iter()
                .find(|unit| unit.is_class())
        }
        _ => ctx
            .visibility
            .resolve_type(ctx.file, node_text(node, ctx.source)),
    }
}

fn maybe_record_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    match ctx.spec.kind {
        TargetKind::Type => maybe_record_type_hit(node, ctx),
        TargetKind::Constructor => maybe_record_constructor_hit(node, ctx),
        TargetKind::FreeFunction => maybe_record_free_function_hit(node, ctx),
        TargetKind::Method => maybe_record_method_hit(node, ctx),
        TargetKind::GlobalField => maybe_record_global_field_hit(node, ctx),
        TargetKind::MemberField => maybe_record_member_field_hit(node, ctx),
    }
}

fn maybe_record_type_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if !matches!(
        node.kind(),
        "type_identifier" | "qualified_identifier" | "scoped_type_identifier" | "template_type"
    ) || is_declaration_name(node)
    {
        return;
    }
    let text = node_text(node, ctx.source);
    if !name_mentions(text, &ctx.spec.member_name) {
        return;
    }
    *ctx.raw_match_count += 1;
    if ctx
        .visibility
        .resolve_type(ctx.file, text)
        .is_some_and(|resolved| same_symbol(&resolved, &ctx.spec.target))
    {
        push_hit(node, ctx);
    } else if !ctx.visibility.is_visible(ctx.file, &ctx.spec.target) {
        *ctx.saw_unproven_match = true;
    }
}

fn maybe_record_constructor_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if !matches!(
        node.kind(),
        "call_expression" | "new_expression" | "declaration"
    ) {
        return;
    }
    let Some(owner) = ctx.spec.owner.as_ref() else {
        return;
    };
    if node.kind() == "declaration" {
        if declaration_mentions_type(node, ctx, owner) {
            push_hit(node, ctx);
        }
        return;
    }
    let Some(type_node) = constructor_type_node(node) else {
        return;
    };
    let text = node_text(type_node, ctx.source);
    if !name_mentions(text, &ctx.spec.member_name) {
        return;
    }
    *ctx.raw_match_count += 1;
    if let Some(expected) = ctx.spec.method_arity
        && call_arity(node) != expected
    {
        return;
    }
    if ctx
        .visibility
        .resolve_type(ctx.file, text)
        .is_some_and(|resolved| same_symbol(&resolved, owner))
    {
        push_hit(type_node, ctx);
    } else {
        *ctx.saw_unproven_match = true;
    }
}

fn maybe_record_free_function_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if node.kind() != "call_expression" {
        return;
    }
    let Some(function) = node.child_by_field_name("function") else {
        return;
    };
    let text = node_text(function, ctx.source);
    if !name_matches_terminal(text, &ctx.spec.member_name) {
        return;
    }
    *ctx.raw_match_count += 1;
    if let Some(expected) = ctx.spec.method_arity
        && call_arity(node) != expected
    {
        return;
    }
    if ctx
        .visibility
        .resolve_named(ctx.file, text, TargetKind::FreeFunction)
        .is_some_and(|resolved| same_symbol(&resolved, &ctx.spec.target))
    {
        push_hit(function, ctx);
    } else {
        *ctx.saw_unproven_match = true;
    }
}

fn maybe_record_method_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if node.kind() != "call_expression" {
        return;
    }
    let Some(function) = node.child_by_field_name("function") else {
        return;
    };
    let text = node_text(function, ctx.source);
    if !name_matches_terminal(text, &ctx.spec.member_name) {
        return;
    }
    *ctx.raw_match_count += 1;
    if let Some(expected) = ctx.spec.method_arity
        && call_arity(node) != expected
    {
        return;
    }
    if receiver_matches_target(function, ctx) || same_owner_context(function, ctx) {
        push_hit(function_terminal_node(function), ctx);
    } else {
        *ctx.saw_unproven_match = true;
    }
}

fn maybe_record_global_field_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if !matches!(
        node.kind(),
        "identifier" | "field_identifier" | "qualified_identifier"
    ) || !name_matches_terminal(node_text(node, ctx.source), &ctx.spec.member_name)
        || is_declaration_name(node)
    {
        return;
    }
    *ctx.raw_match_count += 1;
    if ctx
        .visibility
        .resolve_named(
            ctx.file,
            node_text(node, ctx.source),
            TargetKind::GlobalField,
        )
        .is_some_and(|resolved| same_symbol(&resolved, &ctx.spec.target))
    {
        push_hit(node, ctx);
    } else {
        *ctx.saw_unproven_match = true;
    }
}

fn maybe_record_member_field_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if node.kind() == "field_expression" {
        let Some(field) = node.child_by_field_name("field") else {
            return;
        };
        if node_text(field, ctx.source) != ctx.spec.member_name {
            return;
        }
        *ctx.raw_match_count += 1;
        if receiver_matches_target(node, ctx) {
            push_hit(field, ctx);
        } else {
            *ctx.saw_unproven_match = true;
        }
        return;
    }

    if !matches!(
        node.kind(),
        "identifier" | "field_identifier" | "qualified_identifier"
    ) || !name_matches_terminal(node_text(node, ctx.source), &ctx.spec.member_name)
        || is_declaration_name(node)
    {
        return;
    }
    *ctx.raw_match_count += 1;
    if ctx
        .visibility
        .resolve_named(
            ctx.file,
            node_text(node, ctx.source),
            TargetKind::MemberField,
        )
        .is_some_and(|resolved| same_symbol(&resolved, &ctx.spec.target))
        || qualified_owner_matches(node_text(node, ctx.source), ctx)
        || same_owner_context(node, ctx)
    {
        push_hit(node, ctx);
    } else {
        *ctx.saw_unproven_match = true;
    }
}

fn scan_text_symbol_hits(ctx: &mut ScanCtx<'_>) {
    if !ctx.visibility.is_visible(ctx.file, &ctx.spec.target) {
        return;
    }
    let symbol = ctx.spec.member_name.as_str();
    let mut start = 0usize;
    while let Some(relative) = ctx.source[start..].find(symbol) {
        let absolute = start + relative;
        let end = absolute + symbol.len();
        start = end;
        if !is_word_boundary(ctx.source, absolute, end) {
            continue;
        }
        push_text_hit(absolute, end, ctx);
        if *ctx.limit_exceeded {
            break;
        }
    }
}

fn push_text_hit(start: usize, end: usize, ctx: &mut ScanCtx<'_>) {
    if *ctx.limit_exceeded || ctx.file == ctx.spec.target.source() {
        return;
    }
    let line_idx = find_line_index_for_offset(ctx.line_starts, start);
    let range = Range {
        start_byte: start,
        end_byte: end,
        start_line: line_idx,
        end_line: find_line_index_for_offset(ctx.line_starts, end),
    };
    let Some(enclosing) = ctx.analyzer.enclosing_code_unit(ctx.file, &range) else {
        return;
    };
    if enclosing == ctx.spec.target {
        return;
    }
    ctx.hits.insert(UsageHit::new(
        ctx.file.clone(),
        line_idx + 1,
        start,
        end,
        enclosing,
        GRAPH_HIT_CONFIDENCE,
        build_snippet(ctx.source, ctx.line_starts, line_idx),
    ));
    if ctx.hits.len() > ctx.max_usages {
        *ctx.limit_exceeded = true;
    }
}

fn is_word_boundary(source: &str, start: usize, end: usize) -> bool {
    let before = source[..start].chars().next_back();
    let after = source[end..].chars().next();
    !before.is_some_and(is_identifier_char) && !after.is_some_and(is_identifier_char)
}

fn is_identifier_char(ch: char) -> bool {
    ch == '_' || ch.is_ascii_alphanumeric()
}

fn receiver_matches_target(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    let Some(owner_fq_name) = ctx.spec.owner_fq_name.as_ref() else {
        return false;
    };
    match node.kind() {
        "field_expression" => node
            .child_by_field_name("argument")
            .or_else(|| node.child_by_field_name("object"))
            .is_some_and(|receiver| receiver_matches_target(receiver, ctx)),
        "call_expression" => node
            .child_by_field_name("function")
            .is_some_and(|function| receiver_matches_target(function, ctx)),
        "identifier" => ctx
            .bindings
            .resolve_symbol(node_text(node, ctx.source))
            .as_precise()
            .is_some_and(|targets| targets.contains(owner_fq_name)),
        "qualified_identifier" | "scoped_identifier" | "field_identifier" => {
            qualified_owner_matches(node_text(node, ctx.source), ctx)
        }
        _ => {
            let text = node_text(node, ctx.source);
            qualified_owner_matches(text, ctx)
        }
    }
}

fn qualified_owner_matches(text: &str, ctx: &ScanCtx<'_>) -> bool {
    let Some(owner_cpp_name) = ctx.spec.owner_cpp_name.as_deref() else {
        return false;
    };
    let normalized = normalize_cpp_reference_text(text);
    normalized == owner_cpp_name
        || normalized
            .strip_suffix(&format!("::{}", ctx.spec.member_name))
            .is_some_and(|owner| owner == owner_cpp_name)
}

fn same_owner_context(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    let context = enclosing_context(node, ctx);
    let Some(owner) = context.owner.as_ref() else {
        return false;
    };
    ctx.spec
        .owner_fq_name
        .as_ref()
        .is_some_and(|target_owner| target_owner == &owner.fq_name())
}

fn push_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if *ctx.limit_exceeded {
        return;
    }
    let start = node.start_byte();
    let end = node.end_byte();
    if is_inside_target_declaration(node, ctx) {
        return;
    }
    let line_idx = find_line_index_for_offset(ctx.line_starts, start);
    let Some(enclosing) = enclosing_context(node, ctx).enclosing.clone() else {
        return;
    };
    if enclosing == ctx.spec.target {
        return;
    }
    ctx.hits.insert(UsageHit::new(
        ctx.file.clone(),
        line_idx + 1,
        start,
        end,
        enclosing,
        GRAPH_HIT_CONFIDENCE,
        build_snippet(ctx.source, ctx.line_starts, line_idx),
    ));
    if ctx.hits.len() > ctx.max_usages {
        *ctx.limit_exceeded = true;
    }
}

fn enclosing_context(node: Node<'_>, ctx: &ScanCtx<'_>) -> EnclosingContext {
    let key = (node.start_byte(), node.end_byte());
    if let Some(cached) = ctx.enclosing_cache.get(&key) {
        return cached.clone();
    }
    let range = Range {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: find_line_index_for_offset(ctx.line_starts, node.start_byte()),
        end_line: find_line_index_for_offset(ctx.line_starts, node.end_byte()),
    };
    let enclosing = ctx.analyzer.enclosing_code_unit(ctx.file, &range);
    let owner = enclosing
        .as_ref()
        .and_then(|enclosing| ctx.analyzer.parent_of(enclosing));
    EnclosingContext { enclosing, owner }
}

fn is_inside_target_declaration(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    if ctx.file != ctx.spec.target.source() {
        return false;
    }
    ctx.analyzer
        .ranges(&ctx.spec.target)
        .iter()
        .any(|range| node.start_byte() >= range.start_byte && node.end_byte() <= range.end_byte)
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

fn resolve_cpp_analyzer(analyzer: &dyn IAnalyzer) -> Option<&CppAnalyzer> {
    if let Some(cpp) = (analyzer as &dyn std::any::Any).downcast_ref::<CppAnalyzer>() {
        return Some(cpp);
    }
    let multi = (analyzer as &dyn std::any::Any).downcast_ref::<MultiAnalyzer>()?;
    match multi.delegates().get(&Language::Cpp) {
        Some(AnalyzerDelegate::Cpp(cpp)) => Some(cpp),
        _ => None,
    }
}

fn target_language(target: &CodeUnit) -> Language {
    file_language(target.source())
}

fn file_language(file: &ProjectFile) -> Language {
    file.rel_path()
        .extension()
        .and_then(|ext| ext.to_str())
        .map(Language::from_extension)
        .unwrap_or(Language::None)
}

fn signature_arity(signature: Option<&str>) -> usize {
    let Some(signature) = signature else {
        return 0;
    };
    let inner = signature
        .strip_prefix('(')
        .and_then(|rest| rest.strip_suffix(')'))
        .unwrap_or(signature)
        .trim();
    if inner.is_empty() {
        return 0;
    }
    inner.split(',').count()
}

fn call_arity(node: Node<'_>) -> usize {
    node.child_by_field_name("arguments")
        .map(|args| args.named_child_count())
        .unwrap_or(0)
}

fn constructor_type_node(node: Node<'_>) -> Option<Node<'_>> {
    match node.kind() {
        "new_expression" => node
            .child_by_field_name("type")
            .or_else(|| node.named_child(0)),
        "call_expression" => node.child_by_field_name("function"),
        _ => None,
    }
}

fn declaration_mentions_type(node: Node<'_>, ctx: &ScanCtx<'_>, owner: &CodeUnit) -> bool {
    let Some(type_node) = node.child_by_field_name("type") else {
        return false;
    };
    ctx.visibility
        .resolve_type(ctx.file, node_text(type_node, ctx.source))
        .is_some_and(|resolved| same_symbol(&resolved, owner))
}

fn extract_variable_name(node: Node<'_>, source: &str) -> Option<String> {
    match node.kind() {
        "identifier" | "field_identifier" => {
            let name = node_text(node, source).trim();
            (!name.is_empty()).then(|| name.to_string())
        }
        _ => node
            .child_by_field_name("declarator")
            .or_else(|| node.child_by_field_name("name"))
            .or_else(|| node.named_child(node.named_child_count().saturating_sub(1)))
            .and_then(|child| extract_variable_name(child, source)),
    }
}

fn is_declarator_node(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "identifier"
            | "field_identifier"
            | "pointer_declarator"
            | "reference_declarator"
            | "array_declarator"
            | "parenthesized_declarator"
            | "function_declarator"
    )
}

fn is_declaration_name(node: Node<'_>) -> bool {
    node.parent()
        .and_then(|parent| parent.child_by_field_name("name"))
        == Some(node)
        || matches!(
            node.parent().map(|parent| parent.kind()),
            Some("function_declarator" | "init_declarator")
        )
}

fn function_terminal_node(node: Node<'_>) -> Node<'_> {
    node.child_by_field_name("field")
        .or_else(|| node.child_by_field_name("name"))
        .unwrap_or(node)
}

fn normalize_type_text(value: &str) -> String {
    normalize_cpp_whitespace(value)
        .trim_start_matches("const ")
        .trim_end_matches('*')
        .trim_end_matches('&')
        .trim()
        .to_string()
}

fn normalize_reference_name(value: &str) -> Option<String> {
    let normalized = normalize_cpp_reference_text(value);
    (!normalized.is_empty()).then_some(normalized)
}

fn normalize_cpp_reference_text(value: &str) -> String {
    let mut text = normalize_cpp_whitespace(value)
        .trim_start_matches("new ")
        .trim()
        .to_string();
    if let Some(index) = text.find(['(', '{']) {
        text.truncate(index);
    }
    if let Some(index) = text.find('<') {
        text.truncate(index);
    }
    text.trim()
        .trim_start_matches("const ")
        .trim_end_matches('*')
        .trim_end_matches('&')
        .trim_matches(':')
        .to_string()
}

fn cpp_name_for(unit: &CodeUnit) -> String {
    let short = unit.short_name().replace(['.', '$'], "::");
    if unit.package_name().is_empty() {
        short
    } else {
        format!("{}::{}", unit.package_name(), short)
    }
}

fn terminal_name(value: &str) -> &str {
    value
        .rsplit("::")
        .next()
        .unwrap_or(value)
        .rsplit(['.', '-', '>'])
        .next()
        .unwrap_or(value)
        .trim()
}

fn name_matches_terminal(value: &str, expected: &str) -> bool {
    terminal_name(&normalize_cpp_reference_text(value)) == expected
}

fn name_mentions(value: &str, expected: &str) -> bool {
    normalize_cpp_reference_text(value)
        .split("::")
        .any(|part| part == expected)
}

fn reference_matches_unit(reference: &str, unit: &CodeUnit) -> bool {
    let cpp_name = cpp_name_for(unit);
    reference == cpp_name
        || terminal_name(reference) == unit.identifier()
            && (unit.package_name().is_empty() || reference == unit.identifier())
}

fn matches_kind_for_lookup(unit: &CodeUnit, kind: TargetKind) -> bool {
    match kind {
        TargetKind::Type
        | TargetKind::Constructor
        | TargetKind::Method
        | TargetKind::MemberField => true,
        TargetKind::FreeFunction => unit.is_function(),
        TargetKind::GlobalField => unit.is_field(),
    }
}

fn is_type_alias(unit: &CodeUnit) -> bool {
    unit.kind() == CodeUnitType::Field
        && unit.signature().is_some_and(|signature| {
            signature.starts_with("typedef ") || signature.starts_with("using ")
        })
}

fn same_symbol(left: &CodeUnit, right: &CodeUnit) -> bool {
    left.kind() == right.kind()
        && left.fq_name() == right.fq_name()
        && left.signature() == right.signature()
        && left.source() == right.source()
}
