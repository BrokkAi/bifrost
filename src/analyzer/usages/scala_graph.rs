use crate::analyzer::common::{language_for_file, language_for_target};
use crate::analyzer::usages::common::usage_hit;
use crate::analyzer::usages::local_inference::{LocalInferenceConfig, LocalInferenceEngine};
use crate::analyzer::usages::model::{FuzzyResult, UsageHit};
use crate::analyzer::usages::outcome::{GraphFailureReason, GraphUsageOutcome};
use crate::analyzer::usages::traits::UsageAnalyzer;
use crate::analyzer::{
    AnalyzerDelegate, CodeUnit, IAnalyzer, ImportAnalysisProvider, ImportInfo, Language,
    MultiAnalyzer, ProjectFile, Range, ScalaAnalyzer,
};
use crate::hash::{HashMap, HashSet};
use crate::text_utils::{compute_line_starts, find_line_index_for_offset};
use std::collections::BTreeSet;
use tree_sitter::{Node, Parser};

const SNIPPET_CONTEXT_LINES: usize = 3;

#[derive(Default)]
pub struct ScalaUsageGraphStrategy {
    _private: (),
}

impl ScalaUsageGraphStrategy {
    pub fn new() -> Self {
        Self { _private: () }
    }

    pub fn can_handle(target: &CodeUnit) -> bool {
        language_for_target(target) == Language::Scala
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
        if language_for_target(target) != Language::Scala {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::UnsupportedTargetLanguage("target is not Scala"),
                "ScalaUsageGraphStrategy",
            );
        }

        let Some(scala) = resolve_scala_analyzer(analyzer) else {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::MissingAnalyzerCapability(
                    "analyzer does not expose ScalaAnalyzer",
                ),
                "ScalaUsageGraphStrategy",
            );
        };

        let Some(spec) = TargetSpec::from_target(scala, target) else {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::UnsupportedTargetShape("target shape is unsupported"),
                "ScalaUsageGraphStrategy",
            );
        };

        let files: HashSet<ProjectFile> = candidate_files
            .iter()
            .filter(|file| language_for_file(file) == Language::Scala)
            .cloned()
            .chain(std::iter::once(target.source().clone()))
            .collect();

        let mut hits = BTreeSet::new();
        let mut limit_exceeded = false;
        for file in files {
            scan_file(
                scala,
                analyzer,
                &file,
                &spec,
                &mut hits,
                max_usages,
                &mut limit_exceeded,
            );
            if hits.len() > max_usages {
                return GraphUsageOutcome::Resolved(FuzzyResult::TooManyCallsites {
                    short_name: target.short_name().to_string(),
                    total_callsites: hits.len(),
                    limit: max_usages,
                });
            }
            if limit_exceeded {
                break;
            }
        }

        GraphUsageOutcome::Resolved(FuzzyResult::success(target.clone(), hits))
    }
}

impl UsageAnalyzer for ScalaUsageGraphStrategy {
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
}

struct TargetSpec {
    target: CodeUnit,
    kind: TargetKind,
    owner: Option<CodeUnit>,
    owner_name: Option<String>,
    member_name: String,
    target_fq_name: String,
    owner_fq_name: Option<String>,
    arity: Option<usize>,
}

impl TargetSpec {
    fn from_target(scala: &ScalaAnalyzer, target: &CodeUnit) -> Option<Self> {
        if target.is_class() {
            let owner_name = scala_display_name(target);
            return Some(Self {
                target: target.clone(),
                kind: TargetKind::Type,
                owner: Some(target.clone()),
                member_name: owner_name.clone(),
                target_fq_name: scala_normalized_fq_name(&target.fq_name()),
                owner_fq_name: Some(scala_normalized_fq_name(&target.fq_name())),
                owner_name: Some(owner_name),
                arity: None,
            });
        }

        let owner = owner_of(scala, target);
        let owner_name = owner.as_ref().map(scala_display_name);
        let kind = if target.is_field() {
            TargetKind::Field
        } else if target.is_synthetic() || owner_name.as_deref() == Some(target.identifier()) {
            TargetKind::Constructor
        } else {
            TargetKind::Method
        };
        let arity = target.signature().and_then(signature_arity).or_else(|| {
            scala
                .signatures(target)
                .first()
                .and_then(|sig| signature_arity(sig))
        });
        let member_name = if kind == TargetKind::Constructor {
            owner_name.clone()?
        } else {
            target.identifier().to_string()
        };
        Some(Self {
            target: target.clone(),
            target_fq_name: scala_normalized_fq_name(&target.fq_name()),
            owner_fq_name: owner
                .as_ref()
                .map(|owner| scala_normalized_fq_name(&owner.fq_name())),
            owner,
            owner_name,
            kind,
            member_name,
            arity,
        })
    }
}

fn resolve_scala_analyzer(analyzer: &dyn IAnalyzer) -> Option<&ScalaAnalyzer> {
    if let Some(scala) = (analyzer as &dyn std::any::Any).downcast_ref::<ScalaAnalyzer>() {
        return Some(scala);
    }

    let multi = (analyzer as &dyn std::any::Any).downcast_ref::<MultiAnalyzer>()?;
    match multi.delegates().get(&Language::Scala) {
        Some(AnalyzerDelegate::Scala(scala)) => Some(scala),
        _ => None,
    }
}

fn owner_of(scala: &ScalaAnalyzer, target: &CodeUnit) -> Option<CodeUnit> {
    if let Some((owner_short, _)) = target.short_name().rsplit_once('.') {
        let owner_fq = if target.package_name().is_empty() {
            owner_short.to_string()
        } else {
            format!("{}.{}", target.package_name(), owner_short)
        };
        if let Some(owner) = scala
            .definitions(&owner_fq)
            .find(|unit| unit.is_class())
            .cloned()
        {
            return Some(owner);
        }
    }

    scala
        .all_declarations()
        .filter(|unit| unit.is_class())
        .find(|candidate| {
            scala
                .direct_children(candidate)
                .any(|child| child == target)
        })
        .cloned()
}

fn scan_file(
    scala: &ScalaAnalyzer,
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    spec: &TargetSpec,
    hits: &mut BTreeSet<UsageHit>,
    max_usages: usize,
    limit_exceeded: &mut bool,
) {
    if *limit_exceeded {
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
        .set_language(&tree_sitter_scala::LANGUAGE.into())
        .is_err()
    {
        return;
    }
    let Some(tree) = parser.parse(source.as_str(), None) else {
        return;
    };
    let line_starts = compute_line_starts(&source);
    let visibility = Visibility::for_file(scala, file, spec);
    let mut bindings = LocalInferenceEngine::new(LocalInferenceConfig::default());
    let mut ctx = ScanCtx {
        scala,
        analyzer,
        file,
        source: &source,
        line_starts: &line_starts,
        spec,
        visibility,
        bindings: &mut bindings,
        hits,
        max_usages,
        limit_exceeded,
        enclosing_cache: HashMap::default(),
    };
    scan_node(tree.root_node(), &mut ctx);
}

struct Visibility {
    type_names: HashSet<String>,
    owner_names: HashSet<String>,
    direct_member_names: HashSet<String>,
    ambiguous_direct_member_names: HashSet<String>,
}

impl Visibility {
    fn for_file(scala: &ScalaAnalyzer, file: &ProjectFile, spec: &TargetSpec) -> Self {
        let mut visibility = Self {
            type_names: HashSet::default(),
            owner_names: HashSet::default(),
            direct_member_names: HashSet::default(),
            ambiguous_direct_member_names: ambiguous_wildcard_members(scala, file, spec),
        };

        let file_package = package_name_of(scala, file);
        if file == spec.target.source()
            || file_package.as_deref() == Some(spec.target.package_name())
        {
            visibility.type_names.insert(spec.member_name.clone());
            if spec.owner.is_none() {
                visibility
                    .direct_member_names
                    .insert(spec.member_name.clone());
            }
            if let Some(owner_name) = spec.owner_name.as_ref() {
                visibility.owner_names.insert(owner_name.clone());
            }
        }
        if spec
            .owner
            .as_ref()
            .is_some_and(|owner| file_package.as_deref() == Some(owner.package_name()))
            && let Some(owner_name) = spec.owner_name.as_ref()
        {
            visibility.owner_names.insert(owner_name.clone());
        }

        for import in scala.import_info_of(file) {
            visibility.apply_import(import, spec);
        }

        visibility
    }

    fn apply_import(&mut self, import: &ImportInfo, spec: &TargetSpec) {
        let Some(path) = scala_import_path(import) else {
            return;
        };
        let local_name = import
            .identifier
            .as_deref()
            .map(str::to_string)
            .unwrap_or_else(|| path.rsplit('.').next().unwrap_or(path.as_str()).to_string());
        if import.is_wildcard {
            if path == spec.target.package_name() {
                self.type_names.insert(spec.member_name.clone());
                if spec.owner.is_none() {
                    self.direct_member_names.insert(spec.member_name.clone());
                }
            }
            if spec
                .owner
                .as_ref()
                .is_some_and(|owner| path == owner.package_name())
                && let Some(owner_name) = spec.owner_name.as_ref()
            {
                self.owner_names.insert(owner_name.clone());
            }
            if spec
                .owner_fq_name
                .as_ref()
                .is_some_and(|owner_fq| path == *owner_fq)
            {
                self.direct_member_names.insert(spec.member_name.clone());
            }
            return;
        }

        let normalized = scala_normalized_fq_name(&path);
        if normalized == spec.target_fq_name {
            self.type_names.insert(local_name.clone());
        }
        if spec
            .owner_fq_name
            .as_ref()
            .is_some_and(|owner_fq| normalized == *owner_fq)
        {
            self.owner_names.insert(local_name.clone());
            if spec.kind == TargetKind::Constructor {
                self.type_names.insert(local_name.clone());
            }
        }
        if normalized == spec.target_fq_name && spec.kind != TargetKind::Type {
            self.direct_member_names.insert(local_name);
        }
    }
}

struct ScanCtx<'a> {
    scala: &'a ScalaAnalyzer,
    analyzer: &'a dyn IAnalyzer,
    file: &'a ProjectFile,
    source: &'a str,
    line_starts: &'a [usize],
    spec: &'a TargetSpec,
    visibility: Visibility,
    bindings: &'a mut LocalInferenceEngine<String>,
    hits: &'a mut BTreeSet<UsageHit>,
    max_usages: usize,
    limit_exceeded: &'a mut bool,
    enclosing_cache: HashMap<(usize, usize), Option<CodeUnit>>,
}

fn scan_node(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if *ctx.limit_exceeded {
        return;
    }
    seed_parent_scope_declarations(node, ctx);
    let enters_scope = enters_local_scope(node);
    if enters_scope {
        ctx.bindings.enter_scope();
        seed_scope_declarations(node, ctx);
    } else {
        seed_inline_declarations(node, ctx);
    }

    if node.kind() == "call_expression" {
        scan_call_expression(node, ctx);
    }
    if is_identifier_node(node) {
        scan_identifier(node, ctx);
    }
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

fn scan_call_expression(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if !matches!(ctx.spec.kind, TargetKind::Method) {
        return;
    }
    let Some(function) = node.child_by_field_name("function") else {
        return;
    };
    let text = node_text(function, ctx.source).trim();
    if text != ctx.spec.member_name || has_dot_qualifier(function, ctx.source) {
        return;
    }
    if !is_locally_shadowed(ctx, text)
        && enclosing_matches_owner(function, ctx)
        && member_call_arity_matches(function, ctx)
    {
        add_hit(function, ctx);
    }
}

fn seed_parent_scope_declarations(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if node.kind() != "function_definition" || !has_ancestor_kind(node, "function_definition") {
        return;
    }
    if let Some(name) = node.child_by_field_name("name") {
        let name = node_text(name, ctx.source).trim();
        if !name.is_empty() {
            ctx.bindings.declare_shadow(name.to_string());
        }
    }
}

fn enters_local_scope(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "class_definition"
            | "object_definition"
            | "trait_definition"
            | "enum_definition"
            | "function_definition"
            | "block"
            | "block_expression"
            | "case_clause"
            | "lambda_expression"
            | "anonymous_function"
    )
}

fn seed_scope_declarations(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    match node.kind() {
        "class_definition" | "object_definition" | "trait_definition" | "enum_definition" => {
            seed_owner_field_bindings(node, ctx);
        }
        "function_definition" => {
            if let Some(name) = node.child_by_field_name("name") {
                let name = node_text(name, ctx.source).trim();
                if !name.is_empty() {
                    ctx.bindings.declare_shadow(name.to_string());
                }
            }
            seed_parameter_bindings(node, ctx);
        }
        "case_clause" => seed_case_pattern_shadow(node, ctx),
        _ => {}
    }
}

fn seed_inline_declarations(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    match node.kind() {
        "val_definition" | "var_definition" => seed_value_definition(node, ctx),
        "function_definition" => {
            if let Some(name) = node.child_by_field_name("name") {
                let name = node_text(name, ctx.source).trim();
                if !name.is_empty() {
                    ctx.bindings.declare_shadow(name.to_string());
                }
            }
        }
        _ => {}
    }
}

fn seed_owner_field_bindings(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if ctx.spec.owner.is_none() {
        return;
    }
    if !enclosing_type_matches_owner(node, ctx) {
        return;
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if matches!(child.kind(), "template_body" | "enum_body") {
            seed_direct_field_bindings(child, ctx);
        }
    }
}

fn seed_direct_field_bindings(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "val_definition" | "var_definition" => seed_value_definition(child, ctx),
            "function_definition"
            | "class_definition"
            | "object_definition"
            | "trait_definition"
            | "enum_definition" => {}
            _ => seed_direct_field_bindings(child, ctx),
        }
    }
}

fn enclosing_type_matches_owner(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    let Some(owner_name) = ctx.spec.owner_name.as_deref() else {
        return false;
    };
    node.child_by_field_name("name")
        .map(|name| node_text(name, ctx.source).trim().trim_end_matches('$') == owner_name)
        .unwrap_or(false)
}

fn seed_parameter_bindings(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() != "parameters" {
            continue;
        }
        for (name, type_name) in typed_parameter_pairs(node_text(child, ctx.source)) {
            seed_or_shadow_typed_symbol(name, Some(type_name), None, ctx);
        }
    }
}

fn typed_parameter_pairs(parameters: &str) -> Vec<(&str, &str)> {
    let inner = parameters
        .trim()
        .trim_start_matches('(')
        .trim_end_matches(')');
    split_top_level_commas(inner)
        .filter_map(|part| {
            let (name, type_text) = part.split_once(':')?;
            let name = name.trim();
            let type_name = simple_type_name(type_text.trim())?;
            (!name.is_empty()).then_some((name, type_name))
        })
        .collect()
}

fn seed_value_definition(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let Some(pattern) = node.child_by_field_name("pattern") else {
        seed_value_definition_from_text(node_text(node, ctx.source), ctx);
        return;
    };
    let type_name = node
        .child_by_field_name("type")
        .and_then(|type_node| simple_type_name(node_text(type_node, ctx.source).trim()));
    let value_name = node
        .child_by_field_name("value")
        .and_then(|value_node| constructor_type_name(node_text(value_node, ctx.source)));
    if type_name.is_none() && value_name.is_none() {
        seed_value_definition_from_text(node_text(node, ctx.source), ctx);
        return;
    }
    for name in pattern_names(pattern, ctx.source) {
        seed_or_shadow_typed_symbol(name, type_name, value_name, ctx);
    }
}

fn seed_value_definition_from_text(text: &str, ctx: &mut ScanCtx<'_>) {
    let trimmed = text.trim_start();
    let Some(after_keyword) = trimmed
        .strip_prefix("val ")
        .or_else(|| trimmed.strip_prefix("var "))
    else {
        return;
    };
    let name_end = after_keyword
        .find(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
        .unwrap_or(after_keyword.len());
    if name_end == 0 {
        return;
    }
    let name = &after_keyword[..name_end];
    let rest = after_keyword[name_end..].trim_start();
    let type_name = rest
        .strip_prefix(':')
        .and_then(|after_colon| simple_type_name(after_colon.trim_start()));
    let value_name = rest
        .split_once('=')
        .and_then(|(_, value)| constructor_type_name(value));
    seed_or_shadow_typed_symbol(name, type_name, value_name, ctx);
}

fn seed_or_shadow_typed_symbol(
    name: &str,
    type_name: Option<&str>,
    value_name: Option<&str>,
    ctx: &mut ScanCtx<'_>,
) {
    let visible_type = type_name
        .or(value_name)
        .filter(|name| ctx.visibility.owner_names.contains(*name));
    if let Some(_type_name) = visible_type
        && let Some(owner_fq_name) = ctx.spec.owner_fq_name.as_ref()
    {
        ctx.bindings
            .seed_symbol(name.to_string(), owner_fq_name.clone());
        return;
    }
    ctx.bindings.declare_shadow(name.to_string());
}

fn simple_type_name(type_text: &str) -> Option<&str> {
    type_text
        .split(['[', '(', '{', '.', ' '])
        .next()
        .map(str::trim)
        .filter(|name| !name.is_empty())
}

fn constructor_type_name(value_text: &str) -> Option<&str> {
    let trimmed = value_text.trim_start();
    let trimmed = trimmed.strip_prefix("new ").unwrap_or(trimmed).trim_start();
    let end = trimmed
        .find(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
        .unwrap_or(trimmed.len());
    (end > 0).then_some(&trimmed[..end])
}

fn pattern_names<'a>(node: Node<'_>, source: &'a str) -> Vec<&'a str> {
    match node.kind() {
        "identifier" | "operator_identifier" => {
            let name = node_text(node, source).trim();
            if name.is_empty() {
                Vec::new()
            } else {
                vec![name]
            }
        }
        "identifiers" | "tuple_pattern" | "pattern" => {
            let mut names = Vec::new();
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                names.extend(pattern_names(child, source));
            }
            names
        }
        _ => {
            let mut names = Vec::new();
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                names.extend(pattern_names(child, source));
            }
            names
        }
    }
}

fn seed_case_pattern_shadow(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if let Some(pattern) = node.child_by_field_name("pattern") {
        for name in pattern_names(pattern, ctx.source) {
            ctx.bindings.declare_shadow(name.to_string());
        }
    }
}

fn scan_identifier(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if has_ancestor_kind(node, "import_declaration") {
        return;
    }
    let text = node_text(node, ctx.source).trim();
    if text.is_empty() {
        return;
    }
    if seed_value_binding_identifier(node, text, ctx) {
        return;
    }

    let proven = match ctx.spec.kind {
        TargetKind::Type => {
            ctx.visibility.type_names.contains(text) && is_type_like_reference(node, ctx.source)
        }
        TargetKind::Constructor => {
            ctx.visibility.type_names.contains(text)
                && is_constructor_like_reference(node, ctx.source)
        }
        TargetKind::Method | TargetKind::Field => member_reference_is_proven(node, text, ctx),
    };
    if proven {
        add_hit(node, ctx);
    }
    if is_simple_assignment_lhs(node, ctx.source) && !ctx.bindings.resolve_symbol(text).is_unknown()
    {
        ctx.bindings.declare_shadow(text.to_string());
    }
}

fn seed_value_binding_identifier(node: Node<'_>, text: &str, ctx: &mut ScanCtx<'_>) -> bool {
    let before = ctx.source[..node.start_byte()].trim_end();
    let Some(keyword) = previous_word(before) else {
        return false;
    };
    if !matches!(keyword, "val" | "var") {
        return false;
    }
    let line_end = ctx.source[node.end_byte()..]
        .find(['\n', '\r', ';'])
        .map(|offset| node.end_byte() + offset)
        .unwrap_or(ctx.source.len());
    let rest = ctx.source[node.end_byte()..line_end].trim_start();
    let type_name = rest
        .strip_prefix(':')
        .and_then(|after_colon| simple_type_name(after_colon.trim_start()));
    let value_name = rest
        .split_once('=')
        .and_then(|(_, value)| constructor_type_name(value));
    seed_or_shadow_typed_symbol(text, type_name, value_name, ctx);
    true
}

fn previous_word(value: &str) -> Option<&str> {
    value
        .rsplit(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
        .find(|part| !part.is_empty())
}

fn member_reference_is_proven(node: Node<'_>, text: &str, ctx: &ScanCtx<'_>) -> bool {
    if ctx.visibility.direct_member_names.contains(text)
        && !ctx.visibility.ambiguous_direct_member_names.contains(text)
        && !has_dot_qualifier(node, ctx.source)
        && !is_locally_shadowed(ctx, text)
        && member_call_arity_matches(node, ctx)
    {
        return true;
    }

    if text != ctx.spec.member_name {
        return false;
    }

    if ctx.spec.owner.is_none() {
        return dotted_qualifier_before(node, ctx.source)
            .is_some_and(|qualifier| qualifier == ctx.spec.target.package_name());
    }

    let Some(qualifier) = dot_qualifier_before(node, ctx.source) else {
        return !is_locally_shadowed(ctx, text)
            && enclosing_matches_owner(node, ctx)
            && member_call_arity_matches(node, ctx);
    };
    if qualifier == "this" {
        return enclosing_matches_owner(node, ctx) && member_call_arity_matches(node, ctx);
    }
    if ctx.visibility.owner_names.contains(&qualifier)
        && !is_locally_shadowed(ctx, &qualifier)
        && member_call_arity_matches(node, ctx)
    {
        return true;
    }
    receiver_binding_matches(node, &qualifier, ctx)
}

fn is_locally_shadowed(ctx: &ScanCtx<'_>, name: &str) -> bool {
    ctx.bindings.is_shadowed(name) && ctx.bindings.resolve_symbol(name).is_unknown()
}

fn receiver_binding_matches(node: Node<'_>, qualifier: &str, ctx: &ScanCtx<'_>) -> bool {
    let Some(target_owner_fq) = ctx.spec.owner_fq_name.as_ref() else {
        return false;
    };
    if !member_call_arity_matches(node, ctx) {
        return false;
    }
    ctx.bindings
        .resolve_symbol(qualifier)
        .as_precise()
        .is_some_and(|targets| targets.contains(target_owner_fq))
}

fn ambiguous_wildcard_members(
    scala: &ScalaAnalyzer,
    file: &ProjectFile,
    spec: &TargetSpec,
) -> HashSet<String> {
    if spec.kind == TargetKind::Type {
        return HashSet::default();
    }

    let mut exposing_wildcards = HashSet::default();
    for import in scala.import_info_of(file) {
        if !import.is_wildcard {
            continue;
        }
        let Some(path) = scala_import_path(import) else {
            continue;
        };
        if wildcard_path_could_expose(scala, &path, spec) {
            exposing_wildcards.insert(path);
        }
    }

    let mut ambiguous = HashSet::default();
    if exposing_wildcards.len() > 1 {
        ambiguous.insert(spec.member_name.clone());
    }
    ambiguous
}

fn wildcard_path_could_expose(scala: &ScalaAnalyzer, path: &str, spec: &TargetSpec) -> bool {
    if spec.owner.is_none() {
        return scala
            .definitions(&format!("{path}.{}", spec.member_name))
            .any(|unit| {
                matches!(spec.kind, TargetKind::Method) && unit.is_function()
                    || matches!(spec.kind, TargetKind::Field) && unit.is_field()
            });
    }

    spec.owner_fq_name
        .as_ref()
        .is_some_and(|owner_fq| path == owner_fq)
}

fn enclosing_matches_owner(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    let Some(owner) = ctx.spec.owner.as_ref() else {
        return false;
    };
    let range = Range {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: node.start_position().row,
        end_line: node.end_position().row,
    };
    let Some(enclosing) = ctx.analyzer.enclosing_code_unit(ctx.file, &range) else {
        return false;
    };
    if enclosing == *owner {
        return true;
    }
    enclosing.source() == owner.source()
        && enclosing.package_name() == owner.package_name()
        && enclosing
            .short_name()
            .strip_prefix(owner.short_name())
            .is_some_and(|rest| rest.starts_with('.'))
}

fn add_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if *ctx.limit_exceeded {
        return;
    }
    let range = Range {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: node.start_position().row,
        end_line: node.end_position().row,
    };
    let cache_key = (range.start_byte, range.end_byte);
    let enclosing = if let Some(cached) = ctx.enclosing_cache.get(&cache_key) {
        cached.clone()
    } else {
        let resolved = ctx
            .analyzer
            .enclosing_code_unit(ctx.file, &range)
            .or_else(|| nearest_declaration(ctx.scala, ctx.file));
        ctx.enclosing_cache.insert(cache_key, resolved.clone());
        resolved
    };
    let Some(enclosing) = enclosing else {
        return;
    };
    if enclosing == ctx.spec.target
        && range_within_any(ctx.analyzer.ranges(&ctx.spec.target), &range)
    {
        return;
    }
    let line = find_line_index_for_offset(ctx.line_starts, range.start_byte) + 1;
    ctx.hits.insert(usage_hit(
        ctx.file,
        line - 1,
        range.start_byte,
        range.end_byte,
        enclosing,
        snippet_around(ctx.source, ctx.line_starts, line),
    ));
    if ctx.hits.len() > ctx.max_usages {
        *ctx.limit_exceeded = true;
    }
}

fn range_within_any(ranges: &[Range], needle: &Range) -> bool {
    ranges
        .iter()
        .any(|range| range.start_byte <= needle.start_byte && needle.end_byte <= range.end_byte)
}

fn nearest_declaration(scala: &ScalaAnalyzer, file: &ProjectFile) -> Option<CodeUnit> {
    scala.declarations(file).next().cloned()
}

fn is_identifier_node(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "identifier" | "type_identifier" | "operator_identifier"
    )
}

fn is_type_like_reference(node: Node<'_>, source: &str) -> bool {
    node.kind() == "type_identifier"
        || is_constructor_like_reference(node, source)
        || parent_kind(node).is_some_and(|kind| {
            matches!(
                kind,
                "type" | "generic_type" | "parameterized_type" | "extends_clause"
            )
        })
}

fn is_constructor_like_reference(node: Node<'_>, source: &str) -> bool {
    let prefix = source[..node.start_byte()].trim_end();
    prefix.ends_with("new")
        || parent_kind(node).is_some_and(|kind| matches!(kind, "call_expression" | "type"))
}

fn member_call_arity_matches(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    if ctx.spec.kind != TargetKind::Method {
        return true;
    }
    let Some(target_arity) = ctx.spec.arity else {
        return true;
    };
    match call_arity_after(node, ctx.source) {
        Some(call_arity) => call_arity == target_arity,
        None => target_arity == 0,
    }
}

fn call_arity_after(node: Node<'_>, source: &str) -> Option<usize> {
    let after = source[node.end_byte()..].trim_start();
    let inner = balanced_parenthesized_prefix(after)?;
    if inner.trim().is_empty() {
        return Some(0);
    }
    Some(split_top_level_commas(inner).count())
}

fn balanced_parenthesized_prefix(source: &str) -> Option<&str> {
    let mut chars = source.char_indices();
    let (_, first) = chars.next()?;
    if first != '(' {
        return None;
    }
    let mut depth = 1usize;
    for (idx, ch) in chars {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(&source[1..idx]);
                }
            }
            _ => {}
        }
    }
    None
}

fn split_top_level_commas(value: &str) -> impl Iterator<Item = &str> {
    let mut depth = 0usize;
    let mut start = 0usize;
    let mut parts = Vec::new();
    for (idx, ch) in value.char_indices() {
        match ch {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                parts.push(value[start..idx].trim());
                start = idx + ch.len_utf8();
            }
            _ => {}
        }
    }
    parts.push(value[start..].trim());
    parts.into_iter().filter(|part| !part.is_empty())
}

fn signature_arity(signature: &str) -> Option<usize> {
    let open = signature.find('(')?;
    let inner = balanced_parenthesized_prefix(&signature[open..])?;
    if inner.trim().is_empty() {
        return Some(0);
    }
    Some(split_top_level_commas(inner).count())
}

fn parent_kind(node: Node<'_>) -> Option<&str> {
    node.parent().map(|parent| parent.kind())
}

fn has_ancestor_kind(node: Node<'_>, kind: &str) -> bool {
    let mut current = node.parent();
    while let Some(parent) = current {
        if parent.kind() == kind {
            return true;
        }
        current = parent.parent();
    }
    false
}

fn has_dot_qualifier(node: Node<'_>, source: &str) -> bool {
    dot_qualifier_before(node, source).is_some()
}

fn is_simple_assignment_lhs(node: Node<'_>, source: &str) -> bool {
    if has_dot_qualifier(node, source) {
        return false;
    }
    let after = source[node.end_byte()..].trim_start();
    after.starts_with('=') && !after.starts_with("=>") && !after.starts_with("==")
}

fn dot_qualifier_before(node: Node<'_>, source: &str) -> Option<String> {
    let before = &source[..node.start_byte()];
    let before = before.trim_end();
    let without_dot = before.strip_suffix('.')?;
    let qualifier: String = without_dot
        .chars()
        .rev()
        .take_while(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '$'))
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    (!qualifier.is_empty()).then_some(qualifier.trim_end_matches('$').to_string())
}

fn dotted_qualifier_before(node: Node<'_>, source: &str) -> Option<String> {
    let before = source[..node.start_byte()].trim_end();
    let without_dot = before.strip_suffix('.')?;
    let qualifier: String = without_dot
        .chars()
        .rev()
        .take_while(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '$' | '.'))
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    (!qualifier.is_empty()).then_some(qualifier.trim_end_matches('$').to_string())
}

fn package_name_of(scala: &ScalaAnalyzer, file: &ProjectFile) -> Option<String> {
    scala
        .declarations(file)
        .next()
        .map(|unit| unit.package_name().to_string())
}

fn scala_import_path(info: &ImportInfo) -> Option<String> {
    let trimmed = info
        .raw_snippet
        .trim()
        .strip_prefix("import ")
        .unwrap_or(info.raw_snippet.trim())
        .trim();
    if trimmed.is_empty() {
        return None;
    }
    if info.is_wildcard {
        return Some(trimmed.trim_end_matches(".*").to_string());
    }
    Some(
        trimmed
            .split_once(" as ")
            .map(|(path, _)| path)
            .unwrap_or(trimmed)
            .trim()
            .to_string(),
    )
}

fn scala_normalized_fq_name(fq_name: &str) -> String {
    fq_name.replace("$.", ".").trim_end_matches('$').to_string()
}

fn scala_display_name(unit: &CodeUnit) -> String {
    unit.short_name()
        .rsplit('.')
        .next()
        .unwrap_or(unit.short_name())
        .trim_end_matches('$')
        .to_string()
}

fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    &source[node.byte_range()]
}

fn snippet_around(source: &str, line_starts: &[usize], one_based_line: usize) -> String {
    if line_starts.is_empty() {
        return String::new();
    }
    let zero_based = one_based_line.saturating_sub(1);
    let start_line = zero_based.saturating_sub(SNIPPET_CONTEXT_LINES.saturating_sub(1));
    let end_line = (zero_based + SNIPPET_CONTEXT_LINES).min(line_starts.len());
    let start = *line_starts.get(start_line).unwrap_or(&0);
    let end = line_starts
        .get(end_line)
        .copied()
        .unwrap_or(source.len())
        .min(source.len());
    source[start..end].trim().to_string()
}
