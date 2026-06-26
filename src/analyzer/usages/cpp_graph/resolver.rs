use crate::analyzer::usages::common::same_node;
use crate::analyzer::usages::cpp_graph::extractor::ScanCtx;
use crate::analyzer::{
    CodeUnit, CodeUnitType, CppAnalyzer, IAnalyzer, ProjectFile, cpp_include_paths,
    cpp_node_text as node_text, normalize_cpp_whitespace,
    resolve_include_targets_with_unique_fallback,
};
use crate::hash::{HashMap, HashSet};
use std::collections::BTreeSet;
use tree_sitter::{Node, Parser};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::analyzer::usages) enum TargetKind {
    Type,
    Constructor,
    FreeFunction,
    Method,
    GlobalField,
    MemberField,
}

pub(super) struct TargetSpec {
    pub(super) target: CodeUnit,
    pub(super) kind: TargetKind,
    pub(super) owner: Option<CodeUnit>,
    pub(super) member_name: String,
    pub(super) owner_fq_name: Option<String>,
    pub(super) owner_cpp_name: Option<String>,
    pub(super) method_arity: Option<usize>,
}

impl TargetSpec {
    pub(super) fn from_target(analyzer: &dyn IAnalyzer, target: &CodeUnit) -> Option<Self> {
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
            // A namespace (module) is not a receiver: a namespace-scoped constant such as
            // `example::DefaultPrefix` is referenced unqualified from inside the namespace and
            // qualified from outside, exactly like a global. Treating a module owner as a
            // member-field owner makes the receiver/owner-context match reject every valid
            // reference, so resolve it as a global field instead.
            let owner = type_owner_of(analyzer, target);
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
            // Free functions declared inside a namespace have a module owner; that namespace is
            // not a call receiver, so resolve them as free functions rather than methods.
            let owner = type_owner_of(analyzer, target);
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

    pub(super) fn new(
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

pub(in crate::analyzer::usages) struct VisibilityIndex {
    pub(super) visible_by_file: HashMap<ProjectFile, HashSet<CodeUnit>>,
    aliases_by_file: HashMap<ProjectFile, Vec<CppAlias>>,
}

struct CppAlias {
    name: String,
    target: String,
}

impl VisibilityIndex {
    pub(in crate::analyzer::usages) fn build(
        cpp: &CppAnalyzer,
        analyzer: &dyn IAnalyzer,
        roots: &HashSet<ProjectFile>,
    ) -> Self {
        let mut files = HashSet::default();
        for file in roots {
            collect_include_closure(cpp, analyzer, file, &mut files);
        }
        let declarations_by_file: HashMap<ProjectFile, BTreeSet<CodeUnit>> = files
            .iter()
            .map(|file| (file.clone(), analyzer.get_declarations(file)))
            .collect();
        let mut visible_by_file = HashMap::default();
        for file in roots {
            let mut visited = HashSet::default();
            let mut visible = HashSet::default();
            collect_visible_declarations(
                cpp,
                analyzer,
                &declarations_by_file,
                file,
                &mut visited,
                &mut visible,
            );
            visible_by_file.insert(file.clone(), visible);
        }
        let aliases_by_file = build_alias_index(&files);
        Self {
            visible_by_file,
            aliases_by_file,
        }
    }

    pub(super) fn is_visible(&self, file: &ProjectFile, target: &CodeUnit) -> bool {
        file == target.source()
            || self
                .visible_by_file
                .get(file)
                .is_some_and(|visible| visible.iter().any(|unit| same_visible_symbol(unit, target)))
    }

    pub(in crate::analyzer::usages) fn visible_units<'a>(
        &'a self,
        file: &ProjectFile,
    ) -> Box<dyn Iterator<Item = &'a CodeUnit> + 'a> {
        match self.visible_by_file.get(file) {
            Some(visible) => Box::new(visible.iter()),
            None => Box::new(std::iter::empty()),
        }
    }

    pub(in crate::analyzer::usages) fn resolve_type(
        &self,
        file: &ProjectFile,
        raw_name: &str,
    ) -> Option<CodeUnit> {
        let normalized = normalize_reference_name(raw_name)?;
        self.visible_by_file
            .get(file)?
            .iter()
            .filter(|unit| unit.kind() == CodeUnitType::Class || is_type_alias(unit))
            .find(|unit| reference_matches_unit(&normalized, unit))
            .cloned()
    }

    pub(super) fn resolves_to_type(
        &self,
        file: &ProjectFile,
        raw_name: &str,
        target: &CodeUnit,
    ) -> bool {
        let Some(resolved) = self.resolve_type(file, raw_name) else {
            return self.parser_alias_resolves_to_type(file, raw_name, target);
        };
        same_symbol(&resolved, target)
            || same_visible_symbol(&resolved, target)
            || self
                .alias_target(&resolved)
                .is_some_and(|alias_target| same_visible_symbol(&alias_target, target))
            || self.parser_alias_resolves_to_type(file, raw_name, target)
    }

    pub(super) fn alias_target(&self, alias: &CodeUnit) -> Option<CodeUnit> {
        let signature = alias.signature()?;
        let raw_target = signature
            .strip_prefix("using ")
            .and_then(|rest| rest.split_once('=').map(|(_, rhs)| rhs))
            .or_else(|| {
                signature
                    .strip_prefix("typedef ")
                    .and_then(|rest| rest.rsplit_once(' ').map(|(lhs, _)| lhs))
            })?
            .trim()
            .trim_end_matches(';')
            .trim();
        self.visible_by_file
            .get(alias.source())?
            .iter()
            .filter(|unit| unit.kind() == CodeUnitType::Class)
            .find(|unit| reference_matches_unit(raw_target, unit))
            .cloned()
    }

    pub(super) fn parser_alias_resolves_to_type(
        &self,
        file: &ProjectFile,
        raw_name: &str,
        target: &CodeUnit,
    ) -> bool {
        let Some(alias_name) = normalize_reference_name(raw_name) else {
            return false;
        };
        self.visible_source_files(file)
            .into_iter()
            .any(|source_file| {
                self.aliases_by_file
                    .get(&source_file)
                    .is_some_and(|aliases| {
                        aliases.iter().any(|alias| {
                            alias.name == alias_name
                                && type_text_matches_target(&alias.target, target)
                        })
                    })
            })
    }

    pub(super) fn visible_source_files(&self, file: &ProjectFile) -> HashSet<ProjectFile> {
        let mut files = HashSet::default();
        files.insert(file.clone());
        if let Some(visible) = self.visible_by_file.get(file) {
            files.extend(visible.iter().map(|unit| unit.source().clone()));
        }
        files
    }

    pub(in crate::analyzer::usages) fn resolve_named(
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

    pub(super) fn contains_named_symbol(
        &self,
        file: &ProjectFile,
        raw_name: &str,
        kind: TargetKind,
        target: &CodeUnit,
    ) -> bool {
        let Some(normalized) = normalize_reference_name(raw_name) else {
            return false;
        };
        self.visible_by_file.get(file).is_some_and(|visible| {
            visible.iter().any(|unit| {
                matches_kind_for_lookup(unit, kind)
                    && reference_matches_unit(&normalized, unit)
                    && same_visible_symbol(unit, target)
            })
        })
    }

    pub(super) fn resolve_known_non_target(
        &self,
        file: &ProjectFile,
        raw_name: &str,
        kind: TargetKind,
        target: &CodeUnit,
    ) -> bool {
        let Some(normalized) = normalize_reference_name(raw_name) else {
            return false;
        };
        normalized.contains("::")
            && self.visible_by_file.get(file).is_some_and(|visible| {
                visible.iter().any(|unit| {
                    matches_kind_for_lookup(unit, kind)
                        && reference_matches_unit(&normalized, unit)
                        && !same_visible_symbol(unit, target)
                })
            })
    }

    pub(super) fn resolve_call_return_type(
        &self,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        raw_name: &str,
        arity: usize,
        lexical_namespace: Option<&str>,
    ) -> Option<CodeUnit> {
        let normalized = normalize_reference_name(raw_name)?;
        let visible = self.visible_by_file.get(file)?;
        let mut candidates = Vec::new();
        for function in visible.iter().filter(|unit| {
            matches_kind_for_lookup(unit, TargetKind::FreeFunction)
                && reference_matches_unit(&normalized, unit)
        }) {
            let signature = cpp_function_signature_text(analyzer, function)?;
            if signature_arity(Some(&signature)) == arity {
                candidates.push((function, signature));
            }
        }
        if !normalized.contains("::")
            && let Some(namespace) = lexical_namespace
        {
            let scoped: Vec<_> = candidates
                .iter()
                .filter(|(function, _)| cpp_namespace_for(function).as_deref() == Some(namespace))
                .cloned()
                .collect();
            if !scoped.is_empty() {
                candidates = scoped;
            }
        }
        let mut resolved_return: Option<CodeUnit> = None;
        for (_function, signature) in candidates {
            let return_text = cpp_function_return_type_text_from_signature(&signature)?;
            let return_type = self.resolve_type(file, &return_text)?;
            if let Some(existing) = resolved_return.as_ref()
                && !same_visible_symbol(existing, &return_type)
            {
                return None;
            }
            resolved_return = Some(return_type);
        }
        resolved_return
    }
}

pub(in crate::analyzer::usages) fn infer_cpp_initializer_type(
    analyzer: &dyn IAnalyzer,
    visibility: &VisibilityIndex,
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
) -> Option<CodeUnit> {
    match node.kind() {
        "new_expression" => {
            let text = normalize_cpp_whitespace(node_text(node, source));
            let rest = text.strip_prefix("new ").unwrap_or(text.as_str());
            visibility.resolve_type(file, rest.split(['(', '{']).next().unwrap_or(rest))
        }
        "call_expression" => node.child_by_field_name("function").and_then(|function| {
            let function_text = node_text(function, source);
            visibility.resolve_type(file, function_text).or_else(|| {
                visibility.resolve_call_return_type(
                    analyzer,
                    file,
                    function_text,
                    call_arity(node),
                    enclosing_namespace_context(node, source).as_deref(),
                )
            })
        }),
        _ => None,
    }
}

fn build_alias_index(files: &HashSet<ProjectFile>) -> HashMap<ProjectFile, Vec<CppAlias>> {
    let mut parser = Parser::new();
    if parser
        .set_language(&tree_sitter_cpp::LANGUAGE.into())
        .is_err()
    {
        return HashMap::default();
    }

    let mut aliases_by_file = HashMap::default();
    for file in files {
        let Ok(source) = file.read_to_string() else {
            continue;
        };
        let Some(tree) = parser.parse(source.as_str(), None) else {
            continue;
        };
        let mut aliases = Vec::new();
        collect_cpp_aliases(tree.root_node(), &source, &mut aliases);
        if !aliases.is_empty() {
            aliases_by_file.insert(file.clone(), aliases);
        }
    }
    aliases_by_file
}

fn collect_cpp_aliases(node: Node<'_>, source: &str, out: &mut Vec<CppAlias>) {
    match node.kind() {
        "alias_declaration" if alias_has_visible_file_scope(node) => {
            if let Some(alias) = cpp_alias_from_alias_declaration(node, source) {
                out.push(alias);
            }
        }
        "type_definition" if alias_has_visible_file_scope(node) => {
            collect_typedef_aliases(node, source, out)
        }
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_cpp_aliases(child, source, out);
    }
}

fn alias_has_visible_file_scope(node: Node<'_>) -> bool {
    let mut current = node.parent();
    while let Some(parent) = current {
        match parent.kind() {
            "translation_unit"
            | "namespace_definition"
            | "declaration_list"
            | "linkage_specification" => current = parent.parent(),
            _ => return false,
        }
    }
    true
}

fn cpp_alias_from_alias_declaration(node: Node<'_>, source: &str) -> Option<CppAlias> {
    let name = node
        .child_by_field_name("name")
        .and_then(|node| normalize_reference_name(node_text(node, source)))?;
    let target = node
        .child_by_field_name("type")
        .and_then(|node| normalize_reference_name(node_text(node, source)))?;
    Some(CppAlias { name, target })
}

fn collect_typedef_aliases(node: Node<'_>, source: &str, out: &mut Vec<CppAlias>) {
    let Some(type_node) = node.child_by_field_name("type") else {
        return;
    };
    let Some(target) = normalize_reference_name(node_text(type_node, source)) else {
        return;
    };

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if same_node(child, type_node) {
            continue;
        }
        if let Some(name) = extract_typedef_declarator_name(child, source) {
            out.push(CppAlias {
                name,
                target: target.clone(),
            });
        }
    }
}

fn extract_typedef_declarator_name(node: Node<'_>, source: &str) -> Option<String> {
    match node.kind() {
        "identifier" | "field_identifier" | "type_identifier" | "qualified_identifier" => {
            normalize_reference_name(node_text(node, source))
        }
        _ => node
            .child_by_field_name("declarator")
            .or_else(|| node.child_by_field_name("name"))
            .or_else(|| last_named_child(node))
            .and_then(|child| extract_typedef_declarator_name(child, source)),
    }
}

fn last_named_child(node: Node<'_>) -> Option<Node<'_>> {
    let count = node.named_child_count();
    if count == 0 {
        None
    } else {
        node.named_child(count - 1)
    }
}

pub(super) fn collect_include_closure(
    cpp: &CppAnalyzer,
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    out: &mut HashSet<ProjectFile>,
) {
    let mut stack = vec![file.clone()];
    while let Some(file) = stack.pop() {
        if !out.insert(file.clone()) {
            continue;
        }
        for include in cpp_include_paths(analyzer.import_statements(&file)) {
            for target in
                resolve_include_targets_with_unique_fallback(cpp.project(), &file, &include)
            {
                stack.push(target);
            }
        }
    }
}

pub(super) fn collect_visible_declarations(
    cpp: &CppAnalyzer,
    analyzer: &dyn IAnalyzer,
    declarations_by_file: &HashMap<ProjectFile, BTreeSet<CodeUnit>>,
    file: &ProjectFile,
    visited: &mut HashSet<ProjectFile>,
    out: &mut HashSet<CodeUnit>,
) {
    let mut stack = vec![file.clone()];
    while let Some(file) = stack.pop() {
        if !visited.insert(file.clone()) {
            continue;
        }
        if let Some(declarations) = declarations_by_file.get(&file) {
            out.extend(declarations.iter().cloned());
        }
        for include in cpp_include_paths(analyzer.import_statements(&file)) {
            for target in
                resolve_include_targets_with_unique_fallback(cpp.project(), &file, &include)
            {
                stack.push(target);
            }
        }
    }
}

pub(in crate::analyzer::usages) fn signature_arity(signature: Option<&str>) -> usize {
    let Some(signature) = signature else {
        return 0;
    };
    let inner = signature
        .find('(')
        .and_then(|open| {
            signature[open + 1..]
                .find(')')
                .map(|close| &signature[open + 1..open + 1 + close])
        })
        .unwrap_or(signature)
        .trim();
    if inner.is_empty() || inner == "void" {
        return 0;
    }
    split_top_level_commas(inner).count()
}

pub(in crate::analyzer::usages) fn call_arity(node: Node<'_>) -> usize {
    node.child_by_field_name("arguments")
        .or_else(|| node.child_by_field_name("parameters"))
        .or_else(|| node.child_by_field_name("value"))
        .or_else(|| first_named_child_of_kind(node, "argument_list"))
        .or_else(|| first_named_child_of_kind(node, "initializer_list"))
        .map(|args| args.named_child_count())
        .unwrap_or(0)
}

pub(in crate::analyzer::usages) fn constructor_type_node(node: Node<'_>) -> Option<Node<'_>> {
    match node.kind() {
        "new_expression" => node
            .child_by_field_name("type")
            .or_else(|| node.named_child(0)),
        "compound_literal_expression" => node.child_by_field_name("type"),
        "call_expression" => node.child_by_field_name("function"),
        _ => None,
    }
}

pub(super) fn field_initializer_constructs_target(
    node: Node<'_>,
    ctx: &ScanCtx<'_>,
    owner: &CodeUnit,
) -> bool {
    let Some(name) = node
        .child_by_field_name("name")
        .or_else(|| first_named_child_of_kind(node, "field_identifier"))
        .or_else(|| first_named_child_of_kind(node, "qualified_identifier"))
    else {
        return false;
    };
    let field_name = node_text(name, ctx.source);
    ctx.visibility
        .visible_by_file
        .get(ctx.file)
        .into_iter()
        .flatten()
        .filter(|unit| unit.is_field() && unit.identifier() == field_name)
        .any(|unit| field_declares_type(unit, ctx, owner))
}

fn field_declares_type(unit: &CodeUnit, ctx: &ScanCtx<'_>, owner: &CodeUnit) -> bool {
    unit.signature()
        .is_some_and(|declaration| field_declaration_type_matches(declaration, unit, ctx, owner))
        || ctx
            .analyzer
            .get_source(unit, false)
            .is_some_and(|declaration| {
                field_declaration_type_matches(&declaration, unit, ctx, owner)
            })
}

fn field_declaration_type_matches(
    declaration: &str,
    unit: &CodeUnit,
    ctx: &ScanCtx<'_>,
    owner: &CodeUnit,
) -> bool {
    ctx.visibility
        .resolves_to_type(ctx.file, declaration, owner)
        || field_type_prefix(declaration, unit.identifier()).is_some_and(|type_text| {
            let normalized = normalize_field_type_text(type_text);
            ctx.visibility.resolves_to_type(ctx.file, type_text, owner)
                || ctx
                    .visibility
                    .resolves_to_type(ctx.file, normalized.as_str(), owner)
        })
}

fn field_type_prefix<'a>(declaration: &'a str, field_name: &str) -> Option<&'a str> {
    let declaration = declaration
        .split(['=', ';'])
        .next()
        .unwrap_or(declaration)
        .trim();
    let index = declaration.rfind(field_name)?;
    let before = &declaration[..index];
    let after = &declaration[index + field_name.len()..];
    if before.chars().next_back().is_some_and(is_identifier_char)
        || after.chars().next().is_some_and(is_identifier_char)
    {
        return None;
    }
    Some(before.trim())
}

fn normalize_field_type_text(type_text: &str) -> String {
    const FIELD_SPECIFIERS: [&str; 7] = [
        "static ",
        "mutable ",
        "constexpr ",
        "constinit ",
        "inline ",
        "volatile ",
        "const ",
    ];

    let mut normalized = normalize_type_text(type_text);
    loop {
        let Some(stripped) = FIELD_SPECIFIERS
            .iter()
            .find_map(|specifier| normalized.strip_prefix(specifier))
        else {
            return normalized;
        };
        normalized = normalize_type_text(stripped);
    }
}

fn is_identifier_char(ch: char) -> bool {
    ch == '_' || ch.is_ascii_alphanumeric()
}

pub(super) fn declaration_mentions_type(
    node: Node<'_>,
    ctx: &ScanCtx<'_>,
    owner: &CodeUnit,
) -> bool {
    let Some(type_node) = node.child_by_field_name("type") else {
        return false;
    };
    ctx.visibility
        .resolves_to_type(ctx.file, node_text(type_node, ctx.source), owner)
}

pub(super) fn declaration_is_object_construction_candidate(
    node: Node<'_>,
    ctx: &ScanCtx<'_>,
) -> bool {
    !ctx.analyzer
        .get_declarations(ctx.file)
        .into_iter()
        .filter(|unit| unit.is_function())
        .any(|unit| {
            ctx.analyzer.ranges(&unit).iter().any(|range| {
                node.start_byte() <= range.start_byte && range.end_byte <= node.end_byte()
            })
        })
}

pub(super) fn declaration_constructor_arity(node: Node<'_>, _ctx: &ScanCtx<'_>) -> usize {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() == "init_declarator" {
            return child
                .child_by_field_name("value")
                .or_else(|| first_named_child_of_kind(child, "initializer_list"))
                .or_else(|| first_named_child_of_kind(child, "compound_literal_expression"))
                .map(declaration_init_value_arity)
                .unwrap_or(0);
        }
        if is_declarator_node(child) {
            return declaration_declarator_arity(child);
        }
    }
    0
}

fn declaration_init_value_arity(value: Node<'_>) -> usize {
    match value.kind() {
        "argument_list" | "initializer_list" => count_non_comment_named_children(value),
        "compound_literal_expression" => call_arity(value),
        _ => 1,
    }
}

fn declaration_declarator_arity(node: Node<'_>) -> usize {
    if let Some(parameters) = node.child_by_field_name("parameters") {
        return count_non_comment_named_children(parameters);
    }
    node.child_by_field_name("declarator")
        .map(declaration_declarator_arity)
        .unwrap_or(0)
}

fn count_non_comment_named_children(node: Node<'_>) -> usize {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .filter(|child| child.kind() != "comment")
        .count()
}

fn first_named_child_of_kind<'tree>(node: Node<'tree>, kind: &str) -> Option<Node<'tree>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| child.kind() == kind)
}

pub(in crate::analyzer::usages) fn split_top_level_commas(
    value: &str,
) -> impl Iterator<Item = &str> {
    struct TopLevelCommaSplit<'a> {
        value: &'a str,
        start: usize,
        angle: usize,
        paren: usize,
        brace: usize,
        bracket: usize,
    }

    impl<'a> Iterator for TopLevelCommaSplit<'a> {
        type Item = &'a str;

        fn next(&mut self) -> Option<Self::Item> {
            if self.start > self.value.len() {
                return None;
            }
            for (offset, ch) in self.value[self.start..].char_indices() {
                let absolute = self.start + offset;
                match ch {
                    '<' => self.angle += 1,
                    '>' => self.angle = self.angle.saturating_sub(1),
                    '(' => self.paren += 1,
                    ')' => self.paren = self.paren.saturating_sub(1),
                    '{' => self.brace += 1,
                    '}' => self.brace = self.brace.saturating_sub(1),
                    '[' => self.bracket += 1,
                    ']' => self.bracket = self.bracket.saturating_sub(1),
                    ',' if self.angle == 0
                        && self.paren == 0
                        && self.brace == 0
                        && self.bracket == 0 =>
                    {
                        let item = self.value[self.start..absolute].trim();
                        self.start = absolute + ch.len_utf8();
                        return Some(item);
                    }
                    _ => {}
                }
            }
            let item = self.value[self.start..].trim();
            self.start = self.value.len() + 1;
            Some(item)
        }
    }

    TopLevelCommaSplit {
        value,
        start: 0,
        angle: 0,
        paren: 0,
        brace: 0,
        bracket: 0,
    }
    .filter(|item| !item.is_empty())
}

pub(in crate::analyzer::usages) fn extract_variable_name(
    node: Node<'_>,
    source: &str,
) -> Option<String> {
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

pub(in crate::analyzer::usages) fn is_declarator_node(node: Node<'_>) -> bool {
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

pub(in crate::analyzer::usages) fn first_type_child(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).find(|child| {
        matches!(
            child.kind(),
            "type_identifier"
                | "primitive_type"
                | "qualified_identifier"
                | "scoped_type_identifier"
                | "struct_specifier"
                | "union_specifier"
                | "enum_specifier"
        )
    })
}

pub(in crate::analyzer::usages) fn is_declaration_name(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    parent.child_by_field_name("name") == Some(node)
        || parent.kind() == "enumerator"
        || matches!(parent.kind(), "function_declarator" | "init_declarator")
            && parent
                .child_by_field_name("declarator")
                .is_some_and(|declarator| node_contains(declarator, node))
}

fn node_contains(parent: Node<'_>, child: Node<'_>) -> bool {
    parent.start_byte() <= child.start_byte() && child.end_byte() <= parent.end_byte()
}

pub(super) fn has_ancestor_kind(node: Node<'_>, kind: &str) -> bool {
    let mut current = node.parent();
    while let Some(parent) = current {
        if parent.kind() == kind {
            return true;
        }
        current = parent.parent();
    }
    false
}

pub(super) fn function_terminal_node(node: Node<'_>) -> Node<'_> {
    node.child_by_field_name("field")
        .or_else(|| node.child_by_field_name("name"))
        .unwrap_or(node)
}

pub(in crate::analyzer::usages) fn normalize_type_text(value: &str) -> String {
    strip_tag_type_prefix(
        normalize_cpp_whitespace(value)
            .trim_start_matches("const ")
            .trim_end_matches('*')
            .trim_end_matches('&')
            .trim(),
    )
    .to_string()
}

fn strip_tag_type_prefix(value: &str) -> &str {
    let value = value.trim_start_matches("const ");
    value
        .strip_prefix("struct ")
        .or_else(|| value.strip_prefix("class "))
        .or_else(|| value.strip_prefix("enum "))
        .unwrap_or(value)
        .trim()
}

pub(super) fn normalize_reference_name(value: &str) -> Option<String> {
    let normalized = normalize_cpp_reference_text(value);
    (!normalized.is_empty()).then_some(normalized)
}

pub(super) fn normalize_cpp_reference_text(value: &str) -> String {
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
    let normalized = text
        .trim()
        .trim_start_matches("const ")
        .trim_end_matches(|ch: char| ch == '*' || ch == '&' || ch.is_whitespace())
        .trim_matches(':')
        .trim();
    strip_tag_type_prefix(normalized).to_string()
}

pub(in crate::analyzer::usages) fn cpp_name_for(unit: &CodeUnit) -> String {
    let short = unit.short_name().replace(['.', '$'], "::");
    if unit.package_name().is_empty() {
        short
    } else {
        format!("{}::{}", unit.package_name(), short)
    }
}

pub(super) fn terminal_name(value: &str) -> &str {
    value
        .rsplit("::")
        .next()
        .unwrap_or(value)
        .rsplit(['.', '-', '>'])
        .next()
        .unwrap_or(value)
        .trim()
}

pub(super) fn name_matches_terminal(value: &str, expected: &str) -> bool {
    terminal_name(&normalize_cpp_reference_text(value)) == expected
}

pub(super) fn name_matches_callable(value: &str, expected: &str) -> bool {
    name_matches_terminal(value, expected)
        || expected.starts_with("operator")
            && terminal_name(&normalize_cpp_reference_text(value)) == "operator"
}

pub(super) fn name_mentions(value: &str, expected: &str) -> bool {
    normalize_cpp_reference_text(value)
        .split("::")
        .any(|part| part == expected)
}

pub(super) fn reference_matches_unit(reference: &str, unit: &CodeUnit) -> bool {
    let cpp_name = cpp_name_for(unit);
    if reference.contains("::") {
        return reference == cpp_name;
    }
    reference == cpp_name
        || terminal_name(reference) == unit.identifier()
            && (unit.package_name().is_empty() || reference == unit.identifier())
}

pub(super) fn matches_kind_for_lookup(unit: &CodeUnit, kind: TargetKind) -> bool {
    match kind {
        TargetKind::Type
        | TargetKind::Constructor
        | TargetKind::Method
        | TargetKind::MemberField => true,
        TargetKind::FreeFunction => unit.is_function(),
        TargetKind::GlobalField => unit.is_field(),
    }
}

pub(super) fn is_type_alias(unit: &CodeUnit) -> bool {
    unit.kind() == CodeUnitType::Field
        && unit.signature().is_some_and(|signature| {
            signature.starts_with("typedef ") || signature.starts_with("using ")
        })
}

pub(super) fn type_text_matches_target(type_text: &str, target: &CodeUnit) -> bool {
    let normalized = normalize_cpp_reference_text(type_text.trim().trim_end_matches(';'));
    normalized == cpp_name_for(target) || normalized == target.identifier()
}

/// The declared return type text of a C++ function unit, with leading declaration specifiers
/// stripped, e.g. `T*` for `T* operator->()`.
pub(in crate::analyzer::usages) fn cpp_function_return_type_text(
    analyzer: &dyn IAnalyzer,
    function: &CodeUnit,
) -> Option<String> {
    let signature = cpp_function_signature_text(analyzer, function)?;
    cpp_function_return_type_text_from_signature(&signature)
}

fn cpp_function_signature_text(analyzer: &dyn IAnalyzer, function: &CodeUnit) -> Option<String> {
    function
        .signature()
        .filter(|signature| signature.contains(function.identifier()))
        .map(str::to_string)
        .or_else(|| analyzer.signatures(function).first().cloned())
        .or_else(|| analyzer.get_source(function, false))
}

fn cpp_function_return_type_text_from_signature(signature: &str) -> Option<String> {
    let open = signature.find('(')?;
    let name_at = cpp_function_name_start(signature, open)?;
    if let Some(return_type) = cpp_trailing_return_type(&signature[name_at..]) {
        return Some(return_type);
    }
    let type_text = cpp_strip_leading_template_clause(&signature[..name_at])
        .split_whitespace()
        .filter(|token| {
            !matches!(
                *token,
                "static" | "virtual" | "inline" | "constexpr" | "explicit" | "friend"
            )
        })
        .collect::<Vec<_>>()
        .join(" ");
    let type_text = type_text.trim();
    (!type_text.is_empty()).then(|| type_text.to_string())
}

fn cpp_function_name_start(signature: &str, open: usize) -> Option<usize> {
    let before_parameters = &signature[..open];
    if let Some(operator_at) = before_parameters.rfind("operator") {
        let boundary = operator_at == 0
            || before_parameters[..operator_at]
                .chars()
                .next_back()
                .is_some_and(|ch| !(ch == '_' || ch.is_ascii_alphanumeric()));
        if boundary {
            return Some(operator_at);
        }
    }
    before_parameters
        .rfind(|ch: char| !(ch == '_' || ch.is_ascii_alphanumeric()))
        .map(|index| index + 1)
}

fn cpp_trailing_return_type(signature_from_name: &str) -> Option<String> {
    let open = signature_from_name.find('(')?;
    let mut depth = 0i32;
    for (offset, ch) in signature_from_name[open..].char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    let rest = signature_from_name[open + offset + ch.len_utf8()..].trim_start();
                    let arrow = rest.find("->")?;
                    let return_type = rest[arrow + 2..].trim_start();
                    let return_type = return_type
                        .split(['{', ';'])
                        .next()
                        .unwrap_or(return_type)
                        .trim();
                    return (!return_type.is_empty()).then(|| return_type.to_string());
                }
            }
            _ => {}
        }
    }
    None
}

/// Strip a leading `template <...>` parameter clause, leaving the declaration that follows.
/// Returns the input unchanged when there is no such clause.
fn cpp_strip_leading_template_clause(text: &str) -> &str {
    let trimmed = text.trim_start();
    let Some(rest) = trimmed.strip_prefix("template") else {
        return text;
    };
    let rest = rest.trim_start();
    if !rest.starts_with('<') {
        return text;
    }
    let mut depth = 0i32;
    for (offset, ch) in rest.char_indices() {
        match ch {
            '<' => depth += 1,
            '>' => {
                depth -= 1;
                if depth == 0 {
                    return rest[offset + ch.len_utf8()..].trim_start();
                }
            }
            _ => {}
        }
    }
    text
}

pub(super) fn cpp_namespace_for(unit: &CodeUnit) -> Option<String> {
    cpp_name_for(unit).rsplit_once("::").map(|(namespace, _)| {
        namespace
            .strip_prefix("anonymous_namespace::")
            .unwrap_or(namespace)
            .to_string()
    })
}

pub(in crate::analyzer::usages) fn enclosing_namespace_context(
    node: Node<'_>,
    source: &str,
) -> Option<String> {
    let mut namespaces = Vec::new();
    let mut current = node.parent();
    while let Some(parent) = current {
        if parent.kind() == "namespace_definition"
            && let Some(name) = parent.child_by_field_name("name")
        {
            let namespace = normalize_cpp_reference_text(node_text(name, source));
            if !namespace.is_empty() {
                namespaces.push(namespace);
            }
        }
        current = parent.parent();
    }
    if namespaces.is_empty() {
        None
    } else {
        namespaces.reverse();
        Some(namespaces.join("::"))
    }
}

/// Like [`precise_parent_of`], but drops module (namespace) parents. A namespace is a scope, not a
/// type or receiver, so namespace-scoped functions and constants resolve as free functions and
/// globals rather than members.
pub(super) fn type_owner_of(analyzer: &dyn IAnalyzer, code_unit: &CodeUnit) -> Option<CodeUnit> {
    precise_parent_of(analyzer, code_unit).filter(|owner| !owner.is_module())
}

pub(super) fn precise_parent_of(
    analyzer: &dyn IAnalyzer,
    code_unit: &CodeUnit,
) -> Option<CodeUnit> {
    let fallback = analyzer.parent_of(code_unit);
    let Some(owner_name) = code_unit
        .short_name()
        .rsplit_once('.')
        .map(|(owner, _)| owner)
    else {
        return fallback;
    };
    analyzer
        .get_all_declarations()
        .into_iter()
        .find(|candidate| {
            candidate.is_class()
                && candidate.source() == code_unit.source()
                && candidate.short_name() == owner_name
                && candidate.package_name() == code_unit.package_name()
        })
        .or_else(|| {
            fallback.filter(|parent| {
                parent.short_name() == owner_name
                    && parent.package_name() == code_unit.package_name()
            })
        })
}

pub(super) fn visible_owner_from_member_name(
    ctx: &ScanCtx<'_>,
    code_unit: &CodeUnit,
) -> Option<CodeUnit> {
    let owner_name = code_unit
        .short_name()
        .rsplit_once('.')
        .map(|(owner, _)| owner)?;
    ctx.visibility
        .visible_by_file
        .get(ctx.file)?
        .iter()
        .find(|candidate| {
            candidate.is_class()
                && candidate.short_name() == owner_name
                && candidate.package_name() == code_unit.package_name()
        })
        .cloned()
}

pub(super) fn same_symbol(left: &CodeUnit, right: &CodeUnit) -> bool {
    left.kind() == right.kind()
        && left.fq_name() == right.fq_name()
        && left.signature() == right.signature()
        && left.source() == right.source()
}

pub(super) fn same_visible_symbol(left: &CodeUnit, right: &CodeUnit) -> bool {
    same_symbol(left, right) || same_logical_symbol(left, right)
}

pub(super) fn same_logical_symbol(left: &CodeUnit, right: &CodeUnit) -> bool {
    left.kind() == right.kind()
        && left.fq_name() == right.fq_name()
        && left.signature() == right.signature()
}
