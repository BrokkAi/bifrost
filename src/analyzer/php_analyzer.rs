use crate::analyzer::clone_detection::{
    CloneCandidateData, CloneCandidateProfile, compact_clone_excerpt,
    compute_ast_refinement_similarity_percent, detect_structural_clone_smells,
};
use crate::analyzer::{
    AnalyzerConfig, CodeUnit, CodeUnitType, IAnalyzer, Language, LanguageAdapter, Project,
    ProjectFile, Range, TestAssertionSmell, TestAssertionWeights, TestDetectionProvider,
    TreeSitterAnalyzer,
};
use crate::{CloneSmell, CloneSmellWeights};
use regex::Regex;
use std::collections::BTreeSet;
use std::sync::{Arc, LazyLock};
use tree_sitter::{Language as TsLanguage, Node, Parser, Point, Tree};

#[derive(Debug, Clone, Default)]
pub struct PhpAdapter;

impl LanguageAdapter for PhpAdapter {
    fn language(&self) -> Language {
        Language::Php
    }

    fn query_directory(&self) -> &'static str {
        "resources/treesitter/php"
    }

    fn parser_language(&self) -> TsLanguage {
        tree_sitter_php::LANGUAGE_PHP.into()
    }

    fn file_extension(&self) -> &'static str {
        "php"
    }

    fn contains_tests(
        &self,
        _file: &ProjectFile,
        source: &str,
        _tree: &Tree,
        parsed: &crate::analyzer::tree_sitter_analyzer::ParsedFile,
    ) -> bool {
        php_contains_tests(source, parsed)
    }

    fn extract_call_receiver(&self, reference: &str) -> Option<String> {
        let trimmed = reference.trim();
        let before_args = trimmed
            .split_once('(')
            .map(|(head, _)| head)
            .unwrap_or(trimmed);
        before_args
            .rsplit_once("::")
            .or_else(|| before_args.rsplit_once("->"))
            .map(|(receiver, _)| receiver.to_string())
    }

    fn parse_file(
        &self,
        file: &ProjectFile,
        source: &str,
        tree: &Tree,
    ) -> crate::analyzer::tree_sitter_analyzer::ParsedFile {
        let package_name = determine_php_package_name(tree.root_node(), source);
        let mut parsed = crate::analyzer::tree_sitter_analyzer::ParsedFile::new(package_name);
        let package_name = parsed.package_name.clone();
        let mut visitor = PhpVisitor {
            file,
            source,
            parsed: &mut parsed,
        };
        visitor.visit_children(tree.root_node(), &PhpScope::new(package_name, None));
        parsed
    }
}

#[derive(Clone)]
pub struct PhpAnalyzer {
    inner: TreeSitterAnalyzer<PhpAdapter>,
}

impl PhpAnalyzer {
    pub fn new(project: Arc<dyn Project>) -> Self {
        Self::new_with_config(project, AnalyzerConfig::default())
    }

    pub fn new_with_config(project: Arc<dyn Project>, config: AnalyzerConfig) -> Self {
        Self {
            inner: TreeSitterAnalyzer::new_with_config(project, PhpAdapter, config),
        }
    }

    pub fn new_with_config_and_storage(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        storage: Arc<crate::analyzer::persistence::AnalyzerStorage>,
    ) -> Self {
        Self {
            inner: TreeSitterAnalyzer::new_with_config_and_storage(
                project, PhpAdapter, config, storage,
            ),
        }
    }

    pub fn from_project<P>(project: P) -> Self
    where
        P: Project + 'static,
    {
        Self::new(Arc::new(project))
    }

    pub fn is_constructor(
        &self,
        method: &CodeUnit,
        class_unit: &CodeUnit,
        _package_name: &str,
    ) -> bool {
        method.is_function()
            && class_unit.is_class()
            && method.identifier() == "__construct"
            && method.fq_name() == format!("{}.__construct", class_unit.fq_name())
    }
}

impl TestDetectionProvider for PhpAnalyzer {}

impl IAnalyzer for PhpAnalyzer {
    fn top_level_declarations<'a>(
        &'a self,
        file: &ProjectFile,
    ) -> Box<dyn Iterator<Item = &'a CodeUnit> + 'a> {
        self.inner.top_level_declarations(file)
    }

    fn analyzed_files<'a>(&'a self) -> Box<dyn Iterator<Item = &'a ProjectFile> + 'a> {
        self.inner.analyzed_files()
    }

    fn all_declarations<'a>(&'a self) -> Box<dyn Iterator<Item = &'a CodeUnit> + 'a> {
        self.inner.all_declarations()
    }

    fn declarations<'a>(
        &'a self,
        file: &ProjectFile,
    ) -> Box<dyn Iterator<Item = &'a CodeUnit> + 'a> {
        self.inner.declarations(file)
    }

    fn definitions<'a>(&'a self, fq_name: &'a str) -> Box<dyn Iterator<Item = &'a CodeUnit> + 'a> {
        self.inner.definitions(fq_name)
    }

    fn direct_children<'a>(
        &'a self,
        code_unit: &CodeUnit,
    ) -> Box<dyn Iterator<Item = &'a CodeUnit> + 'a> {
        self.inner.direct_children(code_unit)
    }

    fn import_statements<'a>(&'a self, file: &ProjectFile) -> &'a [String] {
        self.inner.import_statements(file)
    }

    fn ranges<'a>(&'a self, code_unit: &CodeUnit) -> &'a [crate::analyzer::Range] {
        self.inner.ranges(code_unit)
    }

    fn compute_cognitive_complexities(&self, file: &ProjectFile) -> Vec<(CodeUnit, u32)> {
        self.inner.compute_cognitive_complexities(file)
    }

    fn signatures<'a>(&'a self, code_unit: &CodeUnit) -> &'a [String] {
        self.inner.signatures(code_unit)
    }

    fn get_top_level_declarations(&self, file: &ProjectFile) -> Vec<CodeUnit> {
        self.inner.get_top_level_declarations(file)
    }

    fn get_analyzed_files(&self) -> BTreeSet<ProjectFile> {
        self.inner.get_analyzed_files()
    }

    fn languages(&self) -> BTreeSet<Language> {
        self.inner.languages()
    }

    fn update(&self, changed_files: &BTreeSet<ProjectFile>) -> Self {
        Self {
            inner: self.inner.update(changed_files),
        }
    }

    fn update_all(&self) -> Self {
        Self {
            inner: self.inner.update_all(),
        }
    }

    fn project(&self) -> &dyn Project {
        self.inner.project()
    }

    fn get_all_declarations(&self) -> Vec<CodeUnit> {
        self.inner.get_all_declarations()
    }

    fn get_declarations(&self, file: &ProjectFile) -> BTreeSet<CodeUnit> {
        self.inner.get_declarations(file)
    }

    fn get_definitions(&self, fq_name: &str) -> Vec<CodeUnit> {
        self.inner.get_definitions(fq_name)
    }

    fn get_direct_children(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        self.inner.get_direct_children(code_unit)
    }

    fn extract_call_receiver(&self, reference: &str) -> Option<String> {
        self.inner.extract_call_receiver(reference)
    }

    fn import_statements_of(&self, file: &ProjectFile) -> Vec<String> {
        self.inner.import_statements_of(file)
    }

    fn enclosing_code_unit(&self, file: &ProjectFile, range: &Range) -> Option<CodeUnit> {
        self.inner.enclosing_code_unit(file, range)
    }

    fn enclosing_code_unit_for_lines(
        &self,
        file: &ProjectFile,
        start_line: usize,
        end_line: usize,
    ) -> Option<CodeUnit> {
        self.inner
            .enclosing_code_unit_for_lines(file, start_line, end_line)
    }

    fn is_access_expression(&self, file: &ProjectFile, start_byte: usize, end_byte: usize) -> bool {
        self.inner.is_access_expression(file, start_byte, end_byte)
    }

    fn find_nearest_declaration(
        &self,
        file: &ProjectFile,
        start_byte: usize,
        end_byte: usize,
        ident: &str,
    ) -> Option<crate::analyzer::DeclarationInfo> {
        self.inner
            .find_nearest_declaration(file, start_byte, end_byte, ident)
    }

    fn ranges_of(&self, code_unit: &CodeUnit) -> Vec<Range> {
        self.inner.ranges_of(code_unit)
    }

    fn get_skeleton(&self, code_unit: &CodeUnit) -> Option<String> {
        let skeleton = self.inner.get_skeleton(code_unit)?;
        if code_unit.is_class() && self.inner.direct_children(code_unit).next().is_none() {
            let trimmed = skeleton.trim();
            if trimmed.ends_with("{\n}") || trimmed.ends_with("{\r\n}") {
                let compact = trimmed.trim_end_matches('}').trim_end().to_string();
                return Some(format!("{compact} }}"));
            }
        }
        Some(skeleton)
    }

    fn get_skeleton_header(&self, code_unit: &CodeUnit) -> Option<String> {
        self.inner.get_skeleton_header(code_unit)
    }

    fn get_source(&self, code_unit: &CodeUnit, include_comments: bool) -> Option<String> {
        self.inner.get_source(code_unit, include_comments)
    }

    fn get_sources(&self, code_unit: &CodeUnit, include_comments: bool) -> BTreeSet<String> {
        self.inner.get_sources(code_unit, include_comments)
    }

    fn search_definitions(&self, pattern: &str, auto_quote: bool) -> BTreeSet<CodeUnit> {
        self.inner.search_definitions(pattern, auto_quote)
    }

    fn search_definitions_persisted(&self, pattern: &str) -> BTreeSet<CodeUnit> {
        self.inner.search_definitions_persisted(pattern)
    }

    fn signatures_of(&self, code_unit: &CodeUnit) -> Vec<String> {
        self.inner.signatures_of(code_unit).to_vec()
    }

    fn contains_tests(&self, file: &ProjectFile) -> bool {
        self.inner.contains_tests(file)
    }

    fn find_test_assertion_smells(
        &self,
        file: &ProjectFile,
        weights: TestAssertionWeights,
    ) -> Vec<TestAssertionSmell> {
        if !self.contains_tests(file) || file_language(file) != Language::Php {
            return Vec::new();
        }
        let Ok(source) = file.read_to_string() else {
            return Vec::new();
        };
        detect_php_test_assertion_smells(file, &source, &weights)
    }

    fn find_structural_clone_smells(
        &self,
        file: &ProjectFile,
        weights: CloneSmellWeights,
    ) -> Vec<CloneSmell> {
        self.find_structural_clone_smells_for_files(std::slice::from_ref(file), weights)
    }

    fn find_structural_clone_smells_for_files(
        &self,
        files: &[ProjectFile],
        weights: CloneSmellWeights,
    ) -> Vec<CloneSmell> {
        let requested_files: Vec<ProjectFile> = files
            .iter()
            .filter(|file| file_language(file) == Language::Php)
            .cloned()
            .collect();
        if requested_files.is_empty() {
            return Vec::new();
        }

        let all_candidates: Vec<CloneCandidateProfile> = self
            .get_all_declarations()
            .into_iter()
            .filter(|code_unit| {
                code_unit.is_function() && file_language(code_unit.source()) == Language::Php
            })
            .filter_map(|code_unit| self.build_clone_candidate_data(&code_unit, weights))
            .map(|candidate| CloneCandidateProfile::create(candidate, weights))
            .collect();
        if all_candidates.is_empty() {
            return Vec::new();
        }

        detect_structural_clone_smells(
            &requested_files,
            all_candidates,
            weights,
            refine_php_clone_similarity,
        )
    }

    fn test_detection_provider(&self) -> Option<&dyn TestDetectionProvider> {
        Some(self)
    }
}

impl PhpAnalyzer {
    fn build_clone_candidate_data(
        &self,
        code_unit: &CodeUnit,
        weights: CloneSmellWeights,
    ) -> Option<CloneCandidateData> {
        self.get_source(code_unit, false)
            .map(|source| source.trim().to_string())
            .filter(|source| !source.is_empty())
            .and_then(|source| {
                let normalized_tokens = normalized_clone_tokens_php(&source);
                if normalized_tokens.len() < weights.min_normalized_tokens.max(0) as usize {
                    return None;
                }
                Some(CloneCandidateData {
                    unit: code_unit.clone(),
                    normalized_tokens,
                    ast_signature: build_php_clone_ast_signature(&source),
                    excerpt: compact_clone_excerpt(&source),
                })
            })
    }
}

static PHP_TEST_METHOD_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?s)function\s+(?P<name>test[A-Za-z0-9_]+)\s*\([^)]*\)\s*:\s*void\s*\{(?P<body>.*?)\n\s*\}"#,
    )
    .expect("valid regex")
});
static PHP_ASSERT_EQUALITY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\$this->assert(?:Same|Equals)\s*\((?P<left>[^,\n]+?)\s*,\s*(?P<right>[^,\n\)]+)"#)
        .expect("valid regex")
});
static PHP_ASSERT_TRUTH_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\$this->assert(?P<matcher>True|False|Null|NotNull)\s*\((?P<arg>[^,\n\)]+)"#)
        .expect("valid regex")
});
static PHP_THROWS_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"\$this->expectException\s*\("#).expect("valid regex"));
static PHP_VERIFY_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"\$[A-Za-z_][A-Za-z0-9_]*->expects\s*\("#).expect("valid regex"));

#[derive(Clone)]
struct PhpAssertionSignal {
    kind: String,
    score: i32,
    shallow: bool,
    reason: String,
    excerpt: String,
    start_byte: usize,
}

fn detect_php_test_assertion_smells(
    file: &ProjectFile,
    source: &str,
    weights: &TestAssertionWeights,
) -> Vec<TestAssertionSmell> {
    let mut findings = Vec::new();
    for captures in PHP_TEST_METHOD_RE.captures_iter(source) {
        let Some(name_match) = captures.name("name") else {
            continue;
        };
        let Some(body_match) = captures.name("body") else {
            continue;
        };
        analyze_php_test_case(
            file,
            name_match.as_str(),
            body_match.as_str(),
            body_match.start(),
            weights,
            &mut findings,
        );
    }
    findings
}

fn analyze_php_test_case(
    file: &ProjectFile,
    name: &str,
    body: &str,
    start_byte: usize,
    weights: &TestAssertionWeights,
    out: &mut Vec<TestAssertionSmell>,
) {
    let assertions = collect_php_assertions(body, weights);
    let assertion_count = assertions.len() as i32;
    let symbol = format!("{}::{}", file, name);

    if assertion_count == 0 {
        out.push(TestAssertionSmell {
            file: file.clone(),
            enclosing_fq_name: symbol,
            assertion_kind: "no-assertions".to_string(),
            score: weights.no_assertion_weight,
            assertion_count: 0,
            reasons: vec!["no-assertions".to_string()],
            excerpt: compact_php_excerpt(body),
            start_byte,
        });
        return;
    }

    for assertion in &assertions {
        if assertion.score <= 0 {
            continue;
        }
        out.push(TestAssertionSmell {
            file: file.clone(),
            enclosing_fq_name: symbol.clone(),
            assertion_kind: assertion.kind.clone(),
            score: assertion.score,
            assertion_count,
            reasons: vec![assertion.reason.clone()],
            excerpt: assertion.excerpt.clone(),
            start_byte: start_byte + assertion.start_byte,
        });
    }

    if assertions.iter().all(|assertion| assertion.shallow) {
        out.push(TestAssertionSmell {
            file: file.clone(),
            enclosing_fq_name: symbol,
            assertion_kind: "shallow-assertions-only".to_string(),
            score: weights.shallow_assertion_only_weight,
            assertion_count,
            reasons: vec!["shallow-assertions-only".to_string()],
            excerpt: compact_php_excerpt(body),
            start_byte,
        });
    }
}

fn collect_php_assertions(body: &str, weights: &TestAssertionWeights) -> Vec<PhpAssertionSignal> {
    let mut assertions = Vec::new();

    for captures in PHP_ASSERT_EQUALITY_RE.captures_iter(body) {
        let whole = captures.get(0).expect("whole match");
        let left = normalize_php_expr(captures.name("left").map(|m| m.as_str()).unwrap_or(""));
        let right = normalize_php_expr(captures.name("right").map(|m| m.as_str()).unwrap_or(""));
        let signal = if left == right {
            let (kind, reason, score) = if is_php_literal(&left) {
                (
                    "constant-equality",
                    "constant-equality",
                    weights.constant_equality_weight,
                )
            } else {
                (
                    "self-comparison",
                    "self-comparison",
                    weights.tautological_assertion_weight,
                )
            };
            PhpAssertionSignal {
                kind: kind.to_string(),
                score,
                shallow: false,
                reason: reason.to_string(),
                excerpt: compact_php_excerpt(whole.as_str()),
                start_byte: whole.start(),
            }
        } else {
            PhpAssertionSignal {
                kind: "meaningful-assertion".to_string(),
                score: 0,
                shallow: false,
                reason: "meaningful-assertion".to_string(),
                excerpt: compact_php_excerpt(whole.as_str()),
                start_byte: whole.start(),
            }
        };
        assertions.push(signal);
    }

    for captures in PHP_ASSERT_TRUTH_RE.captures_iter(body) {
        let whole = captures.get(0).expect("whole match");
        let matcher = captures.name("matcher").map(|m| m.as_str()).unwrap_or("");
        let arg = normalize_php_expr(captures.name("arg").map(|m| m.as_str()).unwrap_or(""));
        let (kind, score, shallow) = match matcher {
            "True" if arg == "true" => ("constant-truth", weights.constant_truth_weight, true),
            "False" if arg == "false" => ("constant-truth", weights.constant_truth_weight, true),
            "Null" | "NotNull" => ("nullness-only", weights.nullness_only_weight, true),
            _ => ("meaningful-assertion", 0, false),
        };
        assertions.push(PhpAssertionSignal {
            kind: kind.to_string(),
            score,
            shallow,
            reason: kind.to_string(),
            excerpt: compact_php_excerpt(whole.as_str()),
            start_byte: whole.start(),
        });
    }

    for regex in [&*PHP_THROWS_RE, &*PHP_VERIFY_RE] {
        for captures in regex.captures_iter(body) {
            let whole = captures.get(0).expect("whole match");
            assertions.push(PhpAssertionSignal {
                kind: "meaningful-assertion".to_string(),
                score: 0,
                shallow: false,
                reason: "meaningful-assertion".to_string(),
                excerpt: compact_php_excerpt(whole.as_str()),
                start_byte: whole.start(),
            });
        }
    }

    assertions
}

fn normalize_php_expr(expr: &str) -> String {
    expr.trim()
        .trim_end_matches(';')
        .trim_matches(|ch| matches!(ch, '(' | ')' | ' '))
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn is_php_literal(expr: &str) -> bool {
    let trimmed = expr.trim();
    (trimmed.starts_with('"') && trimmed.ends_with('"'))
        || (trimmed.starts_with('\'') && trimmed.ends_with('\''))
        || matches!(trimmed, "true" | "false" | "null")
        || trimmed.parse::<i64>().is_ok()
        || trimmed.parse::<f64>().is_ok()
}

fn compact_php_excerpt(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn file_language(file: &ProjectFile) -> Language {
    file.rel_path()
        .extension()
        .and_then(|ext| ext.to_str())
        .map(Language::from_extension)
        .unwrap_or(Language::None)
}

const PHP_CLONE_AST_IDENTIFIER_TYPES: &[&str] = &["name", "variable_name"];
const PHP_CLONE_AST_STRING_TYPES: &[&str] = &["string", "encapsed_string", "string_value"];
const PHP_CLONE_AST_NUMBER_TYPES: &[&str] = &["integer", "float"];

fn normalized_clone_tokens_php(source: &str) -> Vec<String> {
    let parse_source = php_clone_parse_source(source);
    let Some(tree) = parse_php_tree(&parse_source) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    collect_normalized_leaf_tokens_php(tree.root_node(), &parse_source, &mut out);
    out
}

fn collect_normalized_leaf_tokens_php(node: Node<'_>, source: &str, out: &mut Vec<String>) {
    if php_is_ignorable_clone_logging_node(node, source) {
        return;
    }
    if node.named_child_count() == 0 {
        let token = normalize_php_clone_leaf_token(node, source);
        if !token.is_empty() {
            out.push(token);
        }
    }
    let child_count = node.child_count();
    for index in 0..child_count {
        if let Some(child) = node.child(index) {
            collect_normalized_leaf_tokens_php(child, source, out);
        }
    }
}

fn normalize_php_clone_leaf_token(node: Node<'_>, source: &str) -> String {
    let kind = node.kind();
    let token = source
        .get(node.start_byte()..node.end_byte())
        .unwrap_or("")
        .trim();
    if token.is_empty() || kind == "comment" {
        return String::new();
    }
    if PHP_CLONE_AST_IDENTIFIER_TYPES.contains(&kind) {
        return "ID".to_string();
    }
    if PHP_CLONE_AST_STRING_TYPES.contains(&kind) {
        return "STR".to_string();
    }
    if PHP_CLONE_AST_NUMBER_TYPES.contains(&kind) {
        return "NUM".to_string();
    }
    if matches!(kind, "boolean" | "boolean_literal") || matches!(token, "true" | "false") {
        return "BOOL".to_string();
    }
    if matches!(kind, "null" | "null_literal") || token == "null" {
        return "NULL".to_string();
    }
    if token.chars().count() == 1 && token.chars().all(|ch| !ch.is_alphanumeric()) {
        return format!("OP:{token}");
    }
    format!("T:{kind}")
}

fn build_php_clone_ast_signature(source: &str) -> String {
    let parse_source = php_clone_parse_source(source);
    let Some(tree) = parse_php_tree(&parse_source) else {
        return String::new();
    };
    let mut labels = Vec::new();
    collect_php_clone_ast_labels(tree.root_node(), &parse_source, &mut labels);
    labels.join("|")
}

fn collect_php_clone_ast_labels(node: Node<'_>, source: &str, out: &mut Vec<String>) {
    if php_is_ignorable_clone_logging_node(node, source) {
        return;
    }
    out.push(normalize_php_clone_ast_label(node, source));
    let child_count = node.child_count();
    for index in 0..child_count {
        if let Some(child) = node.child(index) {
            collect_php_clone_ast_labels(child, source, out);
        }
    }
}

fn normalize_php_clone_ast_label(node: Node<'_>, source: &str) -> String {
    let kind = node.kind();
    let text = source
        .get(node.start_byte()..node.end_byte())
        .unwrap_or("")
        .trim();
    if PHP_CLONE_AST_IDENTIFIER_TYPES.contains(&kind) {
        return "ID".to_string();
    }
    if PHP_CLONE_AST_STRING_TYPES.contains(&kind) {
        return "STR".to_string();
    }
    if PHP_CLONE_AST_NUMBER_TYPES.contains(&kind) {
        return "NUM".to_string();
    }
    if matches!(kind, "boolean" | "boolean_literal") || matches!(text, "true" | "false") {
        return "BOOL".to_string();
    }
    if matches!(kind, "null" | "null_literal") || text == "null" {
        return "NULL".to_string();
    }
    format!("N:{kind}")
}

fn refine_php_clone_similarity(
    left: &CloneCandidateData,
    right: &CloneCandidateData,
    token_similarity: i32,
    weights: CloneSmellWeights,
) -> i32 {
    if left.ast_signature.is_empty() || right.ast_signature.is_empty() {
        return token_similarity;
    }
    let ast_similarity =
        compute_ast_refinement_similarity_percent(&left.ast_signature, &right.ast_signature);
    if ast_similarity == 0 {
        return token_similarity;
    }
    if ast_similarity < weights.ast_similarity_percent {
        return 0;
    }
    token_similarity.min(ast_similarity)
}

fn parse_php_tree(source: &str) -> Option<Tree> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_php::LANGUAGE_PHP.into())
        .expect("failed to load php parser");
    parser.parse(source, None)
}

fn php_clone_parse_source(source: &str) -> String {
    if source.trim_start().starts_with("<?php") {
        source.to_string()
    } else {
        format!("<?php\n{source}")
    }
}

fn php_is_ignorable_clone_logging_node(node: Node<'_>, source: &str) -> bool {
    match node.kind() {
        "expression_statement" | "echo_statement" => {
            let text = source
                .get(node.start_byte()..node.end_byte())
                .unwrap_or("")
                .trim();
            text.starts_with("error_log(")
                || text.starts_with("print(")
                || text.starts_with("echo ")
        }
        _ => false,
    }
}

#[derive(Clone)]
struct PhpScope {
    package_name: String,
    class_unit: Option<CodeUnit>,
}

impl PhpScope {
    fn new(package_name: String, class_unit: Option<CodeUnit>) -> Self {
        Self {
            package_name,
            class_unit,
        }
    }
}

struct PhpVisitor<'a> {
    file: &'a ProjectFile,
    source: &'a str,
    parsed: &'a mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
}

impl<'a> PhpVisitor<'a> {
    fn visit_children(&mut self, node: Node<'_>, scope: &PhpScope) {
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            self.visit_node(child, scope);
        }
    }

    fn visit_node(&mut self, node: Node<'_>, scope: &PhpScope) {
        match node.kind() {
            "namespace_definition" => self.visit_namespace(node, scope),
            "class_declaration" | "interface_declaration" | "trait_declaration" => {
                self.visit_type_declaration(node, scope)
            }
            "function_definition" => self.visit_function(node, scope),
            "method_declaration" => self.visit_method(node, scope),
            "property_declaration" => self.visit_property_declaration(node, scope),
            "const_declaration" => self.visit_const_declaration(node, scope),
            "declaration_list" | "compound_statement" => self.visit_children(node, scope),
            _ => {}
        }
    }

    fn visit_namespace(&mut self, node: Node<'_>, scope: &PhpScope) {
        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let package_name = php_node_text(name_node, self.source).replace('\\', ".");
        let scope = PhpScope::new(package_name, scope.class_unit.clone());
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            match child.kind() {
                "namespace_name" | "name" => {}
                _ => self.visit_node(child, &scope),
            }
        }
    }

    fn visit_type_declaration(&mut self, node: Node<'_>, scope: &PhpScope) {
        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let name = php_node_text(name_node, self.source).trim().to_string();
        if name.is_empty() {
            return;
        }

        let short_name = if let Some(parent) = &scope.class_unit {
            format!("{}${name}", parent.short_name())
        } else {
            name
        };
        let code_unit = CodeUnit::new(
            self.file.clone(),
            CodeUnitType::Class,
            scope.package_name.clone(),
            short_name,
        );
        self.parsed.add_code_unit(
            code_unit.clone(),
            node,
            self.source,
            scope.class_unit.clone(),
            None,
        );
        self.parsed
            .set_primary_range(&code_unit, php_declaration_range(node, self.source));
        self.parsed
            .add_signature(code_unit.clone(), php_type_signature(node, self.source));

        if let Some(body) = php_class_body(node) {
            self.visit_children(
                body,
                &PhpScope::new(scope.package_name.clone(), Some(code_unit)),
            );
        }
    }

    fn visit_function(&mut self, node: Node<'_>, scope: &PhpScope) {
        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let name = php_node_text(name_node, self.source).trim().to_string();
        if name.is_empty() {
            return;
        }
        let short_name = if let Some(parent) = &scope.class_unit {
            format!("{}.{}", parent.short_name(), name)
        } else {
            name
        };
        let code_unit = CodeUnit::new(
            self.file.clone(),
            CodeUnitType::Function,
            scope.package_name.clone(),
            short_name,
        );
        self.parsed.add_code_unit(
            code_unit.clone(),
            node,
            self.source,
            scope.class_unit.clone(),
            None,
        );
        self.parsed
            .set_primary_range(&code_unit, php_declaration_range(node, self.source));
        self.parsed
            .add_signature(code_unit, php_function_signature(node, self.source));
    }

    fn visit_method(&mut self, node: Node<'_>, scope: &PhpScope) {
        self.visit_function(node, scope);
    }

    fn visit_property_declaration(&mut self, node: Node<'_>, scope: &PhpScope) {
        let Some(parent) = &scope.class_unit else {
            return;
        };
        let modifiers = php_property_prefix(node, self.source);
        let type_prefix = node
            .child_by_field_name("type")
            .map(|type_node| format!("{} ", php_node_text(type_node, self.source).trim()))
            .unwrap_or_default();
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if child.kind() != "property_element" {
                continue;
            }
            let Some(name_node) = child.child_by_field_name("name") else {
                continue;
            };
            let raw_name = php_node_text(name_node, self.source).trim().to_string();
            if raw_name.is_empty() {
                continue;
            }
            let stripped_name = raw_name.trim_start_matches('$');
            let code_unit = CodeUnit::new(
                self.file.clone(),
                CodeUnitType::Field,
                scope.package_name.clone(),
                format!("{}.{}", parent.short_name(), stripped_name),
            );
            self.parsed.add_code_unit(
                code_unit.clone(),
                node,
                self.source,
                Some(parent.clone()),
                None,
            );
            self.parsed
                .set_primary_range(&code_unit, php_declaration_range(node, self.source));
            let value = child
                .child_by_field_name("default_value")
                .filter(|value| php_is_literal(*value));
            let signature = if let Some(value) = value {
                format!(
                    "{modifiers}{type_prefix}{raw_name} = {};",
                    php_node_text(value, self.source).trim()
                )
            } else {
                format!("{modifiers}{type_prefix}{raw_name};")
            };
            self.parsed.add_signature(code_unit, signature);
        }
    }

    fn visit_const_declaration(&mut self, node: Node<'_>, scope: &PhpScope) {
        let prefix = php_const_prefix(node, self.source);
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if child.kind() != "const_element" {
                continue;
            }
            let Some(name_node) = php_find_named_descendant(child, "name") else {
                continue;
            };
            let name = php_node_text(name_node, self.source).trim().to_string();
            if name.is_empty() {
                continue;
            }
            let short_name = if let Some(parent) = &scope.class_unit {
                format!("{}.{}", parent.short_name(), name)
            } else {
                format!("_module_.{name}")
            };
            let code_unit = CodeUnit::new(
                self.file.clone(),
                CodeUnitType::Field,
                scope.package_name.clone(),
                short_name,
            );
            self.parsed.add_code_unit(
                code_unit.clone(),
                node,
                self.source,
                scope.class_unit.clone(),
                None,
            );
            self.parsed
                .set_primary_range(&code_unit, php_declaration_range(node, self.source));
            let value = php_const_value(child).filter(|value| php_is_literal(*value));
            let signature = if let Some(value) = value {
                format!(
                    "{prefix}{name} = {};",
                    php_node_text(value, self.source).trim()
                )
            } else {
                format!("{prefix}{name};")
            };
            self.parsed.add_signature(code_unit, signature);
        }
    }
}

fn determine_php_package_name(root: Node<'_>, source: &str) -> String {
    let mut cursor = root.walk();
    for child in root.named_children(&mut cursor) {
        if child.kind() != "namespace_definition" {
            continue;
        }
        if let Some(name_node) = child.child_by_field_name("name") {
            return php_node_text(name_node, source).replace('\\', ".");
        }
    }
    String::new()
}

fn php_class_body(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("body").or_else(|| {
        let mut cursor = node.walk();
        node.named_children(&mut cursor)
            .find(|child| child.kind() == "declaration_list")
    })
}

fn php_type_signature(node: Node<'_>, source: &str) -> String {
    let declaration_text = php_raw_text_with_attributes(node, source);
    let trimmed = normalize_php_snippet(&declaration_text);
    let Some((head, _)) = trimmed.split_once('{') else {
        return trimmed.to_string();
    };
    format!("{} {{", head.trim_end())
}

fn php_function_signature(node: Node<'_>, source: &str) -> String {
    let declaration_range = php_declaration_range(node, source);
    if let Some(body) = node.child_by_field_name("body") {
        let header =
            normalize_php_snippet(&source[declaration_range.start_byte..body.start_byte()]);
        format!("{header} {{ ... }}")
    } else {
        php_text_with_attributes(node, source).trim().to_string()
    }
}

fn php_property_prefix(node: Node<'_>, source: &str) -> String {
    let mut parts = php_attribute_lines(node, source);
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "visibility_modifier"
            | "static_modifier"
            | "readonly_modifier"
            | "abstract_modifier"
            | "final_modifier" => parts.push(php_node_text(child, source).trim().to_string()),
            _ => {}
        }
    }
    if parts.is_empty() {
        String::new()
    } else {
        format!("{} ", parts.join(" "))
    }
}

fn php_const_prefix(node: Node<'_>, source: &str) -> String {
    let mut parts = php_attribute_lines(node, source);
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "visibility_modifier"
            | "static_modifier"
            | "readonly_modifier"
            | "abstract_modifier"
            | "final_modifier" => parts.push(php_node_text(child, source).trim().to_string()),
            _ => {}
        }
    }
    parts.push("const".to_string());
    format!("{} ", parts.join(" "))
}

fn php_attribute_lines(node: Node<'_>, source: &str) -> Vec<String> {
    let mut attributes = Vec::new();
    let mut current = node;
    while let Some(prev) = current.prev_named_sibling() {
        if prev.kind() != "attribute_list" {
            break;
        }
        let gap = &source[prev.end_byte()..current.start_byte()];
        if !gap.trim().is_empty() {
            break;
        }
        attributes.push(php_node_text(prev, source).trim().to_string());
        current = prev;
    }
    attributes.reverse();
    attributes
}

fn php_text_with_attributes(node: Node<'_>, source: &str) -> String {
    normalize_php_snippet(&php_raw_text_with_attributes(node, source))
}

fn php_raw_text_with_attributes(node: Node<'_>, source: &str) -> String {
    let range = php_declaration_range(node, source);
    source[range.start_byte..range.end_byte].to_string()
}

fn php_declaration_range(node: Node<'_>, source: &str) -> Range {
    let mut start_byte = node.start_byte();
    let mut start_point = node.start_position();
    let mut current = node;
    while let Some(prev) = current.prev_named_sibling() {
        if prev.kind() != "attribute_list" {
            break;
        }
        let gap = &source[prev.end_byte()..current.start_byte()];
        if !gap.trim().is_empty() {
            break;
        }
        start_byte = prev.start_byte();
        start_point = prev.start_position();
        current = prev;
    }
    php_range(
        start_byte,
        start_point,
        node.end_byte(),
        node.end_position(),
    )
}

fn php_contains_tests(
    source: &str,
    parsed: &crate::analyzer::tree_sitter_analyzer::ParsedFile,
) -> bool {
    if parsed.declarations.iter().any(|code_unit| {
        let lower = code_unit.identifier().to_ascii_lowercase();
        (code_unit.is_class() && lower.contains("test"))
            || (code_unit.is_function() && lower.starts_with("test"))
    }) {
        return true;
    }

    static DOCBLOCK_TEST_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        Regex::new(
            r"(?is)/\*\*.*?@test.*?\*/\s*(?:(?:public|protected|private|static|final|abstract|readonly)\s+)*function\b",
        )
        .unwrap()
    });
    DOCBLOCK_TEST_RE.is_match(source)
}

fn php_is_literal(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "integer"
            | "float"
            | "string"
            | "encapsed_string"
            | "string_value"
            | "boolean"
            | "boolean_literal"
            | "null"
            | "null_literal"
    )
}

fn php_node_text(node: Node<'_>, source: &str) -> String {
    source[node.start_byte()..node.end_byte()].to_string()
}

fn php_const_value(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("value").or_else(|| {
        let mut cursor = node.walk();
        node.named_children(&mut cursor)
            .filter(|child| child.kind() != "name")
            .find(|child| child.kind() != "comment")
    })
}

fn php_find_named_descendant<'a>(node: Node<'a>, kind: &str) -> Option<Node<'a>> {
    if node.kind() == kind {
        return Some(node);
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if let Some(found) = php_find_named_descendant(child, kind) {
            return Some(found);
        }
    }
    None
}

fn normalize_php_snippet(snippet: &str) -> String {
    snippet
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

fn php_range(start_byte: usize, start: Point, end_byte: usize, end: Point) -> Range {
    Range {
        start_byte,
        end_byte,
        start_line: start.row + 1,
        end_line: end.row + 1,
    }
}
