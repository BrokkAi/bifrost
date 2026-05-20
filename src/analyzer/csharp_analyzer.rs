use crate::analyzer::clone_detection::{
    CloneCandidateData, CloneCandidateProfile, compact_clone_excerpt,
    compute_ast_refinement_similarity_percent, detect_structural_clone_smells,
};
use crate::analyzer::{
    AnalyzerConfig, CodeUnit, CodeUnitType, IAnalyzer, Language, LanguageAdapter, Project,
    ProjectFile, TestAssertionSmell, TestAssertionWeights, TestDetectionProvider,
    TreeSitterAnalyzer,
};
use crate::{CloneSmell, CloneSmellWeights};
use regex::Regex;
use std::collections::BTreeSet;
use std::sync::{Arc, LazyLock};
use tree_sitter::{Language as TsLanguage, Node, Parser, Tree};

#[derive(Debug, Clone, Default)]
pub struct CSharpAdapter;

impl LanguageAdapter for CSharpAdapter {
    fn language(&self) -> Language {
        Language::CSharp
    }

    fn query_directory(&self) -> &'static str {
        "resources/treesitter/c_sharp"
    }

    fn parser_language(&self) -> TsLanguage {
        tree_sitter_c_sharp::LANGUAGE.into()
    }

    fn file_extension(&self) -> &'static str {
        "cs"
    }

    fn contains_tests(
        &self,
        _file: &ProjectFile,
        source: &str,
        _tree: &Tree,
        _parsed: &crate::analyzer::tree_sitter_analyzer::ParsedFile,
    ) -> bool {
        csharp_contains_tests(source)
    }

    fn extract_call_receiver(&self, reference: &str) -> Option<String> {
        let trimmed = reference.trim();
        let before_args = trimmed
            .split_once('(')
            .map(|(head, _)| head)
            .unwrap_or(trimmed);
        before_args
            .rsplit_once('.')
            .map(|(receiver, _)| receiver.to_string())
    }

    fn parse_file(
        &self,
        file: &ProjectFile,
        source: &str,
        tree: &Tree,
    ) -> crate::analyzer::tree_sitter_analyzer::ParsedFile {
        let mut parsed = crate::analyzer::tree_sitter_analyzer::ParsedFile::new(String::new());
        let mut visitor = CSharpVisitor {
            file,
            source,
            parsed: &mut parsed,
        };
        visitor.visit_container(tree.root_node(), "", None);
        parsed
    }
}

#[derive(Clone)]
pub struct CSharpAnalyzer {
    inner: TreeSitterAnalyzer<CSharpAdapter>,
}

impl CSharpAnalyzer {
    pub fn new(project: Arc<dyn Project>) -> Self {
        Self::new_with_config(project, AnalyzerConfig::default())
    }

    pub fn new_with_config(project: Arc<dyn Project>, config: AnalyzerConfig) -> Self {
        Self {
            inner: TreeSitterAnalyzer::new_with_config(project, CSharpAdapter, config),
        }
    }

    pub fn new_with_config_and_storage(
        project: Arc<dyn Project>,
        config: AnalyzerConfig,
        storage: Arc<crate::analyzer::persistence::AnalyzerStorage>,
    ) -> Self {
        Self {
            inner: TreeSitterAnalyzer::new_with_config_and_storage(
                project,
                CSharpAdapter,
                config,
                storage,
            ),
        }
    }

    pub fn from_project<P>(project: P) -> Self
    where
        P: Project + 'static,
    {
        Self::new(Arc::new(project))
    }
}

impl TestDetectionProvider for CSharpAnalyzer {}

impl IAnalyzer for CSharpAnalyzer {
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

    fn parse_errors(&self, file: &ProjectFile) -> Option<Vec<crate::analyzer::ParseError>> {
        self.inner.parse_errors(file)
    }

    fn extract_call_receiver(&self, reference: &str) -> Option<String> {
        self.inner.extract_call_receiver(reference)
    }

    fn import_statements_of(&self, file: &ProjectFile) -> Vec<String> {
        self.inner.import_statements_of(file)
    }

    fn enclosing_code_unit(
        &self,
        file: &ProjectFile,
        range: &crate::analyzer::Range,
    ) -> Option<CodeUnit> {
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

    fn ranges_of(&self, code_unit: &CodeUnit) -> Vec<crate::analyzer::Range> {
        self.inner.ranges_of(code_unit)
    }

    fn get_skeleton(&self, code_unit: &CodeUnit) -> Option<String> {
        self.inner.get_skeleton(code_unit)
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
        if !self.contains_tests(file) || file_language(file) != Language::CSharp {
            return Vec::new();
        }
        let Ok(source) = self.inner.project().read_source(file) else {
            return Vec::new();
        };
        detect_csharp_test_assertion_smells(file, &source, &weights)
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
            .filter(|file| file_language(file) == Language::CSharp)
            .cloned()
            .collect();
        if requested_files.is_empty() {
            return Vec::new();
        }

        let all_candidates: Vec<CloneCandidateProfile> = self
            .get_all_declarations()
            .into_iter()
            .filter(|code_unit| {
                code_unit.is_function() && file_language(code_unit.source()) == Language::CSharp
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
            refine_csharp_clone_similarity,
        )
    }

    fn test_detection_provider(&self) -> Option<&dyn TestDetectionProvider> {
        Some(self)
    }
}

impl CSharpAnalyzer {
    fn build_clone_candidate_data(
        &self,
        code_unit: &CodeUnit,
        weights: CloneSmellWeights,
    ) -> Option<CloneCandidateData> {
        self.get_source(code_unit, false)
            .map(|source| source.trim().to_string())
            .filter(|source| !source.is_empty())
            .and_then(|source| {
                let normalized_tokens = normalized_clone_tokens_csharp(&source);
                if normalized_tokens.len() < weights.min_normalized_tokens.max(0) as usize {
                    return None;
                }
                Some(CloneCandidateData {
                    unit: code_unit.clone(),
                    normalized_tokens,
                    ast_signature: build_csharp_clone_ast_signature(&source),
                    excerpt: compact_clone_excerpt(&source),
                })
            })
    }
}

#[derive(Clone)]
struct CSharpScope {
    package_name: String,
    class_unit: Option<CodeUnit>,
}

struct CSharpVisitor<'a> {
    file: &'a ProjectFile,
    source: &'a str,
    parsed: &'a mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
}

impl<'a> CSharpVisitor<'a> {
    fn visit_container(
        &mut self,
        node: Node<'_>,
        package_name: &str,
        class_unit: Option<CodeUnit>,
    ) {
        let scope = CSharpScope {
            package_name: package_name.to_string(),
            class_unit,
        };
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            self.visit_node(child, &scope);
        }
    }

    fn visit_node(&mut self, node: Node<'_>, scope: &CSharpScope) {
        match node.kind() {
            "namespace_declaration" | "file_scoped_namespace_declaration" => {
                self.visit_namespace(node, scope)
            }
            "class_declaration" | "interface_declaration" | "struct_declaration" => {
                self.visit_type_declaration(node, scope)
            }
            "method_declaration" => self.visit_method(node, scope),
            "constructor_declaration" => self.visit_constructor(node, scope),
            "property_declaration" => self.visit_property(node, scope),
            "field_declaration" => self.visit_field_declaration(node, scope),
            _ => {}
        }
    }

    fn visit_namespace(&mut self, node: Node<'_>, scope: &CSharpScope) {
        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let raw_name = cs_node_text(name_node, self.source).trim();
        if raw_name.is_empty() {
            return;
        }
        let package_name = if scope.package_name.is_empty() {
            raw_name.to_string()
        } else {
            format!("{}.{}", scope.package_name, raw_name)
        };
        if let Some(body) = cs_namespace_body(node) {
            self.visit_container(body, &package_name, scope.class_unit.clone());
        }
    }

    fn visit_type_declaration(&mut self, node: Node<'_>, scope: &CSharpScope) {
        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let name = cs_node_text(name_node, self.source).trim();
        if name.is_empty() {
            return;
        }

        let short_name = if let Some(parent) = &scope.class_unit {
            format!("{}${name}", parent.short_name())
        } else {
            name.to_string()
        };
        let code_unit = CodeUnit::new(
            self.file.clone(),
            CodeUnitType::Class,
            scope.package_name.clone(),
            short_name,
        );
        if self.parsed.declarations.contains(&code_unit) {
            return;
        }
        self.parsed.add_code_unit(
            code_unit.clone(),
            node,
            self.source,
            scope.class_unit.clone(),
            None,
        );
        self.parsed
            .add_signature(code_unit.clone(), csharp_type_signature(node, self.source));

        if let Some(body) = cs_type_body(node) {
            self.visit_container(body, &scope.package_name, Some(code_unit));
        }
    }

    fn visit_method(&mut self, node: Node<'_>, scope: &CSharpScope) {
        let Some(parent) = &scope.class_unit else {
            return;
        };
        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let name = cs_node_text(name_node, self.source).trim();
        if name.is_empty() {
            return;
        }
        let signature_key = csharp_parameter_key(node, self.source);
        let code_unit = CodeUnit::with_signature(
            self.file.clone(),
            CodeUnitType::Function,
            scope.package_name.clone(),
            format!("{}.{}", parent.short_name(), name),
            Some(signature_key),
            false,
        );
        self.parsed.add_code_unit(
            code_unit.clone(),
            node,
            self.source,
            Some(parent.clone()),
            None,
        );
        self.parsed
            .add_signature(code_unit, csharp_method_skeleton(node, self.source));
    }

    fn visit_constructor(&mut self, node: Node<'_>, scope: &CSharpScope) {
        let Some(parent) = &scope.class_unit else {
            return;
        };
        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let name = cs_node_text(name_node, self.source).trim();
        if name.is_empty() {
            return;
        }
        let code_unit = CodeUnit::with_signature(
            self.file.clone(),
            CodeUnitType::Function,
            scope.package_name.clone(),
            format!("{}.{}", parent.short_name(), name),
            Some(csharp_parameter_key(node, self.source)),
            false,
        );
        self.parsed.add_code_unit(
            code_unit.clone(),
            node,
            self.source,
            Some(parent.clone()),
            None,
        );
        self.parsed
            .add_signature(code_unit, csharp_constructor_skeleton(node, self.source));
    }

    fn visit_property(&mut self, node: Node<'_>, scope: &CSharpScope) {
        let Some(parent) = &scope.class_unit else {
            return;
        };
        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let name = cs_node_text(name_node, self.source).trim();
        if name.is_empty() {
            return;
        }
        let code_unit = CodeUnit::new(
            self.file.clone(),
            CodeUnitType::Field,
            scope.package_name.clone(),
            format!("{}.{}", parent.short_name(), name),
        );
        self.parsed.add_code_unit(
            code_unit.clone(),
            node,
            self.source,
            Some(parent.clone()),
            None,
        );
        self.parsed
            .add_signature(code_unit, csharp_property_signature(node, self.source));
    }

    fn visit_field_declaration(&mut self, node: Node<'_>, scope: &CSharpScope) {
        let Some(parent) = &scope.class_unit else {
            return;
        };
        let Some(declaration) = node
            .child_by_field_name("declaration")
            .or_else(|| first_named_child_of_kind(node, "variable_declaration"))
        else {
            return;
        };

        let prefix = csharp_field_prefix(node, declaration, self.source);
        let type_text = declaration
            .child_by_field_name("type")
            .map(|child| normalize_cs_whitespace(cs_node_text(child, self.source)))
            .unwrap_or_default();
        let declaration_text = normalize_cs_whitespace(cs_node_text(node, self.source));

        let mut cursor = declaration.walk();
        for child in declaration.named_children(&mut cursor) {
            if child.kind() != "variable_declarator" {
                continue;
            }
            let Some(name_node) = child.child_by_field_name("name") else {
                continue;
            };
            let name = cs_node_text(name_node, self.source).trim();
            if name.is_empty() {
                continue;
            }
            let code_unit = CodeUnit::new(
                self.file.clone(),
                CodeUnitType::Field,
                scope.package_name.clone(),
                format!("{}.{}", parent.short_name(), name),
            );
            self.parsed.add_code_unit(
                code_unit.clone(),
                child,
                self.source,
                Some(parent.clone()),
                None,
            );
            self.parsed.add_signature(
                code_unit,
                csharp_field_signature(&prefix, &type_text, &declaration_text, child, self.source),
            );
        }
    }
}

static CSHARP_TEST_METHOD_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?s)(?:\[[^\]]*(?:Fact|Theory|Test|TestMethod)[^\]]*\]\s*)+[\w<>\[\],\s]+\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*\)\s*\{(?P<body>.*?)\n\}"#,
    )
    .expect("valid regex")
});
static CSHARP_ASSERT_EQUALITY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"Assert\.(?:Equal|Same)\s*\((?P<left>[^,\n]+?)\s*,\s*(?P<right>[^,\n\)]+)"#)
        .expect("valid regex")
});
static CSHARP_ASSERT_TRUTH_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"Assert\.(?P<matcher>True|False|Null|NotNull)\s*\((?P<arg>[^,\n\)]+)"#)
        .expect("valid regex")
});
static CSHARP_THROWS_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"Assert\.Throws(?:Async)?<|Assert\.Throws(?:Async)?\s*\("#).expect("valid regex")
});
static CSHARP_VERIFY_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"\.\s*Verify\s*\("#).expect("valid regex"));

#[derive(Clone)]
struct CSharpAssertionSignal {
    kind: String,
    score: i32,
    shallow: bool,
    meaningful: bool,
    reason: String,
    excerpt: String,
    start_byte: usize,
}

fn detect_csharp_test_assertion_smells(
    file: &ProjectFile,
    source: &str,
    weights: &TestAssertionWeights,
) -> Vec<TestAssertionSmell> {
    let mut findings = Vec::new();
    for captures in CSHARP_TEST_METHOD_RE.captures_iter(source) {
        let Some(name_match) = captures.name("name") else {
            continue;
        };
        let Some(body_match) = captures.name("body") else {
            continue;
        };
        analyze_csharp_test_case(
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

fn analyze_csharp_test_case(
    file: &ProjectFile,
    name: &str,
    body: &str,
    start_byte: usize,
    weights: &TestAssertionWeights,
    out: &mut Vec<TestAssertionSmell>,
) {
    let assertions = collect_csharp_assertions(body, weights);
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
            excerpt: compact_csharp_excerpt(body),
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
        let score = (weights.shallow_assertion_only_weight
            - csharp_meaningful_assertion_credit(assertions.iter(), weights))
        .max(0);
        if score > 0 {
            out.push(TestAssertionSmell {
                file: file.clone(),
                enclosing_fq_name: symbol,
                assertion_kind: "shallow-assertions-only".to_string(),
                score,
                assertion_count,
                reasons: vec!["shallow-assertions-only".to_string()],
                excerpt: compact_csharp_excerpt(body),
                start_byte,
            });
        }
    }
}

fn collect_csharp_assertions(
    body: &str,
    weights: &TestAssertionWeights,
) -> Vec<CSharpAssertionSignal> {
    let mut assertions = Vec::new();

    for captures in CSHARP_ASSERT_EQUALITY_RE.captures_iter(body) {
        let whole = captures.get(0).expect("whole match");
        let left = normalize_csharp_expr(captures.name("left").map(|m| m.as_str()).unwrap_or(""));
        let right = normalize_csharp_expr(captures.name("right").map(|m| m.as_str()).unwrap_or(""));
        let signal = if left == right {
            let (kind, reason, score) = if is_csharp_literal(&left) {
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
            CSharpAssertionSignal {
                kind: kind.to_string(),
                score,
                shallow: false,
                meaningful: false,
                reason: reason.to_string(),
                excerpt: compact_csharp_excerpt(whole.as_str()),
                start_byte: whole.start(),
            }
        } else {
            CSharpAssertionSignal {
                kind: "meaningful-assertion".to_string(),
                score: 0,
                shallow: false,
                meaningful: true,
                reason: "meaningful-assertion".to_string(),
                excerpt: compact_csharp_excerpt(whole.as_str()),
                start_byte: whole.start(),
            }
        };
        assertions.push(signal);
    }

    for captures in CSHARP_ASSERT_TRUTH_RE.captures_iter(body) {
        let whole = captures.get(0).expect("whole match");
        let matcher = captures.name("matcher").map(|m| m.as_str()).unwrap_or("");
        let arg = normalize_csharp_expr(captures.name("arg").map(|m| m.as_str()).unwrap_or(""));
        let (kind, score, shallow) = match matcher {
            "True" if arg == "true" => ("constant-truth", weights.constant_truth_weight, true),
            "False" if arg == "false" => ("constant-truth", weights.constant_truth_weight, true),
            "Null" | "NotNull" => ("nullness-only", weights.nullness_only_weight, true),
            _ => ("meaningful-assertion", 0, false),
        };
        assertions.push(CSharpAssertionSignal {
            kind: kind.to_string(),
            score,
            shallow,
            meaningful: score == 0,
            reason: kind.to_string(),
            excerpt: compact_csharp_excerpt(whole.as_str()),
            start_byte: whole.start(),
        });
    }

    for regex in [&*CSHARP_THROWS_RE, &*CSHARP_VERIFY_RE] {
        for captures in regex.captures_iter(body) {
            let whole = captures.get(0).expect("whole match");
            assertions.push(CSharpAssertionSignal {
                kind: "meaningful-assertion".to_string(),
                score: 0,
                shallow: false,
                meaningful: true,
                reason: "meaningful-assertion".to_string(),
                excerpt: compact_csharp_excerpt(whole.as_str()),
                start_byte: whole.start(),
            });
        }
    }

    assertions
}

fn csharp_meaningful_assertion_credit<'a>(
    assertions: impl Iterator<Item = &'a CSharpAssertionSignal>,
    weights: &TestAssertionWeights,
) -> i32 {
    let count = assertions.filter(|assertion| assertion.meaningful).count() as i32;
    let creditable = count.min(weights.meaningful_assertion_credit_cap.max(0));
    weights.meaningful_assertion_credit.max(0) * creditable
}

fn normalize_csharp_expr(expr: &str) -> String {
    expr.trim()
        .trim_end_matches(';')
        .trim_matches(|ch| matches!(ch, '(' | ')' | ' '))
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn is_csharp_literal(expr: &str) -> bool {
    let trimmed = expr.trim();
    (trimmed.starts_with('"') && trimmed.ends_with('"'))
        || matches!(trimmed, "true" | "false" | "null")
        || trimmed.parse::<i64>().is_ok()
        || trimmed.parse::<f64>().is_ok()
}

fn compact_csharp_excerpt(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn file_language(file: &ProjectFile) -> Language {
    file.rel_path()
        .extension()
        .and_then(|ext| ext.to_str())
        .map(Language::from_extension)
        .unwrap_or(Language::None)
}

const CSHARP_CLONE_AST_IDENTIFIER_TYPES: &[&str] = &["identifier"];
const CSHARP_CLONE_AST_STRING_TYPES: &[&str] = &["string_literal"];
const CSHARP_CLONE_AST_NUMBER_TYPES: &[&str] = &["integer_literal", "real_literal"];

fn normalized_clone_tokens_csharp(source: &str) -> Vec<String> {
    let Some(tree) = parse_csharp_tree(source) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    collect_normalized_leaf_tokens_csharp(tree.root_node(), source, &mut out);
    out
}

fn collect_normalized_leaf_tokens_csharp(node: Node<'_>, source: &str, out: &mut Vec<String>) {
    if node.named_child_count() == 0 {
        let token = normalize_csharp_clone_leaf_token(node, source);
        if !token.is_empty() {
            out.push(token);
        }
    }
    let child_count = node.child_count();
    for index in 0..child_count {
        if let Some(child) = node.child(index) {
            collect_normalized_leaf_tokens_csharp(child, source, out);
        }
    }
}

fn normalize_csharp_clone_leaf_token(node: Node<'_>, source: &str) -> String {
    let kind = node.kind();
    let token = source
        .get(node.start_byte()..node.end_byte())
        .unwrap_or("")
        .trim();
    if token.is_empty() || kind == "comment" {
        return String::new();
    }
    if CSHARP_CLONE_AST_IDENTIFIER_TYPES.contains(&kind) {
        return "ID".to_string();
    }
    if CSHARP_CLONE_AST_STRING_TYPES.contains(&kind) {
        return "STR".to_string();
    }
    if CSHARP_CLONE_AST_NUMBER_TYPES.contains(&kind) {
        return "NUM".to_string();
    }
    if matches!(token, "true" | "false") {
        return "BOOL".to_string();
    }
    if token.chars().count() == 1 && token.chars().all(|ch| !ch.is_alphanumeric()) {
        return format!("OP:{token}");
    }
    format!("T:{kind}")
}

fn build_csharp_clone_ast_signature(source: &str) -> String {
    let Some(tree) = parse_csharp_tree(source) else {
        return String::new();
    };
    let mut labels = Vec::new();
    collect_csharp_clone_ast_labels(tree.root_node(), source, &mut labels);
    labels.join("|")
}

fn collect_csharp_clone_ast_labels(node: Node<'_>, source: &str, out: &mut Vec<String>) {
    out.push(normalize_csharp_clone_ast_label(node, source));
    let child_count = node.child_count();
    for index in 0..child_count {
        if let Some(child) = node.child(index) {
            collect_csharp_clone_ast_labels(child, source, out);
        }
    }
}

fn normalize_csharp_clone_ast_label(node: Node<'_>, source: &str) -> String {
    let kind = node.kind();
    let text = source
        .get(node.start_byte()..node.end_byte())
        .unwrap_or("")
        .trim();
    if CSHARP_CLONE_AST_IDENTIFIER_TYPES.contains(&kind) {
        return "ID".to_string();
    }
    if CSHARP_CLONE_AST_STRING_TYPES.contains(&kind) {
        return "STR".to_string();
    }
    if CSHARP_CLONE_AST_NUMBER_TYPES.contains(&kind) {
        return "NUM".to_string();
    }
    if matches!(text, "true" | "false") {
        return "BOOL".to_string();
    }
    format!("N:{kind}")
}

fn refine_csharp_clone_similarity(
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

fn parse_csharp_tree(source: &str) -> Option<Tree> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_c_sharp::LANGUAGE.into())
        .expect("failed to load csharp parser");
    parser.parse(source, None)
}

fn cs_node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    source.get(node.start_byte()..node.end_byte()).unwrap_or("")
}

fn normalize_cs_whitespace(value: &str) -> String {
    let mut result = String::new();
    let mut prev_space = false;
    for ch in value.chars() {
        if ch.is_whitespace() {
            if !prev_space {
                result.push(' ');
            }
            prev_space = true;
        } else {
            result.push(ch);
            prev_space = false;
        }
    }
    result.trim().to_string()
}

fn cs_namespace_body(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("body")
        .or_else(|| last_named_child(node))
}

fn cs_type_body(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("body")
        .or_else(|| first_named_child_of_kind(node, "declaration_list"))
}

fn csharp_type_signature(node: Node<'_>, source: &str) -> String {
    let text = normalize_cs_whitespace(cs_node_text(node, source));
    let head = text.split('{').next().unwrap_or(text.as_str()).trim();
    format!("{head} {{")
}

fn csharp_method_skeleton(node: Node<'_>, source: &str) -> String {
    let text = normalize_cs_whitespace(cs_node_text(node, source));
    let head = text.split('{').next().unwrap_or(text.as_str()).trim();
    format!("{} {{ … }}", head.trim_end_matches(';').trim())
}

fn csharp_constructor_skeleton(node: Node<'_>, source: &str) -> String {
    csharp_method_skeleton(node, source)
}

fn csharp_property_signature(node: Node<'_>, source: &str) -> String {
    normalize_cs_whitespace(cs_node_text(node, source))
}

fn csharp_parameter_key(node: Node<'_>, source: &str) -> String {
    let Some(parameters) = node.child_by_field_name("parameters") else {
        return "()".to_string();
    };
    let mut parts = Vec::new();
    let mut cursor = parameters.walk();
    for child in parameters.named_children(&mut cursor) {
        if child.kind() != "parameter" {
            continue;
        }
        let part = child
            .child_by_field_name("type")
            .map(|type_node| normalize_cs_whitespace(cs_node_text(type_node, source)))
            .unwrap_or_else(|| normalize_cs_whitespace(cs_node_text(child, source)));
        parts.push(part);
    }
    format!("({})", parts.join(", "))
}

fn csharp_field_prefix(field_node: Node<'_>, declaration: Node<'_>, source: &str) -> String {
    let field_text = cs_node_text(field_node, source);
    let end = declaration
        .start_byte()
        .saturating_sub(field_node.start_byte());
    let prefix = field_text.get(..end).unwrap_or(field_text);
    let prefix = normalize_cs_whitespace(prefix);
    regex::Regex::new(r"^(?:\[[^\]]+\]\s*)+")
        .ok()
        .map(|regex| regex.replace(&prefix, "").trim().to_string())
        .unwrap_or(prefix)
}

fn csharp_field_signature(
    prefix: &str,
    type_text: &str,
    declaration_text: &str,
    declarator: Node<'_>,
    source: &str,
) -> String {
    let name = declarator
        .child_by_field_name("name")
        .map(|child| cs_node_text(child, source).trim().to_string())
        .unwrap_or_default();
    let initializer = declarator
        .child_by_field_name("value")
        .or_else(|| declarator.child_by_field_name("initializer"))
        .and_then(|value| csharp_literal_initializer(value, source));
    let initializer =
        initializer.or_else(|| csharp_literal_initializer_from_text(declaration_text, &name));

    let base = if prefix.is_empty() {
        format!("{type_text} {name}")
    } else {
        format!("{prefix} {type_text} {name}")
    };
    let base = normalize_cs_whitespace(&base);
    if let Some(initializer) = initializer {
        format!("{base} = {initializer};")
    } else {
        format!("{base};")
    }
}

fn csharp_literal_initializer(node: Node<'_>, source: &str) -> Option<String> {
    let kind = node.kind();
    if matches!(
        kind,
        "integer_literal"
            | "real_literal"
            | "string_literal"
            | "character_literal"
            | "boolean_literal"
            | "null_literal"
    ) {
        return Some(normalize_cs_whitespace(cs_node_text(node, source)));
    }
    None
}

fn csharp_literal_initializer_from_text(declaration_text: &str, name: &str) -> Option<String> {
    let pattern = format!(
        r#"\b{}\s*=\s*("([^"\\]|\\.)*"|'([^'\\]|\\.)*'|[-+]?\d+(?:\.\d+)?|true|false|null)\s*(?:,|;)"#,
        regex::escape(name)
    );
    regex::Regex::new(&pattern)
        .ok()
        .and_then(|regex| regex.captures(declaration_text))
        .and_then(|captures| captures.get(1))
        .map(|value| value.as_str().to_string())
}

fn first_named_child_of_kind<'a>(node: Node<'a>, kind: &str) -> Option<Node<'a>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| child.kind() == kind)
}

fn last_named_child(node: Node<'_>) -> Option<Node<'_>> {
    let count = node.named_child_count();
    if count == 0 {
        None
    } else {
        node.named_child(count - 1)
    }
}

fn csharp_contains_tests(source: &str) -> bool {
    static TEST_ATTR_RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let regex = TEST_ATTR_RE.get_or_init(|| {
        regex::Regex::new(
            r"\[(?:[A-Za-z_][A-Za-z0-9_.]*\.)?(?:Test|Fact|Theory)(?:Attribute)?(?:\s*\(|\s*\])",
        )
        .expect("valid csharp test regex")
    });
    regex.is_match(source)
}
