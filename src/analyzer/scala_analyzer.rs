use crate::analyzer::clone_detection::{
    CloneCandidateData, CloneCandidateProfile, compact_clone_excerpt,
    compute_ast_refinement_similarity_percent, detect_structural_clone_smells,
};
use crate::analyzer::{
    AnalyzerConfig, CodeUnit, CodeUnitType, IAnalyzer, ImportAnalysisProvider, ImportInfo,
    Language, LanguageAdapter, Project, ProjectFile, TestAssertionSmell, TestAssertionWeights,
    TestDetectionProvider, TreeSitterAnalyzer,
};
use crate::hash::HashSet;
use crate::{CloneSmell, CloneSmellWeights};
use regex::Regex;
use std::collections::BTreeSet;
use std::sync::{Arc, LazyLock};
use tree_sitter::{Language as TsLanguage, Node, Parser, Tree};

#[derive(Debug, Clone, Default)]
pub struct ScalaAdapter;

impl LanguageAdapter for ScalaAdapter {
    fn language(&self) -> Language {
        Language::Scala
    }

    fn query_directory(&self) -> &'static str {
        "resources/treesitter/scala"
    }

    fn parser_language(&self) -> TsLanguage {
        tree_sitter_scala::LANGUAGE.into()
    }

    fn file_extension(&self) -> &'static str {
        "scala"
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

    fn contains_tests(
        &self,
        _file: &ProjectFile,
        source: &str,
        _tree: &Tree,
        _parsed: &crate::analyzer::tree_sitter_analyzer::ParsedFile,
    ) -> bool {
        scala_contains_tests(source)
    }

    fn parse_file(
        &self,
        file: &ProjectFile,
        source: &str,
        tree: &Tree,
    ) -> crate::analyzer::tree_sitter_analyzer::ParsedFile {
        let mut parsed = crate::analyzer::tree_sitter_analyzer::ParsedFile::new(String::new());
        let mut visitor = ScalaVisitor {
            file,
            source,
            parsed: &mut parsed,
        };
        visitor.visit_compilation_unit(tree.root_node(), "");
        parsed
    }
}

#[derive(Clone)]
pub struct ScalaAnalyzer {
    inner: TreeSitterAnalyzer<ScalaAdapter>,
}

impl ScalaAnalyzer {
    pub fn new(project: Arc<dyn Project>) -> Self {
        Self::new_with_config(project, AnalyzerConfig::default())
    }

    pub fn new_with_config(project: Arc<dyn Project>, config: AnalyzerConfig) -> Self {
        Self {
            inner: TreeSitterAnalyzer::new_with_config(project, ScalaAdapter, config),
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
                ScalaAdapter,
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

    fn render_skeleton_recursive(
        &self,
        code_unit: &CodeUnit,
        indent: &str,
        header_only: bool,
        out: &mut String,
    ) {
        for signature in self.signatures_of(code_unit) {
            if signature.is_empty() {
                continue;
            }
            for line in signature.lines() {
                out.push_str(indent);
                out.push_str(line);
                out.push('\n');
            }
        }

        let all_children: Vec<_> = self.direct_children(code_unit).collect();
        let field_children: Vec<_> = all_children
            .iter()
            .copied()
            .filter(|child| child.is_field())
            .collect();
        let children = if header_only {
            field_children.clone()
        } else {
            all_children.clone()
        };

        if !children.is_empty() || code_unit.is_class() {
            let child_indent = format!("{indent}  ");
            for child in children {
                self.render_skeleton_recursive(child, &child_indent, header_only, out);
            }
            if header_only && all_children.len() > field_children.len() {
                out.push_str(&child_indent);
                out.push_str("[...]\n");
            }
            if code_unit.is_class() {
                out.push_str(indent);
                out.push_str("}\n");
            }
        }
    }

    fn resolve_import_info(&self, info: &ImportInfo) -> Vec<CodeUnit> {
        let Some(path) = scala_import_path(info) else {
            return Vec::new();
        };
        if info.is_wildcard {
            return self.inner.class_declarations_in_package(&path).to_vec();
        }
        self.inner
            .definitions(&path)
            .filter(|unit| unit.is_class())
            .cloned()
            .collect()
    }
}

impl TestDetectionProvider for ScalaAnalyzer {}

impl ImportAnalysisProvider for ScalaAnalyzer {
    fn imported_code_units_of(&self, file: &ProjectFile) -> HashSet<CodeUnit> {
        let mut imported = HashSet::default();
        for info in self.inner.import_info_of(file) {
            for code_unit in self.resolve_import_info(info) {
                imported.insert(code_unit);
            }
        }
        imported
    }

    fn referencing_files_of(&self, file: &ProjectFile) -> HashSet<ProjectFile> {
        let mut result = HashSet::default();
        let target_package = self.inner.package_name_of(file).unwrap_or("");
        let target_names: HashSet<String> = self
            .inner
            .top_level_declarations(file)
            .filter(|unit| unit.is_class())
            .map(scala_importable_name)
            .collect();

        for candidate in self.inner.all_files() {
            if candidate == file {
                continue;
            }
            if self.inner.package_name_of(candidate).unwrap_or("") == target_package
                && self
                    .inner
                    .type_identifiers_of(candidate)
                    .is_some_and(|identifiers| {
                        identifiers
                            .iter()
                            .any(|identifier| target_names.contains(identifier))
                    })
            {
                result.insert(candidate.clone());
                continue;
            }
            if self.could_import_file(candidate, self.import_info_of(candidate), file) {
                result.insert(candidate.clone());
            }
        }
        result
    }

    fn import_info_of<'a>(&'a self, file: &ProjectFile) -> &'a [ImportInfo] {
        self.inner.import_info_of(file)
    }

    fn could_import_file(
        &self,
        source_file: &ProjectFile,
        imports: &[ImportInfo],
        target: &ProjectFile,
    ) -> bool {
        if source_file == target {
            return false;
        }

        let source_package = self.inner.package_name_of(source_file).unwrap_or("");
        let target_package = self.inner.package_name_of(target).unwrap_or("");
        if source_package == target_package {
            return true;
        }

        let target_names: HashSet<String> = self
            .inner
            .top_level_declarations(target)
            .filter(|unit| unit.is_class())
            .map(scala_importable_name)
            .collect();
        imports.iter().any(|info| {
            let Some(path) = scala_import_path(info) else {
                return false;
            };
            if info.is_wildcard {
                return path == target_package;
            }
            let Some((package, imported)) = path.rsplit_once('.') else {
                return false;
            };
            package == target_package && target_names.contains(imported)
        })
    }
}

impl IAnalyzer for ScalaAnalyzer {
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
        Box::new(
            self.inner
                .direct_children(code_unit)
                .filter(|child| !child.is_synthetic()),
        )
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

    fn import_analysis_provider(&self) -> Option<&dyn ImportAnalysisProvider> {
        Some(self)
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
        self.inner
            .get_direct_children(code_unit)
            .into_iter()
            .filter(|child| !child.is_synthetic())
            .collect()
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
        let mut rendered = String::new();
        self.render_skeleton_recursive(code_unit, "", false, &mut rendered);
        (!rendered.is_empty()).then(|| rendered.trim_end().to_string())
    }

    fn get_skeleton_header(&self, code_unit: &CodeUnit) -> Option<String> {
        let mut rendered = String::new();
        self.render_skeleton_recursive(code_unit, "", true, &mut rendered);
        (!rendered.is_empty()).then(|| rendered.trim_end().to_string())
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
        if !self.contains_tests(file) || file_language(file) != Language::Scala {
            return Vec::new();
        }
        let Ok(source) = self.inner.project().read_source(file) else {
            return Vec::new();
        };
        detect_scala_test_assertion_smells(file, &source, &weights)
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
            .filter(|file| file_language(file) == Language::Scala)
            .cloned()
            .collect();
        if requested_files.is_empty() {
            return Vec::new();
        }

        let all_candidates: Vec<CloneCandidateProfile> = self
            .get_all_declarations()
            .into_iter()
            .filter(|code_unit| {
                code_unit.is_function() && file_language(code_unit.source()) == Language::Scala
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
            refine_scala_clone_similarity,
        )
    }

    fn test_detection_provider(&self) -> Option<&dyn TestDetectionProvider> {
        Some(self)
    }
}

impl ScalaAnalyzer {
    fn build_clone_candidate_data(
        &self,
        code_unit: &CodeUnit,
        weights: CloneSmellWeights,
    ) -> Option<CloneCandidateData> {
        self.get_source(code_unit, false)
            .map(|source| source.trim().to_string())
            .filter(|source| !source.is_empty())
            .and_then(|source| {
                let normalized_tokens = normalized_clone_tokens_scala(&source);
                if normalized_tokens.len() < weights.min_normalized_tokens.max(0) as usize {
                    return None;
                }
                Some(CloneCandidateData {
                    unit: code_unit.clone(),
                    normalized_tokens,
                    ast_signature: build_scala_clone_ast_signature(&source),
                    excerpt: compact_clone_excerpt(&source),
                })
            })
    }
}

static SCALA_TEST_BLOCK_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?s)"(?P<name>[^"]+)"\s+should\s+"[^"]+"\s+in\s*\{(?P<body>.*?)\n\}"#)
        .expect("valid regex")
});
static SCALA_FUNSUITE_TEST_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?s)test\s*\("(?P<name>[^"]+)"\)\s*\{(?P<body>.*?)\n\s*\}"#).expect("valid regex")
});
static SCALA_ASSERT_COMPARISON_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"assert(?:Result)?\s*\((?P<left>[^=\n\)]+?)\s*(?P<op>==|!=)\s*(?P<right>[^,\n\)]+)\)"#,
    )
    .expect("valid regex")
});
static SCALA_ASSERT_SIMPLE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"assert(?:Result)?\s*\((?P<expr>[^,\n\)]+)\)"#).expect("valid regex")
});
static SCALA_JUNIT_EQUALITY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"assert(?:Equals|Same)\s*\((?P<left>[^,\n]+?)\s*,\s*(?P<right>[^,\n\)]+)"#)
        .expect("valid regex")
});
static SCALA_JUNIT_NULLNESS_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"assert(?:NotNull|Null)\s*\((?P<arg>[^,\n\)]+)"#).expect("valid regex")
});
static SCALA_SHOULDBE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?P<left>[A-Za-z0-9_\."]+)\s+should(?:Be|Equal)\s+(?P<right>[A-Za-z0-9_\."]+)"#)
        .expect("valid regex")
});
static SCALA_THROWS_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"assertThrows\[|thrownBy\s*\{|intercept\["#).expect("valid regex")
});
static SCALA_VERIFY_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"verify\s*\("#).expect("valid regex"));

#[derive(Clone)]
struct ScalaAssertionSignal {
    kind: String,
    score: i32,
    shallow: bool,
    reason: String,
    excerpt: String,
    start_byte: usize,
}

fn detect_scala_test_assertion_smells(
    file: &ProjectFile,
    source: &str,
    weights: &TestAssertionWeights,
) -> Vec<TestAssertionSmell> {
    let mut findings = Vec::new();
    for captures in SCALA_TEST_BLOCK_RE.captures_iter(source) {
        let Some(name_match) = captures.name("name") else {
            continue;
        };
        let Some(body_match) = captures.name("body") else {
            continue;
        };
        analyze_scala_test_case(
            file,
            name_match.as_str(),
            body_match.as_str(),
            body_match.start(),
            weights,
            &mut findings,
        );
    }
    for captures in SCALA_FUNSUITE_TEST_RE.captures_iter(source) {
        let Some(name_match) = captures.name("name") else {
            continue;
        };
        let Some(body_match) = captures.name("body") else {
            continue;
        };
        analyze_scala_test_case(
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

fn analyze_scala_test_case(
    file: &ProjectFile,
    name: &str,
    body: &str,
    start_byte: usize,
    weights: &TestAssertionWeights,
    out: &mut Vec<TestAssertionSmell>,
) {
    let assertions = collect_scala_assertions(body, weights);
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
            excerpt: compact_scala_excerpt(body),
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
            excerpt: compact_scala_excerpt(body),
            start_byte,
        });
    }
}

fn collect_scala_assertions(
    body: &str,
    weights: &TestAssertionWeights,
) -> Vec<ScalaAssertionSignal> {
    let mut assertions = Vec::new();

    for captures in SCALA_SHOULDBE_RE.captures_iter(body) {
        let whole = captures.get(0).expect("whole match");
        let left = normalize_scala_expr(captures.name("left").map(|m| m.as_str()).unwrap_or(""));
        let right = normalize_scala_expr(captures.name("right").map(|m| m.as_str()).unwrap_or(""));
        let signal = if left == right {
            let (kind, reason, score) = if is_scala_literal(&left) {
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
            ScalaAssertionSignal {
                kind: kind.to_string(),
                score,
                shallow: false,
                reason: reason.to_string(),
                excerpt: compact_scala_excerpt(whole.as_str()),
                start_byte: whole.start(),
            }
        } else {
            ScalaAssertionSignal {
                kind: "meaningful-assertion".to_string(),
                score: 0,
                shallow: false,
                reason: "meaningful-assertion".to_string(),
                excerpt: compact_scala_excerpt(whole.as_str()),
                start_byte: whole.start(),
            }
        };
        assertions.push(signal);
    }

    for captures in SCALA_JUNIT_EQUALITY_RE.captures_iter(body) {
        let whole = captures.get(0).expect("whole match");
        let left = normalize_scala_expr(captures.name("left").map(|m| m.as_str()).unwrap_or(""));
        let right = normalize_scala_expr(captures.name("right").map(|m| m.as_str()).unwrap_or(""));
        let signal = if left == right {
            let (kind, reason, score) = if is_scala_literal(&left) {
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
            ScalaAssertionSignal {
                kind: kind.to_string(),
                score,
                shallow: false,
                reason: reason.to_string(),
                excerpt: compact_scala_excerpt(whole.as_str()),
                start_byte: whole.start(),
            }
        } else if let Some(literal) = oversized_scala_literal(&left, &right, weights) {
            ScalaAssertionSignal {
                kind: "overspecified-literal".to_string(),
                score: weights.overspecified_literal_weight,
                shallow: false,
                reason: format!("overspecified-literal:{literal}"),
                excerpt: compact_scala_excerpt(whole.as_str()),
                start_byte: whole.start(),
            }
        } else {
            ScalaAssertionSignal {
                kind: "meaningful-assertion".to_string(),
                score: 0,
                shallow: false,
                reason: "meaningful-assertion".to_string(),
                excerpt: compact_scala_excerpt(whole.as_str()),
                start_byte: whole.start(),
            }
        };
        assertions.push(signal);
    }

    for captures in SCALA_JUNIT_NULLNESS_RE.captures_iter(body) {
        let whole = captures.get(0).expect("whole match");
        assertions.push(ScalaAssertionSignal {
            kind: "nullness-only".to_string(),
            score: weights.nullness_only_weight,
            shallow: true,
            reason: "nullness-only".to_string(),
            excerpt: compact_scala_excerpt(whole.as_str()),
            start_byte: whole.start(),
        });
    }

    for captures in SCALA_ASSERT_COMPARISON_RE.captures_iter(body) {
        let whole = captures.get(0).expect("whole match");
        let left = normalize_scala_expr(captures.name("left").map(|m| m.as_str()).unwrap_or(""));
        let right = normalize_scala_expr(captures.name("right").map(|m| m.as_str()).unwrap_or(""));
        let operator = captures.name("op").map(|m| m.as_str()).unwrap_or("==");
        let signal = if operator == "==" && left == right {
            let (kind, reason, score) = if is_scala_literal(&left) {
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
            ScalaAssertionSignal {
                kind: kind.to_string(),
                score,
                shallow: false,
                reason: reason.to_string(),
                excerpt: compact_scala_excerpt(whole.as_str()),
                start_byte: whole.start(),
            }
        } else if operator == "==" {
            if let Some(literal) = oversized_scala_literal(&left, &right, weights) {
                ScalaAssertionSignal {
                    kind: "overspecified-literal".to_string(),
                    score: weights.overspecified_literal_weight,
                    shallow: false,
                    reason: format!("overspecified-literal:{literal}"),
                    excerpt: compact_scala_excerpt(whole.as_str()),
                    start_byte: whole.start(),
                }
            } else if is_scala_null_literal(&left) || is_scala_null_literal(&right) {
                ScalaAssertionSignal {
                    kind: "nullness-only".to_string(),
                    score: weights.nullness_only_weight,
                    shallow: true,
                    reason: "nullness-only".to_string(),
                    excerpt: compact_scala_excerpt(whole.as_str()),
                    start_byte: whole.start(),
                }
            } else {
                ScalaAssertionSignal {
                    kind: "meaningful-assertion".to_string(),
                    score: 0,
                    shallow: false,
                    reason: "meaningful-assertion".to_string(),
                    excerpt: compact_scala_excerpt(whole.as_str()),
                    start_byte: whole.start(),
                }
            }
        } else {
            ScalaAssertionSignal {
                kind: "meaningful-assertion".to_string(),
                score: 0,
                shallow: false,
                reason: "meaningful-assertion".to_string(),
                excerpt: compact_scala_excerpt(whole.as_str()),
                start_byte: whole.start(),
            }
        };
        assertions.push(signal);
    }

    for captures in SCALA_ASSERT_SIMPLE_RE.captures_iter(body) {
        let whole = captures.get(0).expect("whole match");
        let expr = normalize_scala_expr(captures.name("expr").map(|m| m.as_str()).unwrap_or(""));
        if expr.contains("==") || expr.contains("!=") {
            continue;
        }
        let signal = if expr == "true" {
            ScalaAssertionSignal {
                kind: "constant-truth".to_string(),
                score: weights.constant_truth_weight,
                shallow: true,
                reason: "constant-truth".to_string(),
                excerpt: compact_scala_excerpt(whole.as_str()),
                start_byte: whole.start(),
            }
        } else {
            ScalaAssertionSignal {
                kind: "meaningful-assertion".to_string(),
                score: 0,
                shallow: false,
                reason: "meaningful-assertion".to_string(),
                excerpt: compact_scala_excerpt(whole.as_str()),
                start_byte: whole.start(),
            }
        };
        assertions.push(signal);
    }

    for regex in [&*SCALA_THROWS_RE, &*SCALA_VERIFY_RE] {
        for captures in regex.captures_iter(body) {
            let whole = captures.get(0).expect("whole match");
            assertions.push(ScalaAssertionSignal {
                kind: "meaningful-assertion".to_string(),
                score: 0,
                shallow: false,
                reason: "meaningful-assertion".to_string(),
                excerpt: compact_scala_excerpt(whole.as_str()),
                start_byte: whole.start(),
            });
        }
    }

    assertions
}

fn normalize_scala_expr(expr: &str) -> String {
    expr.trim()
        .trim_matches(|ch| matches!(ch, '(' | ')' | ' '))
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn is_scala_literal(expr: &str) -> bool {
    let trimmed = expr.trim();
    (trimmed.starts_with('"') && trimmed.ends_with('"'))
        || matches!(trimmed, "true" | "false" | "null")
        || trimmed.parse::<i64>().is_ok()
        || trimmed.parse::<f64>().is_ok()
}

fn is_scala_null_literal(expr: &str) -> bool {
    expr.trim() == "null"
}

fn compact_scala_excerpt(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn oversized_scala_literal(
    left: &str,
    right: &str,
    weights: &TestAssertionWeights,
) -> Option<String> {
    [left, right].into_iter().find_map(|expr| {
        let trimmed = expr.trim();
        let unquoted = trimmed
            .strip_prefix('"')
            .and_then(|s| s.strip_suffix('"'))?;
        (unquoted.len() >= weights.large_literal_length_threshold.max(0) as usize)
            .then(|| trimmed.to_string())
    })
}

fn file_language(file: &ProjectFile) -> Language {
    file.rel_path()
        .extension()
        .and_then(|ext| ext.to_str())
        .map(Language::from_extension)
        .unwrap_or(Language::None)
}

const SCALA_CLONE_AST_IDENTIFIER_TYPES: &[&str] = &["identifier"];
const SCALA_CLONE_AST_STRING_TYPES: &[&str] = &["string"];
const SCALA_CLONE_AST_NUMBER_TYPES: &[&str] = &["integer_literal", "floating_point_literal"];

fn normalized_clone_tokens_scala(source: &str) -> Vec<String> {
    let Some(tree) = parse_scala_tree(source) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    collect_normalized_leaf_tokens_scala(tree.root_node(), source, &mut out);
    out
}

fn collect_normalized_leaf_tokens_scala(node: Node<'_>, source: &str, out: &mut Vec<String>) {
    if node.named_child_count() == 0 {
        let token = normalize_scala_clone_leaf_token(node, source);
        if !token.is_empty() {
            out.push(token);
        }
    }
    let child_count = node.child_count();
    for index in 0..child_count {
        if let Some(child) = node.child(index) {
            collect_normalized_leaf_tokens_scala(child, source, out);
        }
    }
}

fn normalize_scala_clone_leaf_token(node: Node<'_>, source: &str) -> String {
    let kind = node.kind();
    let token = source
        .get(node.start_byte()..node.end_byte())
        .unwrap_or("")
        .trim();
    if token.is_empty() || kind == "comment" {
        return String::new();
    }
    if SCALA_CLONE_AST_IDENTIFIER_TYPES.contains(&kind) {
        return "ID".to_string();
    }
    if SCALA_CLONE_AST_STRING_TYPES.contains(&kind) {
        return "STR".to_string();
    }
    if SCALA_CLONE_AST_NUMBER_TYPES.contains(&kind) {
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

fn build_scala_clone_ast_signature(source: &str) -> String {
    let Some(tree) = parse_scala_tree(source) else {
        return String::new();
    };
    let mut labels = Vec::new();
    collect_scala_clone_ast_labels(tree.root_node(), source, &mut labels);
    labels.join("|")
}

fn collect_scala_clone_ast_labels(node: Node<'_>, source: &str, out: &mut Vec<String>) {
    out.push(normalize_scala_clone_ast_label(node, source));
    let child_count = node.child_count();
    for index in 0..child_count {
        if let Some(child) = node.child(index) {
            collect_scala_clone_ast_labels(child, source, out);
        }
    }
}

fn normalize_scala_clone_ast_label(node: Node<'_>, source: &str) -> String {
    let kind = node.kind();
    let text = source
        .get(node.start_byte()..node.end_byte())
        .unwrap_or("")
        .trim();
    if SCALA_CLONE_AST_IDENTIFIER_TYPES.contains(&kind) {
        return "ID".to_string();
    }
    if SCALA_CLONE_AST_STRING_TYPES.contains(&kind) {
        return "STR".to_string();
    }
    if SCALA_CLONE_AST_NUMBER_TYPES.contains(&kind) {
        return "NUM".to_string();
    }
    if matches!(text, "true" | "false") {
        return "BOOL".to_string();
    }
    format!("N:{kind}")
}

fn refine_scala_clone_similarity(
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

fn parse_scala_tree(source: &str) -> Option<Tree> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_scala::LANGUAGE.into())
        .expect("failed to load scala parser");
    parser.parse(source, None)
}

struct ScalaVisitor<'a> {
    file: &'a ProjectFile,
    source: &'a str,
    parsed: &'a mut crate::analyzer::tree_sitter_analyzer::ParsedFile,
}

impl<'a> ScalaVisitor<'a> {
    fn visit_compilation_unit(&mut self, node: Node<'_>, package_name: &str) {
        let mut current_package = package_name.to_string();
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            match child.kind() {
                "package_clause" => {
                    let package = scala_package_name(child, self.source);
                    if !package.is_empty() {
                        current_package = if current_package.is_empty() {
                            package
                        } else {
                            format!("{current_package}.{package}")
                        };
                        if self.parsed.package_name.is_empty() {
                            self.parsed.package_name = current_package.clone();
                        }
                    }
                    if let Some(body) = child.child_by_field_name("body") {
                        self.visit_compilation_unit(body, &current_package);
                    }
                }
                "import_declaration" => {
                    let raw = scala_node_text(child, self.source).trim().to_string();
                    if !raw.is_empty() {
                        self.parsed.imports.extend(parse_scala_import_infos(&raw));
                        self.parsed.import_statements.push(raw);
                    }
                }
                "class_definition" | "object_definition" | "trait_definition"
                | "enum_definition" => self.visit_type_declaration(child, &current_package, None),
                "function_definition" => self.visit_function(child, &current_package, None),
                "val_definition" | "var_definition" => {
                    self.visit_field_declaration(child, &current_package, None)
                }
                _ => {}
            }
        }
    }

    fn visit_type_declaration(
        &mut self,
        node: Node<'_>,
        package_name: &str,
        parent: Option<CodeUnit>,
    ) {
        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let raw_name = scala_node_text(name_node, self.source).trim();
        if raw_name.is_empty() {
            return;
        }

        let display_name = if node.kind() == "object_definition" {
            format!("{raw_name}$")
        } else {
            raw_name.to_string()
        };
        let short_name = if let Some(parent) = &parent {
            format!("{}.{}", parent.short_name(), display_name)
        } else {
            display_name
        };
        let code_unit = CodeUnit::new(
            self.file.clone(),
            CodeUnitType::Class,
            package_name.to_string(),
            short_name,
        );
        if self.parsed.declarations.contains(&code_unit) {
            return;
        }

        self.parsed
            .add_code_unit(code_unit.clone(), node, self.source, parent.clone(), None);
        self.parsed
            .add_signature(code_unit.clone(), scala_type_signature(node, self.source));

        if node.kind() == "class_definition"
            && node.child_by_field_name("class_parameters").is_some()
        {
            let constructor = CodeUnit::new(
                self.file.clone(),
                CodeUnitType::Function,
                package_name.to_string(),
                format!("{}.{}", code_unit.short_name(), raw_name),
            )
            .with_synthetic(true);
            self.parsed.add_code_unit(
                constructor.clone(),
                node,
                self.source,
                Some(code_unit.clone()),
                None,
            );
            self.parsed.add_signature(
                constructor,
                scala_primary_constructor_signature(node, self.source),
            );
        }

        if let Some(body) = node.child_by_field_name("body") {
            self.visit_template_body(body, package_name, &code_unit);
        }
    }

    fn visit_template_body(&mut self, body: Node<'_>, package_name: &str, parent: &CodeUnit) {
        let mut cursor = body.walk();
        for child in body.named_children(&mut cursor) {
            match child.kind() {
                "function_definition" => {
                    self.visit_function(child, package_name, Some(parent.clone()))
                }
                "val_definition" | "var_definition" => {
                    self.visit_field_declaration(child, package_name, Some(parent.clone()))
                }
                "class_definition" | "object_definition" | "trait_definition"
                | "enum_definition" => {
                    self.visit_type_declaration(child, package_name, Some(parent.clone()))
                }
                "simple_enum_case" => self.visit_enum_case(child, package_name, parent),
                "enum_case_definitions" | "enum_body" => {
                    self.visit_template_body(child, package_name, parent)
                }
                _ => {}
            }
        }
    }

    fn visit_function(&mut self, node: Node<'_>, package_name: &str, parent: Option<CodeUnit>) {
        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let raw_name = scala_node_text(name_node, self.source).trim();
        if raw_name.is_empty() {
            return;
        }

        let effective_name = if raw_name == "this" {
            parent
                .as_ref()
                .map(|code_unit| last_segment(code_unit.short_name()).to_string())
                .unwrap_or_else(|| raw_name.to_string())
        } else {
            raw_name.to_string()
        };
        let short_name = if let Some(parent) = &parent {
            format!("{}.{}", parent.short_name(), effective_name)
        } else {
            effective_name
        };

        let code_unit = CodeUnit::new(
            self.file.clone(),
            CodeUnitType::Function,
            package_name.to_string(),
            short_name,
        );
        self.parsed
            .add_code_unit(code_unit.clone(), node, self.source, parent, None);
        self.parsed
            .add_signature(code_unit, scala_function_signature(node, self.source));
    }

    fn visit_field_declaration(
        &mut self,
        node: Node<'_>,
        package_name: &str,
        parent: Option<CodeUnit>,
    ) {
        let Some(pattern) = node.child_by_field_name("pattern") else {
            return;
        };

        for name in scala_pattern_names(pattern, self.source) {
            let short_name = if let Some(parent) = &parent {
                format!("{}.{}", parent.short_name(), name)
            } else {
                name.clone()
            };
            let code_unit = CodeUnit::new(
                self.file.clone(),
                CodeUnitType::Field,
                package_name.to_string(),
                short_name,
            );
            self.parsed
                .add_code_unit(code_unit.clone(), node, self.source, parent.clone(), None);
            self.parsed
                .add_signature(code_unit, scala_field_signature(node, self.source, &name));
        }
    }

    fn visit_enum_case(&mut self, node: Node<'_>, package_name: &str, parent: &CodeUnit) {
        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let name = scala_node_text(name_node, self.source).trim();
        if name.is_empty() {
            return;
        }

        let code_unit = CodeUnit::new(
            self.file.clone(),
            CodeUnitType::Field,
            package_name.to_string(),
            format!("{}.{}", parent.short_name(), name),
        );
        self.parsed.add_code_unit(
            code_unit.clone(),
            node,
            self.source,
            Some(parent.clone()),
            None,
        );
        self.parsed.add_signature(code_unit, format!("case {name}"));
    }
}

fn scala_node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    &source[node.byte_range()]
}

fn parse_scala_import_infos(raw: &str) -> Vec<ImportInfo> {
    let trimmed = raw
        .trim()
        .strip_prefix("import ")
        .unwrap_or(raw.trim())
        .trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    if let Some(prefix_end) = trimmed.find(".{") {
        let prefix = trimmed[..prefix_end].trim();
        let grouped = trimmed[prefix_end + 2..].trim_end_matches('}').trim();
        return split_scala_import_group(grouped)
            .into_iter()
            .filter_map(|part| {
                let (imported, alias) = split_scala_alias(&part);
                if imported.is_empty() {
                    return None;
                }
                let is_wildcard = imported == "*";
                Some(ImportInfo {
                    raw_snippet: if let Some(alias) = &alias {
                        format!("import {prefix}.{imported} as {alias}")
                    } else if is_wildcard {
                        format!("import {prefix}.*")
                    } else {
                        format!("import {prefix}.{imported}")
                    },
                    is_wildcard,
                    identifier: (!is_wildcard)
                        .then(|| alias.clone().unwrap_or_else(|| imported.clone())),
                    alias,
                })
            })
            .collect();
    }

    let is_wildcard = trimmed.ends_with(".*");
    let path = trimmed.trim_end_matches(".*").trim();
    let (path, alias) = split_scala_alias(path);
    let identifier = if is_wildcard {
        None
    } else {
        Some(
            alias
                .clone()
                .unwrap_or_else(|| path.rsplit('.').next().unwrap_or(path.as_str()).to_string()),
        )
    };
    vec![ImportInfo {
        raw_snippet: if let Some(alias) = &alias {
            format!("import {path} as {alias}")
        } else if is_wildcard {
            format!("import {path}.*")
        } else {
            format!("import {path}")
        },
        is_wildcard,
        identifier,
        alias,
    }]
}

fn split_scala_import_group(grouped: &str) -> Vec<String> {
    grouped
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(str::to_string)
        .collect()
}

fn split_scala_alias(raw: &str) -> (String, Option<String>) {
    let trimmed = raw.trim();
    if let Some((name, alias)) = trimmed.split_once(" as ") {
        return (name.trim().to_string(), Some(alias.trim().to_string()));
    }
    if let Some((name, alias)) = trimmed.split_once(" => ") {
        return (name.trim().to_string(), Some(alias.trim().to_string()));
    }
    (trimmed.to_string(), None)
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
    let (path, _) = split_scala_alias(trimmed);
    Some(path)
}

fn scala_importable_name(unit: &CodeUnit) -> String {
    last_segment(unit.short_name())
        .trim_end_matches('$')
        .to_string()
}

fn scala_package_name(node: Node<'_>, source: &str) -> String {
    node.child_by_field_name("name")
        .map(|name| scala_node_text(name, source).trim().to_string())
        .unwrap_or_default()
}

fn scala_type_signature(node: Node<'_>, source: &str) -> String {
    let keyword = match node.kind() {
        "class_definition" => "class",
        "object_definition" => "object",
        "trait_definition" => "trait",
        "enum_definition" => "enum",
        _ => "class",
    };
    let name = node
        .child_by_field_name("name")
        .map(|name| scala_node_text(name, source).trim())
        .unwrap_or("");
    let type_params = node
        .child_by_field_name("type_parameters")
        .map(|child| scala_node_text(child, source).trim().to_string())
        .unwrap_or_default();
    let class_params = node
        .child_by_field_name("class_parameters")
        .map(|child| scala_node_text(child, source).trim().to_string())
        .unwrap_or_default();
    format!(
        "{}{} {}{}{} {{",
        scala_modifier_prefix(node, source),
        keyword,
        name,
        type_params,
        class_params
    )
}

fn scala_primary_constructor_signature(node: Node<'_>, source: &str) -> String {
    let name = node
        .child_by_field_name("name")
        .map(|name| scala_node_text(name, source).trim())
        .unwrap_or("");
    let params = node
        .child_by_field_name("class_parameters")
        .map(|child| scala_node_text(child, source).trim().to_string())
        .unwrap_or_default();
    format!("def {name}{params} = {{...}}")
}

fn scala_function_signature(node: Node<'_>, source: &str) -> String {
    let name = node
        .child_by_field_name("name")
        .map(|name| scala_node_text(name, source).trim())
        .unwrap_or("");
    let mut parts = Vec::new();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if matches!(child.kind(), "type_parameters" | "parameters") {
            parts.push(scala_node_text(child, source).trim().to_string());
        }
    }
    let return_type = node
        .child_by_field_name("return_type")
        .map(|child| format!(": {}", scala_node_text(child, source).trim()))
        .unwrap_or_default();

    format!(
        "{}def {}{}{} = {{...}}",
        scala_modifier_prefix(node, source),
        name,
        parts.join(""),
        return_type
    )
}

fn scala_field_signature(node: Node<'_>, source: &str, name: &str) -> String {
    let keyword = if node.kind() == "var_definition" {
        "var"
    } else {
        "val"
    };
    let type_text = node
        .child_by_field_name("type")
        .map(|child| format!(": {}", scala_node_text(child, source).trim()))
        .unwrap_or_default();
    let initializer = node
        .child_by_field_name("value")
        .and_then(|value| scala_literal_initializer(value, source, node.start_position().column))
        .map(|value| format!(" = {value}"))
        .unwrap_or_default();

    format!(
        "{}{} {}{}{}",
        scala_modifier_prefix(node, source),
        keyword,
        name,
        type_text,
        initializer
    )
}

fn scala_modifier_prefix(node: Node<'_>, source: &str) -> String {
    let mut modifiers = Vec::new();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "modifiers" | "access_modifier" => {
                let text = scala_node_text(child, source).trim();
                if !text.is_empty() {
                    modifiers.push(text.to_string());
                }
            }
            _ => {}
        }
    }

    if modifiers.is_empty() {
        String::new()
    } else {
        format!("{} ", modifiers.join(" "))
    }
}

fn scala_pattern_names(node: Node<'_>, source: &str) -> Vec<String> {
    match node.kind() {
        "identifier" | "operator_identifier" => {
            vec![scala_node_text(node, source).trim().to_string()]
        }
        "identifiers" => {
            let mut names = Vec::new();
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                if matches!(child.kind(), "identifier" | "operator_identifier") {
                    let text = scala_node_text(child, source).trim();
                    if !text.is_empty() {
                        names.push(text.to_string());
                    }
                }
            }
            names
        }
        _ => {
            let text = scala_node_text(node, source).trim();
            if text.is_empty() {
                Vec::new()
            } else {
                vec![text.to_string()]
            }
        }
    }
}

fn scala_literal_initializer(
    node: Node<'_>,
    source: &str,
    declaration_indent: usize,
) -> Option<String> {
    let kind = node.kind();
    if kind == "string"
        || kind.ends_with("_literal")
        || matches!(kind, "true" | "false" | "null" | "null_literal")
    {
        let text = scala_node_text(node, source).trim().to_string();
        Some(strip_declaration_indent(&text, declaration_indent))
    } else {
        None
    }
}

fn last_segment(name: &str) -> &str {
    name.rsplit('.').next().unwrap_or(name)
}

fn scala_contains_tests(source: &str) -> bool {
    source.contains("@Test")
        || source.contains("@org.junit.Test")
        || source.contains("test(\"")
        || source.contains("test (\"")
        || (source.contains(" should ") && source.contains(" in {"))
}

fn strip_declaration_indent(text: &str, declaration_indent: usize) -> String {
    let continuation_indent = declaration_indent.saturating_sub(2);
    let mut lines = text.lines();
    let Some(first) = lines.next() else {
        return String::new();
    };
    let mut normalized = vec![first.to_string()];
    for line in lines {
        let trimmed = if line.trim().is_empty() {
            String::new()
        } else {
            line.chars().skip(continuation_indent).collect::<String>()
        };
        normalized.push(trimmed);
    }
    normalized.join("\n")
}
