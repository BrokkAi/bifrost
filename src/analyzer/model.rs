use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::fmt;
use std::fs::File;
use std::hash::{Hash, Hasher};
use std::io;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Language {
    None,
    Java,
    Go,
    Cpp,
    JavaScript,
    TypeScript,
    Python,
    Rust,
    Php,
    Scala,
    CSharp,
}

impl Language {
    pub fn extensions(self) -> &'static [&'static str] {
        match self {
            Language::None => &[],
            Language::Java => &["java"],
            Language::Go => &["go"],
            Language::Cpp => &["c", "cc", "cpp", "cxx", "h", "hpp", "hh", "hxx"],
            Language::JavaScript => &["js", "mjs", "cjs", "jsx"],
            Language::TypeScript => &["ts", "tsx"],
            Language::Python => &["py"],
            Language::Rust => &["rs"],
            Language::Php => &["php"],
            Language::Scala => &["scala"],
            Language::CSharp => &["cs"],
        }
    }

    pub fn from_extension(extension: &str) -> Self {
        let normalized = extension.trim_start_matches('.').to_ascii_lowercase();
        for language in [
            Language::Java,
            Language::Go,
            Language::Cpp,
            Language::JavaScript,
            Language::TypeScript,
            Language::Python,
            Language::Rust,
            Language::Php,
            Language::Scala,
            Language::CSharp,
        ] {
            if language.extensions().contains(&normalized.as_str()) {
                return language;
            }
        }
        Language::None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum CodeUnitType {
    Class,
    Function,
    Field,
    Module,
    Macro,
}

impl CodeUnitType {
    /// Lowercase English label suitable for inline use in human-facing
    /// report sentences (e.g. "large class spans 423 lines"). Distinct from
    /// the on-disk persistence label so the two evolve independently.
    pub fn display_lowercase(&self) -> &'static str {
        match self {
            CodeUnitType::Class => "class",
            CodeUnitType::Function => "function",
            CodeUnitType::Field => "field",
            CodeUnitType::Module => "module",
            CodeUnitType::Macro => "macro",
        }
    }
}

#[derive(Debug, PartialEq, Eq, Hash)]
struct ProjectFileInner {
    root: PathBuf,
    rel_path: PathBuf,
}

#[derive(Clone)]
pub struct ProjectFile(Arc<ProjectFileInner>);

impl ProjectFile {
    pub fn new(root: impl Into<PathBuf>, rel_path: impl Into<PathBuf>) -> Self {
        let root = root.into();
        let rel_path = rel_path.into();

        assert!(root.is_absolute(), "project root must be absolute");
        assert!(
            !rel_path.is_absolute(),
            "project file path must be relative"
        );

        Self(Arc::new(ProjectFileInner {
            root: root.normalize(),
            rel_path: rel_path.normalize(),
        }))
    }

    pub fn root(&self) -> &Path {
        &self.0.root
    }

    pub fn rel_path(&self) -> &Path {
        &self.0.rel_path
    }

    pub fn abs_path(&self) -> PathBuf {
        self.0.root.join(&self.0.rel_path)
    }

    pub fn parent(&self) -> PathBuf {
        self.0
            .rel_path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_default()
    }

    pub fn exists(&self) -> bool {
        self.abs_path().exists()
    }

    pub fn is_binary(&self) -> io::Result<bool> {
        let path = self.abs_path();
        if !path.exists() || !path.is_file() {
            return Ok(false);
        }

        let mut file = File::open(path)?;
        let mut buf = [0u8; 8192];
        let read = file.read(&mut buf)?;
        Ok(buf[..read].contains(&0))
    }

    pub fn read_to_string(&self) -> io::Result<String> {
        std::fs::read_to_string(self.abs_path())
    }

    pub fn write(&self, contents: impl AsRef<str>) -> io::Result<()> {
        if let Some(parent) = self.abs_path().parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(self.abs_path(), contents.as_ref())
    }
}

impl fmt::Debug for ProjectFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProjectFile")
            .field("root", &self.0.root)
            .field("rel_path", &self.0.rel_path)
            .finish()
    }
}

impl PartialEq for ProjectFile {
    fn eq(&self, other: &Self) -> bool {
        self.0.root == other.0.root && self.0.rel_path == other.0.rel_path
    }
}

impl Eq for ProjectFile {}

impl Hash for ProjectFile {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.root.hash(state);
        self.0.rel_path.hash(state);
    }
}

impl Ord for ProjectFile {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.0.root.cmp(&other.0.root) {
            Ordering::Equal => self.0.rel_path.cmp(&other.0.rel_path),
            ordering => ordering,
        }
    }
}

impl PartialOrd for ProjectFile {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for ProjectFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.rel_path.display())
    }
}

#[derive(Debug, PartialEq, Eq, Hash)]
struct CodeUnitInner {
    source: ProjectFile,
    kind: CodeUnitType,
    package_name: String,
    short_name: String,
    signature: Option<String>,
    synthetic: bool,
}

#[derive(Clone)]
pub struct CodeUnit(Arc<CodeUnitInner>);

impl CodeUnit {
    pub fn new(
        source: ProjectFile,
        kind: CodeUnitType,
        package_name: impl Into<String>,
        short_name: impl Into<String>,
    ) -> Self {
        Self::with_signature(source, kind, package_name, short_name, None, false)
    }

    pub fn with_signature(
        source: ProjectFile,
        kind: CodeUnitType,
        package_name: impl Into<String>,
        short_name: impl Into<String>,
        signature: Option<String>,
        synthetic: bool,
    ) -> Self {
        let package_name = package_name.into();
        let short_name = short_name.into();
        assert!(
            !short_name.is_empty(),
            "short_name must not be empty (kind={kind:?}, package_name={package_name:?}, source={source}, signature={signature:?}, synthetic={synthetic})"
        );

        Self(Arc::new(CodeUnitInner {
            source,
            kind,
            package_name,
            short_name,
            signature,
            synthetic,
        }))
    }

    pub fn source(&self) -> &ProjectFile {
        &self.0.source
    }

    pub fn kind(&self) -> CodeUnitType {
        self.0.kind
    }

    pub fn package_name(&self) -> &str {
        &self.0.package_name
    }

    pub fn short_name(&self) -> &str {
        &self.0.short_name
    }

    pub fn signature(&self) -> Option<&str> {
        self.0.signature.as_deref()
    }

    pub fn is_synthetic(&self) -> bool {
        self.0.synthetic
    }

    pub fn is_anonymous(&self) -> bool {
        self.0.short_name.contains("$anon$")
    }

    pub fn fq_name(&self) -> String {
        if self.0.package_name.is_empty() {
            self.0.short_name.clone()
        } else {
            format!("{}.{}", self.0.package_name, self.0.short_name)
        }
    }

    // This is the structural identifier used by lookup, import, and usage code.
    // For user-facing names, prefer the display helpers in `analyzer::common`
    // so languages like Scala can render idiomatic names without changing the
    // matching semantics encoded here.
    pub fn identifier(&self) -> &str {
        let member_name = self
            .0
            .short_name
            .rsplit('.')
            .next()
            .unwrap_or(&self.0.short_name);
        if matches!(self.0.kind, CodeUnitType::Function | CodeUnitType::Field)
            || member_name.ends_with('$')
        {
            member_name
        } else {
            member_name.rsplit('$').next().unwrap_or(member_name)
        }
    }

    pub fn without_signature(&self) -> Self {
        Self::with_signature(
            self.0.source.clone(),
            self.0.kind,
            self.0.package_name.clone(),
            self.0.short_name.clone(),
            None,
            self.0.synthetic,
        )
    }

    pub fn with_synthetic(&self, synthetic: bool) -> Self {
        Self::with_signature(
            self.0.source.clone(),
            self.0.kind,
            self.0.package_name.clone(),
            self.0.short_name.clone(),
            self.0.signature.clone(),
            synthetic,
        )
    }

    pub fn is_class(&self) -> bool {
        self.0.kind == CodeUnitType::Class
    }

    pub fn is_function(&self) -> bool {
        self.0.kind == CodeUnitType::Function
    }

    pub fn is_field(&self) -> bool {
        self.0.kind == CodeUnitType::Field
    }

    pub fn is_module(&self) -> bool {
        self.0.kind == CodeUnitType::Module
    }

    pub fn is_macro(&self) -> bool {
        self.0.kind == CodeUnitType::Macro
    }
}

impl fmt::Debug for CodeUnit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CodeUnit")
            .field("source", &self.0.source)
            .field("kind", &self.0.kind)
            .field("package_name", &self.0.package_name)
            .field("short_name", &self.0.short_name)
            .field("signature", &self.0.signature)
            .field("synthetic", &self.0.synthetic)
            .finish()
    }
}

impl PartialEq for CodeUnit {
    fn eq(&self, other: &Self) -> bool {
        self.0.source == other.0.source
            && self.0.kind == other.0.kind
            && self.0.package_name == other.0.package_name
            && self.0.short_name == other.0.short_name
            && self.0.signature == other.0.signature
            && self.0.synthetic == other.0.synthetic
    }
}

impl Eq for CodeUnit {}

impl Hash for CodeUnit {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.source.hash(state);
        self.0.kind.hash(state);
        self.0.package_name.hash(state);
        self.0.short_name.hash(state);
        self.0.signature.hash(state);
        self.0.synthetic.hash(state);
    }
}

impl Ord for CodeUnit {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0
            .package_name
            .cmp(&other.0.package_name)
            .then_with(|| self.0.short_name.cmp(&other.0.short_name))
            .then_with(|| self.0.kind.cmp(&other.0.kind))
            .then_with(|| self.0.source.cmp(&other.0.source))
            .then_with(|| self.0.signature.cmp(&other.0.signature))
            .then_with(|| self.0.synthetic.cmp(&other.0.synthetic))
    }
}

impl PartialOrd for CodeUnit {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Range {
    pub start_byte: usize,
    pub end_byte: usize,
    pub start_line: usize,
    pub end_line: usize,
}

/// A tree-sitter parse-error span captured during analysis so the LSP
/// diagnostic handler can skip re-parsing on every request. `kind` records
/// whether tree-sitter flagged the span as an `ERROR` node or a `MISSING`
/// child; for missing nodes we also keep the grammar's expected-node name so
/// the diagnostic message reads "missing foo".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub range: Range,
    pub kind: ParseErrorKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseErrorKind {
    /// A tree-sitter `ERROR` node — unexpected/unparseable input.
    Error,
    /// A `MISSING` node — the parser inserted a placeholder for a token the
    /// grammar required. The wrapped string is the node kind that was
    /// expected (e.g. `"}"`, `";"`).
    Missing(String),
}

/// Comment line counts and span lines for a [`CodeUnit`], with optional roll-up
/// of nested declarations (e.g. methods inside a class). Mirrors brokk-shared
/// `CommentDensityStats` field-for-field so report output stays byte-for-byte
/// equivalent to brokk-core MCP.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommentDensityStats {
    pub fq_name: String,
    pub relative_path: String,
    pub header_comment_lines: u32,
    pub inline_comment_lines: u32,
    /// Lines covered by this declaration's ranges (may sum overload ranges).
    pub span_lines: u32,
    /// Header lines including nested declarations (for class-like units equals own plus children).
    pub rolled_up_header_comment_lines: u32,
    /// Inline lines including nested declarations.
    pub rolled_up_inline_comment_lines: u32,
    /// Span lines including nested declarations (sum of descendant spans for roll-up).
    pub rolled_up_span_lines: u32,
}

/// Tunable weights for test-assertion smell detection. Mirrors the Brokk
/// analyzer defaults so MCP output stays behaviorally aligned when Bifrost is
/// used as a drop-in replacement for this tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TestAssertionWeights {
    pub no_assertion_weight: i32,
    pub tautological_assertion_weight: i32,
    pub constant_truth_weight: i32,
    pub constant_equality_weight: i32,
    pub nullness_only_weight: i32,
    pub shallow_assertion_only_weight: i32,
    pub overspecified_literal_weight: i32,
    pub anonymous_test_double_weight: i32,
    pub repeated_anonymous_test_double_weight: i32,
    pub meaningful_assertion_credit: i32,
    pub meaningful_assertion_credit_cap: i32,
    pub large_literal_length_threshold: i32,
}

impl TestAssertionWeights {
    pub fn defaults() -> Self {
        Self {
            no_assertion_weight: 5,
            tautological_assertion_weight: 6,
            constant_truth_weight: 4,
            constant_equality_weight: 4,
            nullness_only_weight: 2,
            shallow_assertion_only_weight: 2,
            overspecified_literal_weight: 2,
            anonymous_test_double_weight: 3,
            repeated_anonymous_test_double_weight: 5,
            meaningful_assertion_credit: 1,
            meaningful_assertion_credit_cap: 4,
            large_literal_length_threshold: 120,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestAssertionSmell {
    pub file: ProjectFile,
    pub enclosing_fq_name: String,
    pub assertion_kind: String,
    pub score: i32,
    pub assertion_count: i32,
    pub reasons: Vec<String>,
    pub excerpt: String,
    pub start_byte: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloneSmellWeights {
    pub min_normalized_tokens: i32,
    pub min_similarity_percent: i32,
    pub shingle_size: i32,
    pub min_shared_shingles: i32,
    pub ast_similarity_percent: i32,
}

impl CloneSmellWeights {
    pub fn defaults() -> Self {
        Self {
            min_normalized_tokens: 12,
            min_similarity_percent: 60,
            shingle_size: 2,
            min_shared_shingles: 3,
            ast_similarity_percent: 70,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloneSmell {
    pub file: ProjectFile,
    pub enclosing_fq_name: String,
    pub peer_file: ProjectFile,
    pub peer_enclosing_fq_name: String,
    pub score: i32,
    pub normalized_token_count: i32,
    pub reasons: Vec<String>,
    pub excerpt: String,
    pub peer_excerpt: String,
}

/// Tunable weights for the exception-handling smell heuristic. Mirrors
/// brokk-shared `IAnalyzer.ExceptionSmellWeights` field-for-field; callers
/// can override individual fields by passing positive values and otherwise
/// fall back to [`ExceptionSmellWeights::defaults`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExceptionSmellWeights {
    pub generic_throwable_weight: i32,
    pub generic_exception_weight: i32,
    pub generic_runtime_exception_weight: i32,
    pub empty_body_weight: i32,
    pub comment_only_body_weight: i32,
    pub small_body_weight: i32,
    pub log_only_weight: i32,
    pub meaningful_body_credit_per_statement: i32,
    pub meaningful_body_statement_threshold: i32,
    pub small_body_max_statements: i32,
}

impl ExceptionSmellWeights {
    /// Default weights copied verbatim from brokk-shared
    /// `IAnalyzer.ExceptionSmellWeights.defaults()` — keep these in lock-step
    /// so identical input files produce identical scores across the two MCP
    /// servers.
    pub fn defaults() -> Self {
        Self {
            generic_throwable_weight: 5,
            generic_exception_weight: 3,
            generic_runtime_exception_weight: 2,
            empty_body_weight: 5,
            comment_only_body_weight: 4,
            small_body_weight: 2,
            log_only_weight: 2,
            meaningful_body_credit_per_statement: 1,
            meaningful_body_statement_threshold: 6,
            small_body_max_statements: 2,
        }
    }
}

/// One suspicious catch handler reported by the analyzer. Mirrors
/// brokk-shared `IAnalyzer.ExceptionHandlingSmell`. Not serde-derived —
/// the embedded [`ProjectFile`] is only constructed inside the analyzer
/// and the report layer rebuilds the rendered table from these in-memory
/// values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExceptionHandlingSmell {
    pub file: ProjectFile,
    pub enclosing_fq_name: String,
    pub catch_type: String,
    pub score: i32,
    pub body_statement_count: u32,
    pub reasons: Vec<String>,
    pub excerpt: String,
    /// Source byte offset of the `catch` clause; used as the deterministic
    /// tie-breaker when two findings share score, file, and enclosing symbol.
    /// Not surfaced in the markdown report — kept here so callers ranking or
    /// deduping can stay stable.
    pub start_byte: usize,
}

impl Range {
    pub fn contains(&self, other: &Range) -> bool {
        self.start_byte <= other.start_byte && self.end_byte >= other.end_byte
    }

    /// Mirrors brokk-shared `Range.isEmpty()` so the maintainability-size
    /// heuristic skips degenerate ranges identically to the JVM analyzer.
    pub fn is_empty(&self) -> bool {
        self.start_line == self.end_line && self.start_byte == self.end_byte
    }

    /// Number of source lines this range spans. Matches brokk-shared
    /// `IAnalyzer.spanLines(Range)`: empty ranges report `0`, non-empty
    /// ranges report at least `1`.
    ///
    /// API note: brokk-shared puts this on `IAnalyzer` (static helper);
    /// bifrost places it on `Range` because the computation depends only
    /// on the range's own fields. Do not "re-align" by adding a trait
    /// method — the current placement is intentional.
    pub fn span_lines(&self) -> u32 {
        if self.is_empty() {
            return 0;
        }
        let diff = self.end_line.saturating_sub(self.start_line) + 1;
        diff.max(1) as u32
    }
}

/// Tunable thresholds for the long-method / god-object maintainability-size
/// heuristic. Mirrors brokk-shared `IAnalyzer.MaintainabilitySizeSmellWeights`
/// field-for-field; the brokk-core MCP wrapper falls back to
/// [`MaintainabilitySizeSmellWeights::defaults`] whenever a knob is `<= 0`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaintainabilitySizeSmellWeights {
    pub long_method_span_lines: i32,
    pub high_complexity_threshold: i32,
    pub god_object_span_lines: i32,
    pub god_object_direct_children: i32,
    pub god_object_functions: i32,
    pub helper_sprawl_functions: i32,
    pub helper_sprawl_workflow_lines: i32,
    pub file_module_leeway_multiplier: i32,
}

impl MaintainabilitySizeSmellWeights {
    /// Default thresholds copied verbatim from brokk-shared
    /// `IAnalyzer.MaintainabilitySizeSmellWeights.defaults()`. Keep these in
    /// lock-step so identical input files produce identical scores across
    /// the two MCP servers.
    pub fn defaults() -> Self {
        Self {
            long_method_span_lines: 80,
            high_complexity_threshold: 10,
            god_object_span_lines: 300,
            god_object_direct_children: 20,
            god_object_functions: 15,
            helper_sprawl_functions: 10,
            helper_sprawl_workflow_lines: 60,
            file_module_leeway_multiplier: 2,
        }
    }
}

/// One oversized function/class/module finding reported by the
/// maintainability-size heuristic. Mirrors brokk-shared
/// `IAnalyzer.MaintainabilitySizeSmell`. Not serde-derived — the embedded
/// [`CodeUnit`] only round-trips through analyzer state, and the report
/// layer renders directly from these in-memory values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaintainabilitySizeSmell {
    pub code_unit: CodeUnit,
    pub range: Range,
    pub score: i32,
    pub own_span_lines: u32,
    pub descendant_span_lines: u32,
    pub direct_child_count: u32,
    pub function_count: u32,
    pub nested_type_count: u32,
    pub max_function_span_lines: u32,
    pub max_cyclomatic_complexity: u32,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportInfo {
    pub raw_snippet: String,
    pub is_wildcard: bool,
    pub identifier: Option<String>,
    pub alias: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DeclarationKind {
    Parameter,
    LocalVariable,
    CatchParameter,
    EnhancedForVariable,
    LambdaParameter,
    PatternVariable,
    ResourceVariable,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeclarationInfo {
    pub identifier: String,
    pub kind: DeclarationKind,
    pub range: Range,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodeBaseMetrics {
    pub file_count: usize,
    pub declaration_count: usize,
}

impl CodeBaseMetrics {
    pub fn new(file_count: usize, declaration_count: usize) -> Self {
        Self {
            file_count,
            declaration_count,
        }
    }
}

pub(crate) trait NormalizePath {
    fn normalize(self) -> PathBuf;
}

impl NormalizePath for PathBuf {
    fn normalize(self) -> PathBuf {
        let mut normalized = PathBuf::new();
        for component in self.components() {
            match component {
                std::path::Component::CurDir => {}
                std::path::Component::ParentDir => {
                    normalized.pop();
                }
                component => normalized.push(component.as_os_str()),
            }
        }
        normalized
    }
}

pub fn metrics_from_declarations(
    declarations: impl IntoIterator<Item = CodeUnit>,
) -> CodeBaseMetrics {
    let declarations: Vec<CodeUnit> = declarations.into_iter().collect();
    let file_count = declarations
        .iter()
        .map(|cu| cu.source().clone())
        .collect::<BTreeSet<_>>()
        .len();
    CodeBaseMetrics::new(file_count, declarations.len())
}
