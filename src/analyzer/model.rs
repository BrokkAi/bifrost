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

    /// Regex templates for usage search, parameterized by `$ident` (a placeholder for the
    /// quoted identifier). Mirrors `Language#getSearchPatterns` in brokk.
    ///
    /// The default fallback is `\b$ident\b` — a word-boundary literal match — used for any
    /// `(language, kind)` pair without a specific override.
    pub fn search_patterns(self, kind: CodeUnitType) -> &'static [&'static str] {
        const DEFAULT: &[&str] = &[r"\b$ident\b"];

        match (self, kind) {
            (Language::Java, CodeUnitType::Function) => &[r"\b$ident\s*\(", r"::\s*$ident\b"],
            (Language::Java, CodeUnitType::Class) => &[
                r"\bnew\s+$ident(?:<.+?>)?\s*\(",
                r"\bextends\s+$ident(?:<.+?>)?",
                r"\bimplements\s+$ident(?:<.+?>)?",
                r"\b$ident\s*\.",
                r"\b$ident(?:<.+?>)?\s+\w+\s*[;=]",
                r"\b$ident(?:<.+?>)?\s+\w+\s*\)",
                r"<\s*$ident\s*>",
                r"\(\s*$ident(?:<.+?>)?\s*\)",
                r"\bimport\s+.*\.$ident\b",
            ],

            (Language::Python, CodeUnitType::Function) => &[r"\b$ident\s*\(", r"\.$ident\s*\("],
            (Language::Python, CodeUnitType::Class) => &[
                r"\b$ident\s*\(",
                r"\bclass\s+\w+\s*\([^)]*$ident[^)]*\):",
                r"\b$ident\s*\.",
                r":\s*$ident\b",
                r"->\s*$ident\b",
                r"\bfrom\s+.*\s+import\s+.*$ident",
                r"\bimport\s+.*\.$ident\b",
            ],

            (Language::Rust, CodeUnitType::Function) => &[r"\b$ident\s*\(", r"\.$ident\s*\("],
            (Language::Rust, CodeUnitType::Class) => &[
                r"\b$ident(?:<.+?>)?\s*\{",
                r"\b$ident(?:<.+?>)?\s*\(",
                r"\bimpl\s+[^{\n]+\s+for\s+$ident(?:<.+?>)?",
                r"\bimpl(?:<.+?>)?\s+$ident(?:<.+?>)?",
                r"\b$ident::",
                r":\s*$ident(?:<.+?>)?",
                r"->\s*$ident(?:<.+?>)?",
                r"<\s*$ident\s*>",
                r"\buse\s+[^{\n]*::$ident\b",
            ],

            (Language::Cpp, CodeUnitType::Function) => {
                &[r"\b$ident\s*\(", r"\.$ident\s*\(", r"::\s*$ident\s*\("]
            }
            (Language::Cpp, CodeUnitType::Class) => &[
                r"\bnew\s+$ident(?:<.+?>)?\s*\(",
                r"\bclass\s+\w+\s*:\s*public\s+$ident(?:<.+?>)?",
                r"\bclass\s+\w+\s*:\s*private\s+$ident(?:<.+?>)?",
                r"\bclass\s+\w+\s*:\s*protected\s+$ident(?:<.+?>)?",
                r"\b$ident(?:<.+?>)?\s+\w+\s*[;=]",
                r"\b$ident(?:<.+?>)?\s*\*",
                r"\b$ident(?:<.+?>)?\s*&",
                r"<\s*$ident\s*>",
                r#"#include\s+"$ident\.h""#,
            ],

            (Language::Scala, CodeUnitType::Function) => &[r"\b$ident\s*\(", r"\.$ident\s*\("],
            (Language::Scala, CodeUnitType::Class) => &[
                r"\bnew\s+$ident(?:\[.+?\])?\s*\(",
                r"\bextends\s+$ident(?:\[.+?\])?",
                r"\bwith\s+$ident(?:\[.+?\])?",
                r"\b$ident\s*\.",
                r":\s*$ident(?:\[.+?\])?",
                r"<\s*$ident\s*>",
                r"\[\s*$ident\s*\]",
                r"\bcase\s+class\s+\w+.*:\s*$ident(?:\[.+?\])?",
                r"\bimport\s+.*\.$ident\b",
            ],

            (Language::Go, CodeUnitType::Function) => &[r"\b$ident\s*\("],

            // JavaScript / TypeScript / PHP / C# / Module / Field / None: fall back to the
            // generic word-boundary match. JS/TS get their richer graph strategy elsewhere.
            _ => DEFAULT,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum CodeUnitType {
    Class,
    Function,
    Field,
    Module,
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

    pub fn identifier(&self) -> &str {
        let name = self
            .0
            .short_name
            .rsplit(['.', '$'])
            .next()
            .unwrap_or(&self.0.short_name);
        if matches!(self.0.kind, CodeUnitType::Function | CodeUnitType::Field) {
            self.0.short_name.rsplit('.').next().unwrap_or(name)
        } else {
            name
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

impl Range {
    pub fn contains(&self, other: &Range) -> bool {
        self.start_byte <= other.start_byte && self.end_byte >= other.end_byte
    }
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
