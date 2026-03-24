use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CodeUnitType {
    Class,
    Function,
    Field,
    Module,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProjectFile {
    root: PathBuf,
    rel_path: PathBuf,
}

impl ProjectFile {
    pub fn new(root: impl Into<PathBuf>, rel_path: impl Into<PathBuf>) -> Self {
        let root = root.into();
        let rel_path = rel_path.into();

        assert!(root.is_absolute(), "project root must be absolute");
        assert!(!rel_path.is_absolute(), "project file path must be relative");

        Self {
            root: root.normalize(),
            rel_path: rel_path.normalize(),
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn rel_path(&self) -> &Path {
        &self.rel_path
    }

    pub fn abs_path(&self) -> PathBuf {
        self.root.join(&self.rel_path)
    }

    pub fn parent(&self) -> PathBuf {
        self.rel_path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_default()
    }

    pub fn exists(&self) -> bool {
        self.abs_path().exists()
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

impl Ord for ProjectFile {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.root.cmp(&other.root) {
            Ordering::Equal => self.rel_path.cmp(&other.rel_path),
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
        write!(f, "{}", self.rel_path.display())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CodeUnit {
    source: ProjectFile,
    kind: CodeUnitType,
    package_name: String,
    short_name: String,
    signature: Option<String>,
    synthetic: bool,
}

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
        let short_name = short_name.into();
        assert!(!short_name.is_empty(), "short_name must not be empty");

        Self {
            source,
            kind,
            package_name: package_name.into(),
            short_name,
            signature,
            synthetic,
        }
    }

    pub fn source(&self) -> &ProjectFile {
        &self.source
    }

    pub fn kind(&self) -> CodeUnitType {
        self.kind
    }

    pub fn package_name(&self) -> &str {
        &self.package_name
    }

    pub fn short_name(&self) -> &str {
        &self.short_name
    }

    pub fn signature(&self) -> Option<&str> {
        self.signature.as_deref()
    }

    pub fn is_synthetic(&self) -> bool {
        self.synthetic
    }

    pub fn fq_name(&self) -> String {
        if self.package_name.is_empty() {
            self.short_name.clone()
        } else {
            format!("{}.{}", self.package_name, self.short_name)
        }
    }

    pub fn identifier(&self) -> &str {
        let name = self.short_name.rsplit(['.', '$']).next().unwrap_or(&self.short_name);
        if matches!(self.kind, CodeUnitType::Function | CodeUnitType::Field) {
            self.short_name.rsplit('.').next().unwrap_or(name)
        } else {
            name
        }
    }

    pub fn without_signature(&self) -> Self {
        Self::with_signature(
            self.source.clone(),
            self.kind,
            self.package_name.clone(),
            self.short_name.clone(),
            None,
            self.synthetic,
        )
    }

    pub fn with_synthetic(&self, synthetic: bool) -> Self {
        Self::with_signature(
            self.source.clone(),
            self.kind,
            self.package_name.clone(),
            self.short_name.clone(),
            self.signature.clone(),
            synthetic,
        )
    }

    pub fn is_class(&self) -> bool {
        self.kind == CodeUnitType::Class
    }

    pub fn is_function(&self) -> bool {
        self.kind == CodeUnitType::Function
    }

    pub fn is_field(&self) -> bool {
        self.kind == CodeUnitType::Field
    }

    pub fn is_module(&self) -> bool {
        self.kind == CodeUnitType::Module
    }
}

impl Ord for CodeUnit {
    fn cmp(&self, other: &Self) -> Ordering {
        (
            self.fq_name(),
            self.kind,
            self.source.clone(),
            self.signature.clone(),
            self.synthetic,
        )
            .cmp(&(
                other.fq_name(),
                other.kind,
                other.source.clone(),
                other.signature.clone(),
                other.synthetic,
            ))
    }
}

impl PartialOrd for CodeUnit {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
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

#[derive(Debug, Clone, PartialEq, Eq)]
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

pub fn metrics_from_declarations(declarations: impl IntoIterator<Item = CodeUnit>) -> CodeBaseMetrics {
    let declarations: Vec<CodeUnit> = declarations.into_iter().collect();
    let file_count = declarations
        .iter()
        .map(|cu| cu.source().clone())
        .collect::<BTreeSet<_>>()
        .len();
    CodeBaseMetrics::new(file_count, declarations.len())
}
