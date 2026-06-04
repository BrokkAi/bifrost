use crate::Language;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestValidationError {
    messages: Vec<String>,
}

impl ManifestValidationError {
    pub fn new(messages: Vec<String>) -> Self {
        Self { messages }
    }

    pub fn messages(&self) -> &[String] {
        &self.messages
    }

    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }
}

impl fmt::Display for ManifestValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.messages.is_empty() {
            return f.write_str("benchmark manifest validation failed");
        }

        writeln!(f, "benchmark manifest validation failed:")?;
        for message in &self.messages {
            writeln!(f, "- {message}")?;
        }
        Ok(())
    }
}

impl std::error::Error for ManifestValidationError {}

#[derive(Debug)]
pub enum ManifestLoadError {
    Io(std::io::Error),
    ParseToml(toml::de::Error),
    Validation(ManifestValidationError),
}

impl fmt::Display for ManifestLoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "failed to read benchmark manifest: {err}"),
            Self::ParseToml(err) => write!(f, "failed to parse benchmark manifest TOML: {err}"),
            Self::Validation(err) => err.fmt(f),
        }
    }
}

impl std::error::Error for ManifestLoadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::ParseToml(err) => Some(err),
            Self::Validation(err) => Some(err),
        }
    }
}

impl From<std::io::Error> for ManifestLoadError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<toml::de::Error> for ManifestLoadError {
    fn from(value: toml::de::Error) -> Self {
        Self::ParseToml(value)
    }
}

impl From<ManifestValidationError> for ManifestLoadError {
    fn from(value: ManifestValidationError) -> Self {
        Self::Validation(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ManifestLanguage {
    #[serde(rename = "java")]
    Java,
    #[serde(rename = "go")]
    Go,
    #[serde(rename = "cpp")]
    Cpp,
    #[serde(rename = "javascript")]
    JavaScript,
    #[serde(rename = "typescript")]
    TypeScript,
    #[serde(rename = "python")]
    Python,
    #[serde(rename = "rust")]
    Rust,
    #[serde(rename = "php")]
    Php,
    #[serde(rename = "scala")]
    Scala,
    #[serde(rename = "csharp")]
    CSharp,
}

impl ManifestLanguage {
    pub const ALL: [Self; 10] = [
        Self::Java,
        Self::Go,
        Self::Cpp,
        Self::JavaScript,
        Self::TypeScript,
        Self::Python,
        Self::Rust,
        Self::Php,
        Self::Scala,
        Self::CSharp,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::Java => "java",
            Self::Go => "go",
            Self::Cpp => "cpp",
            Self::JavaScript => "javascript",
            Self::TypeScript => "typescript",
            Self::Python => "python",
            Self::Rust => "rust",
            Self::Php => "php",
            Self::Scala => "scala",
            Self::CSharp => "csharp",
        }
    }

    pub fn analyzer_language(self) -> Language {
        match self {
            Self::Java => Language::Java,
            Self::Go => Language::Go,
            Self::Cpp => Language::Cpp,
            Self::JavaScript => Language::JavaScript,
            Self::TypeScript => Language::TypeScript,
            Self::Python => Language::Python,
            Self::Rust => Language::Rust,
            Self::Php => Language::Php,
            Self::Scala => Language::Scala,
            Self::CSharp => Language::CSharp,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum BenchmarkScenario {
    #[serde(rename = "workspace_build")]
    WorkspaceBuild,
    #[serde(rename = "search_symbols")]
    SearchSymbols,
    #[serde(rename = "get_symbol_locations")]
    GetSymbolLocations,
    #[serde(rename = "get_summaries")]
    GetSummaries,
    #[serde(rename = "most_relevant_files")]
    MostRelevantFiles,
}

impl BenchmarkScenario {
    pub const ALL: [Self; 5] = [
        Self::WorkspaceBuild,
        Self::SearchSymbols,
        Self::GetSymbolLocations,
        Self::GetSummaries,
        Self::MostRelevantFiles,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::WorkspaceBuild => "workspace_build",
            Self::SearchSymbols => "search_symbols",
            Self::GetSymbolLocations => "get_symbol_locations",
            Self::GetSummaries => "get_summaries",
            Self::MostRelevantFiles => "most_relevant_files",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkManifest {
    #[serde(default = "default_warmup_iterations")]
    pub warmup_iterations: usize,
    #[serde(default = "default_measured_iterations")]
    pub measured_iterations: usize,
    #[serde(default = "default_output_dir")]
    pub output_dir: PathBuf,
    #[serde(default = "default_repo_cache_dir")]
    pub repo_cache_dir: PathBuf,
    #[serde(default = "default_required_languages")]
    pub required_languages: Vec<ManifestLanguage>,
    #[serde(default = "default_required_scenarios")]
    pub required_scenarios: Vec<BenchmarkScenario>,
    #[serde(default)]
    pub repos: Vec<BenchmarkRepoTarget>,
}

impl BenchmarkManifest {
    pub fn from_toml_str(contents: &str) -> Result<Self, ManifestLoadError> {
        let manifest: Self = toml::from_str(contents)?;
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn load_from_path(path: impl AsRef<Path>) -> Result<Self, ManifestLoadError> {
        let contents = fs::read_to_string(path)?;
        Self::from_toml_str(&contents)
    }

    pub fn validate(&self) -> Result<(), ManifestValidationError> {
        let mut errors = Vec::new();

        if self.warmup_iterations == 0 {
            errors.push("warmup_iterations must be greater than zero".to_string());
        }
        if self.measured_iterations == 0 {
            errors.push("measured_iterations must be greater than zero".to_string());
        }
        if self.repos.is_empty() {
            errors.push("manifest must define at least one [[repos]] entry".to_string());
        }

        let required_languages = dedupe_languages(&self.required_languages);
        if required_languages.is_empty() {
            errors.push("required_languages must not be empty".to_string());
        }

        let required_scenarios = dedupe_scenarios(&self.required_scenarios);
        if required_scenarios.is_empty() {
            errors.push("required_scenarios must not be empty".to_string());
        }

        let mut seen_repo_names = BTreeSet::new();
        let mut covered_languages = BTreeSet::new();
        let mut covered_scenarios = BTreeSet::new();

        for repo in &self.repos {
            repo.validate(&mut errors);
            if !repo.name.trim().is_empty() && !seen_repo_names.insert(repo.name.trim().to_string())
            {
                errors.push(format!("duplicate repo name `{}`", repo.name.trim()));
            }

            for language in repo.language_set() {
                covered_languages.insert(language);
            }
            for scenario in repo.scenario_set() {
                covered_scenarios.insert(scenario);
            }
        }

        for required_language in required_languages {
            if !covered_languages.contains(&required_language) {
                errors.push(format!(
                    "required language `{}` is not covered by any repo entry",
                    required_language.label()
                ));
            }
        }

        for required_scenario in required_scenarios {
            if !covered_scenarios.contains(&required_scenario) {
                errors.push(format!(
                    "required scenario `{}` is not enabled by any repo entry",
                    required_scenario.label()
                ));
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(ManifestValidationError::new(errors))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkRepoTarget {
    pub name: String,
    pub url: String,
    pub commit: String,
    pub languages: Vec<ManifestLanguage>,
    #[serde(default)]
    pub extensions: Vec<String>,
    pub scenarios: Vec<BenchmarkScenario>,
    #[serde(default)]
    pub search_patterns: Vec<String>,
    #[serde(default)]
    pub location_symbols: Vec<String>,
    #[serde(default)]
    pub summary_targets: Vec<String>,
    #[serde(default)]
    pub seed_file_paths: Vec<String>,
}

impl BenchmarkRepoTarget {
    pub fn language_set(&self) -> BTreeSet<ManifestLanguage> {
        dedupe_languages(&self.languages)
    }

    pub fn scenario_set(&self) -> BTreeSet<BenchmarkScenario> {
        dedupe_scenarios(&self.scenarios)
    }

    fn validate(&self, errors: &mut Vec<String>) {
        let name = self.name.trim();
        if name.is_empty() {
            errors.push("repo entry has an empty name".to_string());
        }

        if self.url.trim().is_empty() {
            errors.push(format!("repo `{name}` must define a non-empty url"));
        }
        if self.commit.trim().is_empty() {
            errors.push(format!("repo `{name}` must define a non-empty commit"));
        }

        let languages = self.language_set();
        if languages.is_empty() {
            errors.push(format!("repo `{name}` must define at least one language"));
        }

        let scenarios = self.scenario_set();
        if scenarios.is_empty() {
            errors.push(format!("repo `{name}` must define at least one scenario"));
        }

        for extension in &self.extensions {
            let normalized = normalize_extension(extension);
            if normalized.is_empty() {
                errors.push(format!("repo `{name}` has an empty extension filter"));
                continue;
            }

            let language = Language::from_extension(&normalized);
            if language == Language::None {
                errors.push(format!(
                    "repo `{name}` uses unsupported extension filter `{}`",
                    extension
                ));
                continue;
            }

            let extension_language = manifest_language_from_analyzer(language).expect("supported");
            if !languages.contains(&extension_language) {
                errors.push(format!(
                    "repo `{name}` uses extension `{}` for language `{}`, but that language is not listed in languages",
                    extension,
                    extension_language.label()
                ));
            }
        }

        if scenarios.contains(&BenchmarkScenario::SearchSymbols)
            && !has_non_blank_values(&self.search_patterns)
        {
            errors.push(format!(
                "repo `{name}` enables `search_symbols` but does not define search_patterns"
            ));
        }

        if scenarios.contains(&BenchmarkScenario::GetSymbolLocations)
            && !has_non_blank_values(&self.location_symbols)
        {
            errors.push(format!(
                "repo `{name}` enables `get_symbol_locations` but does not define location_symbols"
            ));
        }

        if scenarios.contains(&BenchmarkScenario::GetSummaries)
            && !has_non_blank_values(&self.summary_targets)
        {
            errors.push(format!(
                "repo `{name}` enables `get_summaries` but does not define summary_targets"
            ));
        }

        if scenarios.contains(&BenchmarkScenario::MostRelevantFiles)
            && !has_non_blank_values(&self.seed_file_paths)
        {
            errors.push(format!(
                "repo `{name}` enables `most_relevant_files` but does not define seed_file_paths"
            ));
        }
    }
}

fn default_warmup_iterations() -> usize {
    1
}

fn default_measured_iterations() -> usize {
    3
}

fn default_output_dir() -> PathBuf {
    PathBuf::from("benchmark-output")
}

fn default_repo_cache_dir() -> PathBuf {
    PathBuf::from("target/benchmark-repos")
}

fn default_required_languages() -> Vec<ManifestLanguage> {
    ManifestLanguage::ALL.to_vec()
}

fn default_required_scenarios() -> Vec<BenchmarkScenario> {
    BenchmarkScenario::ALL.to_vec()
}

fn dedupe_languages(languages: &[ManifestLanguage]) -> BTreeSet<ManifestLanguage> {
    languages.iter().copied().collect()
}

fn dedupe_scenarios(scenarios: &[BenchmarkScenario]) -> BTreeSet<BenchmarkScenario> {
    scenarios.iter().copied().collect()
}

fn normalize_extension(extension: &str) -> String {
    extension
        .trim()
        .trim_start_matches('.')
        .to_ascii_lowercase()
}

fn has_non_blank_values(values: &[String]) -> bool {
    values.iter().any(|value| !value.trim().is_empty())
}

fn manifest_language_from_analyzer(language: Language) -> Option<ManifestLanguage> {
    match language {
        Language::Java => Some(ManifestLanguage::Java),
        Language::Go => Some(ManifestLanguage::Go),
        Language::Cpp => Some(ManifestLanguage::Cpp),
        Language::JavaScript => Some(ManifestLanguage::JavaScript),
        Language::TypeScript => Some(ManifestLanguage::TypeScript),
        Language::Python => Some(ManifestLanguage::Python),
        Language::Rust => Some(ManifestLanguage::Rust),
        Language::Php => Some(ManifestLanguage::Php),
        Language::Scala => Some(ManifestLanguage::Scala),
        Language::CSharp => Some(ManifestLanguage::CSharp),
        Language::None => None,
    }
}
