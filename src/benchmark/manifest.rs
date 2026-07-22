use crate::Language;
use crate::analyzer::structural::{
    CodeQuery, CodeQueryPlanSource, CodeQuerySeed, Pattern, StringPredicate,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

const MAX_QUERY_CODE_CASE_ID_LENGTH: usize = 64;

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
    #[serde(rename = "get_symbol_ancestors")]
    GetSymbolAncestors,
    #[serde(rename = "get_summaries")]
    GetSummaries,
    #[serde(rename = "most_relevant_files")]
    MostRelevantFiles,
    #[serde(rename = "scan_usages")]
    ScanUsages,
    #[serde(rename = "dead_code_smells")]
    DeadCodeSmells,
    #[serde(rename = "get_definition")]
    GetDefinition,
    #[serde(rename = "call_hierarchy")]
    CallHierarchy,
    #[serde(rename = "type_hierarchy")]
    TypeHierarchy,
    #[serde(rename = "query_code")]
    QueryCode,
}

impl BenchmarkScenario {
    pub const ALL: [Self; 12] = [
        Self::WorkspaceBuild,
        Self::SearchSymbols,
        Self::GetSymbolLocations,
        Self::GetSymbolAncestors,
        Self::GetSummaries,
        Self::MostRelevantFiles,
        Self::ScanUsages,
        Self::DeadCodeSmells,
        Self::GetDefinition,
        Self::CallHierarchy,
        Self::TypeHierarchy,
        Self::QueryCode,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::WorkspaceBuild => "workspace_build",
            Self::SearchSymbols => "search_symbols",
            Self::GetSymbolLocations => "get_symbol_locations",
            Self::GetSymbolAncestors => "get_symbol_ancestors",
            Self::GetSummaries => "get_summaries",
            Self::MostRelevantFiles => "most_relevant_files",
            Self::ScanUsages => "scan_usages",
            Self::DeadCodeSmells => "dead_code_smells",
            Self::GetDefinition => "get_definition",
            Self::CallHierarchy => "call_hierarchy",
            Self::TypeHierarchy => "type_hierarchy",
            Self::QueryCode => "query_code",
        }
    }

    pub fn tool_name(self) -> &'static str {
        match self {
            Self::ScanUsages => "scan_usages_by_reference",
            Self::DeadCodeSmells => "report_dead_code_and_unused_abstraction_smells",
            Self::GetDefinition => "get_definitions_by_location",
            Self::CallHierarchy | Self::TypeHierarchy => self.label(),
            _ => self.label(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryCodeWorkload {
    ExactName,
    Broad,
    Regex,
    Containment,
    TypedTraversal,
    WarmReuse,
}

impl QueryCodeWorkload {
    pub const ALL: [Self; 6] = [
        Self::ExactName,
        Self::Broad,
        Self::Regex,
        Self::Containment,
        Self::TypedTraversal,
        Self::WarmReuse,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::ExactName => "exact_name",
            Self::Broad => "broad",
            Self::Regex => "regex",
            Self::Containment => "containment",
            Self::TypedTraversal => "typed_traversal",
            Self::WarmReuse => "warm_reuse",
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
        let mut query_code_languages = BTreeSet::new();
        let mut query_code_workloads = BTreeSet::new();

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
            if !repo.query_code_queries.is_empty() {
                for query in &repo.query_code_queries {
                    if let Ok(decoded) = query.decode() {
                        let traits = QueryCodeTraits::from_query(&decoded, &repo.language_set());
                        query_code_languages.extend(traits.languages);
                        query_code_workloads.extend(query.workloads.iter().copied());
                    }
                }
            }
        }

        for &required_language in &required_languages {
            if !covered_languages.contains(&required_language) {
                errors.push(format!(
                    "required language `{}` is not covered by any repo entry",
                    required_language.label()
                ));
            }
        }

        for &required_scenario in &required_scenarios {
            if !covered_scenarios.contains(&required_scenario) {
                errors.push(format!(
                    "required scenario `{}` is not enabled by any repo entry",
                    required_scenario.label()
                ));
            }
        }

        if required_scenarios.contains(&BenchmarkScenario::QueryCode) {
            for &required_language in &required_languages {
                if !query_code_languages.contains(&required_language) {
                    errors.push(format!(
                        "required language `{}` has no query_code benchmark case",
                        required_language.label()
                    ));
                }
            }
            for workload in QueryCodeWorkload::ALL {
                if !query_code_workloads.contains(&workload) {
                    errors.push(format!(
                        "query_code benchmark corpus does not cover `{}` workload",
                        workload.label()
                    ));
                }
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(ManifestValidationError::new(errors))
        }
    }

    pub fn covered_languages(&self) -> BTreeSet<ManifestLanguage> {
        self.repos
            .iter()
            .flat_map(BenchmarkRepoTarget::language_set)
            .collect()
    }

    pub fn covered_scenarios(&self) -> BTreeSet<BenchmarkScenario> {
        self.repos
            .iter()
            .flat_map(BenchmarkRepoTarget::scenario_set)
            .collect()
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
    pub ancestor_symbols: Vec<String>,
    #[serde(default)]
    pub summary_targets: Vec<String>,
    #[serde(default)]
    pub seed_file_paths: Vec<String>,
    #[serde(default)]
    pub usage_symbols: Vec<String>,
    #[serde(default)]
    pub usage_targets: Vec<BenchmarkLocationSelector>,
    #[serde(default)]
    pub dead_code_file_paths: Vec<String>,
    #[serde(default)]
    pub dead_code_fq_names: Vec<String>,
    #[serde(default)]
    pub dead_code_expect_report_contains: Vec<String>,
    #[serde(default)]
    pub dead_code_expect_report_absent: Vec<String>,
    #[serde(default)]
    pub definition_queries: Vec<DefinitionQueryTarget>,
    #[serde(default)]
    pub call_hierarchy_queries: Vec<HierarchyQueryTarget>,
    #[serde(default)]
    pub type_hierarchy_queries: Vec<HierarchyQueryTarget>,
    #[serde(default)]
    pub query_code_queries: Vec<QueryCodeBenchmarkCase>,
}

pub type ScanUsageQueryTarget = BenchmarkLocationSelector;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkLocationSelector {
    pub path: String,
    #[serde(default)]
    pub line: Option<usize>,
    #[serde(default)]
    pub column: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefinitionQueryTarget {
    #[serde(flatten)]
    pub selector: BenchmarkLocationSelector,
    pub expected_status: String,
    #[serde(default)]
    pub expected_fqn: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HierarchyQueryTarget {
    #[serde(flatten)]
    pub selector: BenchmarkLocationSelector,
    #[serde(default)]
    pub min_incoming: usize,
    #[serde(default)]
    pub min_outgoing: usize,
    #[serde(default)]
    pub min_supertypes: usize,
    #[serde(default)]
    pub min_subtypes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryCodeBenchmarkCase {
    pub id: String,
    pub workloads: Vec<QueryCodeWorkload>,
    pub query_json: String,
    #[serde(default)]
    pub required_paths: Vec<String>,
    #[serde(default)]
    pub expected_witness_json: Option<String>,
    #[serde(default)]
    pub min_results: Option<usize>,
    #[serde(default)]
    pub max_results: Option<usize>,
    #[serde(default)]
    pub expected_truncated: bool,
    #[serde(default)]
    pub expected_diagnostic_codes: Vec<String>,
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
        if scenarios.len() != self.scenarios.len() {
            let mut seen = BTreeSet::new();
            for scenario in &self.scenarios {
                if !seen.insert(*scenario) {
                    errors.push(format!(
                        "repo `{name}` defines duplicate scenario `{}`",
                        scenario.label()
                    ));
                }
            }
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

        if scenarios.contains(&BenchmarkScenario::GetSymbolAncestors)
            && !has_non_blank_values(&self.ancestor_symbols)
        {
            errors.push(format!(
                "repo `{name}` enables `get_symbol_ancestors` but does not define ancestor_symbols"
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

        if scenarios.contains(&BenchmarkScenario::ScanUsages)
            && !has_non_blank_values(&self.usage_symbols)
            && self.usage_targets.is_empty()
        {
            errors.push(format!(
                "repo `{name}` enables `scan_usages` but does not define usage_symbols or usage_targets"
            ));
        }
        if !self.usage_symbols.is_empty() && !self.usage_targets.is_empty() {
            errors.push(format!(
                "repo `{name}` must define only one of usage_symbols or usage_targets"
            ));
        }
        for (index, query) in self.usage_targets.iter().enumerate() {
            let label = format!("repo `{name}` usage_targets[{index}]");
            query.validate(&label, false, errors);
        }

        if scenarios.contains(&BenchmarkScenario::DeadCodeSmells) {
            if !has_non_blank_values(&self.dead_code_fq_names) {
                errors.push(format!(
                    "repo `{name}` enables `dead_code_smells` but does not define dead_code_fq_names"
                ));
            }
            if !has_non_blank_values(&self.dead_code_expect_report_contains)
                && !has_non_blank_values(&self.dead_code_expect_report_absent)
            {
                errors.push(format!(
                    "repo `{name}` enables `dead_code_smells` but does not define dead_code_expect_report_contains or dead_code_expect_report_absent"
                ));
            }
        }
        for (field, values) in [
            ("dead_code_file_paths", &self.dead_code_file_paths),
            ("dead_code_fq_names", &self.dead_code_fq_names),
            (
                "dead_code_expect_report_contains",
                &self.dead_code_expect_report_contains,
            ),
            (
                "dead_code_expect_report_absent",
                &self.dead_code_expect_report_absent,
            ),
        ] {
            if values.iter().any(|value| value.trim().is_empty()) {
                errors.push(format!("repo `{name}` has a blank {field} entry"));
            }
        }

        if scenarios.contains(&BenchmarkScenario::GetDefinition) {
            if self.definition_queries.is_empty() {
                errors.push(format!(
                    "repo `{name}` enables `get_definition` but does not define definition_queries"
                ));
            }
            for (index, query) in self.definition_queries.iter().enumerate() {
                query.validate(name, index, errors);
            }
        }

        if scenarios.contains(&BenchmarkScenario::CallHierarchy) {
            if self.call_hierarchy_queries.is_empty() {
                errors.push(format!(
                    "repo `{name}` enables `call_hierarchy` but does not define call_hierarchy_queries"
                ));
            }
            for (index, query) in self.call_hierarchy_queries.iter().enumerate() {
                query.validate(name, "call_hierarchy_queries", index, errors);
            }
        }

        if scenarios.contains(&BenchmarkScenario::TypeHierarchy) {
            if self.type_hierarchy_queries.is_empty() {
                errors.push(format!(
                    "repo `{name}` enables `type_hierarchy` but does not define type_hierarchy_queries"
                ));
            }
            for (index, query) in self.type_hierarchy_queries.iter().enumerate() {
                query.validate(name, "type_hierarchy_queries", index, errors);
            }
        }

        if scenarios.contains(&BenchmarkScenario::QueryCode) {
            if self.query_code_queries.is_empty() {
                errors.push(format!(
                    "repo `{name}` enables `query_code` but does not define query_code_queries"
                ));
            }
        } else if !self.query_code_queries.is_empty() {
            errors.push(format!(
                "repo `{name}` defines query_code_queries but does not enable `query_code`"
            ));
        }
        let mut query_ids = BTreeSet::new();
        for (index, query) in self.query_code_queries.iter().enumerate() {
            query.validate(name, index, &languages, errors);
            let id = query.id.trim();
            if !id.is_empty() && !query_ids.insert(id) {
                errors.push(format!(
                    "repo `{name}` defines duplicate query_code case id `{id}`"
                ));
            }
        }
    }
}

impl QueryCodeBenchmarkCase {
    fn validate(
        &self,
        repo_name: &str,
        index: usize,
        repo_languages: &BTreeSet<ManifestLanguage>,
        errors: &mut Vec<String>,
    ) {
        let label = format!("repo `{repo_name}` query_code_queries[{index}]");
        let id = self.id.trim();
        if id.is_empty() {
            errors.push(format!("{label} must define a non-empty id"));
        } else if id.len() > MAX_QUERY_CODE_CASE_ID_LENGTH
            || !id.is_ascii()
            || !id
                .bytes()
                .next()
                .is_some_and(|byte| byte.is_ascii_alphanumeric())
            || !id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            errors.push(format!(
                "{label} id must be an ASCII slug of at most {MAX_QUERY_CODE_CASE_ID_LENGTH} bytes using letters, digits, `_`, or `-`"
            ));
        }

        let workloads = self.workloads.iter().copied().collect::<BTreeSet<_>>();
        if workloads.is_empty() {
            errors.push(format!("{label} must define at least one workload"));
        } else if workloads.len() != self.workloads.len() {
            errors.push(format!("{label} defines duplicate workloads"));
        }

        let decoded = match serde_json::from_str::<serde_json::Value>(&self.query_json) {
            Ok(value) => match value.as_object() {
                Some(object) => {
                    if object.contains_key("query_file") {
                        errors.push(format!(
                            "{label} must embed a query and cannot use query_file"
                        ));
                    }
                    if object.contains_key("execution_mode") {
                        errors.push(format!(
                            "{label} cannot set execution_mode; the benchmark always profiles"
                        ));
                    }
                    match CodeQuery::from_json(&value) {
                        Ok(query) => Some(query),
                        Err(error) => {
                            errors.push(format!("{label} has an invalid query_json: {error}"));
                            None
                        }
                    }
                }
                None => {
                    errors.push(format!("{label} query_json must contain a JSON object"));
                    None
                }
            },
            Err(error) => {
                errors.push(format!("{label} has invalid query_json: {error}"));
                None
            }
        };

        if let Some(query) = decoded.as_ref() {
            let traits = QueryCodeTraits::from_query(query, repo_languages);
            for language in &traits.languages {
                if !repo_languages.contains(language) {
                    errors.push(format!(
                        "{label} queries language `{}` which is not declared by repo `{repo_name}`",
                        language.label()
                    ));
                }
            }
            for unsupported in &traits.unsupported_languages {
                errors.push(format!(
                    "{label} queries unsupported benchmark language `{}`",
                    unsupported.config_label()
                ));
            }
            for workload in workloads
                .iter()
                .filter(|workload| **workload != QueryCodeWorkload::WarmReuse)
            {
                if !traits.workloads.contains(workload) {
                    errors.push(format!(
                        "{label} declares `{}` workload but the decoded query does not exercise it",
                        workload.label()
                    ));
                }
            }
        }

        let mut required_paths = BTreeSet::new();
        for raw_path in &self.required_paths {
            let path = raw_path.trim();
            if !is_safe_workspace_relative_path(path) {
                errors.push(format!(
                    "{label} required path `{raw_path}` must be a normalized workspace-relative path without `.` or `..` components"
                ));
            } else if !required_paths.insert(path) {
                errors.push(format!("{label} defines duplicate required path `{path}`"));
            }
        }

        let has_witness = match &self.expected_witness_json {
            Some(witness) => match serde_json::from_str::<serde_json::Value>(witness) {
                Ok(value) if value.is_object() => true,
                Ok(_) => {
                    errors.push(format!(
                        "{label} expected_witness_json must contain a JSON object"
                    ));
                    false
                }
                Err(error) => {
                    errors.push(format!(
                        "{label} has invalid expected_witness_json: {error}"
                    ));
                    false
                }
            },
            None => false,
        };
        if !has_witness && self.min_results.unwrap_or(0) == 0 {
            errors.push(format!(
                "{label} must require a positive result count or an exact result witness"
            ));
        }
        if let (Some(min), Some(max)) = (self.min_results, self.max_results)
            && min > max
        {
            errors.push(format!(
                "{label} min_results {min} exceeds max_results {max}"
            ));
        }
        if has_witness && self.max_results == Some(0) {
            errors.push(format!(
                "{label} cannot require a witness while max_results is zero"
            ));
        }

        let diagnostic_codes = self
            .expected_diagnostic_codes
            .iter()
            .map(|code| code.trim())
            .collect::<BTreeSet<_>>();
        if diagnostic_codes.iter().any(|code| code.is_empty()) {
            errors.push(format!("{label} has a blank expected diagnostic code"));
        }
        if diagnostic_codes.len() != self.expected_diagnostic_codes.len() {
            errors.push(format!(
                "{label} defines duplicate expected diagnostic codes"
            ));
        }
    }

    pub(crate) fn required_paths(&self) -> impl Iterator<Item = &String> {
        self.required_paths.iter()
    }

    fn decode(&self) -> Result<CodeQuery, String> {
        let value = serde_json::from_str::<serde_json::Value>(&self.query_json)
            .map_err(|error| error.to_string())?;
        CodeQuery::from_json(&value).map_err(|error| error.to_string())
    }
}

#[derive(Default)]
struct QueryCodeTraits {
    languages: BTreeSet<ManifestLanguage>,
    unsupported_languages: BTreeSet<Language>,
    workloads: BTreeSet<QueryCodeWorkload>,
}

impl QueryCodeTraits {
    fn from_query(query: &CodeQuery, repo_languages: &BTreeSet<ManifestLanguage>) -> Self {
        let mut traits = Self::default();
        let mut plans = vec![&query.plan];
        while let Some(plan) = plans.pop() {
            if !plan.steps.is_empty() {
                traits.workloads.insert(QueryCodeWorkload::TypedTraversal);
            }
            match &plan.source {
                CodeQueryPlanSource::Seed(seed) => {
                    traits.observe_seed(seed, repo_languages);
                }
                CodeQueryPlanSource::Set { branches, .. } => plans.extend(branches),
            }
        }
        traits
    }

    fn observe_seed(&mut self, seed: &CodeQuerySeed, repo_languages: &BTreeSet<ManifestLanguage>) {
        if seed.languages.is_empty() {
            self.languages.extend(repo_languages);
        } else {
            for &language in &seed.languages {
                match manifest_language_from_analyzer(language) {
                    Some(language) => {
                        self.languages.insert(language);
                    }
                    None => {
                        self.unsupported_languages.insert(language);
                    }
                }
            }
        }

        if matches!(seed.root.name.as_ref(), Some(StringPredicate::Exact(_))) {
            self.workloads.insert(QueryCodeWorkload::ExactName);
        }
        if seed.root.name.is_none() && seed.root.text.is_none() {
            self.workloads.insert(QueryCodeWorkload::Broad);
        }
        if seed.inside.is_some() || positive_patterns(seed).any(|pattern| pattern.has.is_some()) {
            self.workloads.insert(QueryCodeWorkload::Containment);
        }
        if positive_patterns(seed).any(pattern_has_regex) {
            self.workloads.insert(QueryCodeWorkload::Regex);
        }
    }
}

fn positive_patterns(seed: &CodeQuerySeed) -> impl Iterator<Item = &Pattern> {
    let mut stack = vec![&seed.root];
    if let Some(inside) = seed.inside.as_ref() {
        stack.push(inside);
    }
    std::iter::from_fn(move || {
        let pattern = stack.pop()?;
        stack.extend(pattern.has.as_deref());
        stack.extend(pattern.callee.as_deref());
        stack.extend(pattern.receiver.as_deref());
        stack.extend(pattern.args.iter());
        stack.extend(pattern.kwargs.iter().map(|(_, pattern)| pattern));
        stack.extend(pattern.left.as_deref());
        stack.extend(pattern.right.as_deref());
        stack.extend(pattern.module.as_deref());
        stack.extend(pattern.decorators.iter());
        stack.extend(pattern.object.as_deref());
        stack.extend(pattern.field.as_deref());
        Some(pattern)
    })
}

fn pattern_has_regex(pattern: &Pattern) -> bool {
    matches!(pattern.name.as_ref(), Some(StringPredicate::Regex(_)))
        || matches!(pattern.text.as_ref(), Some(StringPredicate::Regex(_)))
}

fn is_safe_workspace_relative_path(raw_path: &str) -> bool {
    let windows_drive_prefix = raw_path.as_bytes().get(1) == Some(&b':')
        && raw_path
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphabetic);
    if raw_path.is_empty()
        || raw_path.len() > 4096
        || raw_path.contains('\\')
        || windows_drive_prefix
        || raw_path
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        return false;
    }
    let path = Path::new(raw_path);
    !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_)))
}

impl BenchmarkLocationSelector {
    fn validate(&self, label: &str, require_column_for_line: bool, errors: &mut Vec<String>) {
        if self.path.trim().is_empty() {
            errors.push(format!("{label} must define a non-empty path"));
        }

        let has_line_location =
            self.line.is_some() && (!require_column_for_line || self.column.is_some());
        if !has_line_location {
            let line_requirement = if require_column_for_line {
                "both line and column"
            } else {
                "line"
            };
            errors.push(format!("{label} must define {line_requirement}"));
        }
        if self.column == Some(0) {
            errors.push(format!("{label} column must be 1-based"));
        }
        if self.line == Some(0) {
            errors.push(format!("{label} line must be 1-based"));
        }
    }
}

impl DefinitionQueryTarget {
    fn validate(&self, repo_name: &str, index: usize, errors: &mut Vec<String>) {
        let label = format!("repo `{repo_name}` definition_queries[{index}]");
        self.selector.validate(&label, true, errors);

        if !is_definition_status(&self.expected_status) {
            errors.push(format!(
                "{label} has unsupported expected_status `{}`",
                self.expected_status
            ));
        }
        if self
            .expected_fqn
            .as_ref()
            .is_some_and(|expected| expected.trim().is_empty())
        {
            errors.push(format!("{label} has a blank expected_fqn"));
        }
    }
}

impl HierarchyQueryTarget {
    fn validate(&self, repo_name: &str, field_name: &str, index: usize, errors: &mut Vec<String>) {
        let label = format!("repo `{repo_name}` {field_name}[{index}]");
        self.selector.validate(&label, true, errors);
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

fn is_definition_status(status: &str) -> bool {
    matches!(
        status,
        "resolved"
            | "no_definition"
            | "unresolvable_import_boundary"
            | "ambiguous"
            | "unsupported_language"
            | "invalid_location"
            | "not_found"
    )
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
        Language::Ruby | Language::None => None,
    }
}
