use crate::analyzer::{CodeUnit, ProjectFile, Range};
use crate::hash::HashMap;
use std::collections::BTreeSet;
use std::hash::{Hash, Hasher};

/// Confidence threshold for filtering hits in [`FuzzyResult::Ambiguous`] outcomes.
pub const CONFIDENCE_THRESHOLD: f64 = 0.5;

/// Immutable metadata describing a single usage occurrence.
///
/// Equality and hashing intentionally key only on `(file, start_offset, end_offset, enclosing)`;
/// `confidence` and `snippet` are excluded so duplicate hits coming from different patterns
/// collapse into one.
#[derive(Debug, Clone)]
pub struct UsageHit {
    pub file: ProjectFile,
    pub line: usize,
    pub start_offset: usize,
    pub end_offset: usize,
    pub enclosing: CodeUnit,
    pub confidence: f64,
    pub snippet: String,
}

impl UsageHit {
    pub fn new(
        file: ProjectFile,
        line: usize,
        start_offset: usize,
        end_offset: usize,
        enclosing: CodeUnit,
        confidence: f64,
        snippet: impl Into<String>,
    ) -> Self {
        Self {
            file,
            line,
            start_offset,
            end_offset,
            enclosing,
            confidence,
            snippet: snippet.into(),
        }
    }

    pub fn with_confidence(&self, confidence: f64) -> Self {
        Self {
            file: self.file.clone(),
            line: self.line,
            start_offset: self.start_offset,
            end_offset: self.end_offset,
            enclosing: self.enclosing.clone(),
            confidence,
            snippet: self.snippet.clone(),
        }
    }
}

impl PartialEq for UsageHit {
    fn eq(&self, other: &Self) -> bool {
        self.file == other.file
            && self.start_offset == other.start_offset
            && self.end_offset == other.end_offset
            && self.enclosing == other.enclosing
    }
}

impl Eq for UsageHit {}

impl Hash for UsageHit {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.file.hash(state);
        self.start_offset.hash(state);
        self.end_offset.hash(state);
        self.enclosing.hash(state);
    }
}

/// Kind of source-level reference produced by graph-based analyzers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReferenceKind {
    MethodCall,
    ConstructorCall,
    FieldRead,
    FieldWrite,
    TypeReference,
    StaticReference,
    SuperCall,
    Inheritance,
}

/// A resolved reference (graph-strategy output, not used by the regex strategy directly).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ReferenceHit {
    pub file: ProjectFile,
    pub range: Range,
    pub enclosing_unit: CodeUnit,
    pub kind: ReferenceKind,
    pub resolved: CodeUnit,
    pub confidence: u32,
}

impl ReferenceHit {
    pub fn confidence_f64(&self) -> f64 {
        f64::from(self.confidence) / 1_000_000.0
    }
}

/// A pre-resolution reference candidate emitted by source extractors before binding.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ReferenceCandidate {
    pub identifier: String,
    pub qualifier: Option<String>,
    pub owner_identifier: Option<String>,
    pub instance_receiver: bool,
    pub kind: ReferenceKind,
    pub range: Range,
    pub enclosing_unit: CodeUnit,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ReceiverTargetRef {
    pub module_specifier: Option<String>,
    pub exported_name: String,
    pub instance_receiver: bool,
    pub confidence: u32,
    pub local_file: Option<ProjectFile>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ResolvedReceiverCandidate {
    pub identifier: String,
    pub receiver_target: ReceiverTargetRef,
    pub kind: ReferenceKind,
    pub range: Range,
    pub enclosing_unit: CodeUnit,
    pub confidence: u32,
}

/// Outcome of [`super::UsageAnalyzer::find_usages`].
///
/// Modelled after the brokk Java sealed interface `FuzzyResult`. The raw enum keeps the
/// matchable shape; convenience methods mirror the Java helpers.
#[derive(Debug, Clone)]
pub enum FuzzyResult {
    /// Resolution succeeded — possibly with zero hits.
    Success {
        hits_by_overload: HashMap<CodeUnit, BTreeSet<UsageHit>>,
    },
    /// The analyzer/LLM could not produce a result for this query.
    Failure { fq_name: String, reason: String },
    /// Multiple definitions share the short name; hits are returned but should be filtered.
    Ambiguous {
        short_name: String,
        candidate_targets: BTreeSet<CodeUnit>,
        hits_by_overload: HashMap<CodeUnit, BTreeSet<UsageHit>>,
    },
    /// Guardrail tripped — too many call sites for the analyzer to enumerate cheaply.
    TooManyCallsites {
        short_name: String,
        total_callsites: usize,
        limit: usize,
    },
}

impl FuzzyResult {
    pub fn success(target: CodeUnit, hits: BTreeSet<UsageHit>) -> Self {
        let mut map = HashMap::default();
        map.insert(target, hits);
        FuzzyResult::Success {
            hits_by_overload: map,
        }
    }

    pub fn empty_success() -> Self {
        FuzzyResult::Success {
            hits_by_overload: HashMap::default(),
        }
    }

    pub fn ambiguous(
        target: CodeUnit,
        short_name: String,
        candidate_targets: BTreeSet<CodeUnit>,
        hits: BTreeSet<UsageHit>,
    ) -> Self {
        let mut map = HashMap::default();
        map.insert(target, hits);
        FuzzyResult::Ambiguous {
            short_name,
            candidate_targets,
            hits_by_overload: map,
        }
    }

    /// Returns every hit, regardless of overload bucket.
    pub fn all_hits(&self) -> BTreeSet<UsageHit> {
        match self {
            FuzzyResult::Success { hits_by_overload }
            | FuzzyResult::Ambiguous {
                hits_by_overload, ..
            } => hits_by_overload
                .values()
                .flat_map(|set| set.iter().cloned())
                .collect(),
            _ => BTreeSet::new(),
        }
    }

    /// Lossy adapter equivalent to `EitherUsagesOrError`. Returns `Ok(set)` for `Success` and
    /// `Ambiguous` (the latter filtered by [`CONFIDENCE_THRESHOLD`]) and `Err(message)` for
    /// `Failure` / `TooManyCallsites`.
    pub fn into_either(self) -> Result<BTreeSet<UsageHit>, String> {
        match self {
            FuzzyResult::Failure { fq_name, .. } => {
                Err(format!("No relevant usages found for symbol: {fq_name}"))
            }
            FuzzyResult::TooManyCallsites {
                short_name,
                total_callsites,
                limit,
            } => Err(format!(
                "Too many call sites for symbol: {short_name} ({total_callsites}, limit {limit})"
            )),
            FuzzyResult::Success { hits_by_overload } => Ok(hits_by_overload
                .into_values()
                .flat_map(BTreeSet::into_iter)
                .collect()),
            FuzzyResult::Ambiguous {
                hits_by_overload, ..
            } => Ok(hits_by_overload
                .into_values()
                .flat_map(BTreeSet::into_iter)
                .filter(|hit| hit.confidence >= CONFIDENCE_THRESHOLD)
                .collect()),
        }
    }
}

// `BTreeSet<UsageHit>` would normally need `Ord`. We provide a stable ordering by the same
// fields used in equality so insertion is deterministic regardless of insertion order.
impl Ord for UsageHit {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.file
            .cmp(&other.file)
            .then_with(|| self.start_offset.cmp(&other.start_offset))
            .then_with(|| self.end_offset.cmp(&other.end_offset))
            .then_with(|| self.enclosing.cmp(&other.enclosing))
    }
}

impl PartialOrd for UsageHit {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

// --- ImportBinder + ExportIndex -----------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ImportKind {
    Default,
    Named,
    Namespace,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ImportBinding {
    pub module_specifier: String,
    pub kind: ImportKind,
    pub imported_name: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct ImportBinder {
    pub bindings: HashMap<String, ImportBinding>,
}

impl ImportBinder {
    pub fn empty() -> Self {
        Self::default()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ExportEntry {
    /// Exported name maps to a local top-level identifier in this file.
    Local { local_name: String },
    /// Exported name re-exports an imported name from another module.
    ReexportedNamed {
        module_specifier: String,
        imported_name: String,
    },
    /// Default export. `local_name` is `None` when the default export is anonymous.
    Default { local_name: Option<String> },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ReexportStar {
    pub module_specifier: String,
}

#[derive(Debug, Clone, Default)]
pub struct ExportIndex {
    pub exports_by_name: HashMap<String, ExportEntry>,
    pub reexport_stars: Vec<ReexportStar>,
}

impl ExportIndex {
    pub fn empty() -> Self {
        Self::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::{CodeUnit, CodeUnitType, ProjectFile};
    use std::path::PathBuf;

    fn project_file(rel: &str) -> ProjectFile {
        let root = std::env::temp_dir().canonicalize().unwrap_or_else(|_| {
            #[cfg(windows)]
            {
                PathBuf::from("C:/")
            }
            #[cfg(not(windows))]
            {
                PathBuf::from("/tmp")
            }
        });
        ProjectFile::new(root, rel)
    }

    fn enclosing_unit() -> CodeUnit {
        CodeUnit::new(
            project_file("Foo.java"),
            CodeUnitType::Function,
            "pkg",
            "Foo.bar",
        )
    }

    #[test]
    fn usage_hit_equality_ignores_confidence_and_snippet() {
        let unit = enclosing_unit();
        let a = UsageHit::new(
            project_file("Foo.java"),
            10,
            100,
            110,
            unit.clone(),
            1.0,
            "snippet a",
        );
        let b = UsageHit::new(
            project_file("Foo.java"),
            10,
            100,
            110,
            unit,
            0.5,
            "snippet b",
        );

        assert_eq!(a, b, "equality should ignore confidence and snippet");
    }

    #[test]
    fn usage_hit_equality_distinguishes_offsets() {
        let unit = enclosing_unit();
        let a = UsageHit::new(
            project_file("Foo.java"),
            10,
            100,
            110,
            unit.clone(),
            1.0,
            "snippet",
        );
        let b = UsageHit::new(project_file("Foo.java"), 10, 200, 210, unit, 1.0, "snippet");

        assert_ne!(a, b);
    }

    #[test]
    fn fuzzy_result_into_either_filters_ambiguous_by_threshold() {
        let unit = enclosing_unit();
        let high = UsageHit::new(
            project_file("Foo.java"),
            10,
            100,
            110,
            unit.clone(),
            1.0,
            "high",
        );
        let low = UsageHit::new(
            project_file("Foo.java"),
            12,
            120,
            130,
            unit.clone(),
            0.1,
            "low",
        );
        let mut hits = BTreeSet::new();
        hits.insert(high.clone());
        hits.insert(low);

        let mut targets = BTreeSet::new();
        targets.insert(unit.clone());

        let result = FuzzyResult::ambiguous(unit, "bar".to_string(), targets, hits);
        let either = result.into_either().expect("ambiguous => Ok");
        assert!(either.contains(&high));
        assert_eq!(either.len(), 1);
    }

    #[test]
    fn fuzzy_result_into_either_failure_returns_error() {
        let result = FuzzyResult::Failure {
            fq_name: "pkg.Foo.bar".to_string(),
            reason: "no analyzer".to_string(),
        };
        assert!(result.into_either().is_err());
    }

    #[test]
    fn fuzzy_result_into_either_too_many_returns_error() {
        let result = FuzzyResult::TooManyCallsites {
            short_name: "bar".to_string(),
            total_callsites: 2000,
            limit: 1000,
        };
        let err = result.into_either().unwrap_err();
        assert!(err.contains("2000"));
        assert!(err.contains("1000"));
    }
}
