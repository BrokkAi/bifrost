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
/// Whether a hit is a real reference to the symbol (a call, read, write, type
/// use, ...), a binding that brings or forwards the symbol (`import` / re-export),
/// or an internal self/this receiver reference.
///
/// The call-graph / relevance surfaces (SearchTools, dead-code, rename, call
/// hierarchy) care about ordinary external `Reference` hits and override /
/// implementation declarations. The LSP `textDocument/references` surface (IDE
/// "find references") also wants import/re-export bindings and self-receiver
/// references, plus definition sites used to connect declarations to bodies.
/// Keeping all in one graph with a kind lets each consumer choose through
/// [`UsageHitSurface`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum UsageHitKind {
    #[default]
    Reference,
    Import,
    Reexport,
    SelfReceiver,
    /// A source occurrence connected through an explicit declared contract,
    /// even when exact runtime evidence names a different structural owner.
    /// Editor references retain this edge; runtime usage surfaces do not.
    DeclaredReference,
    /// A callable definition corresponding to a separate declaration. Definition
    /// sites are editor-visible for navigation but are not runtime usages.
    Definition,
    /// A declaration that overrides/implements the queried declaration.
    OverrideDeclaration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum UsageProof {
    #[default]
    Proven,
    Unproven,
}

/// Who produced a reference or call answer, and therefore whether its proof
/// tiers are authoritative.
///
/// A native proof-tiered provider certifies the inventory it enumerated: a
/// retained unproven site, an omitted candidate total, or an incompleteness
/// diagnostic is a gap in a list that claims to be complete, so a consumer that
/// must publish only proven evidence has to reject the answer instead of
/// presenting the remainder as the whole truth. A legacy language resolver
/// makes no such claim; unproven and editor-only candidates are the answer it
/// has always returned, and dropping them would remove references its callers
/// depend on.
///
/// [`Legacy`](Self::Legacy) is the default so that an answer no proof-tiered
/// producer stamped is never mistaken for a certified inventory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum UsageProofAuthority {
    #[default]
    Legacy,
    Native,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum UsageHitSurface {
    /// Agent/search/relevance/call-graph surfaces that should count only external
    /// references from other semantic contexts.
    #[default]
    ExternalUsages,
    /// Editor find-references surface that should show every source occurrence that
    /// points at the symbol, including import bindings and self/this receiver calls.
    LspReferences,
}

impl UsageHitKind {
    /// The value domain the `usage_kind` row fields publish (issue #2515),
    /// in [`UsageHitKind::ALL`] order. Pinned by a unit test.
    pub const WIRE_LABELS: &'static [&'static str] = &[
        "reference",
        "import",
        "reexport",
        "self_receiver",
        "declared_reference",
        "definition",
        "override_declaration",
    ];

    pub const ALL: [Self; 7] = [
        UsageHitKind::Reference,
        UsageHitKind::Import,
        UsageHitKind::Reexport,
        UsageHitKind::SelfReceiver,
        UsageHitKind::DeclaredReference,
        UsageHitKind::Definition,
        UsageHitKind::OverrideDeclaration,
    ];

    pub fn wire_label(self) -> &'static str {
        match self {
            UsageHitKind::Reference => "reference",
            UsageHitKind::Import => "import",
            UsageHitKind::Reexport => "reexport",
            UsageHitKind::SelfReceiver => "self_receiver",
            UsageHitKind::DeclaredReference => "declared_reference",
            UsageHitKind::Definition => "definition",
            UsageHitKind::OverrideDeclaration => "override_declaration",
        }
    }

    pub fn included_in(self, surface: UsageHitSurface) -> bool {
        match surface {
            UsageHitSurface::ExternalUsages => {
                matches!(
                    self,
                    UsageHitKind::Reference | UsageHitKind::OverrideDeclaration
                )
            }
            UsageHitSurface::LspReferences => true,
        }
    }

    pub fn external_label(self) -> Option<&'static str> {
        match self {
            UsageHitKind::Reference => None,
            UsageHitKind::OverrideDeclaration => Some("override_declaration"),
            UsageHitKind::Import
            | UsageHitKind::Reexport
            | UsageHitKind::SelfReceiver
            | UsageHitKind::DeclaredReference
            | UsageHitKind::Definition => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct UsageHit {
    pub file: ProjectFile,
    pub line: usize,
    pub start_offset: usize,
    pub end_offset: usize,
    pub enclosing: CodeUnit,
    pub confidence: f64,
    pub snippet: String,
    pub kind: UsageHitKind,
    pub proof: UsageProof,
    /// Why a candidate remains unproven, when a producer can identify it.
    pub reason_kind: Option<String>,
    /// Structured source-reference classification when the analyzer can
    /// determine it without guessing from source text.
    pub reference_kind: Option<ReferenceKind>,
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
            kind: UsageHitKind::Reference,
            proof: UsageProof::Proven,
            reason_kind: None,
            reference_kind: None,
        }
    }

    /// Reclassify this hit as an `Import` binding.
    pub fn into_import(mut self) -> Self {
        self.kind = UsageHitKind::Import;
        self
    }

    /// Reclassify this hit as a binding-only re-export. It remains available to
    /// editor find-references while agent/search surfaces omit it as noise.
    pub fn into_reexport(mut self) -> Self {
        self.kind = UsageHitKind::Reexport;
        self
    }

    /// Reclassify this hit as a self/this receiver reference.
    pub fn into_self_receiver(mut self) -> Self {
        self.kind = UsageHitKind::SelfReceiver;
        self
    }

    /// Reclassify this hit as an editor-only declared-contract reference.
    pub fn into_declared_reference(mut self) -> Self {
        self.kind = UsageHitKind::DeclaredReference;
        self
    }

    /// Reclassify this hit as an editor-visible definition site.
    pub fn into_definition(mut self) -> Self {
        self.kind = UsageHitKind::Definition;
        self
    }

    /// Reclassify this hit as an override/implementation declaration.
    pub fn into_override_declaration(mut self) -> Self {
        self.kind = UsageHitKind::OverrideDeclaration;
        self
    }

    pub fn into_unproven(mut self) -> Self {
        self.proof = UsageProof::Unproven;
        self
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
            kind: self.kind,
            proof: self.proof,
            reason_kind: self.reason_kind.clone(),
            reference_kind: self.reference_kind,
        }
    }

    pub fn with_reason_kind(mut self, reason_kind: impl Into<String>) -> Self {
        self.reason_kind = Some(reason_kind.into());
        self
    }

    pub fn with_reference_kind(mut self, kind: ReferenceKind) -> Self {
        self.reference_kind = Some(kind);
        self
    }

    /// Whether this hit belongs on the editor find-references / rename
    /// surface: included by [`UsageHitKind::included_in`] for
    /// [`UsageHitSurface::LspReferences`], and not a `Self`-type-alias
    /// occurrence. A `Self`-type-alias hit names its owner through the
    /// language's own alias for the enclosing type rather than by writing the
    /// type's name, so the token is not the symbol's name: it must not be
    /// listed as a reference, and it must not be rewritten by a rename.
    /// Editor find-references and rename share this one check so the two
    /// surfaces cannot drift apart on it again.
    pub fn is_lsp_reference_site(&self) -> bool {
        self.kind.included_in(UsageHitSurface::LspReferences)
            && self.reference_kind != Some(ReferenceKind::SelfTypeAlias)
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
    /// An occurrence that names its owner through the language's own alias for
    /// the enclosing type (Rust's capital `Self`) rather than by writing the
    /// type's name. It is a type reference for graph and usage surfaces, and
    /// the editor find-references surface excludes it: the token is not the
    /// symbol's name, so rust-analyzer and the LSP contract do not list it.
    SelfTypeAlias,
    StaticReference,
    SuperCall,
    Inheritance,
}

/// A resolved reference emitted by graph strategies before rendering as a usage hit.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ReferenceHit {
    pub file: ProjectFile,
    pub range: Range,
    pub enclosing_unit: CodeUnit,
    pub kind: Option<ReferenceKind>,
    pub resolved: CodeUnit,
    pub confidence: u32,
    pub usage_kind: UsageHitKind,
    pub proof: UsageProof,
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

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReferenceGraphResult {
    pub hits: BTreeSet<UsageHit>,
    pub external_frontier_specifiers: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageAnalysisDiagnostic {
    pub fq_name: String,
    pub strategy: String,
    pub reason_kind: String,
    pub reason: String,
}

/// Outcome of a usage analyzer's `find_usages`.
///
/// Modelled after the brokk Java sealed interface `FuzzyResult`. The raw enum keeps the
/// matchable shape; convenience methods mirror the Java helpers.
#[derive(Debug, Clone)]
pub enum FuzzyResult {
    /// Resolution succeeded — possibly with zero hits.
    Success {
        hits_by_overload: HashMap<CodeUnit, BTreeSet<UsageHit>>,
        unproven_by_overload: HashMap<CodeUnit, BTreeSet<UsageHit>>,
        unproven_total_by_overload: HashMap<CodeUnit, usize>,
    },
    /// Structured evidence is available, but semantic enumeration is incomplete.
    /// Proven hits remain useful positives; missing hits cannot prove absence.
    /// Execution cancellation and budgets are reported separately by the query.
    Incomplete {
        hits_by_overload: HashMap<CodeUnit, BTreeSet<UsageHit>>,
        unproven_by_overload: HashMap<CodeUnit, BTreeSet<UsageHit>>,
        unproven_total_by_overload: HashMap<CodeUnit, usize>,
        diagnostics: Vec<UsageAnalysisDiagnostic>,
    },
    /// The analyzer/LLM could not produce a result for this query.
    Failure {
        fq_name: String,
        reason_kind: String,
        reason: String,
    },
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
        sample_hits: BTreeSet<UsageHit>,
    },
}

impl FuzzyResult {
    pub const MAX_UNPROVEN_HITS_PER_SYMBOL: usize = 20;

    pub fn success(target: CodeUnit, hits: BTreeSet<UsageHit>) -> Self {
        Self::success_with_unproven(target, hits, BTreeSet::new())
    }

    pub fn success_with_unproven(
        target: CodeUnit,
        hits: BTreeSet<UsageHit>,
        unproven: BTreeSet<UsageHit>,
    ) -> Self {
        let mut map = HashMap::default();
        map.insert(target.clone(), hits);
        let mut unproven_map = HashMap::default();
        let mut unproven_total_map = HashMap::default();
        let (external, editor_only): (Vec<_>, Vec<_>) = unproven
            .into_iter()
            .partition(|hit| hit.kind.included_in(UsageHitSurface::ExternalUsages));
        let unproven_total = external.len();
        if unproven_total > 0 {
            unproven_total_map.insert(target.clone(), unproven_total);
        }
        if unproven_total > 0 || !editor_only.is_empty() {
            let capped = external
                .into_iter()
                .chain(editor_only)
                .take(Self::MAX_UNPROVEN_HITS_PER_SYMBOL)
                .collect();
            unproven_map.insert(target.clone(), capped);
        }
        FuzzyResult::Success {
            hits_by_overload: map,
            unproven_by_overload: unproven_map,
            unproven_total_by_overload: unproven_total_map,
        }
    }

    pub fn empty_success() -> Self {
        FuzzyResult::Success {
            hits_by_overload: HashMap::default(),
            unproven_by_overload: HashMap::default(),
            unproven_total_by_overload: HashMap::default(),
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

    /// Returns every external-usage hit, regardless of overload bucket. Excludes
    /// import/re-export bindings and self/this receiver hits because
    /// call-graph/relevance surfaces want externally meaningful references only.
    pub fn all_hits(&self) -> BTreeSet<UsageHit> {
        self.all_hits_for_surface(UsageHitSurface::ExternalUsages)
    }

    /// Returns every hit for the requested usage surface.
    pub fn all_hits_for_surface(&self, surface: UsageHitSurface) -> BTreeSet<UsageHit> {
        self.all_hits_unfiltered()
            .into_iter()
            .filter(|hit| hit.kind.included_in(surface))
            .collect()
    }

    /// Returns every editor-visible hit, including import/re-export bindings and
    /// self/this receiver hits.
    pub fn all_hits_including_imports(&self) -> BTreeSet<UsageHit> {
        self.all_hits_for_surface(UsageHitSurface::LspReferences)
    }

    fn all_hits_unfiltered(&self) -> BTreeSet<UsageHit> {
        match self {
            FuzzyResult::Success {
                hits_by_overload, ..
            }
            | FuzzyResult::Incomplete {
                hits_by_overload, ..
            }
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
    /// `Failure` / `TooManyCallsites` / `Incomplete`.
    pub fn into_either(self) -> Result<BTreeSet<UsageHit>, String> {
        match self {
            FuzzyResult::Incomplete { diagnostics, .. } => {
                Err(format!("Usage analysis is incomplete: {diagnostics:?}"))
            }
            FuzzyResult::Failure { fq_name, .. } => {
                Err(format!("No relevant usages found for symbol: {fq_name}"))
            }
            FuzzyResult::TooManyCallsites {
                short_name,
                total_callsites,
                limit,
                ..
            } => Err(format!(
                "Too many call sites for symbol: {short_name} ({total_callsites}, limit {limit})"
            )),
            FuzzyResult::Success {
                hits_by_overload, ..
            } => Ok(hits_by_overload
                .into_values()
                .flat_map(BTreeSet::into_iter)
                .filter(|hit| hit.kind.included_in(UsageHitSurface::ExternalUsages))
                .collect()),
            FuzzyResult::Ambiguous {
                hits_by_overload, ..
            } => Ok(hits_by_overload
                .into_values()
                .flat_map(BTreeSet::into_iter)
                .filter(|hit| {
                    hit.kind.included_in(UsageHitSurface::ExternalUsages)
                        && hit.confidence >= CONFIDENCE_THRESHOLD
                })
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
    CommonJsRequire,
    Glob,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ImportBinding {
    pub module_specifier: String,
    /// Full module loaded by a namespace import when the locally bound module
    /// differs from it. Python's `import pkg.child` binds `pkg` while loading
    /// `pkg.child`; aliased namespace imports bind the full module directly.
    pub namespace_imported_module: Option<String>,
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
    /// Exported name *is* another module, not a name looked up inside one.
    /// Python's `from pkg import sub` binds the submodule `pkg.sub` whenever
    /// that module exists; resolving it must stop at the module rather than
    /// re-enter `pkg.sub` looking for a member called `sub`.
    ReexportedModule { module_specifier: String },
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
    use crate::analyzer::model::{CodeUnit, CodeUnitType, ProjectFile};
    use brokk_bifrost_test_macros::hardwon;
    use std::path::PathBuf;

    /// The `usage_kind` row field publishes this list as its value domain, so a
    /// label that drifts from `wire_label` would let a policy literal be
    /// rejected that a row can actually hold (issue #2515).
    #[test]
    #[hardwon(
        "#2515: an unknown persisted usage-kind label silently made a policy predicate vacuous"
    )]
    fn every_usage_hit_kind_wire_label_is_published_in_variant_order() {
        let mapped = UsageHitKind::ALL
            .iter()
            .map(|kind| kind.wire_label())
            .collect::<Vec<_>>();
        assert_eq!(mapped, UsageHitKind::WIRE_LABELS);
    }

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
    fn incomplete_usage_retains_positive_evidence_without_certifying_absence() {
        let unit = enclosing_unit();
        let reference = UsageHit::new(
            project_file("Foo.java"),
            10,
            100,
            110,
            unit.clone(),
            1.0,
            "target()",
        );
        let import = UsageHit::new(
            project_file("Foo.java"),
            1,
            0,
            10,
            unit.clone(),
            1.0,
            "import target",
        )
        .into_import();
        let diagnostic = UsageAnalysisDiagnostic {
            fq_name: unit.fq_name().to_string(),
            strategy: "native".to_string(),
            reason_kind: "unsupported_reference".to_string(),
            reason: "A structured reference remains unresolved".to_string(),
        };
        for hits in [
            BTreeSet::new(),
            BTreeSet::from([reference.clone(), import.clone()]),
        ] {
            let result = FuzzyResult::Incomplete {
                hits_by_overload: [(unit.clone(), hits.clone())].into_iter().collect(),
                unproven_by_overload: HashMap::default(),
                unproven_total_by_overload: HashMap::default(),
                diagnostics: vec![diagnostic.clone()],
            };
            assert_eq!(result.all_hits_including_imports(), hits);
            assert_eq!(
                result.all_hits(),
                hits.into_iter().filter(|hit| hit == &reference).collect()
            );
            let error = result
                .into_either()
                .expect_err("partial enumeration cannot certify absence");
            assert!(error.contains(&diagnostic.reason_kind), "{error}");
            assert!(error.contains(&diagnostic.reason), "{error}");
        }
    }

    #[test]
    #[hardwon("#3815: a Rust self-type alias was incorrectly published as an LSP reference site")]
    fn lsp_reference_sites_preserve_bindings_and_exclude_self_type_aliases() {
        let reference = UsageHit::new(
            project_file("lib.rs"),
            1,
            0,
            6,
            enclosing_unit(),
            1.0,
            "Widget",
        );
        for kind in [
            UsageHitKind::Reference,
            UsageHitKind::Import,
            UsageHitKind::Reexport,
            UsageHitKind::SelfReceiver,
            UsageHitKind::DeclaredReference,
            UsageHitKind::Definition,
            UsageHitKind::OverrideDeclaration,
        ] {
            let mut hit = reference.clone();
            hit.kind = kind;
            hit.reference_kind = Some(ReferenceKind::TypeReference);
            assert!(hit.is_lsp_reference_site(), "explicit reference: {kind:?}");
            hit.reference_kind = Some(ReferenceKind::SelfTypeAlias);
            assert!(!hit.is_lsp_reference_site(), "self alias: {kind:?}");
        }
        assert!(reference.is_lsp_reference_site());
    }
}
