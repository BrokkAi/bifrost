//! The canonical reference-edge derivation layer (issue #1479).
//!
//! One edge states that a source site refers to a target declaration, with the
//! reference kind, the proof, the usage-kind classification and the producer
//! that derived it. Two producers project into this one row shape:
//!
//! - the *forward* producer walks a file's classified occurrence rows
//!   ([`super::occurrence_rows`]) and emits an edge per resolved target;
//! - the *inverse* producer runs the usage index for a seed declaration (the
//!   same [`UsageFinder`] query the `references-of` step performs) and emits
//!   an edge per usage hit.
//!
//! Neither producer re-implements the other's analysis: forward rows are the
//! resolver's own answers and inverse rows are the usage strategies' own
//! answers, so a disagreement between the two sets is a real disagreement
//! between the two production analyses -- which is exactly what the parity
//! assertions built on this layer exist to surface.
//!
//! Deliberately not a stored third graph: rows are derived on demand from the
//! two existing producers, and every row is stamped with the workspace
//! generation it was derived in so a comparison can refuse to relate rows
//! from two different snapshots.

use super::edges::{EdgeAxis, EdgeProvenance, OwnerRelation, SiteClass};
use super::kinds::NormalizedKind;
use super::occurrence_rows::{
    OccurrenceCompleteness, OccurrenceTarget, OccurrencesCancelled, ast_id, occurrences_for_file,
};
use super::search::expansions::{classify_reference_kind, reference_hits_for_target};
use crate::analyzer::usages::{
    ReferenceHit, ReferenceKind, UsageFinder, UsageHitKind, UsageHitSurface, UsageProof,
    UsageQueryCompletion,
};
use crate::analyzer::{CodeUnit, IAnalyzer, ProjectFile, Range};
use crate::cancellation::CancellationToken;
use crate::hash::HashMap;

/// Bounds for one inverse derivation. The file bound matches the reference
/// traversal's scan bound; the hit bound is per seed declaration.
pub const MAX_INVERSE_EDGE_FILES: usize = 20_000;
pub const MAX_INVERSE_EDGE_HITS: usize = 5_000;

/// The site end of an edge: where in the workspace the reference is spelled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdgeSite {
    pub file: ProjectFile,
    pub range: Range,
    /// The content-scoped AST identity of the site token, present exactly when
    /// the producer can address the token as a facts-arena node (forward rows
    /// always can; inverse rows gain it in the classification milestone).
    /// Never fabricated: `None` means the site is addressed by `file` plus
    /// byte range over the same content, which is exact, not heuristic.
    pub ast_id: Option<String>,
    /// The declaration lexically enclosing the site, when known.
    pub enclosing: Option<CodeUnit>,
}

/// One canonical reference edge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReferenceEdgeRow {
    pub site: EdgeSite,
    pub target: CodeUnit,
    /// Typed source-level classification, absent when no producer could state
    /// one. Absence is "unclassified", never a kind.
    pub reference_kind: Option<ReferenceKind>,
    pub proof: UsageProof,
    pub usage_kind: UsageHitKind,
    pub site_class: SiteClass,
    /// How the site's enclosing declaration relates to the target, computed
    /// once by [`classify_owner_relation`] for both producers. `Unknown` when
    /// the classifier cannot relate the owners; never silently `External`.
    pub owner_relation: OwnerRelation,
    pub provenance: EdgeProvenance,
    /// The workspace generation both endpoints were read from. A comparison
    /// across two generations is refused, not fudged.
    pub generation: u64,
}

impl ReferenceEdgeRow {
    /// Whether this edge belongs to the given usage surface. Definition sites
    /// and import bindings are editor-visible but not external usages, exactly
    /// as on the usage-hit surface this delegates to.
    pub fn included_in(&self, surface: UsageHitSurface) -> bool {
        self.usage_kind.included_in(surface)
    }
}

/// Why an edge derivation's rows are less than the whole truth.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EdgeIncompleteReason {
    /// The adapter declares the axis unsupported, so absence of rows for it
    /// says nothing.
    AxisUnsupported(EdgeAxis),
    /// No structural provider is registered for the language in question.
    NoStructuralAdapter,
    /// The usage listing was cut short (too many call sites, or a scan
    /// budget), so absent inverse edges are unknown, not absent.
    UsageListingTruncated,
    /// The usage analysis reported a typed failure for the seed declaration.
    UsageAnalysisFailed { reason_kind: String, reason: String },
    /// The usage query was cancelled before completing.
    Cancelled,
    /// The file's occurrence rows are themselves incomplete, so the forward
    /// edge set derived from them is missing an unknown number of rows.
    OccurrenceRowsIncomplete,
}

/// Which axes this derivation layer answers.
pub const EDGE_PRODUCER_AXES: &[EdgeAxis] = &[
    EdgeAxis::ForwardProjection,
    EdgeAxis::InverseProjection,
    EdgeAxis::KindClassification,
    EdgeAxis::ProofAttribution,
    EdgeAxis::OwnerClassification,
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EdgeCompleteness {
    Complete,
    Incomplete { reasons: Vec<EdgeIncompleteReason> },
}

impl EdgeCompleteness {
    pub fn is_complete(&self) -> bool {
        matches!(self, Self::Complete)
    }

    /// Whether rows for `axis` can be trusted to be the complete set.
    pub fn covers(&self, axis: EdgeAxis) -> bool {
        if !EDGE_PRODUCER_AXES.contains(&axis) {
            return false;
        }
        match self {
            Self::Complete => true,
            Self::Incomplete { reasons } => !reasons.iter().any(|reason| match reason {
                EdgeIncompleteReason::AxisUnsupported(unsupported) => *unsupported == axis,
                EdgeIncompleteReason::UsageListingTruncated
                | EdgeIncompleteReason::UsageAnalysisFailed { .. } => {
                    axis == EdgeAxis::InverseProjection
                }
                EdgeIncompleteReason::OccurrenceRowsIncomplete => {
                    axis == EdgeAxis::ForwardProjection
                }
                EdgeIncompleteReason::NoStructuralAdapter | EdgeIncompleteReason::Cancelled => true,
            }),
        }
    }
}

/// One producer's derived edges with an explicit account of what is missing.
#[derive(Debug, Clone)]
pub struct EdgeDerivationResult {
    pub edges: Vec<ReferenceEdgeRow>,
    pub completeness: EdgeCompleteness,
    /// Which producer derived this result. Also the reason
    /// [`Self::covers`] exists: a forward derivation can never vouch for the
    /// inverse projection, however complete it is, and vice versa.
    pub provenance: EdgeProvenance,
    pub generation: u64,
}

impl EdgeDerivationResult {
    fn incomplete(
        reasons: Vec<EdgeIncompleteReason>,
        provenance: EdgeProvenance,
        generation: u64,
    ) -> Self {
        Self {
            edges: Vec::new(),
            completeness: EdgeCompleteness::Incomplete { reasons },
            provenance,
            generation,
        }
    }

    /// Whether this result's rows can be trusted to be the complete set for
    /// `axis`. The other producer's projection axis is never covered: one
    /// producer vouching for the other's output is exactly the confusion this
    /// layer exists to remove.
    pub fn covers(&self, axis: EdgeAxis) -> bool {
        let foreign_projection = match self.provenance {
            EdgeProvenance::Forward => EdgeAxis::InverseProjection,
            EdgeProvenance::Inverse => EdgeAxis::ForwardProjection,
        };
        if axis == foreign_projection {
            return false;
        }
        self.completeness.covers(axis)
    }
}

fn supports_edge_axis(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    axis: EdgeAxis,
) -> Option<bool> {
    let language = crate::analyzer::common::language_for_file(file);
    analyzer
        .structural_search_providers()
        .into_iter()
        .find(|provider| provider.structural_language() == language)
        .map(|provider| provider.structural_supports_edge_axis(axis))
}

/// How the declaration enclosing a use site relates to the edge's target.
/// One computation for both producers, so the classification can never drift
/// between the forward and inverse surfaces.
///
/// The owner of a unit is the unit itself when it is class-like, else its
/// parent declaration. `Unknown` is the honest answer whenever an owner is
/// missing, or the owners are distinct classes and no type-hierarchy provider
/// can rule inheritance in or out; it is never collapsed into `External`.
pub fn classify_owner_relation(
    analyzer: &dyn IAnalyzer,
    site_enclosing: Option<&CodeUnit>,
    target: &CodeUnit,
) -> OwnerRelation {
    let Some(enclosing) = site_enclosing else {
        return OwnerRelation::Unknown;
    };
    if enclosing == target {
        return OwnerRelation::SelfReference;
    }
    let owner_of = |unit: &CodeUnit| {
        if unit.is_class() {
            Some(unit.clone())
        } else {
            analyzer.parent_of(unit)
        }
    };
    let (Some(site_owner), Some(target_owner)) = (owner_of(enclosing), owner_of(target)) else {
        return OwnerRelation::Unknown;
    };
    if site_owner == target_owner {
        return OwnerRelation::SameOwner;
    }
    if !target_owner.is_class() {
        return OwnerRelation::External;
    }
    if !site_owner.is_class() {
        return OwnerRelation::External;
    }
    match analyzer.type_hierarchy_provider() {
        Some(hierarchy) => {
            if hierarchy.get_ancestors(&site_owner).contains(&target_owner) {
                OwnerRelation::InheritedOwner
            } else {
                OwnerRelation::External
            }
        }
        None => OwnerRelation::Unknown,
    }
}

/// Per-file map from an identifier token's exact byte range to its
/// facts-arena AST identity, built once per file so a batch of inverse hits
/// pays one arena pass instead of one per hit.
///
/// The lookup is exact, not heuristic: the facts snapshot and the usage hit
/// address the same analyzed content, so range equality over it is the same
/// join the forward producer states through `OccurrenceRow::ast_id`.
struct SiteIdentityIndex {
    by_range: HashMap<(usize, usize), String>,
}

impl SiteIdentityIndex {
    fn build(analyzer: &dyn IAnalyzer, file: &ProjectFile) -> Self {
        let language = crate::analyzer::common::language_for_file(file);
        let facts = analyzer
            .structural_search_providers()
            .into_iter()
            .find(|provider| provider.structural_language() == language)
            .and_then(|provider| provider.structural_facts(file));
        let mut by_range = HashMap::default();
        if let Some(facts) = facts {
            let identity = facts.source_identity();
            for (node, fact) in facts.nodes().iter().enumerate() {
                if fact.kind == NormalizedKind::Identifier {
                    by_range
                        .entry((fact.range.start_byte, fact.range.end_byte))
                        .or_insert_with(|| ast_id(identity, node as u32));
                }
            }
        }
        Self { by_range }
    }

    fn ast_id(&self, range: &Range) -> Option<String> {
        self.by_range
            .get(&(range.start_byte, range.end_byte))
            .cloned()
    }
}

/// Project one usage hit into the canonical row shape.
///
/// A `Vec` and not a set on purpose: two hits that disagree only on proof or
/// kind are two rows here, where the usage-hit identity would collapse them.
/// The disagreement is the data.
fn edge_rows_from_reference_hits(
    analyzer: &dyn IAnalyzer,
    hits: impl IntoIterator<Item = ReferenceHit>,
    generation: u64,
) -> Vec<ReferenceEdgeRow> {
    let mut site_identities: HashMap<ProjectFile, SiteIdentityIndex> = HashMap::default();
    hits.into_iter()
        .map(|hit| {
            let site_class = match hit.usage_kind {
                UsageHitKind::Definition | UsageHitKind::OverrideDeclaration => {
                    SiteClass::DeclarationSite
                }
                UsageHitKind::Reference
                | UsageHitKind::Import
                | UsageHitKind::Reexport
                | UsageHitKind::SelfReceiver => SiteClass::UseSite,
            };
            let owner_relation =
                classify_owner_relation(analyzer, Some(&hit.enclosing_unit), &hit.resolved);
            let ast_id = site_identities
                .entry(hit.file.clone())
                .or_insert_with(|| SiteIdentityIndex::build(analyzer, &hit.file))
                .ast_id(&hit.range);
            ReferenceEdgeRow {
                site: EdgeSite {
                    file: hit.file,
                    range: hit.range,
                    ast_id,
                    enclosing: Some(hit.enclosing_unit),
                },
                target: hit.resolved,
                reference_kind: hit.kind,
                proof: hit.proof,
                usage_kind: hit.usage_kind,
                site_class,
                owner_relation,
                provenance: EdgeProvenance::Inverse,
                generation,
            }
        })
        .collect()
}

/// Every inverse edge of one seed declaration: the sites the usage index can
/// enumerate that point at it, in the canonical row shape.
pub fn inverse_edges_for_declaration(
    analyzer: &dyn IAnalyzer,
    declaration: &CodeUnit,
    cancellation: Option<&CancellationToken>,
) -> EdgeDerivationResult {
    let generation = analyzer.project().analysis_generation();
    let file = declaration.source();
    match supports_edge_axis(analyzer, file, EdgeAxis::InverseProjection) {
        Some(true) => {}
        Some(false) => {
            return EdgeDerivationResult::incomplete(
                vec![EdgeIncompleteReason::AxisUnsupported(
                    EdgeAxis::InverseProjection,
                )],
                EdgeProvenance::Inverse,
                generation,
            );
        }
        None => {
            return EdgeDerivationResult::incomplete(
                vec![EdgeIncompleteReason::NoStructuralAdapter],
                EdgeProvenance::Inverse,
                generation,
            );
        }
    }

    let mut finder = UsageFinder::new();
    if let Some(cancellation) = cancellation {
        finder = finder.with_cancellation(cancellation.clone());
    }
    let query = finder.query(
        analyzer,
        std::slice::from_ref(declaration),
        MAX_INVERSE_EDGE_FILES,
        MAX_INVERSE_EDGE_HITS,
    );

    let mut reasons = Vec::new();
    match query.completion {
        UsageQueryCompletion::Complete => {}
        UsageQueryCompletion::Cancelled => reasons.push(EdgeIncompleteReason::Cancelled),
        UsageQueryCompletion::CandidateFilesBudgetExhausted
        | UsageQueryCompletion::SourceBytesBudgetExhausted => {
            reasons.push(EdgeIncompleteReason::UsageListingTruncated);
        }
    }
    if let crate::analyzer::usages::FuzzyResult::Failure {
        reason_kind,
        reason,
        ..
    } = &query.result
    {
        reasons.push(EdgeIncompleteReason::UsageAnalysisFailed {
            reason_kind: reason_kind.clone(),
            reason: reason.clone(),
        });
    }
    let (hits, truncated) = reference_hits_for_target(analyzer, query.result, declaration);
    if truncated {
        reasons.push(EdgeIncompleteReason::UsageListingTruncated);
    }
    if supports_edge_axis(analyzer, file, EdgeAxis::OwnerClassification) != Some(true) {
        reasons.push(EdgeIncompleteReason::AxisUnsupported(
            EdgeAxis::OwnerClassification,
        ));
    }

    EdgeDerivationResult {
        edges: edge_rows_from_reference_hits(analyzer, hits, generation),
        completeness: if reasons.is_empty() {
            EdgeCompleteness::Complete
        } else {
            EdgeCompleteness::Incomplete { reasons }
        },
        provenance: EdgeProvenance::Inverse,
        generation,
    }
}

/// Every forward edge of one file: each reference-class occurrence that the
/// resolver resolved to declared targets, in the canonical row shape.
///
/// An occurrence whose resolution failed, stopped at a boundary, or landed on
/// a file-local lexical binding contributes no edge -- that is data about the
/// forward surface, not incompleteness: the parity comparison finding an
/// inverse edge with no forward counterpart at such a site is exactly the
/// mined regression shape this layer exists to expose. Ambiguity is preserved
/// as uncertainty: a multi-target resolution emits one row per target, each
/// `Unproven`.
pub fn forward_edges_for_file(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    cancellation: &CancellationToken,
) -> Result<EdgeDerivationResult, OccurrencesCancelled> {
    let generation = analyzer.project().analysis_generation();
    match supports_edge_axis(analyzer, file, EdgeAxis::ForwardProjection) {
        Some(true) => {}
        Some(false) => {
            return Ok(EdgeDerivationResult::incomplete(
                vec![EdgeIncompleteReason::AxisUnsupported(
                    EdgeAxis::ForwardProjection,
                )],
                EdgeProvenance::Forward,
                generation,
            ));
        }
        None => {
            return Ok(EdgeDerivationResult::incomplete(
                vec![EdgeIncompleteReason::NoStructuralAdapter],
                EdgeProvenance::Forward,
                generation,
            ));
        }
    }

    let occurrences = occurrences_for_file(analyzer, file, cancellation)?;
    let mut edges = Vec::new();
    for row in &occurrences.rows {
        let OccurrenceTarget::Resolved(units) = &row.target else {
            continue;
        };
        let proof = if units.len() == 1 {
            UsageProof::Proven
        } else {
            UsageProof::Unproven
        };
        for unit in units {
            let kind = classify_reference_kind(
                analyzer,
                file,
                row.range.start_byte,
                row.range.end_byte,
                unit,
            );
            edges.push(ReferenceEdgeRow {
                site: EdgeSite {
                    file: file.clone(),
                    range: row.range,
                    ast_id: Some(row.ast_id()),
                    enclosing: row.enclosing.clone(),
                },
                target: unit.clone(),
                reference_kind: kind,
                proof,
                usage_kind: UsageHitKind::Reference,
                site_class: SiteClass::UseSite,
                owner_relation: classify_owner_relation(analyzer, row.enclosing.as_ref(), unit),
                provenance: EdgeProvenance::Forward,
                generation,
            });
        }
    }

    let mut reasons = Vec::new();
    if let OccurrenceCompleteness::Incomplete { .. } = &occurrences.completeness {
        reasons.push(EdgeIncompleteReason::OccurrenceRowsIncomplete);
    }
    if supports_edge_axis(analyzer, file, EdgeAxis::OwnerClassification) != Some(true) {
        reasons.push(EdgeIncompleteReason::AxisUnsupported(
            EdgeAxis::OwnerClassification,
        ));
    }
    let completeness = if reasons.is_empty() {
        EdgeCompleteness::Complete
    } else {
        EdgeCompleteness::Incomplete { reasons }
    };
    Ok(EdgeDerivationResult {
        edges,
        completeness,
        provenance: EdgeProvenance::Forward,
        generation,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::{AnalyzerConfig, Language, Project, TestProject, WorkspaceAnalyzer};
    use std::path::PathBuf;
    use std::sync::Arc;
    use tempfile::TempDir;

    struct Fixture {
        _temp: TempDir,
        workspace: WorkspaceAnalyzer,
        files: Vec<ProjectFile>,
    }

    impl Fixture {
        fn new(language: Language, sources: &[(&str, &str)]) -> Self {
            let temp = tempfile::tempdir().expect("temp dir");
            let root: PathBuf = temp.path().canonicalize().expect("canonical root");
            let files = sources
                .iter()
                .map(|(relative_path, source)| {
                    let file = ProjectFile::new(root.clone(), *relative_path);
                    file.write(source).expect("write fixture source");
                    file
                })
                .collect::<Vec<_>>();
            let project = TestProject::new(root, language);
            let workspace = WorkspaceAnalyzer::build(
                Arc::new(project) as Arc<dyn Project>,
                AnalyzerConfig::default(),
            );
            Self {
                _temp: temp,
                workspace,
                files,
            }
        }

        fn analyzer(&self) -> &dyn IAnalyzer {
            self.workspace.analyzer()
        }

        fn declaration(&self, fq_suffix: &str) -> CodeUnit {
            self.analyzer()
                .all_declarations()
                .find(|unit| unit.fq_name().ends_with(fq_suffix))
                .unwrap_or_else(|| panic!("fixture must declare {fq_suffix}"))
        }
    }

    const JAVA_TARGET: &str =
        "package fixture;\n\npublic class Registry {\n    public void register() {\n    }\n}\n";
    const JAVA_CALLER: &str = "package fixture;\n\npublic class Startup {\n    void boot(Registry registry) {\n        registry.register();\n    }\n}\n";

    /// The acceptance shape for this milestone: one plain proven cross-file
    /// call yields a forward row and an inverse row that agree field for field
    /// on everything except the fields that legitimately differ between the
    /// producers (`provenance`, and the forward-only `ast_id`).
    #[test]
    fn forward_and_inverse_producers_agree_on_a_plain_proven_call() {
        let fixture = Fixture::new(
            Language::Java,
            &[
                ("src/Registry.java", JAVA_TARGET),
                ("src/Startup.java", JAVA_CALLER),
            ],
        );
        let analyzer = fixture.analyzer();
        let target = fixture.declaration("Registry.register");

        let inverse = inverse_edges_for_declaration(analyzer, &target, None);
        assert!(
            inverse.completeness.is_complete(),
            "inverse derivation must be complete: {:?}",
            inverse.completeness
        );
        let inverse_call = inverse
            .edges
            .iter()
            .find(|edge| edge.usage_kind == UsageHitKind::Reference)
            .expect("the call site must appear as an inverse edge");

        let caller_file = &fixture.files[1];
        let forward = forward_edges_for_file(analyzer, caller_file, &CancellationToken::new())
            .expect("not cancelled");
        let forward_call = forward
            .edges
            .iter()
            .find(|edge| edge.target.fq_name() == target.fq_name())
            .expect("the call site must appear as a forward edge");

        assert_eq!(forward_call.site.file, inverse_call.site.file);
        assert_eq!(
            forward_call.site.range.start_byte,
            inverse_call.site.range.start_byte
        );
        assert_eq!(
            forward_call.site.range.end_byte,
            inverse_call.site.range.end_byte
        );
        assert_eq!(forward_call.target.fq_name(), inverse_call.target.fq_name());
        assert_eq!(forward_call.reference_kind, inverse_call.reference_kind);
        assert_eq!(forward_call.reference_kind, Some(ReferenceKind::MethodCall));
        assert_eq!(forward_call.proof, UsageProof::Proven);
        assert_eq!(inverse_call.proof, UsageProof::Proven);
        assert_eq!(forward_call.usage_kind, inverse_call.usage_kind);
        assert_eq!(forward_call.site_class, SiteClass::UseSite);
        assert_eq!(forward_call.generation, inverse_call.generation);
        assert_eq!(forward_call.provenance, EdgeProvenance::Forward);
        assert_eq!(inverse_call.provenance, EdgeProvenance::Inverse);
        assert!(forward_call.site.ast_id.is_some());
        assert_eq!(forward_call.site.ast_id, inverse_call.site.ast_id);
        assert_eq!(forward_call.owner_relation, inverse_call.owner_relation);
        assert_ne!(forward_call.owner_relation, OwnerRelation::Unknown);
    }

    const JAVA_BASE: &str =
        "package fixture;\n\npublic class Base {\n    public void ping() {\n    }\n}\n";
    const JAVA_DERIVED: &str = "package fixture;\n\npublic class Derived extends Base {\n    void run() {\n        helper();\n        run();\n    }\n\n    void helper() {\n    }\n}\n";

    /// The one shared classifier answers every relation the issue names, from
    /// the units alone, so both producers inherit identical classifications by
    /// construction.
    #[test]
    fn the_owner_classifier_states_each_relation() {
        let fixture = Fixture::new(
            Language::Java,
            &[
                ("src/Base.java", JAVA_BASE),
                ("src/Derived.java", JAVA_DERIVED),
            ],
        );
        let analyzer = fixture.analyzer();
        let base_ping = fixture.declaration("Base.ping");
        let derived_run = fixture.declaration("Derived.run");
        let derived_helper = fixture.declaration("Derived.helper");

        assert_eq!(
            classify_owner_relation(analyzer, Some(&derived_run), &derived_helper),
            OwnerRelation::SameOwner
        );
        assert_eq!(
            classify_owner_relation(analyzer, Some(&derived_run), &derived_run),
            OwnerRelation::SelfReference
        );
        assert_eq!(
            classify_owner_relation(analyzer, Some(&derived_run), &base_ping),
            OwnerRelation::InheritedOwner
        );
        assert_eq!(
            classify_owner_relation(analyzer, None, &base_ping),
            OwnerRelation::Unknown
        );
    }

    /// An adapter without a forward surface answers with a typed abstention,
    /// never an empty complete set.
    #[test]
    fn a_language_without_forward_support_reports_the_axis_not_empty_rows() {
        let fixture = Fixture::new(
            Language::Kotlin,
            &[(
                "src/Main.kt",
                "class Registry {\n    fun register() {\n    }\n}\n",
            )],
        );
        let result = forward_edges_for_file(
            fixture.analyzer(),
            &fixture.files[0],
            &CancellationToken::new(),
        )
        .expect("not cancelled");
        assert!(result.edges.is_empty());
        assert_eq!(
            result.completeness,
            EdgeCompleteness::Incomplete {
                reasons: vec![EdgeIncompleteReason::AxisUnsupported(
                    EdgeAxis::ForwardProjection
                )]
            }
        );
        assert!(!result.covers(EdgeAxis::ForwardProjection));
        assert!(!result.covers(EdgeAxis::InverseProjection));
    }

    /// Two hits that disagree only on proof are two canonical rows. The
    /// usage-hit identity excludes proof, so upstream sets collapse exactly
    /// this disagreement; the canonical layer must not.
    #[test]
    fn rows_that_disagree_only_on_proof_stay_distinct() {
        let fixture = Fixture::new(
            Language::Java,
            &[
                ("src/Registry.java", JAVA_TARGET),
                ("src/Startup.java", JAVA_CALLER),
            ],
        );
        let target = fixture.declaration("Registry.register");
        let caller = fixture.declaration("Startup.boot");
        let range = Range {
            start_byte: 10,
            end_byte: 18,
            start_line: 4,
            end_line: 4,
        };
        let hit = |proof| ReferenceHit {
            file: fixture.files[1].clone(),
            range,
            enclosing_unit: caller.clone(),
            kind: Some(ReferenceKind::MethodCall),
            resolved: target.clone(),
            confidence: 1_000_000,
            usage_kind: UsageHitKind::Reference,
            proof,
        };
        let rows = edge_rows_from_reference_hits(
            fixture.analyzer(),
            [hit(UsageProof::Proven), hit(UsageProof::Unproven)],
            7,
        );
        assert_eq!(rows.len(), 2);
        assert_ne!(rows[0], rows[1]);
        assert_eq!(rows[0].proof, UsageProof::Proven);
        assert_eq!(rows[1].proof, UsageProof::Unproven);
    }

    /// The covers table: axes this producer does not answer are never covered,
    /// and each incomplete reason blocks exactly its own projection.
    #[test]
    fn completeness_covers_the_declared_axes_only() {
        let complete = EdgeCompleteness::Complete;
        for &axis in EDGE_PRODUCER_AXES {
            assert!(complete.covers(axis));
        }

        let truncated = EdgeCompleteness::Incomplete {
            reasons: vec![EdgeIncompleteReason::UsageListingTruncated],
        };
        assert!(!truncated.covers(EdgeAxis::InverseProjection));
        assert!(truncated.covers(EdgeAxis::ForwardProjection));

        let occurrence_gap = EdgeCompleteness::Incomplete {
            reasons: vec![EdgeIncompleteReason::OccurrenceRowsIncomplete],
        };
        assert!(!occurrence_gap.covers(EdgeAxis::ForwardProjection));
        assert!(occurrence_gap.covers(EdgeAxis::InverseProjection));

        let cancelled = EdgeCompleteness::Incomplete {
            reasons: vec![EdgeIncompleteReason::Cancelled],
        };
        for &axis in EDGE_PRODUCER_AXES {
            assert!(!cancelled.covers(axis));
        }
    }
}
