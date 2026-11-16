//! Evaluation units: the smallest piece of policy work a run reuses.
//!
//! A unit is one policy evaluated over one partition of the workspace -- for
//! the match family, one seed file -- together with the exact set of inputs
//! that execution read. Runs over two workspaces may share a unit's product when
//! every one of those reads still denotes the same content, which is what
//! [`verify_read_set`] decides.
//!
//! Nothing here is per policy or per family beyond the key's own fields. The
//! same key, the same verification and the same store serve every policy: a
//! family differs only in how its execution is partitioned, which is a
//! property of the plan's structure that the RQL crate computes.
//!
//! [`verify_read_set`]: brokk_bifrost_analysis::analyzer::verify_read_set

use brokk_bifrost_analysis::gitblob::ParseVariant;
use brokk_bifrost_core::lever_tokens::{LeverIdentity, LeverTokens};
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserializer, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::{LazyLock, Mutex, OnceLock};
use std::time::Duration;

use brokk_bifrost_analysis::analyzer::invalidation::{ArtifactVerdictLog, BudgetMode};
use brokk_bifrost_analysis::analyzer::read_ledger::read_set_digest;
use brokk_bifrost_analysis::analyzer::semantic::SemanticBudgetReplay;
use brokk_bifrost_analysis::analyzer::semantic::ids::StableDigest;
use brokk_bifrost_analysis::analyzer::semantic_model::ActiveSemanticModelSnapshot;
use brokk_bifrost_analysis::analyzer::store::AnalyzerStore;
use brokk_bifrost_analysis::analyzer::store::policy_units::{
    PolicyUnitAttestation, PolicyUnitPartitionRow, PolicyUnitRow, PolicyUnitRowKey,
};
use brokk_bifrost_analysis::analyzer::{
    ChangedFacts, HeadInputs, Language, Oid, ReadKey, ReadSetDigest, WorkspaceAnalyzer,
    analysis_epoch_digest,
};
use brokk_bifrost_flow::dataflow::SolverWork;
use brokk_bifrost_rql::PlanWidenDetail;
use brokk_bifrost_rql::structural::UnitExecutionResult;
use brokk_bifrost_rql::structural::identifier_typos::IdentifierTypoTable;
use brokk_bifrost_rql::structural::{
    CodeQueryCompletion, CodeQueryDiagnostic, CodeQueryExecutionWork,
};
use std::sync::Arc;

use super::budget::PolicyBudget;
use super::definition::{PolicyAnalysisType, PolicyId};
use super::finding::{PolicyFinding, PolicyFindingSeed, PolicyIncompleteReason};
use super::identity::PolicySemanticHash;
use super::projection::{TypestateProjectedFinding, TypestateProjectedFindingSeed};
use super::resolved::LoadedPolicy;
use super::typestate_policy::TypestateGap;

/// The digest a unit key carries when no semantic models were active.
///
/// A fixed value rather than an absent field: "no models were active" is an
/// input like any other, and a unit produced without models must not match one
/// produced with them.
const NO_ACTIVE_MODELS: &str = "bifrost-policy-unit:no-active-models:v1";

/// This crate's own revision, folded into the engine epoch beside the
/// analyzer's parser epochs: the policy substrate lever (#11570), one change
/// name per line in `levers/policy-substrate.tokens`.
///
/// The analyzer epoch says which parsers derived the facts a unit read. It
/// says nothing about how this crate shapes a published product or composes a
/// finding identity, and a run must read back neither from an older engine.
/// Add a line whenever a change makes either something this engine would no
/// longer mint; see `.agents/docs/cache-identity-levers.md`.
static POLICY_SUBSTRATE_LEVER: LazyLock<LeverTokens<'static>> = LazyLock::new(|| {
    LeverTokens::parse(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/levers/policy-substrate.tokens"
    )))
    .expect("the policy substrate lever file is well formed")
});
const POLICY_SUBSTRATE_LEVER_NAME: &str = "policy-substrate";

fn substrate_identity(identity: LeverIdentity) -> String {
    format!("bifrost-policy-unit:substrate:{identity}")
}
/// The epoch every unit key and the evaluation row key carry.
fn policy_substrate_epoch(lowering: StableDigest) -> StableDigest {
    static SUBSTRATE: LazyLock<String> = LazyLock::new(|| {
        substrate_identity(POLICY_SUBSTRATE_LEVER.identity(POLICY_SUBSTRATE_LEVER_NAME))
    });
    StableDigest::sha256(format!(
        "{}\u{1}{}\u{1}{lowering}",
        *SUBSTRATE,
        analysis_epoch_digest(),
    ))
}

/// The epoch a head one substrate change older keyed its units by.
#[cfg(test)]
pub(crate) fn substrate_epoch_before_last_token(lowering: StableDigest) -> StableDigest {
    let previous = substrate_identity(
        POLICY_SUBSTRATE_LEVER.identity_before_last_token(POLICY_SUBSTRATE_LEVER_NAME),
    );
    StableDigest::sha256(format!(
        "{previous}\u{1}{}\u{1}{lowering}",
        analysis_epoch_digest()
    ))
}

/// Which partition of the workspace one unit covers.
///
/// A `Seed` unit is keyed by the file its seed enumeration walked and the blob
/// that path resolved to, because the same path holding different bytes is a
/// different unit even when nothing else moved. `Whole` is retained for
/// loading legacy persisted products, but new widened evaluations do not mint
/// it: a widened run evaluates directly and publishes no unit.
///
/// A `Binding` unit is one seed file of one row binding of a relational
/// assertion policy. It names the binding beside the file, because one
/// relational policy runs one query per declared binding over the same seed
/// files: two bindings keyed by the file alone would be one key, and the
/// second binding's rows would be served from the first binding's unit.
///
/// An `AssertFile` unit is one subject file of an assertion policy. It carries
/// the digest of that file's subject rows beside the blob, because a subject
/// selector that bound different rows in the same bytes asked a different
/// question of the same file and must not be answered with the first
/// question's findings.
///
/// A `Selector` unit is one seed file of one selector of a policy that
/// compiles selectors: the file, the blob that path resolved to, and the
/// selector's own document path. The path is part of the key because one
/// policy compiles many selectors over the same seed files -- a typestate
/// policy's subjects, events, terminals and dependencies -- and two of them
/// keyed by the file alone would be one key, and the second selector's sites
/// would be served from the first selector's unit.
///
/// A `Root` unit is one solver root of a typestate policy: the file the root
/// procedure is declared in, the blob that path resolved to, and the root's
/// own checkout-independent semantic locator. The locator is part of the key
/// because one file declares many procedures and a typestate policy solves
/// each of them separately: two roots keyed by the file alone would be one
/// key, and the second root's findings would be served from the first root's
/// unit. It carries the compile that produced it beside the locator -- the
/// compiled protocol hash and binding-plan hash together -- because every
/// projection a root solve produces is sealed to those two hashes and the
/// projection authority drops a projection that names any other compile. A
/// root served across a compile boundary therefore reports nothing rather
/// than reporting something wrong, which is the one failure a store must not
/// have.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum UnitPartition {
    Seed {
        language: Language,
        rel_path: Box<str>,
        blob: Oid,
    },
    Binding {
        binding: Box<str>,
        language: Language,
        rel_path: Box<str>,
        blob: Oid,
    },
    AssertFile {
        language: Language,
        rel_path: Box<str>,
        blob: Oid,
        subjects: StableDigest,
    },
    Root {
        language: Language,
        rel_path: Box<str>,
        blob: Oid,
        locator: StableDigest,
        compilation: StableDigest,
    },
    Selector {
        language: Language,
        rel_path: Box<str>,
        blob: Oid,
        selector: StableDigest,
    },
    Prefix {
        language: Language,
        rel_path: Box<str>,
        blob: Oid,
        cut: StableDigest,
        input: StableDigest,
    },
    Output {
        language: Language,
        rel_path: Box<str>,
        blob: Oid,
        anchor: StableDigest,
        compilation: StableDigest,
    },
    Whole,
    /// A reusable ordinary-plan operand, independent of a source file. The
    /// question binds its role, canonical plan and originating query grant.
    Operand {
        question: StableDigest,
    },
}

impl UnitPartition {
    /// The stable label of this partition kind.
    pub const fn stable_label(&self) -> &'static str {
        match self {
            Self::Seed { .. } => "seed",
            Self::Binding { .. } => "binding",
            Self::AssertFile { .. } => "assert_file",
            Self::Root { .. } => "root",
            Self::Selector { .. } => "selector",
            Self::Prefix { .. } => "prefix",
            Self::Output { .. } => "output",
            Self::Whole => "whole",
            Self::Operand { .. } => "operand",
        }
    }
}

/// Everything that decides whether two evaluations are the same question.
///
/// The policy's semantic hash and the family fix what is being asked, the
/// partition fixes over which content, and the three digests fix the engine
/// that would answer: the analyzer configuration folded into every content
/// identity, the active semantic-model set, and the analysis epoch every
/// persisted fact was derived under. A run that differs in any of them is
/// asking a different question and gets a different key rather than a wrong
/// answer.
///
/// Ordinary operand questions bind their originating query budget. Other units
/// share keys across budgets subject to their replay grants. A unit produced under a budget cut holds a
/// correct, reported-incomplete subset, and which subset a cut returns is not a
/// contract, so a shared unit is never read as exact for any one budget.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PolicyUnitKey {
    pub policy: PolicySemanticHash,
    pub family: PolicyAnalysisType,
    pub partition: UnitPartition,
    pub configuration: StableDigest,
    pub models: StableDigest,
    pub epoch: StableDigest,
}

/// What one unit produced.
///
/// A query unit's product is the projection of its rendered rows, their
/// evidence and the execution's counters, which is exactly what the merge and
/// the policy adapter consume. An assert unit's product is not rows at all: it
/// is what one iteration of the assertion per-file loop produced.
#[derive(Debug, Clone)]
pub(crate) enum PolicyUnitProduct {
    Rows(UnitExecutionResult),
    AssertFile(AssertFileProduct),
    Root(RootProduct),
    Selector(Box<SelectorProduct>),
    Prefix(String),
    Output(String),
}

impl PolicyUnitProduct {
    /// The rendered rows this product carries, or `None` when it carries a
    /// product of another shape.
    ///
    /// A caller that asked a rows-shaped question and got something else is
    /// holding a store that answered a different question, which is a load
    /// failure rather than an empty answer.
    pub(crate) fn into_rows(self) -> Option<UnitExecutionResult> {
        match self {
            Self::Rows(rows) => Some(rows),
            Self::AssertFile(_)
            | Self::Root(_)
            | Self::Selector(_)
            | Self::Prefix(_)
            | Self::Output(_) => None,
        }
    }

    /// The per-file assertion product this carries, or `None` when it carries a
    /// product of another shape.
    pub(crate) fn into_assert_file(self) -> Option<AssertFileProduct> {
        match self {
            Self::AssertFile(product) => Some(product),
            Self::Rows(_)
            | Self::Root(_)
            | Self::Selector(_)
            | Self::Prefix(_)
            | Self::Output(_) => None,
        }
    }

    /// The per-root typestate product this carries, or `None` when it carries
    /// a product of another shape.
    pub(crate) fn into_root(self) -> Option<RootProduct> {
        match self {
            Self::Root(product) => Some(product),
            Self::Rows(_)
            | Self::AssertFile(_)
            | Self::Selector(_)
            | Self::Prefix(_)
            | Self::Output(_) => None,
        }
    }

    /// The per-seed selector product this carries, or `None` when it carries a
    /// product of another shape.
    pub(crate) fn into_selector(self) -> Option<SelectorProduct> {
        match self {
            Self::Selector(product) => Some(*product),
            Self::Rows(_)
            | Self::AssertFile(_)
            | Self::Root(_)
            | Self::Prefix(_)
            | Self::Output(_) => None,
        }
    }

    /// The stable label of this product kind.
    pub(crate) const fn stable_label(&self) -> &'static str {
        match self {
            Self::Rows(_) => "rows",
            Self::AssertFile(_) => "assert_file",
            Self::Root(_) => "root",
            Self::Selector(_) => "selector",
            Self::Prefix(_) => "prefix",
            Self::Output(_) => "output",
        }
    }
}

/// The report-retention producer's result, retained through assertion unit replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum AssertFileRetention {
    None,
    DetailRetention,
    FindingRetention {
        omitted_lower_bound: std::num::NonZeroU64,
    },
}

impl AssertFileRetention {
    pub(crate) fn combined(self, other: Self) -> Self {
        match (self, other) {
            (Self::None, value) | (value, Self::None) => value,
            (
                Self::FindingRetention {
                    omitted_lower_bound: left,
                },
                Self::FindingRetention {
                    omitted_lower_bound: right,
                },
            ) => Self::FindingRetention {
                omitted_lower_bound: std::num::NonZeroU64::new(
                    left.get().saturating_add(right.get()),
                )
                .expect("positive omission sum"),
            },
            (value @ Self::FindingRetention { .. }, _)
            | (_, value @ Self::FindingRetention { .. }) => value,
            _ => Self::DetailRetention,
        }
    }
}

/// What one iteration of the assertion per-file loop produced.
///
/// Exactly the file's contribution to the run's accumulators, and nothing
/// else: the findings its asserts violated, the typed reasons it could not be
/// concluded (empty when it was), the completion of every row query it ran, the
/// query diagnostics it raised, and what it scanned. The merge appends each of
/// these to the run-wide accumulator in path order, and the run then finishes
/// exactly as a whole evaluation finishes.
///
/// A file's iteration never returns both findings and reasons: a verdict over
/// an incomplete row set is never a pass and never a finding, so an unconcluded
/// file contributes no findings at all.
#[derive(Debug, Clone, Serialize)]
pub struct AssertFileProduct {
    pub retention: AssertFileRetention,
    pub findings: Vec<PolicyFinding>,
    pub unconcluded: Vec<PolicyIncompleteReason>,
    pub row_completions: Vec<CodeQueryCompletion>,
    pub diagnostics: Vec<CodeQueryDiagnostic>,
    pub work: CodeQueryExecutionWork,
}

/// What one iteration of the typestate per-root loop appended.
///
/// Exactly the root's contribution to the run's accumulators and nothing else:
/// the violations it projected, in the order the loop appended them; the typed
/// gaps its own analysis left, which become the run's incomplete reasons and
/// diagnostics; and what it added to the run's
/// counters, including the four request-wide finding lanes it consumed. The
/// merge appends each of these in root order into the same accumulators a
/// whole evaluation fills, and the run then finishes exactly as a whole
/// evaluation finishes.
///
/// The projections rather than the findings they become: one iteration of the
/// loop appends projections, and the batch that turns them into findings runs
/// once over every root's, under the seal minted for this evaluation.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct RootProduct {
    pub findings: Vec<TypestateProjectedFinding>,
    pub gaps: Vec<TypestateGap>,
    pub work: RootWork,
}

/// What one root's iteration added to the run's counters, and what it took out
/// of the lanes every root of the evaluation shares.
///
/// The first five fields are the run's reporting counters. Everything after
/// them is a shared allowance this root consumed: the four `finding_*` lanes
/// of the request-wide finding budget, the solver and semantic ledgers the
/// solve charged, the execution budget's materialized files and traversal
/// steps, and the artifact leases the root's window committed. They are part
/// of the product because those allowances are shared: a run that reused this
/// root still has to charge what the root's own solve cost, or a later root
/// would see an allowance no whole evaluation would have given it and the
/// sliced run would reach a lane later than the whole run does.
#[derive(Debug, Clone, Copy, Default, Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RootWork {
    pub reached_rows: u64,
    pub subject_rows: u64,
    pub terminal_rows: u64,
    pub retained_analysis_findings: u64,
    pub omitted_analysis_findings: u64,
    pub finding_reached_rows: u64,
    pub finding_candidates: u64,
    pub finding_witness_expansions: u64,
    pub finding_witness_bytes: u64,
    pub solver: SolverWork,
    pub semantic: SemanticBudgetReplay,
    pub materialized_files: u64,
    pub traversal_steps: u64,
    pub artifact_leases: u64,
    pub artifact_lease_bytes: u64,
}

/// What one seed file's execution of one selector contributed to a compile.
///
/// Two halves, because a selector unit answers two questions. `rows` is the
/// query's own product, exactly as a match unit publishes it: the merge sums
/// its counters and checks them against the cumulative caps the whole
/// execution enforces, which is what licenses claiming the merged product is
/// the whole product. `sites` is what the compile actually consumes -- the
/// sites this seed file selected, projected onto content-addressed identities
/// -- because a selected site is derived from a row's own typed value and that
/// value is not reconstructible from the row projection.
///
/// The three charges are what this unit took out of the session's shared
/// semantic ledgers, so a run that reuses the unit leaves those ledgers where
/// the execution left them and the compile's remaining budget after the last
/// unit is the budget a whole-workspace selector execution would have left.
/// There is no artifact charge: a unit whose execution retained artifact
/// allocations is never published, because those allocations are process-local
/// and a reused unit could not hand them to the compile.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SelectorProduct {
    pub rows: UnitExecutionResult,
    pub sites: Vec<SelectorProductSite>,
    pub semantic: SemanticBudgetReplay,
    pub materialized_files: u64,
    pub traversal_steps: u64,
}

impl SelectorProduct {
    /// Incompatible retained selector JSON must trigger fresh execution.
    fn decode_retained(json: &str) -> Option<Box<Self>> {
        serde_json::from_str(json).ok()
    }
}

/// One selected site, over identities a second checkout resolves the same way.
///
/// The workspace-relative path rather than the `ProjectFile` the compile holds
/// (that one carries a checkout root), and the two quality verdicts spelled as
/// their reasons: absent means the verdict was `Proven` or `Complete`, present
/// means it was not and carries why.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SelectorProductSite {
    pub rel_path: Box<str>,
    pub start: usize,
    pub end: usize,
    pub unproven: Option<Box<str>>,
    pub partial: Option<Box<str>>,
}

/// Read one root unit's product back under the budget its projections' caps
/// are stated in.
///
/// A seed for the reason [`AssertFileProductSeed`] is one: a projection is
/// normalized against a budget, and the budget that matters is the reading
/// run's.
pub(crate) struct RootProductSeed<'a> {
    budget: &'a PolicyBudget,
}

impl<'a> RootProductSeed<'a> {
    pub(crate) const fn new(budget: &'a PolicyBudget) -> Self {
        Self { budget }
    }
}

/// The field names a root unit product carries, named once so the visitor and
/// the error it raises for an unknown field cannot disagree.
const ROOT_FIELDS: &[&str] = &["findings", "gaps", "work"];

impl<'de> DeserializeSeed<'de> for RootProductSeed<'_> {
    type Value = RootProduct;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_struct(
            "RootProduct",
            ROOT_FIELDS,
            RootProductVisitor {
                budget: self.budget,
            },
        )
    }
}

/// Reads a root unit product's fields, handing the budget to the projections.
///
/// Hand-written rather than derived for the same reason the assert unit's
/// visitor is: a derived struct cannot carry a seed into one of its fields.
struct RootProductVisitor<'a> {
    budget: &'a PolicyBudget,
}

impl<'de> Visitor<'de> for RootProductVisitor<'_> {
    type Value = RootProduct;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("one typestate root's evaluation product")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut findings: Option<Vec<TypestateProjectedFinding>> = None;
        let mut gaps: Option<Vec<TypestateGap>> = None;
        let mut work: Option<RootWork> = None;
        while let Some(field) = map.next_key::<String>()? {
            let duplicate = match field.as_str() {
                "findings" => findings
                    .replace(map.next_value_seed(ProjectionListSeed {
                        budget: self.budget,
                    })?)
                    .is_some(),
                "gaps" => gaps.replace(map.next_value()?).is_some(),
                "work" => work.replace(map.next_value()?).is_some(),
                other => return Err(de::Error::unknown_field(other, ROOT_FIELDS)),
            };
            if duplicate {
                return Err(de::Error::duplicate_field("a root unit product field"));
            }
        }
        let product = RootProduct {
            findings: findings.ok_or_else(|| de::Error::missing_field("findings"))?,
            gaps: gaps.ok_or_else(|| de::Error::missing_field("gaps"))?,
            work: work.ok_or_else(|| de::Error::missing_field("work"))?,
        };
        // One retained analysis finding projects to at least one violation and
        // may project to several -- a terminal expectation with two states
        // outside it is two -- so the counter is bounded by the list rather
        // than equal to it, and neither can be nonzero without the other. A
        // stored product outside those bounds would merge a work report no
        // evaluation produced.
        let projected = u64::try_from(product.findings.len()).unwrap_or(u64::MAX);
        if product.work.retained_analysis_findings > projected
            || (product.work.retained_analysis_findings == 0) != (projected == 0)
        {
            return Err(de::Error::custom(
                "a stored root unit counts retained findings its own projections cannot account \
                 for",
            ));
        }
        Ok(product)
    }
}

/// One root's projections, each read under the reading run's budget.
struct ProjectionListSeed<'a> {
    budget: &'a PolicyBudget,
}

fn collect_seeded_sequence<'de, A, S>(
    mut sequence: A,
    mut seed: impl FnMut() -> S,
) -> Result<Vec<S::Value>, A::Error>
where
    A: SeqAccess<'de>,
    S: DeserializeSeed<'de>,
{
    let mut values = Vec::with_capacity(sequence.size_hint().unwrap_or_default());
    while let Some(value) = sequence.next_element_seed(seed())? {
        values.push(value);
    }
    Ok(values)
}

impl<'de> DeserializeSeed<'de> for ProjectionListSeed<'_> {
    type Value = Vec<TypestateProjectedFinding>;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(self)
    }
}

impl<'de> Visitor<'de> for ProjectionListSeed<'_> {
    type Value = Vec<TypestateProjectedFinding>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a list of projected typestate violations")
    }

    fn visit_seq<A>(self, seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        collect_seeded_sequence(seq, || TypestateProjectedFindingSeed::new(self.budget))
    }
}

/// Read one assert unit's product back under the budget its findings' caps are
/// stated in.
///
/// A seed rather than a plain `Deserialize` for the reason
/// [`PolicyFindingSeed`] is one: a finding is validated against a budget, and
/// the budget that matters is the reading run's.
pub(crate) struct AssertFileProductSeed<'a> {
    budget: &'a PolicyBudget,
}

impl<'a> AssertFileProductSeed<'a> {
    pub(crate) const fn new(budget: &'a PolicyBudget) -> Self {
        Self { budget }
    }
}

impl<'de> DeserializeSeed<'de> for AssertFileProductSeed<'_> {
    type Value = AssertFileProduct;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_struct(
            "AssertFileProduct",
            FIELDS,
            AssertFileProductVisitor {
                budget: self.budget,
            },
        )
    }
}

/// Reads the product's fields, handing the budget to the findings.
///
/// Hand-written rather than derived because a derived struct cannot carry a
/// seed into one of its fields, and the findings are exactly the field that
/// needs one.
struct AssertFileProductVisitor<'a> {
    budget: &'a PolicyBudget,
}

impl<'de> Visitor<'de> for AssertFileProductVisitor<'_> {
    type Value = AssertFileProduct;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("one assertion file's evaluation product")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut retention: Option<AssertFileRetention> = None;
        let mut findings: Option<Vec<PolicyFinding>> = None;
        let mut unconcluded: Option<Vec<PolicyIncompleteReason>> = None;
        let mut row_completions: Option<Vec<CodeQueryCompletion>> = None;
        let mut diagnostics: Option<Vec<CodeQueryDiagnostic>> = None;
        let mut work: Option<CodeQueryExecutionWork> = None;
        while let Some(field) = map.next_key::<String>()? {
            let duplicate = match field.as_str() {
                "retention" => retention.replace(map.next_value()?).is_some(),
                "findings" => findings
                    .replace(map.next_value_seed(FindingListSeed {
                        budget: self.budget,
                    })?)
                    .is_some(),
                "unconcluded" => unconcluded.replace(map.next_value()?).is_some(),
                "row_completions" => row_completions.replace(map.next_value()?).is_some(),
                "diagnostics" => diagnostics.replace(map.next_value()?).is_some(),
                "work" => work.replace(map.next_value()?).is_some(),
                other => return Err(de::Error::unknown_field(other, FIELDS)),
            };
            if duplicate {
                return Err(de::Error::duplicate_field("an assert unit product field"));
            }
        }
        let product = AssertFileProduct {
            retention: retention.ok_or_else(|| de::Error::missing_field("retention"))?,
            findings: findings.ok_or_else(|| de::Error::missing_field("findings"))?,
            unconcluded: unconcluded.ok_or_else(|| de::Error::missing_field("unconcluded"))?,
            row_completions: row_completions
                .ok_or_else(|| de::Error::missing_field("row_completions"))?,
            diagnostics: diagnostics.ok_or_else(|| de::Error::missing_field("diagnostics"))?,
            work: work.ok_or_else(|| de::Error::missing_field("work"))?,
        };
        // A verdict over an incomplete row set is never a pass and never a
        // finding, so a file that could not be concluded contributes none. A
        // stored product that reports both would merge findings the run that
        // produced them had already discarded.
        if !product.findings.is_empty() && !product.unconcluded.is_empty() {
            return Err(de::Error::custom(
                "a stored assert unit reports findings for a file it could not conclude",
            ));
        }
        Ok(product)
    }
}

/// The field names an assert unit product carries, named once so the visitor
/// and the error it raises for an unknown field cannot disagree.
const FIELDS: &[&str] = &[
    "retention",
    "findings",
    "unconcluded",
    "row_completions",
    "diagnostics",
    "work",
];

/// One file's findings, each read under the reading run's budget.
struct FindingListSeed<'a> {
    budget: &'a PolicyBudget,
}

impl<'de> DeserializeSeed<'de> for FindingListSeed<'_> {
    type Value = Vec<PolicyFinding>;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(self)
    }
}

impl<'de> Visitor<'de> for FindingListSeed<'_> {
    type Value = Vec<PolicyFinding>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a list of policy findings")
    }

    fn visit_seq<A>(self, seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        collect_seeded_sequence(seq, || PolicyFindingSeed::new(self.budget))
    }
}

/// One published unit: what it answered, and every input that answer depends
/// on.
///
/// `reads` is the ledger's own key set and `read_digest` is derived from it at
/// construction, so the two can never disagree about which reads a unit's
/// verification must cover.
///
/// `snapshots` are the content identities of the workspaces the unit's
/// name-index answers are known to hold on. A name-index read is proved by the
/// names that moved between two workspaces, which holds only for a read set
/// whose index answers are the first workspace's, so a reader verifies a
/// unit's index reads only against what moved since one of these snapshots.
/// The snapshot that computed the unit is one; every later verification adds
/// the snapshots it proved the answers on (see
/// [`PolicyIncrementalContext::publication_snapshots`]).
#[derive(Debug, Clone)]
pub struct PolicyUnit {
    // Buffered publication input, absent on units loaded for reuse/attestation.
    seed_parse_variant: Option<ParseVariant>,
    key: PolicyUnitKey,
    product: PolicyUnitProduct,
    reads: Vec<ReadKey>,
    read_digest: ReadSetDigest,
    budget_mode: BudgetMode,
    snapshots: Vec<StableDigest>,
}

impl PolicyUnit {
    /// Publish one unit's product under the reads that produced it, whose
    /// name-index answers are those of each workspace in `snapshots`.
    pub(crate) fn new(
        key: PolicyUnitKey,
        seed_parse_variant: Option<ParseVariant>,
        product: PolicyUnitProduct,
        reads: Vec<ReadKey>,
        budget_mode: BudgetMode,
        snapshots: Vec<StableDigest>,
    ) -> Self {
        assert!(
            !snapshots.is_empty(),
            "a unit's index answers hold on the snapshot that computed it"
        );
        let read_digest = read_set_digest(&reads);
        Self {
            key,
            seed_parse_variant,
            product,
            reads,
            read_digest,
            budget_mode,
            snapshots,
        }
    }

    pub const fn key(&self) -> &PolicyUnitKey {
        &self.key
    }

    pub(crate) const fn product(&self) -> &PolicyUnitProduct {
        &self.product
    }

    pub fn reads(&self) -> &[ReadKey] {
        &self.reads
    }

    pub const fn read_digest(&self) -> ReadSetDigest {
        self.read_digest
    }

    pub const fn budget_mode(&self) -> BudgetMode {
        self.budget_mode
    }

    /// The content identities of the workspaces this unit's name-index
    /// answers hold on.
    pub fn snapshots(&self) -> &[StableDigest] {
        &self.snapshots
    }

    /// Record that this unit's name-index answers hold on `snapshots` too.
    fn attest(&mut self, snapshots: &[StableDigest]) {
        for snapshot in snapshots {
            if !self.snapshots.contains(snapshot) {
                self.snapshots.push(*snapshot);
            }
        }
    }

    /// Whether any read of this unit is a name-index probe, the one kind of
    /// read whose proof depends on the snapshot that recorded it.
    pub fn reads_name_index(&self) -> bool {
        self.reads
            .iter()
            .any(|read| matches!(read, ReadKey::Index { .. }))
    }
}

/// Where published units are looked up and published.
///
/// One evaluation batch owns one store. Milestone 3 adds the persisted
/// implementation behind the same two operations; nothing above this trait
/// knows which one it is holding.
pub trait PolicyUnitStore: Send {
    /// Load every unit `keys` names, before the lookups start.
    ///
    /// One policy asks about every seed file of the workspace, so a store that
    /// answers each lookup on its own would pay a round trip per file before
    /// reading a single fact. An in-memory store already holds everything and
    /// does nothing here.
    ///
    /// `Err` is a store that could not answer -- a row that would not load,
    /// a database that would not read -- which is not the same as "nothing was
    /// published under this key". A policy whose store failed widens rather
    /// than treating a failure as an absence, because an absence is a claim
    /// about what was published and a failure is a claim about nothing.
    fn prefetch(
        &mut self,
        _keys: &[PolicyUnitKey],
        _budget: &PolicyBudget,
        _row_node_count: Option<usize>,
    ) -> Result<(), PolicyUnitStoreError> {
        Ok(())
    }

    fn lookup(&self, key: &PolicyUnitKey) -> Option<&PolicyUnit>;
    fn publish(&mut self, unit: PolicyUnit);

    /// Record that the unit under `key`, verified from `verified_on`, holds on
    /// `snapshots` too.
    ///
    /// Applies only while the unit this store holds is still attested on
    /// `verified_on`: verification proved its answers there equal its answers
    /// on `snapshots`, and says nothing about a unit holding other answers.
    fn attest(
        &mut self,
        key: &PolicyUnitKey,
        verified_on: StableDigest,
        snapshots: &[StableDigest],
    );
}

/// A store that could not answer.
///
/// Carried as prose because every one of these is reported and none is
/// recovered from: the policy widens, evaluates in full, and says the product
/// could not be loaded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyUnitStoreError(String);

impl PolicyUnitStoreError {
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl std::fmt::Display for PolicyUnitStoreError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// The units one batch published, for the lifetime of that batch.
#[derive(Debug, Default)]
pub struct InMemoryPolicyUnitStore {
    units: HashMap<PolicyUnitKey, PolicyUnit>,
}

impl InMemoryPolicyUnitStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl PolicyUnitStore for InMemoryPolicyUnitStore {
    fn lookup(&self, key: &PolicyUnitKey) -> Option<&PolicyUnit> {
        self.units.get(key)
    }

    fn publish(&mut self, unit: PolicyUnit) {
        self.units.insert(unit.key.clone(), unit);
    }

    fn attest(
        &mut self,
        key: &PolicyUnitKey,
        verified_on: StableDigest,
        snapshots: &[StableDigest],
    ) {
        if let Some(unit) = self.units.get_mut(key)
            && unit.snapshots.contains(&verified_on)
        {
            unit.attest(snapshots);
        }
    }
}

/// The units of one batch, backed by the repository's analyzer cache.
///
/// Everything a run derives from content lives in that cache, and a unit is
/// derived from content: the file it covers, the files and lookups it read,
/// the policy text, the configuration, the models, the epoch. Publishing units
/// there is what makes the second run of `--diff-base` on the same branch do
/// almost no work, and it is why this exists at all -- an in-memory store
/// serves one process and forgets.
///
/// Reads are prefetched per policy in one query and publications are buffered
/// until the caller flushes them. The incremental context commits a complete
/// policy attempt to this store before buffering, so a widened attempt never
/// leaves a half-published unit set behind; the buffered rows are then written
/// in one database transaction.
pub struct PersistedPolicyUnitStore {
    store: Arc<AnalyzerStore>,
    loaded: HashMap<PolicyUnitKey, PolicyUnit>,
    pending: Vec<PolicyUnit>,
    attestations: Vec<PolicyUnitAttestation>,
    published: usize,
}

impl PersistedPolicyUnitStore {
    pub fn new(store: Arc<AnalyzerStore>) -> Self {
        Self {
            store,
            loaded: HashMap::new(),
            pending: Vec::new(),
            attestations: Vec::new(),
            published: 0,
        }
    }

    /// Write every buffered publication, in one transaction, and then every
    /// buffered attestation.
    ///
    /// The caller decides when: a cancelled or deadline-terminated run flushes
    /// nothing, because its units describe work that stopped early and nothing
    /// downstream can tell that from work that finished. Returns how many
    /// units were published.
    pub fn flush(&mut self) -> Result<usize, PolicyUnitStoreError> {
        let written = self.flush_units()?;
        // After the units, so that a unit this run published and a later
        // policy of the same run verified on another snapshot is in the store
        // when its attestation names it.
        let attestations = std::mem::take(&mut self.attestations);
        self.store
            .attest_policy_units(attestations)
            .map_err(|error| PolicyUnitStoreError::new(format!("{error}")))?;
        Ok(written)
    }

    fn flush_units(&mut self) -> Result<usize, PolicyUnitStoreError> {
        if self.pending.is_empty() {
            return Ok(0);
        }
        let rows = self
            .pending
            .drain(..)
            .map(|unit| unit_row(&unit))
            .collect::<Result<Vec<_>, _>>()?;
        let written = self
            .store
            .publish_policy_units(rows)
            .map_err(|error| PolicyUnitStoreError::new(format!("{error}")))?;
        self.published += written;
        Ok(written)
    }

    /// How many units this store has written.
    pub const fn published(&self) -> usize {
        self.published
    }

    /// The store these units are published to and read from.
    pub const fn store(&self) -> &Arc<AnalyzerStore> {
        &self.store
    }
}

impl PolicyUnitStore for PersistedPolicyUnitStore {
    fn prefetch(
        &mut self,
        keys: &[PolicyUnitKey],
        budget: &PolicyBudget,
        row_node_count: Option<usize>,
    ) -> Result<(), PolicyUnitStoreError> {
        let wanted = keys
            .iter()
            .filter(|key| !self.loaded.contains_key(key))
            .cloned()
            .collect::<Vec<_>>();
        if wanted.is_empty() {
            return Ok(());
        }
        let rows = wanted.iter().map(row_key).collect::<Vec<_>>();
        let answers = self
            .store
            .policy_units_for_keys(&rows)
            .map_err(|error| PolicyUnitStoreError::new(format!("{error}")))?;
        for (key, answer) in wanted.into_iter().zip(answers) {
            let Some(row) = answer else {
                continue;
            };
            // Product shapes evolve with the policy substrate (#10985, #11321). A
            // retained incompatible JSON product is a miss, so execution can
            // rebuild it rather than turn a cache upgrade into a store error.
            let product = if row.product_kind == "selector" {
                let Some(product) = SelectorProduct::decode_retained(&row.product) else {
                    continue;
                };
                PolicyUnitProduct::Selector(product)
            } else {
                match product_of_row(&row, budget) {
                    Ok(product) => product,
                    Err(_) if missing_legacy_diagnostic_cause(&row) => continue,
                    Err(error) => return Err(error),
                }
            };
            self.loaded.insert(
                key.clone(),
                unit_of_row_with_product(key, row, product, row_node_count)?,
            );
        }
        Ok(())
    }

    fn lookup(&self, key: &PolicyUnitKey) -> Option<&PolicyUnit> {
        self.loaded.get(key)
    }

    fn publish(&mut self, unit: PolicyUnit) {
        self.loaded.insert(unit.key.clone(), unit.clone());
        self.pending.push(unit);
    }

    fn attest(
        &mut self,
        key: &PolicyUnitKey,
        verified_on: StableDigest,
        snapshots: &[StableDigest],
    ) {
        let Some(unit) = self.loaded.get_mut(key) else {
            return;
        };
        if !unit.snapshots.contains(&verified_on) {
            return;
        }
        unit.attest(snapshots);
        self.attestations.push(PolicyUnitAttestation {
            key: row_key(key),
            read_set_digest: *unit.read_digest.digest().as_bytes(),
            verified_on: *verified_on.as_bytes(),
            snapshots: snapshots
                .iter()
                .map(|snapshot| *snapshot.as_bytes())
                .collect(),
        });
    }
}

/// The store's spelling of one unit key.
///
/// Digests become lowercase hex and the family becomes its stable label,
/// because a persisted key is compared by SQL and must be one shape per value.
pub fn row_key(key: &PolicyUnitKey) -> PolicyUnitRowKey {
    PolicyUnitRowKey {
        policy_semantic_hash: StableDigest::from_array(*key.policy.as_bytes()).to_string(),
        family: key.family.label().to_string(),
        partition: match &key.partition {
            UnitPartition::Seed {
                language,
                rel_path,
                blob,
            } => PolicyUnitPartitionRow::Seed {
                rel_path: rel_path.to_string(),
                blob: *blob,
                language: *language,
            },
            UnitPartition::Binding {
                binding,
                language,
                rel_path,
                blob,
            } => PolicyUnitPartitionRow::Binding {
                rel_path: rel_path.to_string(),
                blob: *blob,
                language: *language,
                // The name is digested rather than stored: the persisted
                // column is one shape for every partition that carries one,
                // and nothing reads a binding's name back out of the store --
                // the key a lookup asks with carries it.
                binding: StableDigest::sha256(binding.as_ref()).to_string(),
            },
            UnitPartition::AssertFile {
                language,
                rel_path,
                blob,
                subjects,
            } => PolicyUnitPartitionRow::AssertFile {
                rel_path: rel_path.to_string(),
                blob: *blob,
                language: *language,
                subjects: subjects.to_string(),
            },
            UnitPartition::Root {
                language,
                rel_path,
                blob,
                locator,
                compilation,
            } => PolicyUnitPartitionRow::Root {
                rel_path: rel_path.to_string(),
                blob: *blob,
                language: *language,
                locator: locator.to_string(),
                compilation: compilation.to_string(),
            },
            UnitPartition::Selector {
                language,
                rel_path,
                blob,
                selector,
            } => PolicyUnitPartitionRow::Selector {
                rel_path: rel_path.to_string(),
                blob: *blob,
                language: *language,
                selector: selector.to_string(),
            },
            UnitPartition::Prefix {
                language,
                rel_path,
                blob,
                cut,
                input,
            } => PolicyUnitPartitionRow::Prefix {
                language: *language,
                rel_path: rel_path.to_string(),
                blob: *blob,
                cut: cut.to_string(),
                input: input.to_string(),
            },
            UnitPartition::Output {
                language,
                rel_path,
                blob,
                anchor,
                compilation,
            } => PolicyUnitPartitionRow::Output {
                language: *language,
                rel_path: rel_path.to_string(),
                blob: *blob,
                anchor: anchor.to_string(),
                compilation: compilation.to_string(),
            },
            UnitPartition::Whole => PolicyUnitPartitionRow::Whole,
            UnitPartition::Operand { question } => PolicyUnitPartitionRow::Operand {
                question: question.to_string(),
            },
        },
        configuration_fingerprint: key.configuration.to_string(),
        active_model_set_hash: key.models.to_string(),
        engine_epoch: key.epoch.to_string(),
    }
}

/// One unit as the row the store writes.
fn unit_row(unit: &PolicyUnit) -> Result<PolicyUnitRow, PolicyUnitStoreError> {
    assert_eq!(
        unit.budget_mode,
        BudgetMode::Exhaustive,
        "only an exhaustive unit is publishable, and the schema says so too"
    );
    let product = match &unit.product {
        PolicyUnitProduct::Rows(rows) => serde_json::to_string(rows),
        PolicyUnitProduct::AssertFile(product) => serde_json::to_string(product),
        PolicyUnitProduct::Root(product) => serde_json::to_string(product),
        PolicyUnitProduct::Selector(product) => serde_json::to_string(product),
        PolicyUnitProduct::Prefix(product) => Ok(product.clone()),
        PolicyUnitProduct::Output(product) => Ok(product.clone()),
    }
    .map_err(|error| {
        PolicyUnitStoreError::new(format!("a unit product could not be serialized: {error}"))
    })?;
    Ok(PolicyUnitRow {
        seed_parse_variant: unit.seed_parse_variant,
        key: row_key(&unit.key),
        product_kind: unit.product.stable_label().to_string(),
        product,
        read_set_digest: *unit.read_digest.digest().as_bytes(),
        reads: unit.reads.clone(),
        snapshots: unit
            .snapshots
            .iter()
            .map(|snapshot| *snapshot.as_bytes())
            .collect(),
    })
}

/// The product one stored row carries.
///
/// Reusing a unit against a workspace also needs its read set, which is what
/// [`unit_of_row`] adds around this. `budget` is the reading run's, because an
/// assert unit's product carries findings and a finding's caps are stated in a
/// budget: a product stored under a wider budget than this run allows is a load
/// error rather than a finding this run would never have retained.
/// Only the legacy diagnostic format is an upgrade miss. Other malformed
/// products retain the store's ProductLoadFailed/full-widening behavior.
/// Stream through ignored fields instead of allocating a second product tree.
fn missing_legacy_diagnostic_cause(row: &PolicyUnitRow) -> bool {
    if !matches!(row.product_kind.as_str(), "rows" | "assert_file") {
        return false;
    }
    #[derive(serde::Deserialize)]
    struct ProductProbe {
        #[serde(default, deserialize_with = "missing_cause")]
        diagnostics: bool,
    }
    #[derive(serde::Deserialize)]
    struct DiagnosticProbe {
        #[serde(default, deserialize_with = "present")]
        incompleteness: bool,
    }
    fn present<'de, D: Deserializer<'de>>(deserializer: D) -> Result<bool, D::Error> {
        <brokk_bifrost_rql::Incompleteness as serde::Deserialize>::deserialize(deserializer)
            .map(|_| true)
    }
    fn missing_cause<'de, D: Deserializer<'de>>(deserializer: D) -> Result<bool, D::Error> {
        struct Probe;
        impl<'de> Visitor<'de> for Probe {
            type Value = bool;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a diagnostic array")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<bool, A::Error> {
                let mut missing = false;
                while let Some(diagnostic) = sequence.next_element::<DiagnosticProbe>()? {
                    missing |= !diagnostic.incompleteness;
                }
                Ok(missing)
            }
        }
        deserializer.deserialize_seq(Probe)
    }
    serde_json::from_str::<ProductProbe>(&row.product).is_ok_and(|probe| probe.diagnostics)
}

fn product_of_row(
    row: &PolicyUnitRow,
    budget: &PolicyBudget,
) -> Result<PolicyUnitProduct, PolicyUnitStoreError> {
    let product = match row.product_kind.as_str() {
        "rows" => serde_json::from_str(&row.product).map(PolicyUnitProduct::Rows),
        "assert_file" => {
            let mut deserializer = serde_json::Deserializer::from_str(&row.product);
            AssertFileProductSeed::new(budget)
                .deserialize(&mut deserializer)
                .map(PolicyUnitProduct::AssertFile)
        }
        "root" => {
            let mut deserializer = serde_json::Deserializer::from_str(&row.product);
            RootProductSeed::new(budget)
                .deserialize(&mut deserializer)
                .map(PolicyUnitProduct::Root)
        }
        "selector" => serde_json::from_str(&row.product).map(PolicyUnitProduct::Selector),
        "prefix" => return Ok(PolicyUnitProduct::Prefix(row.product.clone())),
        "output" => return Ok(PolicyUnitProduct::Output(row.product.clone())),
        other => {
            return Err(PolicyUnitStoreError::new(format!(
                "a published unit carries an unknown product kind `{other}`"
            )));
        }
    };
    product.map_err(|error| {
        PolicyUnitStoreError::new(format!(
            "a published unit product could not be read: {error}"
        ))
    })
}

/// One stored row as the unit an evaluation may reuse.
///
/// Every failure here is a load error rather than a malformed unit: a product
/// that will not parse, a read set whose digest does not match the reads that
/// came back with it. The caller widens and says so; nothing partially loaded
/// ever reaches a merge.
pub fn unit_of_row(
    key: PolicyUnitKey,
    row: PolicyUnitRow,
    budget: &PolicyBudget,
    row_node_count: Option<usize>,
) -> Result<PolicyUnit, PolicyUnitStoreError> {
    let product = product_of_row(&row, budget)?;
    unit_of_row_with_product(key, row, product, row_node_count)
}

fn unit_of_row_with_product(
    key: PolicyUnitKey,
    row: PolicyUnitRow,
    product: PolicyUnitProduct,
    row_node_count: Option<usize>,
) -> Result<PolicyUnit, PolicyUnitStoreError> {
    if let PolicyUnitProduct::Rows(rows) = &product
        && let Some(counts) = &rows.budgeted_work.step_outputs
        && !counts.is_empty()
        && Some(counts.len()) != row_node_count
    {
        return Err(PolicyUnitStoreError::new(
            "a published unit's step output counters do not match its physical plan".to_string(),
        ));
    }

    let unit = PolicyUnit::new(
        key,
        None,
        product,
        row.reads,
        BudgetMode::Exhaustive,
        row.snapshots
            .into_iter()
            .map(StableDigest::from_array)
            .collect(),
    );
    if unit.read_digest.digest().as_bytes() != &row.read_set_digest {
        return Err(PolicyUnitStoreError::new(
            "a published unit's read set does not digest to the identity it was published under"
                .to_string(),
        ));
    }
    Ok(unit)
}

/// The three non-source inputs every unit key and every verification carries.
///
/// Read once per evaluated workspace, because all three are properties of the
/// engine, the analyzer and the run's model activation rather than of any one
/// policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkspaceUnitInputs {
    model_read_digest: StableDigest,
    configuration: StableDigest,
    models: StableDigest,
    epoch: StableDigest,
}

impl WorkspaceUnitInputs {
    #[cfg(test)]
    pub(crate) fn with_lowering_identity(mut self, lowering: StableDigest) -> Self {
        self.epoch = policy_substrate_epoch(lowering);
        self
    }
    #[cfg(test)]
    pub(crate) fn with_previous_epoch(
        mut self,
        workspace: &WorkspaceAnalyzer,
        models: Option<&ActiveSemanticModelSnapshot>,
    ) -> Self {
        self.epoch = substrate_epoch_before_last_token(workspace.policy_lowering_identity(models));
        self
    }

    /// The inputs `workspace` evaluates under, with `models` as the activation
    /// the run pinned.
    ///
    /// The configuration fingerprint is the one the analyzer folds into every
    /// content identity, spelled the same way (#2529): the `Debug` rendering
    /// of the configuration, with a workspace that carries none behaving as
    /// the defaults describe.
    ///
    /// `typos` is the run's identifier typo table. It is pack data activated
    /// for the run, like the models, so its digest joins the `models` digest
    /// and a different table re-runs every unit (#10386). A table changes only
    /// with a rules pack release, which changes other pack content too.
    pub fn of(
        workspace: &WorkspaceAnalyzer,
        models: Option<&ActiveSemanticModelSnapshot>,
        typos: Option<&IdentifierTypoTable>,
    ) -> Self {
        let configuration = workspace.config().cloned().unwrap_or_default();
        let model_set = models.map_or_else(
            || StableDigest::sha256(NO_ACTIVE_MODELS),
            |models| StableDigest::sha256(models.active_models().active_model_set_hash()),
        );
        Self {
            model_read_digest:
                brokk_bifrost_analysis::analyzer::i_analyzer::current_model_set_digest(
                    models.map(|models| models.active_models().active_model_set_hash()),
                ),
            configuration: StableDigest::sha256(format!("{configuration:?}")),
            models: match typos {
                None => model_set,
                Some(typos) => {
                    let mut bytes = model_set.as_bytes().to_vec();
                    bytes.extend_from_slice(b"\x01identifier-typos\x01");
                    bytes.extend_from_slice(&typos.content_digest());
                    StableDigest::sha256(bytes)
                }
            },
            epoch: policy_substrate_epoch(workspace.policy_lowering_identity(models)),
        }
    }

    pub const fn configuration(&self) -> StableDigest {
        self.configuration
    }

    pub const fn models(&self) -> StableDigest {
        self.models
    }

    pub const fn epoch(&self) -> StableDigest {
        self.epoch
    }

    /// The unit key one policy's `partition` is published under.
    pub fn unit_key(&self, policy: &LoadedPolicy, partition: UnitPartition) -> PolicyUnitKey {
        PolicyUnitKey {
            policy: policy.semantic_hash(),
            family: policy.definition().analysis.analysis_type(),
            partition,
            configuration: self.configuration,
            models: self.models,
            epoch: self.epoch,
        }
    }

    /// What verification compares one policy's recorded reads against.
    pub fn head_inputs(&self, policy: &LoadedPolicy) -> HeadInputs {
        HeadInputs {
            models: self.model_read_digest,
            policy_semantic_hash: StableDigest::from_array(*policy.semantic_hash().as_bytes()),
            policy_source: StableDigest::from_array(*policy.source_hash().as_bytes()),
            configuration: self.configuration,
            epoch: self.epoch,
        }
    }
}

/// The content identity of one analyzed workspace snapshot, as a unit records
/// the workspace that computed it.
///
/// The whole-workspace content identity folds every analyzed path with the
/// blob it resolves to, every overlay, the per-language analysis epochs and
/// the analyzer configuration, and carries no absolute path. Two snapshots
/// with one identity therefore publish the same facts to every name index,
/// which is the property a unit's index reads depend on. `None` when the
/// analyzer states no identity, and such a workspace cannot publish or reuse a
/// unit at all.
pub fn workspace_snapshot(workspace: &WorkspaceAnalyzer) -> Option<StableDigest> {
    workspace
        .analyzer()
        .workspace_content_identities()?
        .whole_workspace()
        .map(|identity| StableDigest::from_array(*identity.as_bytes()))
}

/// The two snapshots a comparison is between.
///
/// A unit computed on either one can be verified here: one computed on `base`
/// against what moved between the base and the head, and one computed on
/// `head` against the head itself. A unit computed on any other snapshot has
/// read index answers this comparison says nothing about, and is recomputed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnitSnapshots {
    /// The workspace the head is compared against.
    pub base: StableDigest,
    /// The workspace this evaluation runs on. Every unit it publishes carries
    /// this identity.
    pub head: StableDigest,
}

impl UnitSnapshots {
    /// A comparison of one snapshot with itself: a full scan, or the base
    /// half of a diff run. It verifies units computed on that snapshot.
    pub const fn of(snapshot: StableDigest) -> Self {
        Self {
            base: snapshot,
            head: snapshot,
        }
    }
}

/// The units one policy's attempt recomputed, provisional until the attempt
/// ends.
///
/// A sliced attempt can widen after recomputing one or more units; those
/// products must not become visible to later runs. The attempt owns this
/// value, and it leaves only by value: `commit_units` publishes all of it with
/// the policy's unit list, `commit_publishable_units` publishes it without
/// one, and dropping it discards it. A widened or failed attempt therefore
/// cannot leak a provisional product into a later attempt.
#[derive(Debug, Default)]
pub(crate) struct StagedUnits {
    units: HashMap<PolicyUnitKey, PolicyUnit>,
}

#[derive(Default)]
struct PendingPolicyPublications {
    units: Vec<PolicyUnit>,
    lists: Vec<(PolicyId, Vec<PolicyUnitKey>)>,
}

impl StagedUnits {
    pub(crate) fn stage(&mut self, unit: PolicyUnit) {
        assert!(
            self.units.insert(unit.key.clone(), unit).is_none(),
            "one policy attempt cannot recompute the same unit key twice"
        );
    }

    pub(crate) fn get(&self, key: &PolicyUnitKey) -> Option<&PolicyUnit> {
        self.units.get(key)
    }
}

/// Everything one evaluation needs to reuse units instead of recomputing them.
///
/// Its presence is the whole condition: an evaluation that holds one has a
/// store to look units up in and a workspace to verify them against, and one
/// that does not executes exactly as it always has. There is no mode to set.
///
/// A full scan and the base half of a `--diff-base` run hold one too. Their
/// changed facts are the workspace against itself, which states that nothing
/// moved, so a unit computed on this same snapshot -- by an earlier scan of
/// this tree, or an earlier evaluation of this base -- has its name-index
/// reads proved by that empty set and every other read checked against the
/// workspace itself. A unit without name-index reads is verified wherever it
/// came from, and one with them from another snapshot is recomputed.
pub struct PolicyIncrementalContext<'a> {
    store: &'a Mutex<dyn PolicyUnitStore>,
    workspace: &'a WorkspaceAnalyzer,
    changed: &'a ChangedFacts,
    /// What moved between the head and itself, built from `changed` the first
    /// time a unit computed on the head asks. Unused when the two snapshots
    /// are one, because `changed` already says exactly that.
    head_unchanged: OnceLock<ChangedFacts>,
    snapshots: UnitSnapshots,
    inputs: WorkspaceUnitInputs,
    base: IncrementalBaseState,
    verdicts: ArtifactVerdictLog,
    runs: Mutex<Vec<PolicyIncrementalRun>>,
    unit_metrics: Mutex<HashMap<PolicyId, UnitPhaseMetrics>>,
    composition_searches: Mutex<HashMap<PolicyId, CompositionSearchMetrics>>,
    discarded_source_inventories:
        Mutex<HashMap<PolicyId, crate::finding::DiscardedSourceInventory>>,
    units: Mutex<Vec<(PolicyId, Vec<PolicyUnitKey>)>>,
    /// Workspace-total base widening can predict that slicing the head will
    /// widen too, so those policies can use their reference whole execution.
    base_workspace_widens: HashMap<PolicyId, WidenReason>,
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct UnitPhaseMetrics {
    pub(crate) prefetch: Duration,
    pub(crate) verify: Duration,
    pub(crate) lookup_replay: Duration,
    pub(crate) recompute: Duration,
    pub(crate) lookups_replayed: u64,
}

/// Observations of composition searches; never used for evaluation.
///
/// A search that ended in an error, or whose provider recorded a failure,
/// counts in `searches_errored` (and `zero_compiled_errored`) and in none of
/// the finding or incompleteness counts: an errored search is not a complete
/// empty search.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct CompositionSearchMetrics {
    pub searches_total: u64,
    pub searches_errored: u64,
    pub zero_compiled_sources: u64,
    pub zero_compiled_errored: u64,
    pub zero_compiled_with_frontier_sources: u64,
    pub zero_compiled_with_findings: u64,
    pub zero_compiled_incomplete: u64,
    pub frontier_bound_sources: u64,
}

impl CompositionSearchMetrics {
    fn is_empty(&self) -> bool {
        self.searches_total == 0
    }
}

impl<'a> PolicyIncrementalContext<'a> {
    pub fn new(
        store: &'a Mutex<dyn PolicyUnitStore>,
        workspace: &'a WorkspaceAnalyzer,
        changed: &'a ChangedFacts,
        inputs: WorkspaceUnitInputs,
        base: IncrementalBaseState,
        snapshots: UnitSnapshots,
    ) -> Self {
        debug_assert_eq!(
            workspace_snapshot(workspace),
            Some(snapshots.head),
            "a context publishes under the identity of the workspace it evaluates"
        );
        Self {
            store,
            workspace,
            changed,
            head_unchanged: OnceLock::new(),
            snapshots,
            inputs,
            base,
            verdicts: ArtifactVerdictLog::default(),
            runs: Mutex::new(Vec::new()),
            unit_metrics: Mutex::new(HashMap::new()),
            composition_searches: Mutex::new(HashMap::new()),
            discarded_source_inventories: Mutex::new(HashMap::new()),
            units: Mutex::new(Vec::new()),
            base_workspace_widens: HashMap::new(),
        }
    }

    /// Carry only workspace-total widening from a base evaluated in this run.
    /// These two reasons depend on workspace totals, which base and head share
    /// up to the change; plan-only reasons fire before enumeration, while
    /// unit-content reasons can differ between base and head.
    ///
    /// This is a prediction, not an observation: a head that would have
    /// sliced (the change took it under the cap) is evaluated whole anyway.
    /// Whole evaluation is the reference answer, so a wrong prediction loses
    /// reuse, never correctness.
    pub fn with_base_review(mut self, review: Option<&PolicyIncrementalReview>) -> Self {
        if let Some(review) = review.filter(|review| review.base == IncrementalBaseState::Evaluated)
        {
            self.base_workspace_widens = review
                .policies
                .iter()
                .filter_map(|run| match run.widen_reason {
                    Some(
                        reason @ (WidenReason::MergedLimitReached
                        | WidenReason::VerificationBudgetExceeded),
                    ) => Some((run.policy_id.clone(), reason)),
                    _ => None,
                })
                .collect();
        }
        self
    }

    pub fn base_workspace_widen(&self, policy_id: &PolicyId) -> Option<WidenReason> {
        self.base_workspace_widens.get(policy_id).copied()
    }

    /// The content identity of the workspace this context evaluates.
    pub const fn snapshot(&self) -> StableDigest {
        self.snapshots.head
    }

    /// The snapshots whose name-index answers a unit with `reads` holds, once
    /// this context computed it or verified it.
    ///
    /// The head always: it computed the unit, or verification proved the
    /// unit's answers equal the head's. The base too when none of its index
    /// probes names a name that moved between the base and the head, because
    /// then the head answered every one of them exactly as the base would:
    /// that is what the changed-name set states. Holding both is what serves
    /// both common flows. Several heads checked against one base verify the
    /// unit against their own difference from that base, and a chain of checks,
    /// each based on the previous head, verifies it against the difference
    /// from that head. A unit that probed a moved name holds only on this
    /// head. An incomplete changed-name set proves nothing about the base.
    pub fn publication_snapshots(&self, reads: &[ReadKey]) -> Vec<StableDigest> {
        let base_answers = self.snapshots.base != self.snapshots.head
            && self.changed.is_complete()
            && reads.iter().all(|read| match read {
                ReadKey::Index { family, key } => !self.changed.contains(*family, key),
                _ => true,
            });
        if base_answers {
            vec![self.snapshots.head, self.snapshots.base]
        } else {
            vec![self.snapshots.head]
        }
    }

    /// One snapshot of `unit_snapshots` this comparison is between, with what
    /// moved between it and this context's head, or `None` when the unit holds
    /// on neither.
    ///
    /// Only a name-index read depends on the answer: every other read is
    /// checked against the head itself. A name-index read is proved by the
    /// names that moved since a snapshot it holds on, so a unit that holds on
    /// the head is checked against nothing, one that holds on the base against
    /// what moved between the base and the head, and a unit from anywhere else
    /// cannot be checked at all. The head is preferred because it proves every
    /// index read without looking at any name.
    pub fn changed_since(
        &self,
        unit_snapshots: &[StableDigest],
    ) -> Option<(StableDigest, &ChangedFacts)> {
        if unit_snapshots.contains(&self.snapshots.head) {
            let changed = if self.snapshots.base == self.snapshots.head {
                self.changed
            } else {
                self.head_unchanged.get_or_init(|| self.changed.head_only())
            };
            Some((self.snapshots.head, changed))
        } else if unit_snapshots.contains(&self.snapshots.base) {
            Some((self.snapshots.base, self.changed))
        } else {
            None
        }
    }

    pub const fn store(&self) -> &'a Mutex<dyn PolicyUnitStore> {
        self.store
    }

    pub const fn workspace(&self) -> &'a WorkspaceAnalyzer {
        self.workspace
    }

    pub const fn changed(&self) -> &'a ChangedFacts {
        self.changed
    }

    pub const fn inputs(&self) -> WorkspaceUnitInputs {
        self.inputs
    }

    /// The reuse decisions this evaluation reached, in the typed vocabulary
    /// #2449 established.
    pub const fn verdicts(&self) -> &ArtifactVerdictLog {
        &self.verdicts
    }

    /// Record what one policy's evaluation did with its units.
    pub fn record_run(&self, run: PolicyIncrementalRun) {
        self.runs
            .lock()
            .expect("policy incremental runs mutex poisoned")
            .push(run);
    }

    pub(crate) fn record_composition_search(
        &self,
        policy_id: &PolicyId,
        compiled_sources: usize,
        frontier_sources: usize,
        findings: bool,
        incomplete: bool,
        errored: bool,
    ) {
        let mut searches = self
            .composition_searches
            .lock()
            .expect("composition search metrics mutex poisoned");
        let metrics = searches.entry(policy_id.clone()).or_default();
        metrics.searches_total += 1;
        metrics.searches_errored += u64::from(errored);
        metrics.frontier_bound_sources += frontier_sources as u64;
        if compiled_sources == 0 {
            metrics.zero_compiled_sources += 1;
            metrics.zero_compiled_errored += u64::from(errored);
            metrics.zero_compiled_with_frontier_sources += u64::from(frontier_sources != 0);
            metrics.zero_compiled_with_findings += u64::from(findings);
            metrics.zero_compiled_incomplete += u64::from(incomplete);
        }
    }

    pub(crate) fn record_discarded_source_inventory(
        &self,
        policy_id: &PolicyId,
        inventory: crate::finding::DiscardedSourceInventory,
    ) {
        self.discarded_source_inventories
            .lock()
            .expect("discarded inventory mutex poisoned")
            .insert(policy_id.clone(), inventory);
    }

    pub(crate) fn note_discarded_source_frontier(
        &self,
        policy_id: &PolicyId,
        selector: &str,
        file: &str,
        gaps: &[String],
    ) {
        let mut inventories = self
            .discarded_source_inventories
            .lock()
            .expect("discarded inventory mutex poisoned");
        if let Some(inventory) = inventories.get_mut(policy_id) {
            for entry in &mut inventory.lost_attributed {
                if entry.selector == selector && entry.attributed_file.as_deref() == Some(file) {
                    entry.frontier_entered_file = true;
                    entry.file_slice_reported_again |= gaps.contains(&entry.message);
                    brokk_bifrost_analysis::profiling::note_with(|| {
                        format!("taint.inventory.frontier_observation={entry:?}")
                    });
                }
            }
        }
    }

    pub(crate) fn has_run(&self, policy_id: &PolicyId) -> bool {
        self.runs
            .lock()
            .expect("policy incremental runs mutex poisoned")
            .iter()
            .any(|run| &run.policy_id == policy_id)
    }

    /// Add one sliced attempt's phase times and replay count to its policy.
    ///
    /// A policy can run more than one attempt (typestate keeps selector and
    /// root units apart), so the record is a sum.
    pub(crate) fn add_unit_metrics(&self, policy_id: &PolicyId, attempt: UnitPhaseMetrics) {
        let mut metrics = self
            .unit_metrics
            .lock()
            .expect("policy unit metrics mutex poisoned");
        let metrics = metrics.entry(policy_id.clone()).or_default();
        metrics.prefetch += attempt.prefetch;
        metrics.verify += attempt.verify;
        metrics.lookup_replay += attempt.lookup_replay;
        metrics.recompute += attempt.recompute;
        metrics.lookups_replayed += attempt.lookups_replayed;
    }

    pub(crate) fn unit_phase_metrics(&self, policy_id: &PolicyId) -> Option<UnitPhaseMetrics> {
        self.unit_metrics
            .lock()
            .expect("policy unit metrics mutex poisoned")
            .get(policy_id)
            .copied()
    }

    /// Publish every unit one policy's attempt staged, and record the unit
    /// list its product was merged from.
    ///
    /// Recorded only when every one of them is published, because a persisted
    /// evaluation names these as the work behind its findings and a partial
    /// list would name work that no policy did.
    pub(crate) fn commit_units(
        &self,
        policy_id: PolicyId,
        mut staged: StagedUnits,
        keys: Vec<PolicyUnitKey>,
    ) {
        let mut seen = HashSet::with_capacity(keys.len());
        let mut committed = Vec::with_capacity(staged.units.len());
        for key in &keys {
            assert!(
                seen.insert(key),
                "a complete unit-key set cannot contain duplicate keys"
            );
            if let Some(unit) = staged.units.remove(key) {
                committed.push(unit);
            }
        }
        assert!(
            staged.units.is_empty(),
            "every recomputed unit must be included in the complete unit-key set"
        );
        if let Some(owner) =
            brokk_bifrost_analysis::analyzer::i_analyzer::PolicyCompletionOwner::current()
        {
            owner.with_pending::<PendingPolicyPublications, _>(|pending| {
                pending.units.extend(committed);
                pending.lists.push((policy_id, keys));
            });
        } else {
            self.publish_completed_units(committed, vec![(policy_id, keys)]);
        }
    }

    pub(crate) fn commit_publishable_units(
        &self,
        mut staged: StagedUnits,
        seed_order: &[PolicyUnitKey],
    ) {
        let mut committed = Vec::new();
        for key in seed_order {
            if let Some(unit) = staged.units.remove(key) {
                committed.push(unit);
            }
        }
        assert!(
            staged.units.is_empty(),
            "every staged unit belongs to the attempt's seed order"
        );
        if let Some(owner) =
            brokk_bifrost_analysis::analyzer::i_analyzer::PolicyCompletionOwner::current()
        {
            owner.with_pending::<PendingPolicyPublications, _>(|pending| {
                pending.units.extend(committed)
            });
        } else {
            self.publish_completed_units(committed, Vec::new());
        }
    }

    pub(crate) fn complete_policy_publications(
        &self,
        owner: &brokk_bifrost_analysis::analyzer::i_analyzer::PolicyCompletionOwner,
    ) {
        let pending = owner.with_pending::<PendingPolicyPublications, _>(std::mem::take);
        if owner.errors().is_empty() {
            self.publish_completed_units(pending.units, pending.lists);
        }
    }

    fn publish_completed_units(
        &self,
        units: Vec<PolicyUnit>,
        lists: Vec<(PolicyId, Vec<PolicyUnitKey>)>,
    ) {
        let mut store = self.store.lock().expect("policy-unit store mutex poisoned");
        for unit in units {
            store.publish(unit);
        }
        self.units
            .lock()
            .expect("policy incremental units mutex poisoned")
            .extend(lists);
    }

    /// The units each policy's product was merged from, in policy order.
    pub fn published_units(&self) -> Vec<(PolicyId, Vec<PolicyUnitKey>)> {
        self.units
            .lock()
            .expect("policy incremental units mutex poisoned")
            .clone()
    }

    /// The review of everything this evaluation reused, in policy order.
    pub fn review(&self) -> PolicyIncrementalReview {
        // The replay count is joined here rather than when a run is recorded:
        // a sliced attempt reports its metrics when its reuse state drops,
        // which can be after the policy recorded its run.
        let metrics = self
            .unit_metrics
            .lock()
            .expect("policy unit metrics mutex poisoned");
        let searches = self
            .composition_searches
            .lock()
            .expect("composition search metrics mutex poisoned");
        let inventories = self
            .discarded_source_inventories
            .lock()
            .expect("discarded inventory mutex poisoned");
        let policies = self
            .runs
            .lock()
            .expect("policy incremental runs mutex poisoned")
            .iter()
            .map(|run| PolicyIncrementalRun {
                lookups_replayed: metrics
                    .get(&run.policy_id)
                    .map_or(0, |metrics| metrics.lookups_replayed),
                composition_searches: searches.get(&run.policy_id).copied().unwrap_or_default(),
                discarded_source_inventory: inventories.get(&run.policy_id).cloned().map(Box::new),
                ..run.clone()
            })
            .collect();
        PolicyIncrementalReview {
            base: self.base,
            policies,
        }
    }
}

/// How this run obtained the base revision's findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IncrementalBaseState {
    /// The base revision was exported, built and evaluated by this run.
    Evaluated,
    /// An earlier run had already evaluated this exact base, so the identities
    /// it concluded were read from the store and the base was neither
    /// exported, built nor evaluated.
    Reused,
}

impl IncrementalBaseState {
    pub const fn stable_label(self) -> &'static str {
        match self {
            Self::Evaluated => "evaluated",
            Self::Reused => "reused",
        }
    }
}

/// Whether one policy was evaluated unit by unit or in full.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IncrementalMode {
    Sliced,
    Full,
}

impl IncrementalMode {
    pub const fn stable_label(self) -> &'static str {
        match self {
            Self::Sliced => "sliced",
            Self::Full => "full",
        }
    }
}

/// Why one policy was evaluated in full instead of unit by unit.
///
/// Widening is always reported. A run that could not bound a unit exactly, or
/// could not merge its units into the bytes a whole evaluation would have
/// produced, evaluates the whole policy and says which of these was true --
/// never silently omits anything, and never claims a reuse it cannot prove.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WidenReason {
    /// The family has no per-partition product at all (taint and flow today,
    /// and every family this milestone has not sliced yet).
    WholePolicyFamily,
    /// The plan's rows are not the concatenation of its per-seed rows.
    PlanCrossesSeeds,
    /// The plan needs workspace-wide preparation that is not safely shared
    /// across independent seed units. Evaluate it once before attempting units.
    WorkspacePreparationRequired,
    /// A unit performed reads the ledger could not name.
    UnitUnbounded,
    /// A unit's own execution was truncated or ran under a bounded budget.
    UnitNotExhaustive,
    /// A unit reported a query diagnostic, which is not additive across
    /// partitions.
    UnitDiagnostics,
    /// The merged product reached a cap the whole execution enforces globally,
    /// so the whole execution might have truncated somewhere in its own order.
    MergedLimitReached,
    /// Verifying the recorded reads would have cost more than the evaluation
    /// it is trying to avoid.
    VerificationBudgetExceeded,
    /// The evidence a verification needs does not exist: an incomplete
    /// changed-fact set, a lookup the head cannot answer, or a base
    /// evaluation the run refused to trust and therefore compared nothing
    /// against.
    ReverseDependencyEvidenceMissing,
    /// A published product could not be loaded.
    ProductLoadFailed,
    /// Reuse was turned off for this run (`--no-incremental`, or
    /// `PolicyEvaluationOptions::with_incremental(false)`). Nothing was
    /// looked up and nothing was published; the policy was evaluated exactly
    /// as a run with no units evaluates it.
    IncrementalDisabled,
}

impl WidenReason {
    pub const fn stable_label(self) -> &'static str {
        match self {
            Self::WholePolicyFamily => "whole_policy_family",
            Self::PlanCrossesSeeds => "plan_crosses_seeds",
            Self::WorkspacePreparationRequired => "workspace_preparation_required",
            Self::UnitUnbounded => "unit_unbounded",
            Self::UnitNotExhaustive => "unit_not_exhaustive",
            Self::UnitDiagnostics => "unit_diagnostics",
            Self::MergedLimitReached => "merged_limit_reached",
            Self::VerificationBudgetExceeded => "verification_budget_exceeded",
            Self::ReverseDependencyEvidenceMissing => "reverse_dependency_evidence_missing",
            Self::ProductLoadFailed => "product_load_failed",
            Self::IncrementalDisabled => "incremental_disabled",
        }
    }
}

/// Why one recomputed Output unit was not published, counted per unit in
/// `PolicyIncrementalRun::output_refusals`. Observational: these labels do
/// not change publication, keys or diagnostics. One unit can have several
/// causes, so the counts overlap and do not sum to the number of refused
/// units.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputRefusalCause {
    DiagnosticsOpen,
    NotCompleteOrAuthoredProven,
    AttributionRunExhausted,
    OmittedFindings,
    OmittedBarriers,
    UndecidedBarrierChecks,
    IncompleteOrTruncatedFinding,
    IncompleteOrTruncatedWitness,
    PublishableFalse,
    /// `OutputUnitSlice::execution_dependent` was true, so the unit's receipt
    /// was not kept. For Output units that predicate is "report evidence is
    /// incomplete or diagnostics are open", the same test as not publishable;
    /// it does not by itself show that the result depended on budget,
    /// cancellation or other execution state.
    ExecutionDependentReceipt,
    UnusableReceipt,
    InnerEvaluationError,
    ProjectionFailure,
}

/// What one policy's evaluation did with its units.
///
/// The counts describe the sliced attempt even when it widened, because "this
/// policy enumerated forty units and recomputed one before the merge reached a
/// cap" is the diagnosis a reader needs, and a widened policy that reported
/// zeros would hide it.
///
/// The `base_` fields say the same of the base revision's evaluation of this
/// policy in the same run. They are zero when the run evaluated no base -- it
/// served the base from a stored evaluation, or reuse was off -- and a base
/// that reused every unit an earlier scan of that revision published reports
/// them all as reused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyIncrementalRun {
    pub policy_id: PolicyId,
    pub mode: IncrementalMode,
    pub units_total: u64,
    pub units_reused: u64,
    pub units_recomputed: u64,
    pub units_unbounded: u64,
    pub lookups_replayed: u64,
    #[serde(skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub output_refusals: std::collections::BTreeMap<OutputRefusalCause, u64>,
    #[serde(skip_serializing_if = "CompositionSearchMetrics::is_empty")]
    pub composition_searches: CompositionSearchMetrics,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discarded_source_inventory: Option<Box<crate::finding::DiscardedSourceInventory>>,
    /// Why the policy was evaluated whole. With `units_total` zero and a
    /// workspace-total reason (`merged_limit_reached`,
    /// `verification_budget_exceeded`), the head did not attempt units: the
    /// reason was predicted from this run's base evaluation rather than
    /// observed on the head.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub widen_reason: Option<WidenReason>,
    /// The plan eligibility or merged-limit detail of query-unit widening. Taint selector
    /// fallback details are not currently copied here; only their widening
    /// reason is retained in range diagnostics.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub widen_detail: Option<PlanWidenDetail>,
    pub base_units_reused: u64,
    pub base_units_recomputed: u64,
    pub base_lookups_replayed: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_widen_reason: Option<WidenReason>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_widen_detail: Option<PlanWidenDetail>,
}

impl PolicyIncrementalRun {
    /// One policy whose family has no per-partition product.
    ///
    /// Taint and flow are whole by design: their solve is one batch over
    /// every region at once, and no partition of it has a product. They are
    /// evaluated exactly as a run with no units evaluates them, and say so.
    pub const fn whole_family(policy_id: PolicyId) -> Self {
        Self::evaluated_in_full(policy_id, WidenReason::WholePolicyFamily)
    }

    /// One policy evaluated whole, for `reason`.
    ///
    /// The counts are zero because nothing was enumerated: a policy that
    /// never attempted a sliced evaluation has no units to report, which is a
    /// different statement from a sliced attempt that widened and reports what
    /// it had enumerated when it did.
    pub const fn evaluated_in_full(policy_id: PolicyId, reason: WidenReason) -> Self {
        Self {
            policy_id,
            mode: IncrementalMode::Full,
            units_total: 0,
            units_reused: 0,
            units_recomputed: 0,
            units_unbounded: 0,
            lookups_replayed: 0,
            output_refusals: std::collections::BTreeMap::new(),
            composition_searches: CompositionSearchMetrics {
                searches_total: 0,
                searches_errored: 0,
                zero_compiled_sources: 0,
                zero_compiled_errored: 0,
                zero_compiled_with_frontier_sources: 0,
                zero_compiled_with_findings: 0,
                zero_compiled_incomplete: 0,
                frontier_bound_sources: 0,
            },
            discarded_source_inventory: None,
            widen_reason: Some(reason),
            widen_detail: None,
            base_units_reused: 0,
            base_units_recomputed: 0,
            base_lookups_replayed: 0,
            base_widen_reason: None,
            base_widen_detail: None,
        }
    }

    /// Record what the base evaluation of the same policy did with its units.
    fn with_base(mut self, base: &Self) -> Self {
        assert_eq!(
            self.policy_id, base.policy_id,
            "a base run describes the same policy as the head run it annotates"
        );
        self.base_units_reused = base.units_reused;
        self.base_units_recomputed = base.units_recomputed;
        self.base_lookups_replayed = base.lookups_replayed;
        self.base_widen_reason = base.widen_reason;
        self.base_widen_detail = base.widen_detail;
        self
    }
}

/// What one batch reused, per policy.
///
/// Carried beside the report rather than inside it: Milestone 3 adds the
/// report section, its retained-size accounting and its renderer. Until then
/// this is the structural evidence a test reads to prove that a byte-identical
/// report was produced by doing less work.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyIncrementalReview {
    base: IncrementalBaseState,
    policies: Vec<PolicyIncrementalRun>,
}

/// The three review enums serialize as their stable labels, which are stated
/// once beside the variants rather than a second time in a serde attribute:
/// the label is the wire contract, and a rename that changed one and not the
/// other would ship two spellings of the same state.
impl Serialize for IncrementalBaseState {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serialize_stable_label(self.stable_label(), serializer)
    }
}

impl Serialize for IncrementalMode {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serialize_stable_label(self.stable_label(), serializer)
    }
}

impl Serialize for WidenReason {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serialize_stable_label(self.stable_label(), serializer)
    }
}

fn serialize_stable_label<S: serde::Serializer>(
    label: &str,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(label)
}

impl PolicyIncrementalReview {
    /// The review of a diff-base run that reused nothing, with `reason` said
    /// once per policy that ran.
    ///
    /// Every `--diff-base` run carries this section, whether or not it reused
    /// anything, because the section is charged to the report's retention
    /// budget: one present in a reusing run and absent in the forced-full run
    /// it must equal byte for byte would move the retention boundary between
    /// them. A run that reused nothing evaluated its base itself, which is
    /// what `Evaluated` says.
    pub fn evaluated_in_full(
        policy_ids: impl IntoIterator<Item = PolicyId>,
        reason: WidenReason,
    ) -> Self {
        Self {
            base: IncrementalBaseState::Evaluated,
            policies: policy_ids
                .into_iter()
                .map(|policy_id| PolicyIncrementalRun::evaluated_in_full(policy_id, reason))
                .collect(),
        }
    }

    pub const fn base(&self) -> IncrementalBaseState {
        self.base
    }

    /// This review with each policy annotated by what the base evaluation of
    /// that policy, in the same run, did with its units.
    ///
    /// A policy the base did not evaluate keeps zero base counts: there was
    /// no base work for it to describe.
    pub fn with_base_runs(self, base: &Self) -> Self {
        let policies = self
            .policies
            .into_iter()
            .map(|run| match base.policy(&run.policy_id) {
                Some(base_run) => run.with_base(base_run),
                None => run,
            })
            .collect();
        Self {
            base: self.base,
            policies,
        }
    }

    pub fn policies(&self) -> &[PolicyIncrementalRun] {
        &self.policies
    }

    /// How many units this batch reused instead of recomputing.
    pub fn reused_units(&self) -> u64 {
        self.policies
            .iter()
            .fold(0, |total, run| total.saturating_add(run.units_reused))
    }

    /// How many units this batch recomputed.
    pub fn recomputed_units(&self) -> u64 {
        self.policies
            .iter()
            .fold(0, |total, run| total.saturating_add(run.units_recomputed))
    }

    /// One policy's run, by identifier.
    pub fn policy(&self, policy_id: &PolicyId) -> Option<&PolicyIncrementalRun> {
        self.policies.iter().find(|run| &run.policy_id == policy_id)
    }
}

/// Exercise the production capture/publication boundary with a supplied read.
#[cfg(feature = "test-support")]
#[doc(hidden)]
pub fn capture_and_store_policy_unit_for_test<T>(
    store: Arc<AnalyzerStore>,
    analyzer: &dyn brokk_bifrost_analysis::analyzer::IAnalyzer,
    label: &str,
    read: impl FnOnce() -> T,
) -> (T, usize) {
    let (answer, reads, _, _) = crate::unit_execution::recompute_unit_judged(
        analyzer,
        None,
        || label.to_owned(),
        || {
            (
                read(),
                brokk_bifrost_core::analyzer::reuse_verdict::ReuseVerdict::Content,
            )
        },
    );
    let mut storage = PersistedPolicyUnitStore::new(store);
    if let Some(reads) = reads {
        let digest = StableDigest::sha256(label);
        let key = PolicyUnitKey {
            policy: PolicySemanticHash::from_lower_hex(&digest.to_string())
                .expect("digest is canonical"),
            family: PolicyAnalysisType::Match,
            partition: UnitPartition::Operand { question: digest },
            configuration: digest,
            models: digest,
            epoch: digest,
        };
        storage.publish(PolicyUnit::new(
            key,
            None,
            PolicyUnitProduct::Prefix(serde_json::to_string(label).expect("JSON policy product")),
            reads,
            BudgetMode::Exhaustive,
            vec![digest],
        ));
    }
    (answer, storage.flush().expect("policy unit storage"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::retained::RetainedSize;
    use brokk_bifrost_analysis::analyzer::IndexFamily;
    use brokk_bifrost_analysis::{AnalyzerConfig, FilesystemProject};
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#12272: selected proofs kept declaration sources outside the request's resident-source budget"
    )]
    fn selected_proof_source_residency() {
        use brokk_bifrost_analysis::analyzer::languages::{
            SelectedCallResultOwnership as Ownership, language_support,
        };
        use brokk_bifrost_analysis::analyzer::semantic::{
            CancellationToken, ProcedureKind, SemanticBudget, SemanticBudgetDimension,
            SemanticRequest,
        };
        use brokk_bifrost_core::analyzer::config::AnalyzerConfig;
        use brokk_bifrost_core::analyzer::model::Language;
        use std::sync::Arc;

        let source =
            "struct Resource { payload: &'static mut u8 } fn selected() -> Resource { panic!() }";
        let project = crate::inline_project::InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"source_residency\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("src/lib.rs", source)
            .build();
        let workspace =
            WorkspaceAnalyzer::build_persisted(project.project_dyn(), AnalyzerConfig::default())
                .unwrap();
        let support = language_support(Language::Rust).unwrap();
        let cancellation = CancellationToken::default();
        let artifact = workspace
            .materialize_program_semantics(
                &project.file("src/lib.rs"),
                &mut SemanticRequest::new(&mut SemanticBudget::default(), &cancellation),
            )
            .unwrap()
            .available_value()
            .cloned()
            .unwrap();
        let procedure = artifact
            .procedures()
            .iter()
            .find(|procedure| procedure.kind() == ProcedureKind::Function)
            .unwrap();
        let procedure = artifact.procedure_handle(procedure.id()).unwrap();
        for (source_bytes, expected) in [
            (source.len(), Ownership::Unknown),
            (source.len() * 3, Ownership::Move),
        ] {
            let mut limits = SemanticBudget::default().limits();
            limits.source_bytes = source_bytes;
            let mut budget = SemanticBudget::new(limits).unwrap();
            // An already retained containing source leaves less room than the
            // selected declaration needs, despite the per-file cap allowing it.
            let containing_source = Arc::new(());
            budget.hold_source(&containing_source, 1).unwrap();
            let starting_residency = budget.resident();
            let mut request = SemanticRequest::new(&mut budget, &cancellation);
            assert_eq!(
                support
                    .ownership_class_of_call_result(&workspace, &procedure, &mut request)
                    .unwrap(),
                expected
            );
            if expected == Ownership::Unknown {
                assert!(
                    request.stop_observed(),
                    "refusal must leave the proof incomplete"
                );
                assert_eq!(
                    request.budget.first_refusal().unwrap().exceeded.dimension(),
                    SemanticBudgetDimension::SourceBytes
                );
            } else {
                assert!(!request.stop_observed());
                assert!(request.budget.first_refusal().is_none());
            }
            assert_eq!(request.budget.resident(), starting_residency);
        }

        // This old complete row records only the containing source's byte,
        // omitting the selected declaration hold that now exceeds this cap.
        let registry = crate::test_support::registry_with_policy(
            "test:source-residency",
            r#"(policy :id "test.source-residency" :name "Residency" :message "Matched"
                :severity warning :analysis (analysis :type match
                  :selector (rql (language rust (function)))))"#,
            "selected-proof source residency",
        );
        let policy = registry.policies().next().unwrap();
        let inputs = WorkspaceUnitInputs::of(&workspace, None, None);
        let old_key = inputs
            .with_previous_epoch(&workspace, None)
            .unit_key(policy, UnitPartition::Whole);
        let current_key = inputs.unit_key(policy, UnitPartition::Whole);
        let mut old_work = CodeQueryExecutionWork::default();
        old_work.semantic.resident_peaks.source_bytes = 1;
        let old = PolicyUnit::new(
            old_key.clone(),
            None,
            PolicyUnitProduct::Rows(UnitExecutionResult {
                except_left_complete_empty: None,
                rows: Vec::new(),
                work: old_work,
                budgeted_work: Default::default(),
                completion: CodeQueryCompletion::Complete,
                depth_bound_status: None,
                depth_answers: Vec::new(),
                diagnostics: Vec::new(),
                truncated: false,
                reuse: Default::default(),
            }),
            Vec::new(),
            BudgetMode::Exhaustive,
            vec![workspace_snapshot(&workspace).unwrap()],
        );
        let store = Arc::clone(workspace.store().unwrap());
        assert_eq!(
            store
                .publish_policy_units(vec![unit_row(&old).unwrap()])
                .unwrap(),
            1
        );
        let mut retained = PersistedPolicyUnitStore::new(store);
        retained
            .prefetch(
                std::slice::from_ref(&old_key),
                &PolicyBudget::default(),
                None,
            )
            .unwrap();
        retained
            .prefetch(
                std::slice::from_ref(&current_key),
                &PolicyBudget::default(),
                None,
            )
            .unwrap();
        assert!(
            retained.lookup(&old_key).is_some(),
            "the old complete receipt must actually be stored"
        );
        assert!(
            retained.lookup(&current_key).is_none(),
            "old source census must not serve the new epoch as complete"
        );

        let prove = |workspace: &WorkspaceAnalyzer| {
            let mut limits = SemanticBudget::default().limits();
            limits.source_bytes = source.len();
            let mut budget = SemanticBudget::new(limits).unwrap();
            let containing_source = Arc::new(());
            budget.hold_source(&containing_source, 1).unwrap();
            let mut request = SemanticRequest::new(&mut budget, &cancellation);
            let answer = support
                .ownership_class_of_call_result(workspace, &procedure, &mut request)
                .unwrap();
            (
                answer,
                request
                    .budget
                    .first_refusal()
                    .map(|refusal| refusal.exceeded.dimension()),
            )
        };
        let warm = prove(&workspace);
        let fresh = project.workspace_analyzer(AnalyzerConfig::default());
        assert_eq!(
            warm,
            (
                Ownership::Unknown,
                Some(SemanticBudgetDimension::SourceBytes)
            )
        );
        assert_eq!(
            warm,
            prove(&fresh),
            "stored old census must agree with a fresh bounded proof"
        );
    }

    #[test]
    #[hardwon("#11321: missing cached diagnostic provenance manufactured a Provider cause")]
    fn missing_cached_diagnostic_provenance_is_a_miss() {
        let fixture = crate::inline_project::InlineTestProject::with_language(Language::TypeScript)
            .file("lib.ts", "function target() {}\n")
            .build();
        let workspace = WorkspaceAnalyzer::build_persisted(
            Arc::new(FilesystemProject::new(fixture.root()).expect("project")),
            AnalyzerConfig::default(),
        )
        .expect("persisted workspace");
        let store = Arc::clone(workspace.store().expect("SQLite store"));
        let blob = ChangedFacts::between(&workspace, &workspace)
            .head_blob(Language::TypeScript, "lib.ts")
            .expect("parsed fixture blob");
        let digest = StableDigest::sha256(b"diagnostic provenance");
        let key = |index: u8| PolicyUnitKey {
            policy: PolicySemanticHash::from_lower_hex(&format!("{:064x}", 1))
                .expect("stored policy hash"),
            family: PolicyAnalysisType::Assertion,
            partition: UnitPartition::AssertFile {
                language: Language::TypeScript,
                rel_path: "lib.ts".into(),
                blob,
                subjects: StableDigest::sha256([index]),
            },
            configuration: digest,
            models: digest,
            epoch: policy_substrate_epoch(digest),
        };
        let keys = [key(1), key(2), key(3)];
        let diagnostic: CodeQueryDiagnostic = serde_json::from_value(serde_json::json!({
            "incompleteness": "configured_cap",
            "code": "semantic_analysis_partial",
            "impact": "incomplete",
            "language": "typescript",
            "message": "deterministic gap"
        }))
        .expect("producer diagnostic");
        assert!(!diagnostic.has_non_utf8_refusal);
        let mut rows = keys
            .iter()
            .map(|key| {
                unit_row(&PolicyUnit::new(
                    key.clone(),
                    Some(ParseVariant::Empty),
                    PolicyUnitProduct::AssertFile(AssertFileProduct {
                        retention: AssertFileRetention::None,
                        findings: Vec::new(),
                        unconcluded: Vec::new(),
                        row_completions: Vec::new(),
                        diagnostics: vec![diagnostic.clone()],
                        work: Default::default(),
                    }),
                    Vec::new(),
                    BudgetMode::Exhaustive,
                    vec![digest],
                ))
                .expect("unit row")
            })
            .collect::<Vec<_>>();
        let mut old: serde_json::Value = serde_json::from_str(&rows[0].product).unwrap();
        old["diagnostics"][0]
            .as_object_mut()
            .unwrap()
            .remove("incompleteness");
        rows[0].product = serde_json::to_string(&old).unwrap();
        let mut invalid: serde_json::Value = serde_json::from_str(&rows[2].product).unwrap();
        invalid["diagnostics"][0]["incompleteness"] = serde_json::json!("invalid cause");
        invalid["diagnostics"]
            .as_array_mut()
            .unwrap()
            .push(old["diagnostics"][0].clone());
        rows[2].product = serde_json::to_string(&invalid).unwrap();
        store.publish_policy_units(rows).expect("persist test rows");
        let mut retained = PersistedPolicyUnitStore::new(store);
        retained
            .prefetch(&keys[..2], &PolicyBudget::default(), None)
            .expect("incompatible row is a miss");
        assert!(retained.lookup(&keys[0]).is_none());
        assert!(
            retained
                .prefetch(&keys[2..], &PolicyBudget::default(), None)
                .is_err(),
            "a present but invalid cause is corruption, never an upgrade miss"
        );
        let PolicyUnitProduct::AssertFile(product) =
            &retained.lookup(&keys[1]).expect("current row").product
        else {
            panic!("assert product");
        };
        assert_eq!(
            product.diagnostics[0].incompleteness,
            brokk_bifrost_rql::Incompleteness::ConfiguredCap
        );
    }

    #[test]
    #[hardwon(
        "#11534: units committed before a policy store failure leaked into loaded and persisted state"
    )]
    fn policy_completion_holds_publication_until_success() {
        use brokk_bifrost_analysis::analyzer::i_analyzer::PolicyCompletionOwner;
        let fixture = crate::inline_project::InlineTestProject::with_language(Language::Python)
            .with_git()
            .file("a.py", "def target():\n    return 1\n")
            .build();
        let workspace = WorkspaceAnalyzer::build_persisted(
            Arc::new(FilesystemProject::new(fixture.root()).unwrap()),
            AnalyzerConfig::default(),
        )
        .unwrap();
        let snapshot = workspace_snapshot(&workspace).unwrap();
        let changed = ChangedFacts::between(&workspace, &workspace);
        let inputs = WorkspaceUnitInputs::of(&workspace, None, None);
        let store = Mutex::new(PersistedPolicyUnitStore::new(Arc::clone(
            workspace.store().unwrap(),
        )));
        let context = PolicyIncrementalContext::new(
            &store,
            &workspace,
            &changed,
            inputs,
            IncrementalBaseState::Evaluated,
            UnitSnapshots {
                base: snapshot,
                head: snapshot,
            },
        );
        let mut keys = Vec::new();
        for (id, fail) in [
            ("test.failed", true),
            ("test.inherited", true),
            ("test.healthy", false),
        ] {
            let preparation =
                brokk_bifrost_analysis::analyzer::AnalyzerQueryScope::new(workspace.analyzer());
            if id == "test.inherited" {
                preparation.record_store_error_for_test(
                    brokk_bifrost_analysis::analyzer::store::StoreError::new("before policy entry"),
                );
            }
            let registry = crate::test_support::registry_with_policy(
                id,
                &format!(
                    r#"(policy :id "{id}" :name "Target" :message "Target" :severity warning
                :analysis (analysis :type match :selector (rql (language python (function)))))"#
                ),
                "policy",
            );
            let policy = registry.policies().next().unwrap();
            let key = inputs.unit_key(policy, UnitPartition::Whole);
            let owner = Arc::new(PolicyCompletionOwner::default());
            let _owner = owner.install();
            let _scope =
                brokk_bifrost_analysis::analyzer::AnalyzerQueryScope::for_policy_evaluation(
                    workspace.analyzer(),
                );
            let mut staged = StagedUnits::default();
            staged.stage(PolicyUnit::new(
                key.clone(),
                None,
                PolicyUnitProduct::Rows(brokk_bifrost_rql::structural::UnitExecutionResult {
                    except_left_complete_empty: None,
                    rows: Vec::new(),
                    work: Default::default(),
                    budgeted_work: Default::default(),
                    depth_bound_status: None,
                    depth_answers: Vec::new(),
                    completion: brokk_bifrost_rql::structural::CodeQueryCompletion::Complete,
                    diagnostics: Vec::new(),
                    truncated: false,
                    reuse: Default::default(),
                }),
                Vec::new(),
                BudgetMode::Exhaustive,
                vec![snapshot],
            ));
            context.commit_units(PolicyId::new(id).unwrap(), staged, vec![key.clone()]);
            assert!(
                store.lock().unwrap().lookup(&key).is_none(),
                "provisional units are invisible"
            );
            assert!(
                context.published_units().is_empty(),
                "provisional lists are invisible"
            );
            if fail && id != "test.inherited" {
                workspace.analyzer().record_query_failure(
                    brokk_bifrost_analysis::analyzer::store::StoreError::new("after unit commit"),
                );
                assert!(!owner.errors().is_empty());
            }
            if fail {
                assert!(
                    !owner.errors().is_empty(),
                    "own and inherited failures reach the owner"
                );
            }
            context.complete_policy_publications(&owner);
            assert_eq!(store.lock().unwrap().lookup(&key).is_some(), !fail);
            owner.acknowledge();
            keys.push(key);
        }
        assert_eq!(
            store.lock().unwrap().flush().unwrap(),
            1,
            "only healthy units reach SQLite"
        );
        assert!(store.lock().unwrap().lookup(&keys[0]).is_none());
        assert!(store.lock().unwrap().lookup(&keys[1]).is_none());
        assert!(store.lock().unwrap().lookup(&keys[2]).is_some());
        assert_eq!(context.published_units().len(), 1);
    }

    #[test]
    fn incompatible_retained_selector_json_is_a_miss() {
        // An older shape may have fields the current decoder no longer knows,
        // or lack mandatory fields. Neither is an evaluation failure.
        for json in [r#"{"sites":[],"legacy_rows":[]}"#, r#"{"sites":[]}"#] {
            assert!(SelectorProduct::decode_retained(json).is_none());
        }
    }

    #[test]
    #[hardwon("#9017: retained policy evaluations replayed across a lowering-only adapter bump")]
    fn lowering_identity_rotates_unit_and_head_keys() {
        let registry = crate::test_support::registry_with_policy(
            "test:lowering-epoch",
            r#"(policy :id "test.lowering-epoch" :name "Epoch" :message "Epoch"
                :severity warning :analysis (analysis :type match
                  :selector (rql (language python (class)))))"#,
            "valid key-boundary policy",
        );
        let policy = registry.policies().next().unwrap();
        let lowering = |version: &[u8]| {
            let identity = brokk_bifrost_analysis::analyzer::semantic::service::SemanticAdapterIdentity::for_adapter(
                "python", version, b"python-intrafile-execution-defaults-v1",
                brokk_bifrost_analysis::analyzer::semantic::DependencyFingerprint::hash_bytes(
                    b"no-intrafile-dependencies"),
            );
            brokk_bifrost_analysis::analyzer::workspace::policy_lowering_identity_from_adapters([(
                Language::Python,
                identity,
                None,
            )])
        };
        let fixed = WorkspaceUnitInputs {
            model_read_digest:
                brokk_bifrost_analysis::analyzer::i_analyzer::current_model_set_digest(None),
            configuration: StableDigest::sha256("configuration"),
            models: StableDigest::sha256("models"),
            epoch: policy_substrate_epoch(lowering(b"python-value-semantics-v57")),
        };
        let changed = fixed.with_lowering_identity(lowering(b"python-value-semantics-v58"));
        assert_ne!(
            row_key(&fixed.unit_key(policy, UnitPartition::Whole)),
            row_key(&changed.unit_key(policy, UnitPartition::Whole))
        );
        assert_ne!(
            fixed.head_inputs(policy).epoch,
            changed.head_inputs(policy).epoch
        );
        let options = crate::test_support::evaluation_options("2026-07-27");
        let scope = crate::scope::parse_policy_scope_document(
            r#"{"schema_version":1,"scopes":[{"path":"tests","reason":"Acquisitions outside production.","exclude_roots":true}]}"#,
        ).unwrap();
        assert_ne!(
            crate::coordinator::base_evaluation_key(&options, None, fixed).options_digest,
            crate::coordinator::base_evaluation_key(&options, Some(&scope), fixed).options_digest,
            "scoped evaluation rows cannot satisfy unscoped requests",
        );

        assert_ne!(
            crate::coordinator::base_evaluation_key(&options, None, fixed),
            crate::coordinator::base_evaluation_key(&options, None, changed),
        );
        let head_key = |inputs| {
            brokk_bifrost_analysis::analyzer::store::policy_units::PolicyEvaluationRowKey {
                base_tree_oid: "head-tree".to_owned(),
                ..crate::coordinator::base_evaluation_key(&options, None, inputs)
            }
        };
        assert_ne!(head_key(fixed), head_key(changed));
        assert_eq!(
            fixed,
            fixed.with_lowering_identity(lowering(b"python-value-semantics-v57"))
        );
    }

    #[test]
    #[hardwon("#9017: adding the first Python file rotated unchanged policy keys")]
    fn lowering_identity_ignores_workspace_language_presence() {
        let fixture = crate::inline_project::InlineTestProject::with_language(Language::TypeScript)
            .with_git()
            .file("a.ts", "export function target() {}\n")
            .build();
        let build = || {
            WorkspaceAnalyzer::build_persisted(
                Arc::new(FilesystemProject::new(fixture.root()).expect("project")),
                AnalyzerConfig::default(),
            )
            .expect("workspace")
        };
        let before = build();
        let WorkspaceAnalyzer::Multi(before_multi) = &before else {
            panic!("TypeScript workspace must have delegates");
        };
        assert!(!before_multi.delegates().contains_key(&Language::Python));
        let first = WorkspaceUnitInputs::of(&before, None, None);
        std::fs::write(fixture.root().join("new.py"), "class Added:\n    pass\n")
            .expect("add Python file");
        let after = build();
        let WorkspaceAnalyzer::Multi(after_multi) = &after else {
            panic!("Python workspace must have delegates");
        };
        assert!(after_multi.delegates().contains_key(&Language::Python));
        let second = WorkspaceUnitInputs::of(&after, None, None);
        assert_eq!(
            before.policy_lowering_identity(None),
            after.policy_lowering_identity(None)
        );
        assert_eq!(first, second);
        let registry = crate::test_support::registry_with_policy(
            "test:presence-epoch",
            r#"(policy :id "test.presence-epoch" :name "Epoch" :message "Epoch"
                :severity warning :analysis (analysis :type match
                  :selector (rql (language typescript (class)))))"#,
            "valid key-boundary policy",
        );
        let policy = registry.policies().next().expect("policy");
        assert_eq!(
            row_key(&first.unit_key(policy, UnitPartition::Whole)),
            row_key(&second.unit_key(policy, UnitPartition::Whole))
        );
        let options = crate::test_support::evaluation_options("2026-07-27");
        assert_eq!(
            crate::coordinator::base_evaluation_key(&options, None, first),
            crate::coordinator::base_evaluation_key(&options, None, second)
        );
    }

    #[test]
    fn edited_workspace_keeps_index_proofs_on_the_snapshot_that_answered_them() {
        let fixture = crate::inline_project::InlineTestProject::with_language(Language::TypeScript)
            .with_git()
            .file("a.ts", "export function target() {}\n")
            .build();
        let build = || {
            WorkspaceAnalyzer::build_persisted(
                Arc::new(FilesystemProject::new(fixture.root()).expect("project")),
                AnalyzerConfig::default(),
            )
            .expect("workspace")
        };
        let base = build();
        let base_snapshot = workspace_snapshot(&base).expect("base identity");
        std::fs::write(fixture.root().join("a.ts"), "export function safe() {}\n")
            .expect("rename declaration");
        let head = build();
        let head_snapshot = workspace_snapshot(&head).expect("head identity");
        assert_ne!(
            base_snapshot, head_snapshot,
            "the edit changes the workspace identity"
        );

        let changed = ChangedFacts::between(&base, &head);
        assert!(
            changed.is_complete(),
            "the fixture needs a complete index difference"
        );
        let family = IndexFamily::DefinitionIdentifier;
        assert!(
            changed.contains(family, b"target"),
            "the renamed name must move"
        );
        assert!(!changed.contains(family, b"other"));
        let store = Mutex::new(InMemoryPolicyUnitStore::new());
        let context = PolicyIncrementalContext::new(
            &store,
            &head,
            &changed,
            WorkspaceUnitInputs::of(&head, None, None),
            IncrementalBaseState::Evaluated,
            UnitSnapshots {
                base: base_snapshot,
                head: head_snapshot,
            },
        );
        assert_eq!(context.snapshot(), head_snapshot);
        assert_eq!(
            context.publication_snapshots(&[ReadKey::index(family, b"target")]),
            vec![head_snapshot],
            "a moved name cannot attest the base answer",
        );
        assert_eq!(
            context.publication_snapshots(&[ReadKey::index(family, b"other")]),
            vec![head_snapshot, base_snapshot],
            "an unchanged name can attest both answers",
        );
        let (verified_on, base_changes) = context
            .changed_since(&[base_snapshot])
            .expect("base-attested unit");
        assert_eq!(verified_on, base_snapshot);
        assert!(base_changes.contains(family, b"target"));
        let (verified_on, head_changes) = context
            .changed_since(&[base_snapshot, head_snapshot])
            .expect("head-attested unit");
        assert_eq!(verified_on, head_snapshot);
        assert!(!head_changes.contains(family, b"target"));

        let registry = crate::test_support::registry_with_policy(
            "test:mixed-reads",
            r#"(policy :id "test.mixed-reads" :name "Mixed reads" :message "Matched"
                :severity warning :analysis (analysis :type match
                  :selector (rql (language typescript (function)))))"#,
            "mixed index and path reads",
        );
        let policy = registry.policies().next().expect("policy");
        let unit = PolicyUnit::new(
            WorkspaceUnitInputs::of(&head, None, None).unit_key(policy, UnitPartition::Whole),
            None,
            PolicyUnitProduct::AssertFile(AssertFileProduct {
                retention: AssertFileRetention::None,
                findings: Vec::new(),
                unconcluded: Vec::new(),
                row_completions: Vec::new(),
                diagnostics: Vec::new(),
                work: Default::default(),
            }),
            vec![
                ReadKey::index(family, b"target"),
                ReadKey::path_absent(Language::TypeScript, "missing.ts"),
            ],
            BudgetMode::Exhaustive,
            vec![base_snapshot],
        );
        assert!(
            unit.reads_name_index(),
            "a mixed read set still depends on a name index"
        );
    }

    #[test]
    fn modeled_python_hierarchy_invalidates_units_and_heads_with_unchanged_models() {
        let registry = crate::test_support::registry_with_policy(
            "test:hierarchy-epoch",
            r#"(policy :id "test.hierarchy-epoch" :name "Epoch" :message "Epoch"
                :severity warning :analysis (analysis :type match
                  :selector (rql (language python (class)))))"#,
            "valid key-boundary policy",
        );
        let policy = registry.policies().next().unwrap();
        // A head one substrate change older keyed its units by the epoch
        // before the lever file's last token.
        {
            let old_epoch =
                substrate_epoch_before_last_token(StableDigest::sha256("test-lowering"));
            for models in [
                StableDigest::sha256(NO_ACTIVE_MODELS),
                StableDigest::sha256("same active model set"),
            ] {
                let current = WorkspaceUnitInputs {
                    model_read_digest:
                        brokk_bifrost_analysis::analyzer::i_analyzer::current_model_set_digest(None),
                    configuration: StableDigest::sha256("same configuration"),
                    models,
                    epoch: policy_substrate_epoch(StableDigest::sha256("test-lowering")),
                };
                let old = WorkspaceUnitInputs {
                    model_read_digest:
                        brokk_bifrost_analysis::analyzer::i_analyzer::current_model_set_digest(None),
                    epoch: old_epoch,
                    ..current
                };
                let current_key = current.unit_key(policy, UnitPartition::Whole);
                let old_key = old.unit_key(policy, UnitPartition::Whole);
                assert_eq!(current_key.models, old_key.models);
                assert_ne!(
                    row_key(&current_key),
                    row_key(&old_key),
                    "persisted unit lookup must miss an old substrate product"
                );
                assert_ne!(
                    current.head_inputs(policy).epoch,
                    old.head_inputs(policy).epoch,
                    "aggregate evaluation/read verification must not reuse old substrate semantics"
                );
            }
        }
    }

    /// The reuse review is charged to the report's retention budget, so its
    /// retained size must not say how the run executed. Two reviews of one
    /// policy set -- the one a reusing run records and the one a forced-full
    /// run records -- therefore cost the same bytes, and every later retention
    /// decision sees the same remaining budget in both modes.
    #[test]
    fn a_reusing_and_a_forced_full_review_retain_the_same_bytes() {
        let sliced = PolicyId::new("test.dynamic-eval").expect("policy id");
        let whole = PolicyId::new("test.taint-flow").expect("policy id");
        let reusing = PolicyIncrementalReview {
            base: IncrementalBaseState::Reused,
            policies: vec![
                PolicyIncrementalRun {
                    policy_id: sliced.clone(),
                    mode: IncrementalMode::Sliced,
                    units_total: 40,
                    units_reused: 39,
                    units_recomputed: 1,
                    units_unbounded: 0,
                    lookups_replayed: 0,
                    output_refusals: Default::default(),
                    composition_searches: Default::default(),
                    discarded_source_inventory: None,
                    widen_reason: None,
                    widen_detail: None,
                    base_units_reused: 38,
                    base_units_recomputed: 2,
                    base_lookups_replayed: 0,
                    base_widen_reason: Some(WidenReason::MergedLimitReached),
                    base_widen_detail: None,
                },
                PolicyIncrementalRun::whole_family(whole.clone()),
            ],
        };
        let forced_full = PolicyIncrementalReview::evaluated_in_full(
            [sliced, whole],
            WidenReason::IncrementalDisabled,
        );

        assert_eq!(
            reusing.policies().len(),
            forced_full.policies().len(),
            "both modes report every policy that ran"
        );
        assert_eq!(reusing.retained_size(), forced_full.retained_size());
    }
}

#[cfg(test)]
#[path = "units/policy_source_identity_tests.rs"]
mod policy_source_identity_tests;
