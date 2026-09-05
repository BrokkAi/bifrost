//! Evaluation units: the smallest piece of policy work a run reuses.
//!
//! A unit is one policy evaluated over one partition of the workspace -- for
//! the match family, one seed file -- together with the exact set of inputs
//! that execution read (`.agents/plans/impact-sliced-diff-base.md`,
//! Milestone 2). Two runs over two workspaces may share a unit's product when
//! every one of those reads still denotes the same content, which is what
//! [`verify_read_set`] decides.
//!
//! Nothing here is per policy or per family beyond the key's own fields. The
//! same key, the same verification and the same store serve every policy: a
//! family differs only in how its execution is partitioned, which is a
//! property of the plan's structure that the RQL crate computes.
//!
//! [`verify_read_set`]: brokk_bifrost_analysis::analyzer::verify_read_set

use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserializer, Serialize};
use std::cell::RefCell;
use std::collections::HashMap;

use brokk_bifrost_analysis::analyzer::invalidation::{ArtifactVerdictLog, BudgetMode};
use brokk_bifrost_analysis::analyzer::read_ledger::read_set_digest;
use brokk_bifrost_analysis::analyzer::semantic::SemanticWork;
use brokk_bifrost_analysis::analyzer::semantic::ids::{LengthDelimitedDigest, StableDigest};
use brokk_bifrost_analysis::analyzer::semantic_model::ActiveSemanticModelSnapshot;
use brokk_bifrost_analysis::analyzer::store::AnalyzerStore;
use brokk_bifrost_analysis::analyzer::store::policy_units::{
    PolicyUnitPartitionRow, PolicyUnitRow, PolicyUnitRowKey,
};
use brokk_bifrost_analysis::analyzer::{
    ChangedFacts, HeadInputs, Language, Oid, ReadKey, ReadSetDigest, WorkspaceAnalyzer,
    analysis_epoch_digest,
};
use brokk_bifrost_flow::dataflow::SolverWork;
use brokk_bifrost_rql::structural::UnitExecutionResult;
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

/// The digest a unit key carries when no semantic models were active.
///
/// A fixed value rather than an absent field: "no models were active" is an
/// input like any other, and a unit produced without models must not match one
/// produced with them.
const NO_ACTIVE_MODELS: &str = "bifrost-policy-unit:no-active-models:v1";

/// This crate's own revision, folded into the engine epoch beside the
/// analyzer's parser epochs.
///
/// The analyzer epoch says which parsers derived the facts a unit read. It
/// says nothing about how this crate shapes a published product or composes a
/// finding identity, and a run must read back neither from an older engine.
/// Bump this whenever a change makes either something this engine would no
/// longer mint.
///
/// The current value is #2968, which took the compiled binding-plan hash out
/// of a typestate finding's identity. Both persisted shapes moved with it: a
/// published root product carries a typestate anchor field this engine no
/// longer accepts, and a recorded base evaluation carries typestate identities
/// this engine no longer mints. The second is the one a reader could not see.
/// Nothing detects it -- the recorded identities simply never join the head's,
/// so every unchanged violation reports as `fixed` and `new` forever, against
/// exactly the bases this change exists to fix.
const POLICY_SUBSTRATE_EPOCH: &str = "bifrost-policy-unit:substrate:2968-typestate-identity";

/// The epoch every unit key and the evaluation row key carry.
fn policy_substrate_epoch() -> StableDigest {
    StableDigest::sha256(format!(
        "{POLICY_SUBSTRATE_EPOCH}\u{1}{}",
        analysis_epoch_digest()
    ))
}

/// Which partition of the workspace one unit covers.
///
/// A `Seed` unit is keyed by the file its seed enumeration walked and the blob
/// that path resolved to, because the same path holding different bytes is a
/// different unit even when nothing else moved. `Whole` is the whole policy,
/// which is what a widened evaluation publishes.
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
/// have (`.agents/plans/impact-sliced-diff-base.md`, Decision Log (5d)).
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
    Whole,
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
            Self::Whole => "whole",
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
    Selector(SelectorProduct),
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
            Self::AssertFile(_) | Self::Root(_) | Self::Selector(_) => None,
        }
    }

    /// The per-file assertion product this carries, or `None` when it carries a
    /// product of another shape.
    pub(crate) fn into_assert_file(self) -> Option<AssertFileProduct> {
        match self {
            Self::AssertFile(product) => Some(product),
            Self::Rows(_) | Self::Root(_) | Self::Selector(_) => None,
        }
    }

    /// The per-root typestate product this carries, or `None` when it carries
    /// a product of another shape.
    pub(crate) fn into_root(self) -> Option<RootProduct> {
        match self {
            Self::Root(product) => Some(product),
            Self::Rows(_) | Self::AssertFile(_) | Self::Selector(_) => None,
        }
    }

    /// The per-seed selector product this carries, or `None` when it carries a
    /// product of another shape.
    pub(crate) fn into_selector(self) -> Option<SelectorProduct> {
        match self {
            Self::Selector(product) => Some(product),
            Self::Rows(_) | Self::AssertFile(_) | Self::Root(_) => None,
        }
    }

    /// The stable label of this product kind.
    pub(crate) const fn stable_label(&self) -> &'static str {
        match self {
            Self::Rows(_) => "rows",
            Self::AssertFile(_) => "assert_file",
            Self::Root(_) => "root",
            Self::Selector(_) => "selector",
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
/// reasons its own analysis was incomplete; and what it added to the run's
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
    pub incomplete_reasons: Vec<PolicyIncompleteReason>,
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
/// sliced run would reach a lane later than the whole run does
/// (`.agents/plans/impact-sliced-diff-base.md`, Decision Log (5c)).
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
    pub semantic: SemanticWork,
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
/// unit is the budget a whole-workspace selector execution would have left
/// (`.agents/plans/impact-sliced-diff-base.md`, Decision Log (5c)). There is
/// no artifact charge: a unit whose execution retained artifact allocations is
/// never published, because the allocations are process-local and a reused
/// unit could not hand them to the compile.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SelectorProduct {
    pub rows: UnitExecutionResult,
    pub sites: Vec<SelectorProductSite>,
    pub semantic: SemanticWork,
    pub materialized_files: u64,
    pub traversal_steps: u64,
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
const ROOT_FIELDS: &[&str] = &["findings", "incomplete_reasons", "work"];

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
        let mut incomplete_reasons: Option<Vec<PolicyIncompleteReason>> = None;
        let mut work: Option<RootWork> = None;
        while let Some(field) = map.next_key::<String>()? {
            let duplicate = match field.as_str() {
                "findings" => findings
                    .replace(map.next_value_seed(ProjectionListSeed {
                        budget: self.budget,
                    })?)
                    .is_some(),
                "incomplete_reasons" => incomplete_reasons.replace(map.next_value()?).is_some(),
                "work" => work.replace(map.next_value()?).is_some(),
                other => return Err(de::Error::unknown_field(other, ROOT_FIELDS)),
            };
            if duplicate {
                return Err(de::Error::duplicate_field("a root unit product field"));
            }
        }
        let product = RootProduct {
            findings: findings.ok_or_else(|| de::Error::missing_field("findings"))?,
            incomplete_reasons: incomplete_reasons
                .ok_or_else(|| de::Error::missing_field("incomplete_reasons"))?,
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

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut projections = Vec::with_capacity(seq.size_hint().unwrap_or_default());
        while let Some(projection) =
            seq.next_element_seed(TypestateProjectedFindingSeed::new(self.budget))?
        {
            projections.push(projection);
        }
        Ok(projections)
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
        let mut findings: Option<Vec<PolicyFinding>> = None;
        let mut unconcluded: Option<Vec<PolicyIncompleteReason>> = None;
        let mut row_completions: Option<Vec<CodeQueryCompletion>> = None;
        let mut diagnostics: Option<Vec<CodeQueryDiagnostic>> = None;
        let mut work: Option<CodeQueryExecutionWork> = None;
        while let Some(field) = map.next_key::<String>()? {
            let duplicate = match field.as_str() {
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

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut findings = Vec::with_capacity(seq.size_hint().unwrap_or_default());
        while let Some(finding) = seq.next_element_seed(PolicyFindingSeed::new(self.budget))? {
            findings.push(finding);
        }
        Ok(findings)
    }
}

/// One published unit: what it answered, and every input that answer depends
/// on.
///
/// `reads` is the ledger's own key set and `read_digest` is derived from it at
/// construction, so the two can never disagree about which reads a unit's
/// verification must cover.
#[derive(Debug, Clone)]
pub struct PolicyUnit {
    key: PolicyUnitKey,
    product: PolicyUnitProduct,
    reads: Vec<ReadKey>,
    read_digest: ReadSetDigest,
    budget_mode: BudgetMode,
}

impl PolicyUnit {
    /// Publish one unit's product under the reads that produced it.
    pub(crate) fn new(
        key: PolicyUnitKey,
        product: PolicyUnitProduct,
        reads: Vec<ReadKey>,
        budget_mode: BudgetMode,
    ) -> Self {
        let read_digest = read_set_digest(&reads);
        Self {
            key,
            product,
            reads,
            read_digest,
            budget_mode,
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
}

/// Where published units are looked up and published.
///
/// One evaluation batch owns one store. Milestone 3 adds the persisted
/// implementation behind the same two operations; nothing above this trait
/// knows which one it is holding.
pub trait PolicyUnitStore {
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
    ) -> Result<(), PolicyUnitStoreError> {
        Ok(())
    }

    fn lookup(&self, key: &PolicyUnitKey) -> Option<&PolicyUnit>;
    fn publish(&mut self, unit: PolicyUnit);
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

    /// How many units this store holds.
    pub fn len(&self) -> usize {
        self.units.len()
    }

    pub fn is_empty(&self) -> bool {
        self.units.is_empty()
    }
}

impl PolicyUnitStore for InMemoryPolicyUnitStore {
    fn lookup(&self, key: &PolicyUnitKey) -> Option<&PolicyUnit> {
        self.units.get(key)
    }

    fn publish(&mut self, unit: PolicyUnit) {
        self.units.insert(unit.key.clone(), unit);
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
/// until the caller flushes them, because a unit publication is one row plus
/// its read set and one transaction per policy is what keeps a widened policy
/// from leaving a half-published unit set behind.
pub struct PersistedPolicyUnitStore {
    store: Arc<AnalyzerStore>,
    loaded: HashMap<PolicyUnitKey, PolicyUnit>,
    pending: Vec<PolicyUnit>,
    published: usize,
}

impl PersistedPolicyUnitStore {
    pub fn new(store: Arc<AnalyzerStore>) -> Self {
        Self {
            store,
            loaded: HashMap::new(),
            pending: Vec::new(),
            published: 0,
        }
    }

    /// Write every buffered publication, in one transaction.
    ///
    /// The caller decides when: a cancelled or deadline-terminated run flushes
    /// nothing, because its units describe work that stopped early and nothing
    /// downstream can tell that from work that finished.
    pub fn flush(&mut self) -> Result<usize, PolicyUnitStoreError> {
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
            self.loaded
                .insert(key.clone(), unit_of_row(key, row, budget)?);
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
}

/// The store's spelling of one unit key.
///
/// Digests become lowercase hex and the family becomes its stable label,
/// because a persisted key is compared by SQL and must be one shape per value.
/// The persisted partition digest of one solver root: its locator folded with
/// the compile whose projections it holds.
fn root_partition_digest(locator: StableDigest, compilation: StableDigest) -> StableDigest {
    let mut digest = LengthDelimitedDigest::new(b"bifrost-policy-root-partition/v1");
    digest.push(locator.as_bytes());
    digest.push(compilation.as_bytes());
    digest.finish()
}

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
                // The persisted column is one digest per partition, and both
                // halves narrow the same question: which root, under which
                // compile. Folding them here keeps the stored key columns as
                // they are; nothing reads either half back out of the store,
                // because the key a lookup asks with carries both.
                locator: root_partition_digest(*locator, *compilation).to_string(),
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
            UnitPartition::Whole => PolicyUnitPartitionRow::Whole,
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
    }
    .map_err(|error| {
        PolicyUnitStoreError::new(format!("a unit product could not be serialized: {error}"))
    })?;
    Ok(PolicyUnitRow {
        key: row_key(&unit.key),
        product_kind: unit.product.stable_label().to_string(),
        product,
        read_set_digest: *unit.read_digest.digest().as_bytes(),
        reads: unit.reads.clone(),
    })
}

/// The product one stored row carries.
///
/// Reusing a unit against a workspace also needs its read set, which is what
/// [`unit_of_row`] adds around this. `budget` is the reading run's, because an
/// assert unit's product carries findings and a finding's caps are stated in a
/// budget: a product stored under a wider budget than this run allows is a load
/// error rather than a finding this run would never have retained.
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
) -> Result<PolicyUnit, PolicyUnitStoreError> {
    let product = product_of_row(&row, budget)?;
    let unit = PolicyUnit::new(key, product, row.reads, BudgetMode::Exhaustive);
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
    configuration: StableDigest,
    models: StableDigest,
    epoch: StableDigest,
}

impl WorkspaceUnitInputs {
    /// The inputs `workspace` evaluates under, with `models` as the activation
    /// the run pinned.
    ///
    /// The configuration fingerprint is the one the analyzer folds into every
    /// content identity, spelled the same way (#2529): the `Debug` rendering
    /// of the configuration, with a workspace that carries none behaving as
    /// the defaults describe.
    pub fn of(workspace: &WorkspaceAnalyzer, models: Option<&ActiveSemanticModelSnapshot>) -> Self {
        let configuration = workspace.config().cloned().unwrap_or_default();
        Self {
            configuration: StableDigest::sha256(format!("{configuration:?}")),
            models: models.map_or_else(
                || StableDigest::sha256(NO_ACTIVE_MODELS),
                |models| StableDigest::sha256(models.active_models().active_model_set_hash()),
            ),
            epoch: policy_substrate_epoch(),
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
            models: self.models,
            policy_semantic_hash: StableDigest::from_array(*policy.semantic_hash().as_bytes()),
            policy_source: StableDigest::from_array(*policy.source_hash().as_bytes()),
            configuration: self.configuration,
            epoch: self.epoch,
        }
    }
}

/// Everything one evaluation needs to reuse units instead of recomputing them.
///
/// Its presence is the whole condition: an evaluation that holds one has a
/// store to look units up in and a workspace to verify them against, and one
/// that does not executes exactly as it always has. There is no mode to set.
///
/// The base half of a `--diff-base` run holds one too. Its store starts empty,
/// so every unit is computed and published; its changed facts are the base
/// against itself, which is the honest statement that nothing moved between
/// the workspace its units were published against and the workspace they were
/// published from.
pub struct PolicyIncrementalContext<'a> {
    store: &'a RefCell<dyn PolicyUnitStore>,
    workspace: &'a WorkspaceAnalyzer,
    changed: &'a ChangedFacts,
    inputs: WorkspaceUnitInputs,
    base: IncrementalBaseState,
    verdicts: ArtifactVerdictLog,
    runs: RefCell<Vec<PolicyIncrementalRun>>,
    units: RefCell<Vec<(PolicyId, Vec<PolicyUnitKey>)>>,
}

impl<'a> PolicyIncrementalContext<'a> {
    pub fn new(
        store: &'a RefCell<dyn PolicyUnitStore>,
        workspace: &'a WorkspaceAnalyzer,
        changed: &'a ChangedFacts,
        inputs: WorkspaceUnitInputs,
        base: IncrementalBaseState,
    ) -> Self {
        Self {
            store,
            workspace,
            changed,
            inputs,
            base,
            verdicts: ArtifactVerdictLog::default(),
            runs: RefCell::new(Vec::new()),
            units: RefCell::new(Vec::new()),
        }
    }

    pub const fn store(&self) -> &'a RefCell<dyn PolicyUnitStore> {
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
        self.runs.borrow_mut().push(run);
    }

    /// Record the units one policy's product was merged from.
    ///
    /// Recorded only when every one of them is published, because a persisted
    /// evaluation names these as the work behind its findings and a partial
    /// list would name work that no policy did.
    pub fn record_units(&self, policy_id: PolicyId, keys: Vec<PolicyUnitKey>) {
        self.units.borrow_mut().push((policy_id, keys));
    }

    /// The units each policy's product was merged from, in policy order.
    pub fn published_units(&self) -> Vec<(PolicyId, Vec<PolicyUnitKey>)> {
        self.units.borrow().clone()
    }

    /// The review of everything this evaluation reused, in policy order.
    pub fn review(&self) -> PolicyIncrementalReview {
        PolicyIncrementalReview {
            base: self.base,
            policies: self.runs.borrow().clone(),
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

/// What one policy's evaluation did with its units.
///
/// The counts describe the sliced attempt even when it widened, because "this
/// policy enumerated forty units and recomputed one before the merge reached a
/// cap" is the diagnosis a reader needs, and a widened policy that reported
/// zeros would hide it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyIncrementalRun {
    pub policy_id: PolicyId,
    pub mode: IncrementalMode,
    pub units_total: u64,
    pub units_reused: u64,
    pub units_recomputed: u64,
    pub units_unbounded: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub widen_reason: Option<WidenReason>,
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
            widen_reason: Some(reason),
        }
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
        serializer.serialize_str(self.stable_label())
    }
}

impl Serialize for IncrementalMode {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.stable_label())
    }
}

impl Serialize for WidenReason {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.stable_label())
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::retained::RetainedSize;

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
                    widen_reason: None,
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
