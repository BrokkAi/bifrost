//! The internal relational plan representation.
//!
//! The authored source model (`crate::definition::RelationalAssertionPlan`) is
//! the hashed, canonical form and never changes shape to serve evaluation. This
//! IR is the evaluated form: every node states its own input relations and its
//! own output schema, so validation and evaluation read one structure instead of
//! re-deriving row domains from the authoring records.
//!
//! The IR is deliberately wider than the authoring surface. Every operator it
//! admits is validated and evaluated here first, so adding syntax for one is a
//! decoder in front of already tested behavior rather than a new capability.

use std::fmt;

use brokk_bifrost_rql::structural::search::DetailedCodeQueryDomain;
use brokk_bifrost_rql::structural::{
    CodeQueryEnumDomain, CodeQueryRowScalarRef, CodeQueryRowScalarType,
};

use crate::definition::{
    AssertCardinality, PolicyAssertId, RelationalAssertionLimits, RowAggregateName, RowBindingName,
    RowExpansionStep, RowGroupName, RowLiteral,
};

/// One owned scalar read from a CodeQuery row.
///
/// Owned rather than borrowed because grouping, distinct counting and finding
/// keys all outlive the borrowed row set.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RowScalar {
    StableId(String),
    String(String),
    Integer(u64),
    Boolean(bool),
    ConstrainedEnum(String),
    DeclarationIdentity(String),
}

impl RowScalar {
    /// The registry scalar type this value belongs to.
    pub const fn scalar_type(&self) -> CodeQueryRowScalarType {
        match self {
            Self::StableId(_) => CodeQueryRowScalarType::StableId,
            Self::String(_) => CodeQueryRowScalarType::String,
            Self::Integer(_) => CodeQueryRowScalarType::Integer,
            Self::Boolean(_) => CodeQueryRowScalarType::Boolean,
            Self::ConstrainedEnum(_) => CodeQueryRowScalarType::ConstrainedEnum,
            Self::DeclarationIdentity(_) => CodeQueryRowScalarType::DeclarationIdentity,
        }
    }
}

impl From<CodeQueryRowScalarRef<'_>> for RowScalar {
    fn from(value: CodeQueryRowScalarRef<'_>) -> Self {
        match value {
            CodeQueryRowScalarRef::StableId(value) => Self::StableId(value.to_string()),
            CodeQueryRowScalarRef::String(value) => Self::String(value.to_string()),
            CodeQueryRowScalarRef::Integer(value) => Self::Integer(value),
            CodeQueryRowScalarRef::Boolean(value) => Self::Boolean(value),
            CodeQueryRowScalarRef::ConstrainedEnum(value) => {
                Self::ConstrainedEnum(value.to_string())
            }
            CodeQueryRowScalarRef::DeclarationIdentity(value) => {
                Self::DeclarationIdentity(value.to_string())
            }
        }
    }
}

/// A relation's position in `RelationalPlanIr::relations`.
///
/// Ids are dense and every operator's inputs have smaller ids than the operator
/// itself, which is what makes the dependency graph acyclic by construction and
/// evaluable in one forward pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IrRelationId(pub usize);

impl IrRelationId {
    pub const fn index(self) -> usize {
        self.0
    }
}

impl fmt::Display for IrRelationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "r{}", self.0)
    }
}

/// One column of a relation schema.
///
/// Columns stay namespaced by the binding (or group) that produced them, so a
/// join concatenating two schemas cannot collide two same-named row fields and
/// an authored `site.ast_id` always addresses the same column after any number
/// of joins.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IrColumn {
    pub qualifier: String,
    pub name: String,
}

impl IrColumn {
    pub fn new(qualifier: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            qualifier: qualifier.into(),
            name: name.into(),
        }
    }
}

impl fmt::Display for IrColumn {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}", self.qualifier, self.name)
    }
}

/// One typed column of a relation schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IrField {
    pub column: IrColumn,
    pub scalar_type: CodeQueryRowScalarType,
    /// Whether the registry declares this field absent for some rows. Only a
    /// nullable field admits an `is-null` test; a required field's null test
    /// would be a constant, which is an authoring mistake rather than a query.
    pub nullable: bool,
    /// The registry's value domain, present exactly for a `ConstrainedEnum`
    /// column. A literal outside it can never match, so the validator rejects
    /// it at load time instead of letting the plan report a clean run
    /// (issue #2515).
    pub value_domain: Option<CodeQueryEnumDomain>,
}

/// The ordered typed columns one relation produces.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IrSchema {
    fields: Vec<IrField>,
}

impl IrSchema {
    pub fn new(fields: Vec<IrField>) -> Self {
        Self { fields }
    }

    pub fn fields(&self) -> &[IrField] {
        &self.fields
    }

    pub fn index_of(&self, column: &IrColumn) -> Option<usize> {
        self.fields.iter().position(|field| &field.column == column)
    }

    pub fn field(&self, column: &IrColumn) -> Option<&IrField> {
        self.fields.iter().find(|field| &field.column == column)
    }

    pub fn len(&self) -> usize {
        self.fields.len()
    }

    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }
}

/// The right-hand side of a comparison: another column of the same relation, or
/// an authored literal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IrOperand {
    Column(IrColumn),
    Literal(RowLiteral),
}

/// Comparison operators.
///
/// `Eq`/`Ne` are defined for every scalar type; the ordered four are defined
/// only over `Integer`, because no other registry scalar carries an order that
/// survives a rename (identity strings sort by spelling, not by meaning).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IrCompareOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

impl IrCompareOp {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Eq => "eq",
            Self::Ne => "ne",
            Self::Lt => "lt",
            Self::Le => "le",
            Self::Gt => "gt",
            Self::Ge => "ge",
        }
    }

    /// Whether this operator needs an ordered scalar type on both sides.
    pub const fn is_ordered(self) -> bool {
        matches!(self, Self::Lt | Self::Le | Self::Gt | Self::Ge)
    }
}

/// The number of literals one `InSet` predicate may enumerate.
pub const MAX_IR_SET_MEMBERS: usize = 64;

/// One row test. A relation-level predicate list is a conjunction.
///
/// Null handling is two-valued on purpose: every comparison against an absent
/// value is false, including `Ne`. A policy that means "absent" says so with
/// `IsNull`, so an absent value never satisfies a test that was written about
/// present values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IrPredicate {
    Compare {
        left: IrColumn,
        op: IrCompareOp,
        right: IrOperand,
    },
    IsNull {
        column: IrColumn,
        /// `true` spells `is-not-null`.
        negated: bool,
    },
    InSet {
        column: IrColumn,
        values: Vec<RowLiteral>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IrJoinKind {
    /// Every matching pair, with both schemas concatenated.
    Inner,
    /// The left rows that have at least one partner. The right schema is not
    /// carried, so a semi join filters without multiplying rows.
    Semi,
    /// The left rows that have no partner. Sound only over an exhaustive right
    /// relation; see `coverage::RelationCoverage`.
    Anti,
}

impl IrJoinKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Inner => "inner",
            Self::Semi => "semi",
            Self::Anti => "anti",
        }
    }
}

/// One equality between a left column and a right column.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IrEquiKey {
    pub left: IrColumn,
    pub right: IrColumn,
}

/// One column of a projection: read `source`, publish it as `output`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IrProjection {
    pub source: IrColumn,
    pub output: IrColumn,
}

/// The folds a group may compute.
///
/// Every fold produces an integer so that one cardinality assertion can state
/// any of them. `Any`/`All` fold a boolean column to 1 or 0, the convention
/// `OrderedEqual` already established.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IrAggregateOp {
    Count,
    CountDistinct,
    Min,
    Max,
    Any,
    All,
    OrderedEqual,
}

impl IrAggregateOp {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Count => "count",
            Self::CountDistinct => "count-distinct",
            Self::Min => "min",
            Self::Max => "max",
            Self::Any => "any",
            Self::All => "all",
            Self::OrderedEqual => "ordered-equal",
        }
    }

    /// Whether the fold reads a value column.
    pub const fn reads_value(self) -> bool {
        matches!(
            self,
            Self::CountDistinct | Self::Min | Self::Max | Self::Any | Self::All
        )
    }

    /// The scalar type the value column must carry, when the fold constrains
    /// it. `CountDistinct` folds any scalar type, so it constrains nothing.
    pub const fn required_value_type(self) -> Option<CodeQueryRowScalarType> {
        match self {
            Self::Min | Self::Max => Some(CodeQueryRowScalarType::Integer),
            Self::Any | Self::All => Some(CodeQueryRowScalarType::Boolean),
            Self::Count | Self::CountDistinct | Self::OrderedEqual => None,
        }
    }
}

/// One ordered sequence recovered from a group's rows: the integer position a
/// row states about itself and the value read at that position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IrOrderedSequence {
    pub position: IrColumn,
    pub value: IrColumn,
}

/// The two sequences an `ordered-equal` fold compares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IrOrderedSequencePair {
    pub left: IrOrderedSequence,
    pub right: IrOrderedSequence,
}

/// One fold over the rows of one group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IrAggregate {
    pub name: RowAggregateName,
    pub op: IrAggregateOp,
    pub value: Option<IrColumn>,
    pub sequences: Option<IrOrderedSequencePair>,
    /// Rows that fail any of these tests do not contribute to this fold. The
    /// group itself still exists, which is what lets a policy count a subset of
    /// a group without losing the group's key.
    pub predicates: Vec<IrPredicate>,
    /// The column this fold publishes in the group relation's schema.
    pub output: IrColumn,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IrRelationOp {
    /// Rows executed for one named binding.
    Source {
        binding: RowBindingName,
        domain: DetailedCodeQueryDomain,
    },
    /// Rows executed for one binding that expands another binding through an
    /// analyzer-owned step. The input relation is named so the expansion
    /// inherits its coverage as well as its own.
    Expand {
        input: IrRelationId,
        binding: RowBindingName,
        step: RowExpansionStep,
        domain: DetailedCodeQueryDomain,
    },
    Project {
        input: IrRelationId,
        columns: Vec<IrProjection>,
    },
    /// Conjunctive row filter.
    Filter {
        input: IrRelationId,
        predicates: Vec<IrPredicate>,
    },
    Join {
        left: IrRelationId,
        right: IrRelationId,
        kind: IrJoinKind,
        on: Vec<IrEquiKey>,
    },
    Group {
        input: IrRelationId,
        by: Vec<IrColumn>,
        aggregates: Vec<IrAggregate>,
    },
}

impl IrRelationOp {
    /// The relations this operator reads, in evaluation order.
    pub fn inputs(&self) -> Vec<IrRelationId> {
        match self {
            Self::Source { .. } => Vec::new(),
            Self::Expand { input, .. }
            | Self::Project { input, .. }
            | Self::Filter { input, .. }
            | Self::Group { input, .. } => vec![*input],
            Self::Join { left, right, .. } => vec![*left, *right],
        }
    }

    pub const fn label(&self) -> &'static str {
        match self {
            Self::Source { .. } => "source",
            Self::Expand { .. } => "expand",
            Self::Project { .. } => "project",
            Self::Filter { .. } => "filter",
            Self::Join { .. } => "join",
            Self::Group { .. } => "group",
        }
    }
}

/// One node of the plan: an operator plus the schema it publishes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IrRelation {
    pub id: IrRelationId,
    /// A human-readable name for diagnostics. Binding relations carry the
    /// authored binding name; group relations carry the authored group name.
    pub name: String,
    pub op: IrRelationOp,
    pub schema: IrSchema,
}

/// One cardinality claim over one aggregate column of one group relation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IrAssertion {
    pub id: PolicyAssertId,
    pub relation: IrRelationId,
    /// The authored group this assertion reads, retained for reporting.
    pub group: RowGroupName,
    pub aggregate: RowAggregateName,
    pub column: IrColumn,
    pub cardinality: AssertCardinality,
}

/// The bounds every operator honors.
///
/// A copy of the authored limits rather than the authored type itself: the
/// authored record is canonical input, and the IR must be free to grow bounds
/// the authoring surface does not spell without touching a hashed structure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IrLimits {
    pub max_source_rows: usize,
    pub max_expanded_rows: usize,
    pub max_join_comparisons: usize,
    pub max_joined_rows: usize,
    pub max_groups: usize,
    pub max_values_per_group: usize,
}

impl From<RelationalAssertionLimits> for IrLimits {
    fn from(limits: RelationalAssertionLimits) -> Self {
        Self {
            max_source_rows: limits.max_source_rows,
            max_expanded_rows: limits.max_expanded_rows,
            max_join_comparisons: limits.max_join_comparisons,
            max_joined_rows: limits.max_joined_rows,
            max_groups: limits.max_groups,
            max_values_per_group: limits.max_values_per_group,
        }
    }
}

impl Default for IrLimits {
    fn default() -> Self {
        Self::from(RelationalAssertionLimits::default())
    }
}

/// A lowered, validatable relational plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelationalPlanIr {
    pub relations: Vec<IrRelation>,
    pub assertions: Vec<IrAssertion>,
    pub limits: IrLimits,
}

impl RelationalPlanIr {
    pub fn relation(&self, id: IrRelationId) -> Option<&IrRelation> {
        self.relations.get(id.index())
    }

    /// The binding each source or expansion relation reads rows for.
    pub fn source_binding(&self, id: IrRelationId) -> Option<&RowBindingName> {
        match &self.relation(id)?.op {
            IrRelationOp::Source { binding, .. } | IrRelationOp::Expand { binding, .. } => {
                Some(binding)
            }
            _ => None,
        }
    }
}

/// Every row expansion step the authoring model can name.
///
/// The relational module owns this list rather than `definition`, because the
/// authored enum is projected into canonical JSON and must stay a plain data
/// declaration.
pub const ALL_ROW_EXPANSION_STEPS: &[RowExpansionStep] = &[
    RowExpansionStep::ReceiverOutcome,
    RowExpansionStep::ReceiverEvidence,
    RowExpansionStep::MemberSelection,
    RowExpansionStep::MemberCandidates,
    RowExpansionStep::CandidateHierarchy,
    RowExpansionStep::MemberFamily,
    RowExpansionStep::FamilyEdges,
    RowExpansionStep::DispatchOutcome,
    RowExpansionStep::DispatchTargets,
];

/// The single table of admitted row expansions: which analyzer step may be
/// applied to which source row domain, and what row domain it produces.
///
/// Validation, lowering and the introspection catalog all read this one
/// function, so a step that becomes executable cannot be admitted by the
/// validator while staying invisible to the published schema.
pub fn expansion_result_domain(
    source: DetailedCodeQueryDomain,
    step: RowExpansionStep,
) -> Option<DetailedCodeQueryDomain> {
    use DetailedCodeQueryDomain as Domain;
    use RowExpansionStep as Step;
    match (source, step) {
        (
            Domain::StructuralMatch
            | Domain::ReferenceSite
            | Domain::CallSite
            | Domain::ExpressionSite
            | Domain::Occurrence
            | Domain::ReceiverAnalysis,
            Step::ReceiverOutcome,
        ) => Some(Domain::ReceiverOutcome),
        (
            Domain::StructuralMatch
            | Domain::ReferenceSite
            | Domain::CallSite
            | Domain::ExpressionSite
            | Domain::Occurrence
            | Domain::ReceiverAnalysis,
            Step::ReceiverEvidence,
        ) => Some(Domain::ReceiverEvidence),
        (Domain::Occurrence, Step::MemberSelection) => Some(Domain::MemberSelection),
        (Domain::Occurrence, Step::CandidateHierarchy) => Some(Domain::CandidateHop),
        (
            Domain::Occurrence | Domain::CallSite | Domain::ReferenceSite | Domain::StructuralMatch,
            Step::DispatchOutcome,
        ) => Some(Domain::DispatchOutcome),
        (
            Domain::Occurrence | Domain::CallSite | Domain::ReferenceSite | Domain::StructuralMatch,
            Step::DispatchTargets,
        ) => Some(Domain::DispatchTarget),
        (Domain::Declaration, Step::MemberFamily) => Some(Domain::MemberFamily),
        (Domain::Declaration, Step::FamilyEdges) => Some(Domain::MemberFamilyEdge),
        _ => None,
    }
}

/// The schema a join publishes: an inner join concatenates both sides, and the
/// two filtering joins publish the left side only.
pub fn join_schema(left: &IrSchema, right: &IrSchema, kind: IrJoinKind) -> IrSchema {
    let mut fields = left.fields().to_vec();
    if kind == IrJoinKind::Inner {
        fields.extend(right.fields().iter().cloned());
    }
    IrSchema::new(fields)
}

/// The schema a group publishes: its key columns with their input types, then
/// one integer column per fold.
///
/// `None` when a key column is not a column of the grouped relation, which the
/// validator reports as an unknown field.
pub fn group_schema(
    input: &IrSchema,
    by: &[IrColumn],
    aggregates: &[IrAggregate],
) -> Option<IrSchema> {
    let mut fields = by
        .iter()
        .map(|column| input.field(column).cloned())
        .collect::<Option<Vec<_>>>()?;
    fields.extend(aggregates.iter().map(|aggregate| IrField {
        column: aggregate.output.clone(),
        scalar_type: CodeQueryRowScalarType::Integer,
        nullable: false,
        value_domain: None,
    }));
    Some(IrSchema::new(fields))
}

/// The schema one row domain publishes, namespaced under one binding.
pub fn domain_schema(qualifier: &str, domain: DetailedCodeQueryDomain) -> IrSchema {
    IrSchema::new(
        domain
            .row_fields()
            .iter()
            .map(|field| IrField {
                column: IrColumn::new(qualifier, field.name),
                scalar_type: field.scalar_type,
                nullable: field.nullable,
                value_domain: field.value_domain,
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The expansion list must name every authored step. An added step fails to
    /// compile here before it can silently drop out of the catalog.
    #[test]
    fn every_authored_expansion_step_is_listed() {
        for step in ALL_ROW_EXPANSION_STEPS {
            let named = match step {
                RowExpansionStep::ReceiverOutcome
                | RowExpansionStep::ReceiverEvidence
                | RowExpansionStep::MemberSelection
                | RowExpansionStep::MemberCandidates
                | RowExpansionStep::CandidateHierarchy
                | RowExpansionStep::MemberFamily
                | RowExpansionStep::FamilyEdges
                | RowExpansionStep::DispatchOutcome
                | RowExpansionStep::DispatchTargets => step.label(),
            };
            assert!(!named.is_empty());
        }
        let mut labels = ALL_ROW_EXPANSION_STEPS
            .iter()
            .map(|step| step.label())
            .collect::<Vec<_>>();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(labels.len(), ALL_ROW_EXPANSION_STEPS.len());
    }
}
