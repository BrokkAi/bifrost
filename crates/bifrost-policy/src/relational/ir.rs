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

use brokk_bifrost_rql::query::{QueryStep, QueryStepOp};
use brokk_bifrost_rql::structural::search::DetailedCodeQueryDomain;
use brokk_bifrost_rql::structural::{
    CodeQueryEnumDomain, CodeQueryRowField, CodeQueryRowScalarRef, CodeQueryRowScalarType,
};

use crate::definition::{
    AssertCardinality, PolicyAssertId, RelationalAssertionLimits, RowAggregateName, RowAggregateOp,
    RowBindingName, RowGroupName, RowLiteral,
};

/// One owned scalar read from a CodeQuery row.
///
/// Owned rather than borrowed because grouping, distinct counting and finding
/// keys all outlive the borrowed row set.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RowScalar {
    StableId(String),
    String(String),
    StringList(Vec<String>),
    IntegerList(Vec<u64>),
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
            Self::StringList(_) => CodeQueryRowScalarType::StringList,
            Self::IntegerList(_) => CodeQueryRowScalarType::IntegerList,
            Self::Integer(_) => CodeQueryRowScalarType::Integer,
            Self::Boolean(_) => CodeQueryRowScalarType::Boolean,
            Self::ConstrainedEnum(_) => CodeQueryRowScalarType::ConstrainedEnum,
            Self::DeclarationIdentity(_) => CodeQueryRowScalarType::DeclarationIdentity,
        }
    }
}

pub(super) const fn row_literal_type(literal: &RowLiteral) -> CodeQueryRowScalarType {
    match literal {
        RowLiteral::String(_) => CodeQueryRowScalarType::String,
        RowLiteral::StringList(_) => CodeQueryRowScalarType::StringList,
        RowLiteral::IntegerList(_) => CodeQueryRowScalarType::IntegerList,
        RowLiteral::Integer(_) => CodeQueryRowScalarType::Integer,
        RowLiteral::Boolean(_) => CodeQueryRowScalarType::Boolean,
        RowLiteral::ConstrainedEnum(_) => CodeQueryRowScalarType::ConstrainedEnum,
    }
}

/// The value as a diagnostic reads it back: identity and enum labels bare,
/// integers and booleans in their own spelling.
impl fmt::Display for RowScalar {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StableId(value)
            | Self::String(value)
            | Self::ConstrainedEnum(value)
            | Self::DeclarationIdentity(value) => formatter.write_str(value),
            Self::Integer(value) => write!(formatter, "{value}"),
            Self::Boolean(value) => write!(formatter, "{value}"),
            Self::StringList(value) => write!(formatter, "{value:?}"),
            Self::IntegerList(value) => write!(formatter, "{value:?}"),
        }
    }
}

impl From<CodeQueryRowScalarRef<'_>> for RowScalar {
    fn from(value: CodeQueryRowScalarRef<'_>) -> Self {
        match value {
            CodeQueryRowScalarRef::StableId(value) => Self::StableId(value.to_string()),
            CodeQueryRowScalarRef::String(value) => Self::String(value.to_string()),
            CodeQueryRowScalarRef::StringList(value) => Self::StringList(value.to_vec()),
            CodeQueryRowScalarRef::IntegerList(value) => Self::IntegerList(value.to_vec()),
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

/// Identity-bearing scalar types admitted by stable-key relational operations.
pub(super) const fn is_stable_key(scalar_type: CodeQueryRowScalarType) -> bool {
    matches!(
        scalar_type,
        CodeQueryRowScalarType::StableId | CodeQueryRowScalarType::DeclarationIdentity
    )
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
        index_of_column(self.fields.iter().map(|field| &field.column), column)
    }

    pub fn field(&self, column: &IrColumn) -> Option<&IrField> {
        self.fields.get(self.index_of(column)?)
    }

    /// Every field name the named binding publishes here, in schema order.
    ///
    /// An unknown-field diagnostic names the complete alternative set rather
    /// than a count, so an author who misspelled a column reads the columns the
    /// binding actually carries at the point of failure.
    pub fn field_names_of(&self, qualifier: &str) -> Vec<String> {
        self.fields
            .iter()
            .filter(|field| field.column.qualifier == qualifier)
            .map(|field| field.column.name.clone())
            .collect()
    }
}

pub(super) fn index_of_column<'a>(
    columns: impl IntoIterator<Item = &'a IrColumn>,
    column: &IrColumn,
) -> Option<usize> {
    columns
        .into_iter()
        .position(|candidate| candidate == column)
}

/// The right-hand side of a comparison: another column of the same relation, or
/// an authored literal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IrOperand {
    Column(IrColumn),
    Literal(RowLiteral),
}

impl fmt::Display for IrOperand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Column(column) => write!(formatter, "{column}"),
            Self::Literal(literal) => write!(formatter, "{literal}"),
        }
    }
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
    /// Membership in a resolver-produced set of stable declaration identities.
    /// Unlike authored `in`, this set is bounded by the workspace declaration
    /// inventory rather than the human-authored literal limit.
    ResolvedIdentitySet {
        column: IrColumn,
        identities: Vec<String>,
    },
}

impl IrPredicate {
    /// The row column this test reads.
    ///
    /// Every test names exactly one, which is the column a diagnostic reports
    /// the row's actual value for.
    pub const fn column(&self) -> &IrColumn {
        match self {
            Self::Compare { left, .. } => left,
            Self::IsNull { column, .. }
            | Self::InSet { column, .. }
            | Self::ResolvedIdentitySet { column, .. } => column,
        }
    }
}

/// The authored spelling of one row test, rendered in one place so that every
/// diagnostic naming a predicate names it the way the policy source wrote it.
impl fmt::Display for IrPredicate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Compare { left, op, right } => {
                write!(formatter, "({left} {} {right})", op.label())
            }
            Self::IsNull { column, negated } => write!(
                formatter,
                "({column} {})",
                if *negated { "is-not-null" } else { "is-null" }
            ),
            Self::InSet { column, values } => {
                write!(formatter, "({column} in (")?;
                for (index, value) in values.iter().enumerate() {
                    if index > 0 {
                        formatter.write_str(" ")?;
                    }
                    write!(formatter, "{value}")?;
                }
                formatter.write_str("))")
            }
            Self::ResolvedIdentitySet { column, identities } => {
                write!(
                    formatter,
                    "({column} in resolved-identities[{}])",
                    identities.len()
                )
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IrJoinKind {
    /// Every matching pair, with both schemas concatenated.
    Inner,
    /// Every matching pair plus one null-extended row for each left row with
    /// no partner. The right schema is carried with every right field marked
    /// nullable.
    Left,
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
            Self::Left => "left",
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
    /// One when the two distinct sets of present stable-key values are equal.
    SetEqual,
    /// One when every distinct present left key occurs on the right.
    Subset,
}

impl IrAggregateOp {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Count => RowAggregateOp::Count.label(),
            Self::CountDistinct => RowAggregateOp::CountDistinct.label(),
            Self::Min => RowAggregateOp::Min.label(),
            Self::Max => RowAggregateOp::Max.label(),
            Self::Any => RowAggregateOp::Any.label(),
            Self::All => RowAggregateOp::All.label(),
            Self::OrderedEqual => RowAggregateOp::OrderedEqual.label(),
            Self::SetEqual => RowAggregateOp::SetEqual.label(),
            Self::Subset => RowAggregateOp::Subset.label(),
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
            Self::Count
            | Self::CountDistinct
            | Self::OrderedEqual
            | Self::SetEqual
            | Self::Subset => None,
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
    pub sets: Option<(IrColumn, IrColumn)>,
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
        schema: IrSchema,
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
            Self::Project { input, .. }
            | Self::Filter { input, .. }
            | Self::Group { input, .. } => vec![*input],
            Self::Join { left, right, .. } => vec![*left, *right],
        }
    }

    pub const fn label(&self) -> &'static str {
        match self {
            Self::Source { .. } => "source",
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
    /// The maximum contributing tuples retained per grouped result for
    /// diagnostics. The aggregate itself is never truncated by this bound.
    pub max_representative_tuples: usize,
}

/// The default number of contributing tuples retained for one violated group.
/// The bound is an IR concern so evaluator and lowerer code can share it
/// without making the IR depend on the evaluator module.
pub const DEFAULT_MAX_REPRESENTATIVE_TUPLES: usize = 8;

impl From<RelationalAssertionLimits> for IrLimits {
    fn from(limits: RelationalAssertionLimits) -> Self {
        Self {
            max_source_rows: limits.max_source_rows,
            max_expanded_rows: limits.max_expanded_rows,
            max_join_comparisons: limits.max_join_comparisons,
            max_joined_rows: limits.max_joined_rows,
            max_groups: limits.max_groups,
            max_values_per_group: limits.max_values_per_group,
            max_representative_tuples: DEFAULT_MAX_REPRESENTATIVE_TUPLES,
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

    /// The binding each source relation reads rows for.
    pub fn source_binding(&self, id: IrRelationId) -> Option<&RowBindingName> {
        match &self.relation(id)?.op {
            IrRelationOp::Source { binding, .. } => Some(binding),
            _ => None,
        }
    }

    /// Whether every finding a complete row set would add is anchored at a
    /// row this evaluation did not see (#5451).
    ///
    /// True when the plan joins nothing, and every assertion bounds an
    /// unfiltered `count` above by zero over a group of source rows. Every
    /// group the evaluation observed then holds a row and is already a
    /// violation. An unseen row either joins a reported group, where it moves
    /// the finding only by becoming the group's first row, or forms a group
    /// of unseen rows. Either way the finding it adds is anchored at an
    /// unseen row, so a reader who knows the files of the unseen rows knows
    /// every file such a finding can be in.
    pub fn anchors_missed_findings_at_missed_rows(&self) -> bool {
        let joins = self
            .relations
            .iter()
            .any(|relation| matches!(relation.op, IrRelationOp::Join { .. }));
        !joins
            && self.assertions.iter().all(|assertion| {
                let Some(IrRelationOp::Group {
                    input, aggregates, ..
                }) = self
                    .relation(assertion.relation)
                    .map(|relation| &relation.op)
                else {
                    return false;
                };
                matches!(
                    assertion.cardinality,
                    AssertCardinality::Exactly(0) | AssertCardinality::AtMost(0)
                ) && aggregates.iter().any(|aggregate| {
                    aggregate.output == assertion.column
                        && aggregate.op == IrAggregateOp::Count
                        && aggregate.predicates.is_empty()
                }) && self.is_narrowed_source(*input)
            })
    }

    /// Whether a relation is one binding's rows, narrowed or reshaped only by
    /// row-local operators, so each of its rows is one source row.
    fn is_narrowed_source(&self, mut id: IrRelationId) -> bool {
        loop {
            match self.relation(id).map(|relation| &relation.op) {
                Some(IrRelationOp::Source { .. }) => return true,
                Some(IrRelationOp::Filter { input, .. } | IrRelationOp::Project { input, .. }) => {
                    id = *input;
                }
                Some(IrRelationOp::Join { .. } | IrRelationOp::Group { .. }) | None => {
                    return false;
                }
            }
        }
    }

    /// The occurrence target fields read from one source binding by this
    /// relational plan. The walk follows typed operator inputs, so new
    /// relational operators must state which columns they read here.
    /// Edge-parity assertions read targets from their dedicated edge rows, not
    /// from an occurrence row, and therefore do not appear in this demand.
    pub fn occurrence_target_fields_for_source(&self, source: &str) -> Vec<&'static str> {
        let mut read = [false; 3];
        for relation in &self.relations {
            match &relation.op {
                IrRelationOp::Source { .. } => {}
                IrRelationOp::Project { columns, .. } => {
                    for column in columns {
                        record_occurrence_target_field(source, &column.source, &mut read);
                    }
                }
                IrRelationOp::Filter { predicates, .. } => {
                    for predicate in predicates {
                        record_occurrence_target_field(source, predicate.column(), &mut read);
                        if let IrPredicate::Compare {
                            right: IrOperand::Column(column),
                            ..
                        } = predicate
                        {
                            record_occurrence_target_field(source, column, &mut read);
                        }
                    }
                }
                IrRelationOp::Join { on, .. } => {
                    for key in on {
                        record_occurrence_target_field(source, &key.left, &mut read);
                        record_occurrence_target_field(source, &key.right, &mut read);
                    }
                }
                IrRelationOp::Group { by, aggregates, .. } => {
                    for column in by {
                        record_occurrence_target_field(source, column, &mut read);
                    }
                    for aggregate in aggregates {
                        if let Some(column) = &aggregate.value {
                            record_occurrence_target_field(source, column, &mut read);
                        }
                        if let Some(sequences) = &aggregate.sequences {
                            for column in [
                                &sequences.left.position,
                                &sequences.left.value,
                                &sequences.right.position,
                                &sequences.right.value,
                            ] {
                                record_occurrence_target_field(source, column, &mut read);
                            }
                        }
                        if let Some((left, right)) = &aggregate.sets {
                            record_occurrence_target_field(source, left, &mut read);
                            record_occurrence_target_field(source, right, &mut read);
                        }
                        for predicate in &aggregate.predicates {
                            record_occurrence_target_field(source, predicate.column(), &mut read);
                            if let IrPredicate::Compare {
                                right: IrOperand::Column(column),
                                ..
                            } = predicate
                            {
                                record_occurrence_target_field(source, column, &mut read);
                            }
                        }
                    }
                }
            }
        }
        ["target_id", "target_kind", "target_count"]
            .into_iter()
            .zip(read)
            .filter_map(|(field, was_read)| was_read.then_some(field))
            .collect()
    }
}

fn record_occurrence_target_field(source: &str, column: &IrColumn, read: &mut [bool; 3]) {
    if column.qualifier != source {
        return;
    }
    let index = match column.name.as_str() {
        "target_id" => 0,
        "target_kind" => 1,
        "target_count" => 2,
        _ => return,
    };
    read[index] = true;
}

/// The RQL expansion steps published by the relation-schema catalog.
pub const ALL_RQL_RELATION_EXPANSION_STEPS: &[QueryStepOp] = &[
    QueryStepOp::ReceiverOutcome,
    QueryStepOp::ReceiverEvidence,
    QueryStepOp::MemberSelection,
    QueryStepOp::CandidatesOf,
    QueryStepOp::CandidateHierarchy,
    QueryStepOp::MemberFamily,
    QueryStepOp::FamilyEdges,
    QueryStepOp::DispatchOutcome,
    QueryStepOp::DispatchTargets,
];

/// Project the RQL validator's typed step contract into the relation-schema
/// catalog. The authoring layer keeps no separate expansion type table.
pub fn expansion_result_domain(
    source: DetailedCodeQueryDomain,
    step: QueryStepOp,
) -> Option<DetailedCodeQueryDomain> {
    let step = QueryStep::from_label(step.label())
        .expect("the relation expansion catalog contains only defaultable RQL steps");
    step.output_kind(source.query_value_kind())
        .map(DetailedCodeQueryDomain::from_query_value_kind)
}

/// The schema a join publishes: an inner join concatenates both sides, a left
/// join concatenates the right side as nullable fields, and the two filtering
/// joins publish the left side only.
pub fn join_schema(left: &IrSchema, right: &IrSchema, kind: IrJoinKind) -> IrSchema {
    let mut fields = left.fields().to_vec();
    match kind {
        IrJoinKind::Inner => fields.extend(right.fields().iter().cloned()),
        IrJoinKind::Left => fields.extend(right.fields().iter().cloned().map(|mut field| {
            field.nullable = true;
            field
        })),
        IrJoinKind::Semi | IrJoinKind::Anti => {}
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
    schema_from_row_fields(
        qualifier,
        domain.row_fields().iter().map(|field| (field.name, field)),
    )
}

/// The schema published by a query binding after all RQL projections.
pub fn query_schema(
    qualifier: &str,
    fields: &[(String, brokk_bifrost_rql::structural::CodeQueryRowField)],
) -> IrSchema {
    schema_from_row_fields(
        qualifier,
        fields.iter().map(|(name, field)| (name.as_str(), field)),
    )
}

fn schema_from_row_fields<'a>(
    qualifier: &str,
    fields: impl IntoIterator<Item = (impl Into<String>, &'a CodeQueryRowField)>,
) -> IrSchema {
    IrSchema::new(
        fields
            .into_iter()
            .map(|(name, field)| IrField {
                column: IrColumn::new(qualifier, name),
                scalar_type: field.scalar_type,
                nullable: field.nullable,
                value_domain: field.value_domain,
            })
            .collect(),
    )
}
