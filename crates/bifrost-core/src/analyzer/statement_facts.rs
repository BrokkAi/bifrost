//! Language-neutral, source-local statement facts.

pub mod producer;

use super::Range;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StatementFactKind {
    AllocaInLoop,
    ComplexBlock,
    ComplexCondition,
    EmptyBlock,
    LongSwitch,
    MissingCaseInSwitch,
    NestedLoopsWithSameVariable,
    UseOfGoto,
}

impl StatementFactKind {
    pub const ALL: &[Self] = &[
        Self::AllocaInLoop,
        Self::ComplexBlock,
        Self::ComplexCondition,
        Self::EmptyBlock,
        Self::LongSwitch,
        Self::MissingCaseInSwitch,
        Self::NestedLoopsWithSameVariable,
        Self::UseOfGoto,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::AllocaInLoop => "alloca-in-loop",
            Self::ComplexBlock => "complex-block",
            Self::ComplexCondition => "complex-condition",
            Self::EmptyBlock => "empty-block",
            Self::LongSwitch => "long-switch",
            Self::MissingCaseInSwitch => "missing-case-in-switch",
            Self::NestedLoopsWithSameVariable => "nested-loops-with-same-variable",
            Self::UseOfGoto => "use-of-goto",
        }
    }

    pub const fn construct(self) -> &'static str {
        match self {
            Self::AllocaInLoop => "cpp_alloca_in_loop",
            Self::ComplexBlock => "cpp_complex_block",
            Self::ComplexCondition => "cpp_complex_condition",
            Self::EmptyBlock => "cpp_empty_block",
            Self::LongSwitch => "cpp_long_switch",
            Self::MissingCaseInSwitch => "cpp_missing_case_in_switch",
            Self::NestedLoopsWithSameVariable => "cpp_nested_loops_with_same_variable",
            Self::UseOfGoto => "cpp_use_of_goto",
        }
    }

    pub fn from_label(label: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|kind| kind.label() == label)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatementFact {
    pub range: Range,
    pub kind: StatementFactKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConditionFact {
    pub range: Range,
    pub logical_operator_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoopFact {
    pub range: Range,
    pub variable: Option<String>,
    pub body_statement_count: usize,
    pub tightly_bounded: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwitchFact {
    pub range: Range,
    pub case_count: usize,
    pub default_present: bool,
    pub long_case: bool,
    pub missing_enum_case: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwitchCaseFact {
    pub range: Range,
    pub value: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabelFact {
    pub range: Range,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GotoFact {
    pub range: Range,
    pub target: String,
    pub forward: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnumFact {
    pub range: Range,
    pub name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnumeratorFact {
    pub range: Range,
    pub enum_range: Range,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StatementFactRows {
    pub statements: Vec<StatementFact>,
    /// Owners whose conditional-compilation activation is unproven.
    pub undecided: Vec<StatementFact>,
    pub conditions: Vec<ConditionFact>,
    pub loops: Vec<LoopFact>,
    pub switches: Vec<SwitchFact>,
    pub switch_cases: Vec<SwitchCaseFact>,
    pub labels: Vec<LabelFact>,
    pub gotos: Vec<GotoFact>,
    pub enums: Vec<EnumFact>,
    pub enumerators: Vec<EnumeratorFact>,
}

impl StatementFactRows {
    pub fn valid(&self) -> bool {
        let valid_range = |range: &Range| range.start_byte <= range.end_byte;
        self.statements.iter().all(|fact| valid_range(&fact.range))
            && self.undecided.iter().all(|fact| valid_range(&fact.range))
            && self.conditions.iter().all(|fact| valid_range(&fact.range))
            && self.loops.iter().all(|fact| valid_range(&fact.range))
            && self.switches.iter().all(|fact| valid_range(&fact.range))
            && self
                .switch_cases
                .iter()
                .all(|fact| valid_range(&fact.range))
            && self.labels.iter().all(|fact| valid_range(&fact.range))
            && self.gotos.iter().all(|fact| valid_range(&fact.range))
            && self.enums.iter().all(|fact| valid_range(&fact.range))
            && self.enumerators.iter().all(|fact| {
                valid_range(&fact.range)
                    && valid_range(&fact.enum_range)
                    && fact.enum_range.contains(&fact.range)
            })
    }

    pub fn estimated_retained_bytes(&self) -> usize {
        let mut bytes = (self.statements.capacity() + self.undecided.capacity())
            * std::mem::size_of::<StatementFact>()
            + self.conditions.capacity() * std::mem::size_of::<ConditionFact>()
            + self.loops.capacity() * std::mem::size_of::<LoopFact>()
            + self.switches.capacity() * std::mem::size_of::<SwitchFact>()
            + self.switch_cases.capacity() * std::mem::size_of::<SwitchCaseFact>()
            + self.labels.capacity() * std::mem::size_of::<LabelFact>()
            + self.gotos.capacity() * std::mem::size_of::<GotoFact>()
            + self.enums.capacity() * std::mem::size_of::<EnumFact>()
            + self.enumerators.capacity() * std::mem::size_of::<EnumeratorFact>();
        for loop_fact in &self.loops {
            bytes += loop_fact.variable.as_ref().map_or(0, String::capacity);
        }
        for case in &self.switch_cases {
            bytes += case.value.as_ref().map_or(0, String::capacity);
        }
        for label in &self.labels {
            bytes += label.name.capacity();
        }
        for goto in &self.gotos {
            bytes += goto.target.capacity();
        }
        for enumeration in &self.enums {
            bytes += enumeration.name.as_ref().map_or(0, String::capacity);
        }
        for enumerator in &self.enumerators {
            bytes += enumerator.name.capacity();
        }
        bytes
    }
}
