//! C/C++ statement-level construct labels used by structural queries, with
//! the nested-loop relation also shared by the C# adapter.
//!
//! The labels are deliberately separate from the language-neutral normalized
//! kind vocabulary. A normalized kind identifies syntax such as a switch or a
//! loop; these facts identify a bounded, rule-shaped aggregate derived from
//! that syntax (for example, a long switch case or a repeated loop variable).

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
pub struct CppStatementFact {
    pub range: Range,
    pub kind: StatementFactKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CppConditionFact {
    pub range: Range,
    pub logical_operator_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CppLoopFact {
    pub range: Range,
    pub variable: Option<String>,
    pub body_statement_count: usize,
    pub tightly_bounded: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CppSwitchFact {
    pub range: Range,
    pub case_count: usize,
    pub default_present: bool,
    pub long_case: bool,
    pub missing_enum_case: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CppSwitchCaseFact {
    pub range: Range,
    pub value: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CppLabelFact {
    pub range: Range,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CppGotoFact {
    pub range: Range,
    pub target: String,
    pub forward: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CppEnumFact {
    pub range: Range,
    pub name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CppEnumeratorFact {
    pub range: Range,
    pub enum_range: Range,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CppStatementFactRows {
    pub statements: Vec<CppStatementFact>,
    pub conditions: Vec<CppConditionFact>,
    pub loops: Vec<CppLoopFact>,
    pub switches: Vec<CppSwitchFact>,
    pub switch_cases: Vec<CppSwitchCaseFact>,
    pub labels: Vec<CppLabelFact>,
    pub gotos: Vec<CppGotoFact>,
    pub enums: Vec<CppEnumFact>,
    pub enumerators: Vec<CppEnumeratorFact>,
}

impl CppStatementFactRows {
    pub fn valid(&self) -> bool {
        let valid_range = |range: &Range| range.start_byte <= range.end_byte;
        self.statements.iter().all(|fact| valid_range(&fact.range))
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
        let mut bytes = self.statements.capacity() * std::mem::size_of::<CppStatementFact>()
            + self.conditions.capacity() * std::mem::size_of::<CppConditionFact>()
            + self.loops.capacity() * std::mem::size_of::<CppLoopFact>()
            + self.switches.capacity() * std::mem::size_of::<CppSwitchFact>()
            + self.switch_cases.capacity() * std::mem::size_of::<CppSwitchCaseFact>()
            + self.labels.capacity() * std::mem::size_of::<CppLabelFact>()
            + self.gotos.capacity() * std::mem::size_of::<CppGotoFact>()
            + self.enums.capacity() * std::mem::size_of::<CppEnumFact>()
            + self.enumerators.capacity() * std::mem::size_of::<CppEnumeratorFact>();
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
