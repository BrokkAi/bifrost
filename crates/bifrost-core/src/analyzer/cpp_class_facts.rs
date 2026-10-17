//! Structured C++ class, special-member, and exception facts.
//!
//! These rows are deliberately separate from the canonical declaration rows.
//! They describe syntax which can occur inside a declaration (a catch or throw
//! operand, for example) and therefore cannot be represented by one
//! `SourceDeclarationId` without losing the source shape that selected it.

use super::Range;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CppClassFactKind {
    AssignmentDoesNotReturnThis,
    CatchByValue,
    ConstructorDelegation,
    ConstructorUsedAsCopyConstructor,
    RuleOfThree,
    RuleOfTwo,
    ThrowingPointer,
    UndisciplinedMultipleInheritance,
}

impl CppClassFactKind {
    pub const ALL: &[Self] = &[
        Self::AssignmentDoesNotReturnThis,
        Self::CatchByValue,
        Self::ConstructorDelegation,
        Self::ConstructorUsedAsCopyConstructor,
        Self::RuleOfThree,
        Self::RuleOfTwo,
        Self::ThrowingPointer,
        Self::UndisciplinedMultipleInheritance,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::AssignmentDoesNotReturnThis => "assignment-does-not-return-this",
            Self::CatchByValue => "catch-by-value",
            Self::ConstructorDelegation => "constructor-delegation",
            Self::ConstructorUsedAsCopyConstructor => "constructor-used-as-copy-constructor",
            Self::RuleOfThree => "rule-of-three",
            Self::RuleOfTwo => "rule-of-two",
            Self::ThrowingPointer => "throwing-pointer",
            Self::UndisciplinedMultipleInheritance => "undisciplined-multiple-inheritance",
        }
    }

    pub fn from_label(label: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|kind| kind.label() == label)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CppAccessSpecifier {
    Public,
    Protected,
    Private,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CppMemberRole {
    Method,
    Constructor,
    Destructor,
    AssignmentOperator,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CppSpecialMemberKind {
    DefaultConstructor,
    CopyConstructor,
    MoveConstructor,
    CopyAssignment,
    MoveAssignment,
    Destructor,
    #[default]
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CppSpecialMemberState {
    Declared,
    Defaulted,
    Deleted,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CppAssignmentReturnShape {
    ReferenceToThis,
    ReferenceOther,
    Value,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CppParameterValueCategory {
    Value,
    LValueReference,
    RValueReference,
    Pointer,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CppThrowOperandShape {
    Rethrow,
    Pointer,
    Value,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CppClassFact {
    pub range: Range,
    pub path: Vec<String>,
    pub is_interface: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CppMemberFact {
    pub range: Range,
    pub owner: Vec<String>,
    pub name: String,
    pub role: CppMemberRole,
    pub special_member: CppSpecialMemberKind,
    pub state: CppSpecialMemberState,
    pub access: CppAccessSpecifier,
    pub copy_parameter: bool,
    pub remaining_parameters_defaulted: bool,
    pub assignment_return: CppAssignmentReturnShape,
    pub initializer_target: Option<Vec<String>>,
    pub delegation_calls: Vec<Range>,
    pub pure_virtual: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CppCatchFact {
    pub range: Range,
    pub value_category: CppParameterValueCategory,
    pub type_name: Vec<String>,
    pub class_type: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CppThrowFact {
    pub range: Range,
    pub operand_shape: CppThrowOperandShape,
    pub thrown_type: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CppClassFactRows {
    pub classes: Vec<CppClassFact>,
    pub members: Vec<CppMemberFact>,
    pub catches: Vec<CppCatchFact>,
    pub throws: Vec<CppThrowFact>,
}

impl CppClassFactRows {
    pub fn valid(&self) -> bool {
        self.classes
            .iter()
            .all(|fact| fact.range.start_byte <= fact.range.end_byte)
            && self
                .members
                .iter()
                .all(|fact| fact.range.start_byte <= fact.range.end_byte)
            && self
                .members
                .iter()
                .flat_map(|fact| fact.delegation_calls.iter())
                .all(|range| range.start_byte <= range.end_byte)
            && self
                .catches
                .iter()
                .all(|fact| fact.range.start_byte <= fact.range.end_byte)
            && self
                .throws
                .iter()
                .all(|fact| fact.range.start_byte <= fact.range.end_byte)
    }

    pub fn estimated_retained_bytes(&self) -> usize {
        let mut bytes = self.classes.capacity() * std::mem::size_of::<CppClassFact>()
            + self.members.capacity() * std::mem::size_of::<CppMemberFact>()
            + self.catches.capacity() * std::mem::size_of::<CppCatchFact>()
            + self.throws.capacity() * std::mem::size_of::<CppThrowFact>();
        for class in &self.classes {
            bytes += class.path.capacity() * std::mem::size_of::<String>()
                + class.path.iter().map(String::capacity).sum::<usize>();
        }
        for member in &self.members {
            bytes += member.owner.capacity() * std::mem::size_of::<String>()
                + member.owner.iter().map(String::capacity).sum::<usize>()
                + member.name.capacity()
                + member.initializer_target.as_ref().map_or(0, |target| {
                    target.capacity() * std::mem::size_of::<String>()
                        + target.iter().map(String::capacity).sum::<usize>()
                })
                + member.delegation_calls.capacity() * std::mem::size_of::<Range>();
        }
        for catch in &self.catches {
            bytes += catch.type_name.capacity() * std::mem::size_of::<String>()
                + catch.type_name.iter().map(String::capacity).sum::<usize>();
        }
        for thrown in &self.throws {
            bytes += thrown.thrown_type.capacity() * std::mem::size_of::<String>()
                + thrown
                    .thrown_type
                    .iter()
                    .map(String::capacity)
                    .sum::<usize>();
        }
        bytes
    }
}
