//! Typed, source-backed C/C++ expression observations.
//!
//! These rows deliberately describe syntax selected by a tree-sitter node.
//! They do not try to recover ABI facts, overload choices, or other semantic
//! claims that the producer cannot prove from the source snapshot.

use super::source_facts::{SourceFactRows, SourceOccurrenceId};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CppExpressionKind {
    ArrayParameter,
    BitField,
    EnumDefinition,
    Enumerator,
    FunctionParameter,
    FunctionSignature,
    IntegerLiteral,
    StringLiteral,
    LoopVariable,
    SizeofExpression,
}

impl CppExpressionKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::ArrayParameter => "array_parameter",
            Self::BitField => "bit_field",
            Self::EnumDefinition => "enum_definition",
            Self::Enumerator => "enumerator",
            Self::FunctionParameter => "function_parameter",
            Self::FunctionSignature => "function_signature",
            Self::IntegerLiteral => "integer_literal",
            Self::StringLiteral => "string_literal",
            Self::LoopVariable => "loop_variable",
            Self::SizeofExpression => "sizeof_expression",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CppTypeForm {
    Builtin,
    Named,
    Pointer,
    Reference,
    Array,
    Function,
    #[default]
    Unknown,
}

impl CppTypeForm {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Builtin => "builtin",
            Self::Named => "named",
            Self::Pointer => "pointer",
            Self::Reference => "reference",
            Self::Array => "array",
            Self::Function => "function",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CppSignedness {
    Signed,
    Unsigned,
    Ambiguous,
    #[default]
    Unknown,
}

impl CppSignedness {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Signed => "signed",
            Self::Unsigned => "unsigned",
            Self::Ambiguous => "ambiguous",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CppSizeofOperandKind {
    Type,
    Expression,
}

impl CppSizeofOperandKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Type => "type",
            Self::Expression => "expression",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CppExpressionCompleteness {
    Complete,
    #[default]
    Open,
}

impl CppExpressionCompleteness {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Open => "open",
        }
    }
}

/// One AST-occurrence keyed expression/declaration observation.
///
/// Optional fields mean that the selected syntax does not prove that value.
/// `completeness_reason` is intentionally a scalar explanation rather than a
/// serialized substructure; consumers can report an open row without
/// mistaking an unavailable value for a negative fact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CppExpressionFact {
    pub occurrence: SourceOccurrenceId,
    pub kind: CppExpressionKind,
    pub name: Option<String>,
    pub type_text: Option<String>,
    pub type_form: CppTypeForm,
    pub signedness: CppSignedness,
    pub width_bits: Option<u16>,
    pub literal_text: Option<String>,
    pub integer_value: Option<i128>,
    pub array_extent: Option<u64>,
    pub array_is_reference: Option<bool>,
    pub parameter_by_value: Option<bool>,
    pub bit_field_width: Option<u64>,
    pub bit_field_anonymous: Option<bool>,
    pub enum_scoped: Option<bool>,
    pub enum_ordinal: Option<u32>,
    pub enum_value: Option<i128>,
    pub has_initializer: Option<bool>,
    pub enum_has_implicit_before_nonreference: Option<bool>,
    pub return_top_level_const: Option<bool>,
    pub member_function: Option<bool>,
    pub member_function_const: Option<bool>,
    pub type_size_bytes: Option<u64>,
    pub type_size_exact: Option<bool>,
    pub sizeof_operand_kind: Option<CppSizeofOperandKind>,
    pub sizeof_operand_is_parameter: Option<bool>,
    pub sizeof_has_side_effect: Option<bool>,
    pub loop_has_short_ancestor: Option<bool>,
    pub completeness: CppExpressionCompleteness,
    pub completeness_reason: Option<String>,
}

/// Query-lifetime source projection used by C++ expression relations. The
/// source arena remains the authority for ranges; rows refer to it by exact
/// occurrence identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CppExpressionSourceFacts {
    pub source: SourceFactRows,
    pub expressions: Vec<CppExpressionFact>,
}

impl CppExpressionFact {
    pub fn new(occurrence: SourceOccurrenceId, kind: CppExpressionKind) -> Self {
        Self {
            occurrence,
            kind,
            name: None,
            type_text: None,
            type_form: CppTypeForm::Unknown,
            signedness: CppSignedness::Unknown,
            width_bits: None,
            literal_text: None,
            integer_value: None,
            array_extent: None,
            array_is_reference: None,
            parameter_by_value: None,
            bit_field_width: None,
            bit_field_anonymous: None,
            enum_scoped: None,
            enum_ordinal: None,
            enum_value: None,
            has_initializer: None,
            enum_has_implicit_before_nonreference: None,
            return_top_level_const: None,
            member_function: None,
            member_function_const: None,
            type_size_bytes: None,
            type_size_exact: None,
            sizeof_operand_kind: None,
            sizeof_operand_is_parameter: None,
            sizeof_has_side_effect: None,
            loop_has_short_ancestor: None,
            completeness: CppExpressionCompleteness::Open,
            completeness_reason: None,
        }
    }

    pub fn complete(mut self) -> Self {
        self.completeness = CppExpressionCompleteness::Complete;
        self.completeness_reason = None;
        self
    }

    pub fn open(mut self, reason: impl Into<String>) -> Self {
        self.completeness = CppExpressionCompleteness::Open;
        self.completeness_reason = Some(reason.into());
        self
    }
}
