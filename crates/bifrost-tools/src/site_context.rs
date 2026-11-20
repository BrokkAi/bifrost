//! Plain-data description of one selected program site.
//!
//! The record carries what a surface needs to say "this value, here": where
//! the site is, what role the selected node plays, and what is known about its
//! constant value. [`SiteContext`] is plain engine data. [`view`] is the one
//! wire form: RQL result rows and the flow tools both embed [`SiteContextView`],
//! so the CLI and MCP render a site identically.

use std::ops::Range;

use brokk_bifrost_analysis::analyzer::semantic::{
    SemanticBudgetExceeded, SemanticCapability, SemanticProviderError,
};
use brokk_bifrost_core::admitted_text::AdmittedText;
use brokk_bifrost_core::analyzer::model::ProjectFile;
use brokk_bifrost_core::retention_budget::RetentionBudget;
use schemars::JsonSchema;
use serde::Serialize;

/// Why a site has no known constant value.
///
/// Never empty: a [`SiteValue::Unknown`] always names exactly one cause.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnknownValueCause {
    /// The site was analyzed and its value is not a compile-time constant.
    NotConstant,
    /// The analysis proved a constant, but the payload (the literal text or
    /// number) is not retained in the facts this query reads.
    ConstantPayloadUnavailable,
    /// The site has no source node whose text could carry a constant: an
    /// external declaration or a summary procedure.
    NoSourceNode,
    /// The value was not analyzed; the typed engine cause says why.
    NotAnalyzed(NotAnalyzedCause),
}

/// The typed engine cause when a site's value was not analyzed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotAnalyzedCause {
    /// The language provider does not support the capability.
    Unsupported(SemanticCapability),
    /// The provider reported the outcome as unknown.
    Unknown,
    /// A semantic budget dimension ran out.
    ExceededBudget(SemanticBudgetExceeded),
    /// The request was cancelled.
    Cancelled,
    /// The provider failed.
    ProviderFailed(SemanticProviderError),
}

/// A constant payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KnownValue {
    /// The decoded value of a string literal.
    Str(String),
    /// The normalized decimal value of an integer literal, taken from the
    /// structural `IntegerLiteralValue`: `0x10` is `"16"`, a negated literal
    /// carries a leading `-`.
    Int(String),
}

/// What is known about the value at a site. Never empty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SiteValue {
    /// A constant with its payload.
    Known(KnownValue),
    /// No constant; the cause says why.
    Unknown(UnknownValueCause),
}

impl SiteValue {
    /// The string payload of a `Known(Str)` value, if any.
    pub fn known_str(&self) -> Option<&str> {
        match self {
            Self::Known(KnownValue::Str(text)) => Some(text),
            _ => None,
        }
    }
}

/// The role the selected node plays at its site. A caller also passes it to
/// select a node: the role chooses which kind of node a position may select.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SiteRole {
    /// An expression that produces a value.
    Value,
    /// A call expression.
    Call,
    /// A name that is bound to a value (a declaration or assignment target).
    Binding,
    /// An argument of a call, by zero-based position and optional keyword.
    /// `index` is the written position in the call's argument list, counting
    /// positional and keyword arguments in source order; the receiver is never
    /// an argument. Arguments with no written argument list, such as
    /// macro-admitted candidates, use role `value`.
    Argument { index: usize, name: Option<String> },
    /// The receiver of a method call or member access.
    Receiver,
    /// A return statement.
    Return,
    /// A write to a field or member. `member` is its fully qualified name as
    /// `CodeUnit::fq_name` renders it.
    FieldWrite { member: String },
    /// A read of a field or member. `member` is its fully qualified name as
    /// `CodeUnit::fq_name` renders it.
    FieldRead { member: String },
    /// A statement.
    Statement,
}

/// Where a site is. Never empty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SiteLocation {
    /// A node of a workspace source file.
    Source {
        path: ProjectFile,
        /// Byte range into the file's source.
        byte_range: Range<usize>,
        /// 1-based start line and column (columns count characters), as
        /// `text_utils::line_column_for_offset` computes them.
        start_line: usize,
        start_column: usize,
        /// 1-based end line and column.
        end_line: usize,
        end_column: usize,
        /// The source text of the node.
        text: String,
    },
    /// The node exists at this byte range in the request's analysis, but its
    /// text and coordinates were not loaded for this response; `reason` says
    /// why.
    Unrendered {
        path: ProjectFile,
        byte_range: Range<usize>,
        reason: UnrenderedReason,
    },
    /// A declaration outside the workspace. `declaration` is its fully
    /// qualified name as `CodeUnit::fq_name` renders it.
    External { declaration: String },
    /// A modeled procedure summary that has no source node. `procedure` is the
    /// procedure's fully qualified name as `CodeUnit::fq_name` renders it.
    Summary { procedure: String },
}

/// Why a site's text and coordinates were not loaded for a response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum UnrenderedReason {
    /// The response's source render budget was exhausted.
    RenderBudget,
    /// The request held two different source snapshots of the file.
    ConflictingSources,
    /// The analyzer had no source to give for the file, or could not
    /// attribute a read of it to the file's parse variant. A warm analyzer
    /// keeps the indexed source after the file changes, so this needs an
    /// analyzer that no longer holds it and a file with no readable blob, or
    /// a store error while looking up the parse variant.
    SourceUnavailable,
}

/// One selected site: where it is, its role, and what is known of its value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SiteContext {
    pub site: SiteLocation,
    pub role: SiteRole,
    pub value: SiteValue,
}

/// The wire form of a [`SiteContext`].
#[cfg_attr(feature = "query-result-fixtures", derive(Default))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct SiteContextView {
    pub site: SiteLocationView,
    pub role: SiteRoleView,
    pub value: SiteValueView,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SiteLocationView {
    Source {
        /// Workspace-relative, slash-separated.
        path: AdmittedText,
        start_byte: usize,
        end_byte: usize,
        start_line: usize,
        start_column: usize,
        end_line: usize,
        end_column: usize,
        text: AdmittedText,
    },
    /// The node exists at this byte range in the request's analysis, but its
    /// text and coordinates were not loaded for this response; `reason` says
    /// why.
    Unrendered {
        /// Workspace-relative, slash-separated.
        path: AdmittedText,
        start_byte: usize,
        end_byte: usize,
        reason: UnrenderedReason,
    },
    External {
        declaration: AdmittedText,
    },
    Summary {
        procedure: AdmittedText,
    },
}

#[cfg(feature = "query-result-fixtures")]
impl Default for SiteLocationView {
    fn default() -> Self {
        Self::Source {
            path: AdmittedText::empty(),
            start_byte: 0,
            end_byte: 0,
            start_line: 1,
            start_column: 1,
            end_line: 1,
            end_column: 1,
            text: AdmittedText::empty(),
        }
    }
}

#[cfg_attr(feature = "query-result-fixtures", derive(Default))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SiteRoleView {
    #[cfg_attr(feature = "query-result-fixtures", default)]
    Value,
    Call,
    Binding,
    Argument {
        index: usize,
        #[serde(skip_serializing_if = "Option::is_none")]
        name: Option<AdmittedText>,
    },
    Receiver,
    Return,
    FieldWrite {
        member: AdmittedText,
    },
    FieldRead {
        member: AdmittedText,
    },
    Statement,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SiteValueView {
    Known { value: KnownValueView },
    Unknown { cause: UnknownValueCauseView },
}

#[cfg(feature = "query-result-fixtures")]
impl Default for SiteValueView {
    fn default() -> Self {
        Self::Unknown {
            cause: UnknownValueCauseView::NotConstant,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum KnownValueView {
    Str {
        value: AdmittedText,
    },
    /// The normalized decimal value.
    Int {
        value: AdmittedText,
    },
}

#[cfg(feature = "query-result-fixtures")]
impl Default for KnownValueView {
    fn default() -> Self {
        Self::Str {
            value: AdmittedText::empty(),
        }
    }
}

#[cfg_attr(feature = "query-result-fixtures", derive(Default))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum UnknownValueCauseView {
    #[cfg_attr(feature = "query-result-fixtures", default)]
    NotConstant,
    ConstantPayloadUnavailable,
    NoSourceNode,
    NotAnalyzed {
        cause: NotAnalyzedCauseView,
    },
}

#[cfg_attr(feature = "query-result-fixtures", derive(Default))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NotAnalyzedCauseView {
    Unsupported {
        /// The `SemanticCapability` label.
        capability: AdmittedText,
    },
    #[cfg_attr(feature = "query-result-fixtures", default)]
    Unknown,
    ExceededBudget {
        /// The public budget lane label: source, rows, retained_bytes, files.
        lane: AdmittedText,
        limit: usize,
        attempted: usize,
    },
    Cancelled,
    ProviderFailed {
        error: ProviderErrorKind,
        /// The provider error's display text.
        message: AdmittedText,
    },
}

#[cfg_attr(feature = "query-result-fixtures", derive(Default))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProviderErrorKind {
    CandidateLocatorRefusal,
    SourceAccess,
    SourceAdmissionRefused,
    InvalidIdentity,
    InvalidArtifact,
    #[cfg_attr(feature = "query-result-fixtures", default)]
    Internal,
}

/// A presentation refusal is distinct from a semantic provider failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SiteAdmissionRefusal {
    OwnerUnavailable,
    RetainedBytes,
}

/// Admission against the existing analyzer owner, never an independent pool.
pub struct SiteAdmission<'a> {
    owner: Option<&'a RetentionBudget>,
}

impl<'a> SiteAdmission<'a> {
    pub fn new(owner: Option<&'a RetentionBudget>) -> Self {
        Self { owner }
    }

    pub fn copy(&self, text: &str) -> Result<AdmittedText, SiteAdmissionRefusal> {
        let owner = self.owner.ok_or(SiteAdmissionRefusal::OwnerUnavailable)?;
        AdmittedText::try_copy(owner, text).ok_or(SiteAdmissionRefusal::RetainedBytes)
    }

    pub fn formatted(
        &self,
        value: std::fmt::Arguments<'_>,
    ) -> Result<AdmittedText, SiteAdmissionRefusal> {
        let owner = self.owner.ok_or(SiteAdmissionRefusal::OwnerUnavailable)?;
        AdmittedText::try_format(owner, value).ok_or(SiteAdmissionRefusal::RetainedBytes)
    }

    pub fn path(&self, file: &ProjectFile) -> Result<AdmittedText, SiteAdmissionRefusal> {
        self.formatted(format_args!(
            "{}",
            brokk_bifrost_core::path_utils::display_workspace_relative_slash_path(file.rel_path())
        ))
    }
}

/// A borrowed role, so dynamic metadata is admitted before its first copy.
#[derive(Clone, Copy)]
pub enum SiteRoleRef<'a> {
    Value,
    Call,
    Binding,
    Argument { index: usize, name: Option<&'a str> },
    Receiver,
    Return,
    FieldWrite { member: &'a str },
    FieldRead { member: &'a str },
    Statement,
}

impl<'a> From<&'a SiteRole> for SiteRoleRef<'a> {
    fn from(role: &'a SiteRole) -> Self {
        match role {
            SiteRole::Value => Self::Value,
            SiteRole::Call => Self::Call,
            SiteRole::Binding => Self::Binding,
            SiteRole::Argument { index, name } => Self::Argument {
                index: *index,
                name: name.as_deref(),
            },
            SiteRole::Receiver => Self::Receiver,
            SiteRole::Return => Self::Return,
            SiteRole::FieldWrite { member } => Self::FieldWrite { member },
            SiteRole::FieldRead { member } => Self::FieldRead { member },
            SiteRole::Statement => Self::Statement,
        }
    }
}

pub fn role_view(
    role: SiteRoleRef<'_>,
    admission: &SiteAdmission<'_>,
) -> Result<SiteRoleView, SiteAdmissionRefusal> {
    Ok(match role {
        SiteRoleRef::Value => SiteRoleView::Value,
        SiteRoleRef::Call => SiteRoleView::Call,
        SiteRoleRef::Binding => SiteRoleView::Binding,
        SiteRoleRef::Argument { index, name } => SiteRoleView::Argument {
            index,
            name: name.map(|name| admission.copy(name)).transpose()?,
        },
        SiteRoleRef::Receiver => SiteRoleView::Receiver,
        SiteRoleRef::Return => SiteRoleView::Return,
        SiteRoleRef::FieldWrite { member } => SiteRoleView::FieldWrite {
            member: admission.copy(member)?,
        },
        SiteRoleRef::FieldRead { member } => SiteRoleView::FieldRead {
            member: admission.copy(member)?,
        },
        SiteRoleRef::Statement => SiteRoleView::Statement,
    })
}

/// A borrowed constant payload or a structural explanation of its absence.
pub enum SiteValueRef<'a> {
    Str(&'a str),
    Int { decimal: &'a str, negative: bool },
    Unknown(UnknownValueCauseRef<'a>),
}

pub enum UnknownValueCauseRef<'a> {
    NotConstant,
    ConstantPayloadUnavailable,
    NoSourceNode,
    NotAnalyzed(&'a NotAnalyzedCause),
}

impl<'a> From<&'a SiteValue> for SiteValueRef<'a> {
    fn from(value: &'a SiteValue) -> Self {
        match value {
            SiteValue::Known(KnownValue::Str(text)) => Self::Str(text),
            SiteValue::Known(KnownValue::Int(decimal)) => Self::Int {
                decimal,
                negative: false,
            },
            SiteValue::Unknown(cause) => Self::Unknown(match cause {
                UnknownValueCause::NotConstant => UnknownValueCauseRef::NotConstant,
                UnknownValueCause::ConstantPayloadUnavailable => {
                    UnknownValueCauseRef::ConstantPayloadUnavailable
                }
                UnknownValueCause::NoSourceNode => UnknownValueCauseRef::NoSourceNode,
                UnknownValueCause::NotAnalyzed(cause) => UnknownValueCauseRef::NotAnalyzed(cause),
            }),
        }
    }
}

pub fn value_view(
    value: SiteValueRef<'_>,
    admission: &SiteAdmission<'_>,
) -> Result<SiteValueView, SiteAdmissionRefusal> {
    Ok(match value {
        SiteValueRef::Str(value) => SiteValueView::Known {
            value: KnownValueView::Str {
                value: admission.copy(value)?,
            },
        },
        SiteValueRef::Int { decimal, negative } => SiteValueView::Known {
            value: KnownValueView::Int {
                value: if negative {
                    admission.formatted(format_args!("-{decimal}"))?
                } else {
                    admission.copy(decimal)?
                },
            },
        },
        SiteValueRef::Unknown(cause) => SiteValueView::Unknown {
            cause: match cause {
                UnknownValueCauseRef::NotConstant => UnknownValueCauseView::NotConstant,
                UnknownValueCauseRef::ConstantPayloadUnavailable => {
                    UnknownValueCauseView::ConstantPayloadUnavailable
                }
                UnknownValueCauseRef::NoSourceNode => UnknownValueCauseView::NoSourceNode,
                UnknownValueCauseRef::NotAnalyzed(cause) => UnknownValueCauseView::NotAnalyzed {
                    cause: not_analyzed_view(cause, admission)?,
                },
            },
        },
    })
}

impl SiteValueView {
    pub fn known_str(&self) -> Option<&AdmittedText> {
        match self {
            Self::Known {
                value: KnownValueView::Str { value },
            } => Some(value),
            _ => None,
        }
    }
}

/// Convert existing semantic site data to the shared admitted wire form.
pub fn view(
    context: &SiteContext,
    admission: &SiteAdmission<'_>,
) -> Result<SiteContextView, SiteAdmissionRefusal> {
    // Mandatory metadata and the exact value precede optional source retention.
    let role = role_view((&context.role).into(), admission)?;
    let value = value_view((&context.value).into(), admission)?;
    let site = match &context.site {
        SiteLocation::Source {
            path,
            byte_range,
            start_line,
            start_column,
            end_line,
            end_column,
            text,
        } => {
            let path = admission.path(path)?;
            match admission.copy(text) {
                Ok(text) => SiteLocationView::Source {
                    path,
                    start_byte: byte_range.start,
                    end_byte: byte_range.end,
                    start_line: *start_line,
                    start_column: *start_column,
                    end_line: *end_line,
                    end_column: *end_column,
                    text,
                },
                Err(SiteAdmissionRefusal::RetainedBytes) => SiteLocationView::Unrendered {
                    path,
                    start_byte: byte_range.start,
                    end_byte: byte_range.end,
                    reason: UnrenderedReason::RenderBudget,
                },
                Err(error) => return Err(error),
            }
        }
        SiteLocation::Unrendered {
            path,
            byte_range,
            reason,
        } => SiteLocationView::Unrendered {
            path: admission.path(path)?,
            start_byte: byte_range.start,
            end_byte: byte_range.end,
            reason: *reason,
        },
        SiteLocation::External { declaration } => SiteLocationView::External {
            declaration: admission.copy(declaration)?,
        },
        SiteLocation::Summary { procedure } => SiteLocationView::Summary {
            procedure: admission.copy(procedure)?,
        },
    };
    Ok(SiteContextView { site, role, value })
}

/// The shared wire form of a not-analyzed cause, with admitted dynamic text.
pub fn not_analyzed_view(
    cause: &NotAnalyzedCause,
    admission: &SiteAdmission<'_>,
) -> Result<NotAnalyzedCauseView, SiteAdmissionRefusal> {
    Ok(match cause {
        NotAnalyzedCause::Unsupported(capability) => NotAnalyzedCauseView::Unsupported {
            capability: AdmittedText::from_static(capability.label()),
        },
        NotAnalyzedCause::Unknown => NotAnalyzedCauseView::Unknown,
        NotAnalyzedCause::ExceededBudget(exceeded) => NotAnalyzedCauseView::ExceededBudget {
            lane: AdmittedText::from_static(exceeded.dimension().public_lane().label()),
            limit: exceeded.limit(),
            attempted: exceeded.attempted(),
        },
        NotAnalyzedCause::Cancelled => NotAnalyzedCauseView::Cancelled,
        NotAnalyzedCause::ProviderFailed(error) => NotAnalyzedCauseView::ProviderFailed {
            error: match error {
                SemanticProviderError::CandidateLocatorRefusal(_) => {
                    ProviderErrorKind::CandidateLocatorRefusal
                }
                SemanticProviderError::SourceAccess(_) => ProviderErrorKind::SourceAccess,
                SemanticProviderError::SourceAdmissionRefused { .. } => {
                    ProviderErrorKind::SourceAdmissionRefused
                }
                SemanticProviderError::InvalidIdentity(_) => ProviderErrorKind::InvalidIdentity,
                SemanticProviderError::InvalidArtifact(_) => ProviderErrorKind::InvalidArtifact,
                SemanticProviderError::Internal(_) => ProviderErrorKind::Internal,
            },
            message: admission.formatted(format_args!("{error}"))?,
        },
    })
}
