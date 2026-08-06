use super::*;

#[derive(Debug, Clone, Serialize)]
pub struct CodeQueryReferenceSite {
    pub path: String,
    pub language: &'static str,
    pub range: CodeQueryRange,
    pub target: CodeQueryDeclaration,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enclosing_declaration: Option<CodeQueryDeclaration>,
    pub usage_kind: &'static str,
    pub proof: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference_kind: Option<&'static str>,
}

/// One classified identifier position.
///
/// `ast_id` is the content-scoped identity of the underlying facts-arena node
/// and is minted with the same recipe a structural capture uses, so string
/// equality of two `ast_id`s *is* the correlation join between a capture and
/// the occurrence at that node. `id` additionally distinguishes the role, so a
/// node classified twice yields two addressable rows.
#[derive(Debug, Clone, Serialize)]
pub struct CodeQueryOccurrence {
    pub id: String,
    pub ast_id: String,
    pub path: String,
    pub language: &'static str,
    pub class: &'static str,
    pub role: &'static str,
    pub namespace: &'static str,
    pub range: CodeQueryRange,
    pub start_byte: usize,
    pub end_byte: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enclosing_symbol: Option<String>,
    pub raw_spelling: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decoded_spelling: Option<String>,
    pub target: CodeQueryOccurrenceTarget,
}

/// What a reference-class occurrence resolves to. A non-reference row is
/// always `none`, and a reference row never is: `unresolved` carries the exact
/// resolver status so an empty target is never mistaken for "not attempted".
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "target_kind", rename_all = "snake_case")]
pub enum CodeQueryOccurrenceTarget {
    None,
    Resolved {
        units: Vec<CodeQueryDeclaration>,
    },
    Lexical {
        name: String,
        kind: &'static str,
        range: CodeQueryRange,
    },
    Unresolved {
        status: &'static str,
    },
}

#[derive(Debug, Clone, Serialize)]
pub struct CodeQueryCallSite {
    pub path: String,
    pub language: &'static str,
    pub range: CodeQueryRange,
    pub callee_range: CodeQueryRange,
    pub caller: CodeQueryDeclaration,
    pub callee: CodeQueryDeclaration,
    pub call_kind: &'static str,
    pub proof: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receiver: Option<CodeQueryRange>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub arguments: Vec<CodeQueryCallArgument>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CodeQueryCallArgument {
    pub range: CodeQueryRange,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub position: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub formal_index: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub formal_name: Option<String>,
    #[serde(skip_serializing_if = "is_false")]
    pub variadic: bool,
    #[serde(skip_serializing_if = "is_false")]
    pub spread: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct CodeQueryExpressionSite {
    pub path: String,
    pub language: &'static str,
    pub range: CodeQueryRange,
    pub text: String,
    pub input_kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameter_index: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameter_name: Option<String>,
    pub caller_fq_name: String,
    pub callee_fq_name: String,
    pub call_range: CodeQueryRange,
}

#[derive(Debug, Clone, Serialize)]
pub struct CodeQueryReceiverAnalysis {
    pub site_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub site_ast_id: Option<String>,
    pub analysis_kind: &'static str,
    pub path: String,
    pub language: &'static str,
    pub range: CodeQueryRange,
    pub text: String,
    pub input_kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capture: Option<String>,
    pub outcome: &'static str,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub values: Vec<CodeQueryReceiverValue>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub member_targets: Vec<CodeQueryDeclaration>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<&'static str>,
}

/// The mandatory terminal row for one receiver/value analysis site. Evidence
/// rows may be empty, but this row always states why and whether that absence
/// is exhaustive.
#[derive(Debug, Clone, Serialize)]
pub struct CodeQueryReceiverOutcome {
    pub id: String,
    pub site_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub site_ast_id: Option<String>,
    pub path: String,
    pub language: &'static str,
    pub range: CodeQueryRange,
    pub analysis_kind: &'static str,
    pub outcome: &'static str,
    pub coverage: &'static str,
    pub candidate_count: usize,
    pub candidates_truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub semantic_unsupported: Option<&'static str>,
    pub setup_nodes: usize,
    pub summary_expansions: usize,
    pub scope_nodes: usize,
}

/// The mandatory member-selection summary row for one reference occurrence,
/// projected from the production resolver's own candidate trace. The row
/// exists even when the file records no trace for the occurrence, so an empty
/// candidate relation can never masquerade as a proven-empty selection.
#[derive(Debug, Clone, Serialize)]
pub struct CodeQueryMemberSelection {
    pub id: String,
    /// The occurrence's content-scoped AST identity; joins selection rows to
    /// occurrence and receiver rows without text or range comparison.
    pub site_ast_id: String,
    pub path: String,
    pub language: &'static str,
    pub range: CodeQueryRange,
    /// The decoded member spelling at the occurrence.
    pub member: String,
    pub role: &'static str,
    /// `selected`, `unresolved`, or `untraced`.
    pub outcome: &'static str,
    pub selected_count: usize,
    pub candidate_count: usize,
    /// `full`, `selection_only`, or `absent`.
    pub trace_completeness: &'static str,
    /// `exhaustive` for a full trace, `open` for a selection-only trace, and
    /// `unsupported` when the language records no trace at all.
    pub coverage: &'static str,
}

/// One typed receiver value retained for a site. Nested factory returns are
/// flattened into a parent-linked chain instead of nested presentation data.
#[derive(Debug, Clone, Serialize)]
pub struct CodeQueryReceiverEvidence {
    pub id: String,
    pub site_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub site_ast_id: Option<String>,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_evidence_id: Option<String>,
    pub ordinal: usize,
    pub chain_hop: usize,
    pub evidence_kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub declaration_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub declaration_fq_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub declaration_kind: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub factory_id: Option<String>,
    pub proof: &'static str,
    pub completeness: &'static str,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "receiver_value_kind", rename_all = "snake_case")]
pub enum CodeQueryReceiverValue {
    AllocationSite {
        type_declaration: CodeQueryDeclaration,
        allocation_site: CodeQuerySourceSite,
    },
    InstanceType {
        declaration: CodeQueryDeclaration,
    },
    ClassOrStaticObject {
        declaration: CodeQueryDeclaration,
    },
    ModuleOrExportObject {
        declaration: CodeQueryDeclaration,
    },
    CurrentReceiver {
        declaration: CodeQueryDeclaration,
    },
    FactoryReturn {
        factory: CodeQueryDeclaration,
        returned_value: Box<CodeQueryReceiverValue>,
    },
}

impl CodeQueryReceiverValue {
    pub fn render_text(&self) -> String {
        match self {
            Self::AllocationSite {
                type_declaration,
                allocation_site,
            } => format!(
                "allocation {} at {}:{}:{}",
                type_declaration.fq_name,
                allocation_site.path,
                allocation_site.range.start_line,
                allocation_site.range.start_column
            ),
            Self::InstanceType { declaration } => {
                format!("instance {}", declaration.fq_name)
            }
            Self::ClassOrStaticObject { declaration } => {
                format!("class/static {}", declaration.fq_name)
            }
            Self::ModuleOrExportObject { declaration } => {
                format!("module/export {}", declaration.fq_name)
            }
            Self::CurrentReceiver { declaration } => {
                format!("current receiver {}", declaration.fq_name)
            }
            Self::FactoryReturn {
                factory,
                returned_value,
            } => format!(
                "factory {} -> {}",
                factory.fq_name,
                returned_value.render_text()
            ),
        }
    }
}

impl CodeQueryReceiverAnalysis {
    pub fn render_detail_lines(&self) -> Vec<String> {
        let mut lines = self
            .values
            .iter()
            .map(|value| format!("value -> {}", value.render_text()))
            .collect::<Vec<_>>();
        lines.extend(
            self.member_targets
                .iter()
                .map(|target| format!("member -> {}", target.fq_name)),
        );
        if let Some(reason) = self.reason {
            lines.push(format!("reason -> {reason}"));
        }
        if let Some(limit) = self.limit {
            lines.push(format!("limit -> {limit}"));
        }
        lines
    }
}
